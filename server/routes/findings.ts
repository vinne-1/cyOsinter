import { Router } from "express";
import { parsePageParams } from "./response";
import { z } from "zod";
import { storage, FULL_SET_LIMIT } from "../storage";
import { createLogger } from "../logger";
import { enrichFinding, buildFallbackInsights, analyzeFindingDetails } from "../ai-service";
import { generateAndPersistWorkspaceInsights, insightFindings } from "../workspace-insights";
import { getCVEForFinding } from "../cve-service";
import { requireWorkspaceRole } from "./auth-middleware";
import { updateFindingSchema } from "./schemas";

const routeLog = createLogger("routes");

/**
 * How many findings the in-memory filter path will consider.
 *
 * Generous rather than unbounded: the alternative is pushing every filter into
 * SQL, which is the right long-term answer but a larger change than this fix.
 */
const FILTERABLE_FINDING_CEILING = 10_000;

export const findingsRouter = Router();

const wsAuth = requireWorkspaceRole("owner", "admin", "analyst", "viewer");

findingsRouter.get("/workspaces/:workspaceId/findings", wsAuth, async (req, res) => {
  try {
    // Filtering and paging happen in memory below, so this fetch has to cover
    // everything the filters could match. Left at the storage default of 500, a
    // workspace with more findings silently lost the rest AND reported a
    // `total` computed from that truncated page — the same "count reflects the
    // page size, not the data" bug the list endpoints were fixed for.
    const result = await storage.getFindings(req.params.workspaceId as string, { limit: FILTERABLE_FINDING_CEILING });
    const { severity, status, search, kind } = req.query;

    let filtered = result.data as Array<Record<string, unknown>>;

    // Optional `?kind=security|control|recon`. The default stays "everything",
    // because several callers (the dashboard, attack paths, reports) fetch this
    // same endpoint and quietly narrowing it under them would change numbers in
    // places nobody was looking. The triage queue asks for what it wants.
    // Rows written before the kind column existed read as "security".
    if (typeof kind === "string" && kind !== "all") {
      filtered = filtered.filter((f) => (f.kind ?? "security") === kind);
    }

    if (severity && typeof severity === "string") {
      filtered = filtered.filter((f) => f.severity === severity);
    }
    if (status && typeof status === "string") {
      filtered = filtered.filter((f) => f.status === status);
    }
    if (search && typeof search === "string") {
      const q = search.toLowerCase();
      filtered = filtered.filter(
        (f) =>
          String(f.title ?? "").toLowerCase().includes(q) ||
          String(f.description ?? "").toLowerCase().includes(q) ||
          String(f.affectedAsset ?? "").toLowerCase().includes(q),
      );
    }

    const total = filtered.length;
    // `Math.max(1, parseInt("abc"))` is NaN, so a malformed `page` used to slice
    // NaN..NaN and return an empty inbox with a 200 and a correct-looking total.
    const { page: pg, pageSize: ps, paged } = parsePageParams(req.query);

    if (!paged) {
      return res.json(filtered);
    }

    const data = filtered.slice((pg - 1) * ps, pg * ps);
    res.json({ data, total, page: pg, pageSize: ps, totalPages: Math.ceil(total / ps) });
  } catch (err) { res.status(500).json({ message: "Internal server error" }); }
});

findingsRouter.get("/findings/:id", async (req, res) => {
  try {
    const finding = await storage.getFinding(req.params.id);
    if (!finding) return res.status(404).json({ message: "Finding not found" });
    // Verify caller has access to the finding's workspace
    const membership = await storage.getWorkspaceMember(finding.workspaceId, req.user!.id);
    if (!membership) return res.status(404).json({ message: "Finding not found" });
    res.json(finding);
  } catch (err) { res.status(500).json({ message: "Internal server error" }); }
});

findingsRouter.patch("/findings/:id", async (req, res) => {
  try {
    const finding = await storage.getFinding(req.params.id);
    if (!finding) return res.status(404).json({ message: "Finding not found" });
    // Verify caller has access to the finding's workspace
    const membership = await storage.getWorkspaceMember(finding.workspaceId, req.user!.id);
    if (!membership) return res.status(404).json({ message: "Finding not found" });
    const parsed = updateFindingSchema.parse(req.body);
    const updated = await storage.updateFinding(req.params.id, parsed);
    if (!updated) return res.status(404).json({ message: "Finding not found" });
    res.json(updated);
  } catch (error: unknown) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
    }
    const message = "Bad request";
    res.status(400).json({ message });
  }
});

findingsRouter.post("/workspaces/:workspaceId/findings/:id/enrich", wsAuth, async (req, res) => {
  res.setTimeout(1800000); // 30 min for Ollama
  try {
    const workspaceId = req.params.workspaceId as string;
    const findingId = req.params.id as string;
    const finding = await storage.getFinding(findingId);
    if (!finding) return res.status(404).json({ message: "Finding not found" });
    if (finding.workspaceId !== workspaceId) return res.status(404).json({ message: "Finding not found" });
    const { data: modules } = await storage.getReconModules(workspaceId);
    let result: { enhancedDescription: string; contextualRisks?: string; additionalRemediation?: string };
    try {
      result = await enrichFinding(finding, modules);
    } catch (enrichErr) {
      routeLog.warn({ err: enrichErr, findingId }, "Enrich fallback for finding");
      result = { enhancedDescription: finding.description };
    }
    const aiEnrichment = {
      ...result,
      enrichedAt: new Date().toISOString(),
    };
    const updated = await storage.updateFinding(findingId, { aiEnrichment });
    if (!updated) return res.status(404).json({ message: "Finding not found" });
    res.json(updated);
  } catch (err) {
    routeLog.warn({ err }, "Enrich error");
    const workspaceId = req.params.workspaceId as string;
    const findingId = req.params.id as string;
    const finding = await storage.getFinding(findingId);
    if (finding && finding.workspaceId === workspaceId) {
      const aiEnrichment = { enhancedDescription: finding.description, enrichedAt: new Date().toISOString() };
      const updated = await storage.updateFinding(findingId, { aiEnrichment }).catch(() => null);
      if (updated) return res.json(updated);
      return res.json({ ...finding, aiEnrichment });
    }
    return res.status(404).json({ message: "Finding not found" });
  }
});

findingsRouter.get("/workspaces/:workspaceId/ai-insights", wsAuth, async (req, res) => {
  try {
    const workspaceId = req.params.workspaceId as string;
    const ws = await storage.getWorkspace(workspaceId);
    if (!ws) return res.status(404).json({ message: "Workspace not found" });
    const [findingsResult, modulesResult, snapshot] = await Promise.all([
      storage.getFindings(workspaceId, { limit: FULL_SET_LIMIT }),
      storage.getReconModules(workspaceId),
      // The last synthesis, if one was ever generated — this is what lets the
      // page show real content on load instead of an empty "Click Generate"
      // state. This route runs no AI itself, so it stays off the 3/min AI
      // rate limiter (mounted only on POST .../ai-insights/summary); reading
      // a stored result must not compete with that budget.
      storage.getAiInsightsSnapshot(workspaceId),
    ]);
    res.json({
      findings: insightFindings(findingsResult.data),
      modules: modulesResult.data,
      workspaceName: ws.name,
      lastSummary: snapshot ? { ...snapshot.content, generatedAt: snapshot.generatedAt } : null,
    });
  } catch (err) {
    routeLog.error({ err }, "AI insights error");
    res.status(500).json({ message: "Failed to load" });
  }
});

findingsRouter.post("/workspaces/:workspaceId/ai-insights/summary", wsAuth, async (req, res) => {
  res.setTimeout(1800000); // 30 min for Ollama inference
  try {
    const workspaceId = req.params.workspaceId as string;
    const ws = await storage.getWorkspace(workspaceId);
    if (!ws) return res.status(404).json({ message: "Workspace not found" });
    // Shared with scan completion (when a scan is launched with AI enrichment
    // on) and read by the Intelligence panel, so "generate" always means the
    // same sequence — findings + recon + CVE context, live verification
    // against the workspace's real hosts, GLM synthesis, persisted snapshot —
    // regardless of which of the three triggered it.
    const result = await generateAndPersistWorkspaceInsights(workspaceId);
    res.json(result);
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : "AI summary failed";
    routeLog.warn({ err }, "AI insights error, returning fallback");
    try {
      const workspaceId = req.params.workspaceId as string;
      const ws = await storage.getWorkspace(workspaceId);
      if (ws) {
        const [fRes, mRes] = await Promise.all([
          storage.getFindings(workspaceId, { limit: FULL_SET_LIMIT }),
          storage.getReconModules(workspaceId),
        ]);
        const fallback = buildFallbackInsights(insightFindings(fRes.data), mRes.data, ws.domain || ws.name);
        const reason =
          errMsg.includes("GLM_API_KEY") || errMsg.includes("not configured")
            ? "ollama_disabled"
            : errMsg.includes("aborted") || errMsg.includes("timed out")
              ? "ollama_timeout"
              : "ollama_error";
        return res.json({ ...fallback, fallbackReason: reason });
      }
    } catch (innerErr) {
      routeLog.error({ err: innerErr }, "AI insights fallback failed");
    }
    res.json({
      summary: "Unable to generate AI insights. GLM did not answer.",
      keyRisks: [],
      threatLandscape: "",
      isAIGenerated: false,
      fallbackReason: "ollama_error",
    });
  }
});

findingsRouter.post("/workspaces/:workspaceId/findings/:id/cve-lookup", wsAuth, async (req, res) => {
  try {
    const workspaceId = req.params.workspaceId as string;
    const id = req.params.id as string;
    const finding = await storage.getFinding(id);
    if (!finding || finding.workspaceId !== workspaceId) return res.status(404).json({ message: "Finding not found" });
    const { data: modules } = await storage.getReconModules(workspaceId);
    let cveRecords: Awaited<ReturnType<typeof getCVEForFinding>>;
    try {
      cveRecords = await getCVEForFinding(finding, modules);
    } catch (cveErr) {
      routeLog.warn({ err: cveErr, findingId: id }, "CVE lookup failed for finding");
      cveRecords = [];
    }
    const aiEnrichment = (finding.aiEnrichment as Record<string, unknown>) ?? {};
    // Collect KEV-positive records for a top-level summary
    const kevMatches = cveRecords
      .filter((c) => c.kev?.inKEV)
      .map((c) => ({
        cveId: c.cveId,
        dueDate: c.kev?.dueDate,
        knownRansomware: c.kev?.knownRansomware,
        notes: c.kev?.notes,
      }));
    const updated = await storage.updateFinding(id, {
      aiEnrichment: {
        ...aiEnrichment,
        cveData: {
          cveIds: cveRecords.map((c) => c.cveId),
          records: cveRecords,
          lastFetched: new Date().toISOString(),
        },
        kevData: {
          checked: true,
          matches: kevMatches,
          hasKEV: kevMatches.length > 0,
          lastChecked: new Date().toISOString(),
        },
      },
    });
    if (!updated) return res.status(404).json({ message: "Finding not found" });
    res.json({ cveRecords, kevMatches, finding: updated });
  } catch (err) {
    routeLog.error({ err }, "CVE lookup error");
    res.status(500).json({ message: "CVE lookup failed" });
  }
});

findingsRouter.post("/workspaces/:workspaceId/findings/:id/analyze", wsAuth, async (req, res) => {
  res.setTimeout(1800000); // 30 min for Ollama
  try {
    const workspaceId = req.params.workspaceId as string;
    const id = req.params.id as string;
    const finding = await storage.getFinding(id);
    if (!finding || finding.workspaceId !== workspaceId) return res.status(404).json({ message: "Finding not found" });
    const { data: modules } = await storage.getReconModules(workspaceId);
    const cveData = (finding.aiEnrichment as Record<string, unknown>)?.cveData as { records?: Array<{ cveId: string; description: string; cvssScore?: number; cvssSeverity?: string; url: string }> } | undefined;
    const reconContext = modules.map((m) => `${m.moduleType}: ${JSON.stringify((m.data as object) ?? {}).slice(0, 300)}`).join("\n");
    const result = await analyzeFindingDetails(finding, cveData?.records ?? undefined, reconContext);
    const aiEnrichment = (finding.aiEnrichment as Record<string, unknown>) ?? {};
    const updated = await storage.updateFinding(id, {
      aiEnrichment: {
        ...aiEnrichment,
        detailedAnalysis: {
          ...result,
          analyzedAt: new Date().toISOString(),
        },
      },
    });
    if (!updated) return res.status(404).json({ message: "Finding not found" });
    res.json({ ...result, finding: updated });
  } catch (err) {
    routeLog.warn({ err }, "Analyze error");
    const workspaceId = req.params.workspaceId as string;
    const id = req.params.id as string;
    const finding = await storage.getFinding(id);
    if (finding && finding.workspaceId === workspaceId) {
      const fallback = { analysis: finding.description, recommendations: [] };
      const aiEnrichment = (finding.aiEnrichment as Record<string, unknown>) ?? {};
      const updated = await storage.updateFinding(id, {
        aiEnrichment: {
          ...aiEnrichment,
          detailedAnalysis: { ...fallback, analyzedAt: new Date().toISOString() },
        },
      }).catch(() => null);
      if (updated) return res.json({ ...fallback, finding: updated });
      return res.json({ ...fallback, finding: { ...finding, aiEnrichment: { ...aiEnrichment, detailedAnalysis: fallback } } });
    }
    return res.status(404).json({ message: "Finding not found" });
  }
});

findingsRouter.post("/workspaces/:workspaceId/findings/enrich-all", wsAuth, async (req, res) => {
  res.setTimeout(3600000); // 60 min for batch (many findings x 30 min each)
  try {
    const workspaceId = req.params.workspaceId as string;
    const { data: allFindings } = await storage.getFindings(workspaceId, { limit: FULL_SET_LIMIT });
    const { data: modules } = await storage.getReconModules(workspaceId);
    /*
     * Enrichment is triage help for WORK, not a pass over every row in the
     * workspace. Without this filter, "Enrich all" spent a GLM call on every
     * `control` row (a protection that IS working, e.g. "DNSSEC Detection")
     * and every `recon` row (a technology fact, e.g. "Apache Detection") and
     * every already-resolved finding — none of which benefit from "clearer,
     * actionable context". This is the same `kind`/status oversight this
     * codebase has already found and fixed in the SLA sweep, both trend
     * endpoints, the compliance mapper input, and the report builders.
     *
     * Findings that already carry enrichment are skipped too, so a second
     * click (to pick up stragglers after a partial run) does not re-spend a
     * GLM call on rows that already have an answer.
     */
    const findingsList = insightFindings(allFindings).filter((f) => {
      const ae = f.aiEnrichment as { enhancedDescription?: string } | null | undefined;
      return !ae?.enhancedDescription;
    });
    let enriched = 0;
    for (const f of findingsList) {
      try {
        const result = await enrichFinding(f, modules);
        const aiEnrichment = { ...result, enrichedAt: new Date().toISOString() };
        await storage.updateFinding(f.id, { aiEnrichment });
        enriched++;
        await new Promise((r) => setTimeout(r, 2000));
      } catch {
        // skip failed
      }
    }
    res.json({ enriched, total: findingsList.length });
  } catch (err) {
    routeLog.warn({ err }, "Enrich-all error");
    const workspaceId = req.params.workspaceId as string;
    const fallbackResult = await storage.getFindings(workspaceId).catch(() => ({ data: [], total: 0, limit: 0, offset: 0 }));
    res.json({ enriched: 0, total: fallbackResult.total, partial: true });
  }
});
