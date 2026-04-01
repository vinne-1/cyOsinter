import { Router } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { enrichFinding, generateWorkspaceInsights, buildFallbackInsights, analyzeFindingDetails, fetchCVEContextForInsights } from "../ai-service";
import { searchThreatIntel } from "../tavily-service";
import { getCVEForFinding } from "../cve-service";
import { updateFindingSchema } from "./schemas";

const routeLog = createLogger("routes");

export const findingsRouter = Router();

findingsRouter.get("/workspaces/:workspaceId/findings", async (req, res) => {
  try {
    const result = await storage.getFindings(req.params.workspaceId);
    const { severity, status, search, page, pageSize } = req.query;

    let filtered = result.data as Array<Record<string, unknown>>;
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
    const pg = Math.max(1, parseInt(String(page ?? "1"), 10));
    const ps = Math.min(200, Math.max(1, parseInt(String(pageSize ?? "0"), 10)));

    if (!pageSize || ps === 0) {
      return res.json(filtered);
    }

    const data = filtered.slice((pg - 1) * ps, pg * ps);
    res.json({ data, total, page: pg, pageSize: ps, totalPages: Math.ceil(total / ps) });
  } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
});

findingsRouter.get("/findings/:id", async (req, res) => {
  try {
    const finding = await storage.getFinding(req.params.id);
    if (!finding) return res.status(404).json({ message: "Finding not found" });
    res.json(finding);
  } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
});

findingsRouter.patch("/findings/:id", async (req, res) => {
  try {
    const parsed = updateFindingSchema.parse(req.body);
    const updated = await storage.updateFinding(req.params.id, parsed);
    if (!updated) return res.status(404).json({ message: "Finding not found" });
    res.json(updated);
  } catch (error: unknown) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
    }
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(400).json({ message });
  }
});

findingsRouter.post("/workspaces/:workspaceId/findings/:id/enrich", async (req, res) => {
  res.setTimeout(1800000); // 30 min for Ollama
  try {
    const finding = await storage.getFinding(req.params.id);
    if (!finding) return res.status(404).json({ message: "Finding not found" });
    if (finding.workspaceId !== req.params.workspaceId) return res.status(404).json({ message: "Finding not found" });
    const { data: modules } = await storage.getReconModules(req.params.workspaceId);
    let result: { enhancedDescription: string; contextualRisks?: string; additionalRemediation?: string };
    try {
      result = await enrichFinding(finding, modules);
    } catch (enrichErr) {
      routeLog.warn({ err: enrichErr, findingId: req.params.id }, "Enrich fallback for finding");
      result = { enhancedDescription: finding.description };
    }
    const aiEnrichment = {
      ...result,
      enrichedAt: new Date().toISOString(),
    };
    const updated = await storage.updateFinding(req.params.id, { aiEnrichment });
    if (!updated) return res.status(404).json({ message: "Finding not found" });
    res.json(updated);
  } catch (err) {
    routeLog.warn({ err }, "Enrich error");
    const finding = await storage.getFinding(req.params.id);
    if (finding && finding.workspaceId === req.params.workspaceId) {
      const aiEnrichment = { enhancedDescription: finding.description, enrichedAt: new Date().toISOString() };
      const updated = await storage.updateFinding(req.params.id, { aiEnrichment }).catch(() => null);
      if (updated) return res.json(updated);
      return res.json({ ...finding, aiEnrichment });
    }
    return res.status(404).json({ message: "Finding not found" });
  }
});

findingsRouter.get("/workspaces/:workspaceId/ai-insights", async (req, res) => {
  try {
    const { workspaceId } = req.params;
    const ws = await storage.getWorkspace(workspaceId);
    if (!ws) return res.status(404).json({ message: "Workspace not found" });
    const [findingsResult, modulesResult] = await Promise.all([
      storage.getFindings(workspaceId),
      storage.getReconModules(workspaceId),
    ]);
    res.json({ findings: findingsResult.data, modules: modulesResult.data, workspaceName: ws.name });
  } catch (err) {
    routeLog.error({ err }, "AI insights error");
    res.status(500).json({ message: err instanceof Error ? err.message : "Failed to load" });
  }
});

findingsRouter.post("/workspaces/:workspaceId/ai-insights/summary", async (req, res) => {
  res.setTimeout(1800000); // 30 min for Ollama inference
  try {
    const { workspaceId } = req.params;
    const ws = await storage.getWorkspace(workspaceId);
    if (!ws) return res.status(404).json({ message: "Workspace not found" });
    const [findingsResult, modulesResult] = await Promise.all([
      storage.getFindings(workspaceId),
      storage.getReconModules(workspaceId),
    ]);
    const findings = findingsResult.data;
    const modules = modulesResult.data;
    const [cveContext, webSearchContext] = await Promise.all([
      fetchCVEContextForInsights(findings, modules, 2),
      searchThreatIntel(ws.name),
    ]);
    const result = await generateWorkspaceInsights(findings, modules, ws.name, {
      cveContext,
      webSearchContext,
    });
    res.json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "AI summary failed";
    const fallbackErrorDetail = msg.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "").slice(0, 500);
    routeLog.warn({ msg }, "AI insights error, returning fallback");
    try {
      const ws = await storage.getWorkspace(req.params.workspaceId);
      if (ws) {
        const [fRes, mRes] = await Promise.all([
          storage.getFindings(req.params.workspaceId),
          storage.getReconModules(req.params.workspaceId),
        ]);
        const fallback = buildFallbackInsights(fRes.data, mRes.data, ws.name);
        const reason =
          msg === "Ollama AI is disabled"
            ? "ollama_disabled"
            : msg.includes("aborted") || msg.includes("timed out")
              ? "ollama_timeout"
              : "ollama_error";
        return res.json({ ...fallback, fallbackReason: reason, fallbackErrorDetail });
      }
    } catch (innerErr) {
      routeLog.error({ err: innerErr }, "AI insights fallback failed");
    }
    res.json({
      summary: "Unable to generate AI insights. Check Integrations—ensure Ollama is running and enabled.",
      keyRisks: [],
      threatLandscape: "",
      isAIGenerated: false,
      fallbackReason: "ollama_error",
      fallbackErrorDetail,
    });
  }
});

findingsRouter.post("/workspaces/:workspaceId/findings/:id/cve-lookup", async (req, res) => {
  try {
    const { workspaceId, id } = req.params;
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
    res.status(500).json({ message: err instanceof Error ? err.message : "CVE lookup failed" });
  }
});

findingsRouter.post("/workspaces/:workspaceId/findings/:id/analyze", async (req, res) => {
  res.setTimeout(1800000); // 30 min for Ollama
  try {
    const { workspaceId, id } = req.params;
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
    const finding = await storage.getFinding(req.params.id);
    if (finding && finding.workspaceId === req.params.workspaceId) {
      const fallback = { analysis: finding.description, recommendations: [] };
      const aiEnrichment = (finding.aiEnrichment as Record<string, unknown>) ?? {};
      const updated = await storage.updateFinding(req.params.id, {
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

findingsRouter.post("/workspaces/:workspaceId/findings/enrich-all", async (req, res) => {
  res.setTimeout(3600000); // 60 min for batch (many findings x 30 min each)
  try {
    const { data: findingsList } = await storage.getFindings(req.params.workspaceId);
    const { data: modules } = await storage.getReconModules(req.params.workspaceId);
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
    const fallbackResult = await storage.getFindings(req.params.workspaceId).catch(() => ({ data: [], total: 0, limit: 0, offset: 0 }));
    res.json({ enriched: 0, total: fallbackResult.total, partial: true });
  }
});
