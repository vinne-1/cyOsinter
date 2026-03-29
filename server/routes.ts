import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import multer from "multer";
import { storage } from "./storage";
import { z } from "zod";
import { insertAssetSchema, insertScanSchema, insertReportSchema, insertWorkspaceSchema, type Finding } from "@shared/schema";
import { runEASMScan, runOSINTScan, runNucleiScan, buildReconModules } from "./scanner";
import { computeSecurityScore } from "@shared/scoring";
import { startMonitoring, stopMonitoring, getMonitoringStatus } from "./continuous-monitoring";
import { enrichIPs, fetchBGPViewForIPs, getIntegrationsStatus, getOllamaConfig } from "./api-integrations";
import { getOllamaStatus, enrichFinding, generateReportSummary, consolidateScanResults, generateWorkspaceInsights, buildFallbackInsights, analyzeFindingDetails, fetchCVEContextForInsights } from "./ai-service";
import { searchThreatIntel } from "./tavily-service";
import { getCVEForFinding } from "./cve-service";
import { parseNmap, nmapToTextSummary } from "./parsers/nmap";

const validSeverities = ["critical", "high", "medium", "low", "info"] as const;
const validStatuses = ["open", "in_review", "resolved", "false_positive", "accepted_risk"] as const;

const updateFindingSchema = z.object({
  status: z.enum(validStatuses).optional(),
  assignee: z.string().nullable().optional(),
});

const createAssetSchema = insertAssetSchema.extend({
  value: z.string().min(1, "Value is required"),
  type: z.enum(["domain", "subdomain", "ip", "service", "certificate"]),
  status: z.enum(["active", "inactive", "unknown"]).default("active"),
});

const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

const createScanSchema = z.object({
  target: z.string().min(1, "Target is required").refine(
    (val) => DOMAIN_REGEX.test(val.trim()),
    { message: "Target must be a valid domain name (e.g. example.com)" }
  ),
  type: z.enum(["easm", "osint", "full"]),
  status: z.enum(["pending", "running", "completed", "failed"]).default("pending"),
  workspaceId: z.string().optional(),
  autoGenerateReport: z.boolean().optional(),
  mode: z.enum(["standard", "gold"]).optional(),
});

const createReportSchema = z.object({
  title: z.string().min(1, "Title is required"),
  type: z.enum(["executive_summary", "full_report", "evidence_pack"]),
  workspaceId: z.string(),
  status: z.enum(["draft", "generating", "completed"]).default("draft"),
  findingIds: z.array(z.string()).optional(),
});

const createWorkspaceSchema = z.object({
  name: z.string().min(1, "Domain name is required"),
  description: z.string().optional(),
});

const startContinuousMonitoringSchema = z.object({
  target: z.string().min(1, "Target is required"),
  workspaceId: z.string().optional(),
});

const stopContinuousMonitoringSchema = z.object({
  workspaceId: z.string().min(1, "Workspace ID is required"),
});

type ReconModule = { moduleType: string; confidence: number | null; data: Record<string, unknown> };

async function buildReportContent(
  workspaceId: string,
  findingIds: string[] | undefined,
  reportType?: string
): Promise<{ content: Record<string, unknown>; summary: string }> {
  const allFindings = await storage.getFindings(workspaceId);
  let includedFindings = (findingIds?.length ?? 0) > 0
    ? allFindings.filter((f) => findingIds!.includes(f.id))
    : allFindings;

  if (reportType === "executive_summary") {
    includedFindings = includedFindings.filter((f) => {
      const evidence = (f.evidence || []) as Array<{ validated?: boolean; confidence?: string }>;
      const hasLowConfidence = evidence.some((e) => e.validated === false && e.confidence === "low");
      return !hasLowConfidence;
    });
  }

  if (reportType === "evidence_pack") {
    const reVerifyCategories = ["exposed_content", "infrastructure_disclosure", "leaked_credential"];
    const now = new Date().toISOString();
    for (const f of includedFindings) {
      if (!reVerifyCategories.includes(f.category)) continue;
      const evidence = (f.evidence || []) as Array<Record<string, unknown>>;
      for (const e of evidence) {
        const url = e.url as string | undefined;
        if (!url || typeof url !== "string" || !url.startsWith("http")) continue;
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 5000);
          const res = await fetch(url, { method: "HEAD", signal: controller.signal, redirect: "follow" });
          clearTimeout(timer);
          e.reVerifiedAt = now;
          e.validated = res.ok;
          e.reVerifyStatus = res.status;
        } catch {
          e.reVerifiedAt = now;
          e.validated = false;
          e.reVerifyStatus = 0;
        }
      }
    }
  }

  const modules = await storage.getReconModules(workspaceId) as ReconModule[];
  const modulesByType = modules.reduce((acc, m) => {
    if (!(m.moduleType in acc)) acc[m.moduleType] = m;
    return acc;
  }, {} as Record<string, ReconModule>);

  const attackSurface = modulesByType.attack_surface?.data as Record<string, unknown> | undefined;
  const cloudFootprint = modulesByType.cloud_footprint?.data as Record<string, unknown> | undefined;

  const osintCategories = ["leaked_credential", "data_leak", "infrastructure_disclosure", "osint_exposure"];
  const osintFindings = includedFindings.filter((f) => osintCategories.includes(f.category));
  const byCategory: Record<string, number> = {};
  for (const c of osintCategories) {
    byCategory[c] = osintFindings.filter((f) => f.category === c).length;
  }

  const content: Record<string, unknown> = {
    totalFindings: includedFindings.length,
    criticalCount: includedFindings.filter((f) => f.severity === "critical").length,
    highCount: includedFindings.filter((f) => f.severity === "high").length,
    mediumCount: includedFindings.filter((f) => f.severity === "medium").length,
    lowCount: includedFindings.filter((f) => f.severity === "low").length,
    resolvedCount: includedFindings.filter((f) => f.status === "resolved").length,
    categories: Array.from(new Set(includedFindings.map((f) => f.category))),
    generatedAt: new Date().toISOString(),
    reconModules: modules.map((m) => ({
      moduleType: m.moduleType,
      confidence: m.confidence ?? 0,
      dataSummary: Object.keys(m.data || {}).slice(0, 5),
    })),
    moduleCoverage: modules.map((m) => ({
      moduleType: m.moduleType,
      included: true,
      summary: `${m.moduleType} (${m.confidence ?? 0}% confidence)`,
    })),
    dnsOverview: modulesByType.dns_overview?.data ?? null,
    redirectChain: modulesByType.redirect_chain?.data ?? null,
    exposedContent: modulesByType.exposed_content?.data ?? null,
    techStack: modulesByType.tech_stack?.data ?? null,
    websiteOverview: modulesByType.website_overview?.data ?? null,
    bgpRouting: modulesByType.bgp_routing?.data ?? null,
    nuclei: modulesByType.nuclei?.data ?? null,
    attackSurface: attackSurface
      ? {
          surfaceRiskScore: attackSurface.surfaceRiskScore,
          tlsGrade: (attackSurface.tlsPosture as Record<string, unknown> | undefined)?.grade,
          securityHeadersGrade: Array.isArray(attackSurface.securityHeaders) ? (attackSurface.securityHeaders[0] as Record<string, unknown>)?.grade : undefined,
        }
      : null,
    securityHeadersMatrix: attackSurface?.securityHeaders
      ? (Array.isArray(attackSurface.securityHeaders)
        ? (attackSurface.securityHeaders as Array<{ header: string; present: boolean; value?: string; grade?: string }>).map((h) => ({
            header: h.header,
            present: !!h.present,
            grade: h.grade ?? "N/A",
            value: h.value ?? null,
          }))
        : Object.entries(attackSurface.securityHeaders as Record<string, { present?: boolean; value?: string | null; grade?: string }>).map(([header, h]) => ({
            header,
            present: !!h?.present,
            grade: h?.grade ?? "N/A",
            value: h?.value ?? null,
          })))
      : [],
    securityHeadersCoverage: attackSurface?.securityHeaders
      ? (() => {
          const arr = Array.isArray(attackSurface.securityHeaders)
            ? attackSurface.securityHeaders as Array<{ header: string; present?: boolean; grade?: string }>
            : Object.entries(attackSurface.securityHeaders as Record<string, { present?: boolean; grade?: string }>).map(([name, h]) => ({ header: name, ...h }));
          const total = arr.length;
          const passing = arr.filter((h) => h.present && (h.grade === "A" || h.grade === "B")).length;
          const missing = arr.filter((h) => !h.present).map((h) => h.header);
          return { passing, total, missing };
        })()
      : null,
    attackSurfaceSummary: attackSurface
      ? (() => {
          const inv = (attackSurface.assetInventory || []) as Array<{ host: string; riskScore: number; waf: string }>;
          const totalHosts = inv.length || 0;
          const highRiskCount = inv.filter((a) => a.riskScore >= 60).length;
          const wafCoverage = totalHosts > 0 ? Math.round((inv.filter((a) => a.waf).length / totalHosts) * 100) : 0;
          return { totalHosts, highRiskCount, wafCoverage };
        })()
      : null,
    attackSurfaceAssets: attackSurface?.assetInventory ?? [],
    cloudFootprint: cloudFootprint
      ? {
          grades: cloudFootprint.grades,
          spfStatus: (cloudFootprint.emailSecurity as Record<string, unknown>)?.spf && typeof (cloudFootprint.emailSecurity as Record<string, unknown>).spf === "object"
            ? ((cloudFootprint.emailSecurity as Record<string, unknown>).spf as Record<string, unknown>)?.status
            : undefined,
          dmarcStatus: (cloudFootprint.emailSecurity as Record<string, unknown>)?.dmarc && typeof (cloudFootprint.emailSecurity as Record<string, unknown>).dmarc === "object"
            ? ((cloudFootprint.emailSecurity as Record<string, unknown>).dmarc as Record<string, unknown>)?.status
            : undefined,
        }
      : null,
    osintDiscovery: {
      leakedCredentials: osintFindings.filter((f) => f.category === "leaked_credential").map((f) => ({ id: f.id, title: f.title, severity: f.severity, affectedAsset: f.affectedAsset })),
      exposedDocuments: osintFindings.filter((f) => f.category === "data_leak").map((f) => ({ id: f.id, title: f.title, severity: f.severity, affectedAsset: f.affectedAsset })),
      infrastructureDisclosure: osintFindings.filter((f) => f.category === "infrastructure_disclosure").map((f) => ({ id: f.id, title: f.title, severity: f.severity, affectedAsset: f.affectedAsset })),
      osintExposure: osintFindings.filter((f) => f.category === "osint_exposure").map((f) => ({ id: f.id, title: f.title, severity: f.severity, affectedAsset: f.affectedAsset })),
      summary: { total: osintFindings.length, byCategory },
    },
  };

  if (reportType === "evidence_pack") {
    const verifiedFindings = includedFindings.filter((f) => {
      const ev = (f.evidence || []) as Array<Record<string, unknown>>;
      return ev.some((e) => e.reVerifiedAt);
    });
    const passedCount = verifiedFindings.filter((f) => {
      const ev = (f.evidence || []) as Array<Record<string, unknown>>;
      return ev.every((e) => !e.reVerifiedAt || e.validated === true);
    }).length;
    content.evidenceVerification = {
      totalVerified: verifiedFindings.length,
      passed: passedCount,
      failed: verifiedFindings.length - passedCount,
      verifiedAt: new Date().toISOString(),
    };
  }

  const postureHistory = await storage.getPostureHistory(workspaceId, 10);
  content.postureTrend = postureHistory.map((p) => ({
    snapshotAt: p.snapshotAt?.toISOString?.() ?? new Date().toISOString(),
    surfaceRiskScore: p.surfaceRiskScore,
    securityScore: p.securityScore,
    findingsCount: p.findingsCount,
    criticalCount: p.criticalCount,
    highCount: p.highCount,
    wafCoverage: p.wafCoverage,
  }));

  const ipAssets = await storage.getAssets(workspaceId);
  const ipsFromAssets = ipAssets.filter((a) => a.type === "ip").map((a) => a.value);
  const publicIPs = attackSurface?.publicIPs as Array<{ ip: string }> | undefined;
  const ipsFromSurface = (publicIPs ?? []).map((p) => (typeof p === "string" ? p : p?.ip)).filter(Boolean);
  const allIPs = Array.from(new Set([...ipsFromAssets, ...ipsFromSurface]));
  if (allIPs.length > 0) {
    try {
      const ipEnrichment = await enrichIPs(allIPs);
      content.ipEnrichment = ipEnrichment;
    } catch (err) {
      console.error("IP enrichment error:", err);
    }
  }

  const crit = content.criticalCount as number;
  const high = content.highCount as number;
  const osintTotal = osintFindings.length;
  const surfaceScore = attackSurface?.surfaceRiskScore as number | undefined;
  const cloudGrade = (cloudFootprint?.grades as Record<string, string> | undefined)?.overall;

  let summary = `This report covers ${includedFindings.length} security findings across ${(content.categories as string[]).length} categories. `;
  if (crit > 0 || high > 0) {
    summary += `${crit} critical and ${high} high severity findings require immediate attention. `;
  }
  if (modules.length > 0) {
    summary += `Intelligence data includes ${modules.length} recon modules. `;
  }
  if (surfaceScore != null) {
    summary += `Attack surface risk score: ${surfaceScore}/100. `;
  }
  if (cloudGrade) {
    summary += `Email security grade: ${cloudGrade}. `;
  }
  if (osintTotal > 0) {
    summary += `OSINT discovery identified ${osintTotal} items (credentials, exposed docs, infrastructure). `;
  }
  if (content.ipEnrichment && Object.keys(content.ipEnrichment as object).length > 0) {
    summary += `IP reputation data from AbuseIPDB and VirusTotal included.`;
  }
  summary = summary.trimEnd();

  const originalSummary = summary;
  const ollamaConfig = getOllamaConfig();
  if (ollamaConfig.enabled && includedFindings.length > 0) {
    try {
      const aiSummary = await generateReportSummary(includedFindings, content);
      if (aiSummary && aiSummary.trim()) {
        summary = aiSummary.trim();
        (content as Record<string, unknown>).aiNarrative = summary;
        (content as Record<string, unknown>).originalSummary = originalSummary;
      }
    } catch (err) {
      console.error("AI report summary failed, using fallback:", err);
    }
  }

  return { content, summary };
}

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {

  app.get("/api/workspaces", async (_req, res) => {
    try {
      const ws = await storage.getWorkspaces();
      res.json(ws);
    } catch (err) {
      console.error("Get workspaces error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
    }
  });

  app.post("/api/workspaces/:id/purge", async (req, res) => {
    try {
      const ws = await storage.getWorkspace(req.params.id);
      if (!ws) return res.status(404).json({ message: "Workspace not found" });
      await storage.purgeWorkspaceData(req.params.id);
      res.status(200).set("Content-Type", "application/json").json({ purged: true, workspaceId: req.params.id });
    } catch (err) {
      console.error("Purge workspace error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Failed to purge workspace" });
    }
  });

  app.get("/api/workspaces/:id", async (req, res) => {
    try {
      const ws = await storage.getWorkspace(req.params.id);
      if (!ws) return res.status(404).json({ message: "Workspace not found" });
      res.json(ws);
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  app.post("/api/workspaces", async (req, res) => {
    try {
      const parsed = createWorkspaceSchema.parse(req.body);
      const existing = await storage.getWorkspaceByName(parsed.name);
      if (existing) {
        return res.status(409).json({ message: "A workspace with this domain already exists", workspace: existing });
      }
      const ws = await storage.createWorkspace({ name: parsed.name, description: parsed.description || null, status: "active" });
      res.status(201).json(ws);
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
      }
      res.status(400).json({ message: error.message });
    }
  });

  app.patch("/api/workspaces/:id", async (req, res) => {
    try {
      const updated = await storage.updateWorkspace(req.params.id, req.body);
      if (!updated) return res.status(404).json({ message: "Workspace not found" });
      res.json(updated);
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  });

  app.delete("/api/workspaces/:id", async (req, res) => {
    try {
      const ws = await storage.getWorkspace(req.params.id);
      if (!ws) return res.status(404).json({ message: "Workspace not found" });
      await storage.deleteWorkspace(req.params.id);
      res.status(204).send();
    } catch (err) {
      console.error("Delete workspace error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
    }
  });

  app.get("/api/workspaces/:workspaceId/assets", async (req, res) => {
    try {
      const assetsList = await storage.getAssets(req.params.workspaceId);
      res.json(assetsList);
    } catch (err) {
      console.error("Get assets error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
    }
  });

  app.get("/api/assets/:id", async (req, res) => {
    try {
      const asset = await storage.getAsset(req.params.id);
      if (!asset) return res.status(404).json({ message: "Asset not found" });
      res.json(asset);
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  app.post("/api/workspaces/:workspaceId/assets", async (req, res) => {
    try {
      const parsed = createAssetSchema.parse({ ...req.body, workspaceId: req.params.workspaceId });
      const asset = await storage.createAsset(parsed);
      res.status(201).json(asset);
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
      }
      res.status(400).json({ message: error.message });
    }
  });

  app.delete("/api/assets/:id", async (req, res) => {
    try {
      await storage.deleteAsset(req.params.id);
      res.status(204).send();
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  app.get("/api/workspaces/:workspaceId/scans", async (req, res) => {
    try {
      const scansList = await storage.getScans(req.params.workspaceId);
      res.json(scansList);
    } catch (err) {
      console.error("Get scans error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
    }
  });

  app.get("/api/scans/:id", async (req, res) => {
    try {
      const scan = await storage.getScan(req.params.id);
      if (!scan) return res.status(404).json({ message: "Scan not found" });
      res.json(scan);
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  app.delete("/api/scans/:id", async (req, res) => {
    try {
      const scan = await storage.getScan(req.params.id);
      if (!scan) return res.status(404).json({ message: "Scan not found" });
      await storage.deleteScan(req.params.id);
      res.status(204).send();
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  app.post("/api/scans", async (req, res) => {
    try {
      const parsed = createScanSchema.parse(req.body);
      // Normalize target: trim whitespace, lowercase, strip trailing dots/slashes
      parsed.target = parsed.target.trim().toLowerCase().replace(/[./]+$/, "");
      if (!parsed.target || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(parsed.target)) {
        return res.status(400).json({ message: "Invalid domain format" });
      }
      const autoGenerateReport = parsed.autoGenerateReport ?? false;
      const scanMode = parsed.mode ?? "standard";
      const gold = scanMode === "gold";
      let workspaceId = parsed.workspaceId;

      if (!workspaceId) {
        let ws = await storage.getWorkspaceByName(parsed.target);
        if (!ws) {
          ws = await storage.createWorkspace({ name: parsed.target, description: null, status: "active" });
        }
        workspaceId = ws.id;
      }

      // Prevent duplicate concurrent scans for same target
      const existingScans = await storage.getScans(workspaceId);
      const alreadyRunning = existingScans.find(s => s.status === "running" && s.target === parsed.target);
      if (alreadyRunning) {
        return res.status(409).json({
          message: `A scan is already running for ${parsed.target}`,
          existingScanId: alreadyRunning.id
        });
      }

      const scan = await storage.createScan({
        workspaceId,
        target: parsed.target,
        type: parsed.type,
        status: parsed.status,
      });

      await storage.updateScan(scan.id, { status: "running", startedAt: new Date() });

      const onProgress = async (
        msg: string,
        percent: number,
        step: string,
        etaSeconds?: number,
      ) => {
        await storage.updateScan(scan.id, {
          progressMessage: msg,
          progressPercent: Math.round(percent),
          currentStep: step,
          estimatedSecondsRemaining: etaSeconds != null ? Math.round(etaSeconds) : null,
        });
      };

      (async () => {
        try {
          const scanType = scan.type;
          const target = scan.target;
          let easmResults: Awaited<ReturnType<typeof runEASMScan>> | null = null;
          let osintResults: Awaited<ReturnType<typeof runOSINTScan>> | null = null;

          let nucleiResults: Awaited<ReturnType<typeof runNucleiScan>> | null = null;
          if (scanType === "full") {
            const scanOptions = { signal: undefined as AbortSignal | undefined, mode: scanMode as "standard" | "gold" };
            const easmProgress = (m: string, p: number, s: string, e?: number) =>
              onProgress(`[EASM] ${m}`, Math.round(Math.min(40, (p * 40) / 100)), `easm_${s}`, e ? Math.ceil(e * 0.4) : undefined);
            easmResults = await runEASMScan(target, easmProgress, scanOptions);
            const osintProgress = (m: string, p: number, s: string, e?: number) =>
              onProgress(`[OSINT] ${m}`, Math.round(40 + (p * 40) / 100), `osint_${s}`, e ? Math.ceil(e * 0.4) : undefined);
            osintResults = await runOSINTScan(target, osintProgress, scanOptions);
            const nucleiUrls: string[] = [`https://${target}`, `http://${target}`];
            const discoveredDomains = (easmResults?.reconData as any)?.discoveredDomains as Array<{ domain: string }> | undefined;
            const nucleiDomainsCap = gold ? 0 : 50;
            const domainsForNuclei = nucleiDomainsCap === 0 ? (discoveredDomains ?? []) : (discoveredDomains ?? []).slice(0, nucleiDomainsCap);
            if (domainsForNuclei.length) {
              for (const d of domainsForNuclei) {
                const host = d.domain;
                nucleiUrls.push(`https://${host}`, `http://${host}`);
              }
            }
            const nucleiProgress = (m: string, p: number, s: string, e?: number) =>
              onProgress(`[Nuclei] ${m}`, Math.round(80 + (p * 20) / 100), `nuclei_${s}`, e ? Math.ceil(e * 0.2) : undefined);
            nucleiResults = await runNucleiScan(target, nucleiUrls, nucleiProgress, { mode: scanMode as "standard" | "gold" });
          } else if (scanType === "easm") {
            easmResults = await runEASMScan(target, onProgress, { mode: scanMode as "standard" | "gold" });
          } else {
            osintResults = await runOSINTScan(target, onProgress, { mode: scanMode as "standard" | "gold" });
          }

          const scanResults = easmResults ?? osintResults!;
          const allFindings = [
            ...(easmResults?.findings ?? []),
            ...(osintResults?.findings ?? []),
            ...(nucleiResults?.findings ?? []),
          ];
          const allAssets = [...(easmResults?.assets ?? []), ...(osintResults?.assets ?? [])];
          const mergedSubdomains = Array.from(new Set([...(easmResults?.subdomains ?? []), ...(osintResults?.subdomains ?? [])]));

          for (const asset of allAssets) {
            try {
              const exists = await storage.assetExists(workspaceId, asset.type, asset.value);
              if (!exists) {
                await storage.createAsset({ workspaceId, type: asset.type, value: asset.value, status: "active", tags: asset.tags });
              }
            } catch (assetErr) {
              console.warn("[Scan] Failed to create asset:", assetErr instanceof Error ? assetErr.message : assetErr);
            }
          }

          const createdFindingIds: string[] = [];
          for (const f of allFindings) {
            try {
              const exists = await storage.findingExists(workspaceId, f.title, f.affectedAsset, f.category);
              if (exists) continue;
              const created = await storage.createFinding({ ...f, workspaceId, scanId: scan.id, status: "open" });
              createdFindingIds.push(created.id);
            } catch (findErr) {
              console.error(`[Scan] Failed to create finding "${f.title}":`, findErr);
            }
          }

          let reconModules: Awaited<ReturnType<typeof buildReconModules>> = [];
          try {
            reconModules = await buildReconModules(target, easmResults, osintResults);
          } catch (reconErr) {
            console.error("[Scan] Failed to build recon modules:", reconErr);
          }

          for (const mod of reconModules) {
            try {
              await storage.createReconModule({
                workspaceId,
                scanId: scan.id,
                target,
                moduleType: mod.moduleType,
                data: mod.data,
                confidence: mod.confidence,
              });
            } catch (modErr) {
              console.error(`[Scan] Failed to create recon module "${mod.moduleType}":`, modErr);
            }
          }

          const ipsFromAttackSurface = reconModules
            .find((m) => m.moduleType === "attack_surface")
            ?.data?.publicIPs as Array<{ ip: string }> | undefined;
          const ipsFromAssets = allAssets.filter((a) => a.type === "ip").map((a) => a.value);
          const ipsFromDiscovered = (easmResults?.reconData as any)?.discoveredDomains
            ?.flatMap((d: { dns?: { ips?: string[] } }) => d.dns?.ips ?? []) ?? [];
          const allIPs = Array.from(new Set([
            ...(ipsFromAttackSurface ?? []).map((p) => (typeof p === "string" ? p : p?.ip)).filter(Boolean),
            ...ipsFromAssets,
            ...ipsFromDiscovered,
          ]));
          if (allIPs.length > 0) {
            let bgpData: Record<string, unknown> = {};
            try {
              bgpData = await fetchBGPViewForIPs(allIPs) as Record<string, unknown>;
            } catch (bgpErr) {
              console.error("BGPView fetch error:", bgpErr);
            }
            try {
              await storage.createReconModule({
                workspaceId,
                scanId: scan.id,
                target,
                moduleType: "bgp_routing",
                data: { ips: bgpData, source: "BGPView API", verifiedAt: new Date().toISOString() },
                confidence: 90,
              });
            } catch (createErr) {
              console.error("BGP routing module create error:", createErr);
            }
          }

          if (nucleiResults && scanType === "full") {
            try {
              await storage.createReconModule({
                workspaceId,
                scanId: scan.id,
                target,
                moduleType: "nuclei",
                data: {
                  source: "Nuclei scanner (all templates)",
                  hits: nucleiResults.nucleiResults ?? [],
                  templateCount: nucleiResults.nucleiResults?.length ?? 0,
                  allTemplatesLoaded: true,
                  skipped: false,
                  verifiedAt: new Date().toISOString(),
                },
                confidence: 95,
              });
            } catch (createErr) {
              console.error("Nuclei module create error:", createErr);
            }
          }

          await storage.updateScan(scan.id, {
            status: "completed",
            completedAt: new Date(),
            findingsCount: createdFindingIds.length,
            progressMessage: null,
            progressPercent: null,
            currentStep: null,
            estimatedSecondsRemaining: null,
            summary: {
              assetsDiscovered: allAssets.length,
              findingsGenerated: createdFindingIds.length,
              criticalCount: allFindings.filter((f) => f.severity === "critical").length,
              highCount: allFindings.filter((f) => f.severity === "high").length,
              subdomainsFound: mergedSubdomains.length,
              verifiedOnly: true,
              mode: scanMode,
            },
          });

          try {
            const modules = await storage.getReconModules(workspaceId);
            const attackSurface = modules.find((m) => m.moduleType === "attack_surface")?.data as Record<string, unknown> | undefined;
            const assetInventory = (attackSurface?.assetInventory || []) as Array<{ riskScore: number; waf: string }>;
            const totalHosts = assetInventory.length || 0;
            const wafCoverage = totalHosts > 0 ? Math.round((assetInventory.filter((a) => a.waf).length / totalHosts) * 100) : null;
            const tlsPosture = attackSurface?.tlsPosture as { grade?: string } | undefined;
            await storage.createPostureSnapshot({
              workspaceId,
              scanId: scan.id,
              target,
              snapshotAt: new Date(),
              surfaceRiskScore: attackSurface?.surfaceRiskScore as number | undefined ?? null,
              tlsGrade: tlsPosture?.grade ?? null,
              securityScore: allFindings.length > 0 ? computeSecurityScore(allFindings) : null,
              findingsCount: allFindings.length,
              criticalCount: allFindings.filter((f) => f.severity === "critical").length,
              highCount: allFindings.filter((f) => f.severity === "high").length,
              openPortsCount: 0,
              wafCoverage,
              metadata: { mode: scanMode },
            });
          } catch (snapErr) {
            const err = snapErr instanceof Error ? snapErr : new Error(String(snapErr));
            console.error("[Scan] Posture snapshot error:", err.message, err.stack);
          }

          if (autoGenerateReport) {
            try {
              const reportTitle = `Scan Report: ${target} - ${new Date().toLocaleDateString()}`;
              const report = await storage.createReport({
                workspaceId,
                title: reportTitle,
                type: "full_report",
                status: "generating",
                findingIds: createdFindingIds.length > 0 ? createdFindingIds : undefined,
              });
              const { content, summary } = await buildReportContent(workspaceId, report.findingIds ?? undefined, report.type);
              await storage.updateReport(report.id, {
                status: "completed",
                content,
                summary,
                generatedAt: new Date(),
              });
            } catch (reportErr) {
              console.error("Auto-generate report error:", reportErr);
            }
          }

          (async () => {
            try {
              const findings = await storage.getFindings(workspaceId);
              const toEnrich = findings
                .filter((f) => (f.severity === "critical" || f.severity === "high") && !(f.aiEnrichment as Record<string, unknown>)?.enhancedDescription)
                .slice(0, 2);
              const modules = await storage.getReconModules(workspaceId);
              for (const f of toEnrich) {
                try {
                  const result = await enrichFinding(f, modules);
                  const existing = (f.aiEnrichment as Record<string, unknown>) ?? {};
                  await storage.updateFinding(f.id, {
                    aiEnrichment: { ...existing, ...result, enrichedAt: new Date().toISOString() },
                  });
                } catch {
                  /* skip failed enrichment */
                }
              }
            } catch {
              /* batch enrichment is best-effort */
            }
          })();
        } catch (err) {
          console.error("Scan processing error:", err);
          try {
            await storage.updateScan(scan.id, {
              status: "failed",
              completedAt: new Date(),
              errorMessage: err instanceof Error ? err.message : String(err),
              progressMessage: null,
              progressPercent: null,
              currentStep: null,
              estimatedSecondsRemaining: null,
            });
          } catch (updateErr) {
            console.error("[Scan] CRITICAL: Failed to mark scan as failed:", updateErr);
          }
        }
      })();

      res.status(201).json({ ...scan, workspaceId });
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
      }
      res.status(400).json({ message: error.message });
    }
  });

  app.get("/api/workspaces/:workspaceId/findings", async (req, res) => {
    try {
      const all = await storage.getFindings(req.params.workspaceId);
      const { severity, status, search, page, pageSize } = req.query;

      let filtered = all as Array<Record<string, unknown>>;
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

  app.get("/api/findings/:id", async (req, res) => {
    try {
      const finding = await storage.getFinding(req.params.id);
      if (!finding) return res.status(404).json({ message: "Finding not found" });
      res.json(finding);
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  app.patch("/api/findings/:id", async (req, res) => {
    try {
      const parsed = updateFindingSchema.parse(req.body);
      const updated = await storage.updateFinding(req.params.id, parsed);
      if (!updated) return res.status(404).json({ message: "Finding not found" });
      res.json(updated);
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
      }
      res.status(400).json({ message: error.message });
    }
  });

  app.post("/api/workspaces/:workspaceId/findings/:id/enrich", async (req, res) => {
    res.setTimeout(1800000); // 30 min for Ollama
    try {
      const finding = await storage.getFinding(req.params.id);
      if (!finding) return res.status(404).json({ message: "Finding not found" });
      if (finding.workspaceId !== req.params.workspaceId) return res.status(404).json({ message: "Finding not found" });
      const modules = await storage.getReconModules(req.params.workspaceId);
      let result: { enhancedDescription: string; contextualRisks?: string; additionalRemediation?: string };
      try {
        result = await enrichFinding(finding, modules);
      } catch (enrichErr) {
        console.warn("[Enrich] Fallback for finding", req.params.id, (enrichErr as Error).message);
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
      console.warn("[Enrich] Error:", err instanceof Error ? err.message : err);
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

  app.get("/api/workspaces/:workspaceId/ai-insights", async (req, res) => {
    try {
      const { workspaceId } = req.params;
      const ws = await storage.getWorkspace(workspaceId);
      if (!ws) return res.status(404).json({ message: "Workspace not found" });
      const [findings, modules] = await Promise.all([
        storage.getFindings(workspaceId),
        storage.getReconModules(workspaceId),
      ]);
      res.json({ findings, modules, workspaceName: ws.name });
    } catch (err) {
      console.error("AI insights error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Failed to load" });
    }
  });

  app.post("/api/workspaces/:workspaceId/ai-insights/summary", async (req, res) => {
    res.setTimeout(1800000); // 30 min for Ollama inference
    try {
      const { workspaceId } = req.params;
      const ws = await storage.getWorkspace(workspaceId);
      if (!ws) return res.status(404).json({ message: "Workspace not found" });
      const [findings, modules] = await Promise.all([
        storage.getFindings(workspaceId),
        storage.getReconModules(workspaceId),
      ]);
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
      console.warn("[AI insights] Error, returning fallback:", msg);
      try {
        const ws = await storage.getWorkspace(req.params.workspaceId);
        if (ws) {
          const [findings, modules] = await Promise.all([
            storage.getFindings(req.params.workspaceId),
            storage.getReconModules(req.params.workspaceId),
          ]);
          const fallback = buildFallbackInsights(findings, modules, ws.name);
          const reason =
            msg === "Ollama AI is disabled"
              ? "ollama_disabled"
              : msg.includes("aborted") || msg.includes("timed out")
                ? "ollama_timeout"
                : "ollama_error";
          return res.json({ ...fallback, fallbackReason: reason, fallbackErrorDetail });
        }
      } catch (innerErr) {
        console.error("[AI insights] Fallback failed:", innerErr);
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

  app.post("/api/workspaces/:workspaceId/findings/:id/cve-lookup", async (req, res) => {
    try {
      const { workspaceId, id } = req.params;
      const finding = await storage.getFinding(id);
      if (!finding || finding.workspaceId !== workspaceId) return res.status(404).json({ message: "Finding not found" });
      const modules = await storage.getReconModules(workspaceId);
      let cveRecords: Awaited<ReturnType<typeof getCVEForFinding>>;
      try {
        cveRecords = await getCVEForFinding(finding, modules);
      } catch (cveErr) {
        console.warn("[CVE] Lookup failed for finding", id, (cveErr as Error).message);
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
      console.error("CVE lookup error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "CVE lookup failed" });
    }
  });

  app.post("/api/workspaces/:workspaceId/findings/:id/analyze", async (req, res) => {
    res.setTimeout(1800000); // 30 min for Ollama
    try {
      const { workspaceId, id } = req.params;
      const finding = await storage.getFinding(id);
      if (!finding || finding.workspaceId !== workspaceId) return res.status(404).json({ message: "Finding not found" });
      const modules = await storage.getReconModules(workspaceId);
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
      console.warn("[Analyze] Error:", err instanceof Error ? err.message : err);
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

  app.post("/api/workspaces/:workspaceId/findings/enrich-all", async (req, res) => {
    res.setTimeout(3600000); // 60 min for batch (many findings x 30 min each)
    try {
      const findingsList = await storage.getFindings(req.params.workspaceId);
      const modules = await storage.getReconModules(req.params.workspaceId);
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
      console.warn("[Enrich-all] Error:", err instanceof Error ? err.message : err);
      const findingsList = await storage.getFindings(req.params.workspaceId).catch(() => []);
      res.json({ enriched: 0, total: findingsList.length, partial: true });
    }
  });

  app.get("/api/workspaces/:workspaceId/reports", async (req, res) => {
    try {
      const reportsList = await storage.getReports(req.params.workspaceId);
      res.json(reportsList);
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  app.get("/api/reports/:id", async (req, res) => {
    try {
      const report = await storage.getReport(req.params.id);
      if (!report) return res.status(404).json({ message: "Report not found" });
      res.json(report);
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  app.get("/api/workspaces/:workspaceId/reports/:reportId/export", async (req, res) => {
    try {
      const report = await storage.getReport(req.params.reportId);
      if (!report) return res.status(404).json({ message: "Report not found" });
      if (report.workspaceId !== req.params.workspaceId) return res.status(404).json({ message: "Report not found" });
      if (report.status !== "completed") return res.status(400).json({ message: "Report not yet completed" });

      const findings = await storage.getFindings(req.params.workspaceId);
      const reportFindings = findings
        .filter((f) => (report.findingIds || []).includes(f.id))
        .map((f) => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          status: f.status,
          category: f.category,
          affectedAsset: f.affectedAsset,
          description: f.description,
        }));

      const exportInput = {
        title: report.title,
        summary: report.summary ?? "",
        generatedAt: report.generatedAt?.toISOString?.() ?? (report.generatedAt as string | null),
        content: report.content as Record<string, unknown> | null,
        findings: reportFindings,
      };

      const format = (req.query.format as string) || "pdf";
      const safeTitle = (report.title || "security-report").replace(/[^a-zA-Z0-9-_]/g, "-").replace(/-+/g, "-").toLowerCase();

      if (format === "csv") {
        const { generateReportCsv } = await import("./report-export.js");
        const csv = generateReportCsv(exportInput);
        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", `attachment; filename="${safeTitle}.csv"`);
        res.send(csv);
        return;
      }

      if (format === "xlsx" || format === "excel") {
        const { generateReportExcel } = await import("./report-export.js");
        const xlsxBuffer = generateReportExcel(exportInput);
        res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        res.setHeader("Content-Disposition", `attachment; filename="${safeTitle}.xlsx"`);
        res.send(xlsxBuffer);
        return;
      }

      const { generateReportPdfBuffer } = await import("./report-pdf.js");
      const pdfBuffer = generateReportPdfBuffer({
        ...exportInput,
        findings: reportFindings.map((f) => ({ id: f.id, title: f.title, severity: f.severity, affectedAsset: f.affectedAsset })),
      });
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="${safeTitle}.pdf"`);
      res.send(pdfBuffer);
    } catch (err) {
      console.error("Report export error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Export failed" });
    }
  });

  app.delete("/api/workspaces/:workspaceId/reports/:reportId", async (req, res) => {
    try {
      const report = await storage.getReport(req.params.reportId);
      if (!report) return res.status(404).json({ message: "Report not found" });
      if (report.workspaceId !== req.params.workspaceId) return res.status(404).json({ message: "Report not found" });
      await storage.deleteReport(req.params.reportId);
      res.status(204).send();
    } catch (err) {
      console.error("Delete report error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Failed to delete report" });
    }
  });

  app.post("/api/continuous-monitoring/start", async (req, res) => {
    try {
      const parsed = startContinuousMonitoringSchema.parse(req.body);
      const result = await startMonitoring(parsed.target, parsed.workspaceId);
      res.status(201).json(result);
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
      }
      res.status(400).json({ message: error.message });
    }
  });

  app.post("/api/continuous-monitoring/stop", async (req, res) => {
    try {
      const parsed = stopContinuousMonitoringSchema.parse(req.body);
      const stopped = stopMonitoring(parsed.workspaceId);
      res.status(200).json({ stopped });
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
      }
      res.status(400).json({ message: error.message });
    }
  });

  app.get("/api/continuous-monitoring/status/:workspaceId", async (req, res) => {
    try {
      const status = getMonitoringStatus(req.params.workspaceId);
      res.json(status);
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  app.get("/api/workspaces/:workspaceId/recon-modules", async (req, res) => {
    try {
      const modules = await storage.getReconModules(req.params.workspaceId);
      res.json(modules);
    } catch (err) {
      console.error("Get recon modules error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
    }
  });

  app.get("/api/workspaces/:workspaceId/posture-history", async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 30, 100);
      const snapshots = await storage.getPostureHistory(req.params.workspaceId, limit);
      res.json(snapshots);
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  app.post("/api/workspaces/:workspaceId/posture-history/backfill", async (req, res) => {
    try {
      const workspaceId = req.params.workspaceId;
      const [scans, existingSnapshots, modules, allFindings] = await Promise.all([
        storage.getScans(workspaceId),
        storage.getPostureHistory(workspaceId, 500),
        storage.getReconModules(workspaceId),
        storage.getFindings(workspaceId),
      ]);
      const snapshotScanIds = new Set((existingSnapshots ?? []).map((s) => s.scanId).filter(Boolean));
      const completedScans = scans.filter((s) => s.status === "completed" && s.completedAt && !snapshotScanIds.has(s.id));
      const attackSurface = modules.find((m) => m.moduleType === "attack_surface")?.data as Record<string, unknown> | undefined;
      const assetInventory = (attackSurface?.assetInventory || []) as Array<{ riskScore: number; waf: string }>;
      const totalHosts = assetInventory.length || 0;
      const wafCoverage = totalHosts > 0 ? Math.round((assetInventory.filter((a) => a.waf).length / totalHosts) * 100) : null;
      const tlsPosture = attackSurface?.tlsPosture as { grade?: string } | undefined;
      let created = 0;
      for (const scan of completedScans) {
        const scanFindings = allFindings.filter((f) => f.scanId === scan.id);
        try {
          await storage.createPostureSnapshot({
            workspaceId,
            scanId: scan.id,
            target: scan.target,
            snapshotAt: scan.completedAt ?? new Date(),
            surfaceRiskScore: attackSurface?.surfaceRiskScore as number | undefined ?? null,
            tlsGrade: tlsPosture?.grade ?? null,
            securityScore: scanFindings.length > 0 ? computeSecurityScore(scanFindings) : null,
            findingsCount: scanFindings.length,
            criticalCount: scanFindings.filter((f) => f.severity === "critical").length,
            highCount: scanFindings.filter((f) => f.severity === "high").length,
            openPortsCount: 0,
            wafCoverage,
            metadata: (scan.summary as Record<string, unknown>) ?? {},
          });
          created++;
        } catch (err) {
          console.error(`[Backfill] Posture snapshot for scan ${scan.id}:`, err instanceof Error ? err.message : err);
        }
      }
      const snapshots = await storage.getPostureHistory(workspaceId, 30);
      res.json({ created, snapshots });
    } catch (err) {
      console.error("[Backfill] Posture history backfill error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Backfill failed" });
    }
  });

  app.get("/api/recon-modules/:id", async (req, res) => {
    try {
      const mod = await storage.getReconModule(req.params.id);
      if (!mod) return res.status(404).json({ message: "Module not found" });
      res.json(mod);
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  app.get("/api/workspaces/:workspaceId/ip-enrichment", async (req, res) => {
    try {
      const workspaceId = req.params.workspaceId;
      const ipAssets = await storage.getAssets(workspaceId);
      const ipsFromAssets = ipAssets.filter((a) => a.type === "ip").map((a) => a.value);
      const modules = await storage.getReconModules(workspaceId);
      const attackSurface = modules.find((m) => m.moduleType === "attack_surface")?.data as Record<string, unknown> | undefined;
      const publicIPs = attackSurface?.publicIPs as Array<{ ip: string }> | undefined;
      const ipsFromSurface = (publicIPs ?? []).map((p) => (typeof p === "string" ? p : p?.ip)).filter(Boolean);
      const allIPs = Array.from(new Set([...ipsFromAssets, ...ipsFromSurface]));
      const ipEnrichment = allIPs.length > 0 ? await enrichIPs(allIPs) : {};
      res.json(ipEnrichment);
    } catch (err) {
      console.error("IP enrichment error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "IP enrichment failed" });
    }
  });

  // Scan comparison: diff findings between two scans
  app.get("/api/workspaces/:workspaceId/scan-diff", async (req, res) => {
    try {
      const { scan1, scan2 } = req.query;
      if (!scan1 || !scan2 || typeof scan1 !== "string" || typeof scan2 !== "string") {
        return res.status(400).json({ message: "scan1 and scan2 query params required" });
      }
      const allFindings = await storage.getFindings(req.params.workspaceId as string);
      const s1Findings = allFindings.filter((f) => f.scanId === scan1);
      const s2Findings = allFindings.filter((f) => f.scanId === scan2);
      const s1Keys = new Set(s1Findings.map((f) => `${f.title}|${f.affectedAsset}|${f.category}`));
      const s2Keys = new Set(s2Findings.map((f) => `${f.title}|${f.affectedAsset}|${f.category}`));
      const newFindings = s2Findings.filter((f) => !s1Keys.has(`${f.title}|${f.affectedAsset}|${f.category}`));
      const resolvedFindings = s1Findings.filter((f) => !s2Keys.has(`${f.title}|${f.affectedAsset}|${f.category}`));
      const persistent = s2Findings.filter((f) => s1Keys.has(`${f.title}|${f.affectedAsset}|${f.category}`));
      res.json({ scan1: scan1, scan2: scan2, new: newFindings, resolved: resolvedFindings, persistent, summary: { newCount: newFindings.length, resolvedCount: resolvedFindings.length, persistentCount: persistent.length } });
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  app.get("/api/integrations/status", (_req, res) => {
    res.json(getIntegrationsStatus());
  });

  app.get("/api/ollama/status", async (_req, res) => {
    try {
      const status = await getOllamaStatus();
      res.json(status);
    } catch {
      res.json({ reachable: false });
    }
  });

  const STUCK_SCAN_AGE_MS = 2 * 60 * 60 * 1000; // 2 hours
  app.post("/api/admin/recover-stuck-scans", async (_req, res) => {
    try {
      const stuck = await storage.getStuckScans(STUCK_SCAN_AGE_MS);
      for (const s of stuck) {
        await storage.updateScan(s.id, {
          status: "failed",
          completedAt: new Date(),
          errorMessage: "Scan timed out or server was restarted (recovered manually)",
          progressMessage: null,
          progressPercent: null,
          currentStep: null,
          estimatedSecondsRemaining: null,
        });
      }
      res.json({ recovered: stuck.length, scanIds: stuck.map((s) => s.id) });
    } catch (err) {
      console.error("Recover stuck scans error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Failed to recover stuck scans" });
    }
  });

  app.post("/api/admin/shutdown", (_req, res) => {
    res.status(200).json({ message: "Shutting down..." });
    res.end();
    setTimeout(() => {
      httpServer.close(() => {
        process.exit(0);
      });
      setTimeout(() => process.exit(0), 3000);
    }, 500);
  });

  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 },
  });

  app.get("/api/workspaces/:workspaceId/imports", async (req, res) => {
    try {
      const ws = await storage.getWorkspace(req.params.workspaceId);
      if (!ws) return res.status(404).json({ message: "Workspace not found" });
      const scans = await storage.getUploadedScans(req.params.workspaceId);
      res.json(scans);
    } catch (err) {
      console.error("List imports error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Failed to list imports" });
    }
  });

  app.post("/api/workspaces/:workspaceId/imports", upload.single("file"), async (req, res) => {
    try {
      const ws = await storage.getWorkspace(req.params.workspaceId as string);
      if (!ws) return res.status(404).json({ message: "Workspace not found" });
      const file = req.file as Express.Multer.File | undefined;
      if (!file || !file.buffer) return res.status(400).json({ message: "No file uploaded" });
      const fileType = (req.body?.fileType as string) || "nmap";
      const validTypes = ["nmap", "nikto", "generic"];
      const type = validTypes.includes(fileType) ? fileType : "generic";
      const rawContent = file.buffer.toString("utf-8");
      const parsed = parseNmap(rawContent, type as "nmap" | "nikto" | "generic");
      const scan = await storage.createUploadedScan({
        workspaceId: req.params.workspaceId as string,
        filename: file.originalname,
        fileType: type,
        rawContent,
        parsedData: { hosts: parsed.hosts, rawSummary: parsed.rawSummary } as Record<string, unknown>,
      });
      res.status(201).json(scan);
    } catch (err) {
      console.error("Upload import error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Failed to upload" });
    }
  });

  app.post("/api/workspaces/:workspaceId/imports/:id/consolidate", async (req, res) => {
    try {
      const { workspaceId, id } = req.params;
      const ws = await storage.getWorkspace(workspaceId);
      if (!ws) return res.status(404).json({ message: "Workspace not found" });
      const scan = await storage.getUploadedScan(id);
      if (!scan || scan.workspaceId !== workspaceId) return res.status(404).json({ message: "Import not found" });
      const existingFindings = await storage.getFindings(workspaceId);
      const parsedData = scan.parsedData as { hosts?: Array<{ address: string; hostname?: string; ports: Array<{ port: number; protocol: string; state: string; service?: string; version?: string }> }>; rawSummary?: string } | null;
      const textForAI = parsedData?.hosts?.length
        ? nmapToTextSummary({ hosts: parsedData.hosts, rawSummary: parsedData.rawSummary })
        : scan.rawContent.slice(0, 12000);
      const result = await consolidateScanResults(textForAI, existingFindings, ws.name);
      for (const nf of result.newFindings) {
        await storage.createFinding({
          workspaceId,
          title: nf.title,
          description: nf.description,
          severity: nf.severity,
          category: nf.category,
          affectedAsset: nf.affectedAsset,
          remediation: nf.remediation,
        });
      }
      for (const mu of result.mergedUpdates) {
        await storage.updateFinding(mu.findingId, mu.updates);
      }
      res.json({ newCount: result.newFindings.length, mergedCount: result.mergedUpdates.length });
    } catch (err) {
      console.error("Consolidate error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Consolidation failed" });
    }
  });

  app.delete("/api/workspaces/:workspaceId/imports/:id", async (req, res) => {
    try {
      const scan = await storage.getUploadedScan(req.params.id);
      if (!scan || scan.workspaceId !== req.params.workspaceId) return res.status(404).json({ message: "Import not found" });
      await storage.deleteUploadedScan(req.params.id);
      res.status(200).json({ deleted: true });
    } catch (err) {
      console.error("Delete import error:", err);
      res.status(500).json({ message: err instanceof Error ? err.message : "Failed to delete" });
    }
  });

  app.post("/api/workspaces/:workspaceId/reports", async (req, res) => {
    try {
      const parsed = createReportSchema.parse({ ...req.body, workspaceId: req.params.workspaceId });
      const report = await storage.createReport(parsed);

      setTimeout(async () => {
        try {
          await storage.updateReport(report.id, { status: "generating" });
          const { content, summary } = await buildReportContent(req.params.workspaceId, report.findingIds ?? undefined, report.type);
          await storage.updateReport(report.id, {
            status: "completed",
            content,
            summary,
            generatedAt: new Date(),
          });
        } catch (err) {
          console.error("Report generation error:", err);
          await storage.updateReport(report.id, { status: "draft" });
        }
      }, 2000);

      res.status(201).json(report);
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
      }
      res.status(400).json({ message: error.message });
    }
  });

  // Auto-recover stuck scans on startup
  (async () => {
    try {
      const stuck = await storage.getStuckScans(STUCK_SCAN_AGE_MS);
      if (stuck.length > 0) {
        for (const s of stuck) {
          await storage.updateScan(s.id, {
            status: "failed",
            completedAt: new Date(),
            errorMessage: "Scan interrupted by server restart (auto-recovered)",
            progressMessage: null,
            progressPercent: null,
            currentStep: null,
            estimatedSecondsRemaining: null,
          });
        }
        console.log(`[startup] Auto-recovered ${stuck.length} stuck scan(s): ${stuck.map(s => s.id.slice(0, 8)).join(", ")}`);
      }
    } catch (err) {
      console.error("[startup] Failed to recover stuck scans:", err);
    }
  })();

  return httpServer;
}
