import { Router } from "express";
import { z } from "zod";
import type { Server } from "http";
import { eq } from "drizzle-orm";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { computeSecurityScore } from "@shared/scoring";
import { startMonitoring, stopMonitoring, getMonitoringStatus } from "../continuous-monitoring";
import { enrichIPs, getIntegrationsStatus, setApiKey, setOllamaConfig } from "../api-integrations";
import { getOllamaStatus } from "../ai-service";
import { requireAdmin } from "./middleware";
import { requireWorkspaceRole } from "./auth-middleware";
import { startContinuousMonitoringSchema, stopContinuousMonitoringSchema } from "./schemas";
import { getQueueStatus } from "../scan-queue";
import { db } from "../db";
import { workspaceMembers } from "@shared/schema";

const routeLog = createLogger("routes");

const STUCK_SCAN_AGE_MS = 2 * 60 * 60 * 1000; // 2 hours

export function createAdminRouter(httpServer: Server): Router {
  const adminRouter = Router();

  const wsAuth = requireWorkspaceRole("owner", "admin", "analyst", "viewer");
  const wsOwnerAdmin = requireWorkspaceRole("owner", "admin");

  adminRouter.get("/integrations/status", requireAdmin, (_req, res) => {
    res.json(getIntegrationsStatus());
  });

  // POST /api/integrations — update API keys and Ollama config
  const updateIntegrationsSchema = z.object({
    abuseipdb: z.string().optional(),
    virustotal: z.string().optional(),
    tavily: z.string().optional(),
    ollamaBaseUrl: z.string().optional(),
    ollamaModel: z.string().optional(),
    ollamaEnabled: z.boolean().optional(),
  });
  adminRouter.post("/integrations", requireAdmin, (req, res) => {
    try {
      const parsed = updateIntegrationsSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: parsed.error.errors[0]?.message ?? "Validation error" });
      }
      const { abuseipdb, virustotal, tavily, ollamaBaseUrl, ollamaModel, ollamaEnabled } = parsed.data;
      if (abuseipdb !== undefined) setApiKey("abuseipdb", abuseipdb);
      if (virustotal !== undefined) setApiKey("virustotal", virustotal);
      if (tavily !== undefined) setApiKey("tavily", tavily);
      if (ollamaBaseUrl !== undefined || ollamaModel !== undefined || ollamaEnabled !== undefined) {
        setOllamaConfig({ baseUrl: ollamaBaseUrl, model: ollamaModel, enabled: ollamaEnabled });
      }
      res.json(getIntegrationsStatus());
    } catch (err) {
      routeLog.error({ err }, "Update integrations error");
      res.status(500).json({ message: "Internal server error" });
    }
  });

  adminRouter.get("/ollama/status", requireAdmin, async (_req, res) => {
    try {
      const status = await getOllamaStatus();
      res.json(status);
    } catch {
      res.json({ reachable: false });
    }
  });

  // POST /api/admin/claim-orphan-workspaces
  // Assigns all workspaces with no members to the calling superadmin user.
  // Use this once after upgrading from a version that didn't track workspace membership.
  adminRouter.post("/admin/claim-orphan-workspaces", requireAdmin, async (req, res) => {
    try {
      const allWorkspaces = await storage.getWorkspaces();
      const claimed: string[] = [];
      for (const ws of allWorkspaces) {
        const existing = await storage.getWorkspaceMember(ws.id, req.user!.id);
        if (!existing) {
          // Check if workspace has ANY members first
          const members = await db.select().from(workspaceMembers).where(eq(workspaceMembers.workspaceId, ws.id)).limit(1);
          if (members.length === 0) {
            await storage.addWorkspaceMember(ws.id, req.user!.id, "owner");
            claimed.push(ws.id);
          }
        }
      }
      res.json({ claimed: claimed.length, workspaceIds: claimed });
    } catch (err) {
      routeLog.error({ err }, "Claim orphan workspaces error");
      res.status(500).json({ message: "Failed to claim orphan workspaces" });
    }
  });

  adminRouter.post("/admin/recover-stuck-scans", requireAdmin, async (_req, res) => {
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
      routeLog.error({ err }, "Recover stuck scans error");
      res.status(500).json({ message: "Failed to recover stuck scans" });
    }
  });

  adminRouter.post("/admin/shutdown", requireAdmin, (_req, res) => {
    res.status(200).json({ message: "Shutting down..." });
    res.end();
    setTimeout(() => {
      httpServer.close(() => {
        process.exit(0);
      });
      setTimeout(() => process.exit(0), 3000);
    }, 500);
  });

  adminRouter.post("/continuous-monitoring/start", wsOwnerAdmin, async (req, res) => {
    try {
      const parsed = startContinuousMonitoringSchema.parse(req.body);
      const result = await startMonitoring(parsed.target, parsed.workspaceId, req.user!.id);
      res.status(201).json(result);
    } catch (error: unknown) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
      }
      res.status(400).json({ message: "Bad request" });
    }
  });

  adminRouter.post("/continuous-monitoring/stop", wsOwnerAdmin, async (req, res) => {
    try {
      const parsed = stopContinuousMonitoringSchema.parse(req.body);
      const stopped = stopMonitoring(parsed.workspaceId);
      res.status(200).json({ stopped });
    } catch (error: unknown) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
      }
      res.status(400).json({ message: "Bad request" });
    }
  });

  adminRouter.get("/continuous-monitoring/status/:workspaceId", wsAuth, async (req, res) => {
    try {
      const status = getMonitoringStatus(req.params.workspaceId as string);
      res.json(status);
    } catch (err) { res.status(500).json({ message: "Internal server error" }); }
  });

  adminRouter.get("/workspaces/:workspaceId/recon-modules", wsAuth, async (req, res) => {
    try {
      const limit = Math.min(parseInt(String(req.query.limit ?? "500"), 10) || 500, 5000);
      const offset = Math.max(parseInt(String(req.query.offset ?? "0"), 10) || 0, 0);
      const result = await storage.getReconModules(req.params.workspaceId as string, { limit, offset });
      res.json(result);
    } catch (err) {
      routeLog.error({ err }, "Get recon modules error");
      res.status(500).json({ message: "Internal server error" });
    }
  });

  adminRouter.get("/recon-modules/:id", async (req, res) => {
    try {
      const mod = await storage.getReconModule(req.params.id);
      if (!mod) return res.status(404).json({ message: "Module not found" });
      // Verify caller is a member of the module's workspace
      const membership = await storage.getWorkspaceMember(mod.workspaceId, req.user!.id);
      if (!membership) return res.status(404).json({ message: "Module not found" });
      res.json(mod);
    } catch (err) { res.status(500).json({ message: "Internal server error" }); }
  });

  adminRouter.get("/workspaces/:workspaceId/posture-history", wsAuth, async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 30, 100);
      const snapshots = await storage.getPostureHistory(req.params.workspaceId as string, limit);
      res.json(snapshots);
    } catch (err) { res.status(500).json({ message: "Internal server error" }); }
  });

  adminRouter.post("/workspaces/:workspaceId/posture-history/backfill", wsAuth, async (req, res) => {
    try {
      const workspaceId = req.params.workspaceId as string;
      const [scansResult, existingSnapshots, modulesResult, findingsResult] = await Promise.all([
        storage.getScans(workspaceId),
        storage.getPostureHistory(workspaceId, 500),
        storage.getReconModules(workspaceId),
        storage.getFindings(workspaceId),
      ]);
      const allFindings = findingsResult.data;
      const snapshotScanIds = new Set((existingSnapshots ?? []).map((s) => s.scanId).filter(Boolean));
      const completedScans = scansResult.data.filter((s) => s.status === "completed" && s.completedAt && !snapshotScanIds.has(s.id));
      const attackSurface = modulesResult.data.find((m) => m.moduleType === "attack_surface")?.data as Record<string, unknown> | undefined;
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
          routeLog.error({ err, scanId: scan.id }, "Backfill posture snapshot error");
        }
      }
      const snapshots = await storage.getPostureHistory(workspaceId, 30);
      res.json({ created, snapshots });
    } catch (err) {
      routeLog.error({ err }, "Posture history backfill error");
      res.status(500).json({ message: "Backfill failed" });
    }
  });

  adminRouter.get("/workspaces/:workspaceId/ip-enrichment", wsAuth, async (req, res) => {
    try {
      const workspaceId = req.params.workspaceId as string;
      const { data: ipAssets } = await storage.getAssets(workspaceId);
      const ipsFromAssets = ipAssets.filter((a) => a.type === "ip").map((a) => a.value);
      const { data: modules } = await storage.getReconModules(workspaceId);
      const attackSurface = modules.find((m) => m.moduleType === "attack_surface")?.data as Record<string, unknown> | undefined;
      const publicIPs = attackSurface?.publicIPs as Array<{ ip: string }> | undefined;
      const ipsFromSurface = (publicIPs ?? []).map((p) => (typeof p === "string" ? p : p?.ip)).filter(Boolean);
      const allIPs = Array.from(new Set([...ipsFromAssets, ...ipsFromSurface]));
      const ipEnrichment = allIPs.length > 0 ? await enrichIPs(allIPs) : {};
      res.json(ipEnrichment);
    } catch (err) {
      routeLog.error({ err }, "IP enrichment error");
      res.status(500).json({ message: "IP enrichment failed" });
    }
  });

  // Scan comparison: diff findings between two scans
  adminRouter.get("/workspaces/:workspaceId/scan-diff", wsAuth, async (req, res) => {
    try {
      const { scan1, scan2 } = req.query;
      if (!scan1 || !scan2 || typeof scan1 !== "string" || typeof scan2 !== "string") {
        return res.status(400).json({ message: "scan1 and scan2 query params required" });
      }
      const { data: diffFindings } = await storage.getFindings(req.params.workspaceId as string);
      const s1Findings = diffFindings.filter((f) => f.scanId === scan1);
      const s2Findings = diffFindings.filter((f) => f.scanId === scan2);
      const s1Keys = new Set(s1Findings.map((f) => `${f.title}|${f.affectedAsset}|${f.category}`));
      const s2Keys = new Set(s2Findings.map((f) => `${f.title}|${f.affectedAsset}|${f.category}`));
      const newFindings = s2Findings.filter((f) => !s1Keys.has(`${f.title}|${f.affectedAsset}|${f.category}`));
      const resolvedFindings = s1Findings.filter((f) => !s2Keys.has(`${f.title}|${f.affectedAsset}|${f.category}`));
      const persistent = s2Findings.filter((f) => s1Keys.has(`${f.title}|${f.affectedAsset}|${f.category}`));
      res.json({ scan1: scan1, scan2: scan2, new: newFindings, resolved: resolvedFindings, persistent, summary: { newCount: newFindings.length, resolvedCount: resolvedFindings.length, persistentCount: persistent.length } });
    } catch (err) { res.status(500).json({ message: "Internal server error" }); }
  });

  // GET /api/status — machine-readable health board (no admin required, just auth)
  adminRouter.get("/status", async (_req, res) => {
    try {
      const queue = getQueueStatus();
      const integrations = getIntegrationsStatus();
      let ollamaReachable = false;
      try { const s = await getOllamaStatus(); ollamaReachable = s.reachable ?? false; } catch { /* ignore */ }

      res.json({
        ok: true,
        version: "1.0.0",
        uptime: Math.floor(process.uptime()),
        db: "ok",
        queue: {
          pending: queue.queueLength,
          running: queue.activeScans,
          maxConcurrent: queue.maxConcurrent,
        },
        ollama: { reachable: ollamaReachable },
        integrations: {
          jira: (integrations as Record<string, unknown>).jira ?? false,
          github: (integrations as Record<string, unknown>).github ?? false,
          shodan: (integrations as Record<string, unknown>).shodan ?? false,
          virustotal: (integrations as Record<string, unknown>).virustotal ?? false,
        },
      });
    } catch (err) {
      routeLog.error({ err }, "Status check error");
      res.status(500).json({ ok: false, error: "Status check failed" });
    }
  });

  // POST /api/admin/doctor — preflight diagnostics (requireAdmin)
  adminRouter.post("/admin/doctor", requireAdmin, async (_req, res) => {
    const checks: Array<{ name: string; status: "pass" | "fail" | "skip"; detail?: string }> = [];

    // 1. Database connectivity
    try {
      await db.execute("SELECT 1" as unknown as Parameters<typeof db.execute>[0]);
      checks.push({ name: "database", status: "pass" });
    } catch (err) {
      checks.push({ name: "database", status: "fail", detail: err instanceof Error ? err.message.slice(0, 100) : "Unknown" });
    }

    // 2. workspace_members table
    try {
      await db.execute("SELECT 1 FROM workspace_members LIMIT 1" as unknown as Parameters<typeof db.execute>[0]);
      checks.push({ name: "workspace_members_table", status: "pass" });
    } catch {
      checks.push({ name: "workspace_members_table", status: "fail", detail: "Table missing — run npm run db:push" });
    }

    // 3. sessions table
    try {
      await db.execute("SELECT 1 FROM sessions LIMIT 1" as unknown as Parameters<typeof db.execute>[0]);
      checks.push({ name: "sessions_table", status: "pass" });
    } catch {
      checks.push({ name: "sessions_table", status: "fail", detail: "Table missing — run npm run db:push" });
    }

    // 4. Ollama
    try {
      const status = await getOllamaStatus();
      checks.push({ name: "ollama", status: status.reachable ? "pass" : "skip", detail: status.reachable ? undefined : "Not reachable (optional)" });
    } catch {
      checks.push({ name: "ollama", status: "skip", detail: "Not reachable (optional)" });
    }

    // 5. Integration config presence (pass/fail/skip — no secrets exposed)
    const integrations = getIntegrationsStatus() as Record<string, unknown>;
    const jiraConfigured = !!(integrations.jira);
    const githubConfigured = !!(integrations.github);
    checks.push({ name: "jira_config", status: jiraConfigured ? "pass" : "skip", detail: jiraConfigured ? undefined : "Not configured (optional)" });
    checks.push({ name: "github_config", status: githubConfigured ? "pass" : "skip", detail: githubConfigured ? undefined : "Not configured (optional)" });

    // 6. Scan queue health
    const queue = getQueueStatus();
    checks.push({ name: "scan_queue", status: "pass", detail: `pending=${queue.queueLength} running=${queue.activeScans}/${queue.maxConcurrent}` });

    const failures = checks.filter(c => c.status === "fail");
    const overall = failures.length === 0 ? "ok" : failures.some(c => ["database", "sessions_table"].includes(c.name)) ? "critical" : "degraded";

    res.json({ overall, checks });
  });

  return adminRouter;
}
