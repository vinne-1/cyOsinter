import { Router } from "express";
import { z } from "zod";
import type { Server } from "http";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { computeSecurityScore } from "@shared/scoring";
import { startMonitoring, stopMonitoring, getMonitoringStatus } from "../continuous-monitoring";
import { enrichIPs, getIntegrationsStatus } from "../api-integrations";
import { getOllamaStatus } from "../ai-service";
import { requireAdmin } from "./middleware";
import { startContinuousMonitoringSchema, stopContinuousMonitoringSchema } from "./schemas";

const routeLog = createLogger("routes");

const STUCK_SCAN_AGE_MS = 2 * 60 * 60 * 1000; // 2 hours

export function createAdminRouter(httpServer: Server): Router {
  const adminRouter = Router();

  adminRouter.get("/integrations/status", (_req, res) => {
    res.json(getIntegrationsStatus());
  });

  adminRouter.get("/ollama/status", async (_req, res) => {
    try {
      const status = await getOllamaStatus();
      res.json(status);
    } catch {
      res.json({ reachable: false });
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
      res.status(500).json({ message: err instanceof Error ? err.message : "Failed to recover stuck scans" });
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

  adminRouter.post("/continuous-monitoring/start", async (req, res) => {
    try {
      const parsed = startContinuousMonitoringSchema.parse(req.body);
      const result = await startMonitoring(parsed.target, parsed.workspaceId);
      res.status(201).json(result);
    } catch (error: unknown) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
      }
      const message = error instanceof Error ? error.message : "Unknown error";
      res.status(400).json({ message });
    }
  });

  adminRouter.post("/continuous-monitoring/stop", async (req, res) => {
    try {
      const parsed = stopContinuousMonitoringSchema.parse(req.body);
      const stopped = stopMonitoring(parsed.workspaceId);
      res.status(200).json({ stopped });
    } catch (error: unknown) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
      }
      const message = error instanceof Error ? error.message : "Unknown error";
      res.status(400).json({ message });
    }
  });

  adminRouter.get("/continuous-monitoring/status/:workspaceId", async (req, res) => {
    try {
      const status = getMonitoringStatus(req.params.workspaceId);
      res.json(status);
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  adminRouter.get("/workspaces/:workspaceId/recon-modules", async (req, res) => {
    try {
      const limit = Math.min(parseInt(String(req.query.limit ?? "500"), 10) || 500, 5000);
      const offset = Math.max(parseInt(String(req.query.offset ?? "0"), 10) || 0, 0);
      const result = await storage.getReconModules(req.params.workspaceId, { limit, offset });
      res.json(result);
    } catch (err) {
      routeLog.error({ err }, "Get recon modules error");
      res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
    }
  });

  adminRouter.get("/recon-modules/:id", async (req, res) => {
    try {
      const mod = await storage.getReconModule(req.params.id);
      if (!mod) return res.status(404).json({ message: "Module not found" });
      res.json(mod);
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  adminRouter.get("/workspaces/:workspaceId/posture-history", async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 30, 100);
      const snapshots = await storage.getPostureHistory(req.params.workspaceId, limit);
      res.json(snapshots);
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  adminRouter.post("/workspaces/:workspaceId/posture-history/backfill", async (req, res) => {
    try {
      const workspaceId = req.params.workspaceId;
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
      res.status(500).json({ message: err instanceof Error ? err.message : "Backfill failed" });
    }
  });

  adminRouter.get("/workspaces/:workspaceId/ip-enrichment", async (req, res) => {
    try {
      const workspaceId = req.params.workspaceId;
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
      res.status(500).json({ message: err instanceof Error ? err.message : "IP enrichment failed" });
    }
  });

  // Scan comparison: diff findings between two scans
  adminRouter.get("/workspaces/:workspaceId/scan-diff", async (req, res) => {
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
    } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
  });

  return adminRouter;
}
