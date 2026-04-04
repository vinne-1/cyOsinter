import type { Express } from "express";
import type { Server } from "http";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { workspacesRouter } from "./workspaces";
import { scansRouter } from "./scans";
import { findingsRouter } from "./findings";
import { reportsRouter } from "./reports";
import { createAdminRouter } from "./admin";
import { importsRouter } from "./imports";
import { alertsRouter } from "./alerts";
import { scheduledScansRouter } from "./scheduled-scans";
import { analyticsRouter } from "./analytics";
import { scanProfilesRouter } from "./scan-profiles";
import { integrationsTicketsRouter } from "./integrations-tickets";
import { authRouter } from "./auth";
import { auditRouter } from "./audit";
import { webhooksRouter } from "./webhooks";
import { apiKeysRouter } from "./api-keys";
import { retentionRouter } from "./retention";
import { findingWorkflowRouter } from "./finding-workflow";
import { scanDiffRouter } from "./scan-diff";
import { playbooksRouter } from "./playbooks";
import { assetRiskRouter } from "./asset-risk";
import { threatIntelRouter } from "./threat-intel";
import { requireAuth } from "./auth-middleware";
import { errorHandler } from "./response";

const routeLog = createLogger("routes");

const STUCK_SCAN_AGE_MS = 2 * 60 * 60 * 1000; // 2 hours

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {

  // ── Public routes (no auth required) ──
  // Auth router is mounted first so /auth/login, /auth/register, /auth/refresh
  // respond before the global requireAuth middleware runs.
  app.use("/api", authRouter);

  // ── Global authentication gate ──
  // Every /api route registered AFTER this line requires a valid session or API key.
  app.use("/api", requireAuth);

  // ── Protected routes ──
  app.use("/api/workspaces", workspacesRouter);
  app.use("/api", scansRouter);
  app.use("/api", findingsRouter);
  app.use("/api", reportsRouter);
  app.use("/api", createAdminRouter(httpServer));
  app.use("/api", importsRouter);
  app.use("/api", alertsRouter);
  app.use("/api", scheduledScansRouter);
  app.use("/api", analyticsRouter);
  app.use("/api", scanProfilesRouter);
  app.use("/api", integrationsTicketsRouter);
  app.use("/api", auditRouter);
  app.use("/api", webhooksRouter);
  app.use("/api", apiKeysRouter);
  app.use("/api", retentionRouter);
  app.use("/api", findingWorkflowRouter);
  app.use("/api", scanDiffRouter);
  app.use("/api", playbooksRouter);
  app.use("/api", assetRiskRouter);
  app.use("/api", threatIntelRouter);

  // Standalone asset routes that don't fit under /api/workspaces
  app.get("/api/assets/:id", async (req, res) => {
    try {
      const asset = await storage.getAsset(req.params.id);
      if (!asset) return res.status(404).json({ message: "Asset not found" });
      // Verify caller is a member of the asset's workspace
      const membership = await storage.getWorkspaceMember(asset.workspaceId, req.user!.id);
      if (!membership) return res.status(404).json({ message: "Asset not found" });
      res.json(asset);
    } catch (err) { res.status(500).json({ message: "Internal server error" }); }
  });

  app.delete("/api/assets/:id", async (req, res) => {
    try {
      const asset = await storage.getAsset(req.params.id);
      if (!asset) return res.status(404).json({ message: "Asset not found" });
      // Verify caller has write access in the asset's workspace
      const membership = await storage.getWorkspaceMember(asset.workspaceId, req.user!.id);
      if (!membership || !["owner", "admin", "analyst"].includes(membership.role)) {
        return res.status(404).json({ message: "Asset not found" });
      }
      await storage.deleteAsset(req.params.id);
      res.status(204).send();
    } catch (err) { res.status(500).json({ message: "Internal server error" }); }
  });

  // Centralized error handler — must be registered after all routes
  app.use("/api", errorHandler);

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
        routeLog.info({ count: stuck.length, scanIds: stuck.map(s => s.id.slice(0, 8)) }, "Auto-recovered stuck scans on startup");
      }
    } catch (err) {
      routeLog.error({ err }, "Failed to recover stuck scans on startup");
    }
  })();

  return httpServer;
}
