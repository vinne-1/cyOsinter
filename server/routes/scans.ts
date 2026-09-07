import { Router } from "express";
import { parsePagination, sendError, sendNotFound } from "./response";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { triggerScan, requestScanCancellation } from "../scan-trigger";
import { requireWorkspaceRole } from "./auth-middleware";
import { createScanSchema } from "./schemas";

const routeLog = createLogger("routes");

export const scansRouter = Router();

const wsAuth = requireWorkspaceRole("owner", "admin", "analyst", "viewer");

scansRouter.get("/workspaces/:workspaceId/scans", wsAuth, async (req, res) => {
  try {
    const { limit, offset } = parsePagination(req.query, { defaultLimit: 500, maxLimit: 5000 });
    const result = await storage.getScans(req.params.workspaceId as string, { limit, offset });
    res.json(result);
  } catch (err) {
    routeLog.error({ err }, "Get scans error");
    res.status(500).json({ message: "Internal server error" });
  }
});

scansRouter.get("/scans/:id", async (req, res) => {
  try {
    const scan = await storage.getScan(req.params.id);
    if (!scan) return res.status(404).json({ message: "Scan not found" });
    // Verify caller has access to the scan's workspace
    const membership = await storage.getWorkspaceMember(scan.workspaceId, req.user!.id);
    if (!membership) return res.status(404).json({ message: "Scan not found" });
    res.json(scan);
  } catch (err) { res.status(500).json({ message: "Internal server error" }); }
});

scansRouter.delete("/scans/:id", async (req, res) => {
  try {
    const scan = await storage.getScan(req.params.id);
    if (!scan) return res.status(404).json({ message: "Scan not found" });
    // Verify caller has admin+ role in the scan's workspace
    const membership = await storage.getWorkspaceMember(scan.workspaceId, req.user!.id);
    if (!membership || !["owner", "admin", "analyst"].includes(membership.role)) {
      return res.status(404).json({ message: "Scan not found" });
    }
    await storage.deleteScan(req.params.id);
    res.status(204).send();
  } catch (err) { res.status(500).json({ message: "Internal server error" }); }
});

scansRouter.post("/scans", async (req, res) => {
  try {
    const parsed = createScanSchema.parse(req.body);
    // Normalize target: trim whitespace, lowercase, strip trailing dots/slashes
    parsed.target = parsed.target.trim().toLowerCase().replace(/[./]+$/, "");
    if (!parsed.target || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(parsed.target)) {
      return res.status(400).json({ message: "Invalid domain format" });
    }
    let scanMode = parsed.mode ?? "standard";
    let scanType = parsed.type;
    let workspaceId = parsed.workspaceId;

    // If a profile is specified, override scan settings from profile config
    if (parsed.profileId) {
      const profile = await storage.getScanProfile(parsed.profileId);
      if (profile) {
        scanType = profile.scanType as typeof scanType;
        scanMode = profile.mode as typeof scanMode;
      }
    } else if (!parsed.mode && parsed.workspaceId) {
      /*
       * No profile named and no mode chosen: fall back to the workspace's
       * DEFAULT profile.
       *
       * `scan_profiles.isDefault` was validated on write, stored, and rendered
       * as a star on the profile card — and read by nothing. Starting a scan
       * never consulted it, so an operator who marked a "safe / low-and-slow"
       * profile as their default got `standard` anyway, and the star was a
       * promise the product did not keep. Same defect as `api_keys.scope`:
       * configured, badged, enforced nowhere.
       *
       * Precedence is deliberate. An explicit `profileId` wins, then an
       * explicit `mode` from a UI that offers the choice, and only then the
       * configured default — otherwise the default would silently override a
       * user who just picked something else in the dialog.
       */
      const profiles = await storage.getScanProfiles(parsed.workspaceId);
      const fallback = profiles.find((p) => p.isDefault);
      // Only the MODE is inherited. `type` is required by the schema, so the
      // caller has always chosen one — a `if (!parsed.type)` guard here could
      // never fire, and shipping a branch that cannot run is how dead code
      // starts looking like behaviour.
      if (fallback) scanMode = fallback.mode as typeof scanMode;
    }

    if (!workspaceId) {
      let ws = await storage.getWorkspaceByName(parsed.target);
      if (!ws) {
        try {
          ws = await storage.createWorkspace({ name: parsed.target, description: null, status: "active" });
          // Auto-add the creating user as owner
          await storage.addWorkspaceMember(ws.id, req.user!.id, "owner");
        } catch {
          // Another concurrent request created the workspace — fetch it
          ws = await storage.getWorkspaceByName(parsed.target);
          if (!ws) {
            return res.status(500).json({ message: "Internal server error" });
          }
        }
      }
      workspaceId = ws.id;
    }

    // Verify caller is a member of the target workspace (at least analyst)
    const membership = await storage.getWorkspaceMember(workspaceId, req.user!.id);
    if (!membership || !["owner", "admin", "analyst"].includes(membership.role)) {
      return res.status(403).json({ message: "You do not have permission to scan this workspace" });
    }

    // Prevent duplicate concurrent scans for same target
    const { data: existingScans } = await storage.getScans(workspaceId);
    const alreadyRunning = existingScans.find(s => s.status === "running" && s.target === parsed.target);
    if (alreadyRunning) {
      return res.status(409).json({
        message: `A scan is already running for ${parsed.target}`,
        existingScanId: alreadyRunning.id
      });
    }

    const scanId = await triggerScan(parsed.target, scanType, workspaceId, scanMode, {
      autoGenerateReport: parsed.autoGenerateReport ?? false,
    });
    const scan = await storage.getScan(scanId);

    res.status(201).json({ ...scan, workspaceId });
  } catch (error: unknown) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
    }
    res.status(400).json({ message: "Bad request" });
  }
});

/**
 * POST /api/scans/:id/cancel — stop a running scan.
 *
 * The scanner was already threaded for this end to end (`checkAborted` between
 * phases, `signal` into every `runWithConcurrency`), but the signal was
 * hardcoded `undefined` and nothing ever asked to cancel — so a Gold scan aimed
 * at the wrong domain ran its full thirty-plus minutes with no way to stop the
 * outbound traffic.
 *
 * A bare-ID route: the path has no `:workspaceId`, so membership is proven here.
 */
scansRouter.post("/scans/:id/cancel", async (req, res) => {
  try {
    const scan = await storage.getScan(req.params.id as string);
    // 404 rather than 403 for a non-member, so the reply does not confirm the
    // scan id belongs to somebody.
    if (!scan) return sendNotFound(res, "Scan");
    if (req.user!.role !== "superadmin") {
      const membership = await storage.getWorkspaceMember(scan.workspaceId, req.user!.id);
      // Viewers may watch a scan but not stop one.
      if (!membership) return sendNotFound(res, "Scan");
      if (!["owner", "admin", "analyst"].includes(membership.role)) {
        return sendError(res, 403, "Insufficient workspace permissions");
      }
    }

    if (scan.status !== "running" && scan.status !== "pending") {
      return sendError(res, 409, `Scan is already ${scan.status}`);
    }

    const stopped = requestScanCancellation(scan.id);
    if (!stopped) {
      // Queued but not yet executing, or running on another instance. Marking
      // the row is still correct: the queue skips a cancelled scan, and an
      // operator gets the outcome they asked for rather than silence.
      await storage.updateScan(scan.id, {
        status: "cancelled",
        completedAt: new Date(),
        errorMessage: "Scan was cancelled.",
        progressMessage: null,
        progressPercent: null,
        currentStep: null,
        estimatedSecondsRemaining: null,
      });
      routeLog.info({ scanId: scan.id }, "scan cancelled before it began executing here");
      return res.json({ cancelled: true, wasRunning: false });
    }

    // The scan's own error path writes the final row once the abort unwinds, so
    // the status is not set twice from two places.
    res.json({ cancelled: true, wasRunning: true });
  } catch (err) {
    routeLog.error({ err }, "Scan cancellation failed");
    sendError(res, 500, "Internal server error");
  }
});
