import { Router } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { triggerScan } from "../scan-trigger";
import { requireWorkspaceRole } from "./auth-middleware";
import { createScanSchema } from "./schemas";

const routeLog = createLogger("routes");

export const scansRouter = Router();

const wsAuth = requireWorkspaceRole("owner", "admin", "analyst", "viewer");

scansRouter.get("/workspaces/:workspaceId/scans", wsAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(String(req.query.limit ?? "500"), 10) || 500, 5000);
    const offset = Math.max(parseInt(String(req.query.offset ?? "0"), 10) || 0, 0);
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
    }

    if (!workspaceId) {
      let ws = await storage.getWorkspaceByName(parsed.target);
      if (!ws) {
        ws = await storage.createWorkspace({ name: parsed.target, description: null, status: "active" });
        // Auto-add the creating user as owner
        await storage.addWorkspaceMember(ws.id, req.user!.id, "owner");
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

    const scanId = await triggerScan(parsed.target, scanType, workspaceId, scanMode);
    const scan = await storage.getScan(scanId);

    res.status(201).json({ ...scan, workspaceId });
  } catch (error: unknown) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
    }
    res.status(400).json({ message: "Bad request" });
  }
});
