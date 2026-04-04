import { Router } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { getNextCronRun } from "../scan-scheduler";
import { createScheduledScanSchema, updateScheduledScanSchema } from "./schemas";
import { requireWorkspaceRole } from "./auth-middleware";

const log = createLogger("routes:scheduled-scans");

const wsAuth = requireWorkspaceRole("owner", "admin", "analyst", "viewer");
const wsWrite = requireWorkspaceRole("owner", "admin", "analyst");

export const scheduledScansRouter = Router();

// GET /api/workspaces/:workspaceId/scheduled-scans
scheduledScansRouter.get("/workspaces/:workspaceId/scheduled-scans", wsAuth, async (req, res) => {
  try {
    const list = await storage.getScheduledScans(req.params.workspaceId as string);
    res.json(list);
  } catch (err) {
    log.error({ err }, "Get scheduled scans error");
    res.status(500).json({ message: "Internal server error" });
  }
});

// GET /api/scheduled-scans/:id
scheduledScansRouter.get("/scheduled-scans/:id", async (req, res) => {
  try {
    const scheduled = await storage.getScheduledScan(req.params.id);
    if (!scheduled) return res.status(404).json({ message: "Scheduled scan not found" });
    // Verify caller is a member of the schedule's workspace
    const membership = await storage.getWorkspaceMember(scheduled.workspaceId, req.user!.id);
    if (!membership) return res.status(404).json({ message: "Scheduled scan not found" });
    res.json(scheduled);
  } catch (err) {
    log.error({ err }, "Get scheduled scan error");
    res.status(500).json({ message: "Internal server error" });
  }
});

// POST /api/workspaces/:workspaceId/scheduled-scans
scheduledScansRouter.post("/workspaces/:workspaceId/scheduled-scans", wsWrite, async (req, res) => {
  try {
    const parsed = createScheduledScanSchema.parse(req.body);
    const workspaceId = req.params.workspaceId as string;

    // Verify workspace exists
    const workspace = await storage.getWorkspace(workspaceId);
    if (!workspace) return res.status(404).json({ message: "Workspace not found" });

    const nextRunAt = getNextCronRun(parsed.cronExpression);

    const created = await storage.createScheduledScan({
      workspaceId,
      target: parsed.target.trim().toLowerCase(),
      scanType: parsed.scanType,
      cronExpression: parsed.cronExpression,
      mode: parsed.mode,
      enabled: parsed.enabled,
      nextRunAt,
      lastRunAt: null,
      lastScanId: null,
    });

    res.status(201).json(created);
  } catch (error: unknown) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
    }
    log.error({ err: error }, "Create scheduled scan error");
    res.status(500).json({ message: "Internal server error" });
  }
});

// PATCH /api/scheduled-scans/:id
scheduledScansRouter.patch("/scheduled-scans/:id", async (req, res) => {
  try {
    const parsed = updateScheduledScanSchema.parse(req.body);
    const existing = await storage.getScheduledScan(req.params.id);
    if (!existing) return res.status(404).json({ message: "Scheduled scan not found" });
    // Verify caller has analyst+ role in the schedule's workspace
    const membership = await storage.getWorkspaceMember(existing.workspaceId, req.user!.id);
    if (!membership || !["owner", "admin", "analyst"].includes(membership.role)) {
      return res.status(404).json({ message: "Scheduled scan not found" });
    }

    const updateData: Record<string, unknown> = { ...parsed };

    // Recompute nextRunAt if cron expression changed
    if (parsed.cronExpression) {
      updateData.nextRunAt = getNextCronRun(parsed.cronExpression);
    }

    const updated = await storage.updateScheduledScan(req.params.id, updateData);
    res.json(updated);
  } catch (error: unknown) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
    }
    log.error({ err: error }, "Update scheduled scan error");
    res.status(500).json({ message: "Internal server error" });
  }
});

// DELETE /api/scheduled-scans/:id
scheduledScansRouter.delete("/scheduled-scans/:id", async (req, res) => {
  try {
    const existing = await storage.getScheduledScan(req.params.id);
    if (!existing) return res.status(404).json({ message: "Scheduled scan not found" });
    // Verify caller has analyst+ role in the schedule's workspace
    const membership = await storage.getWorkspaceMember(existing.workspaceId, req.user!.id);
    if (!membership || !["owner", "admin", "analyst"].includes(membership.role)) {
      return res.status(404).json({ message: "Scheduled scan not found" });
    }
    await storage.deleteScheduledScan(req.params.id);
    res.status(204).send();
  } catch (err) {
    log.error({ err }, "Delete scheduled scan error");
    res.status(500).json({ message: "Internal server error" });
  }
});
