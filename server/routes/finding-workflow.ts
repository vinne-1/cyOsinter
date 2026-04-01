/**
 * Finding workflow routes: state transitions, assignments, SLA tracking, dedup groups.
 */

import { Router } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { sendError, sendNotFound, sendValidationError } from "./response";
import { requireAuth } from "./auth-middleware";
import { createLogger } from "../logger";

const log = createLogger("finding-workflow-routes");

export const findingWorkflowRouter = Router();

// ── Workflow state transitions ──

const transitionSchema = z.object({
  state: z.enum(["open", "in_progress", "resolved", "false_positive", "accepted_risk"]),
  assigneeId: z.string().optional(),
  priority: z.enum(["critical", "high", "medium", "low"]).optional(),
  dueDate: z.string().datetime().optional(),
});

findingWorkflowRouter.patch("/findings/:id/workflow", async (req, res) => {
  try {
    const finding = await storage.getFinding(req.params.id);
    if (!finding) return sendNotFound(res, "Finding");

    const parsed = transitionSchema.parse(req.body);
    const updates: Record<string, unknown> = { workflowState: parsed.state };
    if (parsed.assigneeId !== undefined) updates.assigneeId = parsed.assigneeId;
    if (parsed.priority !== undefined) updates.priority = parsed.priority;
    if (parsed.dueDate !== undefined) updates.dueDate = new Date(parsed.dueDate);

    await storage.updateFinding(finding.id, updates);
    log.info({ findingId: finding.id, newState: parsed.state }, "Finding workflow updated");
    res.json({ success: true, state: parsed.state });
  } catch (err) {
    if (err instanceof z.ZodError) return sendValidationError(res, err.errors[0]?.message ?? "Validation error");
    sendError(res, 500, err instanceof Error ? err.message : "Internal error");
  }
});

// ── Bulk workflow update ──

const bulkTransitionSchema = z.object({
  findingIds: z.array(z.string().min(1)).min(1).max(100),
  state: z.enum(["open", "in_progress", "resolved", "false_positive", "accepted_risk"]),
  assigneeId: z.string().optional(),
});

findingWorkflowRouter.patch("/findings/bulk/workflow", async (req, res) => {
  try {
    const { findingIds, state, assigneeId } = bulkTransitionSchema.parse(req.body);
    const results: Array<{ id: string; success: boolean; error?: string }> = [];

    for (const id of findingIds) {
      try {
        const finding = await storage.getFinding(id);
        if (!finding) {
          results.push({ id, success: false, error: "Not found" });
          continue;
        }
        const updates: Record<string, unknown> = { workflowState: state };
        if (assigneeId) updates.assigneeId = assigneeId;
        await storage.updateFinding(id, updates);
        results.push({ id, success: true });
      } catch (err) {
        results.push({ id, success: false, error: err instanceof Error ? err.message : "Failed" });
      }
    }

    res.json({ results });
  } catch (err) {
    if (err instanceof z.ZodError) return sendValidationError(res, err.errors[0]?.message ?? "Validation error");
    sendError(res, 500, err instanceof Error ? err.message : "Internal error");
  }
});

// ── Finding groups (dedup) ──

findingWorkflowRouter.get("/workspaces/:workspaceId/finding-groups", async (req, res) => {
  try {
    // Finding groups would come from storage — for now use the dedup service
    const { getFindingGroups } = await import("../finding-dedup");
    const groups = await getFindingGroups(req.params.workspaceId as string);
    res.json(groups);
  } catch (err) {
    sendError(res, 500, err instanceof Error ? err.message : "Internal error");
  }
});

// POST /workspaces/:workspaceId/finding-groups/compute — recompute finding groups
findingWorkflowRouter.post("/workspaces/:workspaceId/finding-groups/compute", requireAuth, async (req, res) => {
  try {
    const { groupFindings } = await import("../finding-dedup");
    const groupCount = await groupFindings(req.params.workspaceId as string);
    res.json({ success: true, groupCount });
  } catch (err) {
    sendError(res, 500, err instanceof Error ? err.message : "Internal error");
  }
});
