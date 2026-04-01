import { Router } from "express";
import { z } from "zod";
import { eq, lt, sql, count } from "drizzle-orm";
import { db } from "../db";
import {
  retentionPolicies,
  scans,
  findings,
  postureSnapshots,
} from "@shared/schema";
import { requireAuth, requireWorkspaceRole } from "./auth-middleware";
import { sendError, sendValidationError, sendNotFound } from "./response";
import { createLogger } from "../logger";

const log = createLogger("retention");

export const retentionRouter = Router();

const upsertSchema = z.object({
  scanRetentionDays: z.number().int().min(1).max(3650).optional(),
  findingRetentionDays: z.number().int().min(1).max(3650).optional(),
  snapshotRetentionDays: z.number().int().min(1).max(3650).optional(),
  archiveEnabled: z.boolean().optional(),
});

// GET /workspaces/:workspaceId/retention
retentionRouter.get(
  "/workspaces/:workspaceId/retention",
  requireAuth,
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const [policy] = await db
        .select()
        .from(retentionPolicies)
        .where(eq(retentionPolicies.workspaceId, req.params.workspaceId as string))
        .limit(1);

      if (!policy) {
        return res.json({
          workspaceId: req.params.workspaceId,
          scanRetentionDays: 365,
          findingRetentionDays: 730,
          snapshotRetentionDays: 365,
          archiveEnabled: false,
        });
      }

      res.json(policy);
    } catch (err) {
      log.error({ err }, "Failed to get retention policy");
      sendError(res, 500, "Failed to get retention policy");
    }
  },
);

// PUT /workspaces/:workspaceId/retention
retentionRouter.put(
  "/workspaces/:workspaceId/retention",
  requireAuth,
  requireWorkspaceRole("owner", "admin"),
  async (req, res) => {
    try {
      const parsed = upsertSchema.safeParse(req.body);
      if (!parsed.success) {
        return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
      }

      const workspaceId = req.params.workspaceId as string;

      const [existing] = await db
        .select()
        .from(retentionPolicies)
        .where(eq(retentionPolicies.workspaceId, workspaceId))
        .limit(1);

      if (existing) {
        const [updated] = await db
          .update(retentionPolicies)
          .set({ ...parsed.data, updatedAt: new Date() })
          .where(eq(retentionPolicies.workspaceId, workspaceId))
          .returning();

        return res.json(updated);
      }

      const [created] = await db
        .insert(retentionPolicies)
        .values({
          workspaceId,
          scanRetentionDays: parsed.data.scanRetentionDays ?? 365,
          findingRetentionDays: parsed.data.findingRetentionDays ?? 730,
          snapshotRetentionDays: parsed.data.snapshotRetentionDays ?? 365,
          archiveEnabled: parsed.data.archiveEnabled ?? false,
        })
        .returning();

      res.status(201).json(created);
    } catch (err) {
      log.error({ err }, "Failed to upsert retention policy");
      sendError(res, 500, "Failed to upsert retention policy");
    }
  },
);

// POST /retention/cleanup — trigger manual retention cleanup
retentionRouter.post("/retention/cleanup", requireAuth, async (req, res) => {
  try {
    const result = await runRetentionCleanup();
    res.json(result);
  } catch (err) {
    log.error({ err }, "Manual retention cleanup failed");
    sendError(res, 500, "Cleanup failed");
  }
});

// ── Retention Cleanup ──

function daysAgo(days: number): Date {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000);
}

/**
 * For each workspace with a retention policy, deletes records older than the
 * configured retention days. Returns counts of deleted records by type.
 */
export async function runRetentionCleanup(): Promise<{ deleted: Record<string, number> }> {
  const deleted: Record<string, number> = {
    scans: 0,
    findings: 0,
    snapshots: 0,
  };

  try {
    const policies = await db.select().from(retentionPolicies);

    for (const policy of policies) {
      const workspaceId = policy.workspaceId;

      // Delete old scans
      if (policy.scanRetentionDays) {
        const cutoff = daysAgo(policy.scanRetentionDays);
        const result = await db
          .delete(scans)
          .where(
            sql`${scans.workspaceId} = ${workspaceId} AND ${scans.completedAt} IS NOT NULL AND ${scans.completedAt} < ${cutoff}`,
          )
          .returning();
        deleted.scans += result.length;
      }

      // Delete old findings
      if (policy.findingRetentionDays) {
        const cutoff = daysAgo(policy.findingRetentionDays);
        const result = await db
          .delete(findings)
          .where(
            sql`${findings.workspaceId} = ${workspaceId} AND ${findings.discoveredAt} < ${cutoff}`,
          )
          .returning();
        deleted.findings += result.length;
      }

      // Delete old snapshots
      if (policy.snapshotRetentionDays) {
        const cutoff = daysAgo(policy.snapshotRetentionDays);
        const result = await db
          .delete(postureSnapshots)
          .where(
            sql`${postureSnapshots.workspaceId} = ${workspaceId} AND ${postureSnapshots.snapshotAt} < ${cutoff}`,
          )
          .returning();
        deleted.snapshots += result.length;
      }

      // Update lastCleanupAt
      await db
        .update(retentionPolicies)
        .set({ lastCleanupAt: new Date() })
        .where(eq(retentionPolicies.id, policy.id));
    }

    log.info({ deleted }, "Retention cleanup completed");
  } catch (err) {
    log.error({ err }, "Retention cleanup failed");
  }

  return { deleted };
}
