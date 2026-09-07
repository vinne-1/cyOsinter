import { Router } from "express";
import { z } from "zod";
import { eq } from "drizzle-orm";
import { db } from "../db";
import { retentionPolicies } from "@shared/schema";
import { requireAuth, requireRole, requireWorkspaceRole } from "./auth-middleware";
import { sendError, sendValidationError, sendNotFound } from "./response";
import { createLogger } from "../logger";
// Lives in server/retention-sweep.ts so it can also run unattended on an
// interval; this route is now just a manual trigger for the same code.
import { runRetentionCleanup } from "../retention-sweep";

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
retentionRouter.post("/retention/cleanup", requireAuth, requireRole("superadmin"), async (req, res) => {
  try {
    const result = await runRetentionCleanup();
    res.json(result);
  } catch (err) {
    log.error({ err }, "Manual retention cleanup failed");
    sendError(res, 500, "Cleanup failed");
  }
});
