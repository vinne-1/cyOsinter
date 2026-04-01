import { Router } from "express";
import { z } from "zod";
import { eq, desc, and, sql, count } from "drizzle-orm";
import { db } from "../db";
import { auditLogs } from "@shared/schema";
import { requireAuth, requireRole } from "./auth-middleware";
import { sendError, sendValidationError } from "./response";
import { createLogger } from "../logger";

const log = createLogger("audit");

export const auditRouter = Router();

/**
 * Records an audit log entry. Safe to call without awaiting in non-critical paths.
 */
export async function logAudit(
  userId: string | null,
  action: string,
  resourceType?: string,
  resourceId?: string,
  metadata?: Record<string, unknown>,
  ipAddress?: string,
): Promise<void> {
  try {
    await db.insert(auditLogs).values({
      userId: userId ?? null,
      action,
      resourceType: resourceType ?? null,
      resourceId: resourceId ?? null,
      metadata: metadata ?? null,
      ipAddress: ipAddress ?? null,
    });
  } catch (err) {
    log.error({ err, action, userId }, "Failed to write audit log");
  }
}

const querySchema = z.object({
  workspaceId: z.string().optional(),
  action: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(500).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

// GET /audit-logs — paginated audit log viewer (admin only)
auditRouter.get(
  "/audit-logs",
  requireAuth,
  requireRole("admin", "superadmin"),
  async (req, res) => {
    try {
      const parsed = querySchema.safeParse(req.query);
      if (!parsed.success) {
        return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
      }

      const { action, limit, offset } = parsed.data;

      const conditions = [];
      if (action) {
        conditions.push(eq(auditLogs.action, action));
      }

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

      const [totalResult] = await db
        .select({ value: count() })
        .from(auditLogs)
        .where(whereClause);

      const total = totalResult?.value ?? 0;

      const rows = await db
        .select()
        .from(auditLogs)
        .where(whereClause)
        .orderBy(desc(auditLogs.timestamp))
        .limit(limit)
        .offset(offset);

      res.json({
        data: rows,
        total,
        limit,
        offset,
      });
    } catch (err) {
      log.error({ err }, "Failed to fetch audit logs");
      sendError(res, 500, "Failed to fetch audit logs");
    }
  },
);
