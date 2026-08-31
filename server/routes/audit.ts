import { Router } from "express";
import { z } from "zod";
import { eq, desc, and, count, gte, lte } from "drizzle-orm";
import { db } from "../db";
import { auditLogs, users } from "@shared/schema";
import { requireAuth, requireRole } from "./auth-middleware";
import { sendError, sendValidationError } from "./response";
import { createLogger } from "../logger";

const log = createLogger("audit");

export const auditRouter = Router();

// Re-exported for callers that already import from this module. The
// implementation lives in server/audit.ts so route files and the mutation
// middleware can share it without a circular import through the router.
export { logAudit, logAuditAsync, clientIp } from "../audit";
export type { AuditAction, AuditEntry } from "../audit";

const querySchema = z.object({
  action: z.string().optional(),
  userId: z.string().optional(),
  resourceType: z.string().optional(),
  /** ISO timestamps bounding the window, inclusive. */
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
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

      const { action, userId, resourceType, from, to, limit, offset } = parsed.data;

      const conditions = [];
      if (action) conditions.push(eq(auditLogs.action, action));
      if (userId) conditions.push(eq(auditLogs.userId, userId));
      if (resourceType) conditions.push(eq(auditLogs.resourceType, resourceType));
      if (from) conditions.push(gte(auditLogs.timestamp, new Date(from)));
      if (to) conditions.push(lte(auditLogs.timestamp, new Date(to)));

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

      // Join the actor so the viewer can show who did it rather than a bare
      // user id. The join is LEFT so entries whose user was deleted (the FK is
      // ON DELETE SET NULL) and unauthenticated events still appear.
      const [[totalResult], rows] = await Promise.all([
        db.select({ value: count() }).from(auditLogs).where(whereClause),
        db
          .select({
            id: auditLogs.id,
            timestamp: auditLogs.timestamp,
            userId: auditLogs.userId,
            userEmail: users.email,
            userName: users.name,
            action: auditLogs.action,
            resourceType: auditLogs.resourceType,
            resourceId: auditLogs.resourceId,
            metadata: auditLogs.metadata,
            ipAddress: auditLogs.ipAddress,
          })
          .from(auditLogs)
          .leftJoin(users, eq(auditLogs.userId, users.id))
          .where(whereClause)
          .orderBy(desc(auditLogs.timestamp))
          .limit(limit)
          .offset(offset),
      ]);

      res.json({
        data: rows.map((r) => ({
          ...r,
          // The viewer renders a single actor label; prefer a name, fall back
          // to the email, then to "System" for unauthenticated/background events.
          userName: r.userName ?? r.userEmail ?? "System",
          // …and a single resource label, e.g. "workspace 1f6ba6e4".
          resource: r.resourceType
            ? `${r.resourceType}${r.resourceId ? ` ${r.resourceId.slice(0, 8)}` : ""}`
            : "—",
        })),
        total: totalResult?.value ?? 0,
        limit,
        offset,
      });
    } catch (err) {
      log.error({ err }, "Failed to fetch audit logs");
      sendError(res, 500, "Failed to fetch audit logs");
    }
  },
);

// GET /audit-logs/actions — distinct action names present in the trail, so the
// viewer's filter reflects reality instead of a hardcoded list.
auditRouter.get(
  "/audit-logs/actions",
  requireAuth,
  requireRole("admin", "superadmin"),
  async (_req, res) => {
    try {
      const rows = await db
        .selectDistinct({ action: auditLogs.action })
        .from(auditLogs)
        .orderBy(auditLogs.action);
      res.json(rows.map((r) => r.action));
    } catch (err) {
      log.error({ err }, "Failed to fetch audit actions");
      sendError(res, 500, "Failed to fetch audit actions");
    }
  },
);
