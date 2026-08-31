import { Router } from "express";
import { z } from "zod";
import { and, desc, eq, inArray, sql } from "drizzle-orm";
import { db } from "../db";
import { cases, caseFindings, findings, users } from "@shared/schema";
import { requireWorkspaceRole } from "./auth-middleware";
import { sendError, sendNotFound, sendValidationError } from "./response";
import { createLogger } from "../logger";
import { computeDueDate } from "../finding-workflow";
// Lifecycle rules live in their own module so they are testable without a DB.
import { isValidCaseTransition, CASE_TERMINAL_STATES, CASE_STATUSES } from "../case-workflow";
export { CASE_TRANSITIONS, isValidCaseTransition } from "../case-workflow";

const log = createLogger("cases");

export const casesRouter = Router();

const wsRead = requireWorkspaceRole("owner", "admin", "analyst", "viewer");
const wsWrite = requireWorkspaceRole("owner", "admin", "analyst");

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const STATUSES = CASE_STATUSES;

const createSchema = z.object({
  title: z.string().min(1, "Title is required").max(300),
  description: z.string().max(5000).optional(),
  severity: z.enum(SEVERITIES).default("medium"),
  ownerId: z.string().optional(),
  /** Findings to attach at creation. */
  findingIds: z.array(z.string()).max(500).optional(),
});

const updateSchema = z.object({
  title: z.string().min(1).max(300).optional(),
  description: z.string().max(5000).optional(),
  status: z.enum(STATUSES).optional(),
  severity: z.enum(SEVERITIES).optional(),
  // Explicit null unassigns; undefined leaves the owner alone.
  ownerId: z.string().nullable().optional(),
});

/**
 * Allocates the next per-workspace reference (CASE-1, CASE-2, …).
 *
 * Derived from the current maximum rather than a global sequence so each
 * workspace numbers from 1 — a shared sequence would leak how many cases other
 * tenants have created.
 */
async function nextReference(workspaceId: string): Promise<string> {
  const [row] = await db
    .select({
      max: sql<number>`COALESCE(MAX(NULLIF(regexp_replace(${cases.reference}, '\\D', '', 'g'), '')::int), 0)`,
    })
    .from(cases)
    .where(eq(cases.workspaceId, workspaceId));
  return `CASE-${(row?.max ?? 0) + 1}`;
}

/** Attaches the owner's name and the finding count to a case row. */
async function decorate(rows: Array<typeof cases.$inferSelect>) {
  if (rows.length === 0) return [];
  const ids = rows.map((r) => r.id);

  const counts = await db
    .select({ caseId: caseFindings.caseId, n: sql<number>`count(*)::int` })
    .from(caseFindings)
    .where(inArray(caseFindings.caseId, ids))
    .groupBy(caseFindings.caseId);
  const countByCase = new Map(counts.map((c) => [c.caseId, c.n]));

  const ownerIds = rows.map((r) => r.ownerId).filter((v): v is string => !!v);
  const owners = ownerIds.length
    ? await db.select({ id: users.id, name: users.name, email: users.email })
        .from(users).where(inArray(users.id, ownerIds))
    : [];
  const ownerById = new Map(owners.map((o) => [o.id, o.name ?? o.email]));

  return rows.map((r) => ({
    ...r,
    findingCount: countByCase.get(r.id) ?? 0,
    ownerName: r.ownerId ? ownerById.get(r.ownerId) ?? null : null,
  }));
}

// ── List ──
casesRouter.get("/workspaces/:workspaceId/cases", wsRead, async (req, res) => {
  try {
    const status = typeof req.query.status === "string" ? req.query.status : undefined;
    const where = status && STATUSES.includes(status as typeof STATUSES[number])
      ? and(eq(cases.workspaceId, req.params.workspaceId as string), eq(cases.status, status))
      : eq(cases.workspaceId, req.params.workspaceId as string);

    const rows = await db.select().from(cases).where(where).orderBy(desc(cases.createdAt)).limit(500);
    res.json({ data: await decorate(rows), total: rows.length, limit: 500, offset: 0 });
  } catch (err) {
    log.error({ err }, "Failed to list cases");
    sendError(res, 500, "Failed to list cases");
  }
});

// ── Create ──
casesRouter.post("/workspaces/:workspaceId/cases", wsWrite, async (req, res) => {
  try {
    const parsed = createSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
    }
    const workspaceId = req.params.workspaceId as string;
    const { title, description, severity, ownerId, findingIds } = parsed.data;

    const [created] = await db
      .insert(cases)
      .values({
        workspaceId,
        reference: await nextReference(workspaceId),
        title,
        description: description ?? null,
        severity,
        ownerId: ownerId ?? null,
        createdBy: req.user?.id ?? null,
        // Same policy as findings, so a case cannot promise a slower deadline
        // than the findings it contains.
        dueAt: computeDueDate(severity, new Date()),
      })
      .returning();

    if (findingIds?.length) {
      // Restricted to this workspace so a case cannot be used to pull in
      // findings the caller has no access to.
      const owned = await db
        .select({ id: findings.id })
        .from(findings)
        .where(and(eq(findings.workspaceId, workspaceId), inArray(findings.id, findingIds)));
      if (owned.length > 0) {
        await db.insert(caseFindings)
          .values(owned.map((f) => ({ caseId: created.id, findingId: f.id })))
          .onConflictDoNothing();
      }
    }

    log.info({ caseId: created.id, reference: created.reference }, "Case created");
    res.status(201).json((await decorate([created]))[0]);
  } catch (err) {
    log.error({ err }, "Failed to create case");
    sendError(res, 500, "Failed to create case");
  }
});

// ── Read one, with its findings ──
casesRouter.get("/cases/:id", async (req, res) => {
  try {
    const [row] = await db.select().from(cases).where(eq(cases.id, req.params.id)).limit(1);
    if (!row) return sendNotFound(res, "Case");

    // Bare-id route: verify membership explicitly, and 404 rather than 403 so
    // the response does not confirm the case exists.
    const { storage } = await import("../storage");
    const membership = await storage.getWorkspaceMember(row.workspaceId, req.user!.id);
    if (!membership && req.user!.role !== "superadmin") return sendNotFound(res, "Case");

    const linked = await db
      .select({ finding: findings })
      .from(caseFindings)
      .innerJoin(findings, eq(caseFindings.findingId, findings.id))
      .where(eq(caseFindings.caseId, row.id));

    res.json({ ...(await decorate([row]))[0], findings: linked.map((l) => l.finding) });
  } catch (err) {
    log.error({ err }, "Failed to load case");
    sendError(res, 500, "Failed to load case");
  }
});

// ── Update ──
casesRouter.patch("/cases/:id", async (req, res) => {
  try {
    const parsed = updateSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
    }

    const [existing] = await db.select().from(cases).where(eq(cases.id, req.params.id)).limit(1);
    if (!existing) return sendNotFound(res, "Case");

    const { storage } = await import("../storage");
    const membership = await storage.getWorkspaceMember(existing.workspaceId, req.user!.id);
    const canWrite = req.user!.role === "superadmin" ||
      (membership && ["owner", "admin", "analyst"].includes(membership.role));
    if (!canWrite) return sendNotFound(res, "Case");

    const next = parsed.data;
    if (next.status && !isValidCaseTransition(existing.status, next.status)) {
      return sendValidationError(res, `Cannot move a case from ${existing.status} to ${next.status}`);
    }

    const updates: Partial<typeof cases.$inferInsert> = { updatedAt: new Date() };
    if (next.title !== undefined) updates.title = next.title;
    if (next.description !== undefined) updates.description = next.description;
    if (next.ownerId !== undefined) updates.ownerId = next.ownerId;

    if (next.severity !== undefined && next.severity !== existing.severity) {
      updates.severity = next.severity;
      // Re-derive the deadline from the ORIGINAL creation time: raising severity
      // must tighten the deadline, not grant a fresh window.
      updates.dueAt = computeDueDate(next.severity, new Date(existing.createdAt));
    }

    if (next.status !== undefined) {
      updates.status = next.status;
      const nowTerminal = CASE_TERMINAL_STATES.includes(next.status);
      updates.closedAt = next.status === "closed" ? new Date() : null;
      // Stop the clock on completion, and restart it if the case is reopened.
      if (nowTerminal) updates.slaBreached = false;
    }

    const [updated] = await db.update(cases).set(updates).where(eq(cases.id, existing.id)).returning();
    res.json((await decorate([updated]))[0]);
  } catch (err) {
    log.error({ err }, "Failed to update case");
    sendError(res, 500, "Failed to update case");
  }
});

// ── Attach / detach findings ──
const linkSchema = z.object({ findingIds: z.array(z.string()).min(1).max(500) });

casesRouter.post("/cases/:id/findings", async (req, res) => {
  try {
    const parsed = linkSchema.safeParse(req.body ?? {});
    if (!parsed.success) return sendValidationError(res, "findingIds is required");

    const [row] = await db.select().from(cases).where(eq(cases.id, req.params.id)).limit(1);
    if (!row) return sendNotFound(res, "Case");

    const { storage } = await import("../storage");
    const membership = await storage.getWorkspaceMember(row.workspaceId, req.user!.id);
    const canWrite = req.user!.role === "superadmin" ||
      (membership && ["owner", "admin", "analyst"].includes(membership.role));
    if (!canWrite) return sendNotFound(res, "Case");

    const owned = await db
      .select({ id: findings.id })
      .from(findings)
      .where(and(eq(findings.workspaceId, row.workspaceId), inArray(findings.id, parsed.data.findingIds)));

    if (owned.length > 0) {
      await db.insert(caseFindings)
        .values(owned.map((f) => ({ caseId: row.id, findingId: f.id })))
        .onConflictDoNothing();
    }
    // Reports what was actually linked, so a caller passing ids from another
    // workspace sees that they were dropped.
    res.json({ linked: owned.length, requested: parsed.data.findingIds.length });
  } catch (err) {
    log.error({ err }, "Failed to link findings");
    sendError(res, 500, "Failed to link findings");
  }
});

casesRouter.delete("/cases/:id/findings/:findingId", async (req, res) => {
  try {
    const [row] = await db.select().from(cases).where(eq(cases.id, req.params.id)).limit(1);
    if (!row) return sendNotFound(res, "Case");

    const { storage } = await import("../storage");
    const membership = await storage.getWorkspaceMember(row.workspaceId, req.user!.id);
    const canWrite = req.user!.role === "superadmin" ||
      (membership && ["owner", "admin", "analyst"].includes(membership.role));
    if (!canWrite) return sendNotFound(res, "Case");

    await db.delete(caseFindings).where(
      and(eq(caseFindings.caseId, row.id), eq(caseFindings.findingId, req.params.findingId)),
    );
    res.status(204).send();
  } catch (err) {
    log.error({ err }, "Failed to unlink finding");
    sendError(res, 500, "Failed to unlink finding");
  }
});

// ── Delete ──
casesRouter.delete("/cases/:id", async (req, res) => {
  try {
    const [row] = await db.select().from(cases).where(eq(cases.id, req.params.id)).limit(1);
    if (!row) return sendNotFound(res, "Case");

    const { storage } = await import("../storage");
    const membership = await storage.getWorkspaceMember(row.workspaceId, req.user!.id);
    const canDelete = req.user!.role === "superadmin" ||
      (membership && ["owner", "admin"].includes(membership.role));
    if (!canDelete) return sendNotFound(res, "Case");

    // case_findings cascades; the findings themselves are untouched.
    await db.delete(cases).where(eq(cases.id, row.id));
    res.status(204).send();
  } catch (err) {
    log.error({ err }, "Failed to delete case");
    sendError(res, 500, "Failed to delete case");
  }
});

// ── Summary, for the dashboard ──
casesRouter.get("/workspaces/:workspaceId/cases-summary", wsRead, async (req, res) => {
  try {
    const [row] = await db
      .select({
        total: sql<number>`count(*)::int`,
        open: sql<number>`count(*) filter (where ${cases.status} not in ('resolved','closed'))::int`,
        unassigned: sql<number>`count(*) filter (where ${cases.ownerId} is null and ${cases.status} not in ('resolved','closed'))::int`,
        breached: sql<number>`count(*) filter (where ${cases.slaBreached})::int`,
      })
      .from(cases)
      .where(eq(cases.workspaceId, req.params.workspaceId as string));

    res.json({
      total: row?.total ?? 0,
      open: row?.open ?? 0,
      unassigned: row?.unassigned ?? 0,
      breached: row?.breached ?? 0,
    });
  } catch (err) {
    log.error({ err }, "Failed to load case summary");
    sendError(res, 500, "Failed to load case summary");
  }
});
