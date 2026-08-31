/**
 * SLA breach monitor.
 *
 * `checkSLABreaches` has existed in finding-workflow.ts since the workflow
 * feature landed, but nothing ever called it: every finding in the database had
 * `sla_breached = false` regardless of age, because the flag was only ever
 * written by a function with no callers. The remediation clock was decorative.
 *
 * This runs the sweep on an interval across every workspace, so a finding that
 * blows its deadline is marked without anyone opening the page.
 */

import { db } from "./db";
import { workspaces, findings, cases } from "@shared/schema";
import { eq, and, or, isNull, ne, lt, sql } from "drizzle-orm";
import { createLogger } from "./logger";
import { computeDueDate, computePriority } from "./finding-workflow";
import { logAudit } from "./audit";

const log = createLogger("sla-monitor");

/** Hourly is granular enough: the tightest SLA is 24 hours. */
const CHECK_INTERVAL_MS = Number(process.env.SLA_CHECK_INTERVAL_MS ?? 60 * 60 * 1000);

/** Workflow states that stop the clock — the work is finished. */
const TERMINAL_STATES = ["verified", "closed"];

let intervalId: ReturnType<typeof setInterval> | null = null;
let running = false;

export interface SlaSweepResult {
  workspacesChecked: number;
  findingsBreached: number;
  casesBreached: number;
  backfilledDueDates: number;
}

/**
 * Fills in the SLA fields for findings created before the clock was wired up.
 *
 * Without a deadline the sweep can never mark them, because a breach is measured
 * against a due date they do not have. Priority is filled at the same time so
 * triage ordering works on historical findings too.
 */
async function backfillDueDates(): Promise<number> {
  const missing = await db
    .select({
      id: findings.id,
      severity: findings.severity,
      discoveredAt: findings.discoveredAt,
      dueDate: findings.dueDate,
      priority: findings.priority,
    })
    .from(findings)
    .where(or(isNull(findings.dueDate), isNull(findings.priority)))
    .limit(5000);

  let updated = 0;
  for (const f of missing) {
    const discoveredAt = f.discoveredAt ? new Date(f.discoveredAt) : new Date();
    await db
      .update(findings)
      .set({
        dueDate: f.dueDate ?? computeDueDate(f.severity, discoveredAt),
        priority: f.priority ?? computePriority(f.severity),
      })
      .where(eq(findings.id, f.id));
    updated++;
  }

  if (updated > 0) log.info({ updated }, "Backfilled SLA fields for pre-existing findings");
  return updated;
}

/**
 * Marks every overdue, still-open finding as breached.
 *
 * A single set-based UPDATE rather than the row-by-row loop the original helper
 * used: that version issued one SELECT plus one UPDATE per finding, which does
 * not scale past a few thousand rows.
 */
export async function runSlaSweep(): Promise<SlaSweepResult> {
  const backfilledDueDates = await backfillDueDates();

  const workspaceRows = await db.select({ id: workspaces.id }).from(workspaces);

  const breached = await db
    .update(findings)
    .set({ slaBreached: true })
    .where(
      and(
        eq(findings.slaBreached, false),
        lt(findings.dueDate, new Date()),
        // Only work that is still outstanding can breach.
        ne(findings.workflowState, TERMINAL_STATES[0]!),
        ne(findings.workflowState, TERMINAL_STATES[1]!),
        ne(findings.status, "resolved"),
        ne(findings.status, "false_positive"),
        ne(findings.status, "accepted_risk"),
      ),
    )
    .returning({ id: findings.id, workspaceId: findings.workspaceId, severity: findings.severity });

  if (breached.length > 0) {
    log.warn({ count: breached.length }, "Findings breached their remediation SLA");
    // A missed deadline is a compliance-relevant event, so it belongs in the
    // audit trail rather than only in application logs.
    await logAudit({
      userId: null,
      action: "sla_breached",
      resourceType: "finding",
      metadata: {
        count: breached.length,
        bySeverity: breached.reduce<Record<string, number>>((acc, f) => {
          acc[f.severity] = (acc[f.severity] ?? 0) + 1;
          return acc;
        }, {}),
      },
    });
  }

  // Cases carry their own deadline — the unit of WORK can blow its SLA even
  // when the individual findings inside it have not.
  const casesBreached = await db
    .update(cases)
    .set({ slaBreached: true })
    .where(
      and(
        eq(cases.slaBreached, false),
        lt(cases.dueAt, new Date()),
        ne(cases.status, "resolved"),
        ne(cases.status, "closed"),
      ),
    )
    .returning({ id: cases.id });

  if (casesBreached.length > 0) {
    log.warn({ count: casesBreached.length }, "Cases breached their remediation SLA");
  }

  return {
    workspacesChecked: workspaceRows.length,
    findingsBreached: breached.length,
    casesBreached: casesBreached.length,
    backfilledDueDates,
  };
}

/** Counts of outstanding work against its deadline, for a workspace. */
export async function getSlaSummary(workspaceId: string): Promise<{
  open: number;
  breached: number;
  dueSoon: number;
  onTrack: number;
}> {
  const soon = new Date(Date.now() + 24 * 60 * 60 * 1000);

  const [row] = await db
    .select({
      open: sql<number>`count(*)::int`,
      breached: sql<number>`count(*) filter (where ${findings.slaBreached})::int`,
      dueSoon: sql<number>`count(*) filter (where not ${findings.slaBreached} and ${findings.dueDate} <= ${soon})::int`,
    })
    .from(findings)
    .where(
      and(
        eq(findings.workspaceId, workspaceId),
        ne(findings.status, "resolved"),
        ne(findings.status, "false_positive"),
        ne(findings.status, "accepted_risk"),
      ),
    );

  const open = row?.open ?? 0;
  const breached = row?.breached ?? 0;
  const dueSoon = row?.dueSoon ?? 0;
  return { open, breached, dueSoon, onTrack: Math.max(0, open - breached - dueSoon) };
}

export function startSlaMonitor(): void {
  if (intervalId) return;
  intervalId = setInterval(() => {
    // Skip rather than overlap: a slow sweep must not stack up behind itself.
    if (running) return;
    running = true;
    void runSlaSweep()
      .catch((err) => log.error({ err }, "SLA sweep failed"))
      .finally(() => {
        running = false;
      });
  }, CHECK_INTERVAL_MS);

  // Run once at startup so a restart does not leave breaches unmarked for an
  // hour, and so the backfill happens on first deploy.
  void runSlaSweep().catch((err) => log.error({ err }, "Initial SLA sweep failed"));

  log.info({ intervalMs: CHECK_INTERVAL_MS }, "SLA monitor started");
}

export function stopSlaMonitor(): void {
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
    log.info("SLA monitor stopped");
  }
}
