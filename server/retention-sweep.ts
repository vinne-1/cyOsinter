/**
 * Data retention sweep.
 *
 * The retention feature was implemented and reachable — `POST /retention/cleanup`
 * deletes per the configured policy and works — but it only ever ran when a
 * superadmin remembered to call it by hand. Nothing scheduled it, so in practice
 * a workspace policy reading "delete scans after 90 days" deleted nothing, ever,
 * and `last_cleanup_at` stayed NULL. For a security product that is not merely a
 * missing feature: retention is a claim made to auditors and data subjects, and
 * the product was asserting a deletion schedule it did not perform.
 *
 * This is the same shape as `startSlaMonitor`, and for the same reason: a policy
 * that depends on someone remembering to trigger it is not a policy.
 *
 * ## Three fixes carried over from the original implementation
 *
 * 1. **`archiveEnabled` is honoured by NOT deleting.** The column was ignored,
 *    so a workspace configured to archive-then-delete got the delete with no
 *    archive. Archiving is not implemented, and silently destroying data an
 *    operator explicitly flagged for retention is the worst available outcome —
 *    so those workspaces are skipped and counted, loudly.
 * 2. **Per-workspace error isolation.** One `try` wrapped the whole loop, so a
 *    single failing workspace aborted the sweep and every workspace after it
 *    kept its data indefinitely, with the failure attributed to the sweep rather
 *    than to that policy.
 * 3. **Counts come from `rowCount`, not `.returning()`.** The original loaded
 *    every deleted row into memory purely to call `.length` on it — a workspace
 *    with a year of findings would materialise all of them during a background
 *    job.
 *
 * Deletions are audited (`retention_purge`), which the action enum already
 * anticipated and nothing wrote. An unattended job that destroys customer data
 * with no record of what it removed is not something a security product should
 * ship.
 */

import { db } from "./db";
import { retentionPolicies, scans, findings, postureSnapshots } from "@shared/schema";
import { eq, sql } from "drizzle-orm";
import { createLogger } from "./logger";
import { logAudit } from "./audit";
import { cleanExpiredSessions } from "./auth";

const log = createLogger("retention-sweep");

/**
 * Daily. Retention is expressed in days, so a shorter period cannot delete
 * anything a daily pass would miss, and the sweep is a bulk DELETE — worth
 * running when it can do a day's work at once rather than hourly.
 */
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;

export interface RetentionResult {
  deleted: { scans: number; findings: number; snapshots: number };
  /** Workspaces skipped because they are configured to archive. */
  skippedArchive: number;
  /** Workspaces whose own cleanup threw; the rest of the sweep still ran. */
  failed: number;
  /** Expired/spent session rows removed. Global, not per workspace. */
  sessionsRemoved?: number;
}

function daysAgo(days: number): Date {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000);
}

/**
 * Deletes rows older than each workspace's configured retention.
 *
 * Never throws: it is called both from an unattended interval and from the
 * admin route, and a single bad policy must not take down either.
 */
export async function runRetentionCleanup(): Promise<RetentionResult> {
  const result: RetentionResult = {
    deleted: { scans: 0, findings: 0, snapshots: 0 },
    skippedArchive: 0,
    failed: 0,
  };

  let policies;
  try {
    policies = await db.select().from(retentionPolicies);
  } catch (err) {
    log.error({ err }, "Retention sweep could not read policies");
    return result;
  }

  for (const policy of policies) {
    const workspaceId = policy.workspaceId;

    // Configured to archive, and archiving does not exist yet. Deleting here
    // would destroy exactly the data the operator asked to keep.
    if (policy.archiveEnabled) {
      result.skippedArchive += 1;
      log.warn(
        { workspaceId },
        "Retention skipped: archiveEnabled is set but archiving is not implemented — no data deleted",
      );
      continue;
    }

    try {
      const removed = { scans: 0, findings: 0, snapshots: 0 };

      if (policy.scanRetentionDays) {
        const cutoff = daysAgo(policy.scanRetentionDays);
        // Only completed scans: an unfinished row has no completedAt and is
        // either running or abandoned, neither of which retention should judge.
        const r = await db
          .delete(scans)
          .where(
            sql`${scans.workspaceId} = ${workspaceId} AND ${scans.completedAt} IS NOT NULL AND ${scans.completedAt} < ${cutoff}`,
          );
        removed.scans = r.rowCount ?? 0;
      }

      if (policy.findingRetentionDays) {
        const cutoff = daysAgo(policy.findingRetentionDays);
        const r = await db
          .delete(findings)
          .where(sql`${findings.workspaceId} = ${workspaceId} AND ${findings.discoveredAt} < ${cutoff}`);
        removed.findings = r.rowCount ?? 0;
      }

      if (policy.snapshotRetentionDays) {
        const cutoff = daysAgo(policy.snapshotRetentionDays);
        const r = await db
          .delete(postureSnapshots)
          .where(sql`${postureSnapshots.workspaceId} = ${workspaceId} AND ${postureSnapshots.snapshotAt} < ${cutoff}`);
        removed.snapshots = r.rowCount ?? 0;
      }

      result.deleted.scans += removed.scans;
      result.deleted.findings += removed.findings;
      result.deleted.snapshots += removed.snapshots;

      await db
        .update(retentionPolicies)
        .set({ lastCleanupAt: new Date() })
        .where(eq(retentionPolicies.id, policy.id));

      // Only record a purge that actually removed something, so the audit log
      // stays a record of deletions rather than a daily heartbeat.
      if (removed.scans + removed.findings + removed.snapshots > 0) {
        await logAudit({
          // No actor: this is an unattended policy sweep, not someone's action.
          userId: null,
          action: "retention_purge",
          resourceType: "workspace",
          resourceId: workspaceId,
          metadata: {
            ...removed,
            scanRetentionDays: policy.scanRetentionDays,
            findingRetentionDays: policy.findingRetentionDays,
            snapshotRetentionDays: policy.snapshotRetentionDays,
          },
        });
      }
    } catch (err) {
      // Isolated on purpose: the next workspace still gets its retention applied.
      result.failed += 1;
      log.error({ err, workspaceId }, "Retention cleanup failed for workspace");
    }
  }

  /*
   * Expired sessions are retention too, and nothing was removing them.
   *
   * `validateSession` deletes an expired row only when someone presents it, so a
   * session nobody returns to persisted forever — carrying `ip_address` and
   * `user_agent` long past the purpose they were collected for. It rides on this
   * sweep rather than its own timer because it is the same job: deleting data
   * whose retention period has ended.
   *
   * Deliberately outside the per-workspace loop and its own try: sessions are
   * global, and a workspace policy failing must not skip them.
   */
  try {
    const sessionsRemoved = await cleanExpiredSessions();
    if (sessionsRemoved > 0) result.sessionsRemoved = sessionsRemoved;
  } catch (err) {
    log.error({ err }, "Expired-session cleanup failed");
  }

  log.info({ ...result }, "Retention sweep completed");
  return result;
}

let intervalId: NodeJS.Timeout | null = null;
let running = false;

export function startRetentionSweep(): void {
  if (intervalId) return;
  intervalId = setInterval(() => {
    // Skip rather than overlap: a slow sweep must not stack up behind itself.
    if (running) return;
    running = true;
    void runRetentionCleanup()
      .catch((err) => log.error({ err }, "Retention sweep failed"))
      .finally(() => {
        running = false;
      });
  }, CHECK_INTERVAL_MS);

  // Once at startup, so a deployment that restarts daily still applies
  // retention rather than resetting the timer before it ever fires.
  void runRetentionCleanup().catch((err) => log.error({ err }, "Initial retention sweep failed"));

  log.info({ intervalMs: CHECK_INTERVAL_MS }, "Retention sweep started");
}

export function stopRetentionSweep(): void {
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
}
