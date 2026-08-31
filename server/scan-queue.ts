/**
 * Durable, multi-instance scan queue backed by PostgreSQL.
 *
 * The previous implementation kept the queue in a module-level array despite a
 * docstring claiming otherwise. That meant:
 *   - a second app instance kept a completely separate queue, so the same scan
 *     could be claimed and run twice;
 *   - anything queued was lost on restart, with no record it had existed;
 *   - `MAX_CONCURRENT` was per-process, so N replicas ran 3N scans.
 *
 * Work is now claimed with `SELECT … FOR UPDATE SKIP LOCKED`, the standard
 * Postgres queue pattern: the row is locked inside a transaction and any other
 * worker skips past it rather than blocking, so N workers claim N distinct jobs
 * with no coordination and no external broker.
 *
 * Crash safety comes from a lease. A claimed job records `locked_by`/`locked_at`;
 * if the holder dies without finishing, the lease expires and another worker
 * reclaims the job. Without that, a crash would strand jobs in `running`
 * forever — the same class of bug the startup reconciler already exists to fix.
 */

import { randomUUID } from "crypto";
import { hostname } from "os";
import { pool } from "./db";
import { triggerScan } from "./scan-trigger";
import { createLogger } from "./logger";

const log = createLogger("scan-queue");

/** Concurrent scans THIS instance will run. Total capacity scales with replicas. */
const MAX_CONCURRENT = Number(process.env.SCAN_CONCURRENCY ?? 3);
const POLL_INTERVAL_MS = 5000;

/**
 * How long a claim is honoured before another worker may steal it. Must exceed
 * the longest realistic scan; a full scan of a large target ran ~6 minutes, so
 * 30 minutes leaves generous headroom while still bounding recovery time.
 */
const LEASE_MS = Number(process.env.SCAN_LEASE_MS ?? 30 * 60 * 1000);

/** Identifies this process in `locked_by`, so a stuck queue can be traced. */
const WORKER_ID = `${hostname()}:${process.pid}:${randomUUID().slice(0, 8)}`;

export interface QueuedScan {
  id: string;
  target: string;
  type: string;
  workspaceId: string;
  mode: string;
  priority: number;
  attempts: number;
  queuedAt: Date;
}

let pollTimer: ReturnType<typeof setInterval> | null = null;
let activeCount = 0;
/** Guards against overlapping drain loops within this process. */
let draining = false;

function getPriority(type: string): number {
  switch (type) {
    case "dast": return 1; // Fast — run ahead of long scans.
    case "easm":
    case "osint": return 2;
    default: return 3;     // "full" and anything unknown.
  }
}

/**
 * Adds a scan to the queue and returns its queue id.
 *
 * Returns a promise now (the previous version was synchronous), because the
 * write must reach the database before the caller can be told it is queued.
 */
export async function enqueueScan(
  target: string,
  type: string,
  workspaceId: string,
  mode: string,
): Promise<string> {
  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO scan_queue (workspace_id, target, type, mode, priority)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id`,
    [workspaceId, target, type, mode, getPriority(type)],
  );
  const id = rows[0]!.id;

  log.info({ queueId: id, target, type }, "Scan enqueued");
  // Start work immediately rather than waiting for the next poll tick.
  void drain();
  return id;
}

/**
 * Atomically claims one job, or returns null when there is nothing to do.
 *
 * The whole statement is a single round trip: the sub-select picks the best
 * candidate under `FOR UPDATE SKIP LOCKED` and the outer UPDATE marks it
 * running. Because both happen in one statement they share a transaction, so
 * two workers can never claim the same row.
 */
async function claimNext(): Promise<QueuedScan | null> {
  const { rows } = await pool.query(
    `UPDATE scan_queue q
        SET status     = 'running',
            locked_by  = $1,
            locked_at  = now(),
            started_at = COALESCE(q.started_at, now()),
            attempts   = q.attempts + 1
      WHERE q.id = (
        SELECT c.id
          FROM scan_queue c
         WHERE (
                 -- Fresh work that is due.
                 (c.status = 'queued' AND c.available_at <= now())
                 -- …or a job whose holder died and whose lease has expired.
                 OR (c.status = 'running' AND c.locked_at < now() - ($2::bigint * interval '1 millisecond'))
               )
           AND c.attempts < c.max_attempts
         ORDER BY c.priority ASC, c.queued_at ASC
         LIMIT 1
         FOR UPDATE SKIP LOCKED
      )
      RETURNING q.id, q.workspace_id, q.target, q.type, q.mode, q.priority, q.attempts, q.queued_at`,
    [WORKER_ID, LEASE_MS],
  );

  const row = rows[0];
  if (!row) return null;

  return {
    id: row.id,
    workspaceId: row.workspace_id,
    target: row.target,
    type: row.type,
    mode: row.mode,
    priority: row.priority,
    attempts: row.attempts,
    queuedAt: row.queued_at,
  };
}

async function markCompleted(queueId: string, scanId: string): Promise<void> {
  await pool.query(
    `UPDATE scan_queue
        SET status = 'completed', finished_at = now(), scan_id = $2, locked_by = NULL, locked_at = NULL
      WHERE id = $1`,
    [queueId, scanId],
  );
}

/**
 * Records a failure. A job with attempts left goes back to `queued` behind an
 * exponential backoff; one that has exhausted them is marked failed so it stops
 * consuming capacity and becomes visible as a problem.
 */
async function markFailed(queueId: string, attempts: number, maxAttempts: number, err: unknown): Promise<void> {
  const message = err instanceof Error ? err.message : String(err);
  const exhausted = attempts >= maxAttempts;

  if (exhausted) {
    await pool.query(
      `UPDATE scan_queue
          SET status = 'failed', finished_at = now(), last_error = $2, locked_by = NULL, locked_at = NULL
        WHERE id = $1`,
      [queueId, message.slice(0, 500)],
    );
    log.error({ queueId, attempts }, "Queued scan failed permanently");
    return;
  }

  // 30s, 60s, 120s… so a transient outage does not spin the queue.
  const backoffSeconds = 30 * 2 ** (attempts - 1);
  await pool.query(
    `UPDATE scan_queue
        SET status = 'queued', last_error = $2, locked_by = NULL, locked_at = NULL,
            available_at = now() + ($3::int * interval '1 second')
      WHERE id = $1`,
    [queueId, message.slice(0, 500), backoffSeconds],
  );
  log.warn({ queueId, attempts, backoffSeconds }, "Queued scan failed, will retry");
}

/** Claims and runs jobs until this instance is at capacity or the queue is empty. */
async function drain(): Promise<void> {
  if (draining) return;
  draining = true;
  try {
    while (activeCount < MAX_CONCURRENT) {
      let item: QueuedScan | null;
      try {
        item = await claimNext();
      } catch (err) {
        log.error({ err }, "Failed to claim a queued scan");
        return;
      }
      if (!item) return;

      activeCount++;
      log.info({ queueId: item.id, target: item.target, active: activeCount }, "Processing queued scan");

      // Deliberately not awaited: the loop continues claiming up to capacity
      // while this scan runs.
      void triggerScan(item.target, item.type, item.workspaceId, item.mode)
        .then(async (scanId) => {
          await markCompleted(item!.id, scanId);
          log.info({ queueId: item!.id, scanId }, "Queued scan started");
        })
        .catch(async (err) => {
          await markFailed(item!.id, item!.attempts, 3, err).catch((e) =>
            log.error({ err: e, queueId: item!.id }, "Failed to record queue failure"),
          );
        })
        .finally(() => {
          activeCount--;
          void drain();
        });
    }
  } finally {
    draining = false;
  }
}

export interface QueueStatus {
  queueLength: number;
  activeScans: number;
  maxConcurrent: number;
  workerId: string;
  items: Array<{ id: string; target: string; type: string; priority: number; status: string; attempts: number; queuedAt: string }>;
}

/**
 * Queue state. Counts come from the database, so they reflect every instance
 * rather than only this process.
 */
export async function getQueueStatus(): Promise<QueueStatus> {
  const { rows } = await pool.query(
    `SELECT id, target, type, priority, status, attempts, queued_at
       FROM scan_queue
      WHERE status IN ('queued', 'running')
      ORDER BY priority ASC, queued_at ASC
      LIMIT 100`,
  );

  return {
    queueLength: rows.filter((r) => r.status === "queued").length,
    activeScans: rows.filter((r) => r.status === "running").length,
    maxConcurrent: MAX_CONCURRENT,
    workerId: WORKER_ID,
    items: rows.map((r) => ({
      id: r.id,
      target: r.target,
      type: r.type,
      priority: r.priority,
      status: r.status,
      attempts: r.attempts,
      queuedAt: new Date(r.queued_at).toISOString(),
    })),
  };
}

/** Cancels a job that has not started. Returns false if it is already running. */
export async function cancelQueuedScan(queueId: string): Promise<boolean> {
  const { rowCount } = await pool.query(
    `UPDATE scan_queue
        SET status = 'failed', finished_at = now(), last_error = 'Cancelled'
      WHERE id = $1 AND status = 'queued'`,
    [queueId],
  );
  if (rowCount) log.info({ queueId }, "Queued scan cancelled");
  return (rowCount ?? 0) > 0;
}

export function startQueuePoller(): void {
  if (pollTimer) return;
  // The poller is the safety net that picks up work enqueued by ANOTHER
  // instance (which cannot call our in-process drain) and reclaims expired
  // leases. Enqueue still drains immediately for local latency.
  pollTimer = setInterval(() => void drain(), POLL_INTERVAL_MS);
  log.info({ workerId: WORKER_ID, maxConcurrent: MAX_CONCURRENT }, "Scan queue poller started");
}

export function stopQueuePoller(): void {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
    log.info("Scan queue poller stopped");
  }
}

/** Exposed for tests and diagnostics. */
export const __queueInternals = { WORKER_ID, MAX_CONCURRENT, LEASE_MS, getPriority };
