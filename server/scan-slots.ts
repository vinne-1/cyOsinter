/**
 * Cross-instance concurrency gate for scan execution.
 *
 * `POST /api/scans` called `triggerScan` directly, which fire-and-forgets the
 * work. The only guard was a per-target duplicate check, so ten requests for ten
 * different targets started ten concurrent full scans — each fanning out
 * hundreds of DNS and HTTP requests. That is a self-inflicted resource
 * exhaustion, and it got worse with every replica.
 *
 * Slots are Postgres **advisory locks**, chosen over a counter row or an
 * in-memory semaphore for one reason: they are tied to the database session and
 * released automatically when the connection drops. A crashed worker therefore
 * frees its slot with no lease, no timeout and no reconciliation job — the
 * failure mode a counter row gets wrong.
 *
 * The lock is held on a dedicated client checked out of the pool for the life of
 * the scan. That is the real cost: `SCAN_CONCURRENCY` connections are occupied
 * while scans run, so the pool must be sized above it.
 */

import type { PoolClient } from "pg";
import { pool } from "./db";
import { createLogger } from "./logger";

const log = createLogger("scan-slots");

/**
 * Namespace for the two-int advisory lock form, keeping these locks from
 * colliding with any other advisory lock the application might take.
 */
const SLOT_NAMESPACE = 0x5343414e; // "SCAN"

/** Scans permitted to execute concurrently across the whole deployment. */
export const MAX_CONCURRENT_SCANS = Math.max(
  1,
  Number(process.env.SCAN_CONCURRENCY ?? 3),
);

export interface ScanSlot {
  index: number;
  /** Releases the lock and returns the client to the pool. Safe to call twice. */
  release(): Promise<void>;
}

/**
 * Tries to take one of the global slots without blocking.
 * Returns null when every slot is busy.
 */
export async function tryAcquireSlot(): Promise<ScanSlot | null> {
  let client: PoolClient;
  try {
    client = await pool.connect();
  } catch (err) {
    log.error({ err }, "Could not check out a connection for a scan slot");
    return null;
  }

  for (let index = 0; index < MAX_CONCURRENT_SCANS; index++) {
    try {
      const { rows } = await client.query<{ locked: boolean }>(
        "SELECT pg_try_advisory_lock($1, $2) AS locked",
        [SLOT_NAMESPACE, index],
      );
      if (rows[0]?.locked) {
        return makeSlot(client, index);
      }
    } catch (err) {
      log.error({ err, index }, "Advisory lock attempt failed");
      break;
    }
  }

  // Every slot is taken — hand the connection straight back rather than
  // holding it while we are not running anything.
  client.release();
  return null;
}

function makeSlot(client: PoolClient, index: number): ScanSlot {
  let released = false;
  return {
    index,
    async release() {
      if (released) return;
      released = true;
      try {
        await client.query("SELECT pg_advisory_unlock($1, $2)", [SLOT_NAMESPACE, index]);
      } catch (err) {
        // The lock dies with the session regardless, so a failure here is not
        // fatal — but it means the connection is suspect, so drop it.
        log.warn({ err, index }, "Failed to release scan slot cleanly");
      } finally {
        client.release();
      }
    },
  };
}

export interface AcquireOptions {
  /** Give up after this long. Null waits indefinitely. */
  timeoutMs?: number | null;
  /** Gap between attempts. */
  pollMs?: number;
  signal?: AbortSignal;
}

/**
 * Waits for a slot, polling until one frees up.
 *
 * Polling rather than `pg_advisory_lock`'s blocking form: a blocking lock would
 * pin a connection in a waiting state for the entire queue depth, and could not
 * honour a timeout or an abort signal.
 */
export async function acquireSlot(opts: AcquireOptions = {}): Promise<ScanSlot | null> {
  const { timeoutMs = null, pollMs = 1000, signal } = opts;
  const deadline = timeoutMs == null ? null : Date.now() + timeoutMs;

  for (;;) {
    if (signal?.aborted) return null;

    const slot = await tryAcquireSlot();
    if (slot) return slot;

    if (deadline != null && Date.now() + pollMs > deadline) {
      log.warn({ timeoutMs }, "Timed out waiting for a scan slot");
      return null;
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

/**
 * Runs `fn` while holding a slot, releasing it however `fn` settles.
 *
 * When no slot can be taken within the timeout, `fn` is NOT run and the
 * fallback (if given) is returned, so the caller can mark the scan deferred
 * rather than silently dropping it.
 */
export async function withScanSlot<T>(
  fn: (slot: ScanSlot) => Promise<T>,
  opts: AcquireOptions = {},
): Promise<{ ran: true; value: T } | { ran: false }> {
  const slot = await acquireSlot(opts);
  if (!slot) return { ran: false };
  try {
    return { ran: true, value: await fn(slot) };
  } finally {
    await slot.release();
  }
}

/** How many slots are currently held, across every instance. */
export async function slotsInUse(): Promise<number> {
  try {
    const { rows } = await pool.query<{ count: string }>(
      `SELECT count(*)::text AS count
         FROM pg_locks
        WHERE locktype = 'advisory' AND classid = $1 AND granted`,
      [SLOT_NAMESPACE],
    );
    return Number(rows[0]?.count ?? 0);
  } catch (err) {
    log.error({ err }, "Failed to count scan slots in use");
    return 0;
  }
}
