/**
 * Postgres-backed store for express-rate-limit.
 *
 * The default MemoryStore keeps counters in process memory, so with N replicas
 * the effective limit is N × the configured value. For the general 100/min
 * throttle that is merely imprecise; for `POST /auth/login` at 5/min it defeats
 * the purpose, because the limit exists specifically to slow credential
 * stuffing and an attacker's requests spread across replicas.
 *
 * ── Why Postgres and not Redis ──────────────────────────────────────────────
 * Redis is the conventional answer and would be faster, but this product is
 * self-hosted and Postgres is already a hard dependency. Adding Redis would
 * make every operator run and secure another service to fix a problem they may
 * not have. If throughput ever justifies it, this Store interface is the seam
 * to swap behind.
 *
 * ── Why a fixed window ──────────────────────────────────────────────────────
 * A sliding window needs a row per request. A fixed window is one UPSERT per
 * request, which matters when this sits in the hot path of every login. The
 * cost is the usual fixed-window burst: a client can spend its full budget at
 * the end of one window and again at the start of the next. For brute-force
 * throttling that is acceptable — and the per-account lockout in server/auth.ts
 * is the control that actually stops a determined attempt.
 */

import type { Store, Options, ClientRateLimitInfo, IncrementResponse } from "express-rate-limit";
import { pool } from "./db";
import { createLogger } from "./logger";

const log = createLogger("rate-limit-store");

/** Sweep interval for expired windows. Rows are tiny; hourly is plenty. */
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;

let cleanupTimer: ReturnType<typeof setInterval> | null = null;

export class PostgresRateLimitStore implements Store {
  private windowMs = 60_000;

  /**
   * Counters are shared through the database, so express-rate-limit must not
   * warn about double counting across instances.
   */
  readonly localKeys = false;

  constructor(private readonly namespace: string) {}

  init(options: Options): void {
    this.windowMs = options.windowMs;
  }

  private scoped(key: string): string {
    // Namespaced so the login and scan limiters cannot share a counter for the
    // same client IP.
    return `${this.namespace}:${key}`;
  }

  /**
   * Increments a client's counter, rolling the window when the old one expired.
   *
   * Done as a single statement: the UPSERT either starts a fresh window or adds
   * to the live one, and `ON CONFLICT` makes concurrent requests from different
   * instances serialise on the primary key rather than racing.
   */
  async increment(key: string): Promise<IncrementResponse> {
    const scoped = this.scoped(key);
    const windowSeconds = Math.ceil(this.windowMs / 1000);

    try {
      const { rows } = await pool.query<{ hits: number; expires_at: Date }>(
        `INSERT INTO rate_limits (key, window_start, hits, expires_at)
         VALUES ($1, now(), 1, now() + ($2::int * interval '1 second'))
         ON CONFLICT (key) DO UPDATE
           SET hits = CASE
                        -- Expired window: start over at 1 rather than carrying
                        -- the previous window's count forward.
                        WHEN rate_limits.expires_at <= now() THEN 1
                        ELSE rate_limits.hits + 1
                      END,
               window_start = CASE
                                WHEN rate_limits.expires_at <= now() THEN now()
                                ELSE rate_limits.window_start
                              END,
               expires_at = CASE
                              WHEN rate_limits.expires_at <= now()
                                THEN now() + ($2::int * interval '1 second')
                              ELSE rate_limits.expires_at
                            END
         RETURNING hits, expires_at`,
        [scoped, windowSeconds],
      );

      const row = rows[0]!;
      return { totalHits: row.hits, resetTime: new Date(row.expires_at) };
    } catch (err) {
      // FAIL OPEN, deliberately. If the database is unreachable the request is
      // already going to fail on its own merits; refusing traffic here would
      // turn a database blip into a total outage. The account lockout is the
      // control that must not fail open, and it does not — it reads committed
      // state and denies when it cannot.
      log.error({ err, key: scoped }, "Rate limit store unavailable; allowing request");
      return { totalHits: 1, resetTime: new Date(Date.now() + this.windowMs) };
    }
  }

  async get(key: string): Promise<ClientRateLimitInfo | undefined> {
    try {
      const { rows } = await pool.query<{ hits: number; expires_at: Date }>(
        `SELECT hits, expires_at FROM rate_limits WHERE key = $1 AND expires_at > now()`,
        [this.scoped(key)],
      );
      const row = rows[0];
      if (!row) return undefined;
      return { totalHits: row.hits, resetTime: new Date(row.expires_at) };
    } catch (err) {
      log.error({ err }, "Failed to read rate limit counter");
      return undefined;
    }
  }

  /** Used when a handler opts out of counting a request it already counted. */
  async decrement(key: string): Promise<void> {
    try {
      await pool.query(
        `UPDATE rate_limits SET hits = GREATEST(0, hits - 1)
          WHERE key = $1 AND expires_at > now()`,
        [this.scoped(key)],
      );
    } catch (err) {
      log.error({ err }, "Failed to decrement rate limit counter");
    }
  }

  async resetKey(key: string): Promise<void> {
    try {
      await pool.query(`DELETE FROM rate_limits WHERE key = $1`, [this.scoped(key)]);
    } catch (err) {
      log.error({ err }, "Failed to reset rate limit key");
    }
  }

  async resetAll(): Promise<void> {
    try {
      await pool.query(`DELETE FROM rate_limits WHERE key LIKE $1`, [`${this.namespace}:%`]);
    } catch (err) {
      log.error({ err }, "Failed to reset rate limit namespace");
    }
  }
}

/** Deletes expired windows so the table does not accumulate dead rows. */
export async function cleanupExpiredRateLimits(): Promise<number> {
  try {
    const { rowCount } = await pool.query(`DELETE FROM rate_limits WHERE expires_at <= now()`);
    return rowCount ?? 0;
  } catch (err) {
    log.error({ err }, "Rate limit cleanup failed");
    return 0;
  }
}

export function startRateLimitCleanup(): void {
  if (cleanupTimer) return;
  cleanupTimer = setInterval(() => {
    void cleanupExpiredRateLimits().then((n) => {
      if (n > 0) log.debug({ deleted: n }, "Cleaned expired rate limit windows");
    });
  }, CLEANUP_INTERVAL_MS);
  log.info("Rate limit cleanup started");
}

export function stopRateLimitCleanup(): void {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
  }
}
