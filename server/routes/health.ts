import { Router } from "express";
import { pool } from "../db";
import { createLogger } from "../logger";

const log = createLogger("health");

export const healthRouter = Router();

/** Process start, so /healthz can report uptime without a global. */
const STARTED_AT = Date.now();

/** Readiness probes are cheap but not free; cache a healthy result briefly. */
const READY_CACHE_MS = 2_000;
let lastReady: { at: number; ok: boolean; latencyMs: number } | null = null;

async function checkDatabase(): Promise<{ ok: boolean; latencyMs: number }> {
  const cached = lastReady;
  if (cached && Date.now() - cached.at < READY_CACHE_MS && cached.ok) {
    return { ok: true, latencyMs: cached.latencyMs };
  }
  const started = Date.now();
  try {
    await pool.query("SELECT 1");
    const latencyMs = Date.now() - started;
    lastReady = { at: Date.now(), ok: true, latencyMs };
    return { ok: true, latencyMs };
  } catch (err) {
    log.error({ err }, "Readiness check failed: database unreachable");
    lastReady = { at: Date.now(), ok: false, latencyMs: Date.now() - started };
    return { ok: false, latencyMs: Date.now() - started };
  }
}

/**
 * Liveness — "is the process up?". Deliberately touches no dependency, so a
 * database outage does not cause an orchestrator to kill and restart an
 * otherwise healthy process (which would not fix the database).
 */
healthRouter.get("/healthz", (_req, res) => {
  res.status(200).json({
    status: "ok",
    uptimeSeconds: Math.floor((Date.now() - STARTED_AT) / 1000),
    version: process.env.APP_VERSION ?? "dev",
  });
});

/**
 * Readiness — "should this instance receive traffic?". Verifies the database,
 * because every meaningful request needs it. Returns 503 when not ready so load
 * balancers and `docker compose` health checks drain the instance instead of
 * serving errors.
 */
healthRouter.get("/readyz", async (_req, res) => {
  const db = await checkDatabase();
  const body = {
    status: db.ok ? "ready" : "not_ready",
    checks: { database: { ok: db.ok, latencyMs: db.latencyMs } },
    uptimeSeconds: Math.floor((Date.now() - STARTED_AT) / 1000),
    version: process.env.APP_VERSION ?? "dev",
  };
  res.status(db.ok ? 200 : 503).json(body);
});
