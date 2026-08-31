import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Options } from "express-rate-limit";

/**
 * The property that matters: counters are SHARED, so the login limit is a
 * global budget rather than a per-process one. The second property is that a
 * database outage fails OPEN — refusing all traffic because the counter table
 * is unreachable would turn a blip into an outage.
 */

const poolQuery = vi.fn();
vi.mock("../../../server/db", () => ({ pool: { query: (...a: unknown[]) => poolQuery(...a) } }));

let mod: typeof import("../../../server/rate-limit-store");

beforeEach(async () => {
  vi.resetModules();
  poolQuery.mockReset();
  mod = await import("../../../server/rate-limit-store");
});

function store(ns = "login") {
  const s = new mod.PostgresRateLimitStore(ns);
  s.init({ windowMs: 60_000 } as Options);
  return s;
}

describe("increment", () => {
  it("returns the shared hit count and reset time", async () => {
    const expires = new Date(Date.now() + 60_000);
    poolQuery.mockResolvedValueOnce({ rows: [{ hits: 3, expires_at: expires }] });

    const res = await store().increment("203.0.113.9");

    expect(res.totalHits).toBe(3);
    expect(res.resetTime).toEqual(expires);
  });

  it("namespaces the key so limiters cannot share a counter", async () => {
    poolQuery.mockResolvedValue({ rows: [{ hits: 1, expires_at: new Date() }] });

    await store("login").increment("1.2.3.4");
    await store("scans").increment("1.2.3.4");

    expect(poolQuery.mock.calls[0]![1]![0]).toBe("login:1.2.3.4");
    expect(poolQuery.mock.calls[1]![1]![0]).toBe("scans:1.2.3.4");
  });

  it("uses a single UPSERT, so concurrent instances serialise on the key", async () => {
    poolQuery.mockResolvedValue({ rows: [{ hits: 1, expires_at: new Date() }] });
    await store().increment("k");

    const sql = String(poolQuery.mock.calls[0]![0]);
    expect(sql).toContain("INSERT INTO rate_limits");
    expect(sql).toContain("ON CONFLICT (key) DO UPDATE");
  });

  it("restarts the count at 1 when the window has expired", async () => {
    poolQuery.mockResolvedValue({ rows: [{ hits: 1, expires_at: new Date() }] });
    await store().increment("k");

    const sql = String(poolQuery.mock.calls[0]![0]);
    // Carrying the previous window's count forward would lock a client out
    // permanently once they hit the limit.
    expect(sql).toContain("WHEN rate_limits.expires_at <= now() THEN 1");
    expect(sql).toContain("ELSE rate_limits.hits + 1");
  });

  it("derives the window length from the middleware options", async () => {
    poolQuery.mockResolvedValue({ rows: [{ hits: 1, expires_at: new Date() }] });
    const s = new mod.PostgresRateLimitStore("login");
    s.init({ windowMs: 120_000 } as Options);
    await s.increment("k");

    expect(poolQuery.mock.calls[0]![1]![1]).toBe(120);
  });

  it("fails OPEN when the database is unreachable", async () => {
    poolQuery.mockRejectedValueOnce(new Error("ECONNREFUSED"));

    const res = await store().increment("k");

    // One hit, not the limit: a counter outage must not deny every request.
    expect(res.totalHits).toBe(1);
    expect(res.resetTime).toBeInstanceOf(Date);
  });
});

describe("localKeys", () => {
  it("declares counters as shared, not per-process", () => {
    // This is what tells express-rate-limit the store is distributed; getting it
    // wrong produces a spurious double-count warning and misleads the reader
    // about whether the limit is actually global.
    expect(store().localKeys).toBe(false);
  });
});

describe("get", () => {
  it("returns the live counter", async () => {
    const expires = new Date(Date.now() + 30_000);
    poolQuery.mockResolvedValueOnce({ rows: [{ hits: 4, expires_at: expires }] });
    expect(await store().get("k")).toEqual({ totalHits: 4, resetTime: expires });
  });

  it("returns undefined when there is no live window", async () => {
    poolQuery.mockResolvedValueOnce({ rows: [] });
    expect(await store().get("k")).toBeUndefined();
  });

  it("ignores expired windows in the query", async () => {
    poolQuery.mockResolvedValueOnce({ rows: [] });
    await store().get("k");
    expect(String(poolQuery.mock.calls[0]![0])).toContain("expires_at > now()");
  });

  it("returns undefined rather than throwing on a database error", async () => {
    poolQuery.mockRejectedValueOnce(new Error("db down"));
    expect(await store().get("k")).toBeUndefined();
  });
});

describe("decrement and reset", () => {
  it("never drives a counter below zero", async () => {
    poolQuery.mockResolvedValueOnce({ rowCount: 1 });
    await store().decrement("k");
    expect(String(poolQuery.mock.calls[0]![0])).toContain("GREATEST(0, hits - 1)");
  });

  it("resetKey removes only that client's counter", async () => {
    poolQuery.mockResolvedValueOnce({ rowCount: 1 });
    await store().resetKey("1.2.3.4");
    expect(poolQuery.mock.calls[0]![1]).toEqual(["login:1.2.3.4"]);
  });

  it("resetAll is scoped to the namespace", async () => {
    poolQuery.mockResolvedValueOnce({ rowCount: 3 });
    await store("scans").resetAll();
    // Must not wipe the login limiter's counters as a side effect.
    expect(poolQuery.mock.calls[0]![1]).toEqual(["scans:%"]);
  });

  it("swallows database errors on decrement", async () => {
    poolQuery.mockRejectedValueOnce(new Error("db down"));
    await expect(store().decrement("k")).resolves.toBeUndefined();
  });
});

describe("cleanup", () => {
  it("deletes only expired windows and reports the count", async () => {
    poolQuery.mockResolvedValueOnce({ rowCount: 7 });
    expect(await mod.cleanupExpiredRateLimits()).toBe(7);
    expect(String(poolQuery.mock.calls[0]![0])).toContain("expires_at <= now()");
  });

  it("reports zero rather than throwing when cleanup fails", async () => {
    poolQuery.mockRejectedValueOnce(new Error("db down"));
    expect(await mod.cleanupExpiredRateLimits()).toBe(0);
  });

  it("starts and stops idempotently", () => {
    expect(() => mod.startRateLimitCleanup()).not.toThrow();
    expect(() => mod.startRateLimitCleanup()).not.toThrow();
    expect(() => mod.stopRateLimitCleanup()).not.toThrow();
    expect(() => mod.stopRateLimitCleanup()).not.toThrow();
  });
});
