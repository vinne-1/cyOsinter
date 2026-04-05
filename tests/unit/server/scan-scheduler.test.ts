/**
 * Unit tests for server/scan-scheduler.ts — cron parsing.
 *
 * Tests: getNextCronRun (exported pure function).
 * startScheduler / stopScheduler / checkDueScans are side-effectful and excluded.
 */

import { describe, it, expect, vi } from "vitest";

// Mock storage and notifications to allow import
vi.mock("../../../server/db", () => ({ db: {} }));
vi.mock("../../../server/storage", () => ({
  storage: {
    getDueScheduledScans: vi.fn().mockResolvedValue([]),
    updateScheduledScan: vi.fn(),
  },
}));
vi.mock("../../../server/notifications", () => ({
  emitScheduledScanTriggered: vi.fn(),
}));

import {
  getNextCronRun,
  startScheduler,
  stopScheduler,
  registerScanTrigger,
} from "../../../server/scan-scheduler";

// ---------------------------------------------------------------------------
// getNextCronRun
// ---------------------------------------------------------------------------
describe("getNextCronRun", () => {
  // Use a fixed reference time for deterministic results
  const ref = new Date("2025-06-15T10:30:00Z"); // Sunday June 15, 2025

  it("parses simple daily cron (0 2 * * *) — next 2:00 AM", () => {
    const next = getNextCronRun("0 2 * * *", ref);
    expect(next.getHours()).toBe(2);
    expect(next.getMinutes()).toBe(0);
    // Should be the next occurrence (same day or next day depending on timezone)
    expect(next.getTime()).toBeGreaterThan(ref.getTime());
  });

  it("parses every-minute cron (* * * * *)", () => {
    const next = getNextCronRun("* * * * *", ref);
    // Should be exactly 1 minute after ref (rounded to next minute)
    expect(next.getTime()).toBeGreaterThan(ref.getTime());
    const diffMs = next.getTime() - ref.getTime();
    expect(diffMs).toBeLessThanOrEqual(60_000);
  });

  it("parses step syntax (*/15 * * * *) — every 15 minutes", () => {
    const next = getNextCronRun("*/15 * * * *", ref);
    expect(next.getTime()).toBeGreaterThan(ref.getTime());
    expect([0, 15, 30, 45]).toContain(next.getMinutes());
  });

  it("parses range syntax (0 9-17 * * *) — hourly 9am to 5pm", () => {
    const next = getNextCronRun("0 9-17 * * *", ref);
    expect(next.getTime()).toBeGreaterThan(ref.getTime());
    expect(next.getMinutes()).toBe(0);
    const hour = next.getHours();
    expect(hour).toBeGreaterThanOrEqual(9);
    expect(hour).toBeLessThanOrEqual(17);
  });

  it("parses list syntax (0 8,12,18 * * *) — specific hours", () => {
    const next = getNextCronRun("0 8,12,18 * * *", ref);
    expect(next.getTime()).toBeGreaterThan(ref.getTime());
    expect(next.getMinutes()).toBe(0);
    expect([8, 12, 18]).toContain(next.getHours());
  });

  it("throws on invalid cron (wrong number of fields)", () => {
    expect(() => getNextCronRun("0 2 * *", ref)).toThrow("Invalid cron expression");
    expect(() => getNextCronRun("0 2 * * * *", ref)).toThrow("Invalid cron expression");
    expect(() => getNextCronRun("", ref)).toThrow("Invalid cron expression");
  });

  it("handles day-of-week restriction (0 9 * * 1) — Mondays only", () => {
    const next = getNextCronRun("0 9 * * 1", ref);
    expect(next.getDay()).toBe(1); // Monday
    expect(next.getHours()).toBe(9);
    expect(next.getMinutes()).toBe(0);
  });

  it("handles day-of-month restriction (0 0 1 * *) — 1st of each month", () => {
    const next = getNextCronRun("0 0 1 * *", ref);
    expect(next.getDate()).toBe(1);
    expect(next.getHours()).toBe(0);
    expect(next.getMinutes()).toBe(0);
  });

  it("handles month restriction (0 0 1 1 *) — January 1st", () => {
    const next = getNextCronRun("0 0 1 1 *", ref);
    expect(next.getMonth()).toBe(0); // January
    expect(next.getDate()).toBe(1);
  });

  it("always returns a date after the reference", () => {
    const expressions = [
      "* * * * *",
      "0 0 * * *",
      "30 6 * * 1-5",
      "0 */4 * * *",
      "0 0 15 * *",
    ];
    for (const expr of expressions) {
      const next = getNextCronRun(expr, ref);
      expect(next.getTime()).toBeGreaterThan(ref.getTime());
    }
  });

  it("falls back to 24h from now if no match found within a year", () => {
    // Month 13 doesn't exist — will never match, so fallback fires
    // Actually cron fields are constrained 1-12 for months. Use something that
    // parses but never matches: month=2 + day=31 (Feb 31 never exists)
    const next = getNextCronRun("0 0 31 2 *", ref);
    // Should fall back to roughly 24h from ref
    const diff = next.getTime() - ref.getTime();
    expect(diff).toBeCloseTo(86_400_000, -3); // within a second
  });

  it("handles whitespace in cron expression", () => {
    const next = getNextCronRun("  0   2   *   *   *  ", ref);
    expect(next.getHours()).toBe(2);
    expect(next.getMinutes()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// registerScanTrigger
// ---------------------------------------------------------------------------
describe("registerScanTrigger", () => {
  it("accepts a function without throwing", () => {
    const fn = vi.fn().mockResolvedValue("scan-123");
    expect(() => registerScanTrigger(fn)).not.toThrow();
  });

  it("accepts null to clear the trigger function", () => {
    expect(() => registerScanTrigger(null)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// startScheduler / stopScheduler
// ---------------------------------------------------------------------------
describe("scheduler lifecycle", () => {
  it("starts and stops without throwing", () => {
    expect(() => startScheduler()).not.toThrow();
    expect(() => stopScheduler()).not.toThrow();
  });

  it("calling stopScheduler when not running is a no-op", () => {
    stopScheduler(); // ensure stopped
    expect(() => stopScheduler()).not.toThrow();
  });

  it("calling startScheduler twice is idempotent", () => {
    expect(() => {
      startScheduler();
      startScheduler(); // second call should be no-op (intervalId already set)
      stopScheduler();
    }).not.toThrow();
  });
});
