/**
 * Unit tests for server/scanner/stealth.ts — the stealth engine that governs
 * outbound request pacing, concurrency, and User-Agent rotation.
 */

import { describe, it, expect } from "vitest";
import {
  resolveProfile,
  StealthController,
  runWithStealth,
  getController,
  currentProfile,
  USER_AGENTS,
  DEFAULT_USER_AGENT,
} from "../../../server/scanner/stealth";

describe("resolveProfile", () => {
  it("returns the standard profile by default and for unknown modes", () => {
    for (const mode of [undefined, null, "", "bogus"]) {
      const p = resolveProfile(mode as string | undefined);
      expect(p.mode).toBe("standard");
      expect(p.fullCoverage).toBe(false);
      expect(p.stealth).toBe(false);
      expect(p.minDelayMs).toBe(0);
    }
  });

  it("gold is full-coverage, fast, and allows intrusive probes", () => {
    const p = resolveProfile("gold");
    expect(p.mode).toBe("gold");
    expect(p.fullCoverage).toBe(true);
    expect(p.stealth).toBe(false);
    expect(p.allowIntrusive).toBe(true);
    expect(p.minDelayMs).toBe(0);
    expect(p.nuclei.allTemplates).toBe(true);
  });

  it("safe is full-coverage, stealthy, throttled, and NOT intrusive", () => {
    const p = resolveProfile("safe");
    expect(p.mode).toBe("safe");
    expect(p.fullCoverage).toBe(true);
    expect(p.stealth).toBe(true);
    expect(p.allowIntrusive).toBe(false);
    expect(p.httpConcurrency).toBeLessThanOrEqual(3);
    expect(p.minDelayMs).toBeGreaterThan(0);
    expect(p.maxDelayMs).toBeGreaterThan(p.minDelayMs);
    expect(p.rotateUserAgent).toBe(true);
    // Full templates for coverage, but a low request rate for stealth.
    expect(p.nuclei.allTemplates).toBe(true);
    expect(p.nuclei.rateLimit).toBeLessThan(resolveProfile("gold").nuclei.rateLimit);
  });
});

describe("StealthController concurrency", () => {
  it("never exceeds the profile's httpConcurrency cap", async () => {
    const profile = { ...resolveProfile("safe"), httpConcurrency: 2, minDelayMs: 0, maxDelayMs: 0 };
    const controller = new StealthController(profile);

    let active = 0;
    let peak = 0;
    const task = () =>
      controller.run(async () => {
        active++;
        peak = Math.max(peak, active);
        await new Promise((r) => setTimeout(r, 15));
        active--;
      });

    await Promise.all(Array.from({ length: 10 }, task));
    expect(peak).toBeLessThanOrEqual(2);
  });

  it("paces successive dispatches by at least the min delay", async () => {
    const profile = { ...resolveProfile("safe"), httpConcurrency: 1, minDelayMs: 30, maxDelayMs: 30 };
    const controller = new StealthController(profile);
    const start = Date.now();
    for (let i = 0; i < 3; i++) {
      await controller.run(async () => {});
    }
    // 3 dispatches spaced ~30ms apart → at least ~2 gaps of delay.
    expect(Date.now() - start).toBeGreaterThanOrEqual(45);
  });
});

describe("StealthController.nextUserAgent", () => {
  it("returns the fixed default UA when rotation is off", () => {
    const controller = new StealthController(resolveProfile("standard"));
    expect(controller.nextUserAgent()).toBe(DEFAULT_USER_AGENT);
    expect(controller.nextUserAgent()).toBe(DEFAULT_USER_AGENT);
  });

  it("rotates through the pool when rotation is on", () => {
    const controller = new StealthController(resolveProfile("safe"));
    const seen = new Set<string>();
    for (let i = 0; i < USER_AGENTS.length; i++) seen.add(controller.nextUserAgent());
    expect(seen.size).toBe(USER_AGENTS.length);
    // Every emitted UA is a real browser UA (not a scanner signature).
    for (const ua of seen) expect(ua).toMatch(/Mozilla\/5\.0/);
  });
});

describe("runWithStealth context", () => {
  it("exposes the resolved profile to code running inside the context", async () => {
    const modeSeen = await runWithStealth("safe", async () => currentProfile().mode);
    expect(modeSeen).toBe("safe");
  });

  it("falls back to a passthrough standard controller outside any context", () => {
    expect(getController().profile.mode).toBe("standard");
  });

  it("reuses the outer context for nested calls (global pacing)", async () => {
    const inner = await runWithStealth("safe", async () => {
      return runWithStealth("gold", async () => currentProfile().mode);
    });
    // The nested call must NOT reset pacing to gold — the outer safe wins.
    expect(inner).toBe("safe");
  });
});

/**
 * The deployment-wide outbound ceiling.
 *
 * `httpConcurrency` is a PER-SCAN budget and `runWithStealth` builds a fresh
 * controller per scan, so the limit multiplied by however many scans ran at
 * once — 64 x 3 = 192 concurrent sockets on default settings. For safe mode it
 * was worse than a resource problem: an operator choosing "low-and-slow" is
 * stating an intent about the rate the TARGET sees, and three concurrent safe
 * scans quietly emitted three times it.
 */
describe("global outbound ceiling", () => {
  it("reports its configuration and starts idle", async () => {
    const { outboundStats } = await import("../../../server/scanner/stealth");
    const stats = outboundStats();
    expect(stats.max).toBeGreaterThan(0);
    expect(stats.inFlight).toBe(0);
  });

  /**
   * The property that matters: two independent scan contexts must not each get
   * a full budget's worth of sockets.
   */
  it("bounds concurrency ACROSS independent scan contexts, not just within one", async () => {
    const { runWithStealth, getController, outboundStats } = await import("../../../server/scanner/stealth");
    const max = outboundStats().max;

    let peak = 0;
    let live = 0;
    const release: Array<() => void> = [];

    const task = () => getController().run(async () => {
      live++;
      peak = Math.max(peak, live);
      await new Promise<void>((r) => release.push(() => { live--; r(); }));
    });

    // Two separate stealth contexts, each firing more work than the global cap.
    const runners = [
      runWithStealth("standard", async () => { await Promise.all(Array.from({ length: max }, task)); }),
      runWithStealth("standard", async () => { await Promise.all(Array.from({ length: max }, task)); }),
    ];

    // Let everything that can start, start.
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    expect(peak).toBeLessThanOrEqual(max);

    // Drain: each release admits a queued waiter, so this must terminate.
    while (release.length > 0) {
      release.shift()!();
      await new Promise((r) => setImmediate(r));
    }
    await Promise.all(runners);
    expect(outboundStats().inFlight).toBe(0);
  });

  it("returns every slot even when the task throws", async () => {
    const { runWithStealth, getController, outboundStats } = await import("../../../server/scanner/stealth");
    await runWithStealth("standard", async () => {
      await expect(
        getController().run(async () => { throw new Error("boom"); }),
      ).rejects.toThrow("boom");
    });
    expect(outboundStats().inFlight).toBe(0);
  });
});
