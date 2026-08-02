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
