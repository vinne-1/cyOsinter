/**
 * Change detection is a three-state signal, and the third state is the point.
 *
 * `newSinceLastRun` was hardcoded `false` while the UI rendered a
 * "New Since Last Run" counter and a per-host New/Known badge — a feature that
 * always said "Known" no matter what had appeared. Making it real introduces a
 * trap: with no prior completed scan there is nothing to compare against, and
 * labelling every host "new" is technically true and useless, while labelling
 * them "known" asserts nothing changed. Neither is supportable, so the absence
 * of a baseline has to be its own state.
 *
 * These tests pin the classification itself, independent of the scanner's
 * network work.
 */
import { describe, it, expect } from "vitest";

/**
 * Mirrors the rule in easm-scan.ts: a verdict only exists when a baseline does.
 * `null` baseline means "no prior completed scan", NOT "the baseline was empty".
 */
function classifyHost(host: string, baseline: Set<string> | null): boolean | undefined {
  return baseline ? !baseline.has(host.toLowerCase()) : undefined;
}

/** Mirrors the counter in recon-builder.ts. */
function summarise(hosts: Array<{ newSinceLastRun?: boolean }>): { count: number | null; hasBaseline: boolean } {
  const hasBaseline = hosts.some((h) => h.newSinceLastRun !== undefined);
  return {
    hasBaseline,
    count: hasBaseline ? hosts.filter((h) => h.newSinceLastRun === true).length : null,
  };
}

describe("change detection", () => {
  it("marks a host new only when the baseline does not contain it", () => {
    const baseline = new Set(["api.example.com", "www.example.com"]);
    expect(classifyHost("api.example.com", baseline)).toBe(false);
    expect(classifyHost("staging.example.com", baseline)).toBe(true);
  });

  it("compares case-insensitively, since DNS is", () => {
    expect(classifyHost("API.Example.COM", new Set(["api.example.com"]))).toBe(false);
  });

  /**
   * The state the whole design exists for. A first scan must not report every
   * host as a new discovery, nor claim they are all previously known.
   */
  it("returns undefined — neither new nor known — when there is no baseline", () => {
    expect(classifyHost("api.example.com", null)).toBeUndefined();
  });

  /**
   * An EMPTY baseline is different from an absent one: the workspace completed a
   * scan and genuinely knew of no hosts, so anything found now really is new.
   */
  it("treats an empty baseline as a real baseline, not as an absent one", () => {
    expect(classifyHost("api.example.com", new Set())).toBe(true);
  });

  it("counts new hosts only when a verdict exists", () => {
    expect(summarise([
      { newSinceLastRun: true },
      { newSinceLastRun: false },
      { newSinceLastRun: true },
    ])).toEqual({ count: 2, hasBaseline: true });
  });

  it("reports no count at all when nothing carried a verdict", () => {
    expect(summarise([{}, {}])).toEqual({ count: null, hasBaseline: false });
  });

  it("does not report zero-new for a baseline-less scan, which would imply nothing changed", () => {
    const { count, hasBaseline } = summarise([{}, {}]);
    expect(hasBaseline).toBe(false);
    expect(count).not.toBe(0);
  });
});
