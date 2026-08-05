/**
 * Unit tests for server/scanner/utils.ts — runWithConcurrency.
 *
 * Tests: concurrency limiting, abort signal, error handling.
 * This is a pure async utility with no external dependencies.
 */

import { describe, it, expect } from "vitest";

import { runWithConcurrency, makeConcurrencyProgress } from "../../../server/scanner/utils";

describe("runWithConcurrency onProgress", () => {
  it("reports completion count for every item, ending at total", async () => {
    const calls: Array<[number, number]> = [];
    await runWithConcurrency([1, 2, 3, 4, 5], 2, async (x) => x, undefined, (done, total) => calls.push([done, total]));
    expect(calls).toHaveLength(5);
    expect(calls.every(([, total]) => total === 5)).toBe(true);
    expect(calls[calls.length - 1][0]).toBe(5);
    // completion counts are monotonic 1..5
    expect(calls.map(([d]) => d).sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5]);
  });

  it("still reports progress when items throw", async () => {
    let last = 0;
    await runWithConcurrency([1, 2, 3], 3, async (x) => { if (x === 2) throw new Error("boom"); return x; }, undefined, (done) => { last = done; });
    expect(last).toBe(3);
  });
});

describe("makeConcurrencyProgress", () => {
  it("maps completion onto a [from,to] band and only fires on whole-percent increases", () => {
    const pcts: number[] = [];
    const cb = makeConcurrencyProgress(0, 14, (pct) => pcts.push(pct));
    for (let i = 1; i <= 100; i++) cb(i, 100);
    expect(pcts[0]).toBeGreaterThanOrEqual(0);
    expect(pcts[pcts.length - 1]).toBe(14);
    // strictly increasing, no duplicates (throttled)
    for (let i = 1; i < pcts.length; i++) expect(pcts[i]).toBeGreaterThan(pcts[i - 1]);
    // never exceeds the band
    expect(Math.max(...pcts)).toBeLessThanOrEqual(14);
  });

  it("maps into a non-zero base band (e.g. 16→52)", () => {
    const pcts: number[] = [];
    const cb = makeConcurrencyProgress(16, 52, (pct) => pcts.push(pct));
    cb(1, 10); cb(5, 10); cb(10, 10);
    expect(pcts[0]).toBeGreaterThanOrEqual(16);
    expect(pcts[pcts.length - 1]).toBe(52);
  });

  it("is a no-op when total is zero", () => {
    let fired = false;
    const cb = makeConcurrencyProgress(0, 14, () => { fired = true; });
    cb(0, 0);
    expect(fired).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// runWithConcurrency
// ---------------------------------------------------------------------------
describe("runWithConcurrency", () => {
  it("processes all items and returns results in order", async () => {
    const items = [1, 2, 3, 4, 5];
    const results = await runWithConcurrency(items, 2, async (n) => n * 10);
    expect(results).toEqual([10, 20, 30, 40, 50]);
  });

  it("returns empty array for empty input", async () => {
    const results = await runWithConcurrency([], 5, async (n: number) => n);
    expect(results).toEqual([]);
  });

  it("limits concurrency to the specified value", async () => {
    let maxActive = 0;
    let active = 0;

    const items = [1, 2, 3, 4, 5, 6, 7, 8];
    await runWithConcurrency(items, 3, async (n) => {
      active++;
      if (active > maxActive) maxActive = active;
      // Simulate async work
      await new Promise((r) => setTimeout(r, 10));
      active--;
      return n;
    });

    expect(maxActive).toBeLessThanOrEqual(3);
  });

  it("handles concurrency of 1 (sequential)", async () => {
    const order: number[] = [];
    const items = [1, 2, 3];
    await runWithConcurrency(items, 1, async (n) => {
      order.push(n);
      return n;
    });
    expect(order).toEqual([1, 2, 3]);
  });

  it("handles concurrency greater than item count", async () => {
    const items = [1, 2];
    const results = await runWithConcurrency(items, 100, async (n) => n * 2);
    expect(results).toEqual([2, 4]);
  });

  it("continues processing when individual items throw", async () => {
    const items = [1, 2, 3, 4];
    const results = await runWithConcurrency(items, 2, async (n) => {
      if (n === 2) throw new Error("item 2 failed");
      return n * 10;
    });
    // Item 2 should be undefined (error caught), others should succeed
    expect(results[0]).toBe(10);
    expect(results[1]).toBeUndefined();
    expect(results[2]).toBe(30);
    expect(results[3]).toBe(40);
  });

  it("aborts via AbortSignal", async () => {
    const controller = new AbortController();
    const items = [1, 2, 3, 4, 5];
    let processed = 0;

    const promise = runWithConcurrency(items, 1, async (n) => {
      processed++;
      if (n === 2) controller.abort();
      await new Promise((r) => setTimeout(r, 5));
      return n;
    }, controller.signal);

    await expect(promise).rejects.toThrow("Scan aborted");
    // Should have started processing but not completed all
    expect(processed).toBeLessThan(5);
  });

  it("preserves result order even with varying delays", async () => {
    const items = [30, 10, 20]; // delays in ms
    const results = await runWithConcurrency(items, 3, async (delay) => {
      await new Promise((r) => setTimeout(r, delay));
      return delay;
    });
    // Results should be in original order, not completion order
    expect(results).toEqual([30, 10, 20]);
  });
});
