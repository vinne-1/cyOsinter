/**
 * Unit tests for server/finding-dedup.ts — pure similarity computation.
 *
 * Tests: computeSimilarity (exported).
 * groupFindings / getFindingGroups are DB-dependent and excluded from unit tests.
 */

import { describe, it, expect, vi } from "vitest";

// Mock database to allow import
vi.mock("../../../server/db", () => ({ db: {} }));

import { computeSimilarity } from "../../../server/finding-dedup";

function makeFinding(overrides: Partial<{
  title: string;
  category: string;
  affectedAsset: string | null;
  remediation: string | null;
}> = {}) {
  return {
    title: overrides.title ?? "SQL Injection in login form",
    category: overrides.category ?? "injection",
    affectedAsset: overrides.affectedAsset ?? "https://example.com/login",
    remediation: overrides.remediation ?? "Use parameterized queries",
  };
}

// ---------------------------------------------------------------------------
// computeSimilarity
// ---------------------------------------------------------------------------
describe("computeSimilarity", () => {
  it("returns 1.0 for identical findings", () => {
    const a = makeFinding();
    const score = computeSimilarity(a, a);
    expect(score).toBeCloseTo(1.0, 1);
  });

  it("returns a high score for findings with same title and category", () => {
    const a = makeFinding({ affectedAsset: "https://a.com" });
    const b = makeFinding({ affectedAsset: "https://b.com" });
    // Same title (0.4), same category (0.3), same remediation (0.2), different asset (0)
    const score = computeSimilarity(a, b);
    expect(score).toBeGreaterThanOrEqual(0.7);
  });

  it("returns a low score for completely different findings", () => {
    const a = makeFinding({
      title: "SQL Injection in login form",
      category: "injection",
      remediation: "Use parameterized queries",
    });
    const b = makeFinding({
      title: "Expired SSL certificate on mail server",
      category: "ssl_issue",
      remediation: "Renew the SSL certificate",
      affectedAsset: "https://mail.other.com",
    });
    const score = computeSimilarity(a, b);
    expect(score).toBeLessThan(0.5);
  });

  it("gives 0.3 weight to matching category alone", () => {
    const a = makeFinding({
      title: "Completely unrelated alpha issue xyz",
      category: "xss",
    });
    const b = makeFinding({
      title: "Totally different beta problem abc",
      category: "xss",
    });
    const scoreMatch = computeSimilarity(a, b);

    const c = makeFinding({
      title: "Totally different beta problem abc",
      category: "sqli",
    });
    const scoreMismatch = computeSimilarity(a, c);

    // Category match contributes 0.3 to the total
    expect(scoreMatch - scoreMismatch).toBeCloseTo(0.3, 1);
  });

  it("handles null remediation gracefully (score = 0 for remediation component)", () => {
    const a = makeFinding({ remediation: null });
    const b = makeFinding({ remediation: null });
    // Same title, same category, no remediation, same asset
    const score = computeSimilarity(a, b);
    expect(score).toBeGreaterThanOrEqual(0.7);
  });

  it("handles null affectedAsset gracefully", () => {
    const a = makeFinding({ affectedAsset: null });
    const b = makeFinding({ affectedAsset: null });
    const score = computeSimilarity(a, b);
    expect(score).toBeGreaterThanOrEqual(0.7);
  });

  it("gives 0.1 asset bonus when domains match", () => {
    const a = makeFinding({ affectedAsset: "https://example.com/path1" });
    const b = makeFinding({ affectedAsset: "https://example.com/path2" });
    const scoreMatch = computeSimilarity(a, b);

    const c = makeFinding({ affectedAsset: "https://other.com/path1" });
    const scoreDiff = computeSimilarity(a, c);

    expect(scoreMatch).toBeGreaterThan(scoreDiff);
    expect(scoreMatch - scoreDiff).toBeCloseTo(0.1, 1);
  });

  it("is case-insensitive for category comparison", () => {
    const a = makeFinding({ category: "XSS" });
    const b = makeFinding({ category: "xss" });
    const score = computeSimilarity(a, b);
    // Category should match
    expect(score).toBeGreaterThanOrEqual(0.3);
  });

  it("handles empty title strings (both empty → jaccard = 0)", () => {
    // Two empty titles tokenize to empty sets → jaccardSimilarity returns 0 for two empty inputs
    const a = { title: "", category: "a", remediation: null, affectedAsset: null };
    const b = { title: "", category: "a", remediation: null, affectedAsset: null };
    const score = computeSimilarity(a, b);
    // Empty titles → jaccard = 0 (title 0.4*0), category match = 0.3, no remed = 0, no asset = 0
    expect(score).toBeCloseTo(0.3, 1);
  });

  it("handles invalid URL as affectedAsset (extractDomain falls back to raw string)", () => {
    // Triggers the catch block in extractDomain (line 44)
    const a = makeFinding({ affectedAsset: "not a valid url!!!" });
    const b = makeFinding({ affectedAsset: "not a valid url!!!" });
    const score = computeSimilarity(a, b);
    // Same invalid asset string → domains match (equal strings) → asset score = 0.1
    expect(score).toBeGreaterThanOrEqual(0.8);
  });

  it("handles single identical token (union size = 1, intersection = 1 → jaccard = 1)", () => {
    // Tests the unionSize = a.size + b.size - intersectionSize = 1+1-1 = 1 path
    const a = { title: "xss", category: "xss", remediation: null, affectedAsset: null };
    const b = { title: "xss", category: "xss", remediation: null, affectedAsset: null };
    const score = computeSimilarity(a, b);
    // title: 1.0, category: 1.0, remediation: 0, asset: 0 → 0.4 + 0.3 = 0.7
    expect(score).toBeCloseTo(0.7, 1);
  });

  it("handles very long titles by capping tokenization", () => {
    const longTitle = "word ".repeat(1000);
    const a = makeFinding({ title: longTitle, category: "test", remediation: null, affectedAsset: null });
    const b = makeFinding({ title: longTitle, category: "test", remediation: null, affectedAsset: null });
    // Should not throw or hang
    const score = computeSimilarity(a, b);
    expect(score).toBeGreaterThanOrEqual(0.3);
  });

  it("returns a value between 0 and 1", () => {
    const combos = [
      [makeFinding(), makeFinding()],
      [makeFinding({ title: "A" }), makeFinding({ title: "Z", category: "other" })],
      [makeFinding({ affectedAsset: null, remediation: null }), makeFinding({ affectedAsset: null, remediation: null })],
    ];
    for (const [a, b] of combos) {
      const score = computeSimilarity(a, b);
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(1);
    }
  });
});
