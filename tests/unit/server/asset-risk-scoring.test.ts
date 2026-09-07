/**
 * Unit tests for server/asset-risk-scoring.ts
 *
 * Strategy:
 * - Mock server/storage and server/db at module level so db.ts never runs
 *   (it would throw without DATABASE_URL).
 * - Test pure scoring helpers directly after exporting them.
 * - Test calculateAssetRisk end-to-end with the mocked storage module.
 */

import { describe, it, expect, vi } from "vitest";
import type { Finding } from "../../../shared/schema";
import fs from "fs";
import path from "path";

// ---------------------------------------------------------------------------
// Module-level mocks — must be hoisted before any imports of the module under test.
// Use vi.hoisted() so the mock fns are available inside the vi.mock factory.
// ---------------------------------------------------------------------------
const { mockGetAssets, mockGetFindings } = vi.hoisted(() => ({
  mockGetAssets: vi.fn(),
  mockGetFindings: vi.fn(),
}));

vi.mock("../../../server/db", () => ({
  db: {},
}));

vi.mock("../../../server/storage", () => ({
  storage: {
    getAssets: mockGetAssets,
    getFindings: mockGetFindings,
  },
}));

// Now safe to import the module under test
import {
  indexFindingsByAsset,
  computeCriticalFindingsFactor,
  computeHighFindingsFactor,
  computeExposureFactor,
  computeTlsFactor,
  computeMediumLowFactor,
  computeOverallScore,
  determineTrend,
  countFindingsBySeverity,
  calculateAssetRisk,
} from "../../../server/asset-risk-scoring";

// ---------------------------------------------------------------------------
// Helper — build minimal Finding objects for test data
// ---------------------------------------------------------------------------
function makeFinding(
  overrides: Partial<Finding> & Pick<Finding, "severity" | "category">,
): Finding {
  return {
    id: `f-${Math.random().toString(36).slice(2)}`,
    workspaceId: "ws-1",
    scanId: null,
    title: "Test finding",
    description: "desc",
    status: "open",
    affectedAsset: "example.com",
    evidence: null,
    cvssScore: null,
    remediation: null,
    assignee: null,
    assigneeId: null,
    priority: null,
    dueDate: null,
    slaBreached: false,
    workflowState: "open",
    groupId: null,
    verificationScanId: null,
    discoveredAt: new Date(),
    resolvedAt: null,
    tags: [],
    aiEnrichment: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// countFindingsBySeverity
// ---------------------------------------------------------------------------
describe("countFindingsBySeverity", () => {
  it("returns zero counts for empty array", () => {
    const counts = countFindingsBySeverity([]);
    expect(counts.critical).toBe(0);
    expect(counts.high).toBe(0);
    expect(counts.medium).toBe(0);
    expect(counts.low).toBe(0);
    expect(counts.info).toBe(0);
  });

  it("counts a single critical finding correctly", () => {
    const f = makeFinding({ severity: "critical", category: "vulnerability" });
    const counts = countFindingsBySeverity([f]);
    expect(counts.critical).toBe(1);
    expect(counts.high).toBe(0);
  });

  it("counts mixed severities correctly", () => {
    const findings = [
      makeFinding({ severity: "critical", category: "vulnerability" }),
      makeFinding({ severity: "critical", category: "vulnerability" }),
      makeFinding({ severity: "high", category: "vulnerability" }),
      makeFinding({ severity: "medium", category: "vulnerability" }),
      makeFinding({ severity: "low", category: "vulnerability" }),
      makeFinding({ severity: "info", category: "vulnerability" }),
    ];
    const counts = countFindingsBySeverity(findings);
    expect(counts.critical).toBe(2);
    expect(counts.high).toBe(1);
    expect(counts.medium).toBe(1);
    expect(counts.low).toBe(1);
    expect(counts.info).toBe(1);
  });

  it("normalises severity casing to lowercase", () => {
    const f = makeFinding({ severity: "HIGH", category: "vulnerability" });
    const counts = countFindingsBySeverity([f]);
    expect(counts.high).toBe(1);
  });

  it("defaults to info for null severity", () => {
    const f = makeFinding({ severity: null as unknown as string, category: "vulnerability" });
    const counts = countFindingsBySeverity([f]);
    expect(counts.info).toBe(1);
  });

  it("handles large arrays without error", () => {
    const findings = Array.from({ length: 5000 }, (_, i) =>
      makeFinding({ severity: i % 2 === 0 ? "critical" : "high", category: "vulnerability" }),
    );
    const counts = countFindingsBySeverity(findings);
    expect(counts.critical).toBe(2500);
    expect(counts.high).toBe(2500);
  });
});

// ---------------------------------------------------------------------------
// computeCriticalFindingsFactor
// ---------------------------------------------------------------------------
describe("computeCriticalFindingsFactor", () => {
  it("returns score 0 with zero critical findings", () => {
    const factor = computeCriticalFindingsFactor({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    expect(factor.score).toBe(0);
    expect(factor.weight).toBe(0.35);
    expect(factor.name).toBe("Critical Findings");
  });

  it("scores 20 per critical finding", () => {
    const factor = computeCriticalFindingsFactor({ critical: 2, high: 0, medium: 0, low: 0, info: 0 });
    expect(factor.score).toBe(40);
  });

  it("caps score at 100 for many criticals", () => {
    const factor = computeCriticalFindingsFactor({ critical: 10, high: 0, medium: 0, low: 0, info: 0 });
    expect(factor.score).toBe(100);
  });

  it("caps exactly at 100 with 5 criticals (5×20=100)", () => {
    const factor = computeCriticalFindingsFactor({ critical: 5, high: 0, medium: 0, low: 0, info: 0 });
    expect(factor.score).toBe(100);
  });

  it("details string includes the count", () => {
    const factor = computeCriticalFindingsFactor({ critical: 3, high: 0, medium: 0, low: 0, info: 0 });
    expect(factor.details).toContain("3");
  });

  it("treats missing critical key as 0", () => {
    const factor = computeCriticalFindingsFactor({} as Record<string, number>);
    expect(factor.score).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// computeHighFindingsFactor
// ---------------------------------------------------------------------------
describe("computeHighFindingsFactor", () => {
  it("returns score 0 for no high findings", () => {
    const factor = computeHighFindingsFactor({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    expect(factor.score).toBe(0);
    expect(factor.weight).toBe(0.25);
    expect(factor.name).toBe("High Findings");
  });

  it("scores 10 per high finding", () => {
    const factor = computeHighFindingsFactor({ critical: 0, high: 3, medium: 0, low: 0, info: 0 });
    expect(factor.score).toBe(30);
  });

  it("caps score at 100 for many highs", () => {
    const factor = computeHighFindingsFactor({ critical: 0, high: 15, medium: 0, low: 0, info: 0 });
    expect(factor.score).toBe(100);
  });

  it("caps exactly at 100 with 10 highs (10×10=100)", () => {
    const factor = computeHighFindingsFactor({ critical: 0, high: 10, medium: 0, low: 0, info: 0 });
    expect(factor.score).toBe(100);
  });

  it("ignores other severity counts", () => {
    const factor = computeHighFindingsFactor({ critical: 5, high: 2, medium: 3, low: 4, info: 1 });
    expect(factor.score).toBe(20);
  });

  it("details string includes the count", () => {
    const factor = computeHighFindingsFactor({ critical: 0, high: 7, medium: 0, low: 0, info: 0 });
    expect(factor.details).toContain("7");
  });
});

// ---------------------------------------------------------------------------
// computeExposureFactor
// ---------------------------------------------------------------------------
describe("computeExposureFactor", () => {
  it("returns score 0 for empty findings", () => {
    const factor = computeExposureFactor([]);
    expect(factor.score).toBe(0);
    expect(factor.weight).toBe(0.15);
    expect(factor.name).toBe("Exposure Level");
  });

  it("scores 15 per exposure finding", () => {
    const findings = [
      makeFinding({ severity: "medium", category: "network_exposure" }),
    ];
    const factor = computeExposureFactor(findings);
    expect(factor.score).toBe(15);
  });

  it("counts all exposure category variants", () => {
    const exposureCategories = [
      "network_exposure",
      "exposed_service",
      "information_disclosure",
      "infrastructure_disclosure",
      "api_exposure",
      "cloud_exposure",
      "container_exposure",
      "data_leak",
    ];
    const findings = exposureCategories.map((c) =>
      makeFinding({ severity: "medium", category: c }),
    );
    const factor = computeExposureFactor(findings);
    // 8 × 15 = 120, capped at 100
    expect(factor.score).toBe(100);
  });

  it("ignores non-exposure categories", () => {
    const findings = [
      makeFinding({ severity: "critical", category: "vulnerability" }),
      makeFinding({ severity: "high", category: "ssl_issue" }),
    ];
    const factor = computeExposureFactor(findings);
    expect(factor.score).toBe(0);
  });

  it("normalises category casing", () => {
    const findings = [
      makeFinding({ severity: "medium", category: "Network_Exposure" }),
    ];
    const factor = computeExposureFactor(findings);
    expect(factor.score).toBe(15);
  });

  it("caps at 100 with many exposure findings", () => {
    const findings = Array.from({ length: 20 }, () =>
      makeFinding({ severity: "medium", category: "network_exposure" }),
    );
    const factor = computeExposureFactor(findings);
    expect(factor.score).toBe(100);
  });

  it("details string includes the exposure count", () => {
    const findings = [
      makeFinding({ severity: "medium", category: "network_exposure" }),
      makeFinding({ severity: "medium", category: "exposed_service" }),
    ];
    const factor = computeExposureFactor(findings);
    expect(factor.details).toContain("2");
  });

  it("handles null category gracefully", () => {
    const findings = [
      makeFinding({ severity: "medium", category: null as unknown as string }),
    ];
    const factor = computeExposureFactor(findings);
    expect(factor.score).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// computeTlsFactor
// ---------------------------------------------------------------------------
describe("computeTlsFactor", () => {
  it("returns score 0 for empty findings", () => {
    const factor = computeTlsFactor([]);
    expect(factor.score).toBe(0);
    expect(factor.weight).toBe(0.1);
    expect(factor.name).toBe("TLS Issues");
  });

  it("scores 25 per TLS finding", () => {
    const findings = [
      makeFinding({ severity: "high", category: "ssl_issue" }),
    ];
    const factor = computeTlsFactor(findings);
    expect(factor.score).toBe(25);
  });

  it("counts all TLS category variants", () => {
    const tlsCategories = ["ssl_issue", "transport_security", "certificate_authority"];
    const findings = tlsCategories.map((c) =>
      makeFinding({ severity: "high", category: c }),
    );
    const factor = computeTlsFactor(findings);
    // 3 × 25 = 75
    expect(factor.score).toBe(75);
  });

  it("ignores non-TLS categories", () => {
    const findings = [
      makeFinding({ severity: "critical", category: "vulnerability" }),
      makeFinding({ severity: "medium", category: "network_exposure" }),
    ];
    const factor = computeTlsFactor(findings);
    expect(factor.score).toBe(0);
  });

  it("caps at 100 with more than 4 TLS findings (4×25=100)", () => {
    const findings = Array.from({ length: 5 }, () =>
      makeFinding({ severity: "high", category: "ssl_issue" }),
    );
    const factor = computeTlsFactor(findings);
    expect(factor.score).toBe(100);
  });

  it("normalises category casing", () => {
    const findings = [
      makeFinding({ severity: "high", category: "SSL_Issue" }),
    ];
    const factor = computeTlsFactor(findings);
    expect(factor.score).toBe(25);
  });

  it("details string includes the TLS count", () => {
    const findings = [
      makeFinding({ severity: "high", category: "ssl_issue" }),
      makeFinding({ severity: "medium", category: "transport_security" }),
    ];
    const factor = computeTlsFactor(findings);
    expect(factor.details).toContain("2");
  });
});

// ---------------------------------------------------------------------------
// computeOverallScore
// ---------------------------------------------------------------------------
describe("computeOverallScore", () => {
  it("returns 0 for all-zero factor scores", () => {
    const factors = [
      { name: "A", score: 0, weight: 0.4, details: "" },
      { name: "B", score: 0, weight: 0.25, details: "" },
      { name: "C", score: 0, weight: 0.2, details: "" },
      { name: "D", score: 0, weight: 0.15, details: "" },
    ];
    expect(computeOverallScore(factors)).toBe(0);
  });

  it("computes weighted sum correctly — only critical factor contributes", () => {
    // 100*0.4 + 0*0.25 + 0*0.2 + 0*0.15 = 40
    const factors = [
      { name: "Critical", score: 100, weight: 0.4, details: "" },
      { name: "High", score: 0, weight: 0.25, details: "" },
      { name: "Exposure", score: 0, weight: 0.2, details: "" },
      { name: "TLS", score: 0, weight: 0.15, details: "" },
    ];
    expect(computeOverallScore(factors)).toBe(40);
  });

  it("computes full-weight sum — all factors at 100 → 100", () => {
    // 100*0.4 + 100*0.25 + 100*0.2 + 100*0.15 = 100
    const factors = [
      { name: "A", score: 100, weight: 0.4, details: "" },
      { name: "B", score: 100, weight: 0.25, details: "" },
      { name: "C", score: 100, weight: 0.2, details: "" },
      { name: "D", score: 100, weight: 0.15, details: "" },
    ];
    expect(computeOverallScore(factors)).toBe(100);
  });

  it("rounds the result to an integer", () => {
    const factors = [
      { name: "A", score: 33, weight: 0.4, details: "" },
      { name: "B", score: 33, weight: 0.25, details: "" },
      { name: "C", score: 33, weight: 0.2, details: "" },
      { name: "D", score: 33, weight: 0.15, details: "" },
    ];
    expect(Number.isInteger(computeOverallScore(factors))).toBe(true);
  });

  it("caps output at 100", () => {
    const factors = [
      { name: "A", score: 200, weight: 0.4, details: "" },
      { name: "B", score: 200, weight: 0.25, details: "" },
      { name: "C", score: 200, weight: 0.2, details: "" },
      { name: "D", score: 200, weight: 0.15, details: "" },
    ];
    expect(computeOverallScore(factors)).toBe(100);
  });

  it("floors output at 0 for negative factor scores", () => {
    const factors = [
      { name: "A", score: -50, weight: 0.4, details: "" },
    ];
    expect(computeOverallScore(factors)).toBe(0);
  });

  it("handles empty factors array and returns 0", () => {
    expect(computeOverallScore([])).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// determineTrend
// ---------------------------------------------------------------------------
describe("determineTrend", () => {
  /**
   * There is no score history in this product, so with nothing closed there is
   * nothing to infer a direction from. This answered "degrading" for any asset
   * holding an open finding, which on live data was 105 of 105 scored assets —
   * a red "risk increasing" arrow derived from no history at all.
   */
  it("returns 'unknown' when there are no findings", () => {
    expect(determineTrend(30, [])).toBe("unknown");
  });

  it("returns 'unknown' when nothing has been closed, whatever the score", () => {
    const openOnly = [
      makeFinding({ severity: "critical", category: "vulnerability", status: "open", workflowState: "open" }),
    ];
    expect(determineTrend(90, openOnly)).toBe("unknown");
  });

  it("returns 'improving' when resolved > open AND score < 50", () => {
    const findings: Finding[] = [
      makeFinding({ severity: "high", category: "vulnerability", status: "open", workflowState: "open" }),
      makeFinding({ severity: "high", category: "vulnerability", status: "resolved", workflowState: "closed" }),
      makeFinding({ severity: "high", category: "vulnerability", status: "resolved", workflowState: "remediated" }),
    ];
    // resolvedCount(2) > openCount(1) AND score(30) < 50
    expect(determineTrend(30, findings)).toBe("improving");
  });

  it("returns 'degrading' when score >= 70 and work has been closed before", () => {
    const findings: Finding[] = [
      makeFinding({ severity: "critical", category: "vulnerability", status: "open", workflowState: "open" }),
      makeFinding({ severity: "low", category: "vulnerability", status: "resolved", workflowState: "closed" }),
    ];
    expect(determineTrend(75, findings)).toBe("degrading");
  });

  /**
   * This case used to assert "degrading" from ZERO resolved findings, which is
   * where the fabricated verdict came from: `open > 0 * 2` is true of any open
   * finding at all. Outstanding work is not the same fact as work getting
   * worse. Degrading now needs remediation to exist and to be outpaced.
   */
  it("returns 'degrading' when open outpaces resolved more than 2:1", () => {
    const findings: Finding[] = [
      makeFinding({ severity: "high", category: "vulnerability", status: "open", workflowState: "open" }),
      makeFinding({ severity: "high", category: "vulnerability", status: "open", workflowState: "open" }),
      makeFinding({ severity: "high", category: "vulnerability", status: "open", workflowState: "open" }),
      makeFinding({ severity: "high", category: "vulnerability", status: "resolved", workflowState: "closed" }),
    ];
    // open(3) > resolved(1)*2=2 → degrading
    expect(determineTrend(40, findings)).toBe("degrading");
  });

  it("does NOT call outstanding work 'degrading' when nothing was ever closed", () => {
    const findings: Finding[] = Array.from({ length: 3 }, () =>
      makeFinding({ severity: "high", category: "vulnerability", status: "open", workflowState: "open" }),
    );
    expect(determineTrend(40, findings)).toBe("unknown");
  });

  it("returns 'stable' when open == resolved and score < 70", () => {
    const findings: Finding[] = [
      makeFinding({ severity: "high", category: "vulnerability", status: "open", workflowState: "open" }),
      makeFinding({ severity: "high", category: "vulnerability", status: "open", workflowState: "open" }),
      makeFinding({ severity: "high", category: "vulnerability", status: "resolved", workflowState: "closed" }),
      makeFinding({ severity: "high", category: "vulnerability", status: "resolved", workflowState: "closed" }),
    ];
    // open(2) <= resolved(2)*2=4 AND score(40)<70 AND NOT resolved(2)>open(2)
    expect(determineTrend(40, findings)).toBe("stable");
  });

  it("counts workflowState 'remediated' as resolved", () => {
    const findings: Finding[] = [
      // status="open" + workflowState="open" → counted as open only
      makeFinding({ severity: "low", category: "vulnerability", status: "open", workflowState: "open" }),
      // status="resolved" + workflowState="remediated" → counted as resolved only (status takes priority for open check)
      makeFinding({ severity: "low", category: "vulnerability", status: "resolved", workflowState: "remediated" }),
      makeFinding({ severity: "low", category: "vulnerability", status: "resolved", workflowState: "remediated" }),
    ];
    // resolvedCount(2) > openCount(1) AND score(20) < 50 → improving
    expect(determineTrend(20, findings)).toBe("improving");
  });

  // A high score is not by itself evidence of MOVEMENT: with nothing closed,
  // there is no second point in time to compare it against.
  it("boundary: score 70 with no closed work is still unknown", () => {
    expect(determineTrend(70, [])).toBe("unknown");
  });

  it("boundary: score 69 with no findings is unknown", () => {
    expect(determineTrend(69, [])).toBe("unknown");
  });

  it("'improving' requires BOTH resolved > open AND score < 50", () => {
    // resolved > open but score >= 50 → should NOT be improving
    const findings: Finding[] = [
      makeFinding({ severity: "high", category: "vulnerability", status: "open", workflowState: "open" }),
      makeFinding({ severity: "high", category: "vulnerability", status: "resolved", workflowState: "closed" }),
      makeFinding({ severity: "high", category: "vulnerability", status: "resolved", workflowState: "closed" }),
    ];
    // score=55 → NOT improving (score not < 50), open(1) <= resolved(2)*2=4 → stable
    expect(determineTrend(55, findings)).toBe("stable");
  });
});

// ---------------------------------------------------------------------------
// calculateAssetRisk — integration test with mocked storage
// ---------------------------------------------------------------------------
describe("calculateAssetRisk", () => {
  it("returns empty array when workspace has no assets", async () => {
    mockGetAssets.mockResolvedValueOnce({ data: [], total: 0 });
    mockGetFindings.mockResolvedValueOnce({ data: [], total: 0 });

    const result = await calculateAssetRisk("ws-empty");
    expect(result).toEqual([]);
  });

  it("returns one entry per asset", async () => {
    mockGetAssets.mockResolvedValueOnce({
      data: [
        { id: "a1", value: "example.com", workspaceId: "ws-1" },
        { id: "a2", value: "api.example.com", workspaceId: "ws-1" },
      ],
      total: 2,
    });
    mockGetFindings.mockResolvedValueOnce({ data: [], total: 0 });

    const result = await calculateAssetRisk("ws-1");
    expect(result).toHaveLength(2);
  });

  it("each result has required fields", async () => {
    mockGetAssets.mockResolvedValueOnce({
      data: [{ id: "a1", value: "example.com", workspaceId: "ws-1" }],
      total: 1,
    });
    mockGetFindings.mockResolvedValueOnce({ data: [], total: 0 });

    const [entry] = await calculateAssetRisk("ws-1");
    expect(entry).toMatchObject({
      assetId: "a1",
      hostname: "example.com",
      overallScore: expect.any(Number),
      factors: expect.any(Array),
      trend: expect.stringMatching(/improving|stable|degrading|unknown/),
      lastUpdated: expect.any(Date),
    });
  });

  it("scores asset higher when it has critical findings", async () => {
    const criticalFinding = makeFinding({
      severity: "critical",
      category: "vulnerability",
      affectedAsset: "risky.example.com",
      status: "open",
      workflowState: "open",
    });

    mockGetAssets.mockResolvedValueOnce({
      data: [{ id: "a1", value: "risky.example.com", workspaceId: "ws-1" }],
      total: 1,
    });
    mockGetFindings.mockResolvedValueOnce({ data: [criticalFinding], total: 1 });

    const [entry] = await calculateAssetRisk("ws-1");
    // 1 critical → 20 points × 0.4 weight = 8 → overallScore = 8
    expect(entry.overallScore).toBeGreaterThan(0);
  });

  it("sorts results by overallScore descending", async () => {
    const criticalFinding = makeFinding({
      severity: "critical",
      category: "vulnerability",
      affectedAsset: "risky.example.com",
      status: "open",
      workflowState: "open",
    });

    mockGetAssets.mockResolvedValueOnce({
      data: [
        { id: "a1", value: "safe.example.com", workspaceId: "ws-1" },
        { id: "a2", value: "risky.example.com", workspaceId: "ws-1" },
      ],
      total: 2,
    });
    mockGetFindings.mockResolvedValueOnce({ data: [criticalFinding], total: 1 });

    const result = await calculateAssetRisk("ws-1");
    expect(result[0].hostname).toBe("risky.example.com");
    expect(result[0].overallScore).toBeGreaterThanOrEqual(result[1].overallScore);
  });

  it("matches findings by partial affectedAsset (subdomain match)", async () => {
    const finding = makeFinding({
      severity: "high",
      category: "ssl_issue",
      affectedAsset: "sub.example.com",
      status: "open",
      workflowState: "open",
    });

    mockGetAssets.mockResolvedValueOnce({
      data: [{ id: "a1", value: "example.com", workspaceId: "ws-1" }],
      total: 1,
    });
    mockGetFindings.mockResolvedValueOnce({ data: [finding], total: 1 });

    const [entry] = await calculateAssetRisk("ws-1");
    // Finding affectedAsset includes "example.com" so it should be assigned
    expect(entry.overallScore).toBeGreaterThan(0);
  });

  it("throws a descriptive error when storage.getAssets fails", async () => {
    mockGetAssets.mockRejectedValueOnce(new Error("DB connection lost"));
    mockGetFindings.mockResolvedValueOnce({ data: [], total: 0 });

    await expect(calculateAssetRisk("ws-err")).rejects.toThrow(
      "Asset risk scoring failed: DB connection lost",
    );
  });

  it("wraps non-Error thrown objects with a generic message", async () => {
    mockGetAssets.mockRejectedValueOnce("string error");
    mockGetFindings.mockResolvedValueOnce({ data: [], total: 0 });

    await expect(calculateAssetRisk("ws-err")).rejects.toThrow(
      "Asset risk scoring failed: Unknown error",
    );
  });
});

/**
 * The finding index must be EXACTLY equivalent to the filter it replaced.
 *
 * The old code filtered every finding for every asset — O(assets x findings),
 * with a `toLowerCase()` allocation per pair, so 10,000 assets and 10,000
 * findings meant 10^8 comparisons and as many allocations for one page load.
 * Inverting that into an index is only safe if it matches on precisely the same
 * inputs, so this asserts the two agree rather than assuming they do.
 */
describe("indexFindingsByAsset", () => {
  const mk = (affectedAsset: string | null) => ({ affectedAsset, severity: "medium", status: "open" } as never);

  /** The original predicate, kept here as the oracle. */
  const originalMatch = (assetValue: string, affected: string | null) => {
    const normalized = assetValue.toLowerCase();
    const a = (affected ?? "").toLowerCase();
    return a === normalized || a.endsWith(`.${normalized}`) || a.startsWith(`${normalized}:`);
  };

  const AFFECTED = [
    "example.com", "api.example.com", "deep.api.example.com",
    "example.com:443", "api.example.com:8443", "1.2.3.4", "1.2.3.4:3306",
    "EXAMPLE.com", "", "notexample.com", "a:b:c",
  ];
  const ASSETS = [
    "example.com", "api.example.com", "com", "1.2.3.4", "notexample.com",
    "EXAMPLE.COM", "a", "a:b", "nothing.here",
  ];

  it("agrees with the original predicate on every asset/finding pair", () => {
    const findings = AFFECTED.map(mk);
    const index = indexFindingsByAsset(findings);

    for (const asset of ASSETS) {
      const viaIndex = new Set((index.get(asset.toLowerCase()) ?? []).map((f) => f.affectedAsset));
      const viaFilter = new Set(
        findings.filter((f) => originalMatch(asset, f.affectedAsset)).map((f) => f.affectedAsset),
      );
      expect(viaIndex, `asset "${asset}" must match the same findings`).toEqual(viaFilter);
    }
  });

  it("matches a subdomain to its parent, and a host:port to its host", () => {
    const index = indexFindingsByAsset([mk("api.example.com"), mk("example.com:443")]);
    expect(index.get("example.com")).toHaveLength(2);
    expect(index.get("api.example.com")).toHaveLength(1);
  });

  it("is case-insensitive on both sides", () => {
    const index = indexFindingsByAsset([mk("API.Example.COM")]);
    expect(index.get("example.com")).toHaveLength(1);
  });

  it("does not match an unrelated lookalike domain", () => {
    const index = indexFindingsByAsset([mk("notexample.com")]);
    expect(index.get("example.com") ?? []).toHaveLength(0);
  });

  it("lists a finding once per key even when several rules point at the same one", () => {
    // "example.com:443" reaches key "example.com" only through the colon rule;
    // it must not be double-counted if another rule reaches it too.
    const index = indexFindingsByAsset([mk("example.com:443")]);
    expect(index.get("example.com")).toHaveLength(1);
  });

  it("ignores findings with no affected asset", () => {
    expect(indexFindingsByAsset([mk(null), mk("")]).size).toBe(0);
  });

  /**
   * The point of the change: it stays usable at a realistic estate size.
   *
   * Deliberately NOT a wall-clock budget. This suite runs on a parallel worker
   * pool, so an absolute millisecond assertion measures contention from other
   * files as much as this function — the first version failed at 3.3s in the
   * full run while passing alone, which is a flaky gate, and a build that cries
   * wolf gets ignored. Scaling is asserted instead: doubling the input must not
   * quadruple the work, which is what catches a regression back to the O(n^2)
   * filter this replaced.
   */
  it("scales linearly rather than quadratically with finding count", () => {
    const build = (n: number) => Array.from({ length: n }, (_, i) => mk(`host${i}.sub${i % 50}.example.com`));
    const small = build(5_000);
    const large = build(10_000);

    const time = (fn: () => void) => { const t = Date.now(); fn(); return Math.max(1, Date.now() - t); };
    // Warm the JIT so the first call does not carry compilation cost.
    indexFindingsByAsset(small);

    const tSmall = time(() => indexFindingsByAsset(small));
    const tLarge = time(() => indexFindingsByAsset(large));

    expect(indexFindingsByAsset(large).get("example.com")).toHaveLength(10_000);
    // Linear would be ~2x. The old quadratic filter would be ~4x and climbing;
    // 8x leaves generous room for scheduler noise while still failing on a
    // genuine complexity regression.
    expect(tLarge / tSmall, `5k took ${tSmall}ms, 10k took ${tLarge}ms`).toBeLessThan(8);
  });
});

// ---------------------------------------------------------------------------
// The guard that would have caught the dead factors
// ---------------------------------------------------------------------------
/**
 * Both category-driven factors named categories the engine has NEVER emitted.
 *
 * The sets were hyphenated — `open-port`, `exposed-service`, `tls`,
 * `missing-hsts` — while every detector emits snake_case (`network_exposure`,
 * `exposed_service`, `ssl_issue`, `transport_security`). So `computeExposure
 * Factor` and `computeTlsFactor` matched nothing at all: 35% of the risk weight
 * was structurally unreachable, and measured on live data EVERY asset in EVERY
 * workspace scored 0.0 — rendered green, "no risk", across 2,633 assets and 163
 * open findings.
 *
 * The unit tests passed throughout, because they fed the factors the same
 * invented vocabulary the factors expected. A closed loop of two wrong things
 * agreeing proves nothing about production; the only fix is to check the set
 * against the taxonomy detectors actually write.
 *
 * This is the same guarantee `compliance-coverage.test.ts` makes about the
 * framework mapping, and it exists for the same reason: a category that names
 * nothing fails silently and forever.
 */
describe("risk-factor categories exist in the real taxonomy", () => {
  it("every exposure and TLS category is one a detector can emit", async () => {
    const { SECURITY_CATEGORIES } = await import(
      "../../../server/scanner/finding-taxonomy"
    );
    const src = fs.readFileSync(
      path.join(process.cwd(), "server", "asset-risk-scoring.ts"),
      "utf8",
    );

    const named: string[] = [];
    const blocks: Array<[string, RegExpExecArray | null]> = [
      ["EXPOSURE_CATEGORIES", /const EXPOSURE_CATEGORIES = new Set\(\[([\s\S]*?)\]\)/.exec(src)],
      ["TLS_CATEGORIES", /const TLS_CATEGORIES = new Set\(\[([\s\S]*?)\]\)/.exec(src)],
    ];
    for (const [setName, block] of blocks) {
      expect(block, `${setName} should be a literal Set in asset-risk-scoring.ts`).not.toBeNull();
      named.push(...[...block![1]!.matchAll(/"([^"]+)"/g)].map((m) => m[1]!));
    }

    expect(named.length).toBeGreaterThan(5);
    const unknown = named.filter((c) => !SECURITY_CATEGORIES.includes(c));
    expect(
      unknown,
      `Asset-risk factors name categories no detector emits: ${unknown.join(", ")}.\n` +
        "A category outside SECURITY_CATEGORIES matches nothing, so its factor is " +
        "permanently 0 and every asset reads as clean. Use the names in " +
        "server/scanner/finding-taxonomy.ts.",
    ).toEqual([]);
  });

  it("the factor weights still sum to 1", () => {
    const src = fs.readFileSync(
      path.join(process.cwd(), "server", "asset-risk-scoring.ts"),
      "utf8",
    );
    const block = /const FACTOR_WEIGHTS = \{([\s\S]*?)\} as const;/.exec(src);
    expect(block).not.toBeNull();
    const weights = [...block![1]!.matchAll(/:\s*([0-9.]+),/g)].map((m) => Number(m[1]));
    expect(weights.length).toBe(5);
    // A weighted average whose weights do not sum to 1 cannot reach its own
    // ceiling — adding a factor without rebalancing silently caps the score.
    expect(weights.reduce((a, b) => a + b, 0)).toBeCloseTo(1, 6);
  });
});

/**
 * A single open CRITICAL finding scored 20 x 0.4 = **8 out of 100**, which the
 * page renders in green as no risk. The band floors fix that, mirroring
 * `computeSecurityScore`'s floors and ceilings inverted.
 */
describe("severity bands dominate volume", () => {
  const zero = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const factorsFor = (counts: Record<string, number>) => [
    computeCriticalFindingsFactor(counts),
    computeHighFindingsFactor(counts),
    computeMediumLowFactor(counts),
  ];

  it("one open critical can never read as low risk", () => {
    const counts = { ...zero, critical: 1 };
    expect(computeOverallScore(factorsFor(counts), counts)).toBeGreaterThanOrEqual(80);
  });

  it("one open medium is not green", () => {
    const counts = { ...zero, medium: 1 };
    // 40 is where the UI stops colouring a score green.
    expect(computeOverallScore(factorsFor(counts), counts)).toBeGreaterThanOrEqual(40);
  });

  it("volume at a lesser severity cannot outrank a critical", () => {
    const manyLows = { ...zero, low: 50 };
    const oneCritical = { ...zero, critical: 1 };
    expect(computeOverallScore(factorsFor(manyLows), manyLows)).toBeLessThan(
      computeOverallScore(factorsFor(oneCritical), oneCritical),
    );
  });

  it("an asset with nothing found against it scores 0", () => {
    expect(computeOverallScore(factorsFor(zero), zero)).toBe(0);
  });

  it("medium and low findings reach the score at all", () => {
    // They contributed to no factor, which is why every real workspace — all
    // medium/low/info — scored zero everywhere.
    const counts = { ...zero, medium: 3, low: 2 };
    expect(computeMediumLowFactor(counts).score).toBe(19);
    expect(computeOverallScore(factorsFor(counts), counts)).toBeGreaterThan(0);
  });
});
