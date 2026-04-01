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
  computeCriticalFindingsFactor,
  computeHighFindingsFactor,
  computeExposureFactor,
  computeTlsFactor,
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
    expect(factor.weight).toBe(0.4);
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
    expect(factor.weight).toBe(0.2);
    expect(factor.name).toBe("Exposure Level");
  });

  it("scores 15 per exposure finding", () => {
    const findings = [
      makeFinding({ severity: "medium", category: "open-port" }),
    ];
    const factor = computeExposureFactor(findings);
    expect(factor.score).toBe(15);
  });

  it("counts all exposure category variants", () => {
    const exposureCategories = [
      "open-port",
      "exposed-service",
      "information-disclosure",
      "directory-listing",
      "api-exposure",
      "cloud-misconfiguration",
      "misconfiguration",
      "exposed-panel",
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
      makeFinding({ severity: "high", category: "tls" }),
    ];
    const factor = computeExposureFactor(findings);
    expect(factor.score).toBe(0);
  });

  it("normalises category casing", () => {
    const findings = [
      makeFinding({ severity: "medium", category: "Open-Port" }),
    ];
    const factor = computeExposureFactor(findings);
    expect(factor.score).toBe(15);
  });

  it("caps at 100 with many exposure findings", () => {
    const findings = Array.from({ length: 20 }, () =>
      makeFinding({ severity: "medium", category: "open-port" }),
    );
    const factor = computeExposureFactor(findings);
    expect(factor.score).toBe(100);
  });

  it("details string includes the exposure count", () => {
    const findings = [
      makeFinding({ severity: "medium", category: "open-port" }),
      makeFinding({ severity: "medium", category: "exposed-service" }),
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
    expect(factor.weight).toBe(0.15);
    expect(factor.name).toBe("TLS Issues");
  });

  it("scores 25 per TLS finding", () => {
    const findings = [
      makeFinding({ severity: "high", category: "tls" }),
    ];
    const factor = computeTlsFactor(findings);
    expect(factor.score).toBe(25);
  });

  it("counts all TLS category variants", () => {
    const tlsCategories = [
      "tls",
      "ssl",
      "certificate",
      "weak-cipher",
      "expired-certificate",
      "missing-hsts",
      "insecure-transport",
      "tls-misconfiguration",
    ];
    const findings = tlsCategories.map((c) =>
      makeFinding({ severity: "high", category: c }),
    );
    const factor = computeTlsFactor(findings);
    // 8 × 25 = 200, capped at 100
    expect(factor.score).toBe(100);
  });

  it("ignores non-TLS categories", () => {
    const findings = [
      makeFinding({ severity: "critical", category: "vulnerability" }),
      makeFinding({ severity: "medium", category: "open-port" }),
    ];
    const factor = computeTlsFactor(findings);
    expect(factor.score).toBe(0);
  });

  it("caps at 100 with more than 4 TLS findings (4×25=100)", () => {
    const findings = Array.from({ length: 5 }, () =>
      makeFinding({ severity: "high", category: "tls" }),
    );
    const factor = computeTlsFactor(findings);
    expect(factor.score).toBe(100);
  });

  it("normalises category casing", () => {
    const findings = [
      makeFinding({ severity: "high", category: "TLS" }),
    ];
    const factor = computeTlsFactor(findings);
    expect(factor.score).toBe(25);
  });

  it("details string includes the TLS count", () => {
    const findings = [
      makeFinding({ severity: "high", category: "tls" }),
      makeFinding({ severity: "medium", category: "ssl" }),
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
  it("returns 'stable' when there are no findings", () => {
    expect(determineTrend(30, [])).toBe("stable");
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

  it("returns 'degrading' when score >= 70", () => {
    const findings: Finding[] = [
      makeFinding({ severity: "critical", category: "vulnerability", status: "open", workflowState: "open" }),
    ];
    expect(determineTrend(75, findings)).toBe("degrading");
  });

  it("returns 'degrading' when open > resolved * 2 (zero resolved)", () => {
    const findings: Finding[] = [
      makeFinding({ severity: "high", category: "vulnerability", status: "open", workflowState: "open" }),
      makeFinding({ severity: "high", category: "vulnerability", status: "open", workflowState: "open" }),
      makeFinding({ severity: "high", category: "vulnerability", status: "open", workflowState: "open" }),
    ];
    // open(3) > 0*2=0 → degrading
    expect(determineTrend(40, findings)).toBe("degrading");
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

  it("boundary: score exactly 70 returns 'degrading'", () => {
    expect(determineTrend(70, [])).toBe("degrading");
  });

  it("boundary: score 69 with no findings returns 'stable'", () => {
    expect(determineTrend(69, [])).toBe("stable");
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
      trend: expect.stringMatching(/improving|stable|degrading/),
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
      category: "tls",
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
