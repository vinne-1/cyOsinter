/**
 * Unit tests for server/differential-reporting.ts — scan comparison / risk delta.
 *
 * Strategy: mock storage and db to avoid real DB connections.
 * Test the compareScanFindings function with controlled finding sets.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Finding, Scan } from "../../../shared/schema";

// ---------------------------------------------------------------------------
// Module-level mocks — hoisted so they're available inside vi.mock factories
// ---------------------------------------------------------------------------
const { mockGetScan, mockGetFindings } = vi.hoisted(() => ({
  mockGetScan: vi.fn(),
  mockGetFindings: vi.fn(),
}));

vi.mock("../../../server/db", () => ({ db: {} }));

vi.mock("../../../server/storage", () => ({
  storage: {
    getScan: mockGetScan,
    getFindings: mockGetFindings,
  },
}));

import { compareScanFindings } from "../../../server/differential-reporting";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function makeScan(overrides: Partial<Scan> & { id: string; workspaceId: string }): Scan {
  return {
    target: "example.com",
    status: "completed",
    type: "easm",
    mode: "quick",
    startedAt: new Date(),
    completedAt: new Date(),
    createdBy: null,
    error: null,
    metadata: null,
    ...overrides,
  } as unknown as Scan;
}

function makeFinding(
  overrides: Partial<Finding> & { title: string; severity: string },
): Finding {
  return {
    id: `f-${Math.random().toString(36).slice(2)}`,
    workspaceId: "ws-1",
    scanId: null,
    category: "vulnerability",
    status: "open",
    description: "Test finding",
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
    checkId: "test",
    resourceType: "web_application",
    resourceId: "example.com",
    provider: null,
    complianceTags: [],
    ...overrides,
  } as unknown as Finding;
}

// ---------------------------------------------------------------------------
// compareScanFindings
// ---------------------------------------------------------------------------
describe("compareScanFindings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns zero-count result when both scans are missing", async () => {
    mockGetScan.mockResolvedValue(null);

    const result = await compareScanFindings("missing-1", "missing-2");
    expect(result.newFindings).toHaveLength(0);
    expect(result.fixedFindings).toHaveLength(0);
    expect(result.persistingFindings).toHaveLength(0);
    expect(result.riskDelta).toBe(0);
  });

  it("returns zero-count result when scan1 is missing", async () => {
    mockGetScan.mockResolvedValueOnce(null);

    const result = await compareScanFindings("missing", "scan-2");
    expect(result.newFindings).toHaveLength(0);
    expect(result.riskDelta).toBe(0);
  });

  it("detects new findings that appear in scan2 but not scan1", async () => {
    const scan1 = makeScan({ id: "s1", workspaceId: "ws-1" });
    const scan2 = makeScan({ id: "s2", workspaceId: "ws-1" });
    mockGetScan
      .mockResolvedValueOnce(scan1)
      .mockResolvedValueOnce(scan2);

    const newFinding = makeFinding({
      title: "New XSS",
      severity: "high",
      scanId: "s2",
      affectedAsset: "example.com",
    });

    mockGetFindings
      .mockResolvedValueOnce({ data: [], total: 0 })          // scan1 findings (empty)
      .mockResolvedValueOnce({ data: [newFinding], total: 1 }); // scan2 findings

    const result = await compareScanFindings("s1", "s2");
    expect(result.newFindings).toHaveLength(1);
    expect(result.newFindings[0].title).toBe("New XSS");
    expect(result.fixedFindings).toHaveLength(0);
    expect(result.persistingFindings).toHaveLength(0);
  });

  it("detects fixed findings that existed in scan1 but not scan2", async () => {
    const scan1 = makeScan({ id: "s1", workspaceId: "ws-1" });
    const scan2 = makeScan({ id: "s2", workspaceId: "ws-1" });
    mockGetScan
      .mockResolvedValueOnce(scan1)
      .mockResolvedValueOnce(scan2);

    const oldFinding = makeFinding({
      title: "Old SQLi",
      severity: "critical",
      scanId: "s1",
      affectedAsset: "example.com",
    });

    mockGetFindings
      .mockResolvedValueOnce({ data: [oldFinding], total: 1 }) // scan1
      .mockResolvedValueOnce({ data: [], total: 0 });           // scan2

    const result = await compareScanFindings("s1", "s2");
    expect(result.fixedFindings).toHaveLength(1);
    expect(result.fixedFindings[0].title).toBe("Old SQLi");
    expect(result.newFindings).toHaveLength(0);
    expect(result.persistingFindings).toHaveLength(0);
  });

  it("detects persisting findings present in both scans (same title + affectedAsset)", async () => {
    const scan1 = makeScan({ id: "s1", workspaceId: "ws-1" });
    const scan2 = makeScan({ id: "s2", workspaceId: "ws-1" });
    mockGetScan
      .mockResolvedValueOnce(scan1)
      .mockResolvedValueOnce(scan2);

    const f1 = makeFinding({ title: "CORS issue", severity: "medium", scanId: "s1", affectedAsset: "api.example.com" });
    const f2 = makeFinding({ title: "CORS issue", severity: "medium", scanId: "s2", affectedAsset: "api.example.com" });

    mockGetFindings
      .mockResolvedValueOnce({ data: [f1], total: 1 })
      .mockResolvedValueOnce({ data: [f2], total: 1 });

    const result = await compareScanFindings("s1", "s2");
    expect(result.persistingFindings).toHaveLength(1);
    expect(result.newFindings).toHaveLength(0);
    expect(result.fixedFindings).toHaveLength(0);
  });

  it("computes negative riskDelta when findings are fixed (risk decreases)", async () => {
    const scan1 = makeScan({ id: "s1", workspaceId: "ws-1" });
    const scan2 = makeScan({ id: "s2", workspaceId: "ws-1" });
    mockGetScan
      .mockResolvedValueOnce(scan1)
      .mockResolvedValueOnce(scan2);

    const criticalFinding = makeFinding({ title: "RCE", severity: "critical", scanId: "s1", affectedAsset: "app.example.com" });

    mockGetFindings
      .mockResolvedValueOnce({ data: [criticalFinding], total: 1 }) // scan1 has critical
      .mockResolvedValueOnce({ data: [], total: 0 });                // scan2 fixed

    const result = await compareScanFindings("s1", "s2");
    // critical removed → riskDelta = 0 - 10 = -10
    expect(result.riskDelta).toBe(-10);
  });

  it("computes positive riskDelta when new high-severity findings appear", async () => {
    const scan1 = makeScan({ id: "s1", workspaceId: "ws-1" });
    const scan2 = makeScan({ id: "s2", workspaceId: "ws-1" });
    mockGetScan
      .mockResolvedValueOnce(scan1)
      .mockResolvedValueOnce(scan2);

    const highFinding = makeFinding({ title: "SQLi", severity: "high", scanId: "s2", affectedAsset: "db.example.com" });

    mockGetFindings
      .mockResolvedValueOnce({ data: [], total: 0 })
      .mockResolvedValueOnce({ data: [highFinding], total: 1 });

    const result = await compareScanFindings("s1", "s2");
    // high added → riskDelta = 7 - 0 = 7
    expect(result.riskDelta).toBe(7);
  });

  it("riskDelta is 0 for info-only changes (info weight = 0)", async () => {
    const scan1 = makeScan({ id: "s1", workspaceId: "ws-1" });
    const scan2 = makeScan({ id: "s2", workspaceId: "ws-1" });
    mockGetScan
      .mockResolvedValueOnce(scan1)
      .mockResolvedValueOnce(scan2);

    const infoFinding = makeFinding({ title: "Version disclosure", severity: "info", scanId: "s2", affectedAsset: "example.com" });

    mockGetFindings
      .mockResolvedValueOnce({ data: [], total: 0 })
      .mockResolvedValueOnce({ data: [infoFinding], total: 1 });

    const result = await compareScanFindings("s1", "s2");
    // info has SEVERITY_SCORE_DIFF weight of 0
    expect(result.riskDelta).toBe(0);
  });

  it("handles mixed changes: some new, some fixed, some persisting", async () => {
    const scan1 = makeScan({ id: "s1", workspaceId: "ws-1" });
    const scan2 = makeScan({ id: "s2", workspaceId: "ws-1" });
    mockGetScan
      .mockResolvedValueOnce(scan1)
      .mockResolvedValueOnce(scan2);

    const persisting = makeFinding({ title: "CORS", severity: "medium", affectedAsset: "api.example.com" });
    const fixed = makeFinding({ title: "XSS", severity: "high", affectedAsset: "app.example.com" });
    const newF = makeFinding({ title: "SQLi", severity: "critical", affectedAsset: "db.example.com" });

    mockGetFindings
      .mockResolvedValueOnce({ data: [{ ...persisting, scanId: "s1" }, { ...fixed, scanId: "s1" }], total: 2 })
      .mockResolvedValueOnce({ data: [{ ...persisting, scanId: "s2" }, { ...newF, scanId: "s2" }], total: 2 });

    const result = await compareScanFindings("s1", "s2");
    expect(result.persistingFindings).toHaveLength(1);
    expect(result.fixedFindings).toHaveLength(1);
    expect(result.newFindings).toHaveLength(1);
    // riskDelta = (medium+critical) - (medium+high) = (4+10) - (4+7) = 14 - 11 = 3
    expect(result.riskDelta).toBe(3);
  });

  it("throws descriptive error when storage.getScan rejects", async () => {
    mockGetScan.mockRejectedValue(new Error("DB failure"));

    await expect(compareScanFindings("s1", "s2")).rejects.toThrow(
      "Scan comparison failed: DB failure",
    );
  });
});
