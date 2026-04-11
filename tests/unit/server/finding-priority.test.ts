import { describe, it, expect, vi } from "vitest";

// Mock DB and storage so importing finding-priority doesn't need DATABASE_URL
vi.mock("../../../server/db", () => ({ db: {} }));
vi.mock("../../../server/storage", () => ({ storage: {} }));
vi.mock("../../../server/enrichment/epss-feed", () => ({
  extractCveIds: vi.fn().mockReturnValue([]),
  fetchEpssScores: vi.fn().mockResolvedValue([]),
}));

import { computeComponents } from "../../../server/enrichment/finding-priority";
import type { Finding } from "../../../shared/schema";

// Minimal finding factory
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    workspaceId: "ws1",
    scanId: null,
    title: "Test Finding",
    description: null,
    severity: "high",
    category: "open_ports",
    status: "open",
    cvssScore: null,
    cvssVector: null,
    affectedAsset: null,
    evidence: null,
    recommendation: null,
    references: null,
    cveIds: null,
    cweIds: null,
    tags: null,
    falsePositive: false,
    acceptedRisk: false,
    assignedTo: null,
    dueDate: null,
    resolvedAt: null,
    discoveredAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as Finding;
}

describe("computeComponents", () => {
  it("uses cvssScore when present", () => {
    const f = makeFinding({ cvssScore: "8.0" });
    const c = computeComponents(f, null, false);
    expect(c.cvssComponent).toBeCloseTo(0.8, 5);
  });

  it("falls back to severity baseline when cvssScore is null", () => {
    const f = makeFinding({ severity: "critical", cvssScore: null });
    const c = computeComponents(f, null, false);
    // critical baseline = 9.0, component = 9.0/10 = 0.9
    expect(c.cvssComponent).toBeCloseTo(0.9, 5);
  });

  it("falls back to severity baseline when cvssScore is not numeric", () => {
    const f = makeFinding({ severity: "medium", cvssScore: "n/a" });
    const c = computeComponents(f, null, false);
    // medium baseline = 5.5 → 0.55
    expect(c.cvssComponent).toBeCloseTo(0.55, 5);
  });

  it("uses EPSS probability when provided", () => {
    const f = makeFinding();
    const c = computeComponents(f, 0.5, false);
    expect(c.epssComponent).toBeCloseTo(0.5, 5);
  });

  it("clamps EPSS to [0, 1]", () => {
    const f = makeFinding();
    expect(computeComponents(f, 1.5, false).epssComponent).toBe(1);
    expect(computeComponents(f, -0.1, false).epssComponent).toBe(0);
  });

  it("sets EPSS to 0 when null", () => {
    const f = makeFinding();
    expect(computeComponents(f, null, false).epssComponent).toBe(0);
  });

  it("sets KEV component to 1 when inKev=true", () => {
    const f = makeFinding();
    expect(computeComponents(f, null, true).kevComponent).toBe(1);
  });

  it("sets KEV component to 0 when inKev=false", () => {
    const f = makeFinding();
    expect(computeComponents(f, null, false).kevComponent).toBe(0);
  });

  it("assigns high exposure for public-facing categories", () => {
    const f = makeFinding({ category: "xss" });
    expect(computeComponents(f, null, false).exposureComponent).toBe(1.0);
  });

  it("assigns partial exposure for non-public categories", () => {
    const f = makeFinding({ category: "open_ports" });
    expect(computeComponents(f, null, false).exposureComponent).toBeCloseTo(0.3, 5);
  });

  it("normalizes category with spaces to underscores", () => {
    const f = makeFinding({ category: "api exposure" });
    expect(computeComponents(f, null, false).exposureComponent).toBe(1.0);
  });

  it("age component is 0 for a finding discovered now", () => {
    const f = makeFinding({ discoveredAt: new Date() });
    const c = computeComponents(f, null, false);
    // ageComponent ≈ 0 seconds / 90d → ~0
    expect(c.ageComponent).toBeCloseTo(0, 2);
  });

  it("age component caps at 1.0 for old findings", () => {
    const old = new Date(Date.now() - 200 * 86_400_000); // 200 days ago
    const f = makeFinding({ discoveredAt: old });
    expect(computeComponents(f, null, false).ageComponent).toBe(1);
  });

  it("age component is ~0.5 at 45 days", () => {
    const fortyFiveDaysAgo = new Date(Date.now() - 45 * 86_400_000);
    const f = makeFinding({ discoveredAt: fortyFiveDaysAgo });
    expect(computeComponents(f, null, false).ageComponent).toBeCloseTo(0.5, 1);
  });

  it("compositeScore is in [0, 100]", () => {
    const f = makeFinding({ cvssScore: "9.8", category: "xss" });
    const c = computeComponents(f, 0.95, true);
    expect(c.compositeScore).toBeGreaterThan(0);
    expect(c.compositeScore).toBeLessThanOrEqual(100);
  });

  it("maximum score (all components = 1) yields 100", () => {
    const old = new Date(Date.now() - 365 * 86_400_000);
    const f = makeFinding({ cvssScore: "10.0", category: "xss", discoveredAt: old });
    const c = computeComponents(f, 1.0, true);
    expect(c.compositeScore).toBe(100);
  });

  it("weights sum correctly: medium severity, no epss, no kev, non-public, new finding", () => {
    const f = makeFinding({ severity: "medium", cvssScore: null, category: "open_ports" });
    const c = computeComponents(f, 0, false);
    // cvss=0.55, epss=0, kev=0, exposure=0.3, age≈0
    // score = (0.30*0.55 + 0.25*0 + 0.20*0 + 0.15*0.3 + 0.10*0) * 100
    //       = (0.165 + 0 + 0 + 0.045 + 0) * 100 = 21.0
    expect(c.compositeScore).toBeCloseTo(21.0, 0);
  });
});
