import { describe, it, expect } from "vitest";
import {
  computeSecurityScore,
  SEVERITY_DEDUCTION,
  SEVERITY_SCORE_DIFF,
  SEVERITY_SCORE_RISK,
} from "../../../shared/scoring";

describe("computeSecurityScore", () => {
  it("returns 100 for empty findings", () => {
    expect(computeSecurityScore([])).toBe(100);
  });

  it("returns 100 when all findings are resolved", () => {
    expect(computeSecurityScore([
      { severity: "critical", status: "resolved" },
      { severity: "high", status: "resolved" },
    ])).toBe(100);
  });

  it("deducts correctly for a single critical finding", () => {
    expect(computeSecurityScore([{ severity: "critical" }])).toBe(80);
  });

  it("deducts correctly for a single high finding", () => {
    expect(computeSecurityScore([{ severity: "high" }])).toBe(90);
  });

  it("deducts correctly for mixed severities", () => {
    const findings = [
      { severity: "critical" },       // -20
      { severity: "high" },            // -10
      { severity: "medium" },          // -5
      { severity: "low" },             // -2
      { severity: "info" },            // -1
    ];
    expect(computeSecurityScore(findings)).toBe(100 - 20 - 10 - 5 - 2 - 1);
  });

  it("never goes below 0", () => {
    const manyFindings = Array.from({ length: 20 }, () => ({ severity: "critical" }));
    expect(computeSecurityScore(manyFindings)).toBe(0);
  });

  it("excludes resolved, false_positive, and accepted_risk findings", () => {
    const findings = [
      { severity: "critical", status: "open" },           // -20
      { severity: "critical", status: "resolved" },        // excluded
      { severity: "high", status: "false_positive" },      // excluded
      { severity: "medium", status: "accepted_risk" },     // excluded
      { severity: "low", status: "risk_accepted" },        // excluded
    ];
    // Only the critical open finding contributes → 100 - 20 = 80
    expect(computeSecurityScore(findings)).toBe(80);
  });

  it("handles uppercase status values gracefully", () => {
    const findings = [
      { severity: "critical", status: "RESOLVED" },
      { severity: "high", status: "FALSE_POSITIVE" },
    ];
    // Status comparison is case-insensitive, so both should be excluded → 100
    expect(computeSecurityScore(findings)).toBe(100);
  });

  it("treats unknown severity as 1 deduction", () => {
    expect(computeSecurityScore([{ severity: "unknown_sev" }])).toBe(99);
  });

  it("handles severity deduction constants correctly", () => {
    expect(SEVERITY_DEDUCTION.critical).toBe(20);
    expect(SEVERITY_DEDUCTION.high).toBe(10);
    expect(SEVERITY_DEDUCTION.medium).toBe(5);
    expect(SEVERITY_DEDUCTION.low).toBe(2);
    expect(SEVERITY_DEDUCTION.info).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// SEVERITY_SCORE_DIFF — used by differential reporting
// ---------------------------------------------------------------------------
describe("SEVERITY_SCORE_DIFF", () => {
  it("has correct weights for each severity level", () => {
    expect(SEVERITY_SCORE_DIFF.critical).toBe(10);
    expect(SEVERITY_SCORE_DIFF.high).toBe(7);
    expect(SEVERITY_SCORE_DIFF.medium).toBe(4);
    expect(SEVERITY_SCORE_DIFF.low).toBe(1);
    expect(SEVERITY_SCORE_DIFF.info).toBe(0);
  });

  it("weights are in descending order from critical to info", () => {
    const order = ["critical", "high", "medium", "low", "info"];
    for (let i = 0; i < order.length - 1; i++) {
      expect(SEVERITY_SCORE_DIFF[order[i]]).toBeGreaterThanOrEqual(
        SEVERITY_SCORE_DIFF[order[i + 1]],
      );
    }
  });

  it("info weight is 0 (info findings don't change risk delta)", () => {
    expect(SEVERITY_SCORE_DIFF.info).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// SEVERITY_SCORE_RISK — used by attack path risk computation (client-side)
// ---------------------------------------------------------------------------
describe("SEVERITY_SCORE_RISK", () => {
  it("has correct weights for each severity level", () => {
    expect(SEVERITY_SCORE_RISK.critical).toBe(10);
    expect(SEVERITY_SCORE_RISK.high).toBe(7.5);
    expect(SEVERITY_SCORE_RISK.medium).toBe(5);
    expect(SEVERITY_SCORE_RISK.low).toBe(2.5);
    expect(SEVERITY_SCORE_RISK.info).toBe(1);
  });

  it("weights are in descending order from critical to info", () => {
    const order = ["critical", "high", "medium", "low", "info"];
    for (let i = 0; i < order.length - 1; i++) {
      expect(SEVERITY_SCORE_RISK[order[i]]).toBeGreaterThan(
        SEVERITY_SCORE_RISK[order[i + 1]],
      );
    }
  });

  it("critical is the maximum weight", () => {
    const max = Math.max(...Object.values(SEVERITY_SCORE_RISK));
    expect(SEVERITY_SCORE_RISK.critical).toBe(max);
  });
});
