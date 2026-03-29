import { describe, it, expect } from "vitest";
import { computeSecurityScore, SEVERITY_DEDUCTION } from "../../../shared/scoring";

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

  it("ignores resolved findings in deduction", () => {
    const findings = [
      { severity: "critical", status: "open" },          // -20
      { severity: "critical", status: "resolved" },       // ignored
      { severity: "high", status: "false_positive" },     // -10 (not resolved)
    ];
    expect(computeSecurityScore(findings)).toBe(70);
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
