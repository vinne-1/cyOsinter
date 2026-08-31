import { describe, it, expect } from "vitest";
import { computeSecurityScore, explainSecurityScore, SEVERITY_DEDUCTION } from "../../../shared/scoring";

/**
 * These tests previously pinned the exact output of a flat linear model
 * (100 - 20*critical - 10*high - ...). That model was replaced because it let
 * volume alone drive a workspace with no critical or high findings to 0/100
 * "Grade F", so the old numeric expectations no longer describe intended
 * behaviour. They are re-expressed here as the properties the score must hold,
 * which is what actually needed protecting.
 *
 * The band arithmetic itself is covered in scoring-grading.test.ts.
 */

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

  it("penalises a critical finding more than a high one", () => {
    expect(computeSecurityScore([{ severity: "critical" }]))
      .toBeLessThan(computeSecurityScore([{ severity: "high" }]));
  });

  it("penalises each severity strictly more than the one below it", () => {
    const score = (severity: string) => computeSecurityScore([{ severity }]);
    expect(score("critical")).toBeLessThan(score("high"));
    expect(score("high")).toBeLessThan(score("medium"));
    expect(score("medium")).toBeLessThan(score("low"));
    expect(score("low")).toBeLessThan(score("info"));
  });

  it("is driven by the worst severity present, not the total count", () => {
    const oneCritical = computeSecurityScore([{ severity: "critical" }]);
    const manyLows = computeSecurityScore(
      Array.from({ length: 50 }, () => ({ severity: "low" })),
    );
    expect(oneCritical).toBeLessThan(manyLows);
  });

  it("never goes below 0 or above 100", () => {
    const many = Array.from({ length: 200 }, () => ({ severity: "critical" }));
    expect(computeSecurityScore(many)).toBe(0);
    expect(computeSecurityScore([])).toBe(100);
  });

  it("ignores findings that are no longer outstanding", () => {
    // false_positive and accepted_risk used to keep deducting: the old filter
    // was `status !== "resolved"`, so explicitly dismissing a finding did
    // nothing to the score.
    expect(computeSecurityScore([
      { severity: "critical", status: "resolved" },
      { severity: "critical", status: "false_positive" },
      { severity: "critical", status: "accepted_risk" },
    ])).toBe(100);
  });

  it("still counts findings that are open or under review", () => {
    expect(computeSecurityScore([{ severity: "critical", status: "in_review" }])).toBeLessThan(100);
    expect(computeSecurityScore([{ severity: "critical", status: "open" }])).toBeLessThan(100);
  });

  it("does not penalise an unknown severity", () => {
    // An unrecognised label is a data problem, not evidence of risk; charging
    // for it would let a scanner bug degrade the grade.
    expect(computeSecurityScore([{ severity: "unknown_sev" }])).toBe(100);
  });

  it("orders the severity weights correctly", () => {
    expect(SEVERITY_DEDUCTION.critical).toBeGreaterThan(SEVERITY_DEDUCTION.high);
    expect(SEVERITY_DEDUCTION.high).toBeGreaterThan(SEVERITY_DEDUCTION.medium);
    expect(SEVERITY_DEDUCTION.medium).toBeGreaterThan(SEVERITY_DEDUCTION.low);
    // Informational findings describe the target rather than a defect.
    expect(SEVERITY_DEDUCTION.info).toBe(0);
  });
});

describe("controls and recon do not affect the score", () => {
  // The taxonomy split findings into security / control / recon. A control is
  // evidence a protection is IN PLACE and recon is a technology fact. If either
  // deducted, a domain that publishes DNSSEC and a security.txt would score
  // WORSE than one that publishes nothing at all — the scanner would be
  // punishing the work it exists to encourage.

  it("a domain with only controls and recon scores 100", () => {
    expect(
      computeSecurityScore([
        { severity: "info", kind: "control" },
        { severity: "info", kind: "control" },
        { severity: "info", kind: "recon" },
        { severity: "medium", kind: "recon" },
      ]),
    ).toBe(100);
  });

  it("adding a control never lowers the score", () => {
    const base = [{ severity: "high", kind: "security" }];
    const withControls = [...base, { severity: "info", kind: "control" }, { severity: "medium", kind: "control" }];
    expect(computeSecurityScore(withControls)).toBe(computeSecurityScore(base));
  });

  it("treats a finding with no kind as security, so nothing stops counting by accident", () => {
    expect(computeSecurityScore([{ severity: "critical" }])).toBe(
      computeSecurityScore([{ severity: "critical", kind: "security" }]),
    );
  });

  it("explains the same set of findings it scores", () => {
    // An explanation that counts a different set than the score it explains is
    // worse than none: it looks authoritative while disagreeing.
    const findings = [
      { severity: "high", kind: "security" },
      { severity: "critical", kind: "recon" },
      { severity: "critical", kind: "control" },
    ];
    const explained = explainSecurityScore(findings);
    expect(explained.score).toBe(computeSecurityScore(findings));
    expect(explained.counts.critical).toBe(0);
    expect(explained.counts.high).toBe(1);
  });
});
