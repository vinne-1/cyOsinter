import { describe, it, expect } from "vitest";
import { computeSecurityScore, explainSecurityScore, deductionFor } from "../../../shared/scoring";

/** Builds n findings of one severity. */
const f = (severity: string, n: number, status = "open") =>
  Array.from({ length: n }, () => ({ severity, status }));

/**
 * The case that prompted this rewrite: a real workspace showed 0/100 "Grade F ·
 * Critical" while reporting 0 critical and 0 high. The old model deducted a flat
 * 5 per medium with no ceiling, so 27 mediums (135) floored the score.
 */
describe("the regression that prompted this", () => {
  const realWorkspace = [...f("medium", 27), ...f("low", 2), ...f("info", 2)];

  it("no longer scores zero when nothing critical or high is open", () => {
    expect(computeSecurityScore(realWorkspace)).toBeGreaterThan(0);
  });

  it("cannot fall below the medium floor when medium is the worst severity", () => {
    expect(computeSecurityScore(realWorkspace)).toBeGreaterThanOrEqual(55);
  });

  it("does not award an A either — 27 open findings is not a clean bill", () => {
    expect(computeSecurityScore(realWorkspace)).toBeLessThan(90);
  });
});

describe("severity sets the ceiling before volume matters", () => {
  it("keeps a low-only workspace in the high band however many there are", () => {
    expect(computeSecurityScore(f("low", 500))).toBeGreaterThanOrEqual(75);
  });

  it("keeps a medium-only workspace above the medium floor", () => {
    expect(computeSecurityScore(f("medium", 500))).toBeGreaterThanOrEqual(55);
  });

  it("lets a single critical outrank a hundred lows", () => {
    // Severity must dominate volume: one critical is a worse posture than a
    // long tail of minor issues.
    expect(computeSecurityScore(f("critical", 1))).toBeLessThan(computeSecurityScore(f("low", 100)));
  });

  it("only allows a zero score when something critical is open", () => {
    expect(computeSecurityScore(f("critical", 60))).toBe(0);
    expect(computeSecurityScore(f("high", 500))).toBeGreaterThan(0);
  });
});

describe("diminishing returns", () => {
  it("charges four findings twice one, not four times", () => {
    // weight * sqrt(n): the 27th missing header is not a fresh problem.
    expect(deductionFor("medium", 4)).toBeCloseTo(deductionFor("medium", 1) * 2, 5);
  });

  it("charges a hundred findings ten times one", () => {
    expect(deductionFor("medium", 100)).toBeCloseTo(deductionFor("medium", 1) * 10, 5);
  });

  it("returns nothing for a severity with no findings", () => {
    expect(deductionFor("critical", 0)).toBe(0);
  });

  it("still makes more findings worse than fewer", () => {
    // Diminishing must not mean flat — volume has to move the number.
    expect(computeSecurityScore(f("medium", 20))).toBeLessThan(computeSecurityScore(f("medium", 2)));
  });
});

describe("informational findings", () => {
  it("does not penalise info findings at all", () => {
    // "DNSSEC detected" describes the target; it is not a defect.
    expect(computeSecurityScore(f("info", 50))).toBe(100);
  });

  it("scores a clean workspace 100", () => {
    expect(computeSecurityScore([])).toBe(100);
  });
});

describe("closed findings are out of scope", () => {
  it("ignores resolved findings", () => {
    expect(computeSecurityScore(f("critical", 10, "resolved"))).toBe(100);
  });

  it("ignores false positives", () => {
    // The previous filter was `status !== "resolved"`, so a finding explicitly
    // marked a false positive still dragged the score down.
    expect(computeSecurityScore(f("critical", 10, "false_positive"))).toBe(100);
  });

  it("ignores accepted risks", () => {
    expect(computeSecurityScore(f("critical", 10, "accepted_risk"))).toBe(100);
  });

  it("still counts findings under review", () => {
    expect(computeSecurityScore(f("critical", 5, "in_review"))).toBeLessThan(100);
  });
});

describe("bounds", () => {
  it("never returns below 0 or above 100", () => {
    for (const set of [[], f("critical", 1000), f("info", 1000), f("low", 1)]) {
      const s = computeSecurityScore(set);
      expect(s).toBeGreaterThanOrEqual(0);
      expect(s).toBeLessThanOrEqual(100);
    }
  });

  it("returns a whole number", () => {
    expect(Number.isInteger(computeSecurityScore(f("medium", 7)))).toBe(true);
  });

  it("treats an unknown severity as harmless rather than throwing", () => {
    expect(() => computeSecurityScore([{ severity: "bogus", status: "open" }])).not.toThrow();
  });
});

describe("explainSecurityScore", () => {
  it("reports the worst severity actually open", () => {
    const e = explainSecurityScore([...f("medium", 3), ...f("low", 9)]);
    expect(e.worstSeverity).toBe("medium");
  });

  it("ignores info when naming the worst severity", () => {
    expect(explainSecurityScore(f("info", 5)).worstSeverity).toBeNull();
  });

  it("flags when the floor rescued the score from raw volume", () => {
    expect(explainSecurityScore(f("medium", 400)).floored).toBe(true);
    expect(explainSecurityScore(f("medium", 1)).floored).toBe(false);
  });

  it("agrees with computeSecurityScore", () => {
    const set = [...f("high", 2), ...f("medium", 6)];
    expect(explainSecurityScore(set).score).toBe(computeSecurityScore(set));
  });
});
