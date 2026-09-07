/**
 * The risk-factor rating.
 *
 * The tests that matter here are not the arithmetic — `scoring.test.ts` covers
 * that. They are the three-state discipline, because the whole reason this
 * module exists is that security-rating vendors publish a perfect score for
 * factors they never assessed, and a client will read our output beside theirs.
 *
 * A regression here does not throw. It quietly awards a 100, which travels into
 * a board pack and a vendor questionnaire as an assurance nobody earned.
 */
import { describe, it, expect } from "vitest";

import {
  RISK_FACTORS,
  computeFactorScores,
  factorForCategory,
  gradeForScore,
  analyseScoreCeiling,
  assessedCategoriesFromModules,
  MODULE_ASSESSES,
  type FactorInput,
} from "../../../shared/risk-factors";
import { SECURITY_CATEGORIES } from "../../../server/scanner/finding-taxonomy";

let seq = 0;
const f = (over: Partial<FactorInput> = {}): FactorInput => ({
  id: `f${++seq}`,
  severity: "medium",
  status: "open",
  kind: "security",
  category: "security_headers",
  ...over,
});

describe("factor coverage", () => {
  /**
   * The same guarantee `compliance-coverage.test.ts` makes for control mapping:
   * a category in no factor contributes to the overall score while appearing in
   * none of the areas the reader is told to act on, so the page does not add up.
   */
  it("maps every emittable security category to exactly one factor", () => {
    const unmapped = SECURITY_CATEGORIES.filter(
      (c) => c !== "unclassified" && !factorForCategory(c),
    );
    expect(unmapped).toEqual([]);
  });

  it("never assigns a category to two factors", () => {
    const seen = new Map<string, string>();
    for (const factor of RISK_FACTORS) {
      for (const c of factor.categories) {
        expect(seen.has(c), `${c} in both ${seen.get(c)} and ${factor.id}`).toBe(false);
        seen.set(c, factor.id);
      }
    }
  });

  /** An unmapped module may only withhold a score, never grant one. */
  it("only names real categories in the module map", () => {
    const known = new Set(RISK_FACTORS.flatMap((x) => x.categories));
    for (const [mod, cats] of Object.entries(MODULE_ASSESSES)) {
      for (const c of cats) expect(known.has(c), `${mod} claims unknown category ${c}`).toBe(true);
    }
  });
});

describe("the three states", () => {
  /**
   * The defect this module exists to prevent, stated as a test: a factor nothing
   * examined must not come back as a perfect score.
   */
  it("reports a factor with no findings and no assessment as not_assessed, NOT 100", () => {
    const factors = computeFactorScores([f({ category: "security_headers" })], ["security_headers"]);
    const network = factors.find((x) => x.id === "network_security")!;

    expect(network.state).toBe("not_assessed");
    expect(network.score).toBeNull();
    expect(network.grade).toBeNull();
    expect(network.reason).toMatch(/absence of evidence/i);
  });

  /** Ran and found nothing IS good news, and must be distinguishable from the above. */
  it("reports a factor whose checks ran and found nothing as clean at 100", () => {
    const factors = computeFactorScores([f()], ["security_headers", "open_port", "ssl_issue"]);
    const network = factors.find((x) => x.id === "network_security")!;

    expect(network.state).toBe("clean");
    expect(network.score).toBe(100);
    expect(network.grade).toBe("A");
  });

  it("scores a factor that has findings", () => {
    const factors = computeFactorScores(
      [f({ severity: "high", category: "open_port" })],
      ["open_port"],
    );
    const network = factors.find((x) => x.id === "network_security")!;

    expect(network.state).toBe("assessed");
    expect(network.findingCount).toBe(1);
    expect(network.worstSeverity).toBe("high");
    expect(network.score).toBeLessThan(100);
  });

  /**
   * Without the assessed set there is no evidence any check ran, so the
   * conservative reading is the only safe one. Defaulting to `clean` here would
   * reintroduce the exact defect through the back door.
   */
  it("defaults to not_assessed when the assessed set is unknown", () => {
    const factors = computeFactorScores([f()]);
    expect(factors.find((x) => x.id === "network_security")!.state).toBe("not_assessed");
    expect(factors.find((x) => x.id === "application_security")!.state).toBe("assessed");
  });

  it("does not let a closed or non-security finding score a factor", () => {
    const factors = computeFactorScores(
      [
        f({ category: "open_port", status: "false_positive" }),
        f({ category: "ssl_issue", kind: "recon" }),
      ],
      ["open_port", "ssl_issue"],
    );
    const network = factors.find((x) => x.id === "network_security")!;
    expect(network.state).toBe("clean");
  });
});

describe("assessedCategoriesFromModules", () => {
  it("derives categories from the modules that ran", () => {
    const cats = assessedCategoriesFromModules(["attack_surface"]);
    expect(cats.has("open_port")).toBe(true);
    expect(cats.has("security_headers")).toBe(false);
  });

  it("ignores a module it does not know rather than guessing", () => {
    expect(assessedCategoriesFromModules(["not_a_real_module"]).size).toBe(0);
  });

  /** End to end: modules that ran drive which factors are scorable. */
  it("turns a completed port scan with no findings into clean, not not_assessed", () => {
    const assessed = assessedCategoriesFromModules(["attack_surface", "web_presence"]);
    const factors = computeFactorScores([f()], assessed);

    expect(factors.find((x) => x.id === "network_security")!.state).toBe("clean");
    // Nothing assessed software currency, so it stays honest about that.
    expect(factors.find((x) => x.id === "software_currency")!.state).toBe("not_assessed");
  });
});

/**
 * The number a rating vendor gets wrong.
 *
 * SecurityScorecard prints a per-issue "SCORE IMPACT" of -5.1 or -2.3, which
 * implies fixing that one issue moves the score by that much. Our model is
 * banded, so inside a band the true marginal impact is usually zero — and
 * saying so, then naming the gate that IS binding, is both honest and more
 * actionable than a decimal that does not survive being acted on.
 */
describe("analyseScoreCeiling", () => {
  it("names the severity capping the score and what clearing it buys", () => {
    const findings = [
      f({ severity: "medium" }),
      f({ severity: "medium", category: "cookie_security" }),
      f({ severity: "low" }),
      f({ severity: "info" }),
    ];
    const a = analyseScoreCeiling(findings);

    expect(a.cappedBy).toBe("medium");
    expect(a.currentCeiling).toBe(85);
    expect(a.blockingCount).toBe(2);
    expect(a.ceilingIfCleared).toBeGreaterThan(a.score);
    expect(a.summary).toContain("2");
  });

  it("counts only findings of the capping severity as blocking", () => {
    const a = analyseScoreCeiling([
      f({ severity: "high" }),
      f({ severity: "medium" }),
      f({ severity: "medium" }),
    ]);
    expect(a.cappedBy).toBe("high");
    expect(a.blockingCount).toBe(1);
  });

  /** Info never caps: it deducts nothing, so claiming it holds the score down is false. */
  it("reports nothing capping when only informational findings are open", () => {
    const a = analyseScoreCeiling([f({ severity: "info" }), f({ severity: "info" })]);
    expect(a.cappedBy).toBeNull();
    expect(a.currentCeiling).toBe(100);
    expect(a.gain).toBe(0);
  });

  it("ignores closed findings when deciding what is capping", () => {
    const a = analyseScoreCeiling([
      f({ severity: "critical", status: "resolved" }),
      f({ severity: "low" }),
    ]);
    expect(a.cappedBy).toBe("low");
  });

  it("has nothing to clear on an empty workspace", () => {
    const a = analyseScoreCeiling([]);
    expect(a.cappedBy).toBeNull();
    expect(a.blockingCount).toBe(0);
  });
});


/**
 * Regression: a factor whose findings exist but whose detector is not named in
 * `MODULE_ASSESSES` reported `not_assessed` **with findingCount 0**, so three
 * real findings disappeared from the rating entirely. Withholding a score is
 * safe; dropping findings under-reports risk, which is the opposite failure.
 */
describe("findings are themselves proof of assessment", () => {
  it("never drops a factor's findings because no module claims its category", () => {
    const factors = computeFactorScores(
      [f({ category: "osint_exposure", severity: "low" })],
      // A module set that says nothing about brand/OSINT at all.
      assessedCategoriesFromModules(["attack_surface"]),
    );
    const brand = factors.find((x) => x.id === "brand_and_intel")!;

    expect(brand.state).toBe("assessed");
    expect(brand.findingCount).toBe(1);
    expect(brand.score).not.toBeNull();
  });

  it("still withholds a score for a factor with neither findings nor a module", () => {
    const factors = computeFactorScores([f()], assessedCategoriesFromModules(["web_presence"]));
    expect(factors.find((x) => x.id === "supply_chain")!.state).toBe("not_assessed");
  });
});

/**
 * The A-F bands existed in three places and disagreed: `scoreGrade` in the
 * client put a C at 65 and a D at 50, while the factor card and the DOCX
 * builder used 70 and 60. One score therefore graded differently on the
 * dashboard hero, the factor table and the exported report. Both callers now
 * delegate here; this pins the boundaries so a future edit has to be deliberate.
 */
describe("grade bands are defined once", () => {
  it("puts the boundaries where the product's existing score grade did", () => {
    expect(gradeForScore(90)).toBe("A");
    expect(gradeForScore(89)).toBe("B");
    expect(gradeForScore(80)).toBe("B");
    expect(gradeForScore(79)).toBe("C");
    expect(gradeForScore(65)).toBe("C");
    expect(gradeForScore(64)).toBe("D");
    expect(gradeForScore(50)).toBe("D");
    expect(gradeForScore(49)).toBe("F");
  });

  it("agrees with the factor scores it labels", () => {
    const factors = computeFactorScores([f({ severity: "high", category: "open_port" })], ["open_port"]);
    const scored = factors.filter((x) => x.score !== null);
    expect(scored.length).toBeGreaterThan(0);
    for (const x of scored) expect(x.grade).toBe(gradeForScore(x.score!));
  });
});

/**
 * The band ceiling is only sometimes the constraint, and the wording for one
 * regime is actively wrong in the other.
 *
 * Found on a live workspace: 60 open medium findings, ceiling 85, actual score
 * 55. The panel read "Score is capped at 85" — while showing 55 — and told the
 * reader that "fixing only some of them does not move it". Both false. At that
 * volume the score is below the ceiling precisely BECAUSE of the count, so
 * every finding closed helps, and discouraging partial remediation is the
 * opposite of the advice the data supports.
 */
describe("what is actually binding the score", () => {
  it("reports the ceiling as binding when the score sits at it", () => {
    const a = analyseScoreCeiling([f({ severity: "medium" }), f({ severity: "medium" })]);
    expect(a.score).toBe(a.currentCeiling);
    expect(a.binding).toBe("ceiling");
    expect(a.summary).toMatch(/cannot exceed/i);
  });

  it("reports volume as binding when sheer count has pulled the score below the ceiling", () => {
    const many = Array.from({ length: 60 }, () => f({ severity: "medium" }));
    const a = analyseScoreCeiling(many);

    expect(a.score).toBeLessThan(a.currentCeiling);
    expect(a.binding).toBe("volume");
    // It must NOT claim the score is capped at a number well above the score.
    expect(a.summary).not.toMatch(/cannot exceed/i);
    expect(a.summary).toMatch(/holding the score/i);
    expect(a.summary).toMatch(/proportionally/i);
  });

  it("never claims a cap above the score it is reporting", () => {
    for (const n of [1, 2, 5, 20, 60, 200]) {
      const a = analyseScoreCeiling(Array.from({ length: n }, () => f({ severity: "medium" })));
      if (a.summary.match(/cannot exceed/i)) {
        expect(a.score, `n=${n} claimed a cap while scoring below it`).toBeGreaterThanOrEqual(a.currentCeiling);
      }
    }
  });

  it("says nothing is binding on a clean workspace", () => {
    expect(analyseScoreCeiling([]).binding).toBe("none");
  });
});
