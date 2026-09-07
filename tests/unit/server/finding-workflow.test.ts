import { describe, it, expect, vi } from "vitest";

// `finding-workflow` pulls in `db` for the SLA sweep, which refuses to load
// without DATABASE_URL. The functions under test here are pure.
vi.mock("../../../server/db", () => ({ db: {}, pool: {} }));
vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import { computeCvssScore } from "../../../server/finding-workflow";

/**
 * CVSS is derived at the choke point when a detector does not supply one.
 *
 * Without it the column stayed NULL and the report rendered "CVSS: -". On a real
 * workspace that landed on the two MEDIUM findings while the LOW and INFO ones
 * showed 3.5 and 2.0 — so the most serious items looked the least assessed,
 * which is the opposite of what a reader should conclude.
 */
describe("computeCvssScore", () => {
  it("orders bands so severity and score never disagree", () => {
    const order = ["info", "low", "medium", "high", "critical"].map((s) => Number(computeCvssScore(s)));
    for (let i = 1; i < order.length; i++) {
      expect(order[i]).toBeGreaterThan(order[i - 1]!);
    }
  });

  it("returns a parseable score for every known severity", () => {
    for (const s of ["critical", "high", "medium", "low", "info"]) {
      expect(Number.isFinite(Number(computeCvssScore(s)))).toBe(true);
    }
  });

  /** An unrecognised severity must not produce an empty or NaN score. */
  it("falls back rather than returning something unrenderable", () => {
    expect(computeCvssScore("nonsense")).toBe("2.0");
    expect(computeCvssScore("")).toBe("2.0");
  });
});
