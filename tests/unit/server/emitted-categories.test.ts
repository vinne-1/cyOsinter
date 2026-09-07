/**
 * Every category a detector emits must be in the taxonomy.
 *
 * `compliance-coverage.test.ts` and `risk-factors.test.ts` both assert that
 * every entry in `SECURITY_CATEGORIES` maps to a control and to a factor. Both
 * passed while two real categories were mapped nowhere, because **they were
 * validating the taxonomy against itself**: a detector emitting a category the
 * taxonomy has never heard of is invisible to a test that starts from the
 * taxonomy.
 *
 * Found on live data: a Bigbasket scan held 98 open security findings while the
 * risk-factor rows summed to 97. The missing one was
 * `certificate_authority` (the CAA check), which was in no taxonomy at all — so
 * it deducted from the security score, appeared in **no** risk factor, and
 * mapped to **no** compliance control, rendering as "No Data" which this
 * codebase documents as reading like a pass. `web_application`, emitted by the
 * WordPress XML-RPC check, had the same three defects.
 *
 * This test starts from the SOURCE instead. It is a static scan, in the same
 * spirit as `bare-id-authorization.test.ts`: a new detector that invents a
 * category fails here rather than silently dropping its findings out of the
 * rating and the compliance report.
 */
import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";

import { SECURITY_CATEGORIES, isSecurityFinding } from "../../../server/scanner/finding-taxonomy";
import { factorForCategory } from "../../../shared/risk-factors";

const SERVER = path.resolve(__dirname, "../../../server");

/**
 * Files whose `category:` field belongs to a DIFFERENT vocabulary.
 *
 * `attack-simulation.ts` labels attack-path scenarios ("injection",
 * "client-side", "dns"), and `tech-fingerprints.ts` labels technologies
 * ("server", "cdn", "payment"). Neither writes a finding, so neither is
 * governed by the finding taxonomy.
 */
const NOT_FINDING_VOCABULARY = new Set(["attack-simulation.ts", "tech-fingerprints.ts"]);

function walk(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return walk(p);
    return e.isFile() && e.name.endsWith(".ts") ? [p] : [];
  });
}

/**
 * Categories that appear within a few lines of a `severity:` literal.
 *
 * Proximity to a severity is what distinguishes a finding from any other object
 * with a `category` field, and it is the cheapest signal that does not require
 * parsing TypeScript.
 */
function emittedCategories(): Map<string, string> {
  const found = new Map<string, string>();
  for (const file of walk(SERVER)) {
    if (NOT_FINDING_VOCABULARY.has(path.basename(file))) continue;
    const lines = fs.readFileSync(file, "utf8").split("\n");
    lines.forEach((line, i) => {
      const m = /category:\s*"([a-z_]+)"/.exec(line);
      if (!m) return;
      const window = lines.slice(Math.max(0, i - 8), i + 9).join("\n");
      if (!/severity:\s*"(critical|high|medium|low|info)"/.test(window)) return;
      if (!found.has(m[1]!)) {
        found.set(m[1]!, `${path.relative(SERVER, file)}:${i + 1}`);
      }
    });
  }
  return found;
}

describe("emitted finding categories", () => {
  const emitted = emittedCategories();

  it("finds the detectors at all (guards against the scan silently matching nothing)", () => {
    // A regex that stops matching would make every assertion below vacuous.
    expect(emitted.size).toBeGreaterThan(15);
    expect(emitted.has("security_headers")).toBe(true);
  });

  it("has every emitted category in SECURITY_CATEGORIES", () => {
    const known = new Set(SECURITY_CATEGORIES);
    const missing = [...emitted.entries()]
      .filter(([c]) => c !== "unclassified" && !known.has(c))
      .map(([c, where]) => `${c} (emitted at ${where})`);

    expect(
      missing,
      "A detector emits a category the taxonomy does not know. It will deduct " +
        "from the security score while appearing in no risk factor and no " +
        "compliance control. Add it to DETECTOR_CATEGORIES, RISK_FACTORS and " +
        "CATEGORY_MAP.",
    ).toEqual([]);
  });

  it("has every emitted category attributed to a risk factor", () => {
    const missing = [...emitted.entries()]
      .filter(([c]) => c !== "unclassified" && !factorForCategory(c))
      .map(([c, where]) => `${c} (emitted at ${where})`);

    expect(missing, "Emitted category belongs to no risk factor").toEqual([]);
  });
});

/**
 * `isSecurityFinding` is the one definition of "this row is WORK".
 *
 * It exists because the rule was open-coded and kept being missed — in the SLA
 * summary and sweep, in both trend endpoints, in the report content builder,
 * and in the DOCX input assembler. Every occurrence was found by reconciling a
 * rendered number against the database, never by a test, and each one put
 * `control` findings — protections that are WORKING — in front of a reader as
 * outstanding problems.
 */
describe("isSecurityFinding", () => {
  it("counts only security findings as work", () => {
    expect(isSecurityFinding({ kind: "security" })).toBe(true);
    expect(isSecurityFinding({ kind: "control" })).toBe(false);
    expect(isSecurityFinding({ kind: "recon" })).toBe(false);
  });

  /**
   * The default is the SAFE direction. Rows written before the `kind` column
   * existed have no value, and treating those as non-work would silently drop
   * historical findings out of the score, the inbox and every report.
   */
  it("treats an absent kind as security", () => {
    expect(isSecurityFinding({})).toBe(true);
    expect(isSecurityFinding({ kind: null })).toBe(true);
    expect(isSecurityFinding({ kind: undefined })).toBe(true);
  });

  it("does not treat an unknown kind as work", () => {
    expect(isSecurityFinding({ kind: "something_new" })).toBe(false);
  });
});
