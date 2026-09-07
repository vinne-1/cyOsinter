/**
 * CERT-In and DPDP mapping.
 *
 * These two frameworks exist for a reason the Western ones do not cover. The
 * CERT-In Directions 2022 oblige every Indian body corporate to report a listed
 * incident **within six hours of noticing it**, and the list explicitly includes
 * "targeted scanning" and "probing of critical networks". So the mapping answers
 * a question OWASP cannot: *if this finding were exploited, which reporting
 * obligation would it trigger?*
 *
 * The DPDP tests are mostly about restraint. An external scan can evidence the
 * technical safeguards under s.8(4); it cannot observe consent, grievance
 * handling or erasure. Shipping those as assessable would be the overclaim that
 * `compliance-guidance.ts` is deliberately left unwired to avoid.
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("../../../server/db", () => ({ db: {}, pool: {} }));
vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import { generateComplianceReport } from "../../../server/compliance-mapper";

type F = Parameters<typeof generateComplianceReport>[0][number];

/** A finding in the shape the mapper reads. `over` MUST be spread — an earlier
 *  version dropped it, so every fixture silently became `security_headers`. */
const withCategory = (category: string, severity = "medium"): F => ({
  id: `f-${category}`,
  category,
  severity,
  status: "open",
  title: `test ${category}`,
} as unknown as F);

describe("CERT-In mapping", () => {
  it("exposes the ten reportable incident categories", () => {
    const r = generateComplianceReport([], "certin");
    expect(r.totalControls).toBe(10);
    expect(r.frameworkVersion).toMatch(/2022/);
  });

  /** The mapping's whole purpose: which reporting duty does this exposure touch? */
  it("routes a finding to the incident type it would be reported under", () => {
    const cases: Array<[string, string]> = [
      ["cookie_security", "CERTIN-02"],       // unauthorised access
      ["security_headers", "CERTIN-07"],      // attacks on applications
      ["osint_exposure", "CERTIN-04"],        // phishing / identity theft
      ["subdomain_takeover", "CERTIN-03"],    // defacement / intrusion
      ["open_port", "CERTIN-06"],             // attacks on servers
      ["cloud_exposure", "CERTIN-08"],        // cloud systems
      ["supply_chain", "CERTIN-10"],          // supply chain
      ["data_leak", "CERTIN-05"],             // data breach / leak
    ];
    for (const [category, control] of cases) {
      const r = generateComplianceReport([withCategory(category)], "certin");
      const m = r.mappings.find((x) => x.control.id === control);
      expect(m?.status, `${category} -> ${control}`).toBe("fail");
    }
  });

  it("leaves untouched incident types as unknown rather than passing them", () => {
    const r = generateComplianceReport([withCategory("cookie_security")], "certin");
    const untouched = r.mappings.find((x) => x.control.id === "CERTIN-09");
    // No finding relates to ransomware, and an external scan cannot say there is
    // none — so it is unknown, never "pass".
    expect(untouched?.status).toBe("unknown");
  });

  it("treats every CERT-In incident type as externally observable", () => {
    const r = generateComplianceReport([], "certin");
    expect(r.mappings.every((m) => m.control.externallyAssessable !== false)).toBe(true);
  });
});

describe("DPDP mapping", () => {
  it("maps transport findings to the s.8(4) cryptography duty", () => {
    const r = generateComplianceReport([withCategory("ssl_issue")], "dpdp");
    expect(r.mappings.find((m) => m.control.id === "DPDP-8.4-CRYPTO")?.status).toBe("fail");
  });

  it("maps a leak to breach-detection readiness under s.8(5)", () => {
    const r = generateComplianceReport([withCategory("data_leak")], "dpdp");
    expect(r.mappings.find((m) => m.control.id === "DPDP-8.5-DETECT")?.status).toBe("fail");
  });

  /**
   * The restraint that matters. Consent, grievance handling, erasure and the
   * Significant Data Fiduciary duties are process obligations. Left unlabelled
   * they render as "No Data", which a reader takes as "probably fine" — the
   * failure mode this codebase documents repeatedly.
   */
  it("marks process obligations as NOT externally assessable", () => {
    const r = generateComplianceReport([], "dpdp");
    const notAssessable = r.mappings
      .filter((m) => m.control.externallyAssessable === false)
      .map((m) => m.control.id);

    expect(notAssessable).toEqual(
      expect.arrayContaining(["DPDP-8.7-RETAIN", "DPDP-6-CONSENT", "DPDP-13-GRIEV", "DPDP-10-SDF"]),
    );
  });

  it("does not claim a passing score from an external scan alone", () => {
    // Nothing found does not mean the Act is satisfied; the unassessable
    // controls must never be counted as passes.
    const r = generateComplianceReport([], "dpdp");
    expect(r.passCount).toBe(0);
  });

  /** Brand abuse is not a personal-data duty, so the column is empty on purpose. */
  it("does not force brand findings into a DPDP control", () => {
    const r = generateComplianceReport([withCategory("brand_threat")], "dpdp");
    expect(r.mappings.every((m) => m.status !== "fail")).toBe(true);
  });
});
