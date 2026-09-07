/**
 * Coverage guard for server/compliance-mapper.ts.
 *
 * A finding category absent from `CATEGORY_MAP` matches no control, so the
 * control is classed `unknown` and the UI renders "No Data" — which reads as
 * "not assessed" and invites the reader to conclude the control passes. That is
 * strictly worse than reporting a failure.
 *
 * It is also exactly what happened: a live workspace showed nine of ten OWASP
 * controls as No Data while holding 31 open findings, because 27 of them were
 * `cookie_security` and the map had no such key. Several keys that *were*
 * present (`open_port`, `s3_exposure`, `nuclei_finding`) named categories no
 * detector has ever emitted.
 *
 * These tests make that class of drift a build failure rather than a silent
 * blank cell.
 */
import { describe, it, expect } from "vitest";
import { SECURITY_CATEGORIES } from "../../../server/scanner/finding-taxonomy";
import { MAPPED_CATEGORIES, generateComplianceReport, generateAllComplianceReports } from "../../../server/compliance-mapper";
import type { Finding } from "@shared/schema";

const finding = (category: string, severity = "medium", status = "open"): Finding =>
  ({ id: `f-${category}-${status}`, category, severity, status } as unknown as Finding);

describe("compliance mapping coverage", () => {
  it("maps every security category the engine can emit", () => {
    const unmapped = SECURITY_CATEGORIES.filter(
      // `unclassified` is deliberately unmapped: it means the taxonomy itself
      // has a gap, and inventing a control for it would hide that.
      (c) => c !== "unclassified" && !MAPPED_CATEGORIES.includes(c),
    );
    expect(unmapped, `unmapped categories would silently render as "No Data": ${unmapped.join(", ")}`).toEqual([]);
  });

  it("maps each category to controls that exist in the framework it names", () => {
    const owaspIds = new Set(generateComplianceReport([], "owasp").mappings.map((m) => m.control.id));
    const cisIds = new Set(generateComplianceReport([], "cis").mappings.map((m) => m.control.id));
    const nistIds = new Set(generateComplianceReport([], "nist").mappings.map((m) => m.control.id));

    for (const category of MAPPED_CATEGORIES) {
      const report = generateAllComplianceReports([finding(category)]);
      // A category that mapped to a non-existent control id would match nothing
      // and leave every control unknown — the same blank cell by another route.
      const matched =
        report.owasp.mappings.some((m) => m.findingIds.length > 0) ||
        report.cis.mappings.some((m) => m.findingIds.length > 0) ||
        report.nist.mappings.some((m) => m.findingIds.length > 0);
      expect(matched, `category "${category}" matched no control in any framework`).toBe(true);
    }

    expect(owaspIds.size).toBe(10);
    expect(cisIds.size).toBe(18);
    expect(nistIds.size).toBe(12);
  });
});

describe("generateComplianceReport", () => {
  /**
   * The regression that motivated this work: a workspace whose findings are
   * overwhelmingly cookie-security issues must not report its access-control
   * and misconfiguration controls as unassessed.
   */
  it("assesses A05 and A07 for a workspace of cookie-security findings", () => {
    const findings = Array.from({ length: 27 }, (_, i) =>
      ({ id: `c${i}`, category: "cookie_security", severity: "medium", status: "open" } as unknown as Finding));
    const report = generateComplianceReport(findings, "owasp");

    const a05 = report.mappings.find((m) => m.control.id === "A05")!;
    const a07 = report.mappings.find((m) => m.control.id === "A07")!;
    expect(a05.status).toBe("fail");
    expect(a07.status).toBe("fail");
    expect(a05.findingIds).toHaveLength(27);
    expect(report.unknownCount).toBeLessThan(10);
  });

  it("reports pass when every mapped finding is resolved, and partial when some remain", () => {
    const allResolved = generateComplianceReport([finding("security_headers", "medium", "resolved")], "owasp");
    expect(allResolved.mappings.find((m) => m.control.id === "A05")!.status).toBe("pass");

    const mixed = generateComplianceReport(
      [finding("security_headers", "medium", "resolved"), { ...finding("security_headers"), id: "open-1" } as Finding],
      "owasp",
    );
    expect(mixed.mappings.find((m) => m.control.id === "A05")!.status).toBe("partial");
  });

  it("leaves a control unknown only when nothing bears on it", () => {
    const report = generateComplianceReport([finding("ssl_issue")], "owasp");
    expect(report.mappings.find((m) => m.control.id === "A02")!.status).toBe("fail");
    // Injection genuinely has no evidence either way from a TLS finding.
    expect(report.mappings.find((m) => m.control.id === "A03")!.status).toBe("unknown");
  });

  it("carries the worst open severity onto the control", () => {
    const report = generateComplianceReport(
      [finding("secret_exposure", "low"), finding("secret_exposure", "critical")],
      "owasp",
    );
    expect(report.mappings.find((m) => m.control.id === "A02")!.severity).toBe("critical");
  });
});
