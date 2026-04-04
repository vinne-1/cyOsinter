/**
 * Unit tests for server/compliance-mapper.ts — compliance report generation.
 *
 * Tests: generateComplianceReport, generateAllComplianceReports.
 * These are pure functions (no DB, no network).
 */

import { describe, it, expect } from "vitest";
import type { Finding } from "@shared/schema";

import {
  generateComplianceReport,
  generateAllComplianceReports,
} from "../../../server/compliance-mapper";

/** Create a minimal Finding-like object for testing */
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: overrides.id ?? `f-${Math.random().toString(36).slice(2, 8)}`,
    title: overrides.title ?? "Test Finding",
    description: overrides.description ?? "A test finding",
    severity: overrides.severity ?? "high",
    category: overrides.category ?? "ssl_issue",
    status: overrides.status ?? "open",
    workspaceId: overrides.workspaceId ?? "ws-1",
    scanId: overrides.scanId ?? "scan-1",
    affectedAsset: overrides.affectedAsset ?? "example.com",
    evidence: overrides.evidence ?? [],
    remediation: overrides.remediation ?? null,
    references: overrides.references ?? [],
    cveIds: overrides.cveIds ?? [],
    source: overrides.source ?? "test",
    confidence: overrides.confidence ?? 80,
    groupId: overrides.groupId ?? null,
    assignee: overrides.assignee ?? null,
    createdAt: overrides.createdAt ?? new Date(),
    updatedAt: overrides.updatedAt ?? new Date(),
  } as Finding;
}

// ---------------------------------------------------------------------------
// generateComplianceReport — OWASP
// ---------------------------------------------------------------------------
describe("generateComplianceReport (OWASP)", () => {
  it("returns a report with 10 OWASP controls", () => {
    const report = generateComplianceReport([], "owasp");
    expect(report.framework).toBe("OWASP Top 10");
    expect(report.frameworkVersion).toBe("2021");
    expect(report.totalControls).toBe(10);
  });

  it("all controls are unknown when no findings exist", () => {
    const report = generateComplianceReport([], "owasp");
    expect(report.unknownCount).toBe(10);
    expect(report.failCount).toBe(0);
    expect(report.passCount).toBe(0);
    expect(report.score).toBe(0);
  });

  it("maps ssl_issue findings to A02 (Cryptographic Failures)", () => {
    const findings = [makeFinding({ category: "ssl_issue", status: "open" })];
    const report = generateComplianceReport(findings, "owasp");
    const a02 = report.mappings.find((m) => m.control.id === "A02");
    expect(a02).toBeDefined();
    expect(a02!.status).toBe("fail");
    expect(a02!.findingIds.length).toBeGreaterThan(0);
  });

  it("marks control as pass when all mapped findings are resolved", () => {
    const findings = [makeFinding({ category: "ssl_issue", status: "resolved" })];
    const report = generateComplianceReport(findings, "owasp");
    const a02 = report.mappings.find((m) => m.control.id === "A02");
    expect(a02!.status).toBe("pass");
  });

  it("marks control as partial when some findings open, some resolved", () => {
    const findings = [
      makeFinding({ id: "f1", category: "ssl_issue", status: "open" }),
      makeFinding({ id: "f2", category: "ssl_issue", status: "resolved" }),
    ];
    const report = generateComplianceReport(findings, "owasp");
    const a02 = report.mappings.find((m) => m.control.id === "A02");
    expect(a02!.status).toBe("partial");
  });

  it("computes score as percentage of passing+partial controls", () => {
    // 1 resolved ssl_issue → A02 passes; 9 other controls unknown → only 1 assessed
    const findings = [makeFinding({ category: "ssl_issue", status: "resolved" })];
    const report = generateComplianceReport(findings, "owasp");
    // A02 is pass, A05 is unknown (ssl_issue doesn't map to A05 — only A02 and CIS-03/CIS-12)
    expect(report.score).toBeGreaterThan(0);
  });

  it("has a generatedAt ISO timestamp", () => {
    const report = generateComplianceReport([], "owasp");
    expect(report.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

// ---------------------------------------------------------------------------
// generateComplianceReport — CIS
// ---------------------------------------------------------------------------
describe("generateComplianceReport (CIS)", () => {
  it("returns 18 CIS controls", () => {
    const report = generateComplianceReport([], "cis");
    expect(report.framework).toBe("CIS Controls");
    expect(report.frameworkVersion).toBe("v8");
    expect(report.totalControls).toBe(18);
  });

  it("maps exposed_credentials to CIS-03 and CIS-05", () => {
    const findings = [makeFinding({ category: "exposed_credentials", status: "open" })];
    const report = generateComplianceReport(findings, "cis");
    const cis03 = report.mappings.find((m) => m.control.id === "CIS-03");
    const cis05 = report.mappings.find((m) => m.control.id === "CIS-05");
    expect(cis03!.status).toBe("fail");
    expect(cis05!.status).toBe("fail");
  });
});

// ---------------------------------------------------------------------------
// generateComplianceReport — NIST
// ---------------------------------------------------------------------------
describe("generateComplianceReport (NIST)", () => {
  it("returns 12 NIST CSF controls", () => {
    const report = generateComplianceReport([], "nist");
    expect(report.framework).toBe("NIST CSF");
    expect(report.frameworkVersion).toBe("2.0");
    expect(report.totalControls).toBe(12);
  });

  it("maps threat_intelligence to DE.CM and DE.AE", () => {
    const findings = [makeFinding({ category: "threat_intelligence", status: "open" })];
    const report = generateComplianceReport(findings, "nist");
    const decm = report.mappings.find((m) => m.control.id === "DE.CM");
    const deae = report.mappings.find((m) => m.control.id === "DE.AE");
    expect(decm!.status).toBe("fail");
    expect(deae!.status).toBe("fail");
  });
});

// ---------------------------------------------------------------------------
// generateAllComplianceReports
// ---------------------------------------------------------------------------
describe("generateAllComplianceReports", () => {
  it("returns reports for all three frameworks", () => {
    const reports = generateAllComplianceReports([]);
    expect(reports).toHaveProperty("owasp");
    expect(reports).toHaveProperty("cis");
    expect(reports).toHaveProperty("nist");
  });

  it("each report has correct framework name", () => {
    const reports = generateAllComplianceReports([]);
    expect(reports.owasp.framework).toBe("OWASP Top 10");
    expect(reports.cis.framework).toBe("CIS Controls");
    expect(reports.nist.framework).toBe("NIST CSF");
  });

  it("severity reflects highest open finding severity", () => {
    const findings = [
      makeFinding({ category: "ssl_issue", severity: "critical", status: "open" }),
      makeFinding({ category: "ssl_issue", severity: "low", status: "open" }),
    ];
    const reports = generateAllComplianceReports(findings);
    const a02 = reports.owasp.mappings.find((m) => m.control.id === "A02");
    expect(a02!.severity).toBe("critical");
  });
});
