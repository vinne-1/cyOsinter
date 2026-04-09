import { describe, expect, it } from "vitest";
import type { Finding } from "@shared/schema";
import { generateAllComplianceReports, generateComplianceReport } from "../server/compliance-mapper";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-1",
    workspaceId: "workspace-1",
    scanId: null,
    title: "Test finding",
    description: "Test finding description",
    severity: "medium",
    status: "open",
    category: "security_headers",
    checkId: "security_headers",
    resourceType: "web_application",
    resourceId: "https://example.com",
    provider: null,
    complianceTags: [],
    affectedAsset: "https://example.com",
    evidence: [],
    cvssScore: null,
    remediation: null,
    assignee: null,
    assigneeId: null,
    priority: null,
    dueDate: null,
    slaBreached: false,
    workflowState: "open",
    groupId: null,
    verificationScanId: null,
    discoveredAt: new Date("2026-04-03T00:00:00.000Z"),
    resolvedAt: null,
    tags: [],
    aiEnrichment: null,
    ...overrides,
  };
}

describe("compliance-mapper", () => {
  it("returns zero score and no assessment data when findings are empty", () => {
    const report = generateComplianceReport([], "owasp");

    expect(report.score).toBe(0);
    expect(report.assessedControls).toBe(0);
    expect(report.hasAssessmentData).toBe(false);
    expect(report.unknownCount).toBe(report.totalControls);
  });

  it("marks mapped open findings as failing and scored", () => {
    const report = generateComplianceReport([makeFinding()], "owasp");
    const mappedControl = report.mappings.find((mapping) => mapping.control.id === "A05");

    expect(report.score).toBe(0);
    expect(report.assessedControls).toBe(1);
    expect(report.hasAssessmentData).toBe(true);
    expect(report.failCount).toBe(1);
    expect(mappedControl?.status).toBe("fail");
  });

  it("marks resolved findings as passing", () => {
    const report = generateComplianceReport([
      makeFinding({
        id: "finding-2",
        status: "resolved",
        resolvedAt: new Date("2026-04-04T00:00:00.000Z"),
      }),
    ], "owasp");
    const mappedControl = report.mappings.find((mapping) => mapping.control.id === "A05");

    expect(report.score).toBe(100);
    expect(report.passCount).toBe(1);
    expect(mappedControl?.status).toBe("pass");
  });

  it("marks mixed open and resolved findings as partial", () => {
    const report = generateComplianceReport([
      makeFinding({ id: "finding-3", status: "open" }),
      makeFinding({
        id: "finding-4",
        status: "resolved",
        resolvedAt: new Date("2026-04-04T00:00:00.000Z"),
      }),
    ], "owasp");
    const mappedControl = report.mappings.find((mapping) => mapping.control.id === "A05");

    expect(report.score).toBe(50);
    expect(report.partialCount).toBe(1);
    expect(mappedControl?.status).toBe("partial");
  });

  it("includes the new assessment metadata in all framework reports", () => {
    const reports = generateAllComplianceReports([makeFinding()]);

    for (const report of Object.values(reports)) {
      expect(report).toHaveProperty("assessedControls");
      expect(report).toHaveProperty("hasAssessmentData");
      expect(report).toHaveProperty("policyRequiredControls");
      expect(report).toHaveProperty("policyRequiredAssessedControls");
      expect(report).toHaveProperty("policyRequiredFailingControls");
      expect(report.hasAssessmentData).toBe(true);
    }
  });

  it("includes SOC2, ISO27001 and HIPAA reports", () => {
    const reports = generateAllComplianceReports([makeFinding()]);

    expect(reports).toHaveProperty("soc2");
    expect(reports).toHaveProperty("iso27001");
    expect(reports).toHaveProperty("hipaa");
  });

  it("prioritizes checkId mapping over category mapping", () => {
    const report = generateComplianceReport([
      makeFinding({
        id: "finding-checkid",
        category: "unknown_category",
        checkId: "cloudtrail-enabled",
      }),
    ], "soc2");

    const cc71 = report.mappings.find((m) => m.control.id === "CC7.1");
    expect(cc71?.overallStatus).toBe("fail");
    expect(cc71?.findingIds.length).toBe(1);
  });
});
