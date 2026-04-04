/**
 * Unit tests for server/report-export.ts — CSV generation and formula injection defense.
 *
 * Tests: generateReportCsv (exported).
 */

import { describe, it, expect } from "vitest";

import { generateReportCsv, type ReportExportInput } from "../../../server/report-export";

function makeInput(overrides: Partial<ReportExportInput> = {}): ReportExportInput {
  return {
    title: overrides.title ?? "Test Report",
    summary: overrides.summary ?? "Summary text",
    generatedAt: overrides.generatedAt ?? "2025-01-15T10:00:00Z",
    content: overrides.content ?? null,
    findings: overrides.findings ?? [],
  };
}

// ---------------------------------------------------------------------------
// generateReportCsv
// ---------------------------------------------------------------------------
describe("generateReportCsv", () => {
  it("generates CSV with header row", () => {
    const csv = generateReportCsv(makeInput());
    const firstLine = csv.split("\n")[0];
    expect(firstLine).toContain("ID");
    expect(firstLine).toContain("Title");
    expect(firstLine).toContain("Severity");
    expect(firstLine).toContain("Status");
    expect(firstLine).toContain("Category");
  });

  it("includes finding rows", () => {
    const csv = generateReportCsv(makeInput({
      findings: [
        {
          id: "f-1",
          title: "SQL Injection",
          severity: "critical",
          status: "open",
          category: "injection",
          affectedAsset: "example.com",
          description: "Found SQL injection",
        },
      ],
    }));
    expect(csv).toContain("f-1");
    expect(csv).toContain("SQL Injection");
    expect(csv).toContain("critical");
  });

  it("neutralizes formula injection — prefixes = with apostrophe", () => {
    const csv = generateReportCsv(makeInput({
      findings: [
        {
          id: "f-evil",
          title: "=CMD('calc')",
          severity: "high",
          status: "open",
        },
      ],
    }));
    // The title should be prefixed with ' to neutralize formula
    expect(csv).toContain("'=CMD");
    expect(csv).not.toMatch(/(?<!'|")=CMD/); // No unprotected =CMD
  });

  it("neutralizes formula injection — prefixes + with apostrophe", () => {
    const csv = generateReportCsv(makeInput({
      findings: [
        {
          id: "f-plus",
          title: "+CMD('calc')",
          severity: "medium",
        },
      ],
    }));
    expect(csv).toContain("'+CMD");
  });

  it("neutralizes formula injection — prefixes - with apostrophe", () => {
    const csv = generateReportCsv(makeInput({
      findings: [
        {
          id: "f-minus",
          title: "-1+1",
          severity: "low",
        },
      ],
    }));
    expect(csv).toContain("'-1+1");
  });

  it("neutralizes formula injection — prefixes @ with apostrophe", () => {
    const csv = generateReportCsv(makeInput({
      findings: [
        {
          id: "f-at",
          title: "@SUM(A1:A10)",
          severity: "info",
        },
      ],
    }));
    expect(csv).toContain("'@SUM");
  });

  it("handles findings with commas and quotes in title", () => {
    const csv = generateReportCsv(makeInput({
      findings: [
        {
          id: "f-comma",
          title: 'Finding with "quotes" and, commas',
          severity: "medium",
        },
      ],
    }));
    // Should be properly escaped with double-quotes
    expect(csv).toContain('""quotes""');
  });

  it("handles empty findings array", () => {
    const csv = generateReportCsv(makeInput({ findings: [] }));
    expect(csv).toContain("ID");
    expect(csv).toContain("Summary");
  });

  it("includes summary in output", () => {
    const csv = generateReportCsv(makeInput({ summary: "Executive overview here" }));
    expect(csv).toContain("Executive overview here");
  });

  it("handles null affectedAsset gracefully", () => {
    const csv = generateReportCsv(makeInput({
      findings: [
        {
          id: "f-null",
          title: "No asset",
          severity: "low",
          affectedAsset: null,
        },
      ],
    }));
    expect(csv).toContain("f-null");
  });
});
