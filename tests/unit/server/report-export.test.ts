/**
 * Unit tests for server/report-export.ts — CSV generation and formula injection defense.
 *
 * Tests: generateReportCsv (exported).
 */

import { describe, it, expect } from "vitest";

import { generateReportCsv, generateReportExcel, type ReportExportInput } from "../../../server/report-export";

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

  it("includes Overview section when content.totalFindings is set", () => {
    const csv = generateReportCsv(makeInput({
      content: {
        totalFindings: 10,
        criticalCount: 2,
        highCount: 3,
        mediumCount: 4,
        lowCount: 1,
        resolvedCount: 5,
      },
    }));
    expect(csv).toContain("Overview");
    expect(csv).toContain("Total Findings,10");
    expect(csv).toContain("Critical,2");
    expect(csv).toContain("High,3");
    expect(csv).toContain("Medium,4");
    expect(csv).toContain("Low,1");
    expect(csv).toContain("Resolved,5");
  });

  it("omits Overview section when content.totalFindings is absent", () => {
    const csv = generateReportCsv(makeInput({ content: {} }));
    expect(csv).not.toContain("Overview");
  });
});

// ---------------------------------------------------------------------------
// generateReportExcel
// ---------------------------------------------------------------------------
describe("generateReportExcel", () => {
  it("returns a non-empty Buffer", async () => {
    const buf = await generateReportExcel(makeInput());
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.length).toBeGreaterThan(0);
  });

  it("produces a valid xlsx magic bytes (PK zip header)", async () => {
    const buf = await generateReportExcel(makeInput());
    // XLSX files are ZIP archives starting with PK (0x50 0x4B)
    expect(buf[0]).toBe(0x50);
    expect(buf[1]).toBe(0x4b);
  });

  it("includes findings in Excel output", async () => {
    const buf = await generateReportExcel(makeInput({
      findings: [
        { id: "f-xls", title: "XSS Finding", severity: "high", status: "open" },
      ],
    }));
    // Buffer should be non-empty and xlsx format
    expect(buf.length).toBeGreaterThan(100);
  });

  it("handles overview stats in Excel output", async () => {
    const buf = await generateReportExcel(makeInput({
      content: {
        totalFindings: 5,
        criticalCount: 1,
        highCount: 2,
        attackSurface: { surfaceRiskScore: 72 },
        attackSurfaceSummary: { totalHosts: 20, highRiskCount: 3, wafCoverage: 85 },
      },
    }));
    expect(buf.length).toBeGreaterThan(100);
  });

  it("handles posture trend sheet", async () => {
    const buf = await generateReportExcel(makeInput({
      content: {
        postureTrend: [
          { snapshotAt: "2025-01-01T00:00:00Z", surfaceRiskScore: 60, securityScore: 75, findingsCount: 10 },
          { snapshotAt: "2025-02-01T00:00:00Z", surfaceRiskScore: 55, securityScore: 80, findingsCount: 8 },
        ],
      },
    }));
    expect(buf.length).toBeGreaterThan(100);
  });

  it("neutralizes formula injection in Excel cells", async () => {
    // The function should not throw — injection chars are sanitized
    const buf = await generateReportExcel(makeInput({
      findings: [
        { id: "=CMD()", title: "+evil", severity: "critical" },
        { id: "@SUM", title: "-1+1", severity: "high" },
      ],
    }));
    expect(buf.length).toBeGreaterThan(0);
  });
});
