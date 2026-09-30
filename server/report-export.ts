import ExcelJS from "exceljs";
import { formatReportDate, formatReportDateOnly } from "./utils/format";

export interface ReportExportInput {
  title: string;
  summary: string;
  generatedAt: string | null;
  content: Record<string, unknown> | null;
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    status?: string;
    category?: string;
    affectedAsset?: string | null;
    description?: string;
    cvssScore?: string | null;
    remediation?: string | null;
    evidence?: Array<Record<string, unknown>> | null;
    tags?: string[] | null;
    assignee?: string | null;
    dueDate?: string | Date | null;
    priority?: number | null;
  }>;
}

/**
 * One line of evidence per finding, for formats too narrow for the full
 * array (CSV/XLSX columns, PDF table rows). The "verification" item
 * `verification-gate.ts` appends is excluded — it restates the finding's own
 * confirmation status, not new evidence — matching `evidenceToText` in
 * report-docx-input.ts, which excludes it for the same reason.
 *
 * `[N instances]` surfaces the aggregation this codebase already does at
 * write time (`checkCookieSecurity` and `per-asset-findings.ts` collapse many
 * occurrences into one finding with one evidence entry per instance) — a
 * reader of the export previously had no way to tell a finding affecting one
 * host from one affecting ninety.
 */
export function summarizeEvidence(evidence: Array<Record<string, unknown>> | null | undefined, maxLen = 300): string {
  if (!Array.isArray(evidence) || evidence.length === 0) return "";
  const real = evidence.filter((e) => e.type !== "verification");
  if (real.length === 0) return "";
  const parts = real
    .map((e) => (e.snippet as string | undefined) ?? (e.description as string | undefined) ?? "")
    .filter(Boolean);
  const instanceNote = real.length > 1 ? `[${real.length} instances] ` : "";
  return (instanceNote + parts.join(" | ")).replace(/\n/g, " ").slice(0, maxLen);
}

function escapeCsvCell(value: string): string {
  let str = String(value ?? "");
  // Neutralise CSV formula injection: prefix dangerous leading chars
  const dangerous = ["=", "+", "-", "@", "\t", "\r"];
  if (dangerous.some((c) => str.startsWith(c))) {
    str = `'${str}`;
  }
  if (str.includes(",") || str.includes('"') || str.includes("\n")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

export function generateReportCsv(input: ReportExportInput): string {
  const lines: string[] = [];
  const headers = [
    "ID", "Title", "Severity", "Status", "Category", "Affected Asset", "Description",
    "CVSS Score", "Remediation", "Evidence", "Tags", "Assignee", "Due Date", "Priority",
  ];
  lines.push(headers.map(escapeCsvCell).join(","));

  for (const f of input.findings) {
    lines.push([
      f.id,
      f.title,
      f.severity,
      f.status ?? "",
      f.category ?? "",
      f.affectedAsset ?? "",
      (f.description ?? "").replace(/\n/g, " ").slice(0, 500),
      f.cvssScore ?? "",
      (f.remediation ?? "").replace(/\n/g, " ").slice(0, 500),
      summarizeEvidence(f.evidence),
      (f.tags ?? []).join("; "),
      f.assignee ?? "",
      f.dueDate ? formatReportDateOnly(typeof f.dueDate === "string" ? f.dueDate : f.dueDate.toISOString()) : "",
      f.priority != null ? String(f.priority) : "",
    ]
      .map(escapeCsvCell)
      .join(","));
  }

  lines.push("");
  lines.push("Summary");
  lines.push(escapeCsvCell(input.summary || "No summary available."));
  lines.push("");
  lines.push("Generated");
  lines.push(escapeCsvCell(formatReportDate(input.generatedAt)));

  const content = input.content || {};
  if (content.totalFindings !== undefined) {
    lines.push("");
    lines.push("Overview");
    lines.push(`Total Findings,${escapeCsvCell(String(content.totalFindings))}`);
    if (content.criticalCount !== undefined) lines.push(`Critical,${escapeCsvCell(String(content.criticalCount))}`);
    if (content.highCount !== undefined) lines.push(`High,${escapeCsvCell(String(content.highCount))}`);
    if (content.mediumCount !== undefined) lines.push(`Medium,${escapeCsvCell(String(content.mediumCount))}`);
    if (content.lowCount !== undefined) lines.push(`Low,${escapeCsvCell(String(content.lowCount))}`);
    if (content.resolvedCount !== undefined) lines.push(`Resolved,${escapeCsvCell(String(content.resolvedCount))}`);
  }

  return lines.join("\n");
}

/** Sanitize a string for Excel to prevent formula injection */
function escapeExcelCell(value: string): string {
  const str = String(value ?? "");
  const dangerous = ["=", "+", "-", "@", "\t", "\r"];
  if (dangerous.some((c) => str.startsWith(c))) {
    return `'${str}`;
  }
  return str;
}

export async function generateReportExcel(input: ReportExportInput): Promise<Buffer> {
  const wb = new ExcelJS.Workbook();

  // Findings sheet
  const wsFindings = wb.addWorksheet("Findings");
  wsFindings.addRow([
    "ID", "Title", "Severity", "Status", "Category", "Affected Asset", "Description",
    "CVSS Score", "Remediation", "Evidence", "Tags", "Assignee", "Due Date", "Priority",
  ]);
  for (const f of input.findings) {
    wsFindings.addRow([
      escapeExcelCell(f.id),
      escapeExcelCell(f.title),
      escapeExcelCell(f.severity),
      escapeExcelCell(f.status ?? ""),
      escapeExcelCell(f.category ?? ""),
      escapeExcelCell(f.affectedAsset ?? ""),
      escapeExcelCell((f.description ?? "").replace(/\n/g, " ").slice(0, 2000)),
      escapeExcelCell(f.cvssScore ?? ""),
      escapeExcelCell((f.remediation ?? "").replace(/\n/g, " ").slice(0, 2000)),
      escapeExcelCell(summarizeEvidence(f.evidence, 2000)),
      escapeExcelCell((f.tags ?? []).join("; ")),
      escapeExcelCell(f.assignee ?? ""),
      f.dueDate ? formatReportDateOnly(typeof f.dueDate === "string" ? f.dueDate : f.dueDate.toISOString()) : "",
      f.priority ?? "",
    ]);
  }

  // Summary sheet
  const wsSummary = wb.addWorksheet("Summary");
  wsSummary.addRow(["Report", input.title]);
  wsSummary.addRow(["Generated", formatReportDate(input.generatedAt)]);
  wsSummary.addRow(["Summary", input.summary || "No summary available."]);

  const content = input.content || {};
  if (content.totalFindings !== undefined) {
    wsSummary.addRow([]);
    wsSummary.addRow(["Overview"]);
    wsSummary.addRow(["Total Findings", content.totalFindings as number]);
    if (content.criticalCount !== undefined) wsSummary.addRow(["Critical", content.criticalCount as number]);
    if (content.highCount !== undefined) wsSummary.addRow(["High", content.highCount as number]);
    if (content.mediumCount !== undefined) wsSummary.addRow(["Medium", content.mediumCount as number]);
    if (content.lowCount !== undefined) wsSummary.addRow(["Low", content.lowCount as number]);
    if (content.resolvedCount !== undefined) wsSummary.addRow(["Resolved", content.resolvedCount as number]);
  }

  const attackSurface = content.attackSurface as Record<string, unknown> | undefined;
  if (attackSurface?.surfaceRiskScore != null) {
    wsSummary.addRow([]);
    wsSummary.addRow(["Attack Surface"]);
    wsSummary.addRow(["Surface Risk Score", `${attackSurface.surfaceRiskScore}/100`]);
  }

  const attackSurfaceSummary = content.attackSurfaceSummary as { totalHosts: number; highRiskCount: number; wafCoverage: number } | undefined;
  if (attackSurfaceSummary) {
    wsSummary.addRow(["Total Hosts", attackSurfaceSummary.totalHosts]);
    wsSummary.addRow(["High Risk Count", attackSurfaceSummary.highRiskCount]);
    wsSummary.addRow(["WAF Coverage %", attackSurfaceSummary.wafCoverage]);
  }

  // Posture Trend sheet
  const postureTrend = content.postureTrend as Array<{ snapshotAt: string; surfaceRiskScore: number | null; securityScore: number | null; findingsCount: number }> | undefined;
  if (postureTrend && postureTrend.length > 0) {
    const wsTrend = wb.addWorksheet("Posture Trend");
    wsTrend.addRow(["Date", "Surface Risk Score", "Security Score", "Findings Count"]);
    for (const p of postureTrend) {
      wsTrend.addRow([
        formatReportDateOnly(p.snapshotAt),
        p.surfaceRiskScore ?? "",
        p.securityScore ?? "",
        p.findingsCount ?? "",
      ]);
    }
  }

  const arrayBuffer = await wb.xlsx.writeBuffer();
  return Buffer.from(arrayBuffer);
}
