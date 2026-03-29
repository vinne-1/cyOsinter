import * as XLSX from "xlsx";

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
  }>;
}

function escapeCsvCell(value: string): string {
  const str = String(value ?? "");
  if (str.includes(",") || str.includes('"') || str.includes("\n")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

export function generateReportCsv(input: ReportExportInput): string {
  const lines: string[] = [];
  const headers = ["ID", "Title", "Severity", "Status", "Category", "Affected Asset", "Description"];
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
    ]
      .map(escapeCsvCell)
      .join(","));
  }

  lines.push("");
  lines.push("Summary");
  lines.push(escapeCsvCell(input.summary || "No summary available."));
  lines.push("");
  lines.push("Generated");
  lines.push(escapeCsvCell(input.generatedAt ? new Date(input.generatedAt).toLocaleString() : "N/A"));

  const content = input.content || {};
  if (content.totalFindings !== undefined) {
    lines.push("");
    lines.push("Overview");
    lines.push(`Total Findings,${content.totalFindings}`);
    if (content.criticalCount !== undefined) lines.push(`Critical,${content.criticalCount}`);
    if (content.highCount !== undefined) lines.push(`High,${content.highCount}`);
    if (content.mediumCount !== undefined) lines.push(`Medium,${content.mediumCount}`);
    if (content.lowCount !== undefined) lines.push(`Low,${content.lowCount}`);
    if (content.resolvedCount !== undefined) lines.push(`Resolved,${content.resolvedCount}`);
  }

  return lines.join("\n");
}

export function generateReportExcel(input: ReportExportInput): Buffer {
  const wb = XLSX.utils.book_new();

  const findingsData = [
    ["ID", "Title", "Severity", "Status", "Category", "Affected Asset", "Description"],
    ...input.findings.map((f) => [
      f.id,
      f.title,
      f.severity,
      f.status ?? "",
      f.category ?? "",
      f.affectedAsset ?? "",
      (f.description ?? "").replace(/\n/g, " ").slice(0, 2000),
    ]),
  ];
  const wsFindings = XLSX.utils.aoa_to_sheet(findingsData);
  XLSX.utils.book_append_sheet(wb, wsFindings, "Findings");

  const summaryData: (string | number | null)[][] = [
    ["Report", input.title],
    ["Generated", input.generatedAt ? new Date(input.generatedAt).toLocaleString() : "N/A"],
    ["Summary", input.summary || "No summary available."],
  ];
  const content = input.content || {};
  if (content.totalFindings !== undefined) {
    summaryData.push(["", ""]);
    summaryData.push(["Overview", ""]);
    summaryData.push(["Total Findings", content.totalFindings as number]);
    if (content.criticalCount !== undefined) summaryData.push(["Critical", content.criticalCount as number]);
    if (content.highCount !== undefined) summaryData.push(["High", content.highCount as number]);
    if (content.mediumCount !== undefined) summaryData.push(["Medium", content.mediumCount as number]);
    if (content.lowCount !== undefined) summaryData.push(["Low", content.lowCount as number]);
    if (content.resolvedCount !== undefined) summaryData.push(["Resolved", content.resolvedCount as number]);
  }
  const attackSurface = content.attackSurface as Record<string, unknown> | undefined;
  if (attackSurface?.surfaceRiskScore != null) {
    summaryData.push(["", ""]);
    summaryData.push(["Attack Surface", ""]);
    summaryData.push(["Surface Risk Score", `${attackSurface.surfaceRiskScore}/100`]);
  }
  const attackSurfaceSummary = content.attackSurfaceSummary as { totalHosts: number; highRiskCount: number; wafCoverage: number } | undefined;
  if (attackSurfaceSummary) {
    summaryData.push(["Total Hosts", attackSurfaceSummary.totalHosts as number]);
    summaryData.push(["High Risk Count", attackSurfaceSummary.highRiskCount as number]);
    summaryData.push(["WAF Coverage %", attackSurfaceSummary.wafCoverage as number]);
  }
  const wsSummary = XLSX.utils.aoa_to_sheet(summaryData);
  XLSX.utils.book_append_sheet(wb, wsSummary, "Summary");

  const postureTrend = content.postureTrend as Array<{ snapshotAt: string; surfaceRiskScore: number | null; securityScore: number | null; findingsCount: number }> | undefined;
  if (postureTrend && postureTrend.length > 0) {
    const trendData = [
      ["Date", "Surface Risk Score", "Security Score", "Findings Count"],
      ...postureTrend.map((p) => [
        new Date(p.snapshotAt).toLocaleDateString(),
        p.surfaceRiskScore ?? "",
        p.securityScore ?? "",
        p.findingsCount ?? "",
      ]),
    ];
    const wsTrend = XLSX.utils.aoa_to_sheet(trendData);
    XLSX.utils.book_append_sheet(wb, wsTrend, "Posture Trend");
  }

  const buffer = XLSX.write(wb, { type: "buffer", bookType: "xlsx" });
  return Buffer.from(buffer);
}
