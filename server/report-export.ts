import ExcelJS from "exceljs";

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
    lines.push(`Total Findings,${escapeCsvCell(String(content.totalFindings))}`);
    if (content.criticalCount !== undefined) lines.push(`Critical,${escapeCsvCell(String(content.criticalCount))}`);
    if (content.highCount !== undefined) lines.push(`High,${escapeCsvCell(String(content.highCount))}`);
    if (content.mediumCount !== undefined) lines.push(`Medium,${escapeCsvCell(String(content.mediumCount))}`);
    if (content.lowCount !== undefined) lines.push(`Low,${escapeCsvCell(String(content.lowCount))}`);
    if (content.resolvedCount !== undefined) lines.push(`Resolved,${escapeCsvCell(String(content.resolvedCount))}`);
  }

  return lines.join("\n");
}

export async function generateReportExcel(input: ReportExportInput): Promise<Buffer> {
  const wb = new ExcelJS.Workbook();

  // Findings sheet
  const wsFindings = wb.addWorksheet("Findings");
  wsFindings.addRow(["ID", "Title", "Severity", "Status", "Category", "Affected Asset", "Description"]);
  for (const f of input.findings) {
    wsFindings.addRow([
      f.id,
      f.title,
      f.severity,
      f.status ?? "",
      f.category ?? "",
      f.affectedAsset ?? "",
      (f.description ?? "").replace(/\n/g, " ").slice(0, 2000),
    ]);
  }

  // Summary sheet
  const wsSummary = wb.addWorksheet("Summary");
  wsSummary.addRow(["Report", input.title]);
  wsSummary.addRow(["Generated", input.generatedAt ? new Date(input.generatedAt).toLocaleString() : "N/A"]);
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
        new Date(p.snapshotAt).toLocaleDateString(),
        p.surfaceRiskScore ?? "",
        p.securityScore ?? "",
        p.findingsCount ?? "",
      ]);
    }
  }

  const arrayBuffer = await wb.xlsx.writeBuffer();
  return Buffer.from(arrayBuffer);
}
