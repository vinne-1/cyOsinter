import { jsPDF } from "jspdf";

export interface ReportPdfInput {
  title: string;
  summary: string;
  generatedAt: string | null;
  content: Record<string, unknown> | null;
  findings: Array<{ id: string; title: string; severity: string; affectedAsset?: string | null }>;
}

const MARGIN = 20;
const PAGE_WIDTH = 210;
const PAGE_HEIGHT = 297;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;
const LINE_HEIGHT = 6;
const SECTION_GAP = 8;

function wrapText(doc: jsPDF, text: string, maxWidth: number): string[] {
  const lines = doc.splitTextToSize(text, maxWidth);
  return lines;
}

function addSectionTitle(doc: jsPDF, y: number, title: string): number {
  doc.setFontSize(10);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(80, 80, 80);
  doc.text(title.toUpperCase(), MARGIN, y);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(0, 0, 0);
  return y + LINE_HEIGHT + 2;
}

function addParagraph(doc: jsPDF, y: number, text: string): number {
  if (!text) return y;
  doc.setFontSize(9);
  const lines = wrapText(doc, text, CONTENT_WIDTH);
  for (const line of lines) {
    if (y > PAGE_HEIGHT - MARGIN - 10) {
      doc.addPage();
      y = MARGIN;
    }
    doc.text(line, MARGIN, y);
    y += LINE_HEIGHT;
  }
  return y + SECTION_GAP;
}

function addTable(
  doc: jsPDF,
  y: number,
  headers: string[],
  rows: string[][],
  colWidths: number[]
): number {
  const rowHeight = 7;
  doc.setFontSize(8);
  doc.setFont("helvetica", "bold");
  let x = MARGIN;
  headers.forEach((h, i) => {
    doc.text(h, x, y);
    x += colWidths[i];
  });
  y += rowHeight;
  doc.setDrawColor(200, 200, 200);
  doc.line(MARGIN, y - 5, MARGIN + colWidths.reduce((a, b) => a + b, 0), y - 5);
  doc.setFont("helvetica", "normal");
  for (const row of rows) {
    if (y > PAGE_HEIGHT - MARGIN - 15) {
      doc.addPage();
      y = MARGIN;
    }
    x = MARGIN;
    row.forEach((cell, i) => {
      const maxChars = Math.max(10, Math.floor(colWidths[i] / 1.8));
      const cellText = String(cell ?? "");
      const truncated = cellText.length > maxChars ? cellText.substring(0, maxChars - 1) + "\u2026" : cellText;
      doc.text(truncated, x, y);
      x += colWidths[i];
    });
    y += rowHeight;
  }
  return y + SECTION_GAP;
}

function checkNewPage(doc: jsPDF, y: number, needed: number): number {
  if (y + needed > PAGE_HEIGHT - MARGIN) {
    doc.addPage();
    return MARGIN;
  }
  return y;
}

const SEVERITY_COLORS: Record<string, [number, number, number]> = {
  critical: [220, 38, 38],
  high: [234, 88, 12],
  medium: [202, 138, 4],
  low: [59, 130, 246],
  info: [100, 116, 139],
};

function addSectionSeparator(doc: jsPDF, y: number): number {
  doc.setDrawColor(220, 220, 220);
  doc.line(MARGIN, y, MARGIN + CONTENT_WIDTH, y);
  return y + 4;
}

export function generateReportPdf(input: ReportPdfInput): jsPDF {
  const doc = new jsPDF({ format: "a4", unit: "mm" });
  let y = MARGIN;

  // Title
  doc.setFontSize(18);
  doc.setFont("helvetica", "bold");
  doc.text(input.title, MARGIN, y);
  y += 12;

  doc.setFontSize(9);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(100, 100, 100);
  doc.text(
    `Generated: ${input.generatedAt ? new Date(input.generatedAt).toLocaleString() : "N/A"}`,
    MARGIN,
    y
  );
  doc.setTextColor(0, 0, 0);
  y += 14;

  // Executive Summary
  y = addSectionTitle(doc, y, "Executive Summary");
  y = addParagraph(doc, y, input.summary || "No summary available.");
  y = checkNewPage(doc, y, 30);

  const content = input.content || {};

  // Overview
  if (
    content.totalFindings !== undefined ||
    content.criticalCount !== undefined ||
    content.highCount !== undefined
  ) {
    y = addSectionTitle(doc, y, "Report Overview");
    const overviewLines: string[] = [];
    if (content.totalFindings !== undefined)
      overviewLines.push(`Total Findings: ${content.totalFindings}`);
    if (content.criticalCount !== undefined)
      overviewLines.push(`Critical: ${content.criticalCount}`);
    if (content.highCount !== undefined)
      overviewLines.push(`High: ${content.highCount}`);
    if (content.mediumCount !== undefined)
      overviewLines.push(`Medium: ${content.mediumCount}`);
    if (content.lowCount !== undefined)
      overviewLines.push(`Low: ${content.lowCount}`);
    if (content.resolvedCount !== undefined)
      overviewLines.push(`Resolved: ${content.resolvedCount}`);
    y = addParagraph(doc, y, overviewLines.join(" | "));
    y = addSectionSeparator(doc, y);
    y = checkNewPage(doc, y, 30);
  }

  // Attack Surface
  const attackSurface = content.attackSurface as Record<string, unknown> | undefined;
  const attackSurfaceSummary = content.attackSurfaceSummary as
    | { totalHosts: number; highRiskCount: number; wafCoverage: number }
    | undefined;
  if (attackSurface || attackSurfaceSummary) {
    y = addSectionTitle(doc, y, "Attack Surface");
    const surfaceLines: string[] = [];
    if (attackSurface?.surfaceRiskScore != null)
      surfaceLines.push(`Surface Risk Score: ${attackSurface.surfaceRiskScore}/100`);
    if (attackSurface?.tlsGrade)
      surfaceLines.push(`TLS Grade: ${attackSurface.tlsGrade}`);
    if (attackSurfaceSummary) {
      surfaceLines.push(
        `Hosts: ${attackSurfaceSummary.totalHosts} | High Risk: ${attackSurfaceSummary.highRiskCount} | WAF Coverage: ${attackSurfaceSummary.wafCoverage}%`
      );
    }
    y = addParagraph(doc, y, surfaceLines.join(". "));
    y = addSectionSeparator(doc, y);
    y = checkNewPage(doc, y, 50);
  }

  // Security Headers Matrix
  const securityHeadersMatrix = content.securityHeadersMatrix as
    | Array<{ header: string; present: boolean; grade: string }>
    | undefined;
  const securityHeadersCoverage = content.securityHeadersCoverage as
    | { passing: number; total: number }
    | undefined;
  if (securityHeadersMatrix && securityHeadersMatrix.length > 0) {
    y = addSectionTitle(
      doc,
      y,
      `Security Headers (${securityHeadersCoverage ? `${securityHeadersCoverage.passing}/${securityHeadersCoverage.total} passing` : ""})`
    );
    const headers = ["Header", "Status", "Grade"];
    const colWidths = [80, 50, 30];
    const rows = securityHeadersMatrix.map((h) => [
      h.header,
      h.present ? "Present" : "Missing",
      h.grade ?? "N/A",
    ]);
    y = addTable(doc, y, headers, rows, colWidths);
    y = addSectionSeparator(doc, y);
    y = checkNewPage(doc, y, 40);
  }

  // Per-Asset Table
  const attackSurfaceAssets = content.attackSurfaceAssets as
    | Array<{ host: string; ip: string; riskScore: number; tlsGrade: string; waf: string; cdn: string }>
    | undefined;
  if (attackSurfaceAssets && attackSurfaceAssets.length > 0) {
    y = addSectionTitle(doc, y, "Per-Asset Attack Surface");
    const headers = ["Host", "IP", "Risk", "TLS", "WAF", "CDN"];
    const colWidths = [45, 35, 20, 20, 35, 35];
    const rows = attackSurfaceAssets.slice(0, 25).map((a) => [
      a.host || "—",
      a.ip || "—",
      String(a.riskScore ?? "—"),
      a.tlsGrade || "—",
      a.waf || "—",
      a.cdn !== "None" ? (a.cdn || "—") : "—",
    ]);
    y = addTable(doc, y, headers, rows, colWidths);
    if (attackSurfaceAssets.length > 25) {
      doc.setFontSize(8);
      doc.text(`... and ${attackSurfaceAssets.length - 25} more`, MARGIN, y);
      y += LINE_HEIGHT;
    }
    y += SECTION_GAP;
    y = checkNewPage(doc, y, 40);
  }

  // Cloud/Email
  const cloudFootprint = content.cloudFootprint as Record<string, unknown> | undefined;
  if (cloudFootprint?.grades) {
    y = addSectionTitle(doc, y, "Cloud & Email Security");
    const grades = cloudFootprint.grades as Record<string, string>;
    const gradeStr = [
      grades.overall && `Overall: ${grades.overall}`,
      grades.spf && `SPF: ${grades.spf}`,
      grades.dmarc && `DMARC: ${grades.dmarc}`,
      grades.dkim && `DKIM: ${grades.dkim}`,
    ]
      .filter(Boolean)
      .join(" | ");
    y = addParagraph(doc, y, gradeStr);
    y = addSectionSeparator(doc, y);
    y = checkNewPage(doc, y, 30);
  }

  // Intelligence Modules
  const reconModules = content.reconModules as Array<{ moduleType: string; confidence: number }> | undefined;
  if (reconModules && reconModules.length > 0) {
    y = addSectionTitle(doc, y, "Intelligence Modules");
    const modStr = reconModules
      .map((m) => `${m.moduleType}: ${m.confidence}%`)
      .join(", ");
    y = addParagraph(doc, y, modStr);
    y = checkNewPage(doc, y, 30);
  }

  // OSINT Discovery
  const osintDiscovery = content.osintDiscovery as {
    summary?: { total: number; byCategory: Record<string, number> };
    leakedCredentials?: Array<{ title: string; severity: string }>;
    exposedDocuments?: Array<{ title: string; severity: string }>;
    infrastructureDisclosure?: Array<{ title: string; severity: string }>;
    osintExposure?: Array<{ title: string; severity: string }>;
  } | undefined;
  if (osintDiscovery && (osintDiscovery.summary?.total ?? 0) > 0) {
    y = addSectionTitle(
      doc,
      y,
      `OSINT Discovery (${osintDiscovery.summary?.total ?? 0} items)`
    );
    if (osintDiscovery.summary?.byCategory) {
      const catStr = Object.entries(osintDiscovery.summary.byCategory)
        .filter(([, c]) => c > 0)
        .map(([k, c]) => `${k}: ${c}`)
        .join(", ");
      y = addParagraph(doc, y, catStr);
    }
    const items = [
      ...(osintDiscovery.leakedCredentials ?? []),
      ...(osintDiscovery.exposedDocuments ?? []),
      ...(osintDiscovery.infrastructureDisclosure ?? []),
      ...(osintDiscovery.osintExposure ?? []),
    ].slice(0, 15);
    for (const item of items) {
      if (y > PAGE_HEIGHT - MARGIN - 10) {
        doc.addPage();
        y = MARGIN;
      }
      doc.setFontSize(8);
      doc.text(`${item.title} [${item.severity}]`, MARGIN, y);
      y += LINE_HEIGHT;
    }
    if (
      (osintDiscovery.leakedCredentials?.length ?? 0) +
        (osintDiscovery.exposedDocuments?.length ?? 0) +
        (osintDiscovery.infrastructureDisclosure?.length ?? 0) +
        (osintDiscovery.osintExposure?.length ?? 0) >
      15
    ) {
      doc.setFontSize(8);
      doc.text("... and more in included findings", MARGIN, y);
      y += LINE_HEIGHT;
    }
    y += SECTION_GAP;
    y = checkNewPage(doc, y, 40);
  }

  // IP Reputation
  const ipEnrichment = content.ipEnrichment as Record<
    string,
    {
      abuseipdb?: { abuseConfidenceScore?: number; totalReports?: number; countryCode?: string; isp?: string };
      virustotal?: { malicious?: number; suspicious?: number; harmless?: number; as_owner?: string; country?: string };
    }
  > | undefined;
  if (ipEnrichment && Object.keys(ipEnrichment).length > 0) {
    y = addSectionTitle(doc, y, "IP Reputation (AbuseIPDB / VirusTotal)");
    for (const [ip, data] of Object.entries(ipEnrichment).slice(0, 10)) {
      if (y > PAGE_HEIGHT - MARGIN - 15) {
        doc.addPage();
        y = MARGIN;
      }
      const abuse = data?.abuseipdb;
      const vt = data?.virustotal;
      const parts: string[] = [ip];
      if (abuse?.abuseConfidenceScore != null)
        parts.push(`AbuseIPDB: ${abuse.abuseConfidenceScore}%`);
      if (vt && (vt.malicious !== undefined || vt.suspicious !== undefined))
        parts.push(`VT: ${vt.malicious ?? 0} mal / ${vt.suspicious ?? 0} susp`);
      if (abuse?.countryCode) parts.push(`Country: ${abuse.countryCode}`);
      doc.setFontSize(8);
      doc.text(parts.join(" | "), MARGIN, y);
      y += LINE_HEIGHT;
    }
    if (Object.keys(ipEnrichment).length > 10) {
      doc.text(`... and ${Object.keys(ipEnrichment).length - 10} more IPs`, MARGIN, y);
      y += LINE_HEIGHT;
    }
    y += SECTION_GAP;
    y = checkNewPage(doc, y, 40);
  }

  // Findings List
  if (input.findings.length > 0) {
    y = addSectionSeparator(doc, y);
    y = addSectionTitle(doc, y, `Included Findings (${input.findings.length})`);
    const fHeaders = ["", "Title", "Asset", "Severity"];
    const fColWidths = [4, 86, 50, 30];
    doc.setFontSize(8);
    doc.setFont("helvetica", "bold");
    let fx = MARGIN;
    fHeaders.forEach((h, i) => { doc.text(h, fx, y); fx += fColWidths[i]; });
    y += 7;
    doc.setDrawColor(200, 200, 200);
    doc.line(MARGIN, y - 5, MARGIN + fColWidths.reduce((a, b) => a + b, 0), y - 5);
    doc.setFont("helvetica", "normal");
    for (const f of input.findings) {
      if (y > PAGE_HEIGHT - MARGIN - 15) {
        doc.addPage();
        y = MARGIN;
      }
      const sevColor = SEVERITY_COLORS[f.severity] ?? [100, 116, 139];
      doc.setFillColor(sevColor[0], sevColor[1], sevColor[2]);
      doc.circle(MARGIN + 1.5, y - 1.5, 1.5, "F");
      doc.setTextColor(0, 0, 0);
      const titleMax = Math.floor(fColWidths[1] / 1.8);
      const titleText = f.title.length > titleMax ? f.title.substring(0, titleMax - 1) + "\u2026" : f.title;
      doc.text(titleText, MARGIN + fColWidths[0], y);
      const assetMax = Math.floor(fColWidths[2] / 1.8);
      const assetText = (f.affectedAsset || "\u2014");
      const assetTrunc = assetText.length > assetMax ? assetText.substring(0, assetMax - 1) + "\u2026" : assetText;
      doc.text(assetTrunc, MARGIN + fColWidths[0] + fColWidths[1], y);
      doc.setTextColor(sevColor[0], sevColor[1], sevColor[2]);
      doc.setFont("helvetica", "bold");
      doc.text(f.severity.toUpperCase(), MARGIN + fColWidths[0] + fColWidths[1] + fColWidths[2], y);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(0, 0, 0);
      y += 7;
    }
    y += SECTION_GAP;
  }

  // Footer on last page
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(128, 128, 128);
    doc.text(
      `Page ${i} of ${pageCount} | ${input.title}`,
      MARGIN,
      PAGE_HEIGHT - 10
    );
    doc.text(
      input.generatedAt ? new Date(input.generatedAt).toLocaleString() : "",
      PAGE_WIDTH - MARGIN - 50,
      PAGE_HEIGHT - 10
    );
    doc.setTextColor(0, 0, 0);
  }

  return doc;
}

export function downloadReportPdf(
  input: ReportPdfInput,
  filename?: string
): void {
  const doc = generateReportPdf(input);
  const safeTitle = (input.title || "security-report")
    .replace(/[^a-zA-Z0-9-_]/g, "-")
    .replace(/-+/g, "-")
    .toLowerCase();
  const name = filename || `${safeTitle}.pdf`;
  doc.save(name);
}
