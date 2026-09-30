import { jsPDF } from "jspdf";
import { formatReportDate, formatReportDateOnly } from "./utils/format";

interface ReportPdfInput {
  title: string;
  summary: string;
  generatedAt: string | null;
  content: Record<string, unknown> | null;
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    affectedAsset?: string | null;
    category?: string | null;
    description?: string | null;
    remediation?: string | null;
    cvssScore?: string | null;
    evidenceSummary?: string;
  }>;
}

const MARGIN = 20;
const PAGE_WIDTH = 210;
const PAGE_HEIGHT = 297;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;
const LINE_HEIGHT = 6;
const SECTION_GAP = 8;

const SEVERITY_COLORS: Record<string, [number, number, number]> = {
  critical: [220, 38, 38],
  high: [234, 88, 12],
  medium: [202, 138, 4],
  low: [59, 130, 246],
  info: [100, 116, 139],
};

function wrapText(doc: jsPDF, text: string, maxWidth: number): string[] {
  return doc.splitTextToSize(text, maxWidth);
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
    if (y > PAGE_HEIGHT - MARGIN - 10) { doc.addPage(); y = MARGIN; }
    doc.text(line, MARGIN, y);
    y += LINE_HEIGHT;
  }
  return y + SECTION_GAP;
}

function addTable(doc: jsPDF, y: number, headers: string[], rows: string[][], colWidths: number[]): number {
  const rowHeight = 7;
  doc.setFontSize(8);
  doc.setFont("helvetica", "bold");
  let x = MARGIN;
  headers.forEach((h, i) => { doc.text(h, x, y); x += colWidths[i]; });
  y += rowHeight;
  doc.setDrawColor(200, 200, 200);
  doc.line(MARGIN, y - 5, MARGIN + colWidths.reduce((a, b) => a + b, 0), y - 5);
  doc.setFont("helvetica", "normal");
  for (const row of rows) {
    if (y > PAGE_HEIGHT - MARGIN - 15) { doc.addPage(); y = MARGIN; }
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
  if (y + needed > PAGE_HEIGHT - MARGIN) { doc.addPage(); return MARGIN; }
  return y;
}

function addSep(doc: jsPDF, y: number): number {
  doc.setDrawColor(220, 220, 220);
  doc.line(MARGIN, y, MARGIN + CONTENT_WIDTH, y);
  return y + 4;
}

export function generateReportPdfBuffer(input: ReportPdfInput): Buffer {
  const doc = new jsPDF({ format: "a4", unit: "mm" });
  let y = MARGIN;

  doc.setFontSize(18);
  doc.setFont("helvetica", "bold");
  doc.text(input.title, MARGIN, y);
  y += 12;

  doc.setFontSize(9);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(100, 100, 100);
  doc.text(`Generated: ${formatReportDate(input.generatedAt)}`, MARGIN, y);
  doc.setTextColor(0, 0, 0);
  y += 14;

  y = addSectionTitle(doc, y, "Executive Summary");
  y = addParagraph(doc, y, input.summary || "No summary available.");
  y = checkNewPage(doc, y, 30);

  const followUp = (input.content?.aiFollowUp && typeof input.content.aiFollowUp === "object"
    ? input.content.aiFollowUp as Record<string, unknown>
    : null);
  if (followUp) {
    y = addSectionTitle(doc, y, "AI Follow-up");
    const themes = Array.isArray(followUp.themes) ? followUp.themes as Array<Record<string, unknown>> : [];
    const checks = Array.isArray(followUp.checks) ? followUp.checks as Array<Record<string, unknown>> : [];
    const steps = Array.isArray(followUp.nextSteps) ? followUp.nextSteps.map((step) => String(step)) : [];
    if (themes.length > 0) {
      y = addParagraph(doc, y, themes.map((theme) => `${theme.title} (${theme.severity}): ${theme.narrative}`).join(" "));
    }
    if (checks.length > 0) {
      y = addParagraph(doc, y, checks.map((check) => `${check.label} [${check.status}]: ${check.summary}`).join(" "));
    }
    if (steps.length > 0) {
      y = addParagraph(doc, y, `Next steps: ${steps.join("; ")}`);
    }
    y = addSep(doc, y);
    y = checkNewPage(doc, y, 30);
  }

  const content = input.content || {};

  if (content.totalFindings !== undefined) {
    y = addSectionTitle(doc, y, "Report Overview");
    const lines: string[] = [];
    if (content.totalFindings !== undefined) lines.push(`Total Findings: ${content.totalFindings}`);
    if (content.criticalCount !== undefined) lines.push(`Critical: ${content.criticalCount}`);
    if (content.highCount !== undefined) lines.push(`High: ${content.highCount}`);
    if (content.mediumCount !== undefined) lines.push(`Medium: ${content.mediumCount}`);
    if (content.lowCount !== undefined) lines.push(`Low: ${content.lowCount}`);
    if (content.resolvedCount !== undefined) lines.push(`Resolved: ${content.resolvedCount}`);
    y = addParagraph(doc, y, lines.join(" | "));
    y = addSep(doc, y);
    y = checkNewPage(doc, y, 30);
  }

  const attackSurface = content.attackSurface as Record<string, unknown> | undefined;
  const attackSurfaceSummary = content.attackSurfaceSummary as { totalHosts: number; highRiskCount: number; wafCoverage: number } | undefined;
  if (attackSurface || attackSurfaceSummary) {
    y = addSectionTitle(doc, y, "Attack Surface");
    const sl: string[] = [];
    if (attackSurface?.surfaceRiskScore != null) sl.push(`Surface Risk Score: ${attackSurface.surfaceRiskScore}/100`);
    if (attackSurface?.tlsGrade) sl.push(`TLS Grade: ${attackSurface.tlsGrade}`);
    if (attackSurfaceSummary) sl.push(`Hosts: ${attackSurfaceSummary.totalHosts} | High Risk: ${attackSurfaceSummary.highRiskCount} | WAF Coverage: ${attackSurfaceSummary.wafCoverage}%`);
    y = addParagraph(doc, y, sl.join(". "));
    y = addSep(doc, y);
    y = checkNewPage(doc, y, 50);
  }

  const shMatrix = content.securityHeadersMatrix as Array<{ header: string; present: boolean; grade: string }> | undefined;
  const shCoverage = content.securityHeadersCoverage as { passing: number; total: number } | undefined;
  if (shMatrix && shMatrix.length > 0) {
    y = addSectionTitle(doc, y, `Security Headers (${shCoverage ? `${shCoverage.passing}/${shCoverage.total} passing` : ""})`);
    y = addTable(doc, y, ["Header", "Status", "Grade"], shMatrix.map((h) => [h.header, h.present ? "Present" : "Missing", h.grade ?? "N/A"]), [80, 50, 30]);
    y = addSep(doc, y);
    y = checkNewPage(doc, y, 40);
  }

  const assets = content.attackSurfaceAssets as Array<{ host: string; ip: string; riskScore: number; tlsGrade: string; waf: string; cdn: string }> | undefined;
  if (assets && assets.length > 0) {
    y = addSectionTitle(doc, y, "Per-Asset Attack Surface");
    y = addTable(doc, y, ["Host", "IP", "Risk", "TLS", "WAF", "CDN"], assets.slice(0, 25).map((a) => [a.host || "\u2014", a.ip || "\u2014", String(a.riskScore ?? "\u2014"), a.tlsGrade || "\u2014", a.waf || "\u2014", a.cdn !== "None" ? (a.cdn || "\u2014") : "\u2014"]), [45, 35, 20, 20, 35, 35]);
    if (assets.length > 25) { doc.setFontSize(8); doc.text(`... and ${assets.length - 25} more`, MARGIN, y); y += LINE_HEIGHT; }
    y += SECTION_GAP;
    y = addSep(doc, y);
    y = checkNewPage(doc, y, 40);
  }

  const cloud = content.cloudFootprint as Record<string, unknown> | undefined;
  if (cloud?.grades) {
    y = addSectionTitle(doc, y, "Cloud & Email Security");
    const g = cloud.grades as Record<string, string>;
    y = addParagraph(doc, y, [g.overall && `Overall: ${g.overall}`, g.spf && `SPF: ${g.spf}`, g.dmarc && `DMARC: ${g.dmarc}`, g.dkim && `DKIM: ${g.dkim}`].filter(Boolean).join(" | "));
    y = addSep(doc, y);
    y = checkNewPage(doc, y, 30);
  }

  const reconModules = content.reconModules as Array<{ moduleType: string; confidence: number }> | undefined;
  if (reconModules && reconModules.length > 0) {
    y = addSectionTitle(doc, y, "Intelligence Modules");
    y = addParagraph(doc, y, reconModules.map((m) => `${m.moduleType}: ${m.confidence}%`).join(", "));
    y = checkNewPage(doc, y, 30);
  }

  const postureTrend = content.postureTrend as Array<{ snapshotAt: string; surfaceRiskScore: number | null; securityScore: number | null; findingsCount: number }> | undefined;
  if (postureTrend && postureTrend.length > 0) {
    y = addSectionTitle(doc, y, "Posture Trend");
    y = addTable(doc, y, ["Date", "Surface Risk", "Security Score", "Findings"], postureTrend.map((p) => [
      formatReportDateOnly(p.snapshotAt),
      p.surfaceRiskScore != null ? String(p.surfaceRiskScore) : "\u2014",
      p.securityScore != null ? String(p.securityScore) : "\u2014",
      String(p.findingsCount ?? "\u2014"),
    ]), [45, 35, 40, 35]);
    y = addSep(doc, y);
    y = checkNewPage(doc, y, 40);
  }

  if (input.findings.length > 0) {
    y = addSep(doc, y);
    y = addSectionTitle(doc, y, `Included Findings (${input.findings.length})`);

    // A per-finding block, not a table \u2014 the DOCX and web reports already
    // show description/remediation/evidence per finding, and a table with
    // only title/asset/severity was the reason this format silently omitted
    // almost everything the other two showed. jsPDF's fixed-width columns
    // cannot hold a paragraph, so this trades row density for actually
    // carrying the content.
    for (const f of input.findings) {
      y = checkNewPage(doc, y, 22);
      const sevColor = SEVERITY_COLORS[f.severity] ?? [100, 116, 139];
      doc.setFillColor(sevColor[0], sevColor[1], sevColor[2]);
      doc.circle(MARGIN + 1.5, y - 1.5, 1.5, "F");
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(0, 0, 0);
      const titleLines = wrapText(doc, f.title, CONTENT_WIDTH - 6);
      doc.text(titleLines, MARGIN + 5, y);
      y += titleLines.length * LINE_HEIGHT;

      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(sevColor[0], sevColor[1], sevColor[2]);
      const metaParts = [f.severity.toUpperCase()];
      if (f.category) metaParts.push(f.category.replace(/_/g, " "));
      if (f.affectedAsset) metaParts.push(f.affectedAsset);
      if (f.cvssScore) metaParts.push(`CVSS ${f.cvssScore}`);
      doc.text(metaParts.join("   \u00b7   "), MARGIN + 5, y);
      doc.setTextColor(0, 0, 0);
      y += LINE_HEIGHT;

      if (f.description) {
        y = checkNewPage(doc, y, 14);
        doc.setFontSize(9);
        const descLines = wrapText(doc, f.description, CONTENT_WIDTH - 6).slice(0, 5);
        doc.text(descLines, MARGIN + 5, y);
        y += descLines.length * LINE_HEIGHT;
      }

      if (f.remediation) {
        y = checkNewPage(doc, y, 12);
        doc.setFontSize(8);
        doc.setFont("helvetica", "bold");
        doc.setTextColor(60, 60, 60);
        doc.text("Remediation:", MARGIN + 5, y);
        doc.setFont("helvetica", "normal");
        doc.setTextColor(0, 0, 0);
        const remLines = wrapText(doc, f.remediation, CONTENT_WIDTH - 32).slice(0, 3);
        doc.text(remLines, MARGIN + 32, y);
        y += Math.max(remLines.length, 1) * LINE_HEIGHT;
      }

      if (f.evidenceSummary) {
        y = checkNewPage(doc, y, 12);
        doc.setFontSize(7.5);
        doc.setFont("helvetica", "italic");
        doc.setTextColor(110, 110, 110);
        const evLines = wrapText(doc, `Evidence: ${f.evidenceSummary}`, CONTENT_WIDTH - 6).slice(0, 2);
        doc.text(evLines, MARGIN + 5, y);
        doc.setFont("helvetica", "normal");
        doc.setTextColor(0, 0, 0);
        y += evLines.length * LINE_HEIGHT;
      }

      y += 3;
      doc.setDrawColor(230, 230, 230);
      doc.line(MARGIN, y - 2, MARGIN + CONTENT_WIDTH, y - 2);
      y += 3;
    }
  }

  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(128, 128, 128);
    doc.text(`Page ${i} of ${pageCount} | ${input.title}`, MARGIN, PAGE_HEIGHT - 10);
    doc.text(formatReportDate(input.generatedAt), PAGE_WIDTH - MARGIN - 50, PAGE_HEIGHT - 10);
    doc.setTextColor(0, 0, 0);
  }

  const arrayBuffer = doc.output("arraybuffer");
  return Buffer.from(arrayBuffer);
}
