import {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ImageRun, PageBreak,
} from "docx";

/**
 * Data-driven DOCX report generator. Produces the professional OSINT/EASM
 * assessment report (cover, executive summary + register, methodology, target
 * info, detailed findings with Asset/Severity/CVSS/Issue/Impact/Evidence/
 * Remediation, email auth, ports, web app, TLS, verified false positives,
 * recommendations, appendix) as a Buffer. Screenshot evidence is optional and
 * embedded when provided (fail-soft when absent).
 */

export interface ReportFinding {
  title: string;
  severity: string;
  category: string;
  affectedAsset: string;
  description?: string;
  cvssScore?: string;
  remediation?: string;
  evidenceText?: string;
  evidenceImageKey?: string;
}

export interface ReportDocxInput {
  target: string;
  ipAddress?: string;
  org?: string;
  generatedAt?: string;
  scanMode?: string;
  recon?: {
    ips?: string[];
    ns?: string[];
    ptr?: Record<string, string[]>;
    subdomains?: string[];
    ssl?: { subject?: string; issuer?: string; validTo?: string; daysRemaining?: number; protocol?: string; altNames?: string[] };
    emailSecurity?: {
      spf?: { found?: boolean; record?: string };
      dmarc?: { found?: boolean; record?: string };
      dkim?: { found?: boolean };
      mx?: Array<{ exchange: string }> | string[];
    };
    ports?: Array<{ port: number; service?: string; banner?: string }>;
    techStack?: Array<{ name: string; source?: string }>;
    wordpress?: { isWordPress: boolean; users: Array<{ id?: number; name?: string; slug?: string }>; xmlrpcEnabled: boolean };
  };
  findings: ReportFinding[];
  falsePositives?: Array<{ claim: string; result: string; verdict: string }>;
  images?: Record<string, Buffer>;
}

const SEV_COLOR: Record<string, string> = {
  critical: "C00000", high: "E03C31", medium: "E69138", low: "F1C232", info: "9FC5E8",
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const sevRank = (s: string) => {
  const i = SEV_ORDER.indexOf((s || "info").toLowerCase());
  return i < 0 ? 99 : i;
};
const NAVY = "1F3864";
const BLUE = "2E75B6";
const GREY = "595959";

function t(text: string, opts: { bold?: boolean; size?: number; color?: string; italics?: boolean } = {}): TextRun {
  return new TextRun({ text, bold: opts.bold, italics: opts.italics, size: (opts.size ?? 21), color: opts.color, font: "Calibri" });
}
function p(text: string, opts: { bold?: boolean; size?: number; color?: string; italics?: boolean; align?: (typeof AlignmentType)[keyof typeof AlignmentType]; spacingAfter?: number } = {}): Paragraph {
  return new Paragraph({ children: [t(text, opts)], alignment: opts.align, spacing: { after: opts.spacingAfter ?? 120 } });
}
function h1(text: string): Paragraph {
  return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 120 }, children: [new TextRun({ text, bold: true, color: NAVY, font: "Calibri", size: 30 })] });
}
function h2(text: string): Paragraph {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 80 }, children: [new TextRun({ text, bold: true, color: BLUE, font: "Calibri", size: 25 })] });
}
function bullet(text: string): Paragraph {
  return new Paragraph({ bullet: { level: 0 }, spacing: { after: 40 }, children: [t(text)] });
}
function evidenceLines(text: string): Paragraph[] {
  return text.split("\n").filter(Boolean).slice(0, 12).map(
    (line) => new Paragraph({ indent: { left: 240 }, spacing: { after: 20 }, children: [new TextRun({ text: line, font: "Consolas", size: 17 })] }),
  );
}

function cell(children: Paragraph[], opts: { fill?: string; width?: number } = {}): TableCell {
  return new TableCell({
    shading: opts.fill ? { fill: opts.fill } : undefined,
    width: opts.width ? { size: opts.width, type: WidthType.PERCENTAGE } : undefined,
    children,
  });
}
function kvTable(rows: Array<[string, string]>): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: rows.map(([k, v]) => new TableRow({
      children: [
        cell([new Paragraph({ children: [t(k, { bold: true, size: 19 })] })], { width: 32 }),
        cell([new Paragraph({ children: [t(v, { size: 19 })] })], { width: 68 }),
      ],
    })),
  });
}

/** Read PNG width/height from the IHDR chunk for correct aspect scaling. */
function pngSize(buf: Buffer): { w: number; h: number } | null {
  if (buf.length < 24 || buf.readUInt32BE(0) !== 0x89504e47) return null;
  return { w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) };
}
function imageParagraph(buf: Buffer, caption?: string): Paragraph[] {
  const size = pngSize(buf);
  const maxW = 540;
  let w = maxW, hgt = Math.round(maxW * 0.6);
  if (size && size.w > 0) {
    w = Math.min(maxW, size.w);
    hgt = Math.round((size.h / size.w) * w);
    if (hgt > 720) { hgt = 720; w = Math.round((size.w / size.h) * hgt); }
  }
  const out: Paragraph[] = [new Paragraph({
    alignment: AlignmentType.CENTER,
    children: [new ImageRun({ type: "png", data: buf, transformation: { width: w, height: hgt } })],
  })];
  if (caption) out.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 160 }, children: [t(caption, { italics: true, size: 16, color: GREY })] }));
  return out;
}

function findingBlock(idx: number, f: ReportFinding, images?: Record<string, Buffer>): Paragraph[] | (Paragraph | Table)[] {
  const sev = (f.severity || "info").toUpperCase();
  const out: (Paragraph | Table)[] = [];
  out.push(h2(`${idx}  ${f.title}`));
  out.push(new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [new TableRow({
      children: [
        cell([new Paragraph({ children: [t("Severity", { bold: true, size: 16 })] }), new Paragraph({ children: [t(sev, { bold: true, size: 19 })] })], { fill: SEV_COLOR[(f.severity || "info").toLowerCase()], width: 25 }),
        cell([new Paragraph({ children: [t("CVSS", { bold: true, size: 16 })] }), new Paragraph({ children: [t(f.cvssScore || "-", { size: 19 })] })], { width: 20 }),
        cell([new Paragraph({ children: [t("Category", { bold: true, size: 16 })] }), new Paragraph({ children: [t(f.category || "-", { size: 19 })] })], { width: 25 }),
        cell([new Paragraph({ children: [t("Affected Asset", { bold: true, size: 16 })] }), new Paragraph({ children: [t(f.affectedAsset || "-", { size: 18 })] })], { width: 30 }),
      ],
    })],
  }));
  if (f.description) {
    out.push(p("Issue / Impact", { bold: true, spacingAfter: 40 }));
    out.push(p(f.description));
  }
  if (f.evidenceText) {
    out.push(p("Evidence", { bold: true, spacingAfter: 40 }));
    out.push(...evidenceLines(f.evidenceText));
  }
  if (f.evidenceImageKey && images && images[f.evidenceImageKey]) {
    out.push(...imageParagraph(images[f.evidenceImageKey]));
  }
  if (f.remediation) {
    out.push(p("Remediation", { bold: true, spacingAfter: 40 }));
    out.push(p(f.remediation));
  }
  out.push(new Paragraph({ spacing: { after: 120 }, children: [] }));
  return out as Paragraph[];
}

export async function generateReportDocx(input: ReportDocxInput): Promise<Buffer> {
  const gen = input.generatedAt ?? new Date().toISOString();
  const findings = [...input.findings].sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
  const counts: Record<string, number> = {};
  for (const f of findings) counts[(f.severity || "info").toLowerCase()] = (counts[(f.severity || "info").toLowerCase()] ?? 0) + 1;
  const recon = input.recon ?? {};
  const images = input.images;

  const children: (Paragraph | Table)[] = [];

  // ── Cover ──
  children.push(new Paragraph({ spacing: { before: 1200 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "OSINT & External Attack Surface", bold: true, size: 52, color: NAVY, font: "Calibri" })] }));
  children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 }, children: [new TextRun({ text: "Assessment Report", bold: true, size: 52, color: NAVY, font: "Calibri" })] }));
  children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 480 }, children: [new TextRun({ text: `${input.org ?? input.target}  ·  ${input.target}`, size: 30, color: BLUE, font: "Calibri" })] }));
  children.push(new Table({
    width: { size: 90, type: WidthType.PERCENTAGE },
    rows: ([
      ["Target", input.ipAddress ? `${input.target} (${input.ipAddress})` : input.target],
      ["Assessment type", "Passive OSINT + External Attack Surface Management (EASM)"],
      ["Scan mode", input.scanMode ?? "Safe / stealth"],
      ["Date", gen.slice(0, 10)],
      ["Classification", "CONFIDENTIAL — Authorized security assessment"],
    ] as Array<[string, string]>).map(([k, v]) => new TableRow({
      children: [cell([new Paragraph({ children: [t(k, { bold: true, size: 19 })] })], { width: 35 }), cell([new Paragraph({ children: [t(v, { size: 19 })] })], { width: 65 })],
    })),
  }));
  children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 480 }, children: [t("Findings independently verified against live sources; false positives filtered out.", { italics: true, size: 16, color: GREY })] }));
  children.push(new Paragraph({ children: [new PageBreak()] }));

  // ── 1. Objective ──
  children.push(h1("1.  Objective & Scope"));
  children.push(p(`This assessment provides an external, attacker's-eye view of the publicly observable digital footprint of ${input.org ?? input.target}. It combines automated passive/active reconnaissance with automated verification of each finding against live sources, so the report reflects confirmed exposure rather than unvalidated tool output.`));
  for (const b of ["Passive infrastructure & hosting discovery", "DNS, subdomain & certificate-transparency enumeration", "Public exposure analysis (paths, files, APIs)", "Network service & open-port exposure", "SSL/TLS & email authentication (SPF/DKIM/DMARC)", "Web-application (CMS) surface review", "IP reputation & third-party corroboration"]) children.push(bullet(b));

  // ── 2. Methodology ──
  children.push(h1("2.  Methodology"));
  children.push(p("Reconnaissance was performed with the Cyber-Shield-Pro EASM/OSINT scanner. Every material finding is automatically re-tested against the live target with strict verification logic (raw-reflection checks for XSS, method-honored checks for HTTP verbs, existence checks for cloud buckets, content checks for exposed files) so scanner noise and false positives are filtered before reporting. Findings that do not reproduce are listed as verified false positives. Only free/open sources are used."));

  // ── 3. Target info ──
  children.push(h1("3.  Target Information"));
  const info: Array<[string, string]> = [["Organization", input.org ?? input.target], ["Primary domain", `https://${input.target}`]];
  if (recon.ips?.length) info.push(["Resolved IP(s)", recon.ips.join(", ")]);
  if (recon.ptr) info.push(["Reverse DNS (PTR)", Object.entries(recon.ptr).map(([ip, n]) => `${ip} → ${n.join(", ")}`).join("; ")]);
  if (recon.ns?.length) info.push(["Name servers", recon.ns.join(", ")]);
  const mxList = Array.isArray(recon.emailSecurity?.mx) ? (recon.emailSecurity!.mx as Array<{ exchange: string } | string>).map((m) => (typeof m === "string" ? m : m.exchange)) : [];
  if (mxList.length) info.push(["Mail (MX)", mxList.join(", ")]);
  if (recon.subdomains?.length) info.push(["Subdomains discovered", `${recon.subdomains.length} — ${recon.subdomains.slice(0, 12).join(", ")}`]);
  if (recon.ssl) info.push(["TLS certificate", `${recon.ssl.issuer ?? ""} ${recon.ssl.protocol ?? ""}${recon.ssl.daysRemaining != null ? ` (~${recon.ssl.daysRemaining} days)` : ""}`.trim()]);
  children.push(kvTable(info));

  // ── 4. Executive summary ──
  children.push(h1("4.  Executive Summary"));
  children.push(p(`The assessment identified ${findings.length} confirmed finding(s) across the external surface. Findings were automatically verified to remove false positives before inclusion.`));
  children.push(new Table({
    width: { size: 60, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({ children: [cell([new Paragraph({ children: [t("Severity", { bold: true })] })]), cell([new Paragraph({ children: [t("Count", { bold: true })] })])] }),
      ...SEV_ORDER.map((s) => new TableRow({ children: [cell([new Paragraph({ children: [t(s.toUpperCase(), { bold: true })] })], { fill: SEV_COLOR[s] }), cell([new Paragraph({ children: [t(String(counts[s] ?? 0))] })])] })),
    ],
  }));

  // Findings register
  children.push(h2("4.1  Findings Register"));
  children.push(new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({ children: [cell([new Paragraph({ children: [t("Severity", { bold: true, size: 17 })] })], { width: 15 }), cell([new Paragraph({ children: [t("Finding", { bold: true, size: 17 })] })], { width: 55 }), cell([new Paragraph({ children: [t("Asset", { bold: true, size: 17 })] })], { width: 30 })] }),
      ...findings.map((f) => new TableRow({ children: [
        cell([new Paragraph({ children: [t((f.severity || "info").toUpperCase(), { bold: true, size: 16 })] })], { fill: SEV_COLOR[(f.severity || "info").toLowerCase()], width: 15 }),
        cell([new Paragraph({ children: [t(f.title, { size: 17 })] })], { width: 55 }),
        cell([new Paragraph({ children: [t(f.affectedAsset, { size: 15 })] })], { width: 30 }),
      ] })),
    ],
  }));
  children.push(new Paragraph({ children: [new PageBreak()] }));

  // ── 5. Detailed findings ──
  children.push(h1("5.  Detailed Findings"));
  findings.forEach((f, i) => { for (const el of findingBlock(i + 1, f, images)) children.push(el); });

  // ── 6. Email auth ──
  const em = recon.emailSecurity;
  if (em) {
    children.push(h1("6.  Email Authentication"));
    children.push(kvTable([
      ["SPF", em.spf?.found ? `PASS — ${em.spf.record ?? ""}` : "MISSING"],
      ["DKIM", em.dkim?.found ? "Present" : "Not found (selector-dependent)"],
      ["DMARC", em.dmarc?.found ? `Present — ${em.dmarc.record ?? ""}` : "MISSING"],
      ["MX", mxList.join(", ") || "-"],
    ]));
  }

  // ── 7. Ports ──
  if (recon.ports?.length) {
    children.push(h1("7.  Network Exposure — Open Ports & Services"));
    children.push(new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: [
        new TableRow({ children: [cell([new Paragraph({ children: [t("Port", { bold: true, size: 17 })] })], { width: 15 }), cell([new Paragraph({ children: [t("Service", { bold: true, size: 17 })] })], { width: 25 }), cell([new Paragraph({ children: [t("Banner / Note", { bold: true, size: 17 })] })], { width: 60 })] }),
        ...recon.ports.map((pt) => new TableRow({ children: [
          cell([new Paragraph({ children: [t(String(pt.port), { bold: true, size: 16 })] })], { width: 15 }),
          cell([new Paragraph({ children: [t(pt.service ?? "-", { size: 16 })] })], { width: 25 }),
          cell([new Paragraph({ children: [t((pt.banner ?? "").slice(0, 90) || "-", { size: 15 })] })], { width: 60 }),
        ] })),
      ],
    }));
  }

  // ── 8. Web app / WordPress ──
  if (recon.wordpress?.isWordPress || recon.techStack?.length) {
    children.push(h1("8.  Web Application Surface"));
    if (recon.techStack?.length) children.push(p(`Technology stack: ${recon.techStack.map((x) => x.name).join(", ")}.`));
    if (recon.wordpress?.isWordPress) {
      children.push(p(`WordPress detected. XML-RPC ${recon.wordpress.xmlrpcEnabled ? "enabled" : "not confirmed"}.${recon.wordpress.users.length ? ` Enumerable user(s): ${recon.wordpress.users.map((u) => u.slug || u.name).filter(Boolean).join(", ")}.` : ""}`));
    }
  }

  // ── 9. TLS ──
  if (recon.ssl) {
    children.push(h1("9.  TLS / Certificate"));
    children.push(kvTable([
      ["Subject", recon.ssl.subject ?? "-"],
      ["Issuer", recon.ssl.issuer ?? "-"],
      ["Valid to", `${recon.ssl.validTo ?? "-"}${recon.ssl.daysRemaining != null ? ` (~${recon.ssl.daysRemaining} days)` : ""}`],
      ["Protocol", recon.ssl.protocol ?? "-"],
      ...(recon.ssl.altNames?.length ? [["SANs", recon.ssl.altNames.join(", ")] as [string, string]] : []),
    ]));
  }

  // ── 10. Recommendations ──
  children.push(h1("10.  Prioritized Recommendations"));
  const highs = findings.filter((f) => sevRank(f.severity) <= 1);
  const meds = findings.filter((f) => sevRank(f.severity) === 2);
  if (highs.length) { children.push(p("Immediate (Critical / High):", { bold: true, spacingAfter: 40 })); for (const f of highs) children.push(bullet(f.remediation || f.title)); }
  if (meds.length) { children.push(p("Short term (Medium):", { bold: true, spacingAfter: 40 })); for (const f of meds) children.push(bullet(f.remediation || f.title)); }

  // ── 11. Verified false positives ──
  if (input.falsePositives?.length) {
    children.push(h1("11.  Verified False Positives"));
    children.push(p("The following were raised by automated tooling but did NOT reproduce on verification and are excluded from the findings above."));
    children.push(new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: [
        new TableRow({ children: [cell([new Paragraph({ children: [t("Automated claim", { bold: true, size: 17 })] })], { width: 35 }), cell([new Paragraph({ children: [t("Verification result", { bold: true, size: 17 })] })], { width: 45 }), cell([new Paragraph({ children: [t("Verdict", { bold: true, size: 17 })] })], { width: 20 })] }),
        ...input.falsePositives.map((fp) => new TableRow({ children: [
          cell([new Paragraph({ children: [t(fp.claim, { size: 16 })] })], { width: 35 }),
          cell([new Paragraph({ children: [t(fp.result, { size: 16 })] })], { width: 45 }),
          cell([new Paragraph({ children: [t(fp.verdict, { bold: true, size: 16, color: GREY })] })], { width: 20 }),
        ] })),
      ],
    }));
  }

  // ── 12. Appendix ──
  children.push(h1("12.  Appendix — Assessment Metadata"));
  children.push(kvTable([
    ["Target", input.ipAddress ? `${input.target} (${input.ipAddress})` : input.target],
    ["Assessment date", gen.slice(0, 10)],
    ["Scan mode", input.scanMode ?? "Safe / stealth"],
    ["Verification", "Automated live re-testing of each finding; false positives filtered"],
    ["Paid APIs used", "None — open-source / free sources only"],
  ]));
  children.push(p("Disclaimer: This assessment reflects the externally observable state of the target at the time of testing and was conducted with authorization for defensive purposes. It is point-in-time and non-exhaustive. Testing was limited to passive observation and non-intrusive verification.", { italics: true, size: 16, color: GREY }));

  const doc = new Document({
    creator: "Cyber-Shield-Pro",
    title: `OSINT & EASM Report — ${input.target}`,
    styles: { default: { document: { run: { font: "Calibri", size: 21 } } } },
    sections: [{ children }],
  });
  return Packer.toBuffer(doc);
}
