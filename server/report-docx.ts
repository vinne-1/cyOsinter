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
    // Full DNS record set (surfaced so every lookup the pipeline performs is reported).
    dnsRecords?: {
      a?: string[]; aaaa?: string[]; ns?: string[]; txt?: string[][];
      mx?: Array<{ priority: number; exchange: string }>;
      caa?: Array<{ tag: string; value: string }>;
      soa?: { nsname?: string; hostmaster?: string } | null;
    };
    dnssec?: { soaPresent?: boolean } | null;
    /** WHOIS / domain registration (registrar, dates, nameservers). */
    whois?: Record<string, string>;
    /** Per-IP reputation + hosting intel (AbuseIPDB / VirusTotal / BGP ASN / geo). */
    ipReputation?: Array<{ ip: string; abuseScore?: number; totalReports?: number; vtMalicious?: number; asn?: number; asnName?: string; isp?: string; country?: string; city?: string; ptr?: string }>;
    /** Server geolocation (from IP geo lookup). */
    geo?: { country?: string; region?: string; city?: string; org?: string };
    /** HTTP redirect chain observed for the primary domain. */
    redirectChain?: Array<{ status: number; url: string; location?: string }>;
  };
  findings: ReportFinding[];
  falsePositives?: Array<{ claim: string; result: string; verdict: string }>;
  images?: Record<string, Buffer>;
  /** Count of detected candidates the live verification gate withheld (fail-closed). */
  withheldCount?: number;
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
/** Read PNG dimensions from the IHDR chunk; null if not a valid PNG with real dimensions. */
function pngSize(buf: Buffer): { w: number; h: number } | null {
  if (buf.length < 24 || buf.readUInt32BE(0) !== 0x89504e47) return null;
  const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);
  if (w <= 0 || h <= 0) return null;
  return { w, h };
}
function imageParagraph(buf: Buffer, caption?: string): Paragraph[] {
  const size = pngSize(buf);
  // Skip anything that isn't a well-formed PNG rather than emitting a broken image.
  if (!size) return caption ? [new Paragraph({ alignment: AlignmentType.CENTER, children: [t(caption, { italics: true, size: 16, color: GREY })] })] : [];
  const maxW = 540;
  let w = Math.min(maxW, size.w);
  let hgt = Math.round((size.h / size.w) * w);
  if (hgt > 720) { hgt = 720; w = Math.round((size.w / size.h) * hgt); }
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

  // Auto-incrementing section numbers so inserting/omitting sections never
  // produces a misnumbered report.
  let secN = 0;
  const sec = (title: string) => h1(`${++secN}.  ${title}`);

  // ── Cover ──
  children.push(new Paragraph({ spacing: { before: 1200 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "OSINT & External Attack Surface", bold: true, size: 52, color: NAVY, font: "Calibri" })] }));
  children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 }, children: [new TextRun({ text: "Assessment Report", bold: true, size: 52, color: NAVY, font: "Calibri" })] }));
  children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 480 }, children: [new TextRun({ text: `${input.org ?? input.target}  ·  ${input.target}`, size: 30, color: BLUE, font: "Calibri" })] }));
  children.push(new Table({
    width: { size: 90, type: WidthType.PERCENTAGE },
    rows: ([
      ["Target", input.ipAddress ? `${input.target} (${input.ipAddress})` : input.target],
      ["Assessment type", "Passive OSINT + External Attack Surface Management (EASM)"],
      ["Scan mode", input.scanMode ?? "Standard"],
      ["Date", gen.slice(0, 10)],
      ["Classification", "CONFIDENTIAL — Authorized security assessment"],
    ] as Array<[string, string]>).map(([k, v]) => new TableRow({
      children: [cell([new Paragraph({ children: [t(k, { bold: true, size: 19 })] })], { width: 35 }), cell([new Paragraph({ children: [t(v, { size: 19 })] })], { width: 65 })],
    })),
  }));
  children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 480 }, children: [t("Findings independently verified against live sources; false positives filtered out.", { italics: true, size: 16, color: GREY })] }));
  children.push(new Paragraph({ children: [new PageBreak()] }));

  // ── 1. Objective ──
  children.push(sec("Objective & Scope"));
  children.push(p(`This assessment provides an external, attacker's-eye view of the publicly observable digital footprint of ${input.org ?? input.target}. It combines automated passive/active reconnaissance with automated verification of each finding against live sources, so the report reflects confirmed exposure rather than unvalidated tool output.`));
  for (const b of ["Passive infrastructure & hosting discovery", "DNS, subdomain & certificate-transparency enumeration", "Public exposure analysis (paths, files, APIs)", "Network service & open-port exposure", "SSL/TLS & email authentication (SPF/DKIM/DMARC)", "Web-application (CMS) surface review", "IP reputation & third-party corroboration"]) children.push(bullet(b));

  // ── 2. Methodology ──
  children.push(sec("Methodology"));
  children.push(p("Reconnaissance was performed with the Cyber-Shield-Pro EASM/OSINT scanner. Every candidate finding passes through a fail-closed verification gate before it is recorded: the gate re-issues a live probe that must reproduce the finding's evidence at report time (raw-reflection checks for XSS, redirect-honored checks for open redirects, method-honored checks for HTTP verbs, live TCP reachability for exposed services, dangling-CNAME plus takeover-fingerprint checks for subdomain takeover, and 2xx-plus-content-marker checks for exposed files and secrets). Any candidate the probe cannot reproduce — including probe errors and timeouts — is withheld and never recorded. As a result, every finding in this report was re-confirmed live; the report contains no unverified findings. Only free/open sources are used."));
  if ((input.withheldCount ?? 0) > 0) {
    children.push(p(`Verification gate: ${input.withheldCount} additional candidate(s) were detected during scanning but withheld from this report because a live re-probe could not reproduce their evidence (fail-closed policy).`, { italics: true, color: GREY }));
  }

  // ── 3. Target info ──
  children.push(sec("Target Information"));
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
  children.push(sec("Executive Summary"));
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
  children.push(sec("Detailed Findings"));
  findings.forEach((f, i) => { for (const el of findingBlock(i + 1, f, images)) children.push(el); });

  // ── DNS Records ── (every DNS lookup the pipeline performs, surfaced)
  const dnsr = recon.dnsRecords;
  const mxDetailed = dnsr?.mx?.length
    ? dnsr.mx.slice(0, 12).map((m) => `${m.exchange} (pri ${m.priority})`)
    : mxList;
  if (dnsr && (dnsr.a?.length || dnsr.aaaa?.length || dnsr.ns?.length || dnsr.mx?.length || dnsr.txt?.length || dnsr.caa?.length || dnsr.soa || recon.dnssec)) {
    children.push(sec("DNS Records"));
    const rows: Array<[string, string]> = [];
    if (dnsr.a?.length) rows.push(["A (IPv4)", dnsr.a.join(", ")]);
    if (dnsr.aaaa?.length) rows.push(["AAAA (IPv6)", dnsr.aaaa.join(", ")]);
    if (dnsr.ns?.length) rows.push(["NS", dnsr.ns.join(", ")]);
    if (mxDetailed.length) rows.push(["MX", mxDetailed.join(", ")]);
    if (dnsr.caa?.length) rows.push(["CAA", dnsr.caa.map((c) => `${c.tag} ${c.value}`).join(", ")]);
    if (dnsr.soa?.nsname) rows.push(["SOA", `${dnsr.soa.nsname}${dnsr.soa.hostmaster ? ` (${dnsr.soa.hostmaster})` : ""}`]);
    if (recon.dnssec) rows.push(["DNSSEC", recon.dnssec.soaPresent ? "SOA present (zone signed / responsive)" : "Not detected"]);
    if (dnsr.txt?.length) {
      const txtFlat = dnsr.txt.map((r) => r.join("")).filter(Boolean);
      if (txtFlat.length) rows.push(["TXT", txtFlat.slice(0, 8).map((r) => r.slice(0, 120)).join("  |  ")]);
    }
    children.push(kvTable(rows));
  }

  // ── Email auth ──
  const em = recon.emailSecurity;
  if (em) {
    children.push(sec("Email Authentication"));
    children.push(kvTable([
      ["SPF", em.spf?.found ? `PASS — ${em.spf.record ?? ""}` : "MISSING"],
      ["DKIM", em.dkim?.found
        ? `Present${(em.dkim as { selector?: string }).selector ? ` (selector: ${(em.dkim as { selector?: string }).selector})` : ""}${(em.dkim as { record?: string }).record ? ` — ${String((em.dkim as { record?: string }).record).slice(0, 80)}…` : ""}`
        : "Not found (selector-dependent)"],
      ["DMARC", em.dmarc?.found ? `Present — ${em.dmarc.record ?? ""}` : "MISSING"],
      ["MX", mxDetailed.join(", ") || "-"],
    ]));
  }

  // ── Domain Registration (WHOIS) ──
  const whois = recon.whois;
  // A value is only presentable if it's a clean field, not a WHOIS referral blob /
  // legal notice / redaction placeholder (which subdomain WHOIS often returns).
  const cleanWhois = (v: unknown): string | undefined => {
    if (typeof v !== "string") return undefined;
    const s = v.trim();
    if (!s || s.length > 120) return undefined;
    if (/<<<|>>>|https?:\/\/|notice|terms of use|redacted|data protected|please query|whois server/i.test(s)) return undefined;
    return s;
  };
  if (whois && Object.keys(whois).length) {
    const pick = (keys: string[]): string | undefined => {
      for (const k of Object.keys(whois)) if (keys.some((w) => k.toLowerCase().includes(w))) { const c = cleanWhois(whois[k]); if (c) return c; }
      return undefined;
    };
    const rows: Array<[string, string]> = [];
    const reg = pick(["registrar"]); if (reg) rows.push(["Registrar", reg]);
    const created = pick(["creat", "registered"]); if (created) rows.push(["Registered", created]);
    const updated = pick(["updat"]); if (updated) rows.push(["Updated", updated]);
    const expires = pick(["expir", "expiry"]); if (expires) rows.push(["Expires", expires]);
    const org = pick(["organization", "registrant org", "org"]); if (org) rows.push(["Registrant org", org]);
    // Fall back to any remaining clean fields if none of the well-known keys matched.
    if (!rows.length) for (const [k, v] of Object.entries(whois)) { const c = cleanWhois(v); if (c) { rows.push([k, c]); if (rows.length >= 8) break; } }
    // Only emit the section when we actually have presentable registration data.
    if (rows.length) { children.push(sec("Domain Registration (WHOIS)")); children.push(kvTable(rows)); }
  }

  // ── IP Reputation & Hosting ──
  if (recon.ipReputation?.length) {
    children.push(sec("IP Reputation & Hosting"));
    children.push(p("Third-party corroboration of each resolved IP (AbuseIPDB abuse score, VirusTotal malicious detections, ASN / hosting owner, and geolocation)."));
    children.push(new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: [
        new TableRow({ children: ["IP", "Abuse", "VT mal.", "ASN / Owner", "Location", "PTR"].map((h, i) =>
          cell([new Paragraph({ children: [t(h, { bold: true, size: 15 })] })], { width: [16, 10, 10, 30, 18, 16][i] })) }),
        ...recon.ipReputation.slice(0, 20).map((r) => new TableRow({ children: [
          cell([new Paragraph({ children: [t(r.ip, { size: 15 })] })], { width: 16 }),
          cell([new Paragraph({ children: [t(r.abuseScore != null ? `${r.abuseScore}%${r.totalReports ? ` (${r.totalReports})` : ""}` : "-", { size: 15, color: (r.abuseScore ?? 0) >= 25 ? "C00000" : GREY })] })], { width: 10 }),
          cell([new Paragraph({ children: [t(r.vtMalicious != null ? String(r.vtMalicious) : "-", { size: 15, color: (r.vtMalicious ?? 0) > 0 ? "C00000" : GREY })] })], { width: 10 }),
          cell([new Paragraph({ children: [t([r.asn ? `AS${r.asn}` : "", r.asnName ?? r.isp ?? ""].filter(Boolean).join(" ") || "-", { size: 15 })] })], { width: 30 }),
          cell([new Paragraph({ children: [t([r.city, r.country].filter(Boolean).join(", ") || "-", { size: 15 })] })], { width: 18 }),
          cell([new Paragraph({ children: [t(r.ptr ?? "-", { size: 14 })] })], { width: 16 }),
        ] })),
      ],
    }));
  }

  // ── Ports ──
  if (recon.ports?.length) {
    children.push(sec("Network Exposure — Open Ports & Services"));
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

  // ── Web app / WordPress ──
  if (recon.wordpress?.isWordPress || recon.techStack?.length) {
    children.push(sec("Web Application Surface"));
    if (recon.techStack?.length) children.push(p(`Technology stack: ${recon.techStack.map((x) => x.name).join(", ")}.`));
    if (recon.wordpress?.isWordPress) {
      children.push(p(`WordPress detected. XML-RPC ${recon.wordpress.xmlrpcEnabled ? "enabled" : "not confirmed"}.${recon.wordpress.users.length ? ` Enumerable user(s): ${recon.wordpress.users.map((u) => u.slug || u.name).filter(Boolean).join(", ")}.` : ""}`));
    }
  }

  // ── TLS ──
  if (recon.ssl) {
    children.push(sec("TLS / Certificate"));
    children.push(kvTable([
      ["Subject", recon.ssl.subject ?? "-"],
      ["Issuer", recon.ssl.issuer ?? "-"],
      ["Valid to", `${recon.ssl.validTo ?? "-"}${recon.ssl.daysRemaining != null ? ` (~${recon.ssl.daysRemaining} days)` : ""}`],
      ["Protocol", recon.ssl.protocol ?? "-"],
      ...(recon.ssl.altNames?.length ? [["SANs", recon.ssl.altNames.join(", ")] as [string, string]] : []),
    ]));
  }

  // ── Redirect chain ──
  if (recon.redirectChain?.length && recon.redirectChain.length > 1) {
    children.push(sec("HTTP Redirect Chain"));
    for (const hop of recon.redirectChain.slice(0, 12)) {
      children.push(bullet(`${hop.status} ${hop.url}${hop.location ? ` → ${hop.location}` : ""}`));
    }
  }

  // ── Recommendations ──
  children.push(sec("Prioritized Recommendations"));
  const highs = findings.filter((f) => sevRank(f.severity) <= 1);
  const meds = findings.filter((f) => sevRank(f.severity) === 2);
  if (highs.length) { children.push(p("Immediate (Critical / High):", { bold: true, spacingAfter: 40 })); for (const f of highs) children.push(bullet(f.remediation || f.title)); }
  if (meds.length) { children.push(p("Short term (Medium):", { bold: true, spacingAfter: 40 })); for (const f of meds) children.push(bullet(f.remediation || f.title)); }

  // ── Verified false positives ──
  if (input.falsePositives?.length) {
    children.push(sec("Verified False Positives"));
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

  // ── Appendix ──
  children.push(sec("Appendix — Assessment Metadata"));
  children.push(kvTable([
    ["Target", input.ipAddress ? `${input.target} (${input.ipAddress})` : input.target],
    ["Assessment date", gen.slice(0, 10)],
    ["Scan mode", input.scanMode ?? "Standard"],
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
