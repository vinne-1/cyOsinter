/**
 * Generates the Cyshield STRATEGY, POSITIONING and ROADMAP DOCX.
 *
 * Screenshots come from `scripts/capture-ui.mjs`, which captures the RUNNING
 * app against real seeded data, so every image in the document is the product
 * as it actually stands rather than a mockup.
 *
 *   node scripts/capture-ui.mjs --theme dark
 *   npx tsx scripts/gen-strategy-doc.mts
 */
import {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ImageRun, PageBreak,
  ShadingType, convertInchesToTwip,
} from "docx";
import fs from "fs";
import path from "path";

const SHOTS = "docs/screenshots";
const OUT = "docs/Cyshield-Strategy-and-Roadmap.docx";

// ── palette ────────────────────────────────────────────────────────────────
const INK = "1A1D23";
const GREY = "5B6472";
const BRAND = "0E7490";
const ACCENT = "B45309";
const RULE = "D8DEE7";
const PANEL = "F4F7FA";
const PANEL_BRAND = "E8F4F7";

// ── primitives ─────────────────────────────────────────────────────────────
const t = (text: string, o: Partial<{ bold: boolean; italics: boolean; size: number; color: string; font: string }> = {}) =>
  new TextRun({ text, bold: o.bold, italics: o.italics, size: o.size ?? 21, color: o.color ?? INK, font: o.font ?? "Segoe UI" });

const p = (text: string, o: Parameters<typeof t>[1] & { after?: number; align?: (typeof AlignmentType)[keyof typeof AlignmentType] } = {}) =>
  new Paragraph({ alignment: o.align, spacing: { after: o.after ?? 120, line: 288 }, children: [t(text, o)] });

/** A paragraph mixing normal and bold runs, written as `plain **bold** plain`. */
const rich = (markup: string, o: { after?: number; size?: number; color?: string } = {}) =>
  new Paragraph({
    spacing: { after: o.after ?? 120, line: 288 },
    children: markup.split(/(\*\*[^*]+\*\*)/g).filter(Boolean).map((seg) =>
      seg.startsWith("**") && seg.endsWith("**")
        ? t(seg.slice(2, -2), { bold: true, size: o.size, color: o.color })
        : t(seg, { size: o.size, color: o.color })),
  });

const h1 = (text: string) => new Paragraph({
  heading: HeadingLevel.HEADING_1,
  spacing: { before: 360, after: 200 },
  border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: BRAND, space: 6 } },
  children: [t(text, { bold: true, size: 30, color: BRAND })],
});

const h2 = (text: string) => new Paragraph({
  heading: HeadingLevel.HEADING_2,
  spacing: { before: 280, after: 140 },
  children: [t(text, { bold: true, size: 25, color: INK })],
});

const h3 = (text: string) => new Paragraph({
  heading: HeadingLevel.HEADING_3,
  spacing: { before: 200, after: 100 },
  children: [t(text, { bold: true, size: 22, color: ACCENT })],
});

const bullet = (text: string, level = 0) => new Paragraph({
  bullet: { level },
  spacing: { after: 80, line: 288 },
  children: text.split(/(\*\*[^*]+\*\*)/g).filter(Boolean).map((seg) =>
    seg.startsWith("**") && seg.endsWith("**") ? t(seg.slice(2, -2), { bold: true }) : t(seg)),
});

const mono = (lines: string[]) => new Paragraph({
  spacing: { before: 120, after: 160 },
  shading: { type: ShadingType.CLEAR, fill: PANEL },
  border: {
    top: { style: BorderStyle.SINGLE, size: 6, color: RULE, space: 8 },
    bottom: { style: BorderStyle.SINGLE, size: 6, color: RULE, space: 8 },
    left: { style: BorderStyle.SINGLE, size: 18, color: BRAND, space: 8 },
    right: { style: BorderStyle.SINGLE, size: 6, color: RULE, space: 8 },
  },
  children: lines.flatMap((l, i) => [
    ...(i ? [new TextRun({ break: 1 })] : []),
    new TextRun({ text: l, font: "Consolas", size: 17, color: INK }),
  ]),
});

/** A pulled-out statement — the claim a section is really making. */
const callout = (title: string, body: string) => new Table({
  width: { size: 100, type: WidthType.PERCENTAGE },
  borders: {
    top: { style: BorderStyle.SINGLE, size: 4, color: BRAND },
    bottom: { style: BorderStyle.SINGLE, size: 4, color: BRAND },
    left: { style: BorderStyle.SINGLE, size: 24, color: BRAND },
    right: { style: BorderStyle.SINGLE, size: 4, color: BRAND },
    insideHorizontal: { style: BorderStyle.NONE, size: 0, color: "auto" },
    insideVertical: { style: BorderStyle.NONE, size: 0, color: "auto" },
  },
  rows: [new TableRow({
    children: [new TableCell({
      shading: { type: ShadingType.CLEAR, fill: PANEL_BRAND },
      margins: { top: 160, bottom: 160, left: 180, right: 180 },
      children: [
        p(title, { bold: true, color: BRAND, size: 21, after: 60 }),
        rich(body, { after: 0 }),
      ],
    })],
  })],
});

function table(headers: string[], rows: string[][], widths?: number[], opts: { noHeader?: boolean } = {}) {
  const cell = (text: string, o: { bold?: boolean; fill?: string; color?: string } = {}) =>
    new TableCell({
      shading: o.fill ? { type: ShadingType.CLEAR, fill: o.fill } : undefined,
      margins: { top: 80, bottom: 80, left: 110, right: 110 },
      children: text.split("\n").map((line, i) => new Paragraph({
        spacing: { after: i === text.split("\n").length - 1 ? 0 : 40, line: 264 },
        children: line.split(/(\*\*[^*]+\*\*)/g).filter(Boolean).map((seg) =>
          seg.startsWith("**") && seg.endsWith("**")
            ? t(seg.slice(2, -2), { bold: true, size: 18, color: o.color })
            : t(seg, { bold: o.bold, size: 18, color: o.color })),
      })),
    });

  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    columnWidths: widths,
    borders: {
      top: { style: BorderStyle.SINGLE, size: 4, color: RULE },
      bottom: { style: BorderStyle.SINGLE, size: 4, color: RULE },
      left: { style: BorderStyle.NONE, size: 0, color: "auto" },
      right: { style: BorderStyle.NONE, size: 0, color: "auto" },
      insideHorizontal: { style: BorderStyle.SINGLE, size: 2, color: RULE },
      insideVertical: { style: BorderStyle.NONE, size: 0, color: "auto" },
    },
    rows: [
      ...(opts.noHeader ? [] : [new TableRow({
        tableHeader: true,
        children: headers.map((hd) => cell(hd, { bold: true, fill: BRAND, color: "FFFFFF" })),
      })]),
      ...rows.map((r, i) => new TableRow({
        children: r.map((c) => cell(c, { fill: i % 2 ? PANEL : undefined })),
      })),
    ],
  });
}

/** Embed a captured screenshot, with its caption and its numbered callouts. */
function figure(file: string, caption: string, callouts: string[] = []): (Paragraph | Table)[] {
  const abs = path.join(SHOTS, file);
  if (!fs.existsSync(abs)) return [p(`[screenshot missing: ${file}]`, { italics: true, color: GREY })];
  const out: (Paragraph | Table)[] = [
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 160, after: 80 },
      children: [new ImageRun({ type: "png", data: fs.readFileSync(abs), transformation: { width: 636, height: 398 } })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: callouts.length ? 100 : 220 },
      children: [t(caption, { italics: true, size: 17, color: GREY })],
    }),
  ];
  for (let i = 0; i < callouts.length; i++) {
    out.push(new Paragraph({
      spacing: { after: i === callouts.length - 1 ? 220 : 60, line: 264 },
      indent: { left: convertInchesToTwip(0.3) },
      children: [
        t(`${i + 1}  `, { bold: true, color: ACCENT, size: 19 }),
        ...callouts[i].split(/(\*\*[^*]+\*\*)/g).filter(Boolean).map((seg) =>
          seg.startsWith("**") && seg.endsWith("**")
            ? t(seg.slice(2, -2), { bold: true, size: 19 })
            : t(seg, { size: 19 })),
      ],
    }));
  }
  return out;
}

const pageBreak = () => new Paragraph({ children: [new PageBreak()] });

// ═══════════════════════════════════════════════════════════════════════════
const body: (Paragraph | Table)[] = [];

// ═══════════════════════════════════════════════════════════════════════════
// Diagram primitives — architecture drawn with native Word elements
//
// The architecture figures are built from tables and text rather than embedded
// as pictures, deliberately. A client can select the text, search it, copy a
// capability name into an email, and edit a box if their estate differs. A PNG
// gives them none of that, goes blurry when scaled, and is unreadable to a
// screen reader. The trade is that layout must be expressed as table geometry.
// ═══════════════════════════════════════════════════════════════════════════

type BandTone = "base" | "brand" | "warn" | "new" | "plan";

const TONE: Record<BandTone, { fill: string; edge: string; head: string }> = {
  base:  { fill: "FBFCFE", edge: "D8DEE7", head: BRAND },
  brand: { fill: "E8F4F7", edge: "A9D4DE", head: BRAND },
  warn:  { fill: "FDF4E7", edge: "ECCFA2", head: ACCENT },
  new:   { fill: "EDF7EE", edge: "B3D9B8", head: "2F7D3A" },
  plan:  { fill: "F3F0FA", edge: "CFC3E8", head: "6B4FA8" },
};

interface BandSpec {
  /** Stage number or phase label shown before the title. */
  tag?: string;
  title: string;
  /** Capability names. Rendered as separated inline text so they wrap cleanly. */
  items: string[];
  /** One line explaining what the stage guarantees. */
  note?: string;
  tone?: BandTone;
}

/** A single row of the diagram: one band, or several side by side. */
function bandRow(bands: BandSpec[]): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    columnWidths: bands.map(() => Math.floor(9360 / bands.length)),
    borders: {
      top: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
      bottom: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
      left: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
      right: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
      insideHorizontal: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
      insideVertical: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
    },
    rows: [
      new TableRow({
        children: bands.map((b) => {
          const tone = TONE[b.tone ?? "base"];
          const kids: Paragraph[] = [
            new Paragraph({
              spacing: { after: 70 },
              children: [
                ...(b.tag ? [t(`${b.tag}  `, { bold: true, size: 17, color: tone.head })] : []),
                t(b.title.toUpperCase(), { bold: true, size: 17, color: tone.head }),
              ],
            }),
            // Capabilities as one wrapping line separated by a middot: it reflows
            // at any page width, which a grid of fixed boxes does not.
            new Paragraph({
              spacing: { after: b.note ? 60 : 0, line: 250 },
              children: [t(b.items.join("   ·   "), { size: 18 })],
            }),
          ];
          if (b.note) {
            kids.push(new Paragraph({
              spacing: { after: 0, line: 240 },
              children: [t(b.note, { size: 16, italics: true, color: GREY })],
            }));
          }
          return new TableCell({
            shading: { type: ShadingType.CLEAR, fill: tone.fill },
            margins: { top: 130, bottom: 130, left: 150, right: 150 },
            borders: {
              top: { style: BorderStyle.SINGLE, size: 4, color: tone.edge },
              bottom: { style: BorderStyle.SINGLE, size: 4, color: tone.edge },
              left: { style: BorderStyle.SINGLE, size: 4, color: tone.edge },
              right: { style: BorderStyle.SINGLE, size: 4, color: tone.edge },
            },
            children: kids,
          });
        }),
      }),
    ],
  });
}

/** Vertical flow connector between two bands. */
const flow = (label?: string) =>
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 60, after: 60 },
    children: [
      t("▼", { size: 20, color: "93A0B0" }),
      ...(label ? [t(`  ${label}`, { size: 15, color: GREY, italics: true })] : []),
    ],
  });

/** Small caption under a diagram. */
const caption = (text: string) =>
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 100, after: 220 },
    children: [t(text, { italics: true, size: 17, color: GREY })],
  });

const add = (...items: (Paragraph | Table)[]) => body.push(...items);
// ═══════════════════════════════════════════════════════════════════════════
add(
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 1500, after: 60 },
    children: [t("Cyshield Pro", { bold: true, size: 56, color: BRAND })],
  }),
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 200 },
    children: [t("The Problem, the Position, and the Road to It", { size: 30, color: INK })],
  }),
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 900 },
    children: [t("Self-hosted External Attack Surface Management, built for a six-hour clock", { italics: true, size: 21, color: GREY })],
  }),
  p("Every capability claim here is measured against the running system, and every gap names what specifically blocks it. Where something was tested and found unworkable, that is stated rather than deferred.", { align: AlignmentType.CENTER, color: GREY }),
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 400 },
    children: [t("3 September 2026", { size: 19, color: GREY })],
  }),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("1  The pitch"),

  h2("The one-sentence version"),
  rich("**Indian regulation gives you six hours to report a cyber incident from the moment you notice it — and what decides whether you notice is whether somebody is continuously watching the part of your estate you forgot you owned.** Cyshield Pro watches it, proves what it finds, and never sends the map of your attack surface to somebody else's cloud."),

  h2("1.1  The Indian client's problem"),
  p("Three facts, each independently verifiable, combine into a problem existing tools do not solve well for an Indian organisation."),

  h3("Fact one — the clock is six hours, and it starts when you notice"),
  rich("The CERT-In Directions of 28 April 2022, in force since 28 June 2022, require any body corporate — **regardless of size** — to report a listed cyber incident within **six hours** of noticing it. The reportable list is not limited to confirmed breaches. It explicitly includes **targeted scanning and probing of critical networks**, unauthorised access, website defacement, data leaks, and attacks on servers and applications."),
  callout(
    "Why that wording decides the sale",
    "Six hours is not a reporting problem; it is a detection problem. The paperwork takes minutes. What takes weeks is discovering that a forgotten staging host is exposed, that a subdomain has been taken over, or that credentials leaked into a public repository. An organisation that learns of its exposure from a third party has already lost the clock. The binding constraint is time-to-notice — exactly what continuous external monitoring compresses.",
  ),

  h3("Fact two — the penalties are large, and the enforcement window is now"),
  rich("The Digital Personal Data Protection Act 2023, with Rules notified in **November 2025**, carries penalties up to **₹250 crore** and a duty to notify both the Data Protection Board and affected Data Principals. Enforcement is phased through 2026: consent and breach-notification machinery expected operational by mid-2026, audits and Significant Data Fiduciary duties by late 2026. This conversation is happening in Indian boardrooms this year."),

  h3("Fact three — sending your attack surface abroad is itself a governance problem"),
  rich("An external attack-surface platform necessarily builds **the single most sensitive document about your organisation**: a complete, current map of every internet-facing weakness you have. Commercial EASM platforms are SaaS, so that map lives on their infrastructure, usually outside India. For a regulated entity — where RBI localisation norms take precedence and DPDP authorises further mandates — that is an uncomfortable answer to give an auditor."),
  rich("**Cyshield Pro is self-hosted.** Scan data never leaves the operator's infrastructure. That is not a pricing decision; it is the structural property that lets a regulated Indian entity adopt the tool without creating a new residency exposure while managing its old one."),

  h2("1.2  The international client's problem"),
  p("The regulatory shape is the same everywhere; only the numbers move."),
  table(
    ["Jurisdiction", "Clock", "What it means operationally"],
    [
      ["India — CERT-In", "6 hours from noticing", "The tightest in the world. Detection speed is the entire game."],
      ["EU — GDPR / NIS2", "72 hours", "Same structure: the clock starts at awareness, not at breach."],
      ["US — SEC (public cos.)", "4 business days from materiality", "Requires a defensible record of when you knew, and what you knew."],
      ["India — DPDP", "Prescribed window to Board and Data Principals", "A second, privacy-side duty on the same event."],
    ],
    [22, 20, 58],
  ),
  rich("All of them start the clock at **awareness**, none accepts \"we did not know\" as a defence, and all reward an organisation that can show a dated, evidenced record of what it saw and when. This product generates that record as a by-product of doing its job."),

  h2("1.3  Where this competes, honestly"),
  table(
    ["Competitor", "Their strength", "Where this wins"],
    [
      ["Censys ASM", "Internet-wide scan data, unmatched breadth", "They perform no validation — buyer's guides call them \"a strong input, not a standalone program\". This ships verified findings, not observations."],
      ["Cortex Xpanse", "Internet-scale scanning, ~500B ports/day", "Cost, and self-hosting. Their own documented weakness — attributing subsidiaries — is unsolved by anyone."],
      ["Detectify", "Crowdsourced payloads from a researcher network", "Broader EASM surface; they sit closer to an application scanner."],
      ["CloudSEK XVigil", "Deep and dark web breadth, 500+ sources", "Data sovereignty, evidence discipline and price. Their dark-web breadth is genuinely ahead of ours."],
      ["SecurityScorecard", "A rating language boards, insurers and procurement already speak, plus peer benchmarking we cannot match", "Their scorecard awards 100/A to factors they have no telemetry for. Ours reports those as “Not assessed”. See 2.2."],
    ],
    [18, 30, 52],
  ),
  callout(
    "The claim worth making, and the one worth refusing",
    "Defensible: for an Indian organisation that must not export its attack-surface data, and that is judged against a six-hour clock, this is the only serious option in its price band — and its findings are verified rather than merely observed. NOT worth claiming: that it sees more of the internet than Censys or Xpanse. It does not, it cannot without their capital, and the claim would collapse in the first proof-of-concept.",
  ),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("2  What the platform does today"),
  p("Measured against the running system on 3 September 2026.", { color: GREY }),

  table(
    ["Dimension", "State"],
    [
      ["Scanner modules", "57 detection and discovery modules"],
      ["Discovery methods", "7 independent, each carrying per-host provenance"],
      ["Compliance frameworks", "5 — OWASP, CIS, NIST, CERT-In, DPDP"],
      ["Security rating", "9 risk factors, each independently graded A–F, with a third state for what was never assessed"],
      ["Unit tests", "1,532 across 94 files, all passing"],
      ["End-to-end tests", "17 Playwright, including a full accessibility sweep"],
      ["Accessibility", "WCAG 2.1 A/AA — zero serious or critical across 27 routes and every tab"],
      ["OWASP ASVS 5.0", "All 70 Level 1 requirements assessed: 58 pass, 9 N/A, 3 operator, 0 fail"],
      ["Measured false positives", "0 of 11 independently verified findings"],
      ["Deployment", "Self-hosted; container runs unprivileged, asserted in CI"],
    ],
    [30, 70],
  ),

  h2("2.1  Architecture as built"),
  p("Each band is a stage every scan passes through. Nothing below is planned — all of it runs today.", { color: GREY }),

  bandRow([{
    tag: "1",
    title: "Discovery — seven independent methods",
    tone: "brand",
    items: [
      "Certificate transparency (crt.sh, Certspotter)",
      "Wordlist brute-force, wildcard-filtered",
      "Nine keyless passive indexes",
      "Keyed datasets — Chaos, SecurityTrails, BeVigil",
      "Permutation of the estate's own naming convention",
      "Certificate subject-alternative names",
      "ASN / BGP routed footprint",
      "Reverse DNS and co-hosting",
      "A, AAAA and CNAME resolution",
    ],
    note: "Every host records which sources named it and how many independently agree. A source that fails is recorded as failed — never as one that found nothing.",
  }]),
  flow(),

  bandRow([
    {
      tag: "2",
      title: "Probe and fingerprint",
      items: [
        "Live host probe (httpx or native)",
        "Open ports",
        "TLS versions actually accepted",
        "Favicon hash for estate grouping",
        "Technology and library versions",
        "WAF and CDN identification",
        "Endpoint crawl (katana or native)",
      ],
      note: "One request per host yields a full fingerprint rather than a liveness bit.",
    },
    {
      tag: "3",
      title: "Detect — 57 modules",
      items: [
        "DNS, SPF, DMARC, MTA-STS",
        "Security headers and CSP content",
        "Cookie attributes",
        "Exposed secrets and files",
        "Cloud storage and container endpoints",
        "Active tests (DAST-lite)",
        "Nuclei templates",
        "Client-side library CVEs via OSV",
        "Dependency confusion",
        "Subdomain takeover",
      ],
      note: "Detectors name an artefact only when its structure is present.",
    },
  ]),
  flow(),

  bandRow([{
    tag: "4",
    title: "Evidence pipeline — what separates a finding from a guess",
    tone: "warn",
    items: [
      "① Response oracle — calibrates each host's not-found behaviour, so a 200 is not evidence",
      "② Body signatures — positive proof the response IS the artefact being named",
      "③ Verification gate — re-probes at report time and withholds what it cannot reproduce",
    ],
    note: "Anything withheld is recorded as withheld, so \"we looked and could not confirm\" never renders the same as \"we never looked\". Measured: 0 false positives across 11 independently verified findings.",
  }]),
  flow(),

  bandRow([
    {
      tag: "5",
      title: "Attribute and prioritise",
      items: [
        "Findings attributed to the host observed",
        "Severity bands with diminishing returns",
        "Remediation SLA clock",
        "Cases as the unit of work",
        "Finding de-duplication",
      ],
      note: "Volume of one repeated misconfiguration does not score as many problems.",
    },
    {
      tag: "6",
      title: "Report and comply",
      tone: "new",
      items: [
        "DOCX, PDF, CSV, XLSX export",
        "OWASP Top 10",
        "CIS Controls v8",
        "NIST CSF 2.0",
        "CERT-In six-hour incident types",
        "DPDP technical safeguards",
      ],
      note: "Every finding carries evidence, verification and remediation.",
    },
    {
      tag: "7",
      title: "Deliver",
      items: [
        "SIEM export (ECS and CEF)",
        "Signed webhooks",
        "Live alerts over WebSocket",
        "Full audit trail",
      ],
      note: "Egress hangs off one choke point, so a new event type is delivered automatically.",
    },
  ]),
  caption("Figure 1 — Current architecture. Highlighted band is the evidence pipeline, the stage that decides what is reported."),
  h2("2.2  The security rating — and the number we refuse to print"),
  p("A rating is how a security posture travels: to a board, an insurer, a procurement questionnaire. The market standard is SecurityScorecard, so the model here follows theirs deliberately — one overall score, a set of independently graded factors, A–F throughout. Two things are different, and both were decided by reading a real SecurityScorecard report end to end.", { color: GREY }),

  h3("The nine factors"),
  bandRow([
    { tag: "", title: "Assessed — scored from findings", items: ["Application Security", "Network Security", "DNS & Email Health", "Software Currency", "Supply Chain", "Data Exposure", "Cloud & Container Posture", "Access Control", "Brand & Threat Intelligence"], note: "Every finding category the engine can emit maps to exactly one factor. A build-time test asserts this, so a new detector cannot deduct from the overall score while appearing in none of the areas the reader is told to act on.", tone: "brand" },
  ]),
  flow(),
  bandRow([
    { title: "Assessed", items: ["Checks ran", "Findings attributed", "Scored and graded"], note: "The ordinary case.", tone: "base" },
    { title: "Clean", items: ["Checks ran", "Nothing outstanding", "Scores 100"], note: "Genuine good news, and distinguishable from the next column.", tone: "new" },
    { title: "Not assessed", items: ["No capable check ran", "No score", "Renders “N/A”"], note: "Never 100. This is the column a rating vendor does not have.", tone: "warn" },
  ]),
  caption("Three states, where a commercial rating has two."),

  h3("Difference 1 — a factor nobody assessed is not a factor scoring 100"),
  rich("A real SecurityScorecard report reviewed for this work grades ten factors and shows **Endpoint Security 100, IP Reputation 100, Hacker Chatter 100 and Social Engineering 100**, each annotated “0 issues”. An outside observer cannot see a company’s endpoint estate at all. Those are not findings of excellence — they are the absence of telemetry, printed as a perfect score."),
  rich("This matters more than it first appears, because the number does not stay on the page. It is pasted into board packs and vendor questionnaires, where **“100” is read as an assurance somebody performed a check**. Our factors therefore carry a third state, and an unassessed area renders as “Not assessed” with the reason attached."),
  callout(
    "We will show fewer perfect scores than a rating vendor, on purpose",
    "On a live client workspace the platform reports **7 of 9 factors assessed** — two are blank because nothing capable of judging them ran. A competitor’s report of the same estate would show nine scores, two of them unearned. The honest version is less flattering and is the one that survives a client asking how the number was arrived at.",
  ),

  h3("Difference 2 — the per-issue “score impact” is a number that does not survive being acted on"),
  rich("SecurityScorecard prints a score impact beside each issue — −5.1, −2.3, −7.6 — implying that fixing that one item moves the rating by that much. We implemented the equivalent and measured it against a live workspace’s findings. **Every value came back 0.0**, and that was correct rather than broken."),
  rich("The reason is the scoring model. Severity bands set a ceiling from the worst severity **present at all**, so with two open medium findings the rating is capped at 85 whether one is fixed or neither. A smooth per-issue gradient is not a property this model has, and printing one would be an invitation to spend a sprint on an item that moves nothing."),
  p("So the platform states the gate instead:", { color: GREY }),
  mono([
    "Score is capped at 85 by 2 medium findings.",
    "Clearing all 2 would raise the score to about 95 (+10).",
    "Fixing only some of them does not move it — the cap is set by any one remaining.",
  ]),
  rich("That is a sprint target, it is actionable, and it is **true**. The decimal would be none of those things. Measured on a live workspace: 85 → 95."),

  h3("What their rating has that ours does not"),
  rich("**Peer and industry benchmarking.** A SecurityScorecard report places the client against an industry cohort — a percentile, and a named peer set. That is genuinely valuable to a board, and it requires a corpus of comparably scored organisations that we do not have. It is listed as a gap rather than approximated, because a percentile computed against an invented cohort is exactly the kind of manufactured number the rest of this section exists to avoid. Closing it needs either real multi-tenant scan volume or a purchased dataset."),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("3  The product as it runs"),
  p("Screenshots of the live application against real scan data, not mock-ups.", { color: GREY }),

  ...figure("01-dashboard.png", "Dashboard — posture, findings and intelligence for the selected workspace.", [
    "**Severity-banded scoring.** An identical workspace scored 0/100 under the earlier linear formula, because 27 medium findings alone floored it. Twenty-seven hosts missing one header is one misconfiguration with 27 instances, not 27 problems.",
    "**Findings triage** — where observations become work.",
  ]),
  ...figure("risk-factors-card.png", "The security rating, decomposed. Two factors read “Not assessed” rather than scoring 100 — no check capable of judging them ran.", [
    "**The gate is stated first.** The banded model means fixing one of the two mediums moves nothing; only clearing the band lifts the cap. That is what the panel says, in place of a per-issue decimal.",
    "**“3 open findings · worst: low” beside a grade A is not a contradiction.** Informational findings deduct nothing by design, so the grade is right — the severity is shown so the reader can see why.",
  ]),
  ...figure("08-compliance.png", "Compliance — five frameworks including the two Indian ones. CERT-In reports incident types implicated rather than a pass rate, because that is the honest shape of a reporting obligation."),
  ...figure("09-brand-threats.png", "Brand protection — lookalike domains, ransomware leak sites, exposed code, app-store abuse and breach-corpus exposure."),
  ...figure("04-findings.png", "Findings inbox — only findings of kind `security` reach here. A control correctly in place is good news and does not belong in a work queue."),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("4  The end state"),

  h2("4.1  Stated plainly"),
  rich("**Continuous assurance instead of periodic assessment.** The estate is monitored without anyone pressing a button. A material change is detected in minutes and reaches the people who must act. The resulting record is already shaped as the CERT-In or DPDP notification it may need to become. Every claim in it is reproducible on demand."),
  rich("The measurable goal: **make \"we noticed within six hours\" a fact the client can evidence**, not an aspiration."),

  h2("4.2  Target architecture"),
  p("Solid bands run today. Dashed bands are planned, and each names what actually blocks it — so this is a schedule, not a wish list.", { color: GREY }),

  bandRow([{
    tag: "BUILT",
    title: "Foundation — running today",
    tone: "brand",
    items: [
      "7-method discovery with provenance",
      "57 detection modules",
      "Three-gate evidence pipeline",
      "Per-host attribution and scoring",
      "5 compliance frameworks",
      "SIEM, webhooks, audit trail",
      "Breach-corpus exposure",
      "Tor transport",
    ],
    note: "Everything the phases below build upon already exists and is tested.",
  }]),
  flow("phase 1 — wiring, no new capability required"),

  bandRow([
    {
      tag: "P1",
      title: "Continuous assurance",
      tone: "plan",
      items: [
        "Scheduled re-scan on a cadence",
        "Diff against the previous run",
        "Alert only on material change",
        "Drafted CERT-In incident record",
        "Time-to-notice metric per workspace",
      ],
      note: "Blocked by nothing. Scheduler, scan-diff, alerting and the CERT-In mapping all exist and are individually tested.",
    },
    {
      tag: "P2",
      title: "Provable quality",
      tone: "plan",
      items: [
        "OWASP ASVS Level 2 assessment",
        "Accuracy corpus of several hundred findings",
        "Published false-positive rate",
      ],
      note: "Blocked by assessment effort, not code. Level 1 already stands at 58 pass, 0 fail.",
    },
  ]),
  flow("phase 3 — requires purchase, not engineering"),

  bandRow([
    {
      tag: "P3",
      title: "Purchased breadth",
      tone: "plan",
      items: [
        "Per-employee breach exposure (HIBP)",
        "Favicon and certificate pivoting (Shodan / Censys)",
        "Android and social brand abuse (commercial feed)",
      ],
      note: "Each is a subscription. The surrounding code already exists in every case.",
    },
    {
      tag: "P4",
      title: "Open problems",
      tone: "plan",
      items: [
        "Entity model — subsidiaries and acquisitions",
        "Deep and dark web forum breadth",
        "JARM / TLS-stack fingerprinting",
      ],
      note: "Blocked by data availability, a legal decision, and the runtime respectively — see section 6.",
    },
  ]),
  caption("Figure 2 — Target architecture. Phase 1 and 2 need no purchase; phase 3 is procurement; phase 4 is unresolved for the whole industry."),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("5  How we get there"),
  p("Ordered so each step is independently useful and none waits on a purchase.", { color: GREY }),

  h2("5.1  Phase 1 — Continuous assurance"),
  rich("**Goal:** the platform notices before the client does, and the notice is already shaped as the regulatory record."),
  table(
    ["Step", "Work", "Done when"],
    [
      ["1.1", "Run scheduled scans on a cadence per workspace and diff each run against the previous.", "A workspace shows what changed between two runs without anyone opening it."],
      ["1.2", "Raise an alert only on material change — a new live host, a new critical or high finding, a takeover becoming claimable.", "A quiet estate produces no alerts for a week; a new exposure pages within minutes."],
      ["1.3", "Render a drafted CERT-In record from a material finding: incident type, first-observed timestamp, affected asset, evidence.", "An operator can file within the six-hour window from the artefact the product produced."],
      ["1.4", "Publish time-to-notice per workspace.", "The core claim becomes a number on the dashboard rather than a sentence in a brochure."],
    ],
    [8, 50, 42],
  ),
  rich("**Why first:** every component exists and is tested. This is the step that converts a tool someone remembers to run into a service that watches — and it is the entire basis of the six-hour pitch."),

  h2("5.2  Phase 2 — Provable quality"),
  rich("**Goal:** the accuracy and assurance claims survive a sceptical buyer's scrutiny."),
  table(
    ["Step", "Work", "Done when"],
    [
      ["2.1", "Complete the ASVS Level 2 assessment, requirement by requirement, in the format already used for Level 1.", "A published document covering 253 cumulative requirements with a code reference each."],
      ["2.2", "Grow the accuracy audit from 11 findings to several hundred, verified against live ground truth.", "A false-positive rate that can be published without the caveat that it is a sample."],
      ["2.3", "Automate the audit so the rate is recomputed rather than hand-measured.", "The number is current in every release, not a snapshot."],
    ],
    [8, 50, 42],
  ),
  rich("**Why second:** it costs nothing but effort, and it is the difference between claiming accuracy and evidencing it. Competitors all assert a sub-1% false-positive rate; almost none show their method."),

  h2("5.3  Phase 3 — Purchased breadth"),
  table(
    ["Purchase", "Cost band", "What it unlocks", "Code status"],
    [
      ["HaveIBeenPwned subscription", "Low monthly", "Per-employee credential exposure across third-party breaches.", "Domain-level exposure already built and keyless."],
      ["Shodan or Censys paid tier", "Moderate", "Favicon and certificate pivoting to find hosts the estate never advertised.", "Hash already computed and displayed for manual pivoting."],
      ["Store / social intelligence feed", "Higher", "Android and social-platform brand abuse.", "iOS already covered; the interface generalises."],
      ["Corporate registry dataset", "Higher", "Subsidiary and acquisition discovery.", "Attribution logic exists; only the data is missing."],
    ],
    [24, 12, 34, 30],
  ),
  rich("**Why last:** each is a subscription decision rather than an engineering one, and none of them is a prerequisite for the phases above."),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("6  What is genuinely blocked, and by what"),
  p("Each of these was tested rather than assumed. Grouped by the kind of blocker, because the remedies differ entirely.", { color: GREY }),

  table(
    ["Capability", "Blocker", "What would clear it"],
    [
      ["Internet-wide pivoting — favicon hash, certificate, host search", "Cost. The free Shodan plan permits host lookup but returns 403 on search.", "A paid tier. The hash is already computed and shown, so an operator can pivot manually today."],
      ["Per-employee breach exposure", "Cost, and deliberate gating — the provider requires proof of domain ownership because the data identifies individuals.", "A subscription plus domain verification."],
      ["Google Play / Android brand abuse", "Platform policy. No free official search API; scraping is fragile and against terms.", "A commercial store-intelligence feed. iOS is covered and reports state Android was not checked."],
      ["Social and executive impersonation", "Platform policy. Search access removed or paywalled across the major networks.", "Paid platform access or a digital-risk feed."],
      ["Entity model — subsidiaries, acquisitions", "Data availability. Tested: RDAP unreachable, registrant organisation GDPR-redacted, and certificate-transparency organisation search depends on a field modern certificates omit.", "A corporate-registry or WHOIS-history dataset. This is also the market leader's documented weakness — nobody solves it cheaply."],
      ["Deep and dark web forum breadth", "A business and legal decision, not engineering. Vetted forum membership carries real exposure.", "An explicit decision. Tor transport and the public ransomware leak-site corpus are already built."],
      ["JARM / TLS-stack fingerprinting", "The runtime. Node cannot craft the precise ClientHello JARM requires.", "A native TLS binding — deliberately not attempted, because a hash that does not match the published corpus is worse than none."],
      ["Internet-scale scanning", "Capital. Competitors scan hundreds of billions of ports daily.", "Not clearable at this scale. Mitigated by breadth of free sources plus permutation, which finds hosts no index has."],
    ],
    [26, 34, 40],
  ),

  h2("6.1  What this deliberately will not do"),
  bullet("**Claim internet-scale coverage.** It does not have it and cannot without the capital; the claim would fail the first proof-of-concept."),
  bullet("**Ship dark-web forum monitoring without an explicit decision.** The transport exists; the legal exposure is a business call, not an engineering one."),
  bullet("**Assert compliance it cannot observe.** DPDP consent, grievance handling and retention are marked \"not externally assessable\" rather than left blank, because a blank control reads as a pass."),
  bullet("**Report anything it cannot reproduce.** The verification gate withholds, and the report states what was withheld and why."),

  h2("Appendix A  Reproducing this document"),
  mono([
    "docker compose up -d db",
    "PORT=5050 npm run dev",
    "npx tsc --noEmit          # zero errors",
    "npm test                  # 1,511 tests / 93 files",
    "npx playwright test       # 17 e2e, incl. accessibility sweep",
    "node scripts/capture-ui.mjs --theme dark --out docs/screenshots",
    "npx tsx scripts/gen-strategy-doc.mts",
  ]),
  p("The architecture figures are built from Word tables rather than embedded pictures, so a client can select the text, search it, and edit a box if their estate differs.", { color: GREY }),

  h2("Appendix B  Supporting documents"),
  bullet("docs/asvs-5.0-conformance.md — all 70 ASVS Level 1 requirements with a code reference each"),
  bullet("docs/detection-accuracy.md — the false-positive audit method and per-finding verdicts"),
  bullet("docs/Cyshield-Current-State.docx — detailed capability and blocker report"),
  bullet("CLAUDE.md — the engineering record: every non-obvious decision, with the failure that motivated it"),
);

// ═══════════════════════════════════════════════════════════════════════════
const doc = new Document({
  creator: "Cyshield Pro",
  title: "Cyshield Pro — Strategy, Positioning and Roadmap",
  styles: { default: { document: { run: { font: "Segoe UI", size: 21, color: INK } } } },
  sections: [{
    properties: { page: { margin: { top: 1000, right: 1000, bottom: 1000, left: 1000 } } },
    children: body,
  }],
});

const buf = await Packer.toBuffer(doc);
fs.mkdirSync(path.dirname(OUT), { recursive: true });

/*
 * Word holds an exclusive lock on an open document, so regenerating while the
 * reader has it open fails with EBUSY. Writing beside it is better than either
 * closing someone's window or losing the run: the document still gets produced,
 * and the operator is told exactly which file to open.
 */
function writeDoc(target: string): string {
  try {
    fs.writeFileSync(target, buf);
    return target;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EBUSY") throw err;
    const alt = target.replace(/\.docx$/, `-${new Date().toISOString().slice(11, 16).replace(":", "")}.docx`);
    fs.writeFileSync(alt, buf);
    console.warn(`${target} is open in Word and locked — wrote ${alt} instead.`);
    return alt;
  }
}

const written = writeDoc(OUT);
console.log(`Wrote ${written} (${(buf.length / 1024 / 1024).toFixed(2)} MB, ${body.length} blocks)`);
