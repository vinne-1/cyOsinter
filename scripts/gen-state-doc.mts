/**
 * Generates the Cyshield CURRENT STATE report DOCX.
 *
 * Screenshots come from `scripts/capture-ui.mjs`, which captures the RUNNING
 * app against real seeded data, so every image in the document is the product
 * as it actually stands rather than a mockup.
 *
 *   node scripts/capture-ui.mjs --theme dark
 *   npx tsx scripts/gen-state-doc.mts
 */
import {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ImageRun, PageBreak,
  ShadingType, convertInchesToTwip,
} from "docx";
import fs from "fs";
import path from "path";

const SHOTS = "docs/screenshots";
const OUT = "docs/Cyshield-Current-State.docx";

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
const add = (...items: (Paragraph | Table)[]) => body.push(...items);
// ═══════════════════════════════════════════════════════════════════════════
// Title
// ═══════════════════════════════════════════════════════════════════════════
add(
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 1600, after: 60 },
    children: [t("Cyshield Pro", { bold: true, size: 56, color: BRAND })],
  }),
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 200 },
    children: [t("Current State Report", { size: 32, color: INK })],
  }),
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 1200 },
    children: [t("Self-hosted External Attack Surface Management and OSINT platform", { italics: true, size: 21, color: GREY })],
  }),
  p("Every figure in this document is a screenshot of the running application against real scan data — not a mockup. Every number is measured, and where something could not be measured this document says so rather than estimating.", { align: AlignmentType.CENTER, color: GREY }),
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 400 },
    children: [t("Generated 2 September 2026", { size: 19, color: GREY })],
  }),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("1  Where the product stands"),

  p("Cyshield Pro discovers an organisation's internet-facing estate, tests it, and turns what it finds into triaged work. It is self-hosted: the scan data never leaves the operator's infrastructure, which is the main structural difference from every commercial platform it competes with."),

  h2("At a glance"),
  table(
    ["Dimension", "State"],
    [
      ["Scanner modules", "56 modules under server/scanner/"],
      ["Unit tests", "1,417 across 86 files — all passing"],
      ["End-to-end tests", "17 Playwright tests including a full accessibility sweep"],
      ["Accessibility", "axe-core WCAG 2.1 A/AA: zero serious or critical across 27 routes and every tab"],
      ["Type safety", "tsc --noEmit clean"],
      ["Production build", "Builds and boots; verified serving traffic from dist/"],
      ["Dependency posture", "0 high, 0 critical advisories (npm audit gates CI at high)"],
      ["Container", "Runs unprivileged as uid 1000; CI asserts it"],
      ["OWASP ASVS 5.0", "All 70 Level 1 requirements assessed: 58 pass, 9 N/A, 3 operator-provided, 0 fail"],
      ["Measured false positives", "0 of 11 independently verified findings, after one root cause was fixed"],
    ],
    [30, 70],
  ),

  h2("What it does, in one paragraph"),
  p("It finds hosts an organisation may not know it owns — through certificate transparency, wordlists, nine passive indexes, three keyed datasets, permutation of the organisation's own naming convention, certificate subject-alternative names, and BGP-announced address space. It then probes what it found, tests it, and refuses to report anything it cannot reproduce. Findings are attributed to the specific host they were observed on, mapped to compliance controls, given a remediation deadline, and grouped into cases."),

  callout(
    "The design principle everything else follows from",
    "A finding that cannot be reproduced is not reported. Three gates stand between a response and a claim: an oracle that calibrates each host's not-found behaviour so a soft-404 cannot be mistaken for a discovery, a signature layer that requires positive proof a response IS the artefact being named, and a verification gate that re-probes at report time and withholds anything it cannot reproduce. Anything withheld is recorded as withheld, so “we looked and could not confirm” never renders identically to “we never looked”.",
  ),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("2  The product as it runs today"),
  p("Each figure below is the live application. Numbered callouts are drawn into the DOM before capture, so they point at real elements rather than annotations added afterwards.", { color: GREY }),

  h2("2.1  Security overview"),
  ...figure("01-dashboard.png", "Dashboard — posture, findings and intelligence for the selected workspace.", [
    "The **posture score with severity bands**. A workspace with 26 open findings and no criticals scores 85 (Grade B). An earlier linear formula scored an identical workspace **0/100**, because 27 medium findings alone floored it — volume of one repeated misconfiguration was being counted as 27 independent problems.",
    "**Findings triage** is the operational centre of the product: observations become work here.",
  ]),

  h2("2.2  Attack surface"),
  ...figure("02-easm.png", "EASM — discovery and scan control for the estate.", [
    "Discovery runs **seven independent methods** and records which ones named each host. Corroboration across independent sources is the cheapest quality signal available, and it is kept rather than flattened into a count.",
  ]),

  h2("2.3  OSINT discovery"),
  ...figure("03-osint.png", "OSINT — passive intelligence about the organisation and its people.", [
    "Every source here is **keyless by default**. Sources that fail are recorded as failed, never as sources that found nothing.",
  ]),

  h2("2.4  Finding triage"),
  ...figure("04-findings.png", "Findings inbox — severity, status, ownership and SLA.", [
    "Only findings of kind **security** reach this inbox. A control that is correctly in place is good news and does not belong in a work queue; recon is context. Deducting for a control being present would score a well-configured domain below an empty one.",
  ]),

  h2("2.5  Cases"),
  ...figure("05-cases.png", "Cases — the unit of work, distinct from the unit of observation.", [
    "A finding is an **observation**; a case is the **work**. One piece of work routinely spans several findings, so the link is a join table rather than a column. Raising a case's severity re-derives its deadline from the original creation time, so it tightens rather than granting a fresh window.",
  ]),

  h2("2.6  Attack paths"),
  ...figure("06-attack-paths.png", "Attack paths — how individual findings chain into a route."),

  h2("2.7  Asset risk"),
  ...figure("07-asset-risk.png", "Asset risk — per-host scoring across the inventory."),
  rich("This page previously reported **0.0 for 262 of 263 assets**. The scoring engine was correct; nothing it consumed was attributable. A Gold scan already fetched each live subdomain's certificate, graded its headers and recorded its banner — and every resulting finding was attributed to the apex domain, so nothing could be joined to a host. Findings are now attributed to the host they were observed on."),

  h2("2.8  Compliance"),
  ...figure("08-compliance.png", "Compliance — findings mapped to OWASP, CIS and NIST controls."),
  rich("A live workspace once showed **nine of ten OWASP controls as “No Data” while holding 31 open findings**, because 27 of them were `cookie_security` and no such key existed in the mapping. “No Data” reads to a reader as “probably fine”, which is strictly worse than reporting the failure. A build-time test now asserts every category the engine can emit is mapped to controls that exist."),

  h2("2.9  Brand threats"),
  ...figure("09-brand-threats.png", "Brand threats — lookalike domains, leak-site exposure, exposed code and app-store monitoring."),
  rich("The **mobile app panel** is new. It searches the Apple App Store for apps published under the organisation's brand and confirms which are genuinely theirs from the developer's own listed website. It never calls an app fake: payment integrations, resellers and partner clients legitimately carry another company's brand."),

  h2("2.10  Intelligence modules"),
  ...figure("10-intelligence.png", "Intelligence — DNS, mail transport, TLS, routed footprint and discovery health."),

  h2("2.11  Reporting"),
  ...figure("11-reports.png", "Reports — evidence-backed export."),

  h2("2.12  Integrations"),
  ...figure("12-integrations.png", "Integrations — optional API keys and outbound destinations."),

  h2("2.13  Scheduled scans"),
  ...figure("13-scheduled-scans.png", "Scheduled scans — recurring coverage."),

  h2("2.14  Audit log"),
  ...figure("14-audit-log.png", "Audit log — every state-changing request, attributed."),
  rich("Roughly **46% of this log was unnamed** until recently. The middleware read the request path inside the response-finished handler, by which time Express had rewritten it for whichever sub-router answered — so “who deleted this workspace” had no answer. The historical rows are deliberately left as they are: an audit log is evidence, and retroactively rewriting it is the one thing it must never do."),

  h2("2.15  Trends, AI insights and threat intel"),
  ...figure("15-trends.png", "Trends — posture over time."),
  ...figure("16-ai-insights.png", "AI insights — local LLM enrichment via Ollama."),
  ...figure("17-threat-intel.png", "Threat intelligence — external context for observed infrastructure."),

  h2("2.16  Access and account security"),
  ...figure("18-api-keys.png", "API keys — scoped credentials for automation."),
  rich("Key scope is now **enforced**. It was validated on create, stored, returned by the list endpoint and rendered as a coloured badge — and checked by nothing, so a key an operator created as “read” could delete workspaces. A product that displays a restriction it does not apply is worse than one with no scopes at all."),
  ...figure("19-account.png", "Account security — password change and session revocation."),
  rich("This page did not exist. There was **no way to change a password anywhere in the product**, so a user who believed their password was compromised had no way to rotate it. Changing it now revokes every other session and issues the caller a fresh token."),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("3  Engine and architecture"),

  h2("3.1  Stack"),
  table(
    ["Layer", "Technology"],
    [
      ["Backend", "Express + TypeScript on Node (ESM)"],
      ["Database", "PostgreSQL via Drizzle ORM"],
      ["Frontend", "React + Vite + Tailwind + shadcn/ui"],
      ["Auth", "Session tokens (SHA-256 hashed at rest), TOTP, OIDC SSO"],
      ["Scanner", "56 modules; optional delegation to nuclei, httpx, katana when installed"],
      ["AI", "Ollama, local — no prompt or finding leaves the deployment"],
      ["Queue", "Durable Postgres queue with FOR UPDATE SKIP LOCKED"],
    ],
    [26, 74],
  ),

  h2("3.2  Discovery"),
  p("Seven methods run, and each host carries provenance recording which of them named it:"),
  bullet("Certificate transparency (crt.sh and Certspotter)"),
  bullet("A 2,258-entry wordlist brute-force, wildcard-filtered"),
  bullet("Nine keyless passive indexes, plus three keyed datasets when configured"),
  bullet("Permutation of the organisation's own naming convention — the only method that learns from the target rather than guessing from a fixed list"),
  bullet("Certificate subject-alternative names read from the live handshake"),
  bullet("BGP-announced address space, behind an attribution gate that refuses by default"),
  bullet("Reverse DNS and reverse-IP co-hosting"),
  rich("Discovery resolves **A, AAAA and CNAME**. It queried only A and CNAME until recently, so a host published solely on IPv6 resolved to nothing and was discarded as non-existent — an entire class of asset was invisible."),

  h2("3.3  Detection"),
  p("Beyond the standard surface (ports, TLS versions actually accepted, DNS and mail security, security headers, cookies, HTTP methods, CORS, GraphQL introspection, cloud storage, container endpoints, secrets), the engine also covers:"),
  bullet("Known vulnerabilities in the client-side libraries a site actually serves, checked against OSV.dev"),
  bullet("Dependency confusion — internal package names nobody owns on npm or PyPI"),
  bullet("Content-Security-Policy content rather than presence, aware of nonces and strict-dynamic"),
  bullet("Subdomain takeover, distinguishing a claimable target from a merely broken record"),
  bullet("Lookalike domains, ransomware leak-site exposure, public code leaks, app-store brand use"),

  h2("3.4  Security architecture"),
  table(
    ["Control", "Implementation"],
    [
      ["Tenant isolation", "Membership checked on every workspace-scoped route; non-members receive 404, never 403, so resource existence is not disclosed"],
      ["SSRF", "Single DNS-resolving, fail-closed guard checking both A and AAAA; redirects are not followed blindly"],
      ["Audit", "Every state-changing request recorded at one choke point, resolved from the URL Express never rewrites"],
      ["Sessions", "Hashed at rest; refresh rotation with reuse detection that revokes the whole chain"],
      ["Passwords", "12-character minimum, no composition rules, screened against 5,000 known-common passwords that would otherwise pass the length rule"],
      ["API keys", "Scope enforced at the /api choke point; no key may manage keys at any scope"],
      ["Rate limits", "Sensitive limiters share a Postgres-backed counter so the budget is not multiplied by replica count"],
      ["Egress", "SIEM export in ECS and CEF; outbound webhooks; both hang off the single event choke point"],
    ],
    [22, 78],
  ),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("4  Evidence of quality"),

  h2("4.1  Measured against an external standard"),
  rich("**OWASP ASVS 5.0.0**, all 70 Level 1 requirements assessed individually with a code reference (`docs/asvs-5.0-conformance.md`):"),
  table(
    ["Verdict", "Count", "Meaning"],
    [
      ["Pass", "58", "A specific control was located and, where observable, exercised"],
      ["Not applicable", "9", "The requirement addresses a feature this application does not have, reason stated"],
      ["Operator-provided", "3", "Real control, but it lives in the deployment (TLS termination)"],
      ["Fail", "0", "—"],
    ],
    [24, 12, 64],
  ),
  p("Five of those passes were failures when the assessment began. The most serious was that no password change existed anywhere in the product."),
  rich("Level 2 (253 cumulative requirements) is **deliberately not claimed**. Much of it is already in place, but publishing a level without a requirement-by-requirement assessment would be the same category of error the product keeps finding in itself: a claim asserted but not performed."),

  h2("4.2  Detection accuracy, measured"),
  p("The industry advertises a false-positive rate below 1%. Rather than scan something new and grade its own homework, the findings already in the database from real scans were audited against live ground truth — DNS resolved directly, headers fetched with curl, certificates read with openssl."),
  table(
    ["Verdict", "Count", "Detail"],
    [
      ["Confirmed true", "8", "3× missing DMARC, missing SPF on a non-mail subdomain, 3× header/CSP, 1× weak HSTS"],
      ["False positive", "2", "Single root cause — the SPF terminator check did not follow redirect=. Fixed"],
      ["Not reproducible", "1", "Recorded as indeterminate rather than counted either way"],
    ],
    [22, 12, 66],
  ),
  rich("Eleven findings is a **sample, not a corpus rate**, and the document says so rather than extrapolating a headline number. Two results are worth keeping: a remediated finding is not a false positive (a certificate-expiry finding from 11 August was renewed on 27 August), and one true positive exists purely because of structural validation — a host with wildcard DNS answers every name, and the scanner correctly refused to count a wildcard TXT record as a DMARC policy."),

  h2("4.3  Quality gates"),
  p("All three must pass before any change is considered done:"),
  bullet("tsc --noEmit — zero type errors"),
  bullet("1,417 unit tests across 86 files"),
  bullet("17 Playwright end-to-end tests, including an accessibility sweep that activates every tab on every route"),
  p("The accessibility sweep is not decorative: it found two real defects living in intelligence panels it had never rendered, because tabbed content mounts one panel at a time and visiting a route only ever measured the default tab."),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("5  Competitive position"),

  h2("5.1  Against the reference points"),
  table(
    ["Capability", "Cyshield", "Note"],
    [
      ["Asset discovery breadth", "Strong", "Seven methods with per-host provenance; broader than most after permutation, SANs and keyed datasets"],
      ["Evidence discipline", "Ahead", "Censys ASM is described in buyer's guides as “a strong input, not a standalone program” because it performs no validation"],
      ["Web application testing", "Comparable", "Crawler-fed DAST plus nuclei; Detectify leads on crowdsourced payloads"],
      ["Vulnerable components", "Comparable", "OSV-backed library CVEs and dependency confusion"],
      ["Brand protection", "Partial", "Lookalike domains, leak sites, exposed code, iOS app store; no social monitoring"],
      ["Dark web", "Absent", "A deliberate decision, not a technical limit — see section 6"],
      ["Internet-scale data", "Absent", "Cannot be replicated without internet-wide scanning infrastructure"],
      ["Data sovereignty", "Ahead", "Self-hosted; scan data never leaves the operator"],
    ],
    [24, 14, 62],
  ),

  h2("5.2  The honest summary"),
  p("Against CloudSEK XVigil the gap is breadth of intelligence sourcing, not engine quality: XVigil aggregates deep-web and dark-web sources this product deliberately does not touch. Against Censys and Cortex Xpanse the gap is internet-scale data, and the advantage is validation — they supply observations, this supplies verified findings. Against Detectify the gap is a researcher community, and the overlap is the largest."),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("6  Blockers, and exactly what clears each"),
  p("Every item below was tested rather than assumed. Each row states what is blocked, what specifically blocks it, and what would clear it.", { color: GREY }),

  h2("6.1  Blocked by cost or infrastructure"),
  table(
    ["Blocked", "Why", "What clears it"],
    [
      [
        "Favicon-hash and certificate pivoting — “find every host on the internet serving this”",
        "Needs an internet-wide scan index. The Shodan key supplied is the free “oss” plan: host lookup works, but /shodan/host/search returns 403 “requires membership”",
        "A paid Shodan membership, or Censys/FOFA credits. The hash itself is already computed and displayed, so an operator can paste it into Shodan today",
      ],
      [
        "Internet-scale asset discovery from the outside in",
        "Cortex Xpanse scans ~500 billion ports daily; that is capital, not code",
        "Not clearable at this scale. The mitigation already in place is breadth of free sources plus permutation, which finds hosts no index has",
      ],
      [
        "Crowdsourced exploit payloads",
        "Detectify's edge is an ethical-hacker community submitting unpublished payloads",
        "Not clearable by code. Nuclei templates are the open equivalent and are public by definition",
      ],
      [
        "Cross-customer threat intelligence",
        "Structural: SaaS vendors see every customer's data; a self-hosted deployment sees one estate",
        "Not clearable without abandoning self-hosting — which is the product's main differentiator",
      ],
    ],
    [26, 36, 38],
  ),

  h2("6.2  Blocked by a credential, and cheap to clear"),
  table(
    ["Blocked", "Why", "What clears it"],
    [
      [
        "Breached-account lookups for the organisation's email addresses",
        "HaveIBeenPwned's account API requires a paid key. The password API (k-anonymity) is free and already used",
        "A HIBP subscription (~$4/month) plus a small collector; the existing OSINT email module is the natural home",
      ],
      [
        "Shodan search-based enrichment",
        "Free plan permits host lookup only",
        "A Shodan membership. Host lookup, DNS resolve and reverse DNS already work on the supplied key",
      ],
    ],
    [26, 36, 38],
  ),

  h2("6.3  Blocked by platform policy"),
  table(
    ["Blocked", "Why", "What clears it"],
    [
      [
        "Google Play / Android app monitoring",
        "No free official search API. Scraping the store is fragile and against its terms",
        "A commercial store-intelligence feed. The iOS side is covered and the report states plainly that Android was not checked",
      ],
      [
        "Social media and executive impersonation monitoring",
        "X, LinkedIn and Meta have removed or paywalled search access",
        "Paid platform API access, or a commercial digital-risk feed",
      ],
    ],
    [26, 36, 38],
  ),

  h2("6.4  Blocked by data availability"),
  table(
    ["Blocked", "Why", "What clears it"],
    [
      [
        "Entity model — discovering subsidiaries and recent acquisitions",
        "Tested: RDAP was unreachable and registrant organisation is GDPR-redacted for most domains; crt.sh organisation search depends on the O field that modern DV certificates do not carry",
        "A commercial corporate-registry or WHOIS-history dataset. Worth noting this is also Cortex Xpanse's own documented weakness — nobody solves it cheaply",
      ],
    ],
    [26, 36, 38],
  ),

  h2("6.5  Blocked technically in this stack"),
  table(
    ["Blocked", "Why", "What clears it"],
    [
      [
        "JARM / TLS-stack fingerprinting of targets",
        "JARM's ten probes depend on exact TLS extension ordering and GREASE values. Node's tls module exposes ciphers, versions, ALPN and sigalgs but cannot craft that ClientHello",
        "A hand-rolled ClientHello over a raw socket, or a native TLS binding. Deliberately not attempted: a hash that does not match the published JARM corpus is worthless, because comparability is the entire point",
      ],
    ],
    [26, 36, 38],
  ),

  h2("6.6  Declined rather than blocked"),
  callout(
    "Dark web and infostealer monitoring",
    "This is CloudSEK XVigil's headline module — 500+ sources spanning Tor forums, paste sites, leaked-data marketplaces and encrypted channels. It is technically reachable, but it requires Tor infrastructure, frequently vetted forum membership, and it carries real legal exposure that is a business decision rather than an engineering one. It is therefore recorded as declined, not as missing. The adjacent slice that can be done cleanly is already done: ransomware leak-site exposure is checked against the public ransomware.live corpus without touching Tor, and the module never fetches the .onion URLs it reports.",
  ),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("7  API keys — tested status"),
  p("Each supplied key was tested against its provider on 2 September 2026. Keys are held in a gitignored environment file and never enter the repository.", { color: GREY }),

  table(
    ["Provider", "Status", "What it enables here"],
    [
      ["GitHub", "Working", "Public-repo code search. Unblocks exposed-code monitoring, which previously returned “not configured” rather than a false clean result"],
      ["ProjectDiscovery Chaos", "Working", "Largest single discovery gain measured: 47,691 hosts for one target, 45,843 of them found by no other source"],
      ["SecurityTrails", "Working", "2,000 hosts on the same target, 357 unique to it"],
      ["BeVigil", "Working", "Hostnames extracted from published mobile apps — 8 hosts no other source had, because an endpoint hardcoded in an APK appears in no certificate or crawl"],
      ["SSLMate / Certspotter", "Working", "Raises the rate limit on a CT source already used keylessly"],
      ["VirusTotal", "Working", "IP and domain reputation enrichment"],
      ["Shodan", "Working, limited", "Free “oss” plan: host lookup, DNS resolve and reverse DNS work; search returns 403"],
      ["Robtex", "Working (keyless)", "The free API needs no key at all"],
      ["urlscan", "Dead", "401 — “API key supplied but not found in database”. The keyless urlscan source still works"],
      ["GitHub (second token)", "Dead", "401. The first GitHub token works and is the one in use"],
    ],
    [22, 16, 62],
  ),

  h2("7.1  Measured effect of the working keys"),
  rich("Aggregated passive discovery for a single large target went from roughly **169 hosts to 48,063** — about a 284× increase in breadth. That gain forced two fixes, because the previous code was written when “all discovered hosts” meant a few hundred:"),
  bullet("The Gold profile probed every discovered host with no ceiling. It now has a finite budget and records when discovery outran it, so a reader can tell a small estate from a truncated look at a large one."),
  bullet("Deduplication used Array.includes inside a loop — O(n²), which at 48,000 hosts against 15,000 permutation candidates is on the order of 10⁸ comparisons. It now uses a set."),

  callout(
    "One security note on the credentials supplied",
    "The working GitHub token carries admin:org, delete_repo, repo, workflow and admin:enterprise scopes — effectively full account control. Public-repo code search needs NO scopes at all. Because these credentials were transmitted in plaintext, the safe course is to revoke them and issue a replacement fine-grained token with no scopes for this purpose. Nothing in this product needs more than that.",
  ),
  pageBreak(),
);

// ═══════════════════════════════════════════════════════════════════════════
add(
  h1("8  What would move the product furthest next"),
  p("Ordered by value per unit of effort, and limited to work that is actually unblocked:"),
  table(
    ["Priority", "Work", "Why it matters"],
    [
      ["1", "Assess and claim OWASP ASVS Level 2", "Much of it is already implemented; the missing part is the assessment, not the code. It is the clearest external credential available"],
      ["2", "Continuous monitoring on a schedule with change alerting", "Discovery is strong and change detection is now a genuine three-state signal; the remaining step is making it run unattended and notify"],
      ["3", "Broaden the accuracy audit beyond eleven findings", "The 0-false-positive result is real but drawn from a small sample; a larger corpus turns it into a defensible published number"],
      ["4", "Android coverage via a commercial store feed", "The iOS half is built and the interface generalises; only the data source is missing"],
      ["5", "Finish wiring or remove the remaining vestigial paths", "Finding workflowState is unreachable by any route and PCI/SOC-2 guidance is unwired; both are documented decisions today, but decisions age"],
    ],
    [10, 34, 56],
  ),

  h2("Appendix A  Reproducing everything in this document"),
  mono([
    "docker compose up -d db",
    "npm run db:push",
    "PORT=5050 npm run dev",
    "npx tsc --noEmit          # zero errors",
    "npm test                  # 1,417 tests / 86 files",
    "npx playwright test       # 17 e2e, incl. accessibility sweep",
    "node scripts/capture-ui.mjs --theme dark --out docs/screenshots",
    "npx tsx scripts/gen-state-doc.mts",
  ]),
  p("The capture script signs in, selects the workspace holding the most findings, draws the numbered callouts into the live DOM and screenshots at 2× device scale — so regenerating this document after a UI change keeps every figure current.", { color: GREY }),

  h2("Appendix B  Supporting documents in the repository"),
  bullet("docs/asvs-5.0-conformance.md — all 70 ASVS Level 1 requirements with a code reference each"),
  bullet("docs/detection-accuracy.md — the false-positive audit method and per-finding verdicts"),
  bullet("CLAUDE.md — the engineering record: every non-obvious decision, with the failure that motivated it"),
);

// ═══════════════════════════════════════════════════════════════════════════
const doc = new Document({
  creator: "Cyshield Pro",
  title: "Cyshield Pro — Current State Report",
  styles: { default: { document: { run: { font: "Segoe UI", size: 21, color: INK } } } },
  sections: [{
    properties: { page: { margin: { top: 1000, right: 1000, bottom: 1000, left: 1000 } } },
    children: body,
  }],
});

const buf = await Packer.toBuffer(doc);
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, buf);
console.log(`Wrote ${OUT} (${(buf.length / 1024 / 1024).toFixed(2)} MB, ${body.length} blocks)`);
