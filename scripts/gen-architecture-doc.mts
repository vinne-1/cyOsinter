/**
 * Generates the Cyshield architecture, competitive-position and roadmap DOCX.
 *
 * Screenshots come from `scripts/capture-ui.mjs`, which captures the RUNNING
 * app against real seeded data, so every image in the document is the product
 * as it actually stands rather than a mockup.
 *
 *   node scripts/capture-ui.mjs --theme dark
 *   npx tsx scripts/gen-architecture-doc.mts
 */
import {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ImageRun, PageBreak,
  ShadingType, convertInchesToTwip,
} from "docx";
import fs from "fs";
import path from "path";

const SHOTS = "docs/screenshots";
const OUT = "docs/Cyshield-Architecture-Competitive-Roadmap.docx";

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

// ── cover ──────────────────────────────────────────────────────────────────
add(
  new Paragraph({ spacing: { before: 2600, after: 0 }, children: [t("CYSHIELD PRO", { bold: true, size: 26, color: BRAND })] }),
  new Paragraph({ spacing: { after: 80 }, children: [t("Architecture, Competitive Position and Roadmap", { bold: true, size: 52, color: INK })] }),
  new Paragraph({
    spacing: { after: 400 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: ACCENT, space: 10 } },
    children: [t("A self-hosted External Attack Surface Management and OSINT platform", { size: 24, color: GREY })],
  }),
  p("What the system is today, how it is built, how it stands against the commercial digital-risk and EASM platforms it competes with, and the path from here to a product that beats them on the dimension that matters most.", { size: 22, color: GREY, after: 600 }),
  table(
    ["", ""],
    [
      ["Repository", "cyOsinter (Cyshield Pro)"],
      ["Document date", new Date().toISOString().slice(0, 10)],
      ["Codebase", "~51,000 lines TypeScript · 47 scanner modules · 28 UI pages · 112 API endpoints · 24 tables"],
      ["Test suite", "1,008 unit tests (60 files) · 17 Playwright E2E · axe WCAG 2.1 AA at zero serious/critical"],
      ["Screenshots", "Captured from the running application against live scan data, not mockups"],
    ],
    [2600, 6400],
    { noHeader: true },
  ),
  pageBreak(),
);

// ── 1. executive summary ───────────────────────────────────────────────────
add(
  h1("1  Executive Summary"),

  p("Cyshield Pro is a self-hosted External Attack Surface Management (EASM) and OSINT platform. A user registers a domain, triggers a scan, and receives security findings — subdomains, exposed services, TLS and DNS weaknesses, leaked secrets, cloud storage exposure, brand and ransomware intelligence — in a multi-tenant web dashboard with case management, SLA tracking, compliance mapping and report export."),

  p("It is a genuinely substantial system. The scanner alone is 47 modules and ~13,800 lines; the application layer adds workspace isolation, an audit trail on every mutation, durable scan queueing with a cross-instance concurrency gate, TOTP-based MFA with refresh-token reuse detection, and a report pipeline that produces client-ready DOCX and Excel output. The dashboard is a deliberately designed bento grid rather than a card wall, and the whole surface measures zero serious or critical accessibility violations across 26 routes."),

  h2("The strategic position"),

  p("The market Cyshield sits in has two established camps and a large open-source hinterland:"),
  bullet("**Digital Risk Protection** platforms — CloudSEK XVigil, Group-IB, Recorded Future — which lead with breadth: dark web, brand abuse, leaked credentials, ransomware intelligence, usually wrapped in a managed-analyst service."),
  bullet("**EASM platforms** — Microsoft Defender EASM, Palo Alto Cortex Xpanse, Censys ASM, Detectify, Bitsight, SecurityScorecard — which lead with discovery scale and continuous inventory of internet-facing assets."),
  bullet("**Open-source recon stacks** — Amass, the ProjectDiscovery suite (subfinder, httpx, nuclei), SpiderFoot, reconFTW — which lead on cost and control, and lose on workflow, persistence and reporting."),

  p("Cyshield is architecturally a hybrid: it has the workflow and multi-tenancy of a commercial platform with the data sovereignty and zero-marginal-cost collection of the open-source stack. That combination is real and defensible. What it does not yet have is the data assets — dark web collection, infostealer log corpora, a global internet-wide scan index — that the incumbents spent years and considerable money building."),

  callout(
    "The differentiator worth building the product around",
    "Every platform in this market has a false-positive problem, and every one of them handles it with severity tuning and analyst review. Cyshield now handles it **structurally**: no finding reaches the database unless a live probe reproduced it, the response was proven distinguishable from the host's catch-all page, and the body was confirmed to be the artefact the finding names. That is a defensible product claim — **evidence-grade findings** — and it is worth more than matching competitors module for module.",
  ),

  h2("Honest current state"),

  table(
    ["Dimension", "Status", "Assessment"],
    [
      ["Discovery breadth", "**Strong**", "47 modules covering DNS, TLS, ports, subdomain enumeration, cloud storage, containers, APIs, mail transport, CT logs, wayback, typosquats"],
      ["Finding precision", "**Strong (newly)**", "Three-gate evidence pipeline; the largest false-positive classes were removed rather than tuned down"],
      ["Workflow & multi-tenancy", "**Strong**", "Workspaces, roles, cases with SLA, audit trail, API keys, webhooks, scheduled scans"],
      ["Reporting", "**Good**", "DOCX/Excel/CSV export with evidence and screenshots; formula-injection safe"],
      ["Proprietary data assets", "**Absent**", "No dark web collection, no infostealer corpus, no internet-wide scan index — the incumbents' main moat"],
      ["Compliance depth", "**Thin**", "OWASP/CIS/NIST frames exist but most controls read 'No Data' because the taxonomy does not yet map to them"],
      ["Continuous monitoring", "**Partial**", "Scheduled scans and diffing exist; true change-detection alerting is shallow"],
      ["Deployment maturity", "**Moderate**", "Docker Compose, health probes, advisory-lock concurrency; no HA story, no managed offering"],
    ],
    [2100, 1500, 5400],
  ),

  pageBreak(),
);

// ── 2. the product today ───────────────────────────────────────────────────
add(
  h1("2  The Product Today"),
  p("Every screenshot in this section was captured from the running application against a real completed scan of a live domain (263 discovered assets, 31 findings, two Gold-mode scans). Numbered markers are drawn onto the interface itself and explained beneath each figure.", { color: GREY }),

  h2("2.1  Executive dashboard"),
  ...figure("01-dashboard.png", "Figure 1 — Security Overview. The bento grid, deliberately not a uniform card row.", [
    "**Posture score, severity-banded.** The score was once a flat linear deduction, and a workspace with zero critical, zero high and 27 medium findings scored 0/100 'Grade F'. It now applies diminishing returns (27 hosts missing one header is one misconfiguration with 27 instances) plus a floor and ceiling per worst-severity-present. The same workspace now reads 71, Grade C.",
    "**Workspace switcher.** Every API route below the auth gate checks workspace membership and returns 404 — not 403 — for a non-member, so the platform never leaks which workspaces exist.",
    "**Open findings.** Renders the server's real total rather than the array length. List endpoints page at 500 by default, so rendering `items.length` once reported '500' for a workspace holding 1,067 assets.",
  ]),
  p("The layout is a bento grid: 4 columns desktop, 2 tablet, 1 mobile, with the cell arithmetic closing exactly so no row is part-filled. Tile size carries hierarchy — the documented failure mode for dense dashboards is a rigid grid of equal cards where every metric gets identical visual weight and the layout tells the reader nothing."),

  pageBreak(),
  h2("2.2  Attack surface"),
  ...figure("02-easm.png", "Figure 2 — External attack surface for a live target: 90 subdomains, 130 IPs, 41 services.", [
    "**Scan trigger.** Execution is gated on a Postgres advisory lock rather than an in-process counter. The lock dies with the database session, so a crashed worker frees its slot with no lease table and no reconciliation job. `SCAN_CONCURRENCY` is a deployment-wide limit, not a per-instance one.",
  ]),
  p("The asset inventory is the system of record: every discovered subdomain, IP, service and certificate is persisted with a first-seen timestamp and provenance tag, so the diff between two scans is a real answer to 'what changed', not a re-derivation."),

  pageBreak(),
  h2("2.3  Finding triage"),
  ...figure("04-findings.png", "Figure 3 — Findings inbox with severity facets and lifecycle state.", [
    "**Search and facets.** The 'Security issues' filter is the `kind` dimension: findings are classified security, control or recon, and only `security` reaches this inbox. A control being in place is good news — deducting for it would score a well-configured domain below an empty one.",
  ]),
  callout(
    "What this screenshot honestly shows",
    "The visible run of nine separate \"Insecure Cookie: <name>\" findings is **stored data from a scan run three weeks ago**, before per-host aggregation landed. The current `checkCookieSecurity` collapses these into one finding per host with every instance preserved as structured evidence — one misconfiguration with 27 instances, not 27 findings. The rows above are exactly the failure this document argues the engine had to fix, still visible because historical findings were never rewritten. **Backfilling them is a Phase 1 item.**",
  ),

  pageBreak(),
  h2("2.4  Intelligence modules"),
  ...figure("10-intelligence.png", "Figure 4 — Fourteen reconnaissance modules, each carrying its own confidence score."),
  p("Recon is separated from findings on purpose. A technology fact ('this host runs nginx') and a security verdict ('this host accepts TLS 1.0') are different kinds of statement, and merging them is the single biggest classification problem in a scanner of this type — it inflates the finding count, drags the posture score down for good news, and trains an analyst to skim past the inbox."),
  p("Note the IP Reputation module at 0% confidence. That is the design working: a check that could not run reports that it did not run, rather than reporting a clean result. The same rule governs the DNSSEC check (`unverifiable` is distinct from `unsigned`), the TLS version enumeration (`indeterminate` is distinct from the server refusing), and the code-leak watch (which returns an error and a 503 without a GitHub token rather than an empty result set, because 'no leaks found' and 'we never looked' must never render identically)."),

  pageBreak(),
  h2("2.5  Attack path analysis"),
  ...figure("06-attack-paths.png", "Figure 5 — Attack chains derived automatically from stored findings."),
  p("Chains are composed from findings by category, mapping reconnaissance-grade weaknesses to the exploitation stage they enable. This is currently a rule-based composition over a small number of chain templates; it is genuinely useful and genuinely shallow, and Section 5 treats deepening it as a Phase 2 item."),

  pageBreak(),
  h2("2.6  Brand and dark-web monitoring"),
  ...figure("09-brand-threats.png", "Figure 6 — Brand threats: typosquat sweeps, ransomware leak-site exposure, source-code leak monitoring."),
  rich("This screen is the clearest expression of a rule the whole engine follows: **never report 'clean' for a check that did not run.** The source-code leak panel says \"Not configured — this check has not run\", names the missing `GITHUB_TOKEN`, and explains that the token is free and needs no scopes. The ransomware panel says \"Not checked yet\", not \"no exposure found\"."),
  p("This matters more than it looks. GitHub's code-search API has no unauthenticated form, so without a token the module returns an error and the API answers 503. Had it returned an empty result set instead, 'no leaks found' and 'we never looked' would render identically — and the second is the one that gets an organisation breached. The same discipline governs the DNSSEC check (`unverifiable` is a distinct state from `unsigned`), the TLS version enumeration (`indeterminate` is distinct from the server refusing), and the SPF external-reporter check (skipped without a resolver rather than assumed to fail)."),

  pageBreak(),
  h2("2.7  Compliance mapping"),
  ...figure("08-compliance.png", "Figure 7 — OWASP Top 10, CIS Controls v8 and NIST CSF 2.0 mapping."),
  rich("This screen is included precisely because it shows a **real gap**. The framework structure is complete and the mapping engine works — A05 Security Misconfiguration correctly reads **Fail** against two findings — but nine of ten OWASP controls read **No Data**. That is not a rendering bug; it is the finding taxonomy not yet producing observations that map to those controls. A compliance view that mostly says 'No Data' is worse than honest: it invites the reader to conclude the controls pass. Section 5 treats this as a Phase 1 correctness item, not a Phase 3 feature."),

  pageBreak(),
  h2("2.8  Asset risk scoring — a defect this document surfaced"),
  ...figure("07-asset-risk.png", "Figure 8 — Asset Risk Scoring: 263 assets, every one scoring 0.0."),
  rich("Preparing this document surfaced a genuine defect. The asset-risk page reports **263 total assets, 0 critical risk, 0.0 average score**, and every row scores zero with an identical 'Critical Findings' top factor. The scoring engine in `server/asset-risk-scoring.ts` is fully implemented and correctly wired — the problem is upstream, in the data it consumes."),
  p("Querying the database directly confirms the cause: all 31 findings in this workspace carry `affected_asset = 'bigbasket.com'`, the apex domain. The asset inventory, meanwhile, holds 130 IPs, 90 subdomains, 41 services and 1 certificate. `findingsForAsset()` matches a finding to an asset by hostname, so it matches exactly one of 263 assets and every other asset scores zero by construction."),
  rich("The root cause is that most detectors record `affectedAsset` as the scan target rather than the specific host the observation was made on. Some modules already do the right thing — container detection attributes to the probed URL — but the OSINT and DAST modules attribute to the apex. **Per-asset risk, per-asset trending and any asset-level prioritisation are inert until finding attribution is host-specific.** This is now the first correctness item in Phase 1."),
  callout(
    "Why this is worth showing rather than hiding",
    "This is the exact failure mode the codebase's own documentation warns about: a feature that looks complete in the code and does nothing at runtime. Three others had already been found this way — the audit log with zero rows, the scan queue with no concurrency limit, and SLA due-dates on none of 126 findings. The lesson the team already wrote down — **before trusting any feature here, grep for a caller** — needs one addition: also check that the data the feature consumes is actually shaped the way it expects.",
  ),

  pageBreak(),
  h2("2.9  Reporting and operations"),
  ...figure("11-reports.png", "Figure 9 — Report generation with full evidence packs."),
  p("Reports are generated as DOCX and Excel with embedded screenshot evidence, redacted secrets and formula-injection protection on every exported cell. The generator is data-driven and deterministic: the same scan produces the same document, which is what makes a report defensible when a client's engineer disputes a finding."),
  p("Beyond these screens the platform also ships scheduled scans with cron expressions, webhook endpoints with encrypted secrets and HTTPS-only URLs, API keys with expiry and revocation, an admin audit-log viewer with action facets, scan comparison and diffing, finding groups, playbooks, and a trends view over posture snapshots.", { after: 220 }),

  pageBreak(),
);

// ── 3. architecture ────────────────────────────────────────────────────────
add(
  h1("3  Architecture"),

  h2("3.1  Stack and topology"),
  table(
    ["Layer", "Technology", "Notes"],
    [
      ["Frontend", "React 18 · TypeScript · Vite · Tailwind · shadcn/ui · wouter", "28 pages, React Query for server state, WebSocket for scan progress"],
      ["API", "Express · TypeScript · Node (ESM)", "112 endpoints across 30 route modules behind a single auth gate"],
      ["Database", "PostgreSQL 16 · Drizzle ORM", "24 tables; `server/storage.ts` is the only data-access surface"],
      ["Scanner", "47 in-process TypeScript modules + Nuclei", "DNS, TLS, ports, OSINT, DAST-lite, cloud, container, brand, dark-web watch"],
      ["Browser automation", "Playwright with a pluggable stealth engine", "Screenshot evidence; engine swappable via `CYSHIELD_BROWSER_ENGINE`"],
      ["AI", "Ollama (local LLM) via `server/ai-service.ts`", "Local by design — finding data never leaves the deployment"],
      ["Queue", "Postgres `scan_queue` with `FOR UPDATE SKIP LOCKED`", "Durable; survives restart, unlike the in-memory queue it replaced"],
      ["Packaging", "Docker Compose", "`/healthz` liveness, `/readyz` DB-backed readiness"],
    ],
    [1500, 3000, 4500],
  ),

  h2("3.2  Scan pipeline"),
  mono([
    "POST /api/scans",
    "  └─ triggerScan()            server/scan-trigger.ts",
    "       └─ enqueueScan()       server/scan-queue.ts   (durable, SKIP LOCKED)",
    "            └─ acquireSlot()  server/scan-slots.ts   (Postgres advisory lock)",
    "                 │                                    ← row stays `pending` until held",
    "                 └─ runEASMScan() | runOSINTScan()   server/scanner/",
    "                      ├─ calibrate(origin)           response-oracle.ts",
    "                      ├─ 47 detector modules",
    "                      ├─ runVerificationGate()       verification-gate.ts",
    "                      └─ storage.createFinding()     ← sets priority + SLA dueDate",
    "                           └─ WebSocket notify       server/notifications.ts",
  ]),
  p("Two properties of this pipeline are worth naming. First, the concurrency gate is a hard requirement, not a nicety: before it existed, N requests for N targets started N concurrent full scans, each fanning out hundreds of DNS and HTTP requests. Second, the SLA deadline is set inside `storage.createFinding` — at the choke point, never per call site — so a new detector cannot forget to set one."),

  h2("3.3  The evidence pipeline — the part that matters"),
  p("This is the architectural claim the product should be sold on, so it is worth stating precisely what was wrong and what replaced it."),
  rich("The engine treated **`status === 200` as proof that a path exists**. On a single-page app, a framework catch-all route, or any server with a custom 200 error page, that is simply false: the server answers `/.env`, `/api/v1/pods` and `/metrics` with `index.html`. The container detector therefore reported **\"Kubernetes Pods API Exposed Without Authentication\" at critical severity for a static marketing site**."),
  p("The defence that existed was a fingerprint string — body length plus the first hundred characters — compared with strict equality. Exact equality is the wrong test: real error pages embed a request id, a CSRF token, or the requested path, so the fingerprint differed on every request and the guard never fired on most real sites."),
  p("Three independent gates now stand between a response and a stored finding."),
  table(
    ["Gate", "Module", "Question it answers", "Failure mode it closes"],
    [
      ["1", "`response-oracle.ts`", "Does this path actually exist, or is this the host's catch-all?", "Probes random non-existent paths in the shapes detectors use (bare, `.json`, `.php`, trailing-slash), then judges by normalised-token Jaccard similarity rather than equality — the auto-calibration technique `ffuf` uses. Two samples per shape: a host whose own error page is unstable has that shape **dropped**, because similarity to one unstable sample would withhold genuine findings."],
      ["2", "`body-signatures.ts`", "Is the response the artefact we are about to name?", "No Prometheus finding without a Prometheus exposition; no Kubernetes finding without a Kubernetes API document. Predicates look for the structure the real artefact must have, never a keyword that could appear in prose."],
      ["3", "`verification-gate.ts`", "Is it still true, right now?", "Re-probes live before persistence. It previously accepted any live 2xx when a finding carried no content marker — so it rubber-stamped exactly the false positives it exists to catch. It now calibrates the origin and withholds anything indistinguishable from the not-found response."],
    ],
    [700, 1700, 2400, 4200],
  ),
  p("Gate 1 can be inconclusive — a host may be unreachable during calibration — and returns `unknown`, which is never treated as a pass. Gate 2 is load-bearing and never skipped: a detector is not permitted to name a technology it has not seen."),
  callout(
    "Measured result",
    "Against a live catch-all single-page application — the exact shape that produced the fabricated critical — three probes that previously produced findings (`/metrics`, `/.env`, `/actuator/env`) are now withheld, with both gates firing independently at 96–98% token overlap against the host's not-found page. **Three fabricated findings before; zero now.**",
  ),

  pageBreak(),
  h3("Credential detection: shape is not an issuer"),
  p("The second-largest false-positive source was the heuristic deciding whether a file contains credentials — which also decides whether a finding is escalated to critical. Two of its rules matched ordinary web content:"),
  bullet("A **bare UUID** was listed as a 'Heroku/generic API key'. Every request id, trace id, asset hash and framework key on the modern web is a UUID, so any HTML page counted as carrying credentials — escalating 'Exposed Environment File' from high to **critical, CVSS 9.8**."),
  bullet("**Any 20-character token with entropy ≥ 4.5**, anywhere in the document. Minified JavaScript, CSP nonces and cache-busting filenames all clear that bar."),
  p("The rewrite keeps three tiers of evidence: known key formats that identify themselves by issuer prefix and length; named assignments whose value is not a documentation placeholder (`.env.example` files are full of `API_KEY=your_api_key_here`); and entropy, which now applies only to the right-hand side of a secret-shaped key name, or to a lone token a caller has already isolated as a candidate — never to arbitrary tokens inside a document."),

  h3("Severity that matches what an attacker can do"),
  table(
    ["Finding", "Was", "Now", "Why"],
    [
      ["Dangling CNAME", "critical `subdomain_takeover`", "low `dns_misconfiguration` unless claimable", "A takeover needs the target to be claimable — a known multi-tenant service, or a registrable domain with no NS records. A broken record inside a zone somebody else still controls is hygiene."],
      ["`/health`, `/metrics`, `/status`", "high 'Debug endpoints exposed'", "`recon`, informational", "These are **supposed** to answer a load balancer unauthenticated. They were pooled with `/actuator/heapdump` into one high finding."],
      ["HTTP 401 / 403 on a probed path", "medium exposure", "informational", "A refusal is the access control working. Rated medium, the count scaled with the wordlist."],
      ["Guessed bucket name returns 403", "low, attributed to customer", "suppressed unless exact-name", "Every provider answers 403 for a bucket existing anywhere in the world, so `<domain>-dev` almost certainly exists — in a stranger's account."],
      ["`PATCH` advertised in `Allow`", "dangerous method", "not reported", "PATCH is the ordinary partial-update verb of every REST API."],
    ],
    [1800, 1800, 1900, 3500],
  ),

  h2("3.4  Security architecture"),
  table(
    ["Control", "Implementation"],
    [
      ["Authentication", "Session tokens; `sessions.token` and `refresh_token` store SHA-256 **hashes**, never the token itself. RFC 6238 TOTP MFA."],
      ["Refresh-token reuse detection", "A spent refresh row is kept rather than deleted, and `family_id` groups a login's rotation chain — replaying a spent token revokes the entire family."],
      ["Credential stuffing", "Per-account lockout via `failed_login_attempts` / `locked_until`, which an IP rate limit cannot provide against distributed attacks. Sensitive limiters use a Postgres-backed store so the budget is shared across instances."],
      ["Tenant isolation", "Every workspace-scoped route checks membership and returns **404, not 403**, so the platform never leaks which resources exist."],
      ["SSRF", "All outbound HTTP to user-controlled URLs (webhooks, Jira base URL, sitemap `<loc>`) passes `isPrivateHost()` — DNS-based and fail-closed."],
      ["Audit trail", "`auditMutations` is mounted at `/api` after the auth gate and records **every** successful non-GET request, so a new route is audited the moment it is mounted. `logAudit` never throws — a failed audit write must not break a request."],
      ["Secret handling at rest", "Stored integration secrets are encrypted (`server/crypto.ts`); secrets found during scanning are masked before storage, including bare issuer-shaped keys that a `name=value` redactor would pass through verbatim."],
      ["Error disclosure", "Route catch blocks return generic messages; `err.message` is never sent to a client. Full context is logged via pino."],
      ["Export safety", "CSV/Excel export applies formula-injection protection."],
      ["Dependencies", "`npm audit --audit-level=high` gates CI: 23 advisories (11 high) reduced to 6 moderate, 0 high."],
    ],
    [2400, 6600],
  ),

  h2("3.5  Quality gates"),
  mono([
    "npx tsc --noEmit       zero errors required",
    "npm test               1,008 unit tests / 60 files",
    "npx playwright test    17 E2E tests, incl. a full axe WCAG 2.1 A/AA sweep",
  ]),
  p("The accessibility sweep covers all 26 routes and must stay at zero serious or critical violations. Several token-level rules came out of it and are easy to regress — white text on the brand cyan measures 2.86:1 against a 4.5:1 requirement, so `--primary-foreground` is deliberately near-black. The E2E suite also has a teardown that deletes by ownership rather than by name, so a workspace with even one human member can never be caught by it."),

  pageBreak(),
);

// ── 4. competitive landscape ───────────────────────────────────────────────
add(
  h1("4  Competitive Position"),
  p("Comparisons below are based on publicly described capabilities and product positioning, not on hands-on evaluation of the commercial platforms. They are intended to locate Cyshield in the market, not to benchmark it.", { italics: true, color: GREY }),

  h2("4.1  CloudSEK XVigil — the closest reference point"),
  p("XVigil is a digital-risk-protection platform organised around monitoring modules that watch an organisation's external footprint and the underground economy around it: attack surface and infrastructure monitoring, brand abuse and fake-domain detection, data-leak and source-code-leak monitoring, credential and dark-web exposure, and ransomware intelligence. It is delivered as SaaS, typically alongside analyst services that triage and contextualise what the platform surfaces."),
  rich("Structurally, Cyshield already implements the same module **shape** for a meaningful subset of that surface. The difference is not architecture — it is the data behind the modules."),
  table(
    ["XVigil capability area", "Cyshield today", "Gap"],
    [
      ["Attack surface & infrastructure monitoring", "**Comparable.** 47 modules, subdomain enumeration, port and service discovery, TLS/DNS posture, cloud storage, container and API exposure", "Continuous re-scan cadence and change alerting are shallower"],
      ["Fake domain / typosquat detection", "**Present.** `typosquat.ts` generates lookalikes and confirms them by DNS; brand-threats page surfaces them", "No registrar/WHOIS-change feed, no content similarity scoring, no takedown workflow"],
      ["Source-code leak monitoring", "**Present.** `code-leak-watch.ts` searches public repositories for org identifiers and scans hits with the shared secret detector", "GitHub only; no GitLab/Bitbucket/paste sites; requires a user-supplied token"],
      ["Ransomware / dark web exposure", "**Partial.** `ransomware-watch.ts` correlates against the public ransomware.live leak-site corpus", "**No dark web collection.** No Tor crawling, no forum or marketplace access — this is the incumbents' deepest moat"],
      ["Leaked credential monitoring", "**Thin.** HIBP-style password checks only", "**No infostealer log corpus.** Stealer logs are how credential exposure is actually detected today"],
      ["Executive / VIP monitoring", "**Partial.** `people-osint.ts` finds public identities and infers email format", "No impersonation detection, no social account monitoring"],
      ["Managed analyst triage", "**Absent by design**", "Self-hosted product, not a service — a positioning choice, not a defect"],
    ],
    [2600, 3400, 3000],
  ),

  h2("4.2  The EASM field"),
  table(
    ["Platform", "Leads on", "Where Cyshield stands"],
    [
      ["Microsoft Defender EASM", "Discovery graph seeded from a large crawl index; Azure-native integration", "Behind on discovery scale; ahead on self-hosting and evidence transparency"],
      ["Palo Alto Cortex Xpanse", "Internet-wide continuous scanning; attribution confidence", "Behind on scan index; comparable on per-target depth"],
      ["Censys ASM", "Internet-wide certificate and host index as the discovery substrate", "Behind on index; uses public CT logs for the same purpose at lower fidelity"],
      ["Detectify", "Crowdsourced payload research feeding an active-scanning engine", "Comparable engine depth via Nuclei; behind on proprietary payload research"],
      ["Bitsight / SecurityScorecard", "Ratings, benchmarking, third-party/supply-chain portfolios", "**Absent.** No third-party portfolio monitoring, no comparative rating"],
    ],
    [2100, 3300, 3600],
  ),

  h2("4.3  The open-source stack it is built on and against"),
  p("Cyshield's collection layer is deliberately built from open methods — public CT logs, DNS over public resolvers, DoH for DNSSEC validation, AXFR probing, wayback harvesting, PGP key servers, WHOIS, Nuclei templates, the SecLists wordlists. This is the same substrate a competent operator would assemble from Amass, subfinder, httpx, nuclei and SpiderFoot."),
  p("The honest comparison is that a skilled engineer with reconFTW and a weekend gets similar raw collection. What they do not get is any of the following, all of which Cyshield has: persistent multi-tenant asset inventory with first-seen provenance; a finding lifecycle with SLA deadlines and case management; an audit trail; role-scoped access; report generation a client will accept; and — now — a verification layer that decides which of the raw collection results are worth a human's attention."),
  callout(
    "The competitive thesis in one sentence",
    "Cyshield does not win by collecting more than the incumbents — it cannot, without their data assets. It wins by being the platform whose findings **a reader can trust without re-verifying them**, self-hosted, on infrastructure the customer controls.",
  ),

  h2("4.4  Where it wins, ties and loses today"),
  table(
    ["", "Assessment"],
    [
      ["**Wins**", "Data sovereignty (fully self-hosted, local LLM, no telemetry). Evidence transparency — every finding carries a reproducible probe and a live re-verification stamp. Cost structure (no per-asset licensing). Auditability of the engine itself: the detection logic is readable, not a vendor black box."],
      ["**Ties**", "Per-target scan depth. Finding workflow, SLA and case management. Report quality. Multi-tenancy and RBAC."],
      ["**Loses**", "Dark web and infostealer data. Internet-wide discovery scale. Third-party/supply-chain portfolio risk. Managed analyst service. Compliance framework depth. Enterprise deployment maturity (HA, SSO/SAML, SIEM-native integration)."],
    ],
    [1400, 7600],
    { noHeader: true },
  ),

  pageBreak(),
);

// ── 5. roadmap ─────────────────────────────────────────────────────────────
add(
  h1("5  Roadmap"),
  p("Sequenced so that correctness precedes breadth. Adding modules to an engine that reports unverified findings multiplies the noise; adding them to one that verifies multiplies the value."),

  h2("Phase 0 — Complete"),
  bullet("Three-gate evidence pipeline (`response-oracle`, `body-signatures`, hardened `verification-gate`)"),
  bullet("Credential detection rewritten; UUID and blanket-entropy false positives removed"),
  bullet("Severity model corrected across takeover, operational endpoints, access-denied responses, bucket attribution and HTTP methods"),
  bullet("Posture scoring rebuilt on severity bands with diminishing returns"),
  bullet("Durable scan queue, advisory-lock concurrency gate, SLA monitor, audit trail — all previously dead code, now wired"),

  h2("Phase 1 — Trust and completeness  (0–3 months)"),
  table(
    ["Item", "Why it comes first"],
    [
      ["**Attribute findings to the host they were observed on**", "Findings record the apex domain, not the specific subdomain, IP or service. This makes per-asset risk scoring inert (263 assets, all scoring 0.0) and blocks asset-level prioritisation, trending and ownership routing. Everything downstream of the asset inventory depends on it."],
      ["**Backfill historical findings** through the new gates and aggregation", "The database still holds pre-fix records — 27 individual cookie findings for one host. Until they are collapsed, the dashboard contradicts the engine's current behaviour."],
      ["**Close the compliance mapping gap**", "Nine of ten OWASP controls read 'No Data'. Either map the taxonomy to them or state coverage explicitly — a control that silently reads as unassessed invites the reader to assume it passed."],
      ["**Surface withheld findings in the UI**", "Detectors now record what they suppressed and why. Exposing that turns the FP work into a visible product feature: 'we checked 412 paths, confirmed 6, withheld 31 with reasons.'"],
      ["**Verification provenance in reports**", "Each finding already carries a live re-verification stamp. Printing it — probe issued, response observed, time checked — is what makes the report defensible to a client's engineer."],
      ["**Change detection and alerting**", "Asset inventory has first-seen timestamps; diffing exists. Turn it into 'a new subdomain appeared, a port opened, a certificate changed' notifications."],
      ["**SSO/SAML and SIEM egress**", "The two hard blockers for enterprise deployment. Neither is research work."],
    ],
    [3000, 6000],
  ),

  h2("Phase 2 — Depth  (3–6 months)"),
  table(
    ["Item", "Open-source building blocks"],
    [
      ["**Real discovery scale**", "Certificate Transparency streaming (certstream) rather than point-in-time crt.sh queries; passive DNS aggregation; ASN/BGP-driven IP-range expansion to find assets the customer forgot they own."],
      ["**Deeper active testing**", "Full ProjectDiscovery integration — `katana` for crawling, `httpx` for probing at scale, custom Nuclei template authoring for the customer's own stack."],
      ["**Attack path graph, properly**", "Replace rule-based chain templates with a real graph over assets and findings; score paths by exploitability rather than by severity sum."],
      ["**Supply-chain / third-party risk**", "The clearest revenue gap against Bitsight and SecurityScorecard. Discover a customer's vendors from DNS, CSP, script origins and mail routing, then scan them as sub-portfolios."],
      ["**Secret detection at repository depth**", "Move beyond code-search hits to cloning and history scanning — the leaked key is usually in an old commit, not the current tree. Gitleaks-style rules over full history."],
    ],
    [2800, 6200],
  ),

  h2("Phase 3 — Data assets  (6–12 months)"),
  p("This is where the incumbents' moat is, and it is the only part of the roadmap that requires sustained investment rather than engineering time."),
  bullet("**Infostealer log ingestion.** Credential exposure today is overwhelmingly stealer-log driven. Even limited, ethically-sourced coverage changes the product's value proposition more than any scanner module."),
  bullet("**Paste and leak-site monitoring** beyond the ransomware corpus already integrated."),
  bullet("**Dark web collection** — the hardest and most legally sensitive item, and the one most reasonably deferred or partnered rather than built."),
  bullet("**Brand abuse at content level** — visual similarity on typosquat domains, fake mobile applications, impersonating social accounts."),

  h2("Phase 4 — Beyond the category  (12 months+)"),
  h3("The idea worth building the company on"),
  rich("Every platform in this market sells **findings**. The buyer's actual problem is that they cannot tell which findings are real, and so they either ignore the tool or pay analysts to re-verify it. Cyshield has already built the mechanism that solves this. The strategic move is to make it the product rather than an implementation detail:"),
  bullet("**Evidence-grade findings as the headline claim.** Every finding ships with the probe that produced it, the probe that reproduced it, the host's own not-found baseline it was distinguished from, and a timestamp. A customer's engineer can re-run it. Nobody in this market currently offers that."),
  bullet("**Publish the verification protocol.** An open, documented standard for what 'confirmed' means, with a reference implementation. Vendors compete on module count; competing on falsifiability is a different axis and a defensible one."),
  bullet("**Continuous re-verification.** A finding is not a static row — re-probe open findings on a schedule and close them automatically when the evidence stops reproducing. This inverts the industry's default, where findings accumulate until a human dismisses them."),
  bullet("**Agentic triage with a local model.** The Ollama integration already keeps inference on-premises. Point it at the evidence bundle, not the finding title, and it can draft the remediation, the business-impact statement and the client-facing narrative without any data leaving the deployment."),
  bullet("**Adversarial self-test.** Run the engine against deliberately-built targets — a catch-all SPA, a soft-404 host, a decoy `.env` — on every CI run, and publish the false-positive rate as a tracked metric. Treat precision as a product SLO."),

  callout(
    "The single highest-leverage thing to do next",
    "Backfill the existing findings through the new gates, then put the withheld-with-reasons list in the UI. It costs days, it makes the dashboard consistent with the engine, and it converts three weeks of correctness work into something a buyer can actually see.",
  ),

  pageBreak(),
);

// ── appendix ───────────────────────────────────────────────────────────────
add(
  h1("Appendix A  Codebase Inventory"),
  table(
    ["Metric", "Value"],
    [
      ["Scanner modules", "47 files, ~13,760 lines"],
      ["Server total", "~29,000 lines TypeScript"],
      ["Client total", "~21,800 lines TypeScript/TSX"],
      ["UI pages", "28"],
      ["API endpoints", "112 across 30 route modules"],
      ["Database tables", "24"],
      ["Unit tests", "1,008 across 60 files"],
      ["E2E tests", "17, including a 26-route axe WCAG 2.1 A/AA sweep at zero serious/critical"],
    ],
    [3400, 5600],
  ),

  h2("Modules added by the precision work"),
  table(
    ["Module", "Responsibility"],
    [
      ["`server/scanner/response-oracle.ts`", "Soft-404 auto-calibration. Establishes how a host answers paths that cannot exist, then judges probes by similarity rather than equality. Returns `soft-404 | real | unknown`."],
      ["`server/scanner/body-signatures.ts`", "Positive content proof. Predicates that confirm a body **is** the artefact a finding names — Kubernetes API, Prometheus exposition, dotenv file, git config, directory index, bucket listing, and others."],
      ["`server/scanner/credential-detection.ts`", "Three-tier credential evidence: known issuer key formats, named assignments with placeholder filtering, and context-bounded entropy. Also the masking used before any secret is stored or exported."],
    ],
    [3000, 6000],
  ),

  h2("Appendix B  Reproducing the screenshots"),
  mono([
    "docker-compose up -d db",
    "npm run db:push",
    "PORT=5050 npm run dev",
    "node scripts/capture-ui.mjs --theme dark --out docs/screenshots",
    "npx tsx scripts/gen-architecture-doc.mts",
  ]),
  p("The capture script signs in, selects the workspace holding the most findings, draws the numbered feature callouts into the live DOM, and screenshots at 2× device scale. Regenerating the document after a UI change therefore keeps every figure current.", { color: GREY }),
);

// ═══════════════════════════════════════════════════════════════════════════
const doc = new Document({
  creator: "Cyshield Pro",
  title: "Cyshield Pro — Architecture, Competitive Position and Roadmap",
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
