/**
 * Render a Markdown OSINT + EASM report from a safe-scan-runner JSON dump.
 * Usage: npx tsx scripts/gen-report.ts <scan.json> [out.md]
 */
import fs from "fs/promises";

const inFile = process.argv[2];
const outFile = process.argv[3] ?? inFile.replace(/\.json$/, "") + "-report.md";

type Finding = { title: string; severity: string; category: string; affectedAsset: string; description: string; cvssScore?: string; remediation?: string };

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const sevRank = (s: string) => { const i = SEV_ORDER.indexOf((s || "info").toLowerCase()); return i < 0 ? 99 : i; };

function esc(s: unknown): string {
  return String(s ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ").trim();
}

async function main() {
  const d = JSON.parse(await fs.readFile(inFile, "utf-8"));
  const findings: Finding[] = d.findings ?? [];
  const easm = d.easmReconData ?? {};
  const osint = d.osintReconData ?? {};
  const L: string[] = [];

  const bySev: Record<string, number> = {};
  for (const f of findings) bySev[(f.severity || "info").toLowerCase()] = (bySev[(f.severity || "info").toLowerCase()] ?? 0) + 1;

  L.push(`# OSINT + EASM Report — ${d.target}`);
  L.push("");
  L.push(`- **Scan mode:** ${d.mode} (stealth: rate-limited, jittered, rotating User-Agents)`);
  L.push(`- **Generated:** ${d.generatedAt}`);
  L.push(`- **Duration:** ${d.durationSeconds}s`);
  L.push(`- **Nuclei:** ${d.nucleiSkipped ? `skipped (${d.nucleiSkipReason})` : "run"}`);
  L.push("");
  L.push(`## Executive Summary`);
  L.push("");
  L.push(`| Metric | Count |`);
  L.push(`|---|---|`);
  L.push(`| Subdomains discovered | ${d.summary.subdomains} |`);
  L.push(`| Assets | ${d.summary.assets} |`);
  L.push(`| Total findings | ${d.summary.findings} |`);
  L.push(`| Recon modules | ${d.summary.reconModules} |`);
  L.push("");
  L.push(`**Findings by severity:** ` + SEV_ORDER.map((s) => `${s}: ${bySev[s] ?? 0}`).join(" · "));
  L.push("");

  // Findings table
  L.push(`## Findings`);
  L.push("");
  if (findings.length === 0) {
    L.push("_No findings._");
  } else {
    const sorted = [...findings].sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
    L.push(`| Severity | CVSS | Category | Asset | Title |`);
    L.push(`|---|---|---|---|---|`);
    for (const f of sorted) {
      L.push(`| ${esc(f.severity).toUpperCase()} | ${esc(f.cvssScore)} | ${esc(f.category)} | ${esc(f.affectedAsset)} | ${esc(f.title)} |`);
    }
    L.push("");
    // Detail for critical/high
    const hi = sorted.filter((f) => sevRank(f.severity) <= 1);
    if (hi.length > 0) {
      L.push(`### Critical / High detail`);
      L.push("");
      for (const f of hi) {
        L.push(`#### [${esc(f.severity).toUpperCase()}] ${esc(f.title)}`);
        L.push(`- **Asset:** ${esc(f.affectedAsset)} · **CVSS:** ${esc(f.cvssScore)} · **Category:** ${esc(f.category)}`);
        L.push(`- ${esc(f.description)}`);
        if (f.remediation) L.push(`- **Remediation:** ${esc(f.remediation)}`);
        L.push("");
      }
    }
  }

  // Subdomains
  L.push(`## Attack Surface — Subdomains (${(d.subdomains ?? []).length})`);
  L.push("");
  if ((d.subdomains ?? []).length) L.push((d.subdomains as string[]).map((s) => `- ${s}`).join("\n"));
  else L.push("_None discovered._");
  L.push("");
  if (easm.passiveSources) {
    L.push(`**Passive source breakdown:** ` + Object.entries(easm.passiveSources).map(([k, v]) => `${k}: ${v}`).join(" · "));
    L.push("");
  }

  // DNS / IPs
  if (easm.dns) {
    L.push(`## DNS & Infrastructure`);
    L.push("");
    L.push(`- **IPs:** ${(easm.dns.ips ?? []).join(", ") || "-"}`);
    L.push(`- **Nameservers:** ${(easm.dns.ns ?? []).join(", ") || "-"}`);
    if (easm.reverseDns) for (const [ip, names] of Object.entries(easm.reverseDns)) L.push(`- **PTR ${ip}:** ${(names as string[]).join(", ")}`);
    if (easm.openPorts?.length) L.push(`- **Open ports (primary IP):** ${easm.openPorts.join(", ")}`);
    if (easm.portScan) for (const [ip, ports] of Object.entries(easm.portScan)) {
      L.push(`- **Port banners ${ip}:** ` + (ports as { port: number; service: string; banner?: string }[]).map((p) => `${p.port}/${p.service}${p.banner ? ` (${esc(p.banner).slice(0, 60)})` : ""}`).join(", "));
    }
    L.push("");
  }

  // TLS
  if (easm.ssl) {
    L.push(`## TLS / Certificate`);
    L.push("");
    L.push(`- **Subject:** ${esc(easm.ssl.subject)} · **Issuer:** ${esc(easm.ssl.issuer)}`);
    L.push(`- **Valid to:** ${esc(easm.ssl.validTo)} (${easm.ssl.daysRemaining} days) · **Protocol:** ${esc(easm.ssl.protocol)}`);
    if (easm.ssl.altNames?.length) L.push(`- **SANs:** ${easm.ssl.altNames.join(", ")}`);
    L.push("");
  }

  // Security headers
  if (easm.securityHeaders) {
    L.push(`## Security Headers`);
    L.push("");
    L.push(`| Header | Present | Grade |`);
    L.push(`|---|---|---|`);
    for (const [h, v] of Object.entries(easm.securityHeaders as Record<string, { present?: boolean; grade?: string }>)) {
      L.push(`| ${esc(h)} | ${v.present ? "yes" : "**no**"} | ${esc(v.grade)} |`);
    }
    L.push("");
  }

  // Email security (OSINT)
  const em = osint.emailSecurity;
  if (em) {
    L.push(`## Email Security (SPF / DMARC / DKIM)`);
    L.push("");
    L.push(`- **SPF:** ${em.spf?.found ? "found" : "**missing**"}${em.spf?.issues?.length ? ` — issues: ${em.spf.issues.join("; ")}` : ""}`);
    L.push(`  - \`${esc(em.spf?.record) || "-"}\``);
    L.push(`- **DMARC:** ${em.dmarc?.found ? "found" : "**missing**"}${em.dmarc?.issues?.length ? ` — issues: ${em.dmarc.issues.join("; ")}` : ""}`);
    L.push(`  - \`${esc(em.dmarc?.record) || "-"}\``);
    L.push(`- **DKIM (default):** ${em.dkim?.found ? "found" : "not found (selector-dependent)"}`);
    L.push(`- **MX:** ${(em.mx ?? []).map((m: { exchange: string }) => m.exchange).join(", ") || "-"}`);
    if (em.cloudProviders?.length) L.push(`- **Cloud providers (from SPF/MX):** ${em.cloudProviders.map((c: { provider: string }) => c.provider).join(", ")}`);
    L.push("");
  }

  // Tech stack
  if ((osint.techStack ?? easm.techStack)?.length) {
    const tech = (osint.techStack ?? easm.techStack) as { name: string; source: string }[];
    L.push(`## Technology Stack`);
    L.push("");
    L.push(tech.map((t) => `- ${t.name} _(${t.source})_`).join("\n"));
    L.push("");
  }

  // Exposed paths (OSINT)
  if (osint.directoryBruteforce?.hits?.length || osint.pathChecks) {
    L.push(`## Exposed Paths / Content`);
    L.push("");
    const hits = osint.directoryBruteforce?.hits ?? [];
    if (hits.length) {
      L.push(`Directory brute-force hits (${hits.length}):`);
      for (const h of hits.slice(0, 60)) L.push(`- \`${esc(h.path)}\` — ${esc(h.responseType ?? h.status)} ${h.severity ? `(${h.severity})` : ""}`);
    } else {
      L.push("_No directory brute-force hits._");
    }
    L.push("");
  }

  // Cloud / container
  if (easm.cloudDiscovery) {
    L.push(`## Cloud Assets`);
    L.push("");
    for (const b of easm.cloudDiscovery.buckets ?? []) L.push(`- **${b.provider} bucket:** ${b.url} (status ${b.status}, ${b.accessible ? "accessible" : "exists"})`);
    for (const s of easm.cloudDiscovery.cloudServices ?? []) L.push(`- **${s.provider} ${s.service}:** ${esc(s.evidence)}`);
    L.push("");
  }
  if (easm.containerExposure?.exposedEndpoints?.length) {
    L.push(`## Container / Orchestration Exposure`);
    L.push("");
    for (const ep of easm.containerExposure.exposedEndpoints) L.push(`- **${ep.type}:** ${ep.url} (status ${ep.status}, ${ep.authenticated ? "auth" : "OPEN"})`);
    L.push("");
  }

  // Wayback
  if (easm.waybackUrls?.length || osint.waybackUrls?.length) {
    const wb = (easm.waybackUrls ?? osint.waybackUrls) as string[];
    L.push(`## Historical URLs (Wayback) — ${wb.length}`);
    L.push("");
    for (const u of wb.slice(0, 40)) L.push(`- ${u}`);
    if (wb.length > 40) L.push(`- … and ${wb.length - 40} more`);
    L.push("");
  }

  // WHOIS
  if (osint.domainInfo && Object.keys(osint.domainInfo).length) {
    L.push(`## WHOIS / Domain Registration`);
    L.push("");
    for (const [k, v] of Object.entries(osint.domainInfo)) L.push(`- **${esc(k)}:** ${esc(v)}`);
    L.push("");
  }

  L.push(`---`);
  L.push(`_Report generated by Cyber-Shield-Pro safe-mode scanner (OSINT + EASM, open-source sources only)._`);

  await fs.writeFile(outFile, L.join("\n"), "utf-8");
  console.log("Wrote", outFile, `(${L.length} lines)`);
}

main().catch((e) => { console.error(e); process.exit(1); });
