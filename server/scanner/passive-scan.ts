import { createLogger } from "../logger.js";
import { checkAborted, type ScanProgressCallback, type ScanOptions, type ScanResults } from "./constants.js";
import {
  getDNSTxtRecords, getMXRecords, getNSRecords, getFullDNSRecords, checkDNSSEC,
  analyzeSPF, analyzeDMARC, extractCloudProvidersFromSPF, extractEmailsFromDNS, resolveDNS,
} from "./dns.js";
import { fetchJSON, httpGetMainPage, getRedirectChain, parseSecurityTxt, parseSetCookie } from "./http.js";
import { getCertificateInfo } from "./tls.js";
import { checkSecurityHeaders, detectServerInfo, detectTechStack, parseSocialTags } from "./detection.js";
import {
  getWhois, extractEmailsFromWhois, extractEmailsFromText, extractEmailsFromCrtSh, getServerLocation,
} from "./osint-helpers.js";
import { buildSPFFindings, buildDMARCFindings, processHarvestedEmails } from "./osint-email-dns.js";
import { scanSubdomainTakeover } from "./takeover.js";
import { fetchSubdomainsFromFreeSources, fetchWaybackUrls, reverseDnsLookup } from "./passive-sources.js";
import { enrichIP } from "../api-integrations.js";

const log = createLogger("scanner");

const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

/**
 * Passive OSINT scan — STRICTLY non-intrusive reconnaissance.
 *
 * This is an explicit allowlist of collectors that either query third-party
 * sources (crt.sh, Shodan InternetDB, WHOIS) or make at most a single normal,
 * unauthenticated, browser-like request to the target's homepage. It performs
 * NO subdomain/directory brute-force, NO port scanning, NO Nuclei, NO DAST,
 * and NO probing of discovered subdomains — so it can be run against targets
 * where only passive recon is authorized.
 *
 * Only DNS lookups (via public resolvers), a read-only TLS handshake, and one
 * homepage GET touch infrastructure related to the target; everything else is
 * third-party data.
 */
export async function runPassiveScan(
  domain: string,
  onProgress?: ScanProgressCallback,
  options?: ScanOptions,
): Promise<ScanResults> {
  if (!domain || !DOMAIN_RE.test(domain)) throw new Error(`Invalid domain: ${domain}`);
  const signal = options?.signal;
  const results: ScanResults = { subdomains: [], assets: [], findings: [], reconData: {} };
  const now = new Date().toISOString();
  const report = async (msg: string, pct: number, step: string, eta?: number) => {
    checkAborted(signal);
    if (onProgress) await onProgress(msg, pct, step, eta);
  };

  log.info({ domain }, "Starting PASSIVE scan (non-intrusive recon only)");
  await report("Passive recon: DNS, WHOIS, email security...", 5, "passive_dns", 60);

  // ── DNS / email security (public resolvers; read-only) ──
  const [txtRecords, dmarcTxt, dkimTxt, mxRecords, nsRecords, dnsRecords, redirectChain, domainInfo, dnssec, apexDns] =
    await Promise.all([
      getDNSTxtRecords(domain),
      getDNSTxtRecords(`_dmarc.${domain}`),
      getDNSTxtRecords(`default._domainkey.${domain}`),
      getMXRecords(domain),
      getNSRecords(domain),
      getFullDNSRecords(domain),
      getRedirectChain(`https://${domain}`),
      getWhois(domain),
      checkDNSSEC(domain),
      resolveDNS(domain),
    ]);

  results.reconData.dnsRecords = dnsRecords;
  results.reconData.redirectChain = redirectChain;
  results.reconData.domainInfo = domainInfo;
  results.reconData.dnssec = dnssec;

  const spfAnalysis = analyzeSPF(txtRecords);
  const dmarcAnalysis = analyzeDMARC(dmarcTxt);
  results.findings.push(...buildSPFFindings(domain, spfAnalysis, txtRecords, now));
  results.findings.push(...buildDMARCFindings(domain, dmarcAnalysis, now));

  const dkimRecord = dkimTxt?.flat().find((r) => r.startsWith("v=DKIM1") || r.includes("p="));
  const cloudProviders = extractCloudProvidersFromSPF(spfAnalysis.record, mxRecords);
  results.reconData.emailSecurity = {
    spf: spfAnalysis,
    dmarc: dmarcAnalysis,
    dkim: { found: !!dkimRecord, selector: "default", record: dkimRecord ? dkimRecord.substring(0, 200) : undefined },
    cloudProviders,
    mx: mxRecords,
    ns: nsRecords,
    txtRecords: txtRecords.flat(),
  };

  // ── Assets from apex resolution (DNS only — no probing) ──
  const apexIPs = Array.from(new Set(apexDns.ips));
  if (apexIPs.length > 0) {
    results.assets.push({ type: "domain", value: domain, tags: ["primary", "resolved", "passive"] });
    for (const ip of apexIPs) results.assets.push({ type: "ip", value: ip, tags: ["resolved-from-domain", "passive"] });
    // Reverse-DNS (PTR) — passive infrastructure mapping.
    try {
      const ptr = await reverseDnsLookup(apexIPs.slice(0, 10));
      if (Object.keys(ptr).length > 0) results.reconData.reverseDns = ptr;
    } catch { /* best-effort */ }
  }

  // Historical URLs from the Wayback Machine (passive web archive).
  try {
    const wayback = await fetchWaybackUrls(domain, 1000);
    if (wayback.length > 0) results.reconData.waybackUrls = wayback;
  } catch { /* best-effort */ }

  await report("Passive recon: certificate transparency (crt.sh)...", 35, "passive_ct", 40);

  // ── Certificate transparency + free passive sources (all third-party) ──
  const [ctNames, freeSources] = await Promise.all([
    enumerateCrtShNames(domain),
    fetchSubdomainsFromFreeSources(domain).catch(() => ({ subdomains: [] as string[], bySource: {} as Record<string, number> })),
  ]);
  const subdomainNames = Array.from(new Set([...ctNames, ...freeSources.subdomains])).filter((n) => n !== domain).sort();
  results.subdomains = subdomainNames;
  if (Object.keys(freeSources.bySource).length > 0) {
    results.reconData.passiveSources = freeSources.bySource;
  }
  results.reconData.dns = {
    ips: apexIPs,
    cnames: apexDns.cnames,
    ns: nsRecords,
    subdomainsFound: subdomainNames.length,
  };
  // Record discovered subdomains as informational assets WITHOUT probing them.
  for (const name of subdomainNames.slice(0, 200)) {
    results.assets.push({ type: "subdomain", value: name, tags: ["ct-log", "passive", "unprobed"] });
  }
  // Passive subdomain-takeover detection: DNS-only (no HTTP probe). A dangling
  // CNAME pointing to an unclaimed known service is a genuine critical/high
  // finding surfaceable purely passively.
  if (subdomainNames.length > 0) {
    try {
      const takeover = await scanSubdomainTakeover(subdomainNames.slice(0, 150), signal, { httpProbe: false });
      results.findings.push(...takeover.findings);
      results.reconData.subdomainTakeover = takeover.results.map((r) => ({
        subdomain: r.subdomain, cname: r.cname, service: r.service, vulnerable: r.vulnerable, confidence: r.confidence,
      }));
    } catch (err) {
      log.warn({ err }, "Passive takeover check failed");
    }
  }

  if (subdomainNames.length > 0) {
    results.findings.push({
      title: `${subdomainNames.length} Subdomain(s) Exposed via Certificate Transparency for ${domain}`,
      description: `Certificate Transparency logs (crt.sh) reveal ${subdomainNames.length} subdomain name(s) for ${domain}. CT logs are public; exposed subdomains widen the discoverable attack surface. This finding is passive — the subdomains were not probed.`,
      severity: "info",
      category: "osint_exposure",
      affectedAsset: domain,
      cvssScore: "0.0",
      remediation: "Review CT-exposed subdomains; retire unused hosts and ensure staging/internal names are not certificated publicly.",
      evidence: [{
        type: "ct_log",
        description: "Subdomains from Certificate Transparency logs",
        snippet: subdomainNames.slice(0, 40).join("\n"),
        source: "crt.sh",
        verifiedAt: now,
      }],
    });
  }

  await report("Passive recon: TLS certificate + homepage headers...", 60, "passive_tls", 30);

  // ── Read-only TLS certificate inspection ──
  const certInfo = await getCertificateInfo(domain);
  if (certInfo) {
    results.assets.push({ type: "certificate", value: domain, tags: ["tls", "passive"] });
    results.reconData.ssl = certInfo as ScanResults["reconData"]["ssl"];
  }

  // ── Single homepage GET (normal, unauthenticated, browser-like) ──
  const mainPage = await httpGetMainPage(`https://${domain}`);
  const emailSources = new Map<string, Set<string>>();
  const addEmail = (email: string, source: string) => {
    const lower = email.toLowerCase();
    if (!emailSources.has(lower)) emailSources.set(lower, new Set());
    emailSources.get(lower)!.add(source);
  };

  if (mainPage) {
    results.reconData.cookies = parseSetCookie(mainPage.setCookieStrings);
    results.reconData.responseHeaders = mainPage.headers;
    results.reconData.techStack = detectTechStack(mainPage.body, mainPage.headers);
    results.reconData.socialTags = parseSocialTags(mainPage.body);

    // Security headers → finding (same grading as active scan, single response)
    const headerChecks = checkSecurityHeaders(mainPage.headers);
    const missing = headerChecks.filter((h) => !h.present);
    if (missing.length >= 3) {
      results.findings.push({
        title: `Multiple Missing Security Headers on ${domain}`,
        description: `${missing.length} security headers are missing from the homepage HTTP response. Missing: ${missing.map((h) => h.header).join(", ")}.`,
        severity: missing.length >= 5 ? "medium" : "low",
        category: "security_headers",
        affectedAsset: domain,
        cvssScore: missing.length >= 5 ? "5.0" : "3.5",
        remediation: "Configure the web server to send the missing security headers.",
        evidence: [{
          type: "http_headers",
          description: "Security header analysis of homepage response",
          snippet: headerChecks.map((h) => `${h.present ? "[PASS]" : "[MISS]"} ${h.header}${h.value ? `: ${h.value}` : ""}`).join("\n"),
          url: `https://${domain}`,
          source: "HTTP response headers",
          verifiedAt: now,
        }],
      });
    }
    const serverLeaks = detectServerInfo(mainPage.headers);
    results.reconData.serverInfo = { leaks: serverLeaks, allHeaders: mainPage.headers } as ScanResults["reconData"]["serverInfo"];

    // security.txt is embedded in the homepage fetch path only if present in headers/body;
    // parse it opportunistically from the body if the page inlines it.
    for (const e of extractEmailsFromText(mainPage.body, domain)) addEmail(e, "Homepage");
    const secTxtMatch = mainPage.body.match(/Contact:\s*mailto:[^\s<]+/i);
    if (secTxtMatch) results.reconData.securityTxt = { raw: secTxtMatch[0], parsed: parseSecurityTxt(secTxtMatch[0]) };
  }

  // ── Email harvesting from passive sources (DNS, WHOIS, CT, homepage) ──
  for (const e of extractEmailsFromDNS(txtRecords, dmarcTxt)) addEmail(e, "DNS records (SPF/DMARC)");
  for (const e of extractEmailsFromWhois(domainInfo as Record<string, string> | null)) addEmail(e, "WHOIS registration");
  try {
    for (const e of await extractEmailsFromCrtSh(domain)) addEmail(e, "Certificate Transparency");
  } catch { /* crt.sh best-effort */ }
  const { findings: emailFindings } = processHarvestedEmails(domain, emailSources, now);
  results.findings.push(...emailFindings);

  await report("Passive recon: Shodan InternetDB IP intel...", 85, "passive_shodan", 15);

  // ── Shodan InternetDB enrichment for apex IPs (third-party, no key) ──
  const threatIntel: Record<string, Awaited<ReturnType<typeof enrichIP>>> = {};
  const serverLocations: Array<{ ip: string; loc: Awaited<ReturnType<typeof getServerLocation>> }> = [];
  for (const ip of apexIPs.slice(0, 5)) {
    try { threatIntel[ip] = await enrichIP(ip); } catch { /* best-effort */ }
    try { serverLocations.push({ ip, loc: await getServerLocation(ip) }); } catch { /* best-effort */ }
    const s = threatIntel[ip]?.shodanInternetDB;
    if (s && s.vulns.length > 0) {
      results.findings.push({
        title: `Known CVEs Reported for ${domain} IP ${ip} (Shodan)`,
        description: `Shodan InternetDB lists ${s.vulns.length} known CVE(s) for ${ip} (open ports: ${s.ports.join(", ") || "n/a"}). These are passive Shodan observations and should be verified against the actual running services.`,
        severity: "medium",
        category: "vulnerability",
        affectedAsset: ip,
        cvssScore: "5.0",
        remediation: "Verify and patch the affected services; restrict exposure of unnecessary ports.",
        evidence: [{
          type: "shodan_internetdb",
          description: "Passive CVE observations from Shodan InternetDB",
          snippet: `Ports: ${s.ports.join(", ")}\nCVEs: ${s.vulns.join(", ")}\nHostnames: ${s.hostnames.join(", ")}`,
          source: "internetdb.shodan.io",
          verifiedAt: now,
        }],
      });
    }
  }
  const firstLoc = serverLocations.find((s) => s.loc)?.loc;
  if (firstLoc) results.reconData.serverLocation = firstLoc;
  if (Object.keys(threatIntel).length > 0) {
    results.reconData.threatIntel = Object.fromEntries(
      Object.entries(threatIntel).map(([ip, e]) => [ip, { abuseipdb: e.abuseipdb, virustotal: e.virustotal, bgp: null }]),
    ) as ScanResults["reconData"]["threatIntel"];
  }

  await report("Passive scan complete.", 100, "passive_done");
  log.info({ domain, findings: results.findings.length, subdomains: results.subdomains.length }, "Passive scan complete");
  return results;
}

/** Enumerate subdomain names from crt.sh certificate transparency logs (third-party, passive). */
async function enumerateCrtShNames(domain: string): Promise<string[]> {
  try {
    const data = await fetchJSON(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, 15000);
    if (!Array.isArray(data)) return [];
    const names = new Set<string>();
    for (const entry of data) {
      const nameValue: string = entry?.name_value ?? "";
      for (const n of nameValue.split(/\n/)) {
        const cleaned = n.trim().toLowerCase().replace(/^\*\./, "");
        if (cleaned.endsWith(domain) && DOMAIN_RE.test(cleaned)) names.add(cleaned);
      }
    }
    return Array.from(names).sort();
  } catch {
    return [];
  }
}
