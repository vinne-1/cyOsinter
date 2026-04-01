import dns from "dns/promises";
import { enrichIP, fetchBGPView } from "../api-integrations.js";
import { createLogger } from "../logger.js";
import {
  SUBDOMAIN_WORDLIST_SOURCE, STANDARD_SUBDOMAIN_WORDLIST_CAP, STANDARD_PROBE_BATCH,
  STANDARD_SUBDOMAIN_CERT_CHECK, STANDARD_PORTS,
  GOLD_SUBDOMAIN_WORDLIST_CAP, GOLD_PROBE_BATCH, GOLD_SUBDOMAIN_CERT_CHECK, GOLD_PORTS,
  isGold, checkAborted, loadSubdomainWordlist,
  type ScanProgressCallback, type ScanOptions, type ScanResults,
} from "./constants.js";
import { resolveDNS, getNSRecords } from "./dns.js";
import { fetchJSON, httpHead, httpGet } from "./http.js";
import { getCertificateInfo } from "./tls.js";
import { scanOpenPorts, checkSecurityHeaders, detectServerInfo, detectWAF, detectCDN } from "./detection.js";
import { runWithConcurrency } from "./utils.js";
import { scanSubdomainTakeover } from "./takeover.js";

const log = createLogger("scanner");

async function checkDNSWildcard(domain: string): Promise<{ isWildcard: boolean; wildcardIPs: Set<string> }> {
  const random = Math.random().toString(36).slice(2, 12);
  const testHost = `nxdomain-${random}.${domain}`;
  try {
    const ips = await dns.resolve4(testHost);
    if (ips.length > 0) {
      return { isWildcard: true, wildcardIPs: new Set(ips) };
    }
  } catch {
    // NXDOMAIN or DNS error = no wildcard
  }
  return { isWildcard: false, wildcardIPs: new Set() };
}

async function enumerateSubdomainsBruteforce(
  domain: string,
  cap = 1000,
  concurrency = 20,
  signal?: AbortSignal,
  excludeIPs?: Set<string>,
): Promise<{ resolved: string[]; tried: number; wildcardDetected: boolean }> {
  const { isWildcard, wildcardIPs } = excludeIPs
    ? { isWildcard: excludeIPs.size > 0, wildcardIPs: excludeIPs }
    : await checkDNSWildcard(domain);

  if (isWildcard) {
    log.info({ domain, wildcardIPs: Array.from(wildcardIPs) }, "Wildcard DNS detected — filtering false positives");
  }

  const prefixes = await loadSubdomainWordlist();
  const toTry = prefixes.slice(0, cap).map((prefix) => `${prefix}.${domain}`);
  const resolved: string[] = [];
  const results = await runWithConcurrency(
    toTry,
    concurrency,
    async (hostname) => {
      const d = await resolveDNS(hostname);
      if (d.ips.length === 0 && d.cnames.length === 0) return null;
      if (isWildcard && d.ips.length > 0 && d.ips.every((ip) => wildcardIPs.has(ip))) return null;
      return hostname;
    },
    signal,
  );
  for (const r of results) {
    if (r) resolved.push(r);
  }
  return { resolved: Array.from(new Set(resolved)).sort(), tried: toTry.length, wildcardDetected: isWildcard };
}

async function enumerateSubdomainsCrtSh(domain: string): Promise<string[]> {
  const data = await fetchJSON(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, 15000);
  if (!data || !Array.isArray(data)) return [];
  const subdomains = new Set<string>();
  for (const entry of data) {
    const name = entry.name_value || entry.common_name || "";
    const names = name.split("\n");
    for (const n of names) {
      const cleaned = n.trim().toLowerCase().replace(/^\*\./, "");
      if (cleaned.endsWith(`.${domain}`) || cleaned === domain) {
        if (!cleaned.includes("*") && !cleaned.includes(" ")) {
          subdomains.add(cleaned);
        }
      }
    }
  }
  return Array.from(subdomains).sort();
}

export async function runEASMScan(domain: string, onProgress?: ScanProgressCallback, options?: ScanOptions): Promise<ScanResults> {
  const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (!domain || !DOMAIN_RE.test(domain)) throw new Error(`Invalid domain: ${domain}`);
  const signal = options?.signal;
  const gold = isGold(options);
  const results: ScanResults = { subdomains: [], assets: [], findings: [], reconData: {} };
  const now = new Date().toISOString();
  const report = async (msg: string, pct: number, step: string, eta?: number) => {
    checkAborted(signal);
    if (onProgress) await onProgress(msg, pct, step, eta);
  };

  const subdomainCap = gold ? GOLD_SUBDOMAIN_WORDLIST_CAP : STANDARD_SUBDOMAIN_WORDLIST_CAP;
  const probeBatchSize = gold ? GOLD_PROBE_BATCH : STANDARD_PROBE_BATCH;
  const certCheckLimit = gold ? GOLD_SUBDOMAIN_CERT_CHECK : STANDARD_SUBDOMAIN_CERT_CHECK;
  const portList = gold ? GOLD_PORTS : STANDARD_PORTS;

  checkAborted(signal);
  log.info({ domain, mode: gold ? "gold" : "standard" }, "Starting EASM scan");
  await report("Enumerating subdomains (crt.sh + bruteforce)...", 0, "enumerate_subdomains", 180);

  const [crtShSubdomains, mainDns, certInfo, nsRecords, bruteforceResult] = await Promise.all([
    enumerateSubdomainsCrtSh(domain),
    resolveDNS(domain),
    getCertificateInfo(domain),
    getNSRecords(domain),
    enumerateSubdomainsBruteforce(domain, subdomainCap === 0 ? 99999 : subdomainCap, 20, signal),
  ]);

  checkAborted(signal);
  const bruteforceSet = new Set(bruteforceResult.resolved);
  const combinedSubdomains = Array.from(new Set([...crtShSubdomains, ...bruteforceResult.resolved])).sort();
  results.subdomains = combinedSubdomains;
  if (bruteforceResult.wildcardDetected) {
    log.info({ domain }, "Wildcard DNS filtering applied — bruteforce results de-duplicated against wildcard IPs");
  }
  await report(`Found ${combinedSubdomains.length} subdomains${bruteforceResult.wildcardDetected ? " (wildcard DNS detected)" : ""}. Probing live hosts...`, 15, "enumerate_subdomains", 150);

  if (mainDns.ips.length > 0) {
    results.assets.push({ type: "domain", value: domain, tags: ["primary", "resolved"] });
    for (const ip of mainDns.ips) {
      results.assets.push({ type: "ip", value: ip, tags: ["resolved-from-domain"] });
    }
  }

  const subdomainProbes: Array<{ subdomain: string; dns: { ips: string[]; cnames: string[] }; httpResult: any; httpsResult: any }> = [];

  const probeBatch = probeBatchSize <= 0 ? combinedSubdomains : combinedSubdomains.slice(0, probeBatchSize);
  log.info({ count: probeBatch.length, tried: bruteforceResult.tried, resolved: bruteforceResult.resolved.length }, "Probing subdomains");

  const probeResults = await runWithConcurrency(
    probeBatch,
    20,
    async (sub) => {
      const subDns = await resolveDNS(sub);
      let httpResult = null;
      let httpsResult = null;
      if (subDns.ips.length > 0 || subDns.cnames.length > 0) {
        [httpsResult, httpResult] = await Promise.all([
          httpHead(`https://${sub}`).catch(() => null),
          httpHead(`http://${sub}`).catch(() => null),
        ]);
      }
      return { subdomain: sub, dns: subDns, httpResult, httpsResult };
    },
    signal,
  );

  for (const r of probeResults) {
    if (r) {
      const probe = r;
      subdomainProbes.push(probe);
      if (probe.dns.ips.length > 0 || probe.dns.cnames.length > 0) {
        results.assets.push({
          type: "subdomain",
          value: probe.subdomain,
          tags: [
            ...(bruteforceSet.has(probe.subdomain) ? ["bruteforce"] : ["crt.sh"]),
            ...(probe.httpsResult ? ["https-live"] : []),
            ...(probe.httpResult ? ["http-live"] : []),
            ...(probe.dns.cnames.length > 0 ? ["has-cname"] : []),
          ],
        });
        for (const ip of probe.dns.ips) {
          if (!results.assets.find(a => a.value === ip)) {
            results.assets.push({ type: "ip", value: ip, tags: ["subdomain-resolution"] });
          }
        }
      }
    }
  }

  checkAborted(signal);
  const liveSubdomains = subdomainProbes.filter(p => p.httpsResult || p.httpResult);
  await report(`Probed ${probeBatch.length} subdomains, ${liveSubdomains.length} live. Analyzing TLS and headers...`, 55, "probe_subdomains", 90);

  const bruteforceLiveWithHttp = liveSubdomains.filter(p => bruteforceSet.has(p.subdomain)).map(p => p.subdomain);
  results.reconData.subdomainBruteforce = {
    wordlistSource: SUBDOMAIN_WORDLIST_SOURCE,
    tried: bruteforceResult.tried,
    resolved: bruteforceResult.resolved,
    liveWithHttp: bruteforceLiveWithHttp,
  };

  for (const live of liveSubdomains) {
    const proto = live.httpsResult ? "https" : "http";
    const port = proto === "https" ? 443 : 80;
    results.assets.push({ type: "service", value: `${proto}://${live.subdomain}:${port}`, tags: ["auto-discovered"] });
  }

  results.reconData.discoveredDomains = liveSubdomains.map((p) => {
    const respHeaders = (p.httpsResult?.headers || p.httpResult?.headers || {}) as Record<string, string>;
    const wafInfo = detectWAF(respHeaders);
    const cdnName = detectCDN(respHeaders);
    return {
      domain: p.subdomain,
      ip: p.dns.ips[0] || p.dns.cnames[0] || "-",
      cdn: cdnName,
      waf: wafInfo.detected,
      wafProvider: wafInfo.provider,
      newSinceLastRun: false,
    };
  });

  const TAKEOVER_PRONE_PATTERNS = /\.(s3\.amazonaws\.com|cloudfront\.net|herokuapp\.com|herokussl\.com|github\.io|azurewebsites\.net|elasticbeanstalk\.com|trafficmanager\.net|zendesk\.com|fastly\.net|ghost\.io|helpscoutdocs\.com|cargo\.site|surge\.sh|bitbucket\.io|pantheon\.site|wpengine\.com|readme\.io|intercom\.io|statuspage\.io|uservoice\.com|feedpress\.me|freshdesk\.com|helpjuice\.com|helpscout\.com|pingdom\.com|tictail\.com|shopify\.com|teamwork\.com|unbounce\.com|tumblr\.com|wordpress\.com|desk\.com|service-now\.com|acquia\.cloud|myshopify\.com)\.?$/i;
  const danglingCnames = subdomainProbes.filter(p => {
    if (p.dns.cnames.length === 0) return false;
    if (p.dns.ips.length > 0) return false;
    return true;
  });

  for (const dc of danglingCnames) {
    const cnameTarget = dc.dns.cnames[0] || "";
    const isTakeoverProne = TAKEOVER_PRONE_PATTERNS.test(cnameTarget);
    results.findings.push({
      title: isTakeoverProne ? `High-Risk Subdomain Takeover: ${dc.subdomain}` : `Potential Subdomain Takeover: ${dc.subdomain}`,
      description: isTakeoverProne
        ? `The subdomain ${dc.subdomain} has a CNAME pointing to ${cnameTarget} (known takeover-prone service) but the target does not resolve. This is a high-risk dangling DNS record.`
        : `The subdomain ${dc.subdomain} has a CNAME record pointing to ${cnameTarget} but the target does not resolve to any IP address. This may indicate a dangling DNS record that could be vulnerable to subdomain takeover.`,
      severity: isTakeoverProne ? "critical" : "high",
      category: "subdomain_takeover",
      affectedAsset: dc.subdomain,
      cvssScore: isTakeoverProne ? "9.1" : "8.2",
      remediation: "Remove the dangling CNAME record if the service is no longer in use, or reclaim the underlying service.",
      evidence: [
        {
          type: "dns_record",
          description: `CNAME record points to unresolvable target`,
          snippet: `${dc.subdomain} CNAME ${dc.dns.cnames[0]}\n; Target does not resolve - potential takeover risk`,
          source: "DNS resolution",
          verifiedAt: now,
        },
      ],
    });
  }

  checkAborted(signal);
  await report("Analyzing TLS certificate and security posture...", 65, "analyze_tls", 60);

  if (certInfo) {
    results.assets.push({
      type: "certificate",
      value: `${certInfo.subject} (${certInfo.issuer})`,
      tags: [`expires-in-${certInfo.daysRemaining}d`, certInfo.protocol],
    });

    if (certInfo.daysRemaining <= 30 && certInfo.daysRemaining > 0) {
      results.findings.push({
        title: `SSL Certificate Expiring in ${certInfo.daysRemaining} Days`,
        description: `The SSL/TLS certificate for ${domain} (issued by ${certInfo.issuer}) will expire on ${certInfo.validTo}. This is ${certInfo.daysRemaining} days from now.`,
        severity: certInfo.daysRemaining <= 7 ? "critical" : certInfo.daysRemaining <= 14 ? "high" : "medium",
        category: "ssl_issue",
        affectedAsset: domain,
        cvssScore: certInfo.daysRemaining <= 7 ? "8.1" : certInfo.daysRemaining <= 14 ? "6.5" : "4.3",
        remediation: `Renew the SSL/TLS certificate for ${domain} before ${certInfo.validTo}.`,
        evidence: [
          {
            type: "certificate_info",
            description: "Live certificate inspection",
            snippet: `Subject: ${certInfo.subject}\nIssuer: ${certInfo.issuer}\nValid From: ${certInfo.validFrom}\nValid To: ${certInfo.validTo}\nDays Remaining: ${certInfo.daysRemaining}\nProtocol: ${certInfo.protocol}\nSerial: ${certInfo.serialNumber}`,
            source: `TLS connection to ${domain}:443`,
            verifiedAt: now,
          },
        ],
      });
    }

    if (certInfo.daysRemaining <= 0) {
      results.findings.push({
        title: `SSL Certificate Has Expired for ${domain}`,
        description: `The SSL/TLS certificate for ${domain} expired on ${certInfo.validTo}. Visitors will see security warnings.`,
        severity: "critical",
        category: "ssl_issue",
        affectedAsset: domain,
        cvssScore: "9.1",
        remediation: `Immediately renew the SSL/TLS certificate for ${domain}.`,
        evidence: [
          {
            type: "certificate_info",
            description: "Expired certificate detected via TLS connection",
            snippet: `Subject: ${certInfo.subject}\nIssuer: ${certInfo.issuer}\nExpired: ${certInfo.validTo}\nDays Past Expiry: ${Math.abs(certInfo.daysRemaining)}`,
            source: `TLS connection to ${domain}:443`,
            verifiedAt: now,
          },
        ],
      });
    }

    results.reconData.ssl = {
      subject: certInfo.subject,
      issuer: certInfo.issuer,
      validFrom: certInfo.validFrom,
      validTo: certInfo.validTo,
      daysRemaining: certInfo.daysRemaining,
      protocol: certInfo.protocol,
      altNames: certInfo.altNames,
    };
  }

  checkAborted(signal);
  const certCheckSubs = certCheckLimit <= 0 ? liveSubdomains : liveSubdomains.slice(0, certCheckLimit);
  for (const live of certCheckSubs) {
    const subCert = await getCertificateInfo(live.subdomain);
    if (subCert && (subCert.daysRemaining <= 30 || subCert.daysRemaining <= 0)) {
      results.findings.push({
        title: `SSL Certificate Issue on ${live.subdomain}`,
        description: subCert.daysRemaining <= 0
          ? `The SSL certificate for ${live.subdomain} has expired.`
          : `The SSL certificate for ${live.subdomain} expires in ${subCert.daysRemaining} days.`,
        severity: subCert.daysRemaining <= 0 ? "critical" : subCert.daysRemaining <= 7 ? "high" : "medium",
        category: "ssl_issue",
        affectedAsset: live.subdomain,
        cvssScore: subCert.daysRemaining <= 0 ? "9.1" : subCert.daysRemaining <= 7 ? "8.1" : "5.3",
        remediation: "Renew the SSL certificate for this subdomain.",
        evidence: [
          {
            type: "certificate_info",
            description: "TLS certificate inspection",
            snippet: `Subject: ${subCert.subject}\nIssuer: ${subCert.issuer}\nDays Remaining: ${subCert.daysRemaining}`,
            source: `TLS connection to ${live.subdomain}:443`,
            verifiedAt: now,
          },
        ],
      });
    }
  }

  await report("Checking security headers and HTTP configuration...", 75, "check_headers", 30);

  const mainHttps = await httpGet(`https://${domain}`);
  if (mainHttps) {
    const headerChecks = checkSecurityHeaders(mainHttps.headers);
    const missingHeaders = headerChecks.filter(h => !h.present);
    const serverLeaks = detectServerInfo(mainHttps.headers);

    if (missingHeaders.length >= 3) {
      results.findings.push({
        title: `Multiple Missing Security Headers on ${domain}`,
        description: `${missingHeaders.length} security headers are missing from the HTTP response on ${domain}. Missing headers: ${missingHeaders.map(h => h.header).join(", ")}.`,
        severity: missingHeaders.length >= 5 ? "medium" : "low",
        category: "security_headers",
        affectedAsset: domain,
        cvssScore: missingHeaders.length >= 5 ? "5.0" : "3.5",
        remediation: "Configure the web server to include the missing security headers.",
        evidence: [
          {
            type: "http_headers",
            description: "Security header analysis of live HTTP response",
            snippet: headerChecks.map(h => `${h.present ? "[PASS]" : "[MISS]"} ${h.header}${h.value ? `: ${h.value}` : ""}`).join("\n"),
            url: `https://${domain}`,
            source: "HTTP response headers",
            verifiedAt: now,
          },
        ],
      });
    }

    if (serverLeaks.length > 0) {
      results.findings.push({
        title: `Server Version Information Disclosed on ${domain}`,
        description: `The web server at ${domain} exposes version information in HTTP response headers, which could help attackers identify specific vulnerabilities.`,
        severity: "low",
        category: "information_disclosure",
        affectedAsset: domain,
        cvssScore: "3.0",
        remediation: "Configure the web server to suppress version information in headers.",
        evidence: [
          {
            type: "http_headers",
            description: "Server information leak in HTTP response headers",
            snippet: serverLeaks.join("\n"),
            url: `https://${domain}`,
            source: "HTTP response headers",
            verifiedAt: now,
          },
        ],
      });
    }

    if (!mainHttps.headers["strict-transport-security"]) {
      const httpPlain = await httpGet(`http://${domain}`);
      if (httpPlain && httpPlain.status === 200) {
        results.findings.push({
          title: `No HSTS and HTTP Available on ${domain}`,
          description: `${domain} serves content over plain HTTP (port 80) and does not set the Strict-Transport-Security header on HTTPS responses. This allows potential downgrade attacks.`,
          severity: "medium",
          category: "ssl_issue",
          affectedAsset: domain,
          cvssScore: "4.8",
          remediation: "Enable HSTS header on all HTTPS responses and redirect HTTP to HTTPS.",
          evidence: [
            {
              type: "http_response",
              description: "HTTP (non-TLS) responds successfully without HSTS enforcement",
              snippet: `HTTP Request: http://${domain}\nStatus: ${httpPlain.status}\nHSTS Header: Not Present\nHTTPS Redirect: ${httpPlain.finalUrl.startsWith("https") ? "Yes (redirect exists but no HSTS)" : "No redirect to HTTPS"}`,
              url: `http://${domain}`,
              source: "HTTP probe",
              verifiedAt: now,
            },
          ],
        });
      }
    }

    results.reconData.securityHeaders = Object.fromEntries(
      headerChecks.map(h => [h.header, { present: h.present, value: h.value || null, grade: h.grade }])
    );
    results.reconData.serverInfo = { leaks: serverLeaks, allHeaders: mainHttps.headers };
  }

  if (gold && liveSubdomains.length > 0) {
    checkAborted(signal);
    await report("Running per-asset TLS, headers, and leak analysis...", 82, "per_asset_analysis", 45);

    const perAssetTls: Record<string, { subject?: string; issuer?: string; daysRemaining?: number; protocol?: string } | null> = {};
    const perAssetHeaders: Record<string, Record<string, { present: boolean; value: string | null }>> = {};
    const perAssetLeaks: Record<string, string[]> = {};
    const wafByHost: Record<string, { waf: boolean; wafProvider: string; cdn: string }> = {};

    const perAssetBatch = gold ? liveSubdomains : liveSubdomains.slice(0, 30);
    const perAssetResults = await runWithConcurrency(
      perAssetBatch,
      10,
      async (live) => {
        const host = live.subdomain;
        const cert = await getCertificateInfo(host);
        const resp = await httpGet(`https://${host}`);
        return { host, cert, resp };
      },
      signal,
    );

    for (const r of perAssetResults) {
      if (!r) continue;
      const { host, cert, resp } = r;
      if (cert) {
        perAssetTls[host] = { subject: cert.subject, issuer: cert.issuer, daysRemaining: cert.daysRemaining, protocol: cert.protocol };
      } else {
        perAssetTls[host] = null;
      }
      if (resp) {
        const hdrs = checkSecurityHeaders(resp.headers);
        perAssetHeaders[host] = Object.fromEntries(hdrs.map(h => [h.header, { present: h.present, value: h.value || null }]));
        perAssetLeaks[host] = detectServerInfo(resp.headers);
        const w = detectWAF(resp.headers);
        const c = detectCDN(resp.headers);
        wafByHost[host] = { waf: w.detected, wafProvider: w.provider, cdn: c };
      }
    }

    results.reconData.perAssetTls = perAssetTls;
    results.reconData.perAssetHeaders = perAssetHeaders;
    results.reconData.perAssetLeaks = perAssetLeaks;
    results.reconData.wafByHost = wafByHost;
  }

  if (mainDns.ips.length > 0) {
    const mainIp = mainDns.ips[0];
    const openPorts = await scanOpenPorts(mainIp, portList);
    results.reconData.openPorts = openPorts;

    if (gold) {
      const allIps = Array.from(new Set(subdomainProbes.flatMap(p => p.dns.ips)));
      const otherIps = allIps.filter(ip => ip !== mainIp);
      const openPortsByIp: Record<string, number[]> = { [mainIp]: openPorts };
      for (const ip of otherIps) {
        openPortsByIp[ip] = await scanOpenPorts(ip, portList);
      }
      results.reconData.openPortsByIp = openPortsByIp;
    }

    // Threat intel enrichment for the primary IP (and subdomain IPs in gold mode)
    try {
      const [abuseResult, bgpResult] = await Promise.all([
        enrichIP(mainIp),
        fetchBGPView(mainIp),
      ]);
      results.reconData.threatIntel = {
        [mainIp]: { abuseipdb: abuseResult.abuseipdb, virustotal: abuseResult.virustotal, bgp: bgpResult },
      };
      if (abuseResult.abuseipdb && abuseResult.abuseipdb.abuseConfidenceScore >= 50) {
        results.findings.push({
          title: `High Abuse Score for Primary IP ${mainIp}`,
          description: `The primary IP address ${mainIp} for ${domain} has an AbuseIPDB confidence score of ${abuseResult.abuseipdb.abuseConfidenceScore}% (${abuseResult.abuseipdb.totalReports} reports). This indicates the IP has been reported for malicious activity.`,
          severity: abuseResult.abuseipdb.abuseConfidenceScore >= 80 ? "high" : "medium",
          category: "threat_intelligence",
          affectedAsset: mainIp,
          cvssScore: abuseResult.abuseipdb.abuseConfidenceScore >= 80 ? "7.5" : "5.3",
          remediation: "Investigate the reported abuse activity. Consider changing IP address or contacting the hosting provider.",
          evidence: [
            {
              type: "threat_intel",
              description: "AbuseIPDB IP reputation check",
              snippet: `IP: ${mainIp}\nAbuse Score: ${abuseResult.abuseipdb.abuseConfidenceScore}%\nTotal Reports: ${abuseResult.abuseipdb.totalReports}\nISP: ${abuseResult.abuseipdb.isp ?? "unknown"}\nCountry: ${abuseResult.abuseipdb.countryCode ?? "unknown"}`,
              source: "AbuseIPDB API",
              verifiedAt: now,
            },
          ],
        });
      }
      if (gold) {
        const allSubIps = Array.from(new Set(subdomainProbes.flatMap(p => p.dns.ips))).filter(ip => ip !== mainIp).slice(0, 10);
        for (const ip of allSubIps) {
          try {
            const [subAbuse, subBgp] = await Promise.all([enrichIP(ip), fetchBGPView(ip)]);
            results.reconData.threatIntel![ip] = { abuseipdb: subAbuse.abuseipdb, virustotal: subAbuse.virustotal, bgp: subBgp };
          } catch (err) {
            log.warn({ err, ip }, "Threat intel enrichment failed");
          }
        }
      }
    } catch (err) {
      log.warn({ err, ip: mainIp }, "Threat intel enrichment failed");
    }
  }

  results.reconData.dns = {
    ips: mainDns.ips,
    cnames: mainDns.cnames,
    ns: nsRecords,
    subdomainsFound: crtShSubdomains.length,
    liveSubdomains: liveSubdomains.map(s => s.subdomain),
    danglingCnames: danglingCnames.map(d => ({ subdomain: d.subdomain, cname: d.dns.cnames[0] })),
  };

  // Subdomain takeover detection
  if (results.subdomains.length > 0) {
    try {
      await report("Checking for subdomain takeover vulnerabilities...", 95, "takeover_check");
      const takeoverResults = await scanSubdomainTakeover(results.subdomains, options?.signal);
      results.findings.push(...takeoverResults.findings);
      if (takeoverResults.results.length > 0) {
        results.reconData.subdomainTakeover = takeoverResults.results.map(r => ({
          subdomain: r.subdomain,
          cname: r.cname,
          service: r.service,
          vulnerable: r.vulnerable,
          confidence: r.confidence,
        }));
      }
    } catch (err) {
      log.warn({ err }, "Subdomain takeover scan failed");
    }
  }

  await report("EASM scan complete.", 100, "build_modules", 0);
  log.info({ domain, subdomains: results.subdomains.length, assets: results.assets.length, findings: results.findings.length }, "EASM scan complete");
  return results;
}
