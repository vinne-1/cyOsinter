import { createLogger } from "../logger.js";
import {
  DIRECTORY_WORDLIST_SOURCE, STANDARD_DIRECTORY_CAP, STANDARD_SITEMAP_LIMIT,
  GOLD_DIRECTORY_CAP, GOLD_SITEMAP_LIMIT, GOLD_PORTS, STANDARD_PORTS,
  OSINT_CREDENTIAL_PATHS, OSINT_DOCUMENT_PATHS, OSINT_INFRA_PATHS, DOCUMENT_EXTENSIONS,
  isGold, checkAborted, loadDirectoryWordlist,
  type ScanProgressCallback, type ScanOptions, type ScanResults,
} from "./constants.js";
import { getDNSTxtRecords, getMXRecords, getNSRecords, getFullDNSRecords, checkDNSSEC, analyzeSPF, analyzeDMARC, extractCloudProvidersFromSPF, extractEmailsFromDNS } from "./dns.js";
import { httpGet, getRedirectChain, httpGetMainPage, parseSetCookie, parseSecurityTxt, fetchSitemapUrls } from "./http.js";
import { detectTechStack, scanOpenPorts, parseSocialTags, validatePathResponse } from "./detection.js";
import { extractEmailsFromText, redactCredentialValues, hasCredentialPattern, generateBackupFilePaths, extractSensitiveRobotsPaths, extractEmailsFromWhois, checkHIBPPasswords, checkS3Buckets, searchPGPKeyServer, extractEmailsFromCrtSh, getServerLocation, getWhois } from "./osint-helpers.js";
import { runWithConcurrency } from "./utils.js";
import { discoverAPIs } from "./api-discovery.js";
import { scanSecrets } from "./secret-scanner.js";

const log = createLogger("scanner");

export async function runOSINTScan(domain: string, onProgress?: ScanProgressCallback, options?: ScanOptions): Promise<ScanResults> {
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

  const directoryCap = gold ? GOLD_DIRECTORY_CAP : STANDARD_DIRECTORY_CAP;
  const sitemapLimit = gold ? GOLD_SITEMAP_LIMIT : STANDARD_SITEMAP_LIMIT;

  checkAborted(signal);
  log.info({ domain, mode: gold ? "gold" : "standard" }, "Starting OSINT scan");
  await report("Fetching DNS, SPF, DMARC, WHOIS...", 0, "dns_email", 120);

  const [txtRecords, dmarcTxt, dkimTxt, mxRecords, nsRecords, dnsRecords, redirectChain, domainInfo] = await Promise.all([
    getDNSTxtRecords(domain),
    getDNSTxtRecords(`_dmarc.${domain}`),
    getDNSTxtRecords(`default._domainkey.${domain}`),
    getMXRecords(domain),
    getNSRecords(domain),
    getFullDNSRecords(domain),
    getRedirectChain(`https://${domain}`),
    getWhois(domain),
  ]);

  results.reconData.dnsRecords = dnsRecords;
  results.reconData.redirectChain = redirectChain;
  results.reconData.domainInfo = domainInfo;

  const spfAnalysis = analyzeSPF(txtRecords);
  const dmarcAnalysis = analyzeDMARC(dmarcTxt);

  if (!spfAnalysis.found) {
    results.findings.push({
      title: `No SPF Record Found for ${domain}`,
      description: `The domain ${domain} does not have an SPF (Sender Policy Framework) DNS record. This means any server can send emails claiming to be from ${domain}, enabling email spoofing attacks.`,
      severity: "medium",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation: "Add an SPF TXT record to the domain's DNS configuration to specify authorized email senders.",
      evidence: [
        {
          type: "dns_query",
          description: "DNS TXT record lookup returned no SPF record",
          snippet: `Domain: ${domain}\nQuery: TXT records\nSPF Record: Not Found\n\nAll TXT records found:\n${txtRecords.flat().length > 0 ? txtRecords.flat().join("\n") : "(none)"}`,
          source: "DNS TXT record lookup",
          verifiedAt: now,
        },
      ],
    });
  } else if (spfAnalysis.issues.length > 0) {
    results.findings.push({
      title: `SPF Record Issues for ${domain}`,
      description: `The SPF record for ${domain} has configuration issues that may weaken email authentication: ${spfAnalysis.issues.join("; ")}.`,
      severity: spfAnalysis.record.includes("+all") ? "high" : "low",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: spfAnalysis.record.includes("+all") ? "7.1" : "3.5",
      remediation: "Update the SPF record to use '-all' or '~all' to restrict unauthorized senders.",
      evidence: [
        {
          type: "dns_query",
          description: "SPF record analysis",
          snippet: `Domain: ${domain}\nSPF Record: ${spfAnalysis.record}\n\nIssues:\n${spfAnalysis.issues.map(i => `- ${i}`).join("\n")}`,
          source: "DNS TXT record lookup",
          verifiedAt: now,
        },
      ],
    });
  }

  if (!dmarcAnalysis.found) {
    results.findings.push({
      title: `No DMARC Record Found for ${domain}`,
      description: `The domain ${domain} does not have a DMARC (Domain-based Message Authentication) DNS record at _dmarc.${domain}. Without DMARC, there is no policy to handle emails that fail SPF/DKIM checks.`,
      severity: "medium",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation: "Add a DMARC TXT record at _dmarc.${domain} with at least a 'p=quarantine' policy.",
      evidence: [
        {
          type: "dns_query",
          description: "DNS TXT record lookup for _dmarc subdomain returned no DMARC record",
          snippet: `Domain: _dmarc.${domain}\nQuery: TXT records\nDMARC Record: Not Found`,
          source: "DNS TXT record lookup",
          verifiedAt: now,
        },
      ],
    });
  } else if (dmarcAnalysis.issues.length > 0) {
    results.findings.push({
      title: `DMARC Policy Weakness for ${domain}`,
      description: `The DMARC record for ${domain} has a weak configuration: ${dmarcAnalysis.issues.join("; ")}.`,
      severity: "low",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: "3.5",
      remediation: "Update the DMARC policy to 'quarantine' or 'reject' and set pct=100.",
      evidence: [
        {
          type: "dns_query",
          description: "DMARC record analysis",
          snippet: `Domain: _dmarc.${domain}\nDMARC Record: ${dmarcAnalysis.record}\n\nIssues:\n${dmarcAnalysis.issues.map(i => `- ${i}`).join("\n")}`,
          source: "DNS TXT record lookup",
          verifiedAt: now,
        },
      ],
    });
  }

  checkAborted(signal);
  await report("Analyzed SPF/DMARC. Running directory bruteforce...", 25, "dns_email", 90);

  // Establish soft-404 baseline fingerprint to detect custom error pages
  const soft404Fingerprint = await (async () => {
    const random = Math.random().toString(36).slice(2, 10);
    const testPath = `/nxtest-${random}-doesnotexist`;
    try {
      const r = await httpGet(`https://${domain}${testPath}`);
      if (r && r.status === 200 && r.body) {
        return `${r.body.length}:${r.body.slice(0, 100).replace(/\s+/g, "")}`;
      }
    } catch {}
    return null;
  })();
  if (soft404Fingerprint) {
    log.info({ domain }, "Soft-404 fingerprint established");
  }

  const baseDirPaths = await loadDirectoryWordlist(directoryCap);
  const backupPaths = generateBackupFilePaths(domain, gold);
  const osintPaths = Array.from(new Set([...baseDirPaths, ...OSINT_CREDENTIAL_PATHS, ...OSINT_DOCUMENT_PATHS, ...OSINT_INFRA_PATHS, ...backupPaths, "/.git/config"]));
  const dirPaths = osintPaths;
  const pathCheckResultsRaw = await runWithConcurrency(
    dirPaths,
    8,
    async (p) => {
      const res = await httpGet(`https://${domain}${p}`);
      return { path: p, label: p, result: res };
    },
    signal,
  );
  const pathCheckResults = pathCheckResultsRaw.filter((r): r is { path: string; label: string; result: { status: number; headers: Record<string, string>; body: string; finalUrl: string } | null } => r != null);
  results.reconData.directoryBruteforce = {
    wordlistSource: DIRECTORY_WORDLIST_SOURCE,
    tried: dirPaths.length,
    hits: pathCheckResults
      .filter((r) => r.result)
      .map((r) => {
        const { status, body, finalUrl } = r.result!;
        const v = validatePathResponse(status, body, finalUrl, r.path);
        return { path: r.path, status, responseType: v.responseType, severity: v.severity, validated: v.validated, confidence: v.confidence, redirectTarget: v.redirectTarget };
      }),
  };
  await report(`Checked ${dirPaths.length} paths. Processing sitemap and main page...`, 65, "directory_bruteforce", 45);

  const exposedPaths: Array<{ path: string; label: string; status: number; snippet: string }> = [];

  for (const r of pathCheckResults) {
    if (!r.result) continue;
    const { path: rPath, label, result } = r;
    const pathValidation = validatePathResponse(result.status, result.body, result.finalUrl, rPath);
    if (result.status !== 200) continue;
    // Soft-404 fingerprint check: skip if body matches baseline 404 page
    if (soft404Fingerprint && result.body) {
      const bodyFingerprint = `${result.body.length}:${result.body.slice(0, 100).replace(/\s+/g, "")}`;
      if (bodyFingerprint === soft404Fingerprint) continue;
    }

    if (rPath === "/.env" && result.body) {
      const hasSecrets = hasCredentialPattern(result.body);
      const redacted = redactCredentialValues(result.body.substring(0, 500));
      results.findings.push({
        title: `Exposed Environment File (.env) on ${domain}`,
        description: hasSecrets
          ? `The .env file at ${domain}/.env is publicly accessible and appears to contain sensitive configuration values (passwords, API keys, tokens).`
          : `The .env file at ${domain}/.env is publicly accessible. It may contain sensitive configuration.`,
        severity: hasSecrets ? "critical" : "high",
        category: hasSecrets ? "leaked_credential" : "data_leak",
        affectedAsset: domain,
        cvssScore: hasSecrets ? "9.8" : "7.5",
        remediation: "Immediately block public access to .env files. Rotate all exposed credentials. Configure web server to deny access to dotfiles.",
        evidence: [
          {
            type: "http_response",
            description: hasSecrets ? "Publicly accessible .env file with sensitive data patterns" : "Publicly accessible .env file",
            url: `https://${domain}${rPath}`,
            snippet: `HTTP Status: 200 OK\nSensitive patterns detected: ${hasSecrets ? "Yes" : "No"}\n\nRedacted content preview:\n${redacted}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if (rPath === "/.git/config" && result.body.includes("[core]")) {
      const hasSecrets = hasCredentialPattern(result.body);
      const snippet = hasSecrets ? redactCredentialValues(result.body.substring(0, 300)) : result.body.substring(0, 300);
      results.findings.push({
        title: `Exposed Git Repository on ${domain}`,
        description: hasSecrets
          ? `The .git directory at ${domain}/.git/config is publicly accessible and contains credential-like patterns. This can expose source code, commit history, and sensitive configuration.`
          : `The .git directory at ${domain}/.git/config is publicly accessible. This can expose source code, commit history, and potentially sensitive files.`,
        severity: hasSecrets ? "critical" : "high",
        category: hasSecrets ? "leaked_credential" : "data_leak",
        affectedAsset: domain,
        cvssScore: hasSecrets ? "9.0" : "7.5",
        remediation: "Block public access to .git directories. Configure web server rules to deny access to all dotfiles and directories.",
        evidence: [
          {
            type: "http_response",
            description: "Git configuration file publicly accessible",
            url: `https://${domain}${rPath}`,
            snippet: `HTTP Status: 200 OK\n\nContent preview:\n${snippet}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if (OSINT_CREDENTIAL_PATHS.includes(rPath) && result.body && hasCredentialPattern(result.body)) {
      const redacted = redactCredentialValues(result.body.substring(0, 500));
      results.findings.push({
        title: `Exposed Credential File (${rPath}) on ${domain}`,
        description: `The file ${rPath} at ${domain} is publicly accessible and contains credential-like patterns (passwords, API keys, tokens).`,
        severity: "critical",
        category: "leaked_credential",
        affectedAsset: domain,
        cvssScore: "9.8",
        remediation: "Immediately block public access to credential and configuration files. Rotate all exposed credentials.",
        evidence: [
          {
            type: "http_response",
            description: "Publicly accessible credential file with sensitive data patterns",
            url: `https://${domain}${rPath}`,
            snippet: `HTTP Status: 200 OK\n\nRedacted content preview:\n${redacted}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if (rPath === "/server-status" && result.body.includes("Apache Server Status")) {
      results.findings.push({
        title: `Apache Server Status Page Exposed on ${domain}`,
        description: `The Apache server-status page is publicly accessible at ${domain}/server-status. This reveals server internals including active connections, request details, and server configuration.`,
        severity: "medium",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Restrict access to /server-status to internal networks or specific IP addresses only.",
        evidence: [
          {
            type: "http_response",
            description: "Apache server-status page publicly accessible",
            url: `https://${domain}${rPath}`,
            snippet: `HTTP Status: 200 OK\nContent includes: Apache Server Status\n\nPreview:\n${result.body.substring(0, 300)}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if ((rPath === "/actuator" || rPath === "/actuator/health") && result.body && (result.body.includes('"status"') || result.body.includes("UP"))) {
      results.findings.push({
        title: `Spring Boot Actuator Exposed on ${domain}`,
        description: `The actuator endpoint at ${domain}${rPath} is publicly accessible. This may expose application health, metrics, and internal state.`,
        severity: "medium",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Restrict access to actuator endpoints. Use Spring Security to protect /actuator.",
        evidence: [
          {
            type: "http_response",
            description: "Spring Boot actuator publicly accessible",
            url: `https://${domain}${rPath}`,
            snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 300)}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if ((rPath === "/phpinfo.php" || rPath === "/info.php") && (result.body.includes("PHP Version") || result.body.includes("phpinfo()"))) {
      results.findings.push({
        title: `PHP Info Page Exposed on ${domain}`,
        description: `The phpinfo page at ${domain}${rPath} is publicly accessible. This reveals PHP version, loaded modules, environment variables, and server configuration.`,
        severity: "medium",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Remove or restrict access to phpinfo pages. Use them only in development environments.",
        evidence: [
          {
            type: "http_response",
            description: "phpinfo page publicly accessible",
            url: `https://${domain}${rPath}`,
            snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 300)}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if (result.body && (result.body.includes("Index of /") || result.body.includes("Directory listing"))) {
      results.findings.push({
        title: `Directory Listing Exposed on ${domain}${rPath}`,
        description: `Directory listing is enabled at ${domain}${rPath}. This exposes file structure and potentially sensitive files to enumeration.`,
        severity: "medium",
        category: "data_leak",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Disable directory listing in web server configuration.",
        evidence: [
          {
            type: "http_response",
            description: "Directory listing detected",
            url: `https://${domain}${rPath}`,
            snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 400)}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if (OSINT_DOCUMENT_PATHS.includes(rPath)) {
      results.findings.push({
        title: `Exposed Document Path (${rPath}) on ${domain}`,
        description: `The path ${rPath} at ${domain} is publicly accessible. This may expose documents, backups, or uploads.`,
        severity: "medium",
        category: "data_leak",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Restrict access to document directories. Ensure sensitive files are not publicly accessible.",
        evidence: [
          {
            type: "http_response",
            description: "Document path publicly accessible",
            url: `https://${domain}${rPath}`,
            snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 400)}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if (rPath === "/robots.txt" && result.body) {
      const disallowLines = result.body.split("\n").filter(l => l.trim().toLowerCase().startsWith("disallow:"));
      const sensitiveDisallows = disallowLines.filter(l => {
        const p = l.split(":").slice(1).join(":").trim().toLowerCase();
        return /admin|backup|internal|private|secret|config|database|wp-admin|phpmyadmin|dashboard|api|debug/.test(p);
      });
      if (sensitiveDisallows.length > 0) {
        exposedPaths.push({ path: rPath, label, status: 200, snippet: result.body.substring(0, 500) });
      }
    }

    if ((rPath === "/swagger.json" || rPath === "/api/docs" || rPath === "/openapi.json") && result.body.length > 50) {
      results.findings.push({
        title: `Exposed API Documentation (Swagger/OpenAPI) on ${domain}`,
        description: `${rPath} at ${domain} is publicly accessible. This exposes API structure, endpoints, and potentially sensitive schema details.`,
        severity: "low",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "3.1",
        remediation: `Restrict access to ${rPath} or ensure it does not expose sensitive API details.`,
        evidence: [
          {
            type: "http_response",
            description: "Swagger/OpenAPI documentation publicly accessible",
            url: `https://${domain}${rPath}`,
            snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 400)}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }
  }

  if (exposedPaths.length > 0) {
    for (const ep of exposedPaths) {
      if (ep.path === "/robots.txt") {
        results.findings.push({
          title: `Robots.txt Reveals Sensitive Paths on ${domain}`,
          description: `The robots.txt file on ${domain} contains Disallow entries that hint at sensitive internal paths (admin panels, backups, databases, etc.). While robots.txt is informational, it gives attackers a map of hidden endpoints.`,
          severity: "info",
          category: "information_disclosure",
          affectedAsset: domain,
          cvssScore: "2.0",
          remediation: "Review robots.txt entries. Ensure listed paths are properly authenticated rather than relying on obscurity.",
          evidence: [
            {
              type: "http_response",
              description: "robots.txt reveals sensitive paths",
              url: `https://${domain}/robots.txt`,
              snippet: ep.snippet,
              source: "HTTP GET request",
              verifiedAt: now,
            },
          ],
        });
      } else {
        results.findings.push({
          title: `Publicly Accessible ${ep.label} on ${domain}`,
          description: `${ep.label} (${ep.path}) is publicly accessible at ${domain}. This may expose internal API structure or application details.`,
          severity: "low",
          category: "information_disclosure",
          affectedAsset: domain,
          cvssScore: "3.1",
          remediation: `Restrict access to ${ep.path} or ensure it does not expose sensitive information.`,
          evidence: [
            {
              type: "http_response",
              description: `${ep.label} publicly accessible`,
              url: `https://${domain}${ep.path}`,
              snippet: `HTTP Status: ${ep.status}\n\nPreview:\n${ep.snippet}`,
              source: "HTTP GET request",
              verifiedAt: now,
            },
          ],
        });
      }
    }
  }

  const dkimRecord = dkimTxt?.flat().find((r) => r.startsWith("v=DKIM1") || r.includes("p="));
  const cloudProviders = extractCloudProvidersFromSPF(spfAnalysis.record, mxRecords);
  results.reconData.emailSecurity = {
    spf: spfAnalysis,
    dmarc: dmarcAnalysis,
    dkim: {
      found: !!dkimRecord,
      selector: "default",
      record: dkimRecord ? dkimRecord.substring(0, 200) : undefined,
    },
    cloudProviders,
    mx: mxRecords,
    ns: nsRecords,
    txtRecords: txtRecords.flat(),
  };

  results.reconData.pathChecks = Object.fromEntries(
    pathCheckResults
      .filter((r) => r.result)
      .map((r) => {
        const { status, body, finalUrl } = r.result!;
        const validated = validatePathResponse(status, body, finalUrl, r.path);
        return [
          r.path,
          {
            status,
            accessible: validated.responseType === "success",
            responseType: validated.responseType,
            severity: validated.severity,
            validated: validated.validated,
            confidence: validated.confidence,
            redirectTarget: validated.redirectTarget,
          },
        ];
      }),
  );

  for (const r of pathCheckResults) {
    if (!r.result) continue;
    const { path: rPath, result } = r;
    if (rPath === "/robots.txt" && result.status === 200 && result.body) {
      results.reconData.robotsTxt = result.body;
      break;
    }
  }
  for (const r of pathCheckResults) {
    if (!r.result) continue;
    const { path: rPath, result } = r;
    if (rPath === "/.well-known/security.txt" && result.status === 200 && result.body) {
      results.reconData.securityTxt = { raw: result.body, parsed: parseSecurityTxt(result.body) };
      break;
    }
  }

  // Probe sensitive paths from robots.txt
  const robotsTxtContent = results.reconData.robotsTxt;
  if (robotsTxtContent) {
    const sensitiveRobotPaths = extractSensitiveRobotsPaths(robotsTxtContent);
    const robotsProbeLimit = gold ? 50 : 15;
    const robotsToProbe = sensitiveRobotPaths.filter(p => !osintPaths.includes(p)).slice(0, robotsProbeLimit);
    if (robotsToProbe.length > 0) {
      log.info({ count: robotsToProbe.length, domain }, "Probing sensitive paths from robots.txt");
      const robotsResults = await runWithConcurrency(robotsToProbe, 4, async (p) => {
        const res = await httpGet(`https://${domain}${p}`);
        return { path: p, result: res };
      }, signal);
      for (const { path: rPath, result } of robotsResults.filter(r => r != null)) {
        if (!result || result.status !== 200 || !result.body) continue;
        if (soft404Fingerprint) {
          const fp = `${result.body.length}:${result.body.slice(0, 100).replace(/\s+/g, "")}`;
          if (fp === soft404Fingerprint) continue;
        }
        results.findings.push({
          title: `Sensitive Path from robots.txt Accessible on ${domain}: ${rPath}`,
          description: `A path listed in robots.txt (${rPath}) is publicly accessible. This path was hidden from crawlers but responds with content, potentially exposing sensitive data.`,
          severity: "medium",
          category: "data_leak",
          affectedAsset: domain,
          cvssScore: "5.3",
          remediation: `Restrict access to ${rPath} with proper authentication instead of relying on robots.txt.`,
          evidence: [{
            type: "http_response",
            description: "Path listed in robots.txt is publicly accessible",
            url: `https://${domain}${rPath}`,
            snippet: `HTTP Status: 200\nSource: robots.txt Disallow entry\nPreview:\n${result.body.substring(0, 300)}`,
            source: "robots.txt + HTTP GET",
            verifiedAt: now,
          }],
        });
      }
    }
  }

  checkAborted(signal);
  await report("Fetching sitemap and main page...", 80, "path_checks", 25);

  const sitemapUrls = await fetchSitemapUrls(domain, sitemapLimit);
  results.reconData.sitemapUrls = sitemapUrls;

  const docUrls = sitemapUrls.filter((u) => {
    try {
      return DOCUMENT_EXTENSIONS.test(new URL(u).pathname);
    } catch {
      return false;
    }
  }).slice(0, gold ? 200 : 30);
  const docResults = await runWithConcurrency(
    docUrls,
    4,
    async (url) => {
      const res = await httpGet(url);
      return res && res.status === 200 ? { url, status: res.status } : null;
    },
    signal,
  );
  for (const dr of docResults) {
    if (dr) {
      results.findings.push({
        title: `Exposed Document in Sitemap on ${domain}`,
        description: `A document URL from the sitemap is publicly accessible: ${dr.url}. This may expose sensitive data.`,
        severity: "medium",
        category: "data_leak",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Restrict access to document files. Ensure sensitive documents are not linked in public sitemaps.",
        evidence: [
          {
            type: "http_response",
            description: "Document from sitemap publicly accessible",
            url: dr.url,
            snippet: `HTTP Status: ${dr.status} OK`,
            source: "HTTP GET request",
            verifiedAt: now,
          },
        ],
      });
    }
  }

  const mainPage = await httpGetMainPage(`https://${domain}`);
  if (mainPage) {
    results.reconData.cookies = parseSetCookie(mainPage.setCookieStrings);
    results.reconData.responseHeaders = mainPage.headers;
    results.reconData.techStack = detectTechStack(mainPage.body, mainPage.headers);
    results.reconData.socialTags = parseSocialTags(mainPage.body);
  }

  // Email harvesting with source attribution
  const emailSources = new Map<string, Set<string>>();
  function addEmail(email: string, source: string) {
    const lower = email.toLowerCase();
    if (!emailSources.has(lower)) emailSources.set(lower, new Set());
    emailSources.get(lower)!.add(source);
  }

  if (mainPage?.body) {
    for (const e of extractEmailsFromText(mainPage.body, domain)) addEmail(e, "Main page");
  }
  const securityTxtData = results.reconData.securityTxt;
  if (securityTxtData?.raw) {
    for (const e of extractEmailsFromText(securityTxtData.raw, domain)) addEmail(e, "security.txt");
  }
  const sitemapSample = sitemapUrls.slice(0, gold ? 50 : 10);
  for (const surl of sitemapSample) {
    const res = await httpGet(surl);
    if (res?.body && res.status === 200) {
      for (const e of extractEmailsFromText(res.body, domain)) addEmail(e, "Sitemap");
    }
  }
  const EMAIL_PAGES_STANDARD = ["/about", "/contact", "/team", "/people", "/staff"];
  const EMAIL_PAGES_GOLD = [...EMAIL_PAGES_STANDARD, "/leadership", "/careers", "/jobs", "/press", "/news",
    "/blog", "/support", "/help", "/legal", "/imprint", "/about-us", "/contact-us", "/our-team", "/who-we-are"];
  const emailPages = gold ? EMAIL_PAGES_GOLD : EMAIL_PAGES_STANDARD;
  const emailPageResults = await runWithConcurrency(emailPages, 4, async (p) => {
    const res = await httpGet(`https://${domain}${p}`);
    if (res?.body && res.status === 200) return { emails: extractEmailsFromText(res.body, domain), source: p };
    return { emails: [], source: p };
  });
  for (const { emails, source } of emailPageResults) {
    for (const e of emails) addEmail(e, `Web page (${source})`);
  }

  // DNS email extraction
  for (const e of extractEmailsFromDNS(txtRecords, dmarcTxt)) addEmail(e, "DNS records (SPF/DMARC)");

  // WHOIS email extraction
  const whoisEmails = extractEmailsFromWhois(domainInfo as Record<string, string> | null);
  for (const e of whoisEmails) addEmail(e, "WHOIS registration");

  // Filter to domain-relevant emails and build finding
  const domainEmails = new Map<string, Set<string>>();
  const otherEmails: string[] = [];
  for (const [email, sources] of Array.from(emailSources)) {
    if (email.endsWith(`@${domain}`) || email.endsWith(`.${domain}`)) {
      domainEmails.set(email, sources);
    } else {
      otherEmails.push(email);
    }
  }

  if (domainEmails.size > 0) {
    const sourceGroups = new Map<string, string[]>();
    for (const [email, sources] of Array.from(domainEmails)) {
      const redacted = `${email.split("@")[0].slice(0, 2)}***@${email.split("@")[1]}`;
      for (const src of Array.from(sources)) {
        if (!sourceGroups.has(src)) sourceGroups.set(src, []);
        sourceGroups.get(src)!.push(redacted);
      }
    }
    const sourceLines = Array.from(sourceGroups.entries())
      .map(([src, emails]) => `${src}: ${emails.slice(0, 3).join(", ")}${emails.length > 3 ? ` (+${emails.length - 3} more)` : ""}`)
      .join("\n");
    results.findings.push({
      title: `Discovered ${domainEmails.size} email address(es) for ${domain}`,
      description: `Email addresses associated with ${domain} were found across ${sourceGroups.size} source(s) including web pages, DNS records, and WHOIS data.`,
      severity: "info",
      category: "osint_exposure",
      affectedAsset: domain,
      cvssScore: "2.0",
      remediation: "Consider whether exposed emails should be public. Use contact forms instead of raw email addresses where possible.",
      evidence: [{
        type: "osint",
        description: "Email addresses discovered from public sources",
        snippet: `Found ${domainEmails.size} email(s) from ${sourceGroups.size} source(s):\n${sourceLines}`,
        source: Array.from(sourceGroups.keys()).join(", "),
        verifiedAt: now,
      }],
    });
  }

  if (otherEmails.length > 0) {
    results.findings.push({
      title: `WHOIS/DNS Contact Emails Discovered for ${domain}`,
      description: `${otherEmails.length} contact email(s) not matching the target domain were found in WHOIS or DNS records.`,
      severity: "info",
      category: "osint_exposure",
      affectedAsset: domain,
      cvssScore: "2.0",
      remediation: "Review WHOIS privacy settings. Consider using domain privacy protection.",
      evidence: [{
        type: "osint",
        description: "Non-domain contact emails from WHOIS/DNS",
        snippet: `Contact emails: ${otherEmails.slice(0, 5).join(", ")}${otherEmails.length > 5 ? ` (+${otherEmails.length - 5} more)` : ""}`,
        source: "WHOIS lookup, DNS records",
        verifiedAt: now,
      }],
    });
  }

  // --- Phase 3: External API integrations ---
  checkAborted(signal);
  await report("Checking credential leaks (HIBP, dorks)...", 75, "credential_apis", 40);

  // 3A: Tavily Google dork for credentials
  try {
    const { searchTavilyDork } = await import("../tavily-service.js");
    const credDorkQueries = gold
      ? [`site:pastebin.com "${domain}" password OR api_key`, `site:github.com "${domain}" password OR secret`, `"${domain}" filetype:env password`]
      : [`site:pastebin.com "${domain}" password OR api_key OR token`];
    for (const query of credDorkQueries) {
      const dorkResults = await searchTavilyDork(query);
      for (const dorkR of dorkResults) {
        if (!dorkR.url || !dorkR.title) continue;
        results.findings.push({
          title: `Potential Credential Leak Found via Google Dorking for ${domain}`,
          description: `A search result mentioning ${domain} with credential-related keywords was found on ${new URL(dorkR.url).hostname}.`,
          severity: "medium",
          category: "leaked_credential",
          affectedAsset: domain,
          cvssScore: "5.3",
          remediation: "Investigate the URL for exposed credentials. Request takedown if confirmed.",
          evidence: [{
            type: "osint",
            description: "Google dork result mentioning credentials",
            url: dorkR.url,
            snippet: `Title: ${dorkR.title}\nURL: ${dorkR.url}\nExcerpt: ${dorkR.content.slice(0, 300)}`,
            source: "Tavily Google Dork Search",
            verifiedAt: now,
          }],
        });
      }
    }
  } catch (err) {
    log.warn({ err }, "Tavily credential dork failed");
  }

  // 3A: Tavily Google dork for documents
  try {
    const { searchTavilyDork } = await import("../tavily-service.js");
    const docDorkQueries = gold
      ? [`site:${domain} filetype:pdf OR filetype:doc OR filetype:xlsx OR filetype:csv`, `site:${domain} filetype:sql OR filetype:bak OR filetype:log`]
      : [`site:${domain} filetype:pdf OR filetype:doc OR filetype:xlsx`];
    for (const query of docDorkQueries) {
      const dorkResults = await searchTavilyDork(query);
      for (const dorkR of dorkResults) {
        if (!dorkR.url) continue;
        results.findings.push({
          title: `Exposed Document Found via Google Dorking for ${domain}`,
          description: `A document associated with ${domain} was found indexed by search engines.`,
          severity: "medium",
          category: "data_leak",
          affectedAsset: domain,
          cvssScore: "5.3",
          remediation: "Review the document for sensitive content. Remove from public access if needed.",
          evidence: [{
            type: "osint",
            description: "Document found via Google dork search",
            url: dorkR.url,
            snippet: `Title: ${dorkR.title}\nURL: ${dorkR.url}\nExcerpt: ${dorkR.content.slice(0, 300)}`,
            source: "Tavily Google Dork Search",
            verifiedAt: now,
          }],
        });
      }
    }
  } catch (err) {
    log.warn({ err }, "Tavily document dork failed");
  }

  // 3B: HIBP Pwned Passwords check on any extracted credential values
  const credentialValues: string[] = [];
  for (const r of pathCheckResults) {
    if (!r.result || r.result.status !== 200 || !r.result.body) continue;
    if (!OSINT_CREDENTIAL_PATHS.includes(r.path) && r.path !== "/.env" && r.path !== "/.git/config") continue;
    const matches = r.result.body.match(/(?:password|passwd|secret|token|api_key|apikey|db_pass|database_url)\s*[=:]\s*["']?([^\s"'\r\n]+)["']?/gi);
    if (matches) {
      for (const m of matches) {
        const val = m.split(/[=:]\s*["']?/)[1]?.replace(/["']$/, "");
        if (val && val.length >= 6 && val !== "null" && val !== "undefined" && val !== "true" && val !== "false") {
          credentialValues.push(val);
        }
      }
    }
  }
  if (credentialValues.length > 0) {
    log.info({ count: Math.min(credentialValues.length, gold ? 20 : 5) }, "Checking extracted credentials against HIBP");
    const hibpResults = await checkHIBPPasswords(credentialValues, gold);
    for (const { redacted, breachCount } of hibpResults) {
      results.findings.push({
        title: `Breached Password Detected in Exposed File on ${domain}`,
        description: `A password extracted from an exposed configuration file has been found in ${breachCount.toLocaleString()} known data breach(es). This indicates the credential is compromised.`,
        severity: "critical",
        category: "leaked_credential",
        affectedAsset: domain,
        cvssScore: "9.8",
        remediation: "Immediately rotate this credential. Audit all systems using this password.",
        evidence: [{
          type: "osint",
          description: "Password found in known data breaches",
          snippet: `Redacted credential: ${redacted}\nFound in ${breachCount.toLocaleString()} known breach(es)`,
          source: "Have I Been Pwned Pwned Passwords API (k-anonymity)",
          verifiedAt: now,
        }],
      });
    }
  }

  // 3C: S3 bucket enumeration
  checkAborted(signal);
  await report("Checking S3 bucket patterns...", 85, "s3_check", 20);
  try {
    const s3BucketResults = await checkS3Buckets(domain, gold);
    for (const { bucket, listable } of s3BucketResults) {
      results.findings.push({
        title: listable ? `Publicly Listable S3 Bucket Found: ${bucket}` : `S3 Bucket Exists for ${domain}: ${bucket}`,
        description: listable
          ? `The S3 bucket "${bucket}" is publicly listable, potentially exposing all stored files and data.`
          : `An S3 bucket named "${bucket}" exists and is associated with ${domain}.`,
        severity: listable ? "high" : "info",
        category: "data_leak",
        affectedAsset: domain,
        cvssScore: listable ? "7.5" : "2.0",
        remediation: listable
          ? "Immediately disable public access on this S3 bucket. Review bucket policies and ACLs."
          : "Verify this bucket's access policies are properly configured.",
        evidence: [{
          type: "osint",
          description: listable ? "S3 bucket is publicly listable" : "S3 bucket exists",
          url: `https://${bucket}.s3.amazonaws.com/`,
          snippet: listable ? "Bucket returns ListBucketResult XML — all objects are publicly enumerable" : "Bucket exists but is not publicly listable",
          source: "S3 bucket enumeration",
          verifiedAt: now,
        }],
      });
    }
  } catch (err) {
    log.warn({ err }, "S3 bucket check failed");
  }

  // 3D+3E: PGP key server + crt.sh email extraction (gold only)
  if (gold) {
    try {
      const [pgpEmails, crtEmails] = await Promise.all([
        searchPGPKeyServer(domain),
        extractEmailsFromCrtSh(domain),
      ]);
      for (const e of pgpEmails) addEmail(e, "PGP key server");
      for (const e of crtEmails) addEmail(e, "Certificate Transparency (crt.sh)");
      // Check if these added new domain emails not already in findings
      const newDomainEmails: string[] = [];
      for (const e of [...pgpEmails, ...crtEmails]) {
        if ((e.endsWith(`@${domain}`) || e.endsWith(`.${domain}`)) && !domainEmails.has(e.toLowerCase())) {
          newDomainEmails.push(e);
        }
      }
      if (newDomainEmails.length > 0) {
        results.findings.push({
          title: `${newDomainEmails.length} Additional Email(s) Found via PGP/Certificate Transparency for ${domain}`,
          description: `Additional email addresses were discovered through PGP key servers and Certificate Transparency logs.`,
          severity: "info",
          category: "osint_exposure",
          affectedAsset: domain,
          cvssScore: "2.0",
          remediation: "Review whether these email addresses should be publicly associated with your domain.",
          evidence: [{
            type: "osint",
            description: "Emails from PGP key servers and certificate transparency",
            snippet: `Emails: ${newDomainEmails.slice(0, 5).map(e => `${e.split("@")[0].slice(0, 2)}***@${e.split("@")[1]}`).join(", ")}`,
            source: "PGP key server, crt.sh",
            verifiedAt: now,
          }],
        });
      }
    } catch (err) {
      log.warn({ err }, "PGP/crt.sh email search failed");
    }
  }

  const firstIp = dnsRecords.a && dnsRecords.a[0];
  const osintPortList = gold ? GOLD_PORTS : [21, 22, 80, 443, 8080, 8443, 3306, 5432, 27017, 6379, 5984];
  const nonHttpPorts = [21, 22, 25, 53, 110, 143, 445, 993, 995, 1433, 3306, 5432, 27017, 6379, 5984, 11211];
  if (firstIp) {
    const [location, openPorts] = await Promise.all([
      getServerLocation(firstIp),
      scanOpenPorts(firstIp, osintPortList),
    ]);
    if (location) results.reconData.serverLocation = location;
    results.reconData.openPorts = openPorts;
    const exposedNonHttp = openPorts.filter((p) => nonHttpPorts.includes(p));
    if (exposedNonHttp.length > 0) {
      const portNames: Record<number, string> = { 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 5984: "CouchDB", 11211: "Memcached", 27017: "MongoDB" };
      results.findings.push({
        title: `Exposed Non-HTTP Ports on ${domain}`,
        description: `Non-HTTP ports are open on ${firstIp}: ${exposedNonHttp.map((p) => `${p} (${portNames[p] || "unknown"})`).join(", ")}. This reveals infrastructure details.`,
        severity: "medium",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Restrict access to database and management ports. Use firewall rules to limit exposure.",
        evidence: [
          {
            type: "port_scan",
            description: "Open non-HTTP ports detected",
            snippet: `Open ports: ${exposedNonHttp.join(", ")}`,
            source: "TCP port scan",
            verifiedAt: now,
          },
        ],
      });
    }
  }
  const dnssec = await checkDNSSEC(domain);
  results.reconData.dnssec = dnssec;

  // API Security Discovery
  try {
    await report("Discovering API endpoints...", 92, "api_discovery");
    const apiResults = await discoverAPIs(domain, signal);
    results.findings.push(...apiResults.findings);
    if (apiResults.endpoints.length > 0) {
      results.reconData.apiDiscovery = {
        endpoints: apiResults.endpoints,
        openApiSpec: apiResults.openApiSpec ? { title: (apiResults.openApiSpec.info as Record<string, unknown>)?.title, version: (apiResults.openApiSpec.info as Record<string, unknown>)?.version, pathCount: apiResults.openApiSpec.paths ? Object.keys(apiResults.openApiSpec.paths as Record<string, unknown>).length : 0 } : null,
      };
    }
  } catch (err) {
    log.warn({ err }, "API discovery scan failed");
  }

  // Secret Exposure Scanning
  try {
    await report("Scanning for exposed secrets...", 96, "secret_scan");
    const secretResults = await scanSecrets(domain, signal);
    results.findings.push(...secretResults.findings);
    if (secretResults.matches.length > 0 || secretResults.leakyPaths.length > 0) {
      results.reconData.secretExposure = {
        matchCount: secretResults.matches.length,
        leakyPaths: secretResults.leakyPaths,
        patternTypes: Array.from(new Set(secretResults.matches.map(m => m.patternName))),
      };
    }
  } catch (err) {
    log.warn({ err }, "Secret exposure scan failed");
  }

  await report("OSINT scan complete.", 100, "build_modules", 0);
  log.info({ domain, findings: results.findings.length }, "OSINT scan complete");
  return results;
}
