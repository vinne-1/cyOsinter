import dns from "dns/promises";
import { enrichIP, fetchBGPView, shodanHostLookup } from "../api-integrations.js";
import { createLogger } from "../logger.js";
import {
  SUBDOMAIN_WORDLIST_SOURCE, STANDARD_SUBDOMAIN_WORDLIST_CAP, STANDARD_PROBE_BATCH,
  STANDARD_SUBDOMAIN_CERT_CHECK, STANDARD_PORTS,
  GOLD_SUBDOMAIN_WORDLIST_CAP, GOLD_PROBE_BATCH, GOLD_SUBDOMAIN_CERT_CHECK, GOLD_PORTS,
  isFullCoverage, checkAborted, loadSubdomainWordlist,
  type ScanProgressCallback, type ScanOptions, type ScanResults,
} from "./constants.js";
import { resolveDNS, getNSRecords } from "./dns.js";
import { fetchJSON, httpHead, httpGet } from "./http.js";
import { getCertificateInfo } from "./tls.js";
import { enumerateTlsVersions, buildTlsProtocolFindings } from "./tls-protocols.js";
import { scanOpenPorts, checkSecurityHeaders, detectServerInfo, detectWAF, detectCDN } from "./detection.js";
import { runWithConcurrency, makeConcurrencyProgress } from "./utils.js";
import { scanSubdomainTakeover } from "./takeover.js";
import { resolveProfile } from "./stealth.js";
import { runPortScan } from "./port-scan.js";
import { runCloudDiscovery } from "./cloud-discovery.js";
import { runContainerDetection } from "./container-detection.js";
import { buildPerAssetFindings } from "./per-asset-findings.js";
import { findVulnerableLibraries, buildLibraryFindings } from "./js-library-cves.js";
import { generatePermutations } from "./permutation.js";
import { inScopeSans } from "./tls.js";
import { fetchFaviconHash, clusterByFavicon } from "./favicon.js";
import { runWAFBypassTest } from "./waf-bypass.js";
import { fetchSubdomainsFromFreeSources, fetchWaybackUrls, reverseDnsLookup, reverseIpLookup, confidenceFromSources, type PassiveDiscovery } from "./passive-sources.js";
import { assessServiceExposure } from "./service-exposure.js";
import { probeHosts } from "./http-probe.js";
import { runAsnExpansion } from "./asn-expansion.js";

/** CVSS score by severity band for findings produced by advanced sub-modules. */
const SEVERITY_CVSS: Record<string, string> = { critical: "9.1", high: "7.5", medium: "5.3", low: "3.1", info: "0.0" };

/** Adapt a sub-module finding (no cvss/evidence) into a full VerifiedFinding. */
function toVerifiedFinding(
  f: { title: string; description: string; severity: string; category: string; affectedAsset: string; remediation: string },
  evidence: ScanResults["findings"][number]["evidence"] = [],
): ScanResults["findings"][number] {
  return { ...f, cvssScore: SEVERITY_CVSS[f.severity] ?? "5.0", evidence };
}

const log = createLogger("scanner");

/** Shape-compatible empty result for the passive-discovery catch path. */
function emptyPassiveDiscovery(): PassiveDiscovery {
  return { subdomains: [], bySource: {}, provenance: {}, sourcesFailed: [] };
}

/**
 * Detects a wildcard record by asking for a name that cannot exist.
 *
 * Covers AAAA as well as A. Once discovery started accepting IPv6-only hosts, an
 * IPv4-only wildcard check became a hole in the other direction: a zone whose
 * wildcard answers AAAA would have every generated permutation "resolve" on
 * IPv6 and pass the filter, which is precisely the flood the filter exists to
 * prevent.
 */
async function checkDNSWildcard(domain: string): Promise<{ isWildcard: boolean; wildcardIPs: Set<string> }> {
  const random = Math.random().toString(36).slice(2, 12);
  const testHost = `nxdomain-${random}.${domain}`;
  const [v4, v6] = await Promise.allSettled([dns.resolve4(testHost), dns.resolve6(testHost)]);
  const addrs = [
    ...(v4.status === "fulfilled" ? v4.value : []),
    ...(v6.status === "fulfilled" ? v6.value : []),
  ];
  if (addrs.length > 0) {
    return { isWildcard: true, wildcardIPs: new Set(addrs) };
  }
  return { isWildcard: false, wildcardIPs: new Set() };
}

async function enumerateSubdomainsBruteforce(
  domain: string,
  cap = 1000,
  concurrency = 20,
  signal?: AbortSignal,
  excludeIPs?: Set<string>,
  onProgress?: (completed: number, total: number) => void,
): Promise<{ resolved: string[]; tried: number; wildcardDetected: boolean; wildcardIPs: Set<string> }> {
  const { isWildcard, wildcardIPs } = excludeIPs
    ? { isWildcard: excludeIPs.size > 0, wildcardIPs: excludeIPs }
    : await checkDNSWildcard(domain);

  if (isWildcard) {
    log.info({ domain, wildcardIPs: Array.from(wildcardIPs) }, "Wildcard DNS detected — filtering false positives");
  }

  // Pass the caller's cap through so gold mode (cap = large) loads the FULL
  // wordlist. Without this, loadSubdomainWordlist() defaulted to the standard
  // 2000-entry cap even in gold, silently limiting enumeration breadth.
  const prefixes = await loadSubdomainWordlist(cap);
  const toTry = prefixes.slice(0, cap).map((prefix) => `${prefix}.${domain}`);
  const resolved: string[] = [];
  const results = await runWithConcurrency(
    toTry,
    concurrency,
    async (hostname) => {
      const d = await resolveDNS(hostname);
      if (!d.resolved) return null;
      // Every address it has is one the wildcard hands out ⇒ it is the wildcard
      // answering, not a host. Checked across both families, since a host with a
      // unique AAAA is a real host even if its A is the wildcard's.
      const addrs = [...d.ips, ...d.ipv6];
      if (isWildcard && addrs.length > 0 && d.cnames.length === 0 && addrs.every((ip) => wildcardIPs.has(ip))) return null;
      return hostname;
    },
    signal,
    onProgress,
  );
  for (const r of results) {
    if (r) resolved.push(r);
  }
  return { resolved: Array.from(new Set(resolved)).sort(), tried: toTry.length, wildcardDetected: isWildcard, wildcardIPs };
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
  const profile = resolveProfile(options?.mode);
  // Full-coverage breadth (gold + safe). `gold` keeps its name below; safe mode
  // shares the same breadth and differs only in pacing (handled by stealth.ts).
  const gold = isFullCoverage(options);
  const stealth = profile.stealth;
  const results: ScanResults = { subdomains: [], assets: [], findings: [], reconData: {} };
  const now = new Date().toISOString();
  const report = async (msg: string, pct: number, step: string, eta?: number) => {
    checkAborted(signal);
    if (onProgress) await onProgress(msg, pct, step, eta);
  };
  // Fire-and-forget progress emitter for use inside long concurrent loops, so
  // the bar advances smoothly instead of plateauing. Never throws (best-effort).
  const emitProgress = (msg: string, pct: number, step: string, eta?: number) => {
    if (onProgress) void Promise.resolve(onProgress(msg, pct, step, eta)).catch(() => {});
  };

  // Baseline for change detection. Absent means "no baseline", not "empty".
  const knownHostSet = options?.knownHosts
    ? new Set(options.knownHosts.map((h) => h.toLowerCase()))
    : null;

  const subdomainCap = gold ? GOLD_SUBDOMAIN_WORDLIST_CAP : STANDARD_SUBDOMAIN_WORDLIST_CAP;
  const probeBatchSize = gold ? GOLD_PROBE_BATCH : STANDARD_PROBE_BATCH;
  const certCheckLimit = gold ? GOLD_SUBDOMAIN_CERT_CHECK : STANDARD_SUBDOMAIN_CERT_CHECK;
  const portList = gold ? GOLD_PORTS : STANDARD_PORTS;

  checkAborted(signal);
  log.info({ domain, mode: profile.mode, stealth }, "Starting EASM scan");
  await report("Enumerating subdomains (crt.sh + bruteforce)...", 0, "enumerate_subdomains", 180);

  // Smooth 1→14% progress across the (long) subdomain brute-force DNS sweep.
  const bruteProgress = makeConcurrencyProgress(1, 14, (pct, done, total) =>
    emitProgress(`Enumerating subdomains — resolved ${done}/${total} candidates...`, pct, "enumerate_subdomains"));

  const [crtShSubdomains, mainDns, certInfo, nsRecords, bruteforceResult, passiveSources] = await Promise.all([
    enumerateSubdomainsCrtSh(domain),
    resolveDNS(domain),
    getCertificateInfo(domain),
    getNSRecords(domain),
    enumerateSubdomainsBruteforce(domain, subdomainCap === 0 ? 99999 : subdomainCap, profile.dnsConcurrency, signal, undefined, bruteProgress),
    // Free, keyless passive sources (CT mirrors, passive DNS, archives). Best-effort.
    fetchSubdomainsFromFreeSources(domain).catch(() => emptyPassiveDiscovery()),
  ]);

  checkAborted(signal);
  const bruteforceSet = new Set(bruteforceResult.resolved);
  const combinedSubdomains = Array.from(
    new Set([...crtShSubdomains, ...bruteforceResult.resolved, ...passiveSources.subdomains]),
  ).sort();

  /*
   * Certificate SANs as a discovery source.
   *
   * `getCertificateInfo` has always returned `altNames`, and they were stored
   * for display and nothing else. A SAN list is the organisation's own statement
   * about which hostnames it serves — better evidence than a wordlist guess, and
   * more current than a CT index, because it comes from the live handshake
   * rather than a log of what was once issued. The certificate was already
   * fetched, so this is analysis rather than traffic.
   *
   * Names are still RESOLVED before being accepted: a certificate routinely
   * outlives the host it was issued for, and an unresolvable SAN is a
   * decommissioned name, not an asset.
   */
  // Set membership, not `Array.includes`. With the keyed passive sources this
  // array reaches tens of thousands of entries, and `includes` inside a loop is
  // O(n²) — 48k hosts against 15k permutation candidates is ~10^8 comparisons.
  const knownSet = new Set(combinedSubdomains);
  const sanCandidates = inScopeSans(certInfo?.altNames ?? [], domain)
    .filter((h) => h !== domain && !knownSet.has(h));
  let sanFound: string[] = [];
  if (sanCandidates.length > 0) {
    const sanResults = await runWithConcurrency(
      sanCandidates,
      profile.dnsConcurrency,
      async (hostname) => {
        const d = await resolveDNS(hostname);
        return d.resolved ? hostname : null;
      },
      signal,
    );
    sanFound = Array.from(new Set(sanResults.filter((h): h is string => Boolean(h)))).sort();
    if (sanFound.length > 0) {
      for (const h of sanFound) {
        if (!knownSet.has(h)) { knownSet.add(h); combinedSubdomains.push(h); }
      }
      combinedSubdomains.sort();
      log.info({ domain, candidates: sanCandidates.length, found: sanFound.length }, "Certificate SAN discovery complete");
    }
  }

  /*
   * Permutation — the only discovery method that learns THIS target's naming
   * convention rather than guessing from a fixed list.
   *
   * crt.sh, the wordlist and the passive indexes can only return a name that
   * already exists somewhere: in a certificate, in a wordlist, in somebody's
   * index. A host that was never certificated, never crawled, and is not named
   * after a common word is invisible to all three. Generating candidates from
   * the hosts already found closes exactly that blind spot — see permutation.ts.
   *
   * Wildcard filtering is not optional here. On a wildcard domain every
   * generated name resolves, so without the same filter the bruteforce uses this
   * stage would invent thousands of hosts. It reuses the wildcard IPs that
   * bruteforce already measured rather than probing for them again.
   */
  const permutationCap = gold ? 15000 : 1500;
  let permutationFound: string[] = [];
  if (combinedSubdomains.length > 0 && permutationCap > 0) {
    const candidates = generatePermutations(domain, combinedSubdomains, { maxCandidates: permutationCap });
    if (candidates.length > 0) {
      await report(`Permuting ${combinedSubdomains.length} known hosts (${candidates.length} candidates)...`, 14, "enumerate_subdomains", 150);
      const wildcardIPs = bruteforceResult.wildcardIPs;
      const permResults = await runWithConcurrency(
        candidates,
        profile.dnsConcurrency,
        async (hostname) => {
          const d = await resolveDNS(hostname);
          if (!d.resolved) return null;
          // Same rule as the wordlist sweep, across both address families.
          const addrs = [...d.ips, ...d.ipv6];
          if (wildcardIPs.size > 0 && addrs.length > 0 && d.cnames.length === 0 && addrs.every((ip) => wildcardIPs.has(ip))) return null;
          return hostname;
        },
        signal,
      );
      permutationFound = Array.from(new Set(permResults.filter((h): h is string => Boolean(h)))).sort();
      if (permutationFound.length > 0) {
        for (const h of permutationFound) {
          if (!knownSet.has(h)) { knownSet.add(h); combinedSubdomains.push(h); }
        }
        combinedSubdomains.sort();
      }
      log.info(
        { domain, candidates: candidates.length, found: permutationFound.length },
        "Permutation discovery complete",
      );
      results.reconData.permutationDiscovery = {
        candidatesTried: candidates.length,
        hostsFound: permutationFound.length,
        // Named so a reader can see which hosts ONLY this method found.
        hosts: permutationFound,
      };
    }
  }
  results.subdomains = combinedSubdomains;

  // Provenance: which independent sources named each host. Merging the sets and
  // keeping only a count threw away the strongest free quality signal there is
  // — whether unrelated indexes agree. A name four sources report is very
  // likely real; one a single HTML scrape produced may be a parsing artefact.
  // The two local methods are folded in as sources of their own, and DNS
  // resolution (added later, once hosts are probed) outranks all of them: an
  // index can be stale, a live A record cannot.
  const discoverySources: Record<string, string[]> = {};
  for (const [host, sources] of Object.entries(passiveSources.provenance)) {
    discoverySources[host] = [...sources];
  }
  for (const host of crtShSubdomains) (discoverySources[host] ??= []).push("crtsh-direct");
  for (const host of bruteforceResult.resolved) (discoverySources[host] ??= []).push("dns-bruteforce");
  for (const host of permutationFound) (discoverySources[host] ??= []).push("dns-permutation");
  for (const host of sanFound) (discoverySources[host] ??= []).push("tls-san");
  for (const host of Object.keys(discoverySources)) {
    discoverySources[host] = Array.from(new Set(discoverySources[host])).sort();
  }
  results.reconData.discoverySources = discoverySources;
  results.reconData.discoveryConfidence = Object.fromEntries(
    Object.entries(discoverySources).map(([host, sources]) => [host, confidenceFromSources(sources)]),
  );

  if (Object.keys(passiveSources.bySource).length > 0) {
    results.reconData.passiveSources = passiveSources.bySource;
  }
  if (passiveSources.sourcesFailed.length > 0) {
    // A source that errored is not a source that found nothing. Recording the
    // difference keeps "we could not look here" out of "there was nothing here".
    results.reconData.passiveSourcesFailed = passiveSources.sourcesFailed;
    log.info({ domain, failed: passiveSources.sourcesFailed }, "some passive discovery sources were unavailable");
  }
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
  // Truncation is recorded, never silent: a reader has to be able to tell "this
  // estate has 300 hosts" from "we looked at 5,000 of 48,000".
  if (probeBatch.length < combinedSubdomains.length) {
    results.reconData.probeCoverage = {
      discovered: combinedSubdomains.length,
      probed: probeBatch.length,
      truncated: true,
    };
    log.warn(
      { discovered: combinedSubdomains.length, probed: probeBatch.length },
      "Probe batch truncated — more hosts were discovered than the profile probes",
    );
  }
  log.info({ count: probeBatch.length, tried: bruteforceResult.tried, resolved: bruteforceResult.resolved.length }, "Probing subdomains");

  const probeResults = await runWithConcurrency(
    probeBatch,
    stealth ? profile.dnsConcurrency : 20,
    async (sub) => {
      const subDns = await resolveDNS(sub);
      let httpResult = null;
      let httpsResult = null;
      if (subDns.resolved) {
        [httpsResult, httpResult] = await Promise.all([
          httpHead(`https://${sub}`).catch(() => null),
          httpHead(`http://${sub}`).catch(() => null),
        ]);
      }
      return { subdomain: sub, dns: subDns, httpResult, httpsResult };
    },
    signal,
    makeConcurrencyProgress(16, 52, (pct, done, total) =>
      emitProgress(`Probing subdomains for live hosts — ${done}/${total}...`, pct, "probe_subdomains")),
  );

  for (const r of probeResults) {
    if (r) {
      const probe = r;
      subdomainProbes.push(probe);
      if (probe.dns.resolved) {
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

  // Enriched probe: one GET per live host yields what an analyst actually
  // triages on — title, technologies, status, redirect target — for the same
  // round trip the old HEAD spent to learn only "something answered".
  await report(`Fingerprinting ${liveSubdomains.length} live hosts...`, 56, "http_probe", 60);
  const hostProbes = new Map<string, Awaited<ReturnType<typeof probeHosts>>[number]>();
  try {
    const probes = await probeHosts(liveSubdomains.map((p) => p.subdomain), {
      concurrency: stealth ? profile.dnsConcurrency : 20,
      signal,
      checkCleartext: gold,
      onProgress: (doneCount, total) =>
        emitProgress(`Fingerprinting live hosts — ${doneCount}/${total}...`, 56 + Math.round((doneCount / Math.max(1, total)) * 4), "http_probe"),
    });
    for (const pr of probes) hostProbes.set(pr.host, pr);
  } catch (err) {
    log.warn({ err, domain }, "host fingerprinting failed (non-fatal) — liveness data retained");
  }

  results.reconData.discoveredDomains = liveSubdomains.map((p) => {
    const respHeaders = (p.httpsResult?.headers || p.httpResult?.headers || {}) as Record<string, string>;
    const wafInfo = detectWAF(respHeaders);
    const cdnName = detectCDN(respHeaders);
    const probe = hostProbes.get(p.subdomain);
    return {
      domain: p.subdomain,
      ip: p.dns.ips[0] || p.dns.cnames[0] || "-",
      cdn: probe?.cdn ?? cdnName,
      waf: probe?.waf ? true : wafInfo.detected,
      wafProvider: probe?.waf ?? wafInfo.provider,
      // Tri-state: true/false only when a baseline exists. This was hardcoded
      // `false`, while the UI rendered a "New Since Last Run" counter and a
      // New/Known badge per host — a change-detection feature that always said
      // "Known" no matter what had appeared.
      newSinceLastRun: knownHostSet ? !knownHostSet.has(p.subdomain.toLowerCase()) : undefined,
      status: probe?.status ?? p.httpsResult?.status ?? p.httpResult?.status,
      title: probe?.title,
      server: probe?.server,
      technologies: probe?.technologies,
      contentLength: probe?.contentLength,
      redirectsTo: probe?.redirectsTo,
    };
  });

  // Cleartext without an HTTPS upgrade, attributed to the host it was seen on.
  for (const probe of Array.from(hostProbes.values())) {
    if (!probe.cleartextWithoutUpgrade) continue;
    results.findings.push({
      title: `Cleartext HTTP Served Without Upgrade on ${probe.host}`,
      description: `${probe.host} answers plain HTTP with content and does not redirect to HTTPS, even though HTTPS is available. Anything a visitor sends before they reach the encrypted site — credentials, session cookies, form data — crosses the network in the clear and can be modified in transit.`,
      severity: "medium",
      category: "transport_security",
      affectedAsset: probe.host,
      cvssScore: "5.9",
      remediation: "Redirect all HTTP traffic to HTTPS with a 301, then add Strict-Transport-Security so browsers stop trying HTTP at all.",
      evidence: [{
        type: "http_response",
        description: "Plain HTTP returned content without redirecting to HTTPS",
        url: `http://${probe.host}`,
        snippet: `HTTPS is available on this host.
http://${probe.host} returned content and did not upgrade the connection.`,
        source: "http-probe",
        verifiedAt: now,
      }],
    });
  }

  /*
   * Favicon hashing.
   *
   * Not for the Shodan pivot — that needs a key — but for two things it does
   * keyless: grouping the estate (hosts sharing an icon are the same app behind
   * different names, so the odd one out is the one to open first), and handing
   * the operator a `http.favicon.hash:` value they can pivot on themselves.
   *
   * No product is ever named from a hash. Public hash-to-product tables exist,
   * but asserting "this is a Jenkins" from an unverified table is the claim the
   * body-signature gates exist to prevent.
   */
  const faviconHosts = Array.from(hostProbes.values()).slice(0, 100).map((p) => p.host);
  if (faviconHosts.length > 1) {
    checkAborted(options?.signal);
    const favicons = await runWithConcurrency(
      faviconHosts,
      8,
      (host) => fetchFaviconHash(host),
      options?.signal,
    );
    const found = favicons.filter((f): f is NonNullable<typeof f> => Boolean(f));
    if (found.length > 0) {
      results.reconData.faviconClusters = clusterByFavicon(found);
      log.info({ hosts: found.length, clusters: results.reconData.faviconClusters.length }, "Favicon clustering complete");
    }
  }

  /*
   * Known vulnerabilities in the client-side libraries each host actually serves.
   *
   * The versions were already being captured by `tech-fingerprints.ts` and were
   * used only to say "you disclosed your version". Now they are checked against
   * OSV.dev (free, keyless) so an outdated jQuery is reported as the exposure it
   * is rather than as a banner-hygiene note.
   *
   * Attributed per host, because that is what makes a finding joinable to the
   * asset inventory — see per-asset-findings.ts for why a roll-up would not be.
   */
  const hostsWithLibraries = Array.from(hostProbes.values()).filter(
    (probe) => probe.libraryVersions && probe.libraryVersions.length > 0,
  );
  if (hostsWithLibraries.length > 0) {
    checkAborted(options?.signal);
    await runWithConcurrency(
      hostsWithLibraries,
      4,
      async (probe) => {
        const libResult = await findVulnerableLibraries(probe.libraryVersions);
        for (const f of buildLibraryFindings(probe.host, libResult)) {
          results.findings.push({
            title: f.title,
            description: f.description,
            severity: f.severity,
            category: f.category,
            affectedAsset: f.affectedAsset,
            cvssScore: f.cvssScore,
            remediation: f.remediation,
            evidence: [{
              type: "vulnerability_database",
              description: "Advisories published for this library version",
              source: "OSV.dev",
              snippet: JSON.stringify(f.evidence, null, 2).slice(0, 4000),
              verifiedAt: now,
            }],
          });
        }
      },
      options?.signal,
    );
  }

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

  // Which protocol versions the server will ACCEPT, not just the one it
  // negotiated with us. A host still speaking TLS 1.0 alongside 1.3 negotiates
  // 1.3 with this scanner and looks perfectly healthy; the obsolete version is
  // only visible if you ask for it specifically.
  if (certInfo) {
    const tlsVersions = await enumerateTlsVersions(domain, 443);
    results.findings.push(...buildTlsProtocolFindings(domain, tlsVersions, new Date().toISOString()));
    if (!tlsVersions.unreachable) {
      results.reconData.tlsVersions = {
        accepted: tlsVersions.results.filter((r) => r.supported).map((r) => r.version),
        obsoleteAccepted: tlsVersions.obsoleteAccepted,
        // An undetermined probe is recorded so the panel can say "could not
        // check" rather than implying the version was refused.
        indeterminate: tlsVersions.results.filter((r) => r.indeterminate).map((r) => r.version),
      };
    }
  }

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

  // Fetch the main page for header analysis, with resilience: a single HTTPS
  // request can fail transiently (slow/round-robin IP), which previously left
  // securityHeaders empty. Retry once, then fall back to http:// so header
  // coverage still populates for reachable hosts.
  const mainHttps =
    (await httpGet(`https://${domain}`)) ||
    (await httpGet(`https://${domain}`)) ||
    (await httpGet(`http://${domain}`));
  if (mainHttps) {
    const headerChecks = checkSecurityHeaders(mainHttps.headers);
    const missingHeaders = headerChecks.filter(h => !h.present);
    const serverLeaks = detectServerInfo(mainHttps.headers);

    // Severity is driven only by the headers that materially reduce risk. Optional
    // / deprecated headers (Permissions-Policy, X-XSS-Protection, COEP/COOP/CORP,
    // X-DNS-Prefetch-Control) do not by themselves justify a medium finding — a site
    // with all critical headers present but a few optional ones missing is low/info,
    // not "Multiple Missing Security Headers (medium)".
    const CRITICAL_HEADER_LABELS = new Set([
      "Strict-Transport-Security (HSTS)",
      "Content-Security-Policy (CSP)",
      "X-Frame-Options",
      "X-Content-Type-Options",
    ]);
    const missingCritical = missingHeaders.filter(h => CRITICAL_HEADER_LABELS.has(h.header));

    // Only surface a finding when a critical header is missing, OR when a large
    // number of headers are absent (a hardening gap worth an informational note).
    if (missingCritical.length >= 1 || missingHeaders.length >= 5) {
      const severity = missingCritical.length >= 2 ? "medium" : missingCritical.length === 1 ? "low" : "info";
      const cvssScore = missingCritical.length >= 2 ? "5.0" : missingCritical.length === 1 ? "3.5" : "1.0";
      const criticalNote = missingCritical.length > 0
        ? ` Critical headers missing: ${missingCritical.map(h => h.header).join(", ")}.`
        : " All critical headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) are present; only optional hardening headers are missing.";
      results.findings.push({
        title: `Missing Security Headers on ${domain}`,
        description: `${missingHeaders.length} of the ${headerChecks.length} checked security headers are missing from the HTTP response on ${domain}.${criticalNote} Missing headers: ${missingHeaders.map(h => h.header).join(", ")}.`,
        severity,
        category: "security_headers",
        affectedAsset: domain,
        cvssScore,
        remediation: missingCritical.length > 0
          ? "Configure the web server to add the missing critical security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), then the optional hardening headers."
          : "Optional hardening only: add the remaining headers (e.g. Permissions-Policy, Referrer-Policy) to further reduce attack surface. Not a material vulnerability.",
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

    // Turn the per-asset analysis into findings ATTRIBUTED TO EACH HOST.
    //
    // This block used to end at the four assignments above: every live
    // subdomain was fetched, its certificate read and its headers graded, and
    // the result went into recon and no further. The only header/TLS/disclosure
    // findings a scan produced were for the apex — so on a real workspace, 90
    // analysed subdomains yielded 31 findings all attributed to the apex, and
    // asset-risk scoring (which matches findings to assets by hostname) scored
    // 262 of 263 assets at zero because nothing was attributable to them.
    const perAssetFindings = buildPerAssetFindings({
      perAssetHeaders,
      perAssetTls,
      perAssetLeaks,
      apex: domain,
      now,
    });
    results.findings.push(...perAssetFindings);
    log.info(
      { domain, hosts: perAssetBatch.length, findings: perAssetFindings.length },
      "per-asset findings attributed to their own hosts",
    );
  }

  if (mainDns.ips.length > 0) {
    const mainIp = mainDns.ips[0];
    // Scan + enrich EVERY unique resolved IP: all apex A-records (both modes) plus
    // subdomain IPs (gold). Previously standard mode only touched the first apex IP,
    // missing load-balanced / multi-homed hosts.
    const subIps = gold ? subdomainProbes.flatMap((p) => p.dns.ips) : [];
    const IP_CAP = gold ? 20 : 8;
    const allIps = Array.from(new Set([...mainDns.ips, ...subIps])).slice(0, IP_CAP);

    // ── Port-scan every resolved IP (both modes) ──
    const openPortsByIp: Record<string, number[]> = {};
    for (const ip of allIps) {
      openPortsByIp[ip] = await scanOpenPorts(ip, portList);
    }
    results.reconData.openPorts = openPortsByIp[mainIp] ?? [];
    results.reconData.openPortsByIp = openPortsByIp;

    // ── Threat-intel enrichment for every resolved IP (bounded; VT is rate-limited) ──
    const ENRICH_CAP = gold ? 12 : 6;
    const threatIntel: NonNullable<typeof results.reconData.threatIntel> = {};
    for (const ip of allIps.slice(0, ENRICH_CAP)) {
      try {
        const [abuse, bgp] = await Promise.all([enrichIP(ip), fetchBGPView(ip)]);
        threatIntel[ip] = { abuseipdb: abuse.abuseipdb, virustotal: abuse.virustotal, bgp };

        // Shodan host enrichment (key-gated; no-op without a configured key).
        try {
          const shodan = await shodanHostLookup(ip);
          if (shodan && (shodan.ports.length > 0 || shodan.vulns.length > 0)) {
            const hasVulns = shodan.vulns.length > 0;
            results.findings.push({
              title: `Shodan-indexed exposure for ${ip}`,
              description: `Shodan has indexed ${ip} (${domain}) with ${shodan.ports.length} open port(s)${shodan.products.length ? ` running ${shodan.products.slice(0, 8).join(", ")}` : ""}.${hasVulns ? ` Shodan associates ${shodan.vulns.length} known CVE(s) with this host: ${shodan.vulns.slice(0, 15).join(", ")}.` : ""} This reflects the host's internet-facing footprint as seen by external scanners.`,
              severity: hasVulns ? "high" : "info",
              category: hasVulns ? "vulnerability" : "network_exposure",
              affectedAsset: ip,
              cvssScore: hasVulns ? "7.5" : "1.0",
              remediation: hasVulns
                ? "Review the CVEs Shodan associates with this host, patch affected services, and restrict unnecessary exposed ports."
                : "Review whether all Shodan-indexed open ports are intended to be internet-facing; close or firewall any that are not.",
              evidence: [{
                type: "shodan",
                description: "Shodan host lookup",
                snippet: `IP: ${ip}\nPorts: ${shodan.ports.join(", ") || "none"}\nProducts: ${shodan.products.join(", ") || "n/a"}\nCVEs: ${shodan.vulns.join(", ") || "none"}\nOrg: ${shodan.org ?? "n/a"}`,
                source: "Shodan API",
                verifiedAt: now,
              }],
            });
          }
        } catch (err) {
          log.warn({ err, ip }, "Shodan lookup failed (non-fatal)");
        }

        if (abuse.abuseipdb && abuse.abuseipdb.abuseConfidenceScore >= 50) {
          const isPrimary = ip === mainIp;
          results.findings.push({
            title: `High Abuse Score for ${isPrimary ? "Primary " : ""}IP ${ip}`,
            description: `The IP address ${ip}${isPrimary ? " (primary)" : ""} for ${domain} has an AbuseIPDB confidence score of ${abuse.abuseipdb.abuseConfidenceScore}% (${abuse.abuseipdb.totalReports} reports). This indicates the IP has been reported for malicious activity.`,
            severity: abuse.abuseipdb.abuseConfidenceScore >= 80 ? "high" : "medium",
            category: "threat_intelligence",
            affectedAsset: ip,
            cvssScore: abuse.abuseipdb.abuseConfidenceScore >= 80 ? "7.5" : "5.3",
            remediation: "Investigate the reported abuse activity. Consider changing IP address or contacting the hosting provider.",
            evidence: [{
              type: "threat_intel",
              description: "AbuseIPDB IP reputation check",
              snippet: `IP: ${ip}\nAbuse Score: ${abuse.abuseipdb.abuseConfidenceScore}%\nTotal Reports: ${abuse.abuseipdb.totalReports}\nISP: ${abuse.abuseipdb.isp ?? "unknown"}\nCountry: ${abuse.abuseipdb.countryCode ?? "unknown"}`,
              source: "AbuseIPDB API",
              verifiedAt: now,
            }],
          });
        }
      } catch (err) {
        log.warn({ err, ip }, "Threat intel enrichment failed");
      }
    }
    if (Object.keys(threatIntel).length > 0) results.reconData.threatIntel = threatIntel;
  }

  results.reconData.dns = {
    ips: mainDns.ips,
    cnames: mainDns.cnames,
    ns: nsRecords,
    subdomainsFound: crtShSubdomains.length,
    liveSubdomains: liveSubdomains.map(s => s.subdomain),
    danglingCnames: danglingCnames.map(d => ({ subdomain: d.subdomain, cname: d.dns.cnames[0] })),
  };

  // Reverse-DNS (PTR) for resolved apex IPs — cheap, always run.
  if (mainDns.ips.length > 0) {
    try {
      const ptr = await reverseDnsLookup(mainDns.ips.slice(0, 10));
      if (Object.keys(ptr).length > 0) results.reconData.reverseDns = ptr;
    } catch (err) {
      log.warn({ err, domain }, "Reverse DNS lookup failed (non-fatal)");
    }
    // Reverse-IP: other domains co-hosted on the same IP (shared-hosting neighbours).
    try {
      const coHosted = await reverseIpLookup(mainDns.ips.slice(0, 5), domain);
      if (Object.keys(coHosted).length > 0) results.reconData.coHostedDomains = coHosted;
    } catch (err) {
      log.warn({ err, domain }, "Reverse IP lookup failed (non-fatal)");
    }

    // Routed footprint. Every other discovery method here starts from a NAME —
    // a wordlist entry, a certificate, an archived URL — so all of them are
    // blind to an asset with no DNS record pointing at it. BGP data finds those
    // from the other end: if the organisation runs its own AS, the global
    // routing table already publishes every prefix it is responsible for.
    //
    // Expansion is refused unless the AS is positively attributable to this
    // organisation; see asn-expansion.ts for why that gate is the whole module.
    try {
      const orgTokens = [domain.split(".")[0], domain, results.reconData.domainInfo?.registrant ?? ""].filter(Boolean);
      const asn = await runAsnExpansion(mainDns.ips.slice(0, 3), orgTokens);
      results.reconData.asnFootprint = {
        asns: asn.asns,
        ownedPrefixes: asn.ownedPrefixes.map((p) => p.prefix),
        ownedAddressCount: asn.ownedAddressCount,
        unavailable: asn.unavailable,
        notes: asn.notes,
      };
      for (const p of asn.ownedPrefixes) {
        results.assets.push({ type: "ip_range", value: p.prefix, tags: ["bgp-announced", "org-owned"] });
      }
      if (asn.ownedPrefixes.length > 0) {
        log.info({ domain, prefixes: asn.ownedPrefixes.length, addresses: asn.ownedAddressCount }, "routed footprint attributed to the organisation");
      }
    } catch (err) {
      log.warn({ err, domain }, "ASN expansion failed (non-fatal)");
    }
  }

  // ── Advanced coverage (full-coverage modes: gold + safe) ──
  // Cloud storage discovery, container/orchestration exposure, and banner-grab
  // port scanning. Each is best-effort and fail-soft. All outbound HTTP is
  // paced by the active stealth profile; the port scan concurrency is lowered
  // in stealth mode so a full-coverage scan stays quiet.
  if (gold) {
    checkAborted(signal);
    await report("Harvesting historical URLs (Wayback Machine)...", 86, "wayback_urls", 50);
    try {
      const wayback = await fetchWaybackUrls(domain, 2000);
      if (wayback.length > 0) results.reconData.waybackUrls = wayback;
    } catch (err) {
      log.warn({ err, domain }, "Wayback URL harvest failed (non-fatal)");
    }

    checkAborted(signal);
    await report("Discovering cloud assets (S3/GCS/Azure)...", 88, "cloud_discovery", 45);
    try {
      const cloud = await runCloudDiscovery(domain, signal);
      if (cloud.buckets.length > 0 || cloud.cloudServices.length > 0) {
        results.reconData.cloudDiscovery = { buckets: cloud.buckets, cloudServices: cloud.cloudServices };
      }
      for (const b of cloud.buckets) {
        results.assets.push({ type: "cloud_bucket", value: b.url, tags: [b.provider, b.accessible ? "public" : "exists"] });
      }
      for (const f of cloud.findings) {
        results.findings.push(toVerifiedFinding(f, [{
          type: "cloud_asset", description: "Cloud storage discovery", source: "cloud-discovery", verifiedAt: now,
        }]));
      }
    } catch (err) {
      log.warn({ err, domain }, "Cloud discovery failed (non-fatal)");
    }

    checkAborted(signal);
    await report("Probing for exposed container/orchestration endpoints...", 90, "container_detection", 40);
    try {
      const container = await runContainerDetection(domain, signal);
      if (container.exposedEndpoints.length > 0) {
        results.reconData.containerExposure = { exposedEndpoints: container.exposedEndpoints };
        for (const ep of container.exposedEndpoints) {
          results.assets.push({ type: "service", value: ep.url, tags: ["container", ep.type, ep.authenticated ? "auth" : "open"] });
        }
      }
      for (const f of container.findings) {
        results.findings.push(toVerifiedFinding(f, [{
          type: "container_exposure", description: "Exposed container/orchestration endpoint", source: "container-detection", verifiedAt: now,
        }]));
      }
    } catch (err) {
      log.warn({ err, domain }, "Container detection failed (non-fatal)");
    }

    // Banner-grab the ports already found open by scanOpenPorts (above) — no
    // need to re-scan the full port list, which would double the work and stall
    // on filtered ports. Only open ports get a banner-grab connection.
    // Banner-grab every resolved IP that has open ports (not just the primary), so
    // the report's service/banner table and dangerous-service checks cover all hosts.
    const openByIp: Record<string, number[]> = results.reconData.openPortsByIp
      ?? (results.reconData.openPorts?.length ? { [mainDns.ips[0]]: results.reconData.openPorts } : {});
    const ipsWithOpen = Object.entries(openByIp).filter(([, ports]) => ports.length > 0);
    if (mainDns.ips.length > 0 && ipsWithOpen.length > 0) {
      checkAborted(signal);
      await report("Banner-grabbing open ports on resolved IPs...", 92, "port_banner_scan", 20);
      const portConcurrency = stealth ? profile.dnsConcurrency : 20;
      for (const [ip, ports] of ipsWithOpen) {
        try {
          const ps = await runPortScan(ip, ports, signal, portConcurrency);
          if (ps.openPorts.length > 0) {
            results.reconData.portScan = { ...(results.reconData.portScan ?? {}), [ip]: ps.openPorts };
          }
          for (const f of ps.findings) {
            results.findings.push(toVerifiedFinding(f, [{
              type: "port_scan", description: "TCP port banner grab", source: "port-scan", verifiedAt: now,
            }]));
          }
          // Elevate Internet-exposed databases to HIGH and flag outdated banners.
          results.findings.push(...assessServiceExposure(ip, ps.openPorts));
        } catch (err) {
          log.warn({ err, ip }, "Banner-grab port scan failed (non-fatal)");
        }
      }
    }

    // Intrusive WAF-bypass testing — only in explicitly aggressive (gold) mode.
    if (profile.allowIntrusive) {
      checkAborted(signal);
      await report("Testing WAF bypass techniques...", 93, "waf_bypass", 30);
      try {
        const allHeaders = results.reconData.serverInfo?.allHeaders;
        const wafProvider = allHeaders ? (detectWAF(allHeaders).provider || null) : null;
        const waf = await runWAFBypassTest(domain, wafProvider, signal);
        for (const f of waf.findings) {
          results.findings.push(toVerifiedFinding(f, [{
            type: "waf_bypass", description: "WAF bypass technique test", source: "waf-bypass", verifiedAt: now,
          }]));
        }
      } catch (err) {
        log.warn({ err, domain }, "WAF bypass test failed (non-fatal)");
      }
    }
  }

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
