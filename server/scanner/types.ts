/**
 * Shared types for the scanner module.
 */

import type { AbuseIPDBResult, VirusTotalResult, BGPViewResult } from "../api-integrations.js";

export interface ReconData {
  // EASM scan properties
  subdomainBruteforce?: {
    wordlistSource: string;
    tried: number;
    resolved: string[];
    liveWithHttp: string[];
  };
  discoveredDomains?: Array<{
    domain: string;
    ip: string;
    cdn?: string;
    waf?: boolean;
    wafProvider?: string;
    /**
     * True when this host was not in the workspace before this scan.
     * `undefined` when there was no baseline to compare against — see
     * `ScanOptions.knownHosts`.
     */
    newSinceLastRun?: boolean;
    status?: number;
    server?: string;
    /**
     * Enriched fingerprint from the single-GET host probe. Liveness alone told
     * an operator that ninety subdomains answered and nothing about any of
     * them; the title and tech stack are what triage actually starts from.
     */
    title?: string;
    technologies?: string[];
    contentLength?: number;
    redirectsTo?: string;
  }>;
  ssl?: {
    subject?: string;
    issuer?: string;
    validFrom?: string;
    validTo?: string;
    daysRemaining?: number;
    protocol?: string;
    altNames?: string[];
  };
  /**
   * TLS versions the host ACCEPTS, as opposed to the single version it happened
   * to negotiate. `indeterminate` is kept separate so the UI can say "could not
   * check" rather than implying a version was refused.
   */
  tlsVersions?: { accepted: string[]; obsoleteAccepted: string[]; indeterminate: string[] };
  securityHeaders?: Record<string, { present?: boolean; value?: string | null; grade?: string }>;
  serverInfo?: {
    leaks?: string[];
    allHeaders?: Record<string, string>;
  };
  perAssetTls?: Record<string, { subject?: string; issuer?: string; daysRemaining?: number; protocol?: string } | null>;
  perAssetHeaders?: Record<string, Record<string, { present?: boolean; value?: string | null }>>;
  perAssetLeaks?: Record<string, string[]>;
  wafByHost?: Record<string, { waf: boolean; wafProvider: string; cdn: string }>;
  openPorts?: number[];
  openPortsByIp?: Record<string, number[]>;
  threatIntel?: Record<string, { abuseipdb: AbuseIPDBResult | null; virustotal: VirusTotalResult | null; bgp: BGPViewResult | null }>;
  dns?: {
    ips?: string[];
    cnames?: string[];
    ns?: string[];
    subdomainsFound?: number;
    liveSubdomains?: string[];
    danglingCnames?: Array<{ subdomain: string; cname: string }>;
  };
  // OSINT scan properties
  dnsRecords?: {
    a?: string[];
    aaaa?: string[];
    cname?: string[];
    soa?: { nsname: string; hostmaster: string; serial: number; refresh: number; retry: number; expire: number; minttl: number } | null;
    txt?: string[][];
    mx?: Array<{ priority: number; exchange: string }>;
    ns?: string[];
    caa?: Array<{ tag: string; value: string }>;
  };
  redirectChain?: Array<{ status: number; url: string; location?: string }>;
  domainInfo?: Record<string, string> | null;
  emailSecurity?: {
    spf?: { found: boolean; record: string; issues: string[] };
    dmarc?: { found: boolean; record: string; issues: string[] };
    dkim?: { found: boolean; selector?: string; record?: string };
    cloudProviders?: Array<{ provider: string; confidence: number; evidence: string[] }>;
    mx?: Array<{ priority: number; exchange: string }>;
    ns?: string[];
    txtRecords?: string[];
  };
  pathChecks?: Record<string, { status: number; accessible: boolean; responseType?: string; severity?: string; validated?: boolean; confidence?: string; redirectTarget?: string }>;
  directoryBruteforce?: {
    wordlistSource?: string;
    tried: number;
    hits: Array<{ path: string; status?: number; responseType?: string; severity?: string; validated?: boolean; confidence?: string; redirectTarget?: string }>;
    found?: number;
    foundPaths?: string[];
  };
  robotsTxt?: string;
  securityTxt?: { raw: string; parsed: Record<string, string> };
  sitemapUrls?: string[];
  cookies?: Array<{ name: string; secure?: boolean; httpOnly?: boolean; sameSite?: string; path?: string }>;
  responseHeaders?: Record<string, string>;
  techStack?: Array<{ name: string; source: string; category?: string; version?: string; thirdParty?: boolean }>;
  socialTags?: Record<string, string>;
  serverLocation?: { country?: string; region?: string; city?: string; org?: string; lat?: number; lon?: number };
  /**
   * Real DNSSEC state. This used to be `{ soaPresent: boolean }`, which was set
   * by resolving an SOA record — something every resolvable domain has — and
   * the DOCX report printed it as "zone signed". See scanner/dnssec.ts.
   */
  dnssec?: {
    signed: boolean;
    dsPresent: boolean;
    dnskeyPresent: boolean;
    authenticatedData: boolean;
    algorithms: number[];
    state: "signed" | "keys-without-delegation" | "unsigned" | "unverifiable";
    detail: string;
  };
  // Phase 2: Advanced detection
  subdomainTakeover?: Array<{
    subdomain: string;
    cname: string;
    service: string | null;
    vulnerable: boolean;
    confidence: string;
  }>;
  apiDiscovery?: {
    endpoints: Array<{
      path: string;
      type: string;
      status: number;
      /**
       * True when the endpoint answered without demanding credentials. Named
       * for what it asserts: the previous `authenticated` field was set to
       * `status !== 401 && status !== 403`, so it read as the opposite of its
       * own value at every call site.
       */
      unauthenticated: boolean;
      details: string;
    }>;
    openApiSpec: { title: unknown; version: unknown; pathCount: number } | null;
  };
  secretExposure?: {
    matchCount: number;
    leakyPaths: string[];
    patternTypes: string[];
  };
  // Phase 3: Advanced EASM coverage (cloud assets, container exposure, port banners)
  cloudDiscovery?: {
    buckets: Array<{ provider: string; name: string; url: string; accessible: boolean; status: number }>;
    cloudServices: Array<{ provider: string; service: string; evidence: string }>;
  };
  containerExposure?: {
    exposedEndpoints: Array<{ url: string; path: string; type: string; status: number; authenticated: boolean }>;
  };
  portScan?: Record<string, Array<{ port: number; service: string; banner?: string }>>;
  // Phase 3: Free passive OSINT sources
  passiveSources?: Record<string, number>;
  /**
   * Sources that errored rather than returning nothing. Kept separate so a
   * collector outage never reads as "this source found no subdomains".
   */
  passiveSourcesFailed?: string[];
  /** Which independent sources named each discovered host. */
  discoverySources?: Record<string, string[]>;
  /**
   * Site-crawl coverage. Recorded because it bounds what the active tests could
   * possibly have found: a truncated crawl means the DAST results describe part
   * of the application, and a reader has to be told which part.
   */
  crawl?: { engine: string; urls: number; parameterised: number; forms: number; truncated: boolean };
  /**
   * Permutation discovery: candidates generated from the hosts already found,
   * and which of them resolved. Recorded because it is the one method whose
   * yield says something about the ESTATE rather than about the internet —
   * hosts only permutation found are, by definition, in no public index.
   */
  permutationDiscovery?: { candidatesTried: number; hostsFound: number; hosts: string[] };
  /**
   * Hosts grouped by the favicon they serve. Ninety subdomains are rarely ninety
   * applications: hosts sharing an icon are almost always the same app behind
   * different names, and the host whose icon matches nothing else is the one
   * worth opening first. The hash is Shodan-compatible so an operator can pivot
   * on it themselves.
   */
  faviconClusters?: Array<{ hash: number; hosts: string[] }>;
  /**
   * Set when more hosts were discovered than the profile probes. Recorded so a
   * reader can tell a small estate from a truncated look at a large one.
   */
  probeCoverage?: { discovered: number; probed: number; truncated: boolean };
  /** Corroboration confidence per host, derived from how many sources agree. */
  discoveryConfidence?: Record<string, "high" | "medium" | "low">;
  reverseDns?: Record<string, string[]>;
  /** Reverse-IP: other domains co-hosted on the same IP (Record<ip, hostnames[]>). */
  coHostedDomains?: Record<string, string[]>;
  /**
   * The organisation's own routed address space, from BGP.
   *
   * Finds assets that no name-based method can reach — a host with no DNS
   * record still sits inside an announced prefix. `asns` records every AS seen
   * behind the target's addresses along with why each was or was not attributed
   * to the organisation, so a refusal to expand is auditable rather than silent.
   */
  asnFootprint?: {
    asns: Array<{ asn: number; name: string; description: string; countryCode?: string; attribution: "owned" | "shared" | "unknown"; reason: string }>;
    ownedPrefixes: string[];
    ownedAddressCount: number;
    unavailable: boolean;
    notes: string[];
  };
  waybackUrls?: string[];
  // Phase 4: Verified web-app checks
  wordpress?: {
    isWordPress: boolean;
    users: Array<{ id?: number; name?: string; slug?: string }>;
    xmlrpcEnabled: boolean;
  };
  // Keyless people/employee-exposure OSINT (org-scoped, public data only).
  /** Which CAs may issue for this domain, and whether anything restricts them. */
  caaAnalysis?: {
    present: boolean;
    issuers: string[];
    wildcardIssuers: string[];
    iodef: string[];
    forbidsAll: boolean;
  };
  /**
   * AXFR result per authoritative nameserver. Recorded even when every server
   * refuses, because "we checked and it is closed" is a different statement
   * from "we never looked" — and only the first is worth anything in a report.
   */
  zoneTransfer?: Array<{ nameserver: string; transferred: boolean; recordCount: number; detail: string }>;
  /** Services the domain advertises via SRV records, grouped by service. */
  srvServices?: Array<{ service: string; description: string; exposure: string; targets: string[] }>;
  /**
   * Mail transport security posture (MTA-STS / TLS-RPT / BIMI). Kept as recon
   * rather than findings so a domain that has these configured gets visible
   * credit for it, instead of only ever being told what is missing.
   */
  mailTransport?: {
    mtaStsMode?: string;
    mtaStsMx?: string[];
    tlsRptDestinations?: string[];
    bimiLogoUrl?: string;
    bimiVmcUrl?: string;
    controls?: string[];
  };
  peopleExposure?: {
    people: Array<{ name?: string; email?: string; emailInferred?: boolean; source: string; gravatar?: { displayName?: string; location?: string; accounts?: string[]; profileUrl?: string } }>;
    emailFormat?: string;
  };
  /**
   * Lookalike domains, ransomware leak-site exposure, branded mobile apps and
   * breach-corpus membership — each shaped exactly like the `data` field
   * `routes/brand-threats.ts` stores per check, so `recon-builder.ts` can
   * persist the same four recon_module types the manual "run sweep" buttons
   * produce, and the Brand Threats page renders either source identically.
   */
  brandMonitoring?: {
    typosquat: Record<string, unknown>;
    ransomware: Record<string, unknown>;
    mobileApps: Record<string, unknown>;
    breachExposure: Record<string, unknown>;
    /** Gold-mode + GITHUB_TOKEN only — see the scan step for why. */
    codeLeaks?: Record<string, unknown>;
  };
}

export interface EvidenceItem {
  [key: string]: unknown;
  type: string;
  description: string;
  url?: string;
  snippet?: string;
  source?: string;
  verifiedAt?: string;
  raw?: Record<string, unknown>;
}

export interface VerifiedFinding {
  title: string;
  description: string;
  severity: string;
  category: string;
  /**
   * security | control | recon. Optional because most modules only ever produce
   * security findings; omitted means "security", which matches the column
   * default so a module that does not think about this cannot accidentally hide
   * a real weakness. See scanner/finding-taxonomy.ts.
   */
  kind?: string;
  affectedAsset: string;
  cvssScore: string;
  remediation: string;
  evidence: EvidenceItem[];
}

export interface ScanResults {
  subdomains: string[];
  assets: Array<{ type: string; value: string; tags: string[] }>;
  findings: VerifiedFinding[];
  reconData: ReconData;
}

export type ScanProgressCallback = (msg: string, percent: number, step: string, etaSeconds?: number) => Promise<void>;

export interface ScanOptions {
  signal?: AbortSignal;
  mode?: "standard" | "gold" | "safe";
  /**
   * Hosts this workspace already knew about before this scan.
   *
   * `undefined` means there is NO baseline — a first scan, or a workspace whose
   * prior scans never completed. That is a third state, not a synonym for "the
   * baseline was empty": with no baseline every host would otherwise be labelled
   * "new", which is technically true and completely useless. Callers must leave
   * this undefined rather than passing an empty array they did not verify.
   */
  knownHosts?: readonly string[];
}

export interface NucleiHit {
  templateId: string;
  templateName?: string;
  severity: string;
  host: string;
  matchedAt?: string;
  type?: string;
  info?: { name: string; description: string };
  matcherName?: string;
  extractedResults?: string[];
}

export interface NucleiScanResult {
  findings: VerifiedFinding[];
  nucleiResults: NucleiHit[];
  templateCount: number;
}
