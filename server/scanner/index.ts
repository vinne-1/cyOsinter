// Barrel file — re-exports from all scanner sub-modules to preserve the public API.

// Detection helpers
export { classifyPathResponse, validatePathResponse, detectTechStack, scanOpenPorts, parseSocialTags, gradeHeader, checkSecurityHeaders, detectServerInfo, detectWAF, detectCDN } from "./detection.js";

// DNS helpers
export { resolveDNS, getDNSTxtRecords, getMXRecords, getNSRecords, getFullDNSRecords, extractCloudProvidersFromSPF, extractEmailsFromDNS } from "./dns.js";

// HTTP helpers
export { fetchJSON, fetchText, httpHead, httpGet, httpRequest, httpGetNoRedirect, getRedirectChain, httpGetMainPage, parseSetCookie, parseSecurityTxt, parseSitemapUrls, fetchSitemapUrls } from "./http.js";

// TLS helpers
export { getCertificateInfo } from "./tls.js";

// OSINT helpers
export { extractEmailsFromText, redactCredentialValues, shannonEntropy, hasCredentialPattern, generateBackupFilePaths, extractSensitiveRobotsPaths, extractEmailsFromWhois, checkHIBPPasswords, checkS3Buckets, searchPGPKeyServer, extractEmailsFromCrtSh, getServerLocation, parseWhois, getWhois } from "./osint-helpers.js";

// Nuclei scanner
export { runNucleiScan } from "./nuclei.js";
export { checkDnssec, describeDnssec } from "./dnssec.js";
export type { NucleiHit, NucleiScanResult } from "./nuclei.js";

// Recon module builder
export { buildReconModules } from "./recon-builder.js";

// Shared utility
export { runWithConcurrency } from "./utils.js";

// Stealth engine (rate limiting, pacing, UA rotation, scan profiles)
export { resolveProfile, runWithStealth, getController, currentProfile, StealthController, stealthFetch, USER_AGENTS, DEFAULT_USER_AGENT } from "./stealth.js";
export type { ScanMode, ScanProfile, NucleiProfile } from "./stealth.js";

// Free passive OSINT sources
export { fetchSubdomainsFromFreeSources, fetchWaybackUrls, reverseDnsLookup } from "./passive-sources.js";

// Verified web-app + service-exposure detectors
export { runWordPressChecks, parseWpUsers, slugFromAuthorRedirect } from "./wordpress-checks.js";
export type { WordPressCheckResults, WordPressUser } from "./wordpress-checks.js";
export { assessServiceExposure } from "./service-exposure.js";
export type { OpenPortInfo } from "./service-exposure.js";

// Constants and types
export type { ScanProgressCallback, ScanOptions, ScanResults, EvidenceItem, VerifiedFinding } from "./constants.js";

// Phase 2: Advanced detection modules
export { scanSubdomainTakeover } from "./takeover.js";
export type { TakeoverResult, TakeoverScanResults } from "./takeover.js";
export { discoverAPIs } from "./api-discovery.js";
export type { ApiEndpoint, ApiDiscoveryResults } from "./api-discovery.js";
export { scanSecrets } from "./secret-scanner.js";
export type { SecretMatch, SecretScanResults } from "./secret-scanner.js";

// Phase 4: DAST-Lite
export { runDASTScan, buildInjectionTargets } from "./dast-lite.js";
export type { InjectionTarget } from "./dast-lite.js";

// Enriched host fingerprinting (httpx when installed, native otherwise).
export { probeHosts, extractTitle, findHttpx } from "./http-probe.js";
export type { HostProbe, ProbeOptions } from "./http-probe.js";

// Site crawler — the endpoint inventory the active tests are aimed at.
export { crawlSite, isInScope, endpointShape, testableParams, extractLinks, extractForms, findKatana } from "./crawler.js";
export type { CrawlResult, CrawledUrl, CrawledForm, CrawlOptions } from "./crawler.js";

// ASN / BGP routed footprint.
export { runAsnExpansion, attributeAsn, looksLikeSharedInfrastructure, addressesInPrefix } from "./asn-expansion.js";
export type { AsnExpansionResult, AsnRecord, AsnPrefix } from "./asn-expansion.js";
export type { DASTFinding, DASTResults } from "./dast-lite.js";

// Phase 3: Advanced scanners
export { runPortScan } from "./port-scan.js";
export type { PortScanResults } from "./port-scan.js";
export { runCloudDiscovery } from "./cloud-discovery.js";
export type { CloudDiscoveryResults } from "./cloud-discovery.js";
export { runContainerDetection } from "./container-detection.js";
export type { ContainerDetectionResults } from "./container-detection.js";
export { runWAFBypassTest } from "./waf-bypass.js";
export type { WAFBypassResults } from "./waf-bypass.js";

// Tor-aware HTTP client and dark web monitoring
export { torFetch, torFetchJson, torFetchText, isTorAvailable, getTorAgent, __resetTorAgent, TOR_PROXY_URL } from "./tor-fetch.js";
export { monitorDarkWeb, __resetDarkWebCache } from "./dark-web-monitor.js";
export type { DarkWebMonitorResult, DarkWebMention, DarkWebLeakDump, DarkWebForumMention } from "./dark-web-monitor.js";

// Main scan orchestrators
export { runEASMScan } from "./easm-scan.js";
export { runOSINTScan } from "./osint-scan.js";
export { runPassiveScan } from "./passive-scan.js";
