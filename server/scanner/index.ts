// Barrel file — re-exports from all scanner sub-modules to preserve the public API.

// Detection helpers
export { classifyPathResponse, validatePathResponse, detectTechStack, scanOpenPorts, parseSocialTags, gradeHeader, checkSecurityHeaders, detectServerInfo, detectWAF, detectCDN } from "./detection.js";

// DNS helpers
export { resolveDNS, getDNSTxtRecords, getMXRecords, getNSRecords, getFullDNSRecords, checkDNSSEC, analyzeSPF, analyzeDMARC, extractCloudProvidersFromSPF, extractEmailsFromDNS } from "./dns.js";

// HTTP helpers
export { fetchJSON, fetchText, httpHead, httpGet, httpGetNoRedirect, getRedirectChain, httpGetMainPage, parseSetCookie, parseSecurityTxt, parseSitemapUrls, fetchSitemapUrls } from "./http.js";

// TLS helpers
export { getCertificateInfo } from "./tls.js";

// OSINT helpers
export { extractEmailsFromText, redactCredentialValues, shannonEntropy, hasCredentialPattern, generateBackupFilePaths, extractSensitiveRobotsPaths, extractEmailsFromWhois, checkHIBPPasswords, checkS3Buckets, searchPGPKeyServer, extractEmailsFromCrtSh, getServerLocation, parseWhois, getWhois } from "./osint-helpers.js";

// Nuclei scanner
export { runNucleiScan } from "./nuclei.js";
export type { NucleiHit, NucleiScanResult } from "./nuclei.js";

// Recon module builder
export { buildReconModules } from "./recon-builder.js";

// Shared utility
export { runWithConcurrency } from "./utils.js";

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
export { runDASTScan } from "./dast-lite.js";
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

// Main scan orchestrators
export { runEASMScan } from "./easm-scan.js";
export { runOSINTScan } from "./osint-scan.js";
