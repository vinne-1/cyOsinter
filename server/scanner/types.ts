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
    newSinceLastRun?: boolean;
    status?: number;
    server?: string;
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
  techStack?: Array<{ name: string; source: string }>;
  socialTags?: Record<string, string>;
  serverLocation?: { country?: string; region?: string; city?: string; org?: string; lat?: number; lon?: number };
  dnssec?: { soaPresent: boolean };
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
      authenticated: boolean;
      details: string;
    }>;
    openApiSpec: { title: unknown; version: unknown; pathCount: number } | null;
  };
  secretExposure?: {
    matchCount: number;
    leakyPaths: string[];
    patternTypes: string[];
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
  mode?: "standard" | "gold";
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
