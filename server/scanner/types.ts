/**
 * Shared types for the scanner module.
 */

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
  reconData: Record<string, Record<string, unknown>>;
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
