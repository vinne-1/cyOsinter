/**
 * Shared scoring logic for attack surface and security posture.
 * Used by both client and server. See docs/scoring.md for documentation.
 */

export const SEVERITY_DEDUCTION = {
  critical: 20,
  high: 10,
  medium: 5,
  low: 2,
  info: 1,
} as const;

export interface FindingForScore {
  severity: string;
  status?: string;
}

/**
 * Security score based on open findings.
 * Formula: max(0, 100 - sum(severityDeduction per finding))
 */
export function computeSecurityScore(findings: FindingForScore[]): number {
  const openFindings = findings.filter((f) => f.status !== "resolved");
  let deduction = 0;
  for (const f of openFindings) {
    const d = SEVERITY_DEDUCTION[f.severity as keyof typeof SEVERITY_DEDUCTION] ?? 1;
    deduction += d;
  }
  return Math.max(0, Math.min(100, 100 - deduction));
}
