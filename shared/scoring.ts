/**
 * Shared scoring logic for attack surface and security posture.
 * Used by both client and server. See docs/scoring.md for documentation.
 */

/**
 * Points deducted per open finding for the Security Score (0–100, higher = better).
 * Formula: max(0, 100 − Σ deductions)
 */
export const SEVERITY_DEDUCTION: Record<string, number> = {
  critical: 20,
  high: 10,
  medium: 5,
  low: 2,
  info: 1,
};

/**
 * Severity weights for Risk Delta computation (scan-diff / differential reporting).
 * Higher = more risky. Summed across findings; delta = newRisk − oldRisk.
 */
export const SEVERITY_SCORE_DIFF: Record<string, number> = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 1,
  info: 0,
};

/**
 * Severity weights for Attack Path Risk computation (client-side).
 * Multiplied by finding count per path node; result capped at 100.
 */
export const SEVERITY_SCORE_RISK: Record<string, number> = {
  critical: 10,
  high: 7.5,
  medium: 5,
  low: 2.5,
  info: 1,
};

/**
 * Statuses that indicate a finding is not actively open and should be
 * excluded from the security score deduction.
 */
const EXCLUDED_STATUSES = new Set([
  "resolved",
  "false_positive",
  "accepted_risk",
  "risk_accepted",
]);

export interface FindingForScore {
  severity: string;
  status?: string;
}

/**
 * Security score based on open findings.
 * Formula: max(0, 100 - sum(severityDeduction per open finding))
 * Findings with status "resolved", "false_positive", or "accepted_risk" are excluded.
 * Returns 100 when there are no open findings.
 */
export function computeSecurityScore(findings: FindingForScore[]): number {
  const openFindings = findings.filter(
    (f) => !EXCLUDED_STATUSES.has((f.status ?? "").toLowerCase()),
  );
  let deduction = 0;
  for (const f of openFindings) {
    const sev = (f.severity ?? "info").toLowerCase();
    const d = SEVERITY_DEDUCTION[sev] ?? 1;
    deduction += d;
  }
  return Math.max(0, Math.min(100, 100 - deduction));
}
