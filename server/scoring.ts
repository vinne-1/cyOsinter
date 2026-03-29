/**
 * Centralized scoring logic for attack surface and security posture.
 * See docs/scoring.md for full documentation.
 */

/**
 * TLS grade to risk points (higher = worse).
 * Weighted at 50% of total score so TLS alone cannot reach 100.
 */
export const TLS_GRADE_RISK: Record<string, number> = {
  A: 10,
  B: 20,
  C: 30,
  D: 40,
  F: 50,
};

/** Max risk points for security headers (8 per missing header, cap 30). Weighted at 30%. */
export const HEADER_RISK_MAX = 30;
export const HEADER_RISK_PER_MISSING = 8;

/** Max risk points for server info leaks (10 per leak, cap 20). Weighted at 20%. */
export const LEAK_RISK_MAX = 20;
export const LEAK_RISK_PER_LEAK = 10;

export { computeSecurityScore } from "@shared/scoring";

export function gradeToRisk(grade: string): number {
  return TLS_GRADE_RISK[grade] ?? 50;
}

export function computeHeaderRisk(missingCount: number): number {
  return Math.min(HEADER_RISK_MAX, missingCount * HEADER_RISK_PER_MISSING);
}

export function computeLeakRisk(leakCount: number): number {
  return Math.min(LEAK_RISK_MAX, leakCount * LEAK_RISK_PER_LEAK);
}

/**
 * Surface risk score: TLS + headers + leaks.
 * Formula: min(100, tlsRisk + headerRisk + leakRisk)
 * - TLS (50% weight): A=10, B=20, C=30, D=40, F=50
 * - Headers (30% weight): 8 pts per missing, max 30
 * - Leaks (20% weight): 10 pts per leak, max 20
 */
export function computeSurfaceRiskScore(
  tlsGrade: string,
  securityHeaders: Record<string, { present?: boolean }> | Array<{ present?: boolean }>,
  serverLeaks: string[]
): { score: number; breakdown: Array<{ category: string; score: number; maxScore: number }> } {
  const tlsRisk = gradeToRisk(tlsGrade);
  const headersObj = typeof securityHeaders === "object" && !Array.isArray(securityHeaders)
    ? securityHeaders
    : Object.fromEntries((securityHeaders as Array<{ present?: boolean }>).map((h, i) => [`h${i}`, h]));
  const missingHeaders = Object.values(headersObj).filter((h) => !h?.present).length;
  const headerRisk = computeHeaderRisk(missingHeaders);
  const leakRisk = computeLeakRisk(serverLeaks.length);
  const score = Math.min(100, tlsRisk + headerRisk + leakRisk);
  return {
    score,
    breakdown: [
      { category: "TLS/Certificate", score: tlsRisk, maxScore: 100 },
      { category: "Security Headers", score: headerRisk, maxScore: HEADER_RISK_MAX },
      { category: "Info Leaks", score: leakRisk, maxScore: LEAK_RISK_MAX },
    ],
  };
}
