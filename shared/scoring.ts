/**
 * Shared scoring logic for attack surface and security posture.
 * Used by both client and server. See docs/scoring.md for documentation.
 */

/** Cost of the FIRST finding at each severity. Later ones cost less — see below. */
export const SEVERITY_DEDUCTION = {
  critical: 20,
  high: 10,
  medium: 5,
  low: 2,
  // Informational findings describe the target; they are not defects and must
  // not drag the score down. "DNSSEC detected" is not a security problem.
  info: 0,
} as const;

/**
 * The lowest score reachable given the WORST severity actually present.
 *
 * Without this, quantity alone could drive a site with nothing worse than
 * medium findings to 0/100 "Critical" — which is what the previous linear model
 * did, and it is indefensible: a grade of F has to mean something is seriously
 * wrong, not that a lot of small things are slightly wrong.
 */
const SEVERITY_FLOOR = {
  critical: 0,
  high: 35,
  medium: 55,
  low: 75,
  info: 95,
  none: 100,
} as const;

/**
 * The HIGHEST score reachable given the worst severity present.
 *
 * The floor alone was not enough: with only a floor, one open critical and a
 * hundred open lows both landed on 80, because volume was doing all the work.
 * A ceiling makes severity dominate — an outstanding critical means you cannot
 * be graded well no matter how tidy everything else is, which is the whole
 * point of calling something critical.
 */
const SEVERITY_CEILING = {
  critical: 45,
  high: 70,
  medium: 85,
  low: 95,
  info: 100,
  none: 100,
} as const;

/** Statuses that take a finding out of scope — it is not outstanding work. */
const CLOSED_STATUSES = new Set(["resolved", "false_positive", "accepted_risk"]);

export interface FindingForScore {
  severity: string;
  status?: string;
}

export type ScoreSeverity = keyof typeof SEVERITY_DEDUCTION;

const SEVERITY_ORDER: ScoreSeverity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Total deduction for `count` findings of one severity, with diminishing
 * returns.
 *
 * `weight * sqrt(count)`: four findings cost twice one, a hundred cost ten
 * times. That matches how the risk actually scales — twenty-seven hosts missing
 * the same header is one misconfiguration with twenty-seven instances, not
 * twenty-seven independent problems, and charging full price for each is what
 * floored the score at zero.
 */
export function deductionFor(severity: ScoreSeverity, count: number): number {
  if (count <= 0) return 0;
  const weight = SEVERITY_DEDUCTION[severity] ?? 0;
  return weight * Math.sqrt(count);
}

/**
 * Security score (0–100) from open findings.
 *
 * Two rules, in order:
 *  1. Sum the per-severity deductions, each with diminishing returns.
 *  2. Clamp the result to the floor implied by the worst severity present, so
 *     the grade always reflects the SEVERITY of what is outstanding and only
 *     then its volume.
 */
export function computeSecurityScore(findings: FindingForScore[]): number {
  const open = findings.filter((f) => !CLOSED_STATUSES.has(f.status ?? "open"));

  const counts: Record<string, number> = {};
  for (const f of open) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

  let deduction = 0;
  for (const sev of SEVERITY_ORDER) {
    deduction += deductionFor(sev, counts[sev] ?? 0);
  }

  // Worst severity that is actually present AND carries weight. Info is skipped
  // because a page full of informational notes is not a degraded posture.
  const worst = SEVERITY_ORDER.find((s) => (counts[s] ?? 0) > 0 && SEVERITY_DEDUCTION[s] > 0);
  const band = worst ?? (open.length > 0 ? "info" : "none");

  // Clamp into the band the worst severity allows, then let volume position the
  // score inside it.
  const raw = 100 - deduction;
  const bounded = Math.min(SEVERITY_CEILING[band], Math.max(SEVERITY_FLOOR[band], raw));
  return Math.round(Math.max(0, Math.min(100, bounded)));
}

/**
 * Explains a score, so the UI can say WHY rather than just showing a number.
 * A posture grade nobody can account for is a number nobody trusts.
 */
export function explainSecurityScore(findings: FindingForScore[]): {
  score: number;
  counts: Record<ScoreSeverity, number>;
  worstSeverity: ScoreSeverity | null;
  /** True when volume was capped by the severity floor rather than summed. */
  floored: boolean;
  /** True when severity, not volume, is what is holding the score down. */
  capped: boolean;
} {
  const open = findings.filter((f) => !CLOSED_STATUSES.has(f.status ?? "open"));
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<ScoreSeverity, number>;
  for (const f of open) {
    if (f.severity in counts) counts[f.severity as ScoreSeverity] += 1;
  }

  let deduction = 0;
  for (const sev of SEVERITY_ORDER) deduction += deductionFor(sev, counts[sev]);

  const worst = SEVERITY_ORDER.find((s) => counts[s] > 0 && SEVERITY_DEDUCTION[s] > 0) ?? null;
  const band = worst ?? (open.length > 0 ? "info" : "none");

  return {
    score: computeSecurityScore(findings),
    counts,
    worstSeverity: worst,
    floored: 100 - deduction < SEVERITY_FLOOR[band],
    /** True when severity, not volume, is what is holding the score down. */
    capped: 100 - deduction > SEVERITY_CEILING[band],
  };
}
