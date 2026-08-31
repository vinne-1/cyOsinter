/**
 * Case lifecycle rules.
 *
 * Kept out of the route file so it can be reasoned about — and tested — without
 * a database connection, the same split that finding-workflow.ts uses.
 */

export const CASE_STATUSES = ["open", "investigating", "contained", "resolved", "closed"] as const;
export type CaseStatus = (typeof CASE_STATUSES)[number];

/**
 * Permitted transitions.
 *
 * Two deliberate choices:
 *  - Every active state can go straight to `closed`. Abandoning work has to be
 *    possible whatever state it is in.
 *  - `closed` can reopen to `open`, because a remediation that did not hold is a
 *    normal outcome. It reopens at the START, not mid-lifecycle, so the work is
 *    re-triaged rather than resuming on stale conclusions.
 */
export const CASE_TRANSITIONS: Record<string, string[]> = {
  open: ["investigating", "closed"],
  investigating: ["contained", "resolved", "open", "closed"],
  contained: ["resolved", "investigating", "closed"],
  resolved: ["closed", "investigating"],
  closed: ["open"],
};

/** States in which the SLA clock has stopped. */
export const CASE_TERMINAL_STATES = ["resolved", "closed"];

/**
 * Whether a case may move from `from` to `to`.
 * A no-op transition is allowed so a PATCH resending the current status
 * does not fail.
 */
export function isValidCaseTransition(from: string, to: string): boolean {
  if (from === to) return true;
  return CASE_TRANSITIONS[from]?.includes(to) ?? false;
}
