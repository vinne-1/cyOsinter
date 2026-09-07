import { eq, and } from "drizzle-orm";
import { db } from "./db";
import { findings } from "@shared/schema";
import { createLogger } from "./logger";

const log = createLogger("finding-workflow");

export const SLA_HOURS: Record<string, number> = {
  critical: 24,
  high: 168,
  medium: 720,
  low: 2160,
  info: 8760,
};

export const WORKFLOW_TRANSITIONS: Record<string, string[]> = {
  open: ["triaged", "in_progress", "closed"],
  triaged: ["in_progress", "closed"],
  in_progress: ["remediated", "closed"],
  remediated: ["verified", "in_progress"],
  verified: ["closed"],
  closed: ["open"],
};

export function isValidTransition(from: string, to: string): boolean {
  const allowed = WORKFLOW_TRANSITIONS[from];
  if (!allowed) {
    return false;
  }
  return allowed.includes(to);
}

export function computeDueDate(severity: string, discoveredAt: Date): Date {
  const hours = SLA_HOURS[severity] ?? SLA_HOURS.info;
  const dueDate = new Date(discoveredAt.getTime() + hours * 60 * 60 * 1000);
  return dueDate;
}

export function isSLABreached(severity: string, discoveredAt: Date): boolean {
  const dueDate = computeDueDate(severity, discoveredAt);
  return new Date() > dueDate;
}

export function computePriority(severity: string): number {
  const priorityMap: Record<string, number> = {
    critical: 1,
    high: 2,
    medium: 3,
    low: 4,
    info: 5,
  };
  return priorityMap[severity] ?? 5;
}

/**
 * A representative CVSS base score for a severity band.
 *
 * Used only when a detector did not supply one. Most do; the ones that do not
 * produced a report where the two MEDIUM findings showed "CVSS: -" while the
 * INFO and LOW findings showed 2.0 and 3.5 — so the most serious items on the
 * page looked LESS quantified than the least serious, which reads to a client
 * as though nobody assessed them.
 *
 * Derived here at the choke point rather than in each detector, for the same
 * reason `computePriority` and `computeDueDate` are: a detector added later
 * inherits it without its author having to remember.
 *
 * These are band midpoints, not a vector computed for this deployment. A
 * detector that can say something more precise should still set `cvssScore`
 * itself, and that value always wins.
 */
export function computeCvssScore(severity: string): string {
  const bandScore: Record<string, string> = {
    critical: "9.0",
    high: "7.5",
    medium: "5.3",
    low: "3.5",
    info: "2.0",
  };
  return bandScore[severity] ?? "2.0";
}

export async function checkSLABreaches(workspaceId: string): Promise<number> {
  try {
    const openFindings = await db
      .select()
      .from(findings)
      .where(
        and(
          eq(findings.workspaceId, workspaceId),
          eq(findings.slaBreached, false),
        ),
      );

    const nonClosedFindings = openFindings.filter(
      (f) => f.workflowState !== "closed" && f.workflowState !== "verified",
    );

    let breachCount = 0;

    for (const finding of nonClosedFindings) {
      const discoveredAt = finding.discoveredAt ?? new Date();
      const breached = isSLABreached(finding.severity, discoveredAt);

      if (breached) {
        await db
          .update(findings)
          .set({ slaBreached: true })
          .where(eq(findings.id, finding.id));
        breachCount++;
      }
    }

    if (breachCount > 0) {
      log.info({ workspaceId, breachCount }, "SLA breaches detected and updated");
    }

    return breachCount;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    log.error({ workspaceId, error: message }, "Failed to check SLA breaches");
    throw new Error(`SLA breach check failed: ${message}`);
  }
}
