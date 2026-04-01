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
