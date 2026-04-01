import { storage } from "./storage";
import { createLogger } from "./logger";
import { emitScheduledScanTriggered } from "./notifications";
import type { ScheduledScan } from "@shared/schema";

const log = createLogger("scan-scheduler");

const CHECK_INTERVAL_MS = 60_000; // Check every minute
let intervalId: ReturnType<typeof setInterval> | null = null;

// Externally injected scan trigger to avoid circular dependency with routes
let triggerScanFn: ((target: string, type: string, workspaceId: string, mode: string) => Promise<string>) | null = null;

export function registerScanTrigger(fn: typeof triggerScanFn): void {
  triggerScanFn = fn;
}

/** Parse a cron expression and compute the next run time after `after` */
export function getNextCronRun(cronExpr: string, after: Date = new Date()): Date {
  const parts = cronExpr.trim().split(/\s+/);
  if (parts.length !== 5) throw new Error(`Invalid cron expression: ${cronExpr}`);

  const [minStr, hourStr, domStr, monStr, dowStr] = parts;

  const parseField = (field: string, min: number, max: number): number[] => {
    const values: number[] = [];
    for (const part of field.split(",")) {
      if (part === "*") {
        for (let i = min; i <= max; i++) values.push(i);
      } else if (part.includes("/")) {
        const [base, stepStr] = part.split("/");
        const step = parseInt(stepStr, 10);
        const start = base === "*" ? min : parseInt(base, 10);
        for (let i = start; i <= max; i += step) values.push(i);
      } else if (part.includes("-")) {
        const [lo, hi] = part.split("-").map(Number);
        for (let i = lo; i <= hi; i++) values.push(i);
      } else {
        values.push(parseInt(part, 10));
      }
    }
    return values.sort((a, b) => a - b);
  };

  const minutes = parseField(minStr, 0, 59);
  const hours = parseField(hourStr, 0, 23);
  const doms = parseField(domStr, 1, 31);
  const months = parseField(monStr, 1, 12);
  const dows = parseField(dowStr, 0, 6); // 0 = Sunday

  // Brute-force search for next matching minute within 366 days
  const candidate = new Date(after);
  candidate.setSeconds(0, 0);
  candidate.setMinutes(candidate.getMinutes() + 1); // start from next minute

  const limit = new Date(after);
  limit.setFullYear(limit.getFullYear() + 1);

  while (candidate < limit) {
    const matchMonth = months.includes(candidate.getMonth() + 1);
    const matchDom = doms.includes(candidate.getDate());
    const matchDow = dows.includes(candidate.getDay());
    const matchHour = hours.includes(candidate.getHours());
    const matchMin = minutes.includes(candidate.getMinutes());

    // DOM and DOW: if both are restricted (not *), match either; if only one is restricted, match that one
    const domIsWild = domStr === "*";
    const dowIsWild = dowStr === "*";
    const dayMatch = domIsWild && dowIsWild
      ? true
      : domIsWild
        ? matchDow
        : dowIsWild
          ? matchDom
          : matchDom || matchDow;

    if (matchMonth && dayMatch && matchHour && matchMin) {
      return candidate;
    }

    candidate.setMinutes(candidate.getMinutes() + 1);
  }

  // Fallback: 24 hours from now
  return new Date(after.getTime() + 86_400_000);
}

/** Check for due scheduled scans and trigger them */
async function checkDueScans(): Promise<void> {
  try {
    const dueScans = await storage.getDueScheduledScans();
    for (const scheduled of dueScans) {
      await triggerScheduledScan(scheduled);
    }
  } catch (err) {
    log.error({ err }, "Error checking due scheduled scans");
  }
}

async function triggerScheduledScan(scheduled: ScheduledScan): Promise<void> {
  if (!triggerScanFn) {
    log.warn("Scan trigger function not registered — skipping scheduled scan");
    return;
  }

  try {
    log.info({ target: scheduled.target, id: scheduled.id }, "Triggering scheduled scan");

    const scanId = await triggerScanFn(
      scheduled.target,
      scheduled.scanType,
      scheduled.workspaceId,
      scheduled.mode,
    );

    const nextRun = getNextCronRun(scheduled.cronExpression);

    await storage.updateScheduledScan(scheduled.id, {
      lastRunAt: new Date(),
      nextRunAt: nextRun,
      lastScanId: scanId,
    });

    await emitScheduledScanTriggered(scheduled.workspaceId, scheduled.target, scanId);
  } catch (err) {
    log.error({ err, scheduledScanId: scheduled.id }, "Failed to trigger scheduled scan");

    // Still advance nextRunAt so we don't retry every minute
    try {
      const nextRun = getNextCronRun(scheduled.cronExpression);
      await storage.updateScheduledScan(scheduled.id, { nextRunAt: nextRun });
    } catch {
      // ignore update failure
    }
  }
}

/** Start the scheduler loop */
export function startScheduler(): void {
  if (intervalId) return;
  intervalId = setInterval(checkDueScans, CHECK_INTERVAL_MS);
  log.info("Scan scheduler started (checking every 60s)");

  // Run immediately on startup
  checkDueScans().catch((err) => log.error({ err }, "Initial scheduler check failed"));
}

/** Stop the scheduler loop */
export function stopScheduler(): void {
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
    log.info("Scan scheduler stopped");
  }
}
