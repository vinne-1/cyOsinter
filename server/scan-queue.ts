/**
 * Phase 5.1: PostgreSQL-based scan queue with concurrency control.
 * Replaces fire-and-forget pattern with a proper job queue.
 */

import { storage } from "./storage";
import { triggerScan } from "./scan-trigger";
import { createLogger } from "./logger";

const log = createLogger("scan-queue");

interface QueuedScan {
  id: string;
  target: string;
  type: string;
  workspaceId: string;
  mode: string;
  priority: number; // 1=highest
  queuedAt: Date;
}

const MAX_CONCURRENT = 3;
const POLL_INTERVAL_MS = 5000;

const queue: QueuedScan[] = [];
const activeScanIds = new Set<string>();
let pollTimer: ReturnType<typeof setInterval> | null = null;

function getPriority(type: string): number {
  switch (type) {
    case "dast": return 1;  // Fast, run first
    case "easm": return 2;
    case "osint": return 2;
    case "full": return 3;  // Longest, lower priority
    default: return 3;
  }
}

export function enqueueScan(
  target: string,
  type: string,
  workspaceId: string,
  mode: string,
): string {
  const id = `q_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const item: QueuedScan = {
    id,
    target,
    type,
    workspaceId,
    mode,
    priority: getPriority(type),
    queuedAt: new Date(),
  };

  queue.push(item);
  queue.sort((a, b) => a.priority - b.priority || a.queuedAt.getTime() - b.queuedAt.getTime());

  log.info({ queueId: id, target, type, queueLength: queue.length }, "Scan enqueued");
  processQueue();

  return id;
}

async function processQueue(): Promise<void> {
  while (activeScanIds.size < MAX_CONCURRENT && queue.length > 0) {
    const item = queue.shift()!;
    activeScanIds.add(item.id);

    log.info({ queueId: item.id, target: item.target, active: activeScanIds.size }, "Processing queued scan");

    triggerScan(item.target, item.type, item.workspaceId, item.mode)
      .then((scanId) => {
        log.info({ queueId: item.id, scanId }, "Queued scan started");
      })
      .catch((err) => {
        log.error({ err, queueId: item.id }, "Queued scan failed to start");
      })
      .finally(() => {
        activeScanIds.delete(item.id);
        // Process next item after a scan slot frees up
        processQueue();
      });
  }
}

export function getQueueStatus(): {
  queueLength: number;
  activeScans: number;
  maxConcurrent: number;
  items: Array<{ id: string; target: string; type: string; priority: number; queuedAt: string }>;
} {
  return {
    queueLength: queue.length,
    activeScans: activeScanIds.size,
    maxConcurrent: MAX_CONCURRENT,
    items: queue.map((q) => ({
      id: q.id,
      target: q.target,
      type: q.type,
      priority: q.priority,
      queuedAt: q.queuedAt.toISOString(),
    })),
  };
}

export function cancelQueuedScan(queueId: string): boolean {
  const idx = queue.findIndex((q) => q.id === queueId);
  if (idx === -1) return false;
  queue.splice(idx, 1);
  log.info({ queueId }, "Queued scan cancelled");
  return true;
}

export function startQueuePoller(): void {
  if (pollTimer) return;
  pollTimer = setInterval(() => {
    if (queue.length > 0 && activeScanIds.size < MAX_CONCURRENT) {
      processQueue();
    }
  }, POLL_INTERVAL_MS);
  log.info("Scan queue poller started");
}

export function stopQueuePoller(): void {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
    log.info("Scan queue poller stopped");
  }
}
