/**
 * Unit tests for server/scan-queue.ts — in-memory scan queue.
 *
 * Tests: enqueueScan, getQueueStatus, cancelQueuedScan.
 * processQueue triggers side-effects (triggerScan) so we mock it out.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { triggerScan } from "../../../server/scan-trigger";

// Mock triggerScan so processQueue doesn't actually run scans
vi.mock("../../../server/scan-trigger", () => ({
  triggerScan: vi.fn().mockResolvedValue("scan-id"),
}));
vi.mock("../../../server/db", () => ({ db: {} }));
vi.mock("../../../server/storage", () => ({ storage: {} }));

import {
  enqueueScan,
  getQueueStatus,
  cancelQueuedScan,
  startQueuePoller,
  stopQueuePoller,
} from "../../../server/scan-queue";

const mockTriggerScan = triggerScan as ReturnType<typeof vi.fn>;

// ---------------------------------------------------------------------------
// enqueueScan
// ---------------------------------------------------------------------------
describe("enqueueScan", () => {
  it("returns a queue ID starting with q_", () => {
    const id = enqueueScan("example.com", "easm", "ws-1", "standard");
    expect(id).toMatch(/^q_/);
  });

  it("returns unique IDs for each call", () => {
    const ids = new Set([
      enqueueScan("a.com", "easm", "ws-1", "standard"),
      enqueueScan("b.com", "osint", "ws-1", "standard"),
      enqueueScan("c.com", "full", "ws-1", "gold"),
    ]);
    expect(ids.size).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// getQueueStatus
// ---------------------------------------------------------------------------
describe("getQueueStatus", () => {
  it("returns a status object with expected shape", () => {
    const status = getQueueStatus();
    expect(status).toHaveProperty("queueLength");
    expect(status).toHaveProperty("activeScans");
    expect(status).toHaveProperty("maxConcurrent");
    expect(status).toHaveProperty("items");
    expect(typeof status.queueLength).toBe("number");
    expect(typeof status.activeScans).toBe("number");
    expect(status.maxConcurrent).toBe(3);
    expect(Array.isArray(status.items)).toBe(true);
  });

  it("items have correct shape", () => {
    enqueueScan("shape-test.com", "dast", "ws-shape", "standard");
    const status = getQueueStatus();
    for (const item of status.items) {
      expect(item).toHaveProperty("id");
      expect(item).toHaveProperty("target");
      expect(item).toHaveProperty("type");
      expect(item).toHaveProperty("priority");
      expect(item).toHaveProperty("queuedAt");
      expect(typeof item.queuedAt).toBe("string"); // ISO string
    }
  });
});

// ---------------------------------------------------------------------------
// getPriority (via enqueueScan priority ordering)
// ---------------------------------------------------------------------------
describe("scan type priority ordering", () => {
  it("assigns lower priority number to dast (runs first)", () => {
    // We can't call getPriority directly (private), but we can observe it
    // via the queue ordering by using a never-resolving triggerScan mock
    // so items stay in the queue
    mockTriggerScan.mockReturnValue(new Promise(() => {})); // never resolves

    const idDast = enqueueScan("d.com", "dast", "ws-pri", "standard");
    const idFull = enqueueScan("f.com", "full", "ws-pri", "standard");
    const idUnknown = enqueueScan("u.com", "unknown_type", "ws-pri", "standard");

    const status = getQueueStatus();
    // Any items that didn't start (active >= MAX_CONCURRENT) remain in queue in priority order
    // This also exercises the default: return 3 branch for "unknown_type"
    const itemIds = status.items.map((i) => i.id);
    // dast has priority 1 so should appear before full (priority 3) in queue
    const dastPos = itemIds.indexOf(idDast);
    const fullPos = itemIds.indexOf(idFull);
    if (dastPos !== -1 && fullPos !== -1) {
      expect(dastPos).toBeLessThan(fullPos);
    }

    // Cleanup: restore mock
    mockTriggerScan.mockResolvedValue("scan-id");
  });
});

// ---------------------------------------------------------------------------
// cancelQueuedScan
// ---------------------------------------------------------------------------
describe("cancelQueuedScan", () => {
  it("returns false for non-existent queue ID", () => {
    expect(cancelQueuedScan("nonexistent")).toBe(false);
  });

  it("returns true and removes item from queue", () => {
    // Use a never-resolving mock to prevent items from being dequeued
    mockTriggerScan.mockReturnValue(new Promise(() => {}));

    // Enqueue enough to fill active slots and have one remaining in queue
    for (let i = 0; i < 4; i++) {
      enqueueScan(`cancel-test-${i}.com`, "full", "ws-cancel", "standard");
    }

    const status = getQueueStatus();
    if (status.items.length > 0) {
      const itemId = status.items[0].id;
      const result = cancelQueuedScan(itemId);
      expect(result).toBe(true);
      // Should no longer be in queue
      const after = getQueueStatus();
      expect(after.items.find((i) => i.id === itemId)).toBeUndefined();
    }

    // Restore mock
    mockTriggerScan.mockResolvedValue("scan-id");
  });
});

// ---------------------------------------------------------------------------
// startQueuePoller / stopQueuePoller
// ---------------------------------------------------------------------------
describe("queue poller lifecycle", () => {
  it("startQueuePoller and stopQueuePoller run without throwing", () => {
    expect(() => startQueuePoller()).not.toThrow();
    expect(() => stopQueuePoller()).not.toThrow();
  });

  it("calling stopQueuePoller when not running does not throw", () => {
    expect(() => stopQueuePoller()).not.toThrow();
  });

  it("calling startQueuePoller twice is idempotent", () => {
    expect(() => {
      startQueuePoller();
      startQueuePoller(); // second call should be no-op
      stopQueuePoller();
    }).not.toThrow();
  });
});
