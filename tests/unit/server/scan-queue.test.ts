/**
 * Unit tests for server/scan-queue.ts — in-memory scan queue.
 *
 * Tests: enqueueScan, getQueueStatus, cancelQueuedScan.
 * processQueue triggers side-effects (triggerScan) so we mock it out.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

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
} from "../../../server/scan-queue";

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
// cancelQueuedScan
// ---------------------------------------------------------------------------
describe("cancelQueuedScan", () => {
  it("returns false for non-existent queue ID", () => {
    expect(cancelQueuedScan("nonexistent")).toBe(false);
  });
});
