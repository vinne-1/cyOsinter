/**
 * Unit tests for server/notifications.ts — WebSocket notification helpers.
 *
 * initNotifications requires a real HTTP server so we test the exported
 * alert-building functions by mocking storage.createAlert and verifying
 * the parameters passed to it.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock database
vi.mock("../../../server/db", () => ({ db: {} }));

const mockCreateAlert = vi.fn().mockImplementation(async (params: any) => ({
  id: "alert-1",
  ...params,
  createdAt: new Date(),
}));

vi.mock("../../../server/storage", () => ({
  storage: {
    createAlert: (...args: any[]) => mockCreateAlert(...args),
  },
}));

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
}));

import {
  emitScanCompleted,
  emitScanFailed,
  emitNewCriticalFinding,
  emitScheduledScanTriggered,
} from "../../../server/notifications";

beforeEach(() => {
  mockCreateAlert.mockClear();
});

// ---------------------------------------------------------------------------
// emitScanCompleted
// ---------------------------------------------------------------------------
describe("emitScanCompleted", () => {
  const baseScan = {
    id: "scan-1",
    workspaceId: "ws-1",
    target: "example.com",
    type: "easm",
    status: "completed",
    summary: { criticalCount: 2, highCount: 5 },
  } as any;

  it("creates an alert with scan_completed type", async () => {
    await emitScanCompleted(baseScan, 10);
    expect(mockCreateAlert).toHaveBeenCalledOnce();
    const args = mockCreateAlert.mock.calls[0][0];
    expect(args.type).toBe("scan_completed");
    expect(args.workspaceId).toBe("ws-1");
    expect(args.scanId).toBe("scan-1");
  });

  it("includes findings count in message", async () => {
    await emitScanCompleted(baseScan, 42);
    const args = mockCreateAlert.mock.calls[0][0];
    expect(args.message).toContain("42 findings");
  });

  it("sets severity to critical when criticalCount > 0", async () => {
    await emitScanCompleted(baseScan, 10);
    const args = mockCreateAlert.mock.calls[0][0];
    expect(args.severity).toBe("critical");
  });

  it("sets severity to high when no criticals but highCount > 0", async () => {
    const scan = { ...baseScan, summary: { criticalCount: 0, highCount: 3 } };
    await emitScanCompleted(scan as any, 5);
    const args = mockCreateAlert.mock.calls[0][0];
    expect(args.severity).toBe("high");
  });

  it("sets severity to info when no critical or high findings", async () => {
    const scan = { ...baseScan, summary: {} };
    await emitScanCompleted(scan as any, 2);
    const args = mockCreateAlert.mock.calls[0][0];
    expect(args.severity).toBe("info");
  });
});

// ---------------------------------------------------------------------------
// emitScanFailed
// ---------------------------------------------------------------------------
describe("emitScanFailed", () => {
  const baseScan = {
    id: "scan-2",
    workspaceId: "ws-2",
    target: "fail.com",
    type: "osint",
    status: "failed",
    summary: null,
  } as any;

  it("creates an alert with scan_failed type and high severity", async () => {
    await emitScanFailed(baseScan, "Connection timeout");
    const args = mockCreateAlert.mock.calls[0][0];
    expect(args.type).toBe("scan_failed");
    expect(args.severity).toBe("high");
    expect(args.message).toContain("Connection timeout");
  });

  it("truncates long error messages to 500 chars", async () => {
    const longMsg = "E".repeat(1000);
    await emitScanFailed(baseScan, longMsg);
    const args = mockCreateAlert.mock.calls[0][0];
    expect(args.message.length).toBe(500);
  });
});

// ---------------------------------------------------------------------------
// emitNewCriticalFinding
// ---------------------------------------------------------------------------
describe("emitNewCriticalFinding", () => {
  it("creates alert for critical finding", async () => {
    const finding = {
      id: "f-1",
      workspaceId: "ws-1",
      title: "RCE in API",
      description: "Remote code execution found",
      severity: "critical",
      category: "injection",
      affectedAsset: "api.example.com",
    } as any;

    await emitNewCriticalFinding(finding);
    expect(mockCreateAlert).toHaveBeenCalledOnce();
    const args = mockCreateAlert.mock.calls[0][0];
    expect(args.type).toBe("new_critical_finding");
    expect(args.severity).toBe("critical");
  });

  it("creates alert for high finding", async () => {
    const finding = {
      id: "f-2",
      workspaceId: "ws-1",
      title: "XSS in comments",
      description: "Stored XSS",
      severity: "high",
      category: "xss",
      affectedAsset: "example.com",
    } as any;

    await emitNewCriticalFinding(finding);
    const args = mockCreateAlert.mock.calls[0][0];
    expect(args.type).toBe("new_high_finding");
  });

  it("truncates description to 300 chars", async () => {
    const finding = {
      id: "f-long",
      workspaceId: "ws-1",
      title: "Issue",
      description: "D".repeat(500),
      severity: "critical",
      category: "misc",
      affectedAsset: null,
    } as any;
    await emitNewCriticalFinding(finding);
    const args = mockCreateAlert.mock.calls[0][0];
    expect(args.message.length).toBe(300);
  });

  it("does NOT create alert for medium/low/info findings", async () => {
    for (const severity of ["medium", "low", "info"]) {
      mockCreateAlert.mockClear();
      const finding = {
        id: `f-${severity}`,
        workspaceId: "ws-1",
        title: "Minor issue",
        description: "Something minor",
        severity,
        category: "info",
        affectedAsset: null,
      } as any;

      await emitNewCriticalFinding(finding);
      expect(mockCreateAlert).not.toHaveBeenCalled();
    }
  });
});

// ---------------------------------------------------------------------------
// emitScheduledScanTriggered
// ---------------------------------------------------------------------------
describe("emitScheduledScanTriggered", () => {
  it("creates alert with scheduled_scan_triggered type and info severity", async () => {
    await emitScheduledScanTriggered("ws-sched", "sched.com", "scan-99");
    expect(mockCreateAlert).toHaveBeenCalledOnce();
    const args = mockCreateAlert.mock.calls[0][0];
    expect(args.type).toBe("scheduled_scan_triggered");
    expect(args.severity).toBe("info");
    expect(args.workspaceId).toBe("ws-sched");
    expect(args.scanId).toBe("scan-99");
    expect(args.message).toContain("sched.com");
  });
});
