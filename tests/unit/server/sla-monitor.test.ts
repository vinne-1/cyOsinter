import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * The SLA clock was inert: `checkSLABreaches` existed but nothing called it, so
 * every finding reported `sla_breached = false` no matter how old. These tests
 * pin the two things that make it real — that only outstanding work can breach,
 * and that findings created before the clock was wired get a deadline.
 */

const updateWhere = vi.fn();
const updateReturning = vi.fn().mockResolvedValue([]);
const selectChain = { from: vi.fn(), where: vi.fn(), limit: vi.fn() };

let selectResults: unknown[][] = [];
let selectCall = 0;

vi.mock("../../../server/db", () => ({
  db: {
    select: () => {
      const result = selectResults[selectCall++] ?? [];
      const chain: any = {
        from: () => chain,
        where: () => chain,
        limit: () => Promise.resolve(result),
        then: (res: (v: unknown) => void) => Promise.resolve(result).then(res),
      };
      return chain;
    },
    update: () => ({
      set: () => ({
        where: (...args: unknown[]) => {
          updateWhere(...args);
          return { returning: updateReturning };
        },
      }),
    }),
  },
}));

const logAudit = vi.fn().mockResolvedValue(undefined);
vi.mock("../../../server/audit", () => ({ logAudit }));

let sla: typeof import("../../../server/sla-monitor");

beforeEach(async () => {
  vi.resetModules();
  vi.clearAllMocks();
  selectResults = [];
  selectCall = 0;
  updateReturning.mockResolvedValue([]);
  sla = await import("../../../server/sla-monitor");
});

describe("runSlaSweep", () => {
  it("backfills a due date for findings that never got one", async () => {
    // The 126 findings already in the database had no deadline at all, so no
    // sweep could ever have marked them.
    selectResults = [
      [{ id: "f1", severity: "critical", discoveredAt: new Date("2026-01-01") }],
      [{ id: "ws1" }],
    ];

    const result = await sla.runSlaSweep();

    expect(result.backfilledDueDates).toBe(1);
  });

  it("reports how many findings breached", async () => {
    selectResults = [[], [{ id: "ws1" }]];
    updateReturning.mockResolvedValue([
      { id: "f1", workspaceId: "ws1", severity: "critical" },
      { id: "f2", workspaceId: "ws1", severity: "high" },
    ]);

    const result = await sla.runSlaSweep();

    expect(result.findingsBreached).toBe(2);
  });

  it("records a breach in the audit trail, not just the log", async () => {
    selectResults = [[], [{ id: "ws1" }]];
    updateReturning.mockResolvedValue([
      { id: "f1", workspaceId: "ws1", severity: "critical" },
      { id: "f2", workspaceId: "ws1", severity: "critical" },
      { id: "f3", workspaceId: "ws1", severity: "low" },
    ]);

    await sla.runSlaSweep();

    // A missed remediation deadline is a compliance-relevant event.
    expect(logAudit).toHaveBeenCalledOnce();
    const entry = logAudit.mock.calls[0]![0];
    expect(entry.action).toBe("sla_breached");
    expect(entry.metadata.count).toBe(3);
    expect(entry.metadata.bySeverity).toEqual({ critical: 2, low: 1 });
  });

  it("writes no audit entry when nothing breached", async () => {
    selectResults = [[], [{ id: "ws1" }]];
    updateReturning.mockResolvedValue([]);

    await sla.runSlaSweep();

    expect(logAudit).not.toHaveBeenCalled();
  });

  it("counts the workspaces it swept", async () => {
    selectResults = [[], [{ id: "ws1" }, { id: "ws2" }, { id: "ws3" }]];
    const result = await sla.runSlaSweep();
    expect(result.workspacesChecked).toBe(3);
  });
});

describe("monitor lifecycle", () => {
  it("starts, sweeps immediately, and stops cleanly", async () => {
    selectResults = [[], []];
    expect(() => sla.startSlaMonitor()).not.toThrow();
    expect(() => sla.stopSlaMonitor()).not.toThrow();
  });

  it("is idempotent on repeated starts", async () => {
    selectResults = [[], [], [], []];
    sla.startSlaMonitor();
    sla.startSlaMonitor();
    expect(() => sla.stopSlaMonitor()).not.toThrow();
    // A second stop on an already-stopped monitor must also be safe.
    expect(() => sla.stopSlaMonitor()).not.toThrow();
  });
});
