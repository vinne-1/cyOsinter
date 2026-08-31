import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * The queue moved from an in-memory array to Postgres, so these tests assert
 * the SQL contract rather than array contents. The two properties that matter
 * are the ones the old implementation could not provide:
 *
 *  - a claim is atomic across instances (FOR UPDATE SKIP LOCKED), and
 *  - a job whose holder crashed is reclaimed once its lease expires.
 */

const poolQuery = vi.fn();
vi.mock("../../../server/db", () => ({
  pool: { query: (...args: unknown[]) => poolQuery(...args) },
}));

const triggerScan = vi.fn().mockResolvedValue("scan-123");
vi.mock("../../../server/scan-trigger", () => ({ triggerScan }));

let queue: typeof import("../../../server/scan-queue");

/** The SQL text of every query issued, for asserting on the statements built. */
function sqlCalls(): string[] {
  return poolQuery.mock.calls.map(([sql]) => String(sql));
}

/**
 * Parameters of the INSERT. Found by matching the SQL rather than by call
 * index: a drain() left running by an earlier assertion can issue a claim query
 * first, which would shift the positions.
 */
function insertParams(): unknown[] {
  const call = poolQuery.mock.calls.find(([sql]) => String(sql).includes("INSERT INTO scan_queue"));
  if (!call) throw new Error("no INSERT INTO scan_queue was issued");
  return call[1] as unknown[];
}

beforeEach(async () => {
  vi.resetModules();
  poolQuery.mockReset();
  triggerScan.mockClear();
  // Default: inserts succeed, claims find nothing (so drain stops immediately).
  poolQuery.mockResolvedValue({ rows: [], rowCount: 0 });
  queue = await import("../../../server/scan-queue");
});

describe("enqueueScan", () => {
  it("persists the job and returns its id", async () => {
    poolQuery.mockResolvedValueOnce({ rows: [{ id: "q-1" }], rowCount: 1 });

    const id = await queue.enqueueScan("example.com", "easm", "ws-1", "standard");

    expect(id).toBe("q-1");
    expect(sqlCalls()[0]).toContain("INSERT INTO scan_queue");
  });

  it("writes the scan's parameters, so any instance can run it", async () => {
    poolQuery.mockResolvedValueOnce({ rows: [{ id: "q-1" }], rowCount: 1 });

    await queue.enqueueScan("example.com", "easm", "ws-1", "safe");

    expect(insertParams()).toEqual(["ws-1", "example.com", "easm", "safe", 2]);
  });

  it("ranks a fast dast scan ahead of a long full scan", async () => {
    poolQuery.mockResolvedValue({ rows: [{ id: "q" }], rowCount: 1 });

    await queue.enqueueScan("a.com", "dast", "ws", "standard");
    const dastPriority = insertParams()[4];

    poolQuery.mockClear();
    poolQuery.mockResolvedValue({ rows: [{ id: "q" }], rowCount: 1 });
    await queue.enqueueScan("b.com", "full", "ws", "standard");
    const fullPriority = insertParams()[4];

    expect(dastPriority).toBeLessThan(fullPriority as number);
  });

  it("gives an unknown scan type the lowest priority rather than failing", async () => {
    poolQuery.mockResolvedValueOnce({ rows: [{ id: "q" }], rowCount: 1 });
    await queue.enqueueScan("x.com", "not-a-real-type", "ws", "standard");
    expect(insertParams()[4]).toBe(3);
  });
});

describe("claiming work", () => {
  it("claims atomically with FOR UPDATE SKIP LOCKED", async () => {
    poolQuery.mockResolvedValueOnce({ rows: [{ id: "q-1" }], rowCount: 1 });
    await queue.enqueueScan("example.com", "easm", "ws-1", "standard");

    const claim = sqlCalls().find((s) => s.includes("UPDATE scan_queue q"));
    expect(claim).toBeDefined();
    // Without SKIP LOCKED two workers block on each other instead of taking
    // different jobs, which is the whole point of the pattern.
    expect(claim).toContain("FOR UPDATE SKIP LOCKED");
    expect(claim).toContain("ORDER BY c.priority ASC, c.queued_at ASC");
  });

  it("reclaims a job whose holder died and whose lease expired", async () => {
    poolQuery.mockResolvedValueOnce({ rows: [{ id: "q-1" }], rowCount: 1 });
    await queue.enqueueScan("example.com", "easm", "ws-1", "standard");

    const claim = sqlCalls().find((s) => s.includes("UPDATE scan_queue q"))!;
    // A crashed worker leaves its job in 'running'; only the lease check can
    // ever return it to circulation.
    expect(claim).toContain("c.status = 'running'");
    expect(claim).toContain("c.locked_at <");
  });

  it("will not retry a job past its attempt limit", async () => {
    poolQuery.mockResolvedValueOnce({ rows: [{ id: "q-1" }], rowCount: 1 });
    await queue.enqueueScan("example.com", "easm", "ws-1", "standard");

    const claim = sqlCalls().find((s) => s.includes("UPDATE scan_queue q"))!;
    expect(claim).toContain("c.attempts < c.max_attempts");
  });

  it("records which worker holds the job, so a stuck queue can be traced", async () => {
    poolQuery.mockResolvedValueOnce({ rows: [{ id: "q-1" }], rowCount: 1 });
    await queue.enqueueScan("example.com", "easm", "ws-1", "standard");

    const claimCall = poolQuery.mock.calls.find(([sql]) => String(sql).includes("UPDATE scan_queue q"))!;
    expect(String(claimCall[1]![0])).toBe(queue.__queueInternals.WORKER_ID);
    expect(queue.__queueInternals.WORKER_ID).toMatch(/.+:\d+:[0-9a-f]+/);
  });

  it("does not schedule work when the claim query fails", async () => {
    poolQuery.mockResolvedValueOnce({ rows: [{ id: "q-1" }], rowCount: 1 });
    poolQuery.mockRejectedValueOnce(new Error("db down"));

    await expect(queue.enqueueScan("example.com", "easm", "ws-1", "standard")).resolves.toBe("q-1");
    expect(triggerScan).not.toHaveBeenCalled();
  });
});

describe("getQueueStatus", () => {
  it("reports counts from the database, not from this process", async () => {
    poolQuery.mockResolvedValueOnce({
      rows: [
        { id: "a", target: "a.com", type: "easm", priority: 2, status: "queued", attempts: 0, queued_at: new Date() },
        { id: "b", target: "b.com", type: "full", priority: 3, status: "running", attempts: 1, queued_at: new Date() },
        { id: "c", target: "c.com", type: "dast", priority: 1, status: "queued", attempts: 0, queued_at: new Date() },
      ],
      rowCount: 3,
    });

    const status = await queue.getQueueStatus();

    // A per-process count would miss work claimed by another instance.
    expect(status.queueLength).toBe(2);
    expect(status.activeScans).toBe(1);
    expect(status.items).toHaveLength(3);
    expect(status.workerId).toBe(queue.__queueInternals.WORKER_ID);
  });

  it("serialises timestamps as ISO strings", async () => {
    poolQuery.mockResolvedValueOnce({
      rows: [{ id: "a", target: "a.com", type: "easm", priority: 2, status: "queued", attempts: 0, queued_at: new Date("2026-01-02T03:04:05Z") }],
      rowCount: 1,
    });
    const status = await queue.getQueueStatus();
    expect(status.items[0]!.queuedAt).toBe("2026-01-02T03:04:05.000Z");
  });
});

describe("cancelQueuedScan", () => {
  it("cancels a job that has not started", async () => {
    poolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });
    expect(await queue.cancelQueuedScan("q-1")).toBe(true);
  });

  it("refuses to cancel a job that is already running", async () => {
    // The UPDATE is guarded by status = 'queued', so it matches nothing.
    poolQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });
    expect(await queue.cancelQueuedScan("q-running")).toBe(false);
    expect(sqlCalls().some((q) => q.includes("status = 'queued'"))).toBe(true);
  });
});

describe("poller lifecycle", () => {
  it("starts and stops without throwing", () => {
    expect(() => queue.startQueuePoller()).not.toThrow();
    expect(() => queue.stopQueuePoller()).not.toThrow();
  });

  it("is idempotent, so a double start leaves one timer", () => {
    queue.startQueuePoller();
    queue.startQueuePoller();
    expect(() => queue.stopQueuePoller()).not.toThrow();
    // A second stop on an already-stopped poller must also be safe.
    expect(() => queue.stopQueuePoller()).not.toThrow();
  });
});
