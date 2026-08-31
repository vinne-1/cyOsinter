import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * The slot gate is the only thing standing between the API and unbounded
 * concurrent scans, so these tests pin the behaviour that matters: a slot is
 * never handed out twice, the pooled connection is always returned, and a
 * failure to release cannot leak capacity.
 */

interface FakeClient {
  query: ReturnType<typeof vi.fn>;
  release: ReturnType<typeof vi.fn>;
}

const connect = vi.fn();
const poolQuery = vi.fn();

vi.mock("../../../server/db", () => ({
  pool: { connect: (...a: unknown[]) => connect(...a), query: (...a: unknown[]) => poolQuery(...a) },
}));

/** A client whose advisory-lock attempts succeed for the given slot indexes. */
function clientGranting(grantIndexes: number[]): FakeClient {
  const client: FakeClient = {
    query: vi.fn(async (sql: string, params?: unknown[]) => {
      if (sql.includes("pg_try_advisory_lock")) {
        const index = Number(params?.[1]);
        return { rows: [{ locked: grantIndexes.includes(index) }] };
      }
      return { rows: [] };
    }),
    release: vi.fn(),
  };
  return client;
}

let slots: typeof import("../../../server/scan-slots");

beforeEach(async () => {
  vi.resetModules();
  connect.mockReset();
  poolQuery.mockReset();
  process.env.SCAN_CONCURRENCY = "3";
  slots = await import("../../../server/scan-slots");
});

describe("tryAcquireSlot", () => {
  it("takes the first free slot", async () => {
    const client = clientGranting([0]);
    connect.mockResolvedValue(client);

    const slot = await slots.tryAcquireSlot();
    expect(slot).not.toBeNull();
    expect(slot!.index).toBe(0);
  });

  it("walks past busy slots to find a free one", async () => {
    // Slots 0 and 1 are held elsewhere; 2 is free.
    const client = clientGranting([2]);
    connect.mockResolvedValue(client);

    const slot = await slots.tryAcquireSlot();
    expect(slot!.index).toBe(2);
    // It must actually have tried the earlier indexes.
    const tried = client.query.mock.calls
      .filter(([sql]) => String(sql).includes("pg_try_advisory_lock"))
      .map(([, params]) => (params as unknown[])[1]);
    expect(tried).toEqual([0, 1, 2]);
  });

  it("returns null when every slot is held", async () => {
    const client = clientGranting([]);
    connect.mockResolvedValue(client);

    expect(await slots.tryAcquireSlot()).toBeNull();
  });

  it("returns the connection to the pool when no slot is free", async () => {
    const client = clientGranting([]);
    connect.mockResolvedValue(client);

    await slots.tryAcquireSlot();
    // Holding a connection while running nothing would drain the pool.
    expect(client.release).toHaveBeenCalledOnce();
  });

  it("never tries more slots than the configured concurrency", async () => {
    const client = clientGranting([]);
    connect.mockResolvedValue(client);

    await slots.tryAcquireSlot();
    const tried = client.query.mock.calls.filter(([sql]) =>
      String(sql).includes("pg_try_advisory_lock"),
    );
    expect(tried).toHaveLength(3);
  });

  it("returns null rather than throwing when the pool is exhausted", async () => {
    connect.mockRejectedValue(new Error("timeout acquiring client"));
    expect(await slots.tryAcquireSlot()).toBeNull();
  });
});

describe("slot release", () => {
  it("unlocks the slot and returns the connection", async () => {
    const client = clientGranting([0]);
    connect.mockResolvedValue(client);

    const slot = await slots.tryAcquireSlot();
    await slot!.release();

    const unlocks = client.query.mock.calls.filter(([sql]) =>
      String(sql).includes("pg_advisory_unlock"),
    );
    expect(unlocks).toHaveLength(1);
    expect(client.release).toHaveBeenCalledOnce();
  });

  it("is idempotent, so a double release cannot free someone else's slot", async () => {
    const client = clientGranting([0]);
    connect.mockResolvedValue(client);

    const slot = await slots.tryAcquireSlot();
    await slot!.release();
    await slot!.release();

    expect(client.query.mock.calls.filter(([s]) => String(s).includes("pg_advisory_unlock"))).toHaveLength(1);
    expect(client.release).toHaveBeenCalledOnce();
  });

  it("still returns the connection when the unlock query fails", async () => {
    const client = clientGranting([0]);
    client.query.mockImplementation(async (sql: string, params?: unknown[]) => {
      if (sql.includes("pg_try_advisory_lock")) return { rows: [{ locked: Number(params?.[1]) === 0 }] };
      throw new Error("connection reset");
    });
    connect.mockResolvedValue(client);

    const slot = await slots.tryAcquireSlot();
    await expect(slot!.release()).resolves.toBeUndefined();
    expect(client.release).toHaveBeenCalledOnce();
  });
});

describe("withScanSlot", () => {
  it("runs the task and reports that it ran", async () => {
    connect.mockResolvedValue(clientGranting([0]));
    const result = await slots.withScanSlot(async () => "done");
    expect(result).toEqual({ ran: true, value: "done" });
  });

  it("releases the slot after the task resolves", async () => {
    const client = clientGranting([0]);
    connect.mockResolvedValue(client);

    await slots.withScanSlot(async () => "done");
    expect(client.release).toHaveBeenCalledOnce();
  });

  it("releases the slot when the task throws, so capacity is not leaked", async () => {
    const client = clientGranting([0]);
    connect.mockResolvedValue(client);

    await expect(
      slots.withScanSlot(async () => { throw new Error("scan blew up"); }),
    ).rejects.toThrow("scan blew up");

    expect(client.query.mock.calls.some(([s]) => String(s).includes("pg_advisory_unlock"))).toBe(true);
    expect(client.release).toHaveBeenCalledOnce();
  });

  it("does NOT run the task when no slot can be acquired", async () => {
    connect.mockResolvedValue(clientGranting([]));
    const task = vi.fn();

    const result = await slots.withScanSlot(task, { timeoutMs: 10, pollMs: 5 });

    expect(result).toEqual({ ran: false });
    expect(task).not.toHaveBeenCalled();
  });
});

describe("acquireSlot", () => {
  it("gives up once the timeout passes", async () => {
    connect.mockResolvedValue(clientGranting([]));
    const started = Date.now();
    expect(await slots.acquireSlot({ timeoutMs: 40, pollMs: 10 })).toBeNull();
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("returns immediately when already aborted", async () => {
    connect.mockResolvedValue(clientGranting([0]));
    const ac = new AbortController();
    ac.abort();
    expect(await slots.acquireSlot({ signal: ac.signal })).toBeNull();
  });

  it("succeeds once a slot frees up between polls", async () => {
    let free = false;
    connect.mockImplementation(async () => clientGranting(free ? [0] : []));
    setTimeout(() => { free = true; }, 25);

    const slot = await slots.acquireSlot({ timeoutMs: 2000, pollMs: 10 });
    expect(slot).not.toBeNull();
  });
});

describe("slotsInUse", () => {
  it("counts granted advisory locks in the scan namespace", async () => {
    poolQuery.mockResolvedValue({ rows: [{ count: "2" }] });
    expect(await slots.slotsInUse()).toBe(2);
  });

  it("reports zero rather than throwing when the query fails", async () => {
    poolQuery.mockRejectedValue(new Error("db down"));
    expect(await slots.slotsInUse()).toBe(0);
  });
});
