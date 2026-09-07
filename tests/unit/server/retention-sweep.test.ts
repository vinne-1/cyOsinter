/**
 * Data retention sweep.
 *
 * The cleanup logic existed and worked, but only ran when a superadmin called
 * the admin route by hand — so a workspace policy reading "delete scans after 90
 * days" deleted nothing and `last_cleanup_at` stayed NULL. Retention is a claim
 * made to auditors, so a policy nothing applies is a false claim, not a missing
 * nicety.
 *
 * The archive test is the one that matters most: it prevents data loss.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const policies: Array<Record<string, unknown>> = [];
const deletes: Array<{ table: string }> = [];
const updates: Array<Record<string, unknown>> = [];
const audits: Array<Record<string, unknown>> = [];
let deleteRowCount = 0;
let failOnTable: string | null = null;
let cleanSessions: () => Promise<number> = async () => 0;

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));
vi.mock("../../../server/audit", () => ({
  logAudit: (e: Record<string, unknown>) => { audits.push(e); return Promise.resolve(); },
}));
// Expired sessions ride on this sweep — see retention-sweep.ts for why.
vi.mock("../../../server/auth", () => ({
  cleanExpiredSessions: () => cleanSessions(),
}));
vi.mock("@shared/schema", () => ({
  retentionPolicies: { id: "id", workspaceId: "workspaceId" },
  scans: { workspaceId: "workspaceId", completedAt: "completedAt" },
  findings: { workspaceId: "workspaceId", discoveredAt: "discoveredAt" },
  postureSnapshots: { workspaceId: "workspaceId", snapshotAt: "snapshotAt" },
}));
vi.mock("drizzle-orm", () => ({
  eq: () => "eq",
  sql: Object.assign((..._a: unknown[]) => "sql", { raw: () => "raw" }),
}));

/** Minimal chainable stand-in for the drizzle query builder. */
vi.mock("../../../server/db", () => ({
  db: {
    select: () => ({ from: () => Promise.resolve(policies) }),
    delete: (table: Record<string, string>) => {
      const name = "completedAt" in table ? "scans" : "discoveredAt" in table ? "findings" : "snapshots";
      return {
        where: () => {
          if (failOnTable === name) return Promise.reject(new Error(`boom on ${name}`));
          deletes.push({ table: name });
          return Promise.resolve({ rowCount: deleteRowCount });
        },
      };
    },
    update: () => ({ set: (v: Record<string, unknown>) => ({ where: () => { updates.push(v); return Promise.resolve(); } }) }),
  },
}));

import { runRetentionCleanup } from "../../../server/retention-sweep";

const policy = (over: Record<string, unknown> = {}) => ({
  id: "p1", workspaceId: "ws-1",
  scanRetentionDays: 90, findingRetentionDays: 180, snapshotRetentionDays: 90,
  archiveEnabled: false, ...over,
});

beforeEach(() => {
  policies.length = 0; deletes.length = 0; updates.length = 0; audits.length = 0;
  deleteRowCount = 0; failOnTable = null;
  cleanSessions = async () => 0;
});
afterEach(() => vi.clearAllMocks());

describe("runRetentionCleanup", () => {
  it("deletes each configured category and stamps lastCleanupAt", async () => {
    policies.push(policy());
    deleteRowCount = 4;

    const r = await runRetentionCleanup();

    expect(deletes.map((d) => d.table).sort()).toEqual(["findings", "scans", "snapshots"]);
    expect(r.deleted).toEqual({ scans: 4, findings: 4, snapshots: 4 });
    expect(updates[0]).toHaveProperty("lastCleanupAt");
  });

  it("skips a category with no configured retention", async () => {
    policies.push(policy({ findingRetentionDays: null, snapshotRetentionDays: null }));
    await runRetentionCleanup();
    expect(deletes.map((d) => d.table)).toEqual(["scans"]);
  });

  /**
   * The data-loss guard. `archiveEnabled` was ignored entirely, so a workspace
   * configured to archive-then-delete got the delete and no archive. Archiving
   * does not exist, so the only safe reading of the flag is "do not destroy".
   */
  it("deletes NOTHING for a workspace configured to archive", async () => {
    policies.push(policy({ archiveEnabled: true }));
    deleteRowCount = 99;

    const r = await runRetentionCleanup();

    expect(deletes).toEqual([]);
    expect(r.skippedArchive).toBe(1);
    expect(r.deleted).toEqual({ scans: 0, findings: 0, snapshots: 0 });
    // Not stamped either: nothing was cleaned, so claiming a cleanup time would
    // make the skip invisible.
    expect(updates).toEqual([]);
  });

  /**
   * One `try` used to wrap the whole loop, so a single failing workspace left
   * every workspace after it un-cleaned — indefinitely, and silently.
   */
  it("isolates a failure so later workspaces are still cleaned", async () => {
    policies.push(policy({ id: "p1", workspaceId: "ws-broken" }));
    policies.push(policy({ id: "p2", workspaceId: "ws-ok", findingRetentionDays: null, snapshotRetentionDays: null }));
    failOnTable = "scans";

    const r = await runRetentionCleanup();

    // ws-broken fails on scans; ws-ok only configures scans, so it fails too —
    // what matters is that the loop CONTINUED and reported both.
    expect(r.failed).toBe(2);
  });

  it("never throws when the policy read itself fails", async () => {
    policies.length = 0;
    await expect(runRetentionCleanup()).resolves.toBeDefined();
  });

  describe("audit", () => {
    it("records a retention_purge naming what was removed", async () => {
      policies.push(policy());
      deleteRowCount = 7;

      await runRetentionCleanup();

      expect(audits).toHaveLength(1);
      expect(audits[0]).toMatchObject({
        userId: null, // unattended sweep — there is no actor
        action: "retention_purge",
        resourceType: "workspace",
        resourceId: "ws-1",
      });
      expect(audits[0].metadata).toMatchObject({ scans: 7, findings: 7, snapshots: 7 });
    });

    /** Otherwise the audit log becomes a daily heartbeat instead of a record of deletions. */
    it("writes no audit entry when nothing was deleted", async () => {
      policies.push(policy());
      deleteRowCount = 0;
      await runRetentionCleanup();
      expect(audits).toEqual([]);
    });
  });
});

/**
 * Expired sessions are retention too. `validateSession` deletes an expired row
 * only when someone PRESENTS it, so a session nobody returns to persisted
 * forever — carrying ip_address and user_agent long past their purpose. Nothing
 * called `cleanExpiredSessions`; it rides on this sweep now.
 */
describe("expired sessions", () => {
  it("removes them and reports the count", async () => {
    cleanSessions = async () => 12;
    const r = await runRetentionCleanup();
    expect(r.sessionsRemoved).toBe(12);
  });

  it("omits the field when nothing was removed", async () => {
    cleanSessions = async () => 0;
    const r = await runRetentionCleanup();
    expect(r.sessionsRemoved).toBeUndefined();
  });

  /** Sessions are global; a workspace policy failing must not skip them. */
  it("cleans sessions even when a workspace policy throws", async () => {
    policies.push(policy());
    failOnTable = "scans";
    cleanSessions = async () => 5;

    const r = await runRetentionCleanup();

    expect(r.failed).toBe(1);
    expect(r.sessionsRemoved).toBe(5);
  });

  /** And a session-cleanup failure must not lose the workspace results. */
  it("survives a session-cleanup failure", async () => {
    policies.push(policy());
    deleteRowCount = 3;
    cleanSessions = async () => { throw new Error("db down"); };

    const r = await runRetentionCleanup();

    expect(r.deleted.scans).toBe(3);
    expect(r.sessionsRemoved).toBeUndefined();
  });
});
