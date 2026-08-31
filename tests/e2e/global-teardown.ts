// Playwright runs globalTeardown in its own process, which does not inherit the
// app's environment — without this DATABASE_URL is undefined and the cleanup
// silently no-ops, which is exactly how the leak went unnoticed.
import "dotenv/config";
import { Pool } from "pg";

/**
 * Removes the data the E2E suite creates.
 *
 * Without this, every run leaked: each spec makes a workspace named
 * `<prefix>-<timestamp>.example.com` and some make a throwaway user, and none of
 * it was ever removed. Ten runs had left 89 workspaces in the database, 65 of
 * them test fixtures, which buried the real ones in the workspace switcher and
 * made the app look broken.
 *
 * ── Safety ──────────────────────────────────────────────────────────────────
 * This deletes by OWNERSHIP, not by name. A workspace is removed only when
 * every one of its members is an `@e2e.local` account — so a real workspace can
 * never be caught by it, even one someone happened to call
 * "something.example.com". A workspace with any human member is left alone.
 *
 * The three long-lived fixture accounts are kept: `global-setup` reuses their
 * cached tokens across runs, and deleting them would force a fresh login every
 * time for no benefit.
 */

/** Fixture accounts global-setup reuses; deleting them just slows the next run. */
const PERSISTENT_USERS = [
  "auth-shared@e2e.local",
  "ws-user-a@e2e.local",
  "ws-user-b@e2e.local",
];

export default async function globalTeardown(): Promise<void> {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.log("[global-teardown] No DATABASE_URL; skipping cleanup.");
    return;
  }

  const pool = new Pool({ connectionString });
  try {
    // Workspaces whose membership is exclusively e2e accounts. The NOT EXISTS
    // clause is what makes this safe: one human member and the row survives.
    const { rows: workspaces } = await pool.query<{ id: string }>(
      `DELETE FROM workspaces w
        WHERE EXISTS (
                SELECT 1 FROM workspace_members m
                  JOIN users u ON u.id = m.user_id
                 WHERE m.workspace_id = w.id AND u.email LIKE '%@e2e.local'
              )
          AND NOT EXISTS (
                SELECT 1 FROM workspace_members m
                  JOIN users u ON u.id = m.user_id
                 WHERE m.workspace_id = w.id AND u.email NOT LIKE '%@e2e.local'
              )
        RETURNING w.id`,
    );

    // Orphaned workspaces with NO members at all and an obvious fixture name.
    // Some specs create a workspace via the scan endpoint, which does not always
    // attach a member, so ownership alone would miss them.
    const { rows: orphans } = await pool.query<{ id: string }>(
      `DELETE FROM workspaces w
        WHERE NOT EXISTS (SELECT 1 FROM workspace_members m WHERE m.workspace_id = w.id)
          AND w.name ~ '^(e2e|scan-list|scan-target|dup|ws)-[0-9]{10,}\\.example\\.com$'
        RETURNING w.id`,
    );

    // Throwaway accounts, keeping the reusable fixtures.
    const { rows: users } = await pool.query<{ id: string }>(
      `DELETE FROM users
        WHERE email LIKE '%@e2e.local'
          AND email <> ALL($1::text[])
        RETURNING id`,
      [PERSISTENT_USERS],
    );

    console.log(
      `[global-teardown] Removed ${workspaces.length} workspace(s), ` +
        `${orphans.length} orphan(s), ${users.length} throwaway user(s).`,
    );
  } catch (err) {
    // Never fail the run on cleanup: the tests already passed or failed on their
    // own merits, and a teardown error must not change that verdict.
    console.warn("[global-teardown] Cleanup failed (non-fatal):", err);
  } finally {
    await pool.end();
  }
}
