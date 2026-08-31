/**
 * Backfills `findings.kind` and repairs the `informational` category.
 *
 * The taxonomy fix (server/scanner/finding-taxonomy.ts) changed what new scans
 * produce, but it could not change what was already stored: 25 of the findings
 * in this database sit in a single `informational` category that mixes real
 * weaknesses, controls that are working, and pure technology facts. Until those
 * rows are repaired the fix is invisible to anyone actually using the product —
 * the inbox still shows the broken taxonomy.
 *
 * ── Safety ──────────────────────────────────────────────────────────────────
 * This script never deletes a finding and never changes its severity, status or
 * workflow state. It writes two columns:
 *
 *   kind      derived from the finding's own title and severity
 *   category  only for rows sitting in a catch-all bucket (`informational` or
 *             `unclassified`); a category any scanner module chose deliberately
 *             is never overwritten
 *
 * It is idempotent — a second run reports "nothing to change" — and re-running
 * it after adding a taxonomy rule is how previously unclassifiable rows get
 * resolved.
 *
 * A finding that has been triaged, assigned, commented on or resolved keeps all
 * of that. Reclassifying is not the same as discarding, and a row an analyst has
 * worked on must survive a taxonomy change intact.
 *
 * Run with --dry-run first. That is the default; --apply is required to write.
 *
 *   npx tsx scripts/backfill-finding-kind.mts            # report only
 *   npx tsx scripts/backfill-finding-kind.mts --apply    # write
 */

import "dotenv/config";
import pg from "pg";
import { classifyObservation } from "../server/scanner/finding-taxonomy.js";

interface Row {
  id: string;
  title: string;
  severity: string;
  category: string;
  kind: string;
}

const APPLY = process.argv.includes("--apply");

async function main(): Promise<void> {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error("DATABASE_URL is not set.");
    process.exit(1);
  }

  const pool = new pg.Pool({ connectionString });
  try {
    const { rows } = await pool.query<Row>(
      `SELECT id, title, severity, category, kind FROM findings ORDER BY discovered_at`,
    );
    console.log(`Read ${rows.length} finding(s).\n`);

    const changes: Array<{ row: Row; kind: string; category: string; reason: string }> = [];

    for (const row of rows) {
      // ONLY the two catch-all buckets are touched.
      //
      // `informational` is the original broken one. `unclassified` is where a
      // previous run of this script put observations no rule matched, so
      // re-running after a rule is added is how those get resolved; if still
      // nothing matches, the row stays exactly where it is.
      //
      // Everything else is left alone on purpose. Any other category was a
      // deliberate decision by a scanner module that had the whole observation
      // in front of it — template id, evidence, matched URL — where this script
      // has nothing but a stored title. Re-deriving those from title text would
      // overrule a better-informed judgement with a worse-informed one, and the
      // first dry run did exactly that: it wanted to demote "Shodan-indexed
      // exposure for 40.126.18.35" from a network_exposure finding to recon
      // purely because the title reads like an observation.
      if (row.category !== "informational" && row.category !== "unclassified") continue;

      const isCve = /\bCVE-\d{4}-\d{4,}\b/i.test(row.title);
      const cls = classifyObservation("", row.title, row.severity, isCve);
      // Take the derived category whatever the kind. Keeping `informational` on
      // the recon and control rows would leave the very label this work exists
      // to remove sitting on 15 findings — a control gets the control's name,
      // and a technology fact gets "technology".
      const nextCategory = cls.category;

      if (nextCategory === row.category && cls.kind === row.kind) continue;
      changes.push({ row, kind: cls.kind, category: nextCategory, reason: cls.reason });
    }

    if (changes.length === 0) {
      console.log("Nothing to change.");
      return;
    }

    const byKind = new Map<string, number>();
    for (const c of changes) byKind.set(c.kind, (byKind.get(c.kind) ?? 0) + 1);

    console.log(`${changes.length} finding(s) would change:\n`);
    for (const c of changes) {
      const cat = c.category === c.row.category ? c.row.category : `${c.row.category} → ${c.category}`;
      console.log(`  [${c.row.kind} → ${c.kind}] ${cat}`);
      console.log(`      ${c.row.title}`);
      console.log(`      ${c.reason}`);
    }
    console.log(`\nBy kind: ${[...byKind].map(([k, n]) => `${k}=${n}`).join(", ")}`);

    if (!APPLY) {
      console.log("\nDry run. Re-run with --apply to write these changes.");
      return;
    }

    // One transaction: a half-applied taxonomy is harder to reason about than
    // either the old one or the new one.
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      for (const c of changes) {
        await client.query(`UPDATE findings SET kind = $1, category = $2 WHERE id = $3`, [
          c.kind,
          c.category,
          c.row.id,
        ]);
      }
      await client.query("COMMIT");
      console.log(`\nApplied ${changes.length} update(s).`);
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error("Backfill failed:", err);
  process.exit(1);
});
