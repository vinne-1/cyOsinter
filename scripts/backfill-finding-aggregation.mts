/**
 * Collapses per-instance findings that should have been one finding per host.
 *
 * `checkCookieSecurity` now emits ONE finding per host with every cookie kept as
 * structured evidence — one misconfiguration with N instances, not N findings.
 * That fix changed what new scans produce and could not change what was already
 * stored: a live workspace still shows 26 separate "Insecure Cookie: <name>"
 * rows for a single host, which buries every other result, inflates the severity
 * counts the posture score is built from, and makes the dashboard contradict the
 * engine's current behaviour.
 *
 * ── What it does ────────────────────────────────────────────────────────────
 * For each (workspace, host, category) group of per-instance findings it keeps
 * ONE row and folds the rest into it:
 *
 *   title      rewritten to the aggregate form
 *   severity   the WORST severity in the group — collapsing must never lower
 *              the recorded risk
 *   evidence   every instance from every row in the group, preserved in full
 *   status     the most-progressed status in the group (see below)
 *
 * ── Safety ──────────────────────────────────────────────────────────────────
 * Analyst work is never discarded. If any row in a group was resolved, marked a
 * false positive, or accepted as risk, the survivor inherits that status rather
 * than reverting to open — re-opening work somebody already closed is worse than
 * leaving the duplicates in place. The survivor is the OLDEST row in the group,
 * so its creation time, SLA deadline and any case links stay valid.
 *
 * Rows that are already aggregated are left alone, so the script is idempotent.
 *
 * Run with --dry-run first. That is the default; --apply is required to write.
 *
 *   npx tsx scripts/backfill-finding-aggregation.mts            # report only
 *   npx tsx scripts/backfill-finding-aggregation.mts --apply    # write
 */

import "dotenv/config";
import pg from "pg";

const APPLY = process.argv.includes("--apply");

/**
 * Categories whose findings were historically emitted per instance.
 *
 * `titlePattern` identifies a per-instance row; a row whose title does not match
 * is already an aggregate and must not be touched.
 */
const AGGREGATABLE = [
  {
    category: "cookie_security",
    titlePattern: /^Insecure Cookie:\s*(.+)$/i,
    aggregateTitle: (host: string, n: number) => `Insecure Cookie Attributes on ${host} (${n} cookies)`,
    describe: (host: string, n: number, names: string[]) =>
      `${n} cookie(s) set by ${host} are missing one or more of the Secure, HttpOnly and SameSite attributes: ${names.slice(0, 12).join(", ")}${names.length > 12 ? `, and ${names.length - 12} more` : ""}. This is a single misconfiguration with ${n} instances rather than ${n} separate problems; each affected cookie is preserved in the evidence below.`,
  },
] as const;

/** Ordered worst-first. */
const SEVERITY_RANK = ["critical", "high", "medium", "low", "info"];

/**
 * Statuses ordered by how much analyst work they represent. A group containing
 * any of the closed states keeps that state.
 */
const STATUS_PRECEDENCE = ["resolved", "false_positive", "accepted_risk", "in_progress", "triaged", "open"];

interface Row {
  id: string;
  workspace_id: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  category: string;
  affected_asset: string;
  evidence: unknown[] | null;
  workflow_state: string | null;
  discovered_at: string;
}

function worstSeverity(rows: Row[]): string {
  for (const s of SEVERITY_RANK) if (rows.some((r) => r.severity === s)) return s;
  return rows[0].severity;
}

function mostProgressedStatus(rows: Row[]): string {
  for (const s of STATUS_PRECEDENCE) if (rows.some((r) => r.status === s)) return s;
  return rows[0].status;
}

/**
 * `workflow_state` is a second lifecycle column that must not disagree with
 * `status` after the merge. Take it from whichever row supplied the winning
 * status, so the pair stays coherent.
 */
function workflowStateFor(rows: Row[], status: string): string | null {
  return rows.find((r) => r.status === status)?.workflow_state ?? rows[0].workflow_state;
}

async function main(): Promise<void> {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error("DATABASE_URL is not set.");
    process.exit(1);
  }

  const pool = new pg.Pool({ connectionString });
  let groupsFound = 0;
  let rowsFolded = 0;

  try {
    for (const spec of AGGREGATABLE) {
      const { rows } = await pool.query<Row>(
        `SELECT id, workspace_id, title, description, severity, status, category,
                affected_asset, evidence, discovered_at, workflow_state
           FROM findings
          WHERE category = $1
          ORDER BY discovered_at ASC NULLS FIRST`,
        [spec.category],
      );

      // Group by workspace + host. Anything whose title is already the
      // aggregate form is skipped, which is what makes a second run a no-op.
      const groups = new Map<string, Row[]>();
      for (const r of rows) {
        if (!spec.titlePattern.test(r.title)) continue;
        const key = `${r.workspace_id}::${r.affected_asset}`;
        (groups.get(key) ?? groups.set(key, []).get(key)!).push(r);
      }

      for (const [key, group] of Array.from(groups.entries())) {
        if (group.length < 2) continue; // a single instance is already "one per host"
        groupsFound++;
        rowsFolded += group.length - 1;

        const [, host] = key.split("::");
        const survivor = group[0]; // oldest — keeps its SLA clock and case links
        const doomed = group.slice(1);
        const instanceNames = group
          .map((r) => r.title.match(spec.titlePattern)?.[1]?.trim())
          .filter((n): n is string => !!n);

        // Every instance's evidence, plus a note recording the merge itself so
        // the collapse is auditable rather than silent.
        const mergedEvidence: unknown[] = [];
        for (const r of group) {
          for (const e of r.evidence ?? []) mergedEvidence.push(e);
        }
        mergedEvidence.push({
          type: "aggregation",
          description: `Collapsed ${group.length} per-instance findings into one finding for this host`,
          snippet: `Original findings: ${instanceNames.join(", ")}`,
          source: "backfill-finding-aggregation",
          verifiedAt: new Date().toISOString(),
        });

        const severity = worstSeverity(group);
        const status = mostProgressedStatus(group);
        const workflowState = workflowStateFor(group, status);
        const title = spec.aggregateTitle(host, group.length);
        const description = spec.describe(host, group.length, instanceNames);

        console.log(
          `${APPLY ? "MERGE" : "would merge"}  ${host}  ${group.length} rows -> 1  ` +
            `[severity ${severity}, status ${status}]`,
        );

        if (!APPLY) continue;

        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          await client.query(
            `UPDATE findings
                SET title = $1, description = $2, severity = $3, status = $4,
                    workflow_state = COALESCE($5, workflow_state), evidence = $6
              WHERE id = $7`,
            [title, description, severity, status, workflowState, JSON.stringify(mergedEvidence), survivor.id],
          );
          // Case links point at findings that are about to disappear; move them
          // to the survivor so a case never loses its evidence. ON CONFLICT
          // covers a case already linked to the survivor.
          await client.query(
            `UPDATE case_findings SET finding_id = $1
              WHERE finding_id = ANY($2::varchar[])
                AND NOT EXISTS (
                  SELECT 1 FROM case_findings cf2
                   WHERE cf2.case_id = case_findings.case_id AND cf2.finding_id = $1
                )`,
            [survivor.id, doomed.map((d) => d.id)],
          );
          await client.query(`DELETE FROM case_findings WHERE finding_id = ANY($1::varchar[])`, [doomed.map((d) => d.id)]);
          await client.query(`DELETE FROM findings WHERE id = ANY($1::varchar[])`, [doomed.map((d) => d.id)]);
          await client.query("COMMIT");
        } catch (err) {
          await client.query("ROLLBACK");
          throw err;
        } finally {
          client.release();
        }
      }
    }

    if (groupsFound === 0) {
      console.log("\nNothing to change — no per-instance finding groups remain.");
    } else {
      console.log(
        `\n${APPLY ? "Merged" : "Would merge"} ${groupsFound} group(s), removing ${rowsFolded} duplicate row(s).`,
      );
      if (!APPLY) console.log("Re-run with --apply to write.");
    }
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
