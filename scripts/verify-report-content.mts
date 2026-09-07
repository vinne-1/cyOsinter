/**
 * Does the generated report contain what the workspace actually holds?
 *
 * The report is the client deliverable, and it is assembled by TWO independent
 * paths — `buildReportContent` for the JSON/PDF content and `buildDocxInput`
 * for the Word document. Each carried its own copy of the "which rows are work"
 * rule, and both got it wrong: a register listed **14 findings where the
 * security work was 4**, opening with "DNSSEC Detection" — a protection that is
 * WORKING — as the first row the client reads.
 *
 * Neither the unit suite nor the API reconciler could see it: there is no
 * read-only endpoint that returns report content, so this drives the builders
 * directly. That is also why it is a script rather than a test — it needs a
 * live database and reads whatever workspaces exist.
 *
 *   npx tsx scripts/verify-report-content.mts
 *
 * Exits non-zero if a report disagrees with the workspace it describes.
 */
import "dotenv/config";
import { storage, FULL_SET_LIMIT } from "../server/storage.js";
import { buildReportContent } from "../server/routes/report-helpers.js";
import { buildDocxInput } from "../server/report-docx-input.js";
import { isSecurityFinding } from "../server/scanner/finding-taxonomy.js";

const problems: string[] = [];
/** Workspaces whose reports were actually built — see the guard at the end. */
let verified = 0;

const wss = await storage.getWorkspaces();
for (const w of wss as Array<{ id: string; name: string }>) {
  const { data: findings } = await storage.getFindings(w.id, { limit: FULL_SET_LIMIT });
  if (findings.length === 0) continue;
  verified++;

  // The same definition the inbox and the security score use.
  const openSec = findings.filter(
    (f) => f.status === "open" && isSecurityFinding(f as { kind?: string | null }),
  );

  const { content } = await buildReportContent(w.id, undefined, "full_report");
  const c = content as Record<string, unknown>;
  const reported = (c.totalFindings as number) ?? -1;

  const docx = await buildDocxInput(w.id, {});
  const cov = c.ipEnrichmentCoverage as { requested?: number; enriched?: number } | undefined;

  if (reported !== openSec.length) {
    problems.push(`[${w.name}] report content counts ${reported} findings != ${openSec.length} open security`);
  }
  if (docx.findings.length !== openSec.length) {
    problems.push(`[${w.name}] DOCX register has ${docx.findings.length} rows != ${openSec.length} open security`);
  }

  console.log(
    `${w.name}: openSec=${openSec.length} content=${reported} docx=${docx.findings.length}` +
    ` ipCoverage=${cov ? `${cov.enriched}/${cov.requested}` : "-"}`,
  );
}

/*
 * A gate that checked nothing must not report success.
 *
 * Every workspace with no findings is skipped, so on a fresh or emptied
 * database this would loop over nothing and print its success line. The
 * authorization probe shipped with exactly that hole — a bad header made
 * every request 401, each iteration hit `continue`, and it still claimed the
 * property held. Counting what was actually examined is the cheapest defence.
 */
if (verified === 0) {
  problems.push(
    "NO COVERAGE: no workspace had findings, so no report was built — this run cannot have passed",
  );
}

if (problems.length) {
  console.error("");
  console.error(`${problems.length} disagreement(s):`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log("");
console.log("reports describe exactly the open security findings of each workspace.");
process.exit(0);
