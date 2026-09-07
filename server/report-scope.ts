/**
 * Which findings belong in a report.
 *
 * Three independent paths build a deliverable from a workspace's findings:
 *
 *   `buildReportContent`   the JSON content, which the PDF renders from
 *   `buildDocxInput`       the Word document
 *   `GET …/reports/:id/export`  the CSV and XLSX
 *
 * Each open-coded the same two-part rule — "the explicit selection, or
 * everything" — and each got the second half wrong in the same way, because
 * "everything" silently meant every ROW rather than every finding. A client's
 * register opened with "DNSSEC Detection" and "security.txt File" (protections
 * that are WORKING) and "robots.txt file" and "AWS Service - Detect"
 * (technology facts), under a summary line reading *"This report covers 14
 * security findings"* when four of them were.
 *
 * The three were found one at a time, each fix revealing the next copy, which
 * is the argument for this file existing rather than a fourth careful edit.
 *
 * The asymmetry is deliberate:
 *
 *  - **No explicit selection** → security findings only. A report with no
 *    stated scope means "our outstanding exposure", and controls and recon
 *    facts are not that.
 *  - **An explicit `findingIds`** → exactly those rows, unfiltered. An operator
 *    who picked specific findings has made a decision, and second-guessing it
 *    would silently drop rows they deliberately included.
 */
import { isSecurityFinding } from "./scanner/finding-taxonomy.js";

/** The minimum a finding must carry to be scoped. */
export interface ScopableFinding {
  id: string;
  kind?: string | null;
}

export function selectReportFindings<T extends ScopableFinding>(
  all: T[],
  findingIds: string[] | null | undefined,
): T[] {
  const explicit = (findingIds?.length ?? 0) > 0;
  if (explicit) {
    const wanted = new Set(findingIds!);
    return all.filter((f) => wanted.has(f.id));
  }
  return all.filter((f) => isSecurityFinding(f));
}
