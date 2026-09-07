import { createLogger } from "./logger";
import { storage } from "./storage";
import { isSecurityFinding } from "./scanner/finding-taxonomy";
import type { Finding } from "@shared/schema";

const log = createLogger("differential-reporting");

const SEVERITY_SCORES: Record<string, number> = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 1,
  info: 0,
};

export interface ScanDiff {
  newFindings: Finding[];
  fixedFindings: Finding[];
  persistingFindings: Finding[];
  riskDelta: number;
}

function findingKey(finding: Finding): string {
  return `${finding.title}::${finding.affectedAsset ?? ""}`;
}

function computeRiskScore(findings: readonly Finding[]): number {
  return findings.reduce((total, f) => {
    const severity = (f.severity ?? "info").toLowerCase();
    return total + (SEVERITY_SCORES[severity] ?? 0);
  }, 0);
}

/**
 * Compare findings between two scans to show what's new, fixed, and persisting.
 * scanId1 is the older (baseline) scan, scanId2 is the newer scan.
 */
export async function compareScanFindings(
  scanId1: string,
  scanId2: string,
): Promise<ScanDiff> {
  try {
    const scan1 = await storage.getScan(scanId1);
    const scan2 = await storage.getScan(scanId2);

    if (!scan1 || !scan2) {
      const missing = !scan1 ? scanId1 : scanId2;
      log.warn({ scanId: missing }, "Scan not found for comparison");
      return { newFindings: [], fixedFindings: [], persistingFindings: [], riskDelta: 0 };
    }

    // Fetch findings for both workspaces, then filter by scanId
    const [result1, result2] = await Promise.all([
      storage.getFindings(scan1.workspaceId, { limit: 10000 }),
      storage.getFindings(scan2.workspaceId, { limit: 10000 }),
    ]);

    /*
     * Security rows only. The diff is rendered as New / Fixed / Persisting
     * findings with severity badges and feeds `riskDelta`, so a recon row
     * ("Apache Detection") appearing in a new scan would be reported as a new
     * FINDING and a control that started being detected would look like a
     * regression.
     *
     * Status is deliberately NOT filtered here, unlike everywhere else this
     * rule appears: which rows are closed is the diff's own subject matter, and
     * removing them would delete the "fixed" half of the answer.
     */
    const findings1 = result1.data.filter((f) => f.scanId === scanId1 && isSecurityFinding(f));
    const findings2 = result2.data.filter((f) => f.scanId === scanId2 && isSecurityFinding(f));

    const oldKeys = new Map<string, Finding>();
    for (const f of findings1) {
      oldKeys.set(findingKey(f), f);
    }

    const newKeys = new Map<string, Finding>();
    for (const f of findings2) {
      newKeys.set(findingKey(f), f);
    }

    const newFindings: Finding[] = [];
    const persistingFindings: Finding[] = [];

    for (const [key, finding] of Array.from(newKeys)) {
      if (oldKeys.has(key)) {
        persistingFindings.push(finding);
      } else {
        newFindings.push(finding);
      }
    }

    const fixedFindings: Finding[] = [];
    for (const [key, finding] of Array.from(oldKeys)) {
      if (!newKeys.has(key)) {
        fixedFindings.push(finding);
      }
    }

    const oldRisk = computeRiskScore(findings1);
    const newRisk = computeRiskScore(findings2);
    const riskDelta = newRisk - oldRisk;

    log.info(
      {
        scanId1,
        scanId2,
        new: newFindings.length,
        fixed: fixedFindings.length,
        persisting: persistingFindings.length,
        riskDelta,
      },
      "Scan comparison complete",
    );

    return { newFindings, fixedFindings, persistingFindings, riskDelta };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    log.error({ scanId1, scanId2, error: message }, "Failed to compare scan findings");
    throw new Error(`Scan comparison failed: ${message}`);
  }
}
