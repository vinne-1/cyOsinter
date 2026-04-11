import { createLogger } from "./logger";
import { storage } from "./storage";
import type { Finding } from "@shared/schema";
import { SEVERITY_SCORE_DIFF } from "@shared/scoring";

const log = createLogger("differential-reporting");

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
    return total + (SEVERITY_SCORE_DIFF[severity] ?? 0);
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

    const findings1 = result1.data.filter((f) => f.scanId === scanId1);
    const findings2 = result2.data.filter((f) => f.scanId === scanId2);

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
