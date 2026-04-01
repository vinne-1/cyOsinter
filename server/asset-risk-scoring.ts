import { createLogger } from "./logger";
import { storage } from "./storage";
import type { Finding } from "@shared/schema";

const log = createLogger("asset-risk-scoring");

export interface RiskFactor {
  name: string;
  score: number;
  weight: number;
  details: string;
}

export interface AssetRiskScore {
  assetId: string;
  hostname: string;
  overallScore: number; // 0-100
  factors: RiskFactor[];
  trend: "improving" | "stable" | "degrading";
  lastUpdated: Date;
}

const FACTOR_WEIGHTS = {
  criticalFindings: 0.4,
  highFindings: 0.25,
  exposure: 0.2,
  tlsIssues: 0.15,
} as const;

function countFindingsBySeverity(
  findings: readonly Finding[],
): Record<string, number> {
  const counts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) {
    const sev = (f.severity ?? "info").toLowerCase();
    counts[sev] = (counts[sev] ?? 0) + 1;
  }
  return counts;
}

function computeCriticalFindingsFactor(counts: Record<string, number>): RiskFactor {
  const critCount = counts.critical ?? 0;
  // Each critical finding adds 20 points, capped at 100
  const score = Math.min(100, critCount * 20);
  return {
    name: "Critical Findings",
    score,
    weight: FACTOR_WEIGHTS.criticalFindings,
    details: `${critCount} critical finding(s) detected`,
  };
}

function computeHighFindingsFactor(counts: Record<string, number>): RiskFactor {
  const highCount = counts.high ?? 0;
  // Each high finding adds 10 points, capped at 100
  const score = Math.min(100, highCount * 10);
  return {
    name: "High Findings",
    score,
    weight: FACTOR_WEIGHTS.highFindings,
    details: `${highCount} high-severity finding(s) detected`,
  };
}

function computeExposureFactor(findings: readonly Finding[]): RiskFactor {
  const exposureCategories = new Set([
    "open-port",
    "exposed-service",
    "information-disclosure",
    "directory-listing",
    "api-exposure",
    "cloud-misconfiguration",
    "misconfiguration",
    "exposed-panel",
  ]);

  const exposureFindings = findings.filter((f) => {
    const category = (f.category ?? "").toLowerCase();
    return exposureCategories.has(category);
  });

  const score = Math.min(100, exposureFindings.length * 15);
  return {
    name: "Exposure Level",
    score,
    weight: FACTOR_WEIGHTS.exposure,
    details: `${exposureFindings.length} exposure-related finding(s) (open ports, exposed services, misconfigurations)`,
  };
}

function computeTlsFactor(findings: readonly Finding[]): RiskFactor {
  const tlsCategories = new Set([
    "tls",
    "ssl",
    "certificate",
    "weak-cipher",
    "expired-certificate",
    "missing-hsts",
    "insecure-transport",
    "tls-misconfiguration",
  ]);

  const tlsFindings = findings.filter((f) => {
    const category = (f.category ?? "").toLowerCase();
    return tlsCategories.has(category);
  });

  const score = Math.min(100, tlsFindings.length * 25);
  return {
    name: "TLS Issues",
    score,
    weight: FACTOR_WEIGHTS.tlsIssues,
    details: `${tlsFindings.length} TLS/SSL issue(s) detected`,
  };
}

function computeOverallScore(factors: readonly RiskFactor[]): number {
  const weighted = factors.reduce(
    (sum, f) => sum + f.score * f.weight,
    0,
  );
  return Math.round(Math.min(100, Math.max(0, weighted)));
}

function determineTrend(
  currentScore: number,
  findings: readonly Finding[],
): "improving" | "stable" | "degrading" {
  const openCount = findings.filter(
    (f) => f.status === "open" || f.workflowState === "open",
  ).length;
  const resolvedCount = findings.filter(
    (f) => f.status === "resolved" || f.workflowState === "closed" || f.workflowState === "remediated",
  ).length;

  if (resolvedCount > openCount && currentScore < 50) {
    return "improving";
  }
  if (openCount > resolvedCount * 2 || currentScore >= 70) {
    return "degrading";
  }
  return "stable";
}

function findingsForAsset(
  assetValue: string,
  allFindings: readonly Finding[],
): Finding[] {
  const normalized = assetValue.toLowerCase();
  return allFindings.filter((f) => {
    const affected = (f.affectedAsset ?? "").toLowerCase();
    return affected === normalized || affected.includes(normalized);
  });
}

/**
 * Calculate composite risk scores for all discovered assets in a workspace.
 * Returns assets sorted by risk score descending.
 */
export async function calculateAssetRisk(
  workspaceId: string,
): Promise<AssetRiskScore[]> {
  try {
    const [assetsResult, findingsResult] = await Promise.all([
      storage.getAssets(workspaceId, { limit: 10000 }),
      storage.getFindings(workspaceId, { limit: 10000 }),
    ]);

    const allAssets = assetsResult.data;
    const allFindings = findingsResult.data;

    log.info(
      { workspaceId, assetCount: allAssets.length, findingCount: allFindings.length },
      "Calculating asset risk scores",
    );

    const riskScores: AssetRiskScore[] = allAssets.map((asset) => {
      const assetFindings = findingsForAsset(asset.value, allFindings);
      const counts = countFindingsBySeverity(assetFindings);

      const factors: RiskFactor[] = [
        computeCriticalFindingsFactor(counts),
        computeHighFindingsFactor(counts),
        computeExposureFactor(assetFindings),
        computeTlsFactor(assetFindings),
      ];

      const overallScore = computeOverallScore(factors);
      const trend = determineTrend(overallScore, assetFindings);

      return {
        assetId: asset.id,
        hostname: asset.value,
        overallScore,
        factors,
        trend,
        lastUpdated: new Date(),
      };
    });

    // Sort by risk score descending
    const sorted = [...riskScores].sort((a, b) => b.overallScore - a.overallScore);

    log.info(
      { workspaceId, scoredAssets: sorted.length },
      "Asset risk scoring complete",
    );

    return sorted;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    log.error({ workspaceId, error: message }, "Failed to calculate asset risk scores");
    throw new Error(`Asset risk scoring failed: ${message}`);
  }
}

/**
 * Get risk score history for a specific asset.
 * Returns current snapshot (historical tracking requires persistent storage of snapshots).
 */
export async function getAssetRiskHistory(
  assetId: string,
): Promise<AssetRiskScore[]> {
  try {
    const asset = await storage.getAsset(assetId);
    if (!asset) {
      log.warn({ assetId }, "Asset not found for risk history");
      return [];
    }

    const findingsResult = await storage.getFindings(asset.workspaceId, { limit: 10000 });
    const assetFindings = findingsForAsset(asset.value, findingsResult.data);
    const counts = countFindingsBySeverity(assetFindings);

    const factors: RiskFactor[] = [
      computeCriticalFindingsFactor(counts),
      computeHighFindingsFactor(counts),
      computeExposureFactor(assetFindings),
      computeTlsFactor(assetFindings),
    ];

    const overallScore = computeOverallScore(factors);
    const trend = determineTrend(overallScore, assetFindings);

    const currentScore: AssetRiskScore = {
      assetId: asset.id,
      hostname: asset.value,
      overallScore,
      factors,
      trend,
      lastUpdated: new Date(),
    };

    return [currentScore];
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    log.error({ assetId, error: message }, "Failed to get asset risk history");
    throw new Error(`Asset risk history failed: ${message}`);
  }
}
