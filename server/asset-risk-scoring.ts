import { createLogger } from "./logger";
import { storage } from "./storage";
import { isSecurityFinding } from "./scanner/finding-taxonomy";
import type { Finding } from "@shared/schema";

const log = createLogger("asset-risk-scoring");

/**
 * Statuses that mean the work is over. A resolved finding must stop scoring
 * against its asset, or remediation never moves the number and the page gives
 * an operator no reason to fix anything.
 */
const CLOSED_STATUSES = new Set(["resolved", "false_positive", "accepted_risk", "closed"]);

/**
 * Rows this page may score: open, and actual security work.
 *
 * The same `kind` rule the inbox, the security score, the SLA clock, the trend
 * endpoints, the report content, the DOCX register and the finding groups each
 * had to be given separately. Without it an "Apache Detection" recon row raises
 * an asset's risk, and a control that is WORKING counts against the host it
 * protects.
 */
export function isScorableFinding(f: Finding): boolean {
  return isSecurityFinding(f) && !CLOSED_STATUSES.has(f.status ?? "open");
}

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
  /**
   * How many scorable findings the score was derived from.
   *
   * A 0 score reached with 0 findings ("nothing was found against this host")
   * and a 0 reached from findings that all scored low are different facts, and
   * the page must not render them identically — the same reason a factor is
   * `not_assessed` rather than a free 100 in shared/risk-factors.ts.
   */
  findingCount: number;
  /** `unknown` when no work has been closed — see determineTrend. */
  trend: "improving" | "stable" | "degrading" | "unknown";
  lastUpdated: Date;
}

const FACTOR_WEIGHTS = {
  criticalFindings: 0.35,
  highFindings: 0.25,
  mediumLowFindings: 0.15,
  exposure: 0.15,
  tlsIssues: 0.1,
} as const;

/**
 * Categories that mean "something is reachable that should not be".
 *
 * These MUST be spelled the way detectors actually emit them. The original set
 * was hyphenated — `open-port`, `exposed-service`, `information-disclosure` —
 * and the engine has never produced a hyphenated category in its life, so this
 * factor and the TLS one below matched **nothing at all**: 35% of the risk
 * weight was dead for every asset in the product, and measured on live data
 * every asset in every workspace scored 0.0 and rendered green.
 *
 * `asset-risk-scoring.test.ts` now checks both sets against
 * `SECURITY_CATEGORIES`, so a name no detector emits fails the build rather
 * than silently disabling a factor forever.
 */
const EXPOSURE_CATEGORIES = new Set([
  "api_exposure",
  "cloud_exposure",
  "container_exposure",
  "data_leak",
  "exposed_service",
  "information_disclosure",
  "infrastructure_disclosure",
  "leaked_credential",
  "network_exposure",
  "secret_exposure",
]);

/** Transport-security categories, again as detectors actually emit them. */
const TLS_CATEGORIES = new Set([
  "certificate_authority",
  "ssl_issue",
  "transport_security",
]);

/**
 * Risk bands: the range the WORST severity present allows.
 *
 * This mirrors `computeSecurityScore`'s floors and ceilings, inverted — there
 * a high score is good, here a high score is bad — and it exists for the same
 * reason. A weighted sum of counts alone is not a risk rating: one open
 * CRITICAL finding produced 20 x 0.4 = **8 out of 100**, which the page renders
 * in green as "no risk". The floor makes severity dominate; the ceiling stops
 * volume at a lesser severity from reading like an outstanding critical.
 *
 * The factors still position the score INSIDE its band, so the decomposition
 * shown in the drill-down continues to explain the number.
 */
const RISK_BANDS: Record<string, { floor: number; ceiling: number }> = {
  critical: { floor: 80, ceiling: 100 },
  high: { floor: 60, ceiling: 85 },
  medium: { floor: 40, ceiling: 65 },
  low: { floor: 15, ceiling: 39 },
  info: { floor: 0, ceiling: 10 },
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export function countFindingsBySeverity(
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

export function computeCriticalFindingsFactor(counts: Record<string, number>): RiskFactor {
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

export function computeHighFindingsFactor(counts: Record<string, number>): RiskFactor {
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

/**
 * Medium and low findings.
 *
 * They previously contributed to NO factor, which is why every asset in every
 * real workspace scored 0: measured on live data, the entire database was
 * medium/low/info, so the two severity factors that existed were structurally
 * unreachable. The per-finding points continue the product's own severity
 * ladder (`SEVERITY_DEDUCTION` in shared/scoring.ts: 20/10/5/2), rather than
 * inventing a second one that could disagree with it.
 */
export function computeMediumLowFactor(counts: Record<string, number>): RiskFactor {
  const mediumCount = counts.medium ?? 0;
  const lowCount = counts.low ?? 0;
  const score = Math.min(100, mediumCount * 5 + lowCount * 2);
  return {
    name: "Medium & Low Findings",
    score,
    weight: FACTOR_WEIGHTS.mediumLowFindings,
    details: `${mediumCount} medium and ${lowCount} low-severity finding(s) detected`,
  };
}

export function computeExposureFactor(findings: readonly Finding[]): RiskFactor {
  const exposureFindings = findings.filter((f) =>
    EXPOSURE_CATEGORIES.has((f.category ?? "").toLowerCase()),
  );

  const score = Math.min(100, exposureFindings.length * 15);
  return {
    name: "Exposure Level",
    score,
    weight: FACTOR_WEIGHTS.exposure,
    details: `${exposureFindings.length} exposure-related finding(s) (exposed services, disclosure, leaked data)`,
  };
}

export function computeTlsFactor(findings: readonly Finding[]): RiskFactor {
  const tlsFindings = findings.filter((f) =>
    TLS_CATEGORIES.has((f.category ?? "").toLowerCase()),
  );

  const score = Math.min(100, tlsFindings.length * 25);
  return {
    name: "TLS Issues",
    score,
    weight: FACTOR_WEIGHTS.tlsIssues,
    details: `${tlsFindings.length} TLS/certificate issue(s) detected`,
  };
}

/** The worst severity actually present, or null when there is nothing to rate. */
export function worstSeverity(counts: Record<string, number>): string | null {
  return SEVERITY_ORDER.find((s) => (counts[s] ?? 0) > 0) ?? null;
}

/**
 * Weighted factor sum, clamped into the band its worst severity allows.
 *
 * An asset with no scorable findings is 0 — nothing was found against it. That
 * is genuinely different from "we never looked", which is why
 * `AssetRiskScore.findingCount` is reported alongside: a 0 with 0 findings and
 * a 0 with findings that all scored low must stay distinguishable.
 */
export function computeOverallScore(
  factors: readonly RiskFactor[],
  counts?: Record<string, number>,
): number {
  const weighted = factors.reduce((sum, f) => sum + f.score * f.weight, 0);
  const raw = Math.min(100, Math.max(0, weighted));

  if (!counts) return Math.round(raw);

  const worst = worstSeverity(counts);
  if (!worst) return 0;

  const band = RISK_BANDS[worst];
  if (!band) return Math.round(raw);
  return Math.round(Math.min(band.ceiling, Math.max(band.floor, raw)));
}

/**
 * Direction of travel, inferred from remediation activity.
 *
 * There is no score history in this product — `calculateAssetRisk` reads one
 * snapshot, and `getAssetRiskHistory` says in its own comment that historical
 * tracking would need stored snapshots. So the only evidence of movement is
 * whether work on this asset has been CLOSED, and when none has, there is
 * nothing to infer a direction from.
 *
 * That case was previously answered "degrading", which measured on live data
 * meant **every asset holding any finding** got a red rising arrow asserting
 * its risk was increasing over time: 105 of 105 scored assets, on no history
 * whatsoever. It is `unknown` now, for the same reason a risk factor is
 * `not_assessed` rather than a free 100 — a verdict nothing measured must not
 * be rendered as one.
 *
 * Pass findings of every status: a resolved row is the entire signal here, so
 * filtering to open ones first makes `improving` unreachable.
 */
export function determineTrend(
  currentScore: number,
  findings: readonly Finding[],
): "improving" | "stable" | "degrading" | "unknown" {
  const openCount = findings.filter(
    (f) => f.status === "open" || f.workflowState === "open",
  ).length;
  const resolvedCount = findings.filter(
    (f) => f.status === "resolved" || f.workflowState === "closed" || f.workflowState === "remediated",
  ).length;

  // No closed work: nothing has been observed to move, in either direction.
  if (resolvedCount === 0) return "unknown";

  if (resolvedCount > openCount && currentScore < 50) {
    return "improving";
  }
  if (openCount > resolvedCount * 2 || currentScore >= 70) {
    return "degrading";
  }
  return "stable";
}

/**
 * Every asset value a finding can be attributed to.
 *
 * This inverts the matching rules so findings can be bucketed once instead of
 * rescanned per asset. The three rules, for asset `A` and affected host `F`:
 *
 *   F === A                  the finding names the asset exactly
 *   F.endsWith("." + A)      the finding names a subdomain of the asset
 *   F.startsWith(A + ":")    the finding names the asset with a port
 *
 * Read backwards, that means one finding belongs to: its own value, each of its
 * dot-suffix parents, and each prefix that ends just before a colon.
 */
function assetKeysForFinding(affected: string): string[] {
  const keys = new Set<string>();
  if (!affected) return [];
  keys.add(affected);

  // Dot-suffix parents: "a.b.c" -> "b.c", "c"
  for (let i = affected.indexOf("."); i !== -1; i = affected.indexOf(".", i + 1)) {
    const parent = affected.slice(i + 1);
    if (parent) keys.add(parent);
  }

  // Prefixes ending before a colon: "host:443" -> "host". Every colon is
  // considered, so "a:b:c" yields "a" and "a:b" exactly as `startsWith` would.
  for (let i = affected.indexOf(":"); i !== -1; i = affected.indexOf(":", i + 1)) {
    const prefix = affected.slice(0, i);
    if (prefix) keys.add(prefix);
  }

  return Array.from(keys);
}

/**
 * Bucket findings by the asset values they belong to.
 *
 * Built once per scoring run. The previous code filtered the whole finding list
 * for every asset — O(assets x findings), with a `toLowerCase()` allocation on
 * each pair — so a workspace with 10,000 assets and 10,000 findings did 10^8
 * comparisons and as many string allocations for a single page load. Indexing
 * makes it O(findings x labels) to build and O(1) to look up.
 */
export function indexFindingsByAsset(allFindings: readonly Finding[]): Map<string, Finding[]> {
  const index = new Map<string, Finding[]>();
  for (const f of allFindings) {
    const affected = (f.affectedAsset ?? "").toLowerCase();
    for (const key of assetKeysForFinding(affected)) {
      const bucket = index.get(key);
      if (bucket) bucket.push(f);
      else index.set(key, [f]);
    }
  }
  return index;
}

function findingsForAsset(
  assetValue: string,
  index: Map<string, Finding[]>,
): Finding[] {
  return index.get(assetValue.toLowerCase()) ?? [];
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

    /*
     * One row per HOST, not per inventory row.
     *
     * The `assets` unique constraint is (workspaceId, TYPE, value), so the apex
     * stored once as `domain` and again as `subdomain` is two rows for one
     * host — and this page keys on the hostname, so it rendered the same host
     * twice with an identical score, and counted it twice in the estate
     * average and the critical-risk tile. `type` is discovery provenance; a
     * host's identity is its name.
     *
     * Live data: 4 such rows across 2,633. Small, but two identical rows is
     * not information, and the count above them is then wrong by the same
     * amount.
     */
    const seenValue = new Set<string>();
    const allAssets = assetsResult.data.filter((a) => {
      const key = (a.value ?? "").toLowerCase();
      if (seenValue.has(key)) return false;
      seenValue.add(key);
      return true;
    });

    // Security rows of ANY status. The score uses only the open ones, but the
    // trend needs the closed ones — they are its only evidence of movement.
    const securityFindings = findingsResult.data.filter(isSecurityFinding);

    log.info(
      {
        workspaceId,
        assetCount: allAssets.length,
        findingCount: securityFindings.filter(isScorableFinding).length,
        totalRows: findingsResult.data.length,
      },
      "Calculating asset risk scores",
    );

    // Built once for the whole run, not rescanned per asset.
    const findingIndex = indexFindingsByAsset(securityFindings);

    const riskScores: AssetRiskScore[] = allAssets.map((asset) => {
      const everything = findingsForAsset(asset.value, findingIndex);
      // Only open security rows may raise risk — see isScorableFinding.
      const assetFindings = everything.filter(isScorableFinding);
      const counts = countFindingsBySeverity(assetFindings);

      const factors: RiskFactor[] = [
        computeCriticalFindingsFactor(counts),
        computeHighFindingsFactor(counts),
        computeMediumLowFactor(counts),
        computeExposureFactor(assetFindings),
        computeTlsFactor(assetFindings),
      ];

      const overallScore = computeOverallScore(factors, counts);
      const trend = determineTrend(overallScore, everything);

      return {
        assetId: asset.id,
        hostname: asset.value,
        overallScore,
        factors,
        findingCount: assetFindings.length,
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
    // Same split as calculateAssetRisk: score the open rows, trend on all of
    // them, because a closed row is the only evidence the trend has.
    const securityFindings = findingsResult.data.filter(isSecurityFinding);
    const everything = findingsForAsset(asset.value, indexFindingsByAsset(securityFindings));
    const assetFindings = everything.filter(isScorableFinding);
    const counts = countFindingsBySeverity(assetFindings);

    const factors: RiskFactor[] = [
      computeCriticalFindingsFactor(counts),
      computeHighFindingsFactor(counts),
      computeMediumLowFactor(counts),
      computeExposureFactor(assetFindings),
      computeTlsFactor(assetFindings),
    ];

    const overallScore = computeOverallScore(factors, counts);
    const trend = determineTrend(overallScore, everything);

    const currentScore: AssetRiskScore = {
      assetId: asset.id,
      hostname: asset.value,
      overallScore,
      factors,
      findingCount: assetFindings.length,
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
