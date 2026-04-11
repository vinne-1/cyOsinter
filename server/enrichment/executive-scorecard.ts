/**
 * Executive Risk Scorecard
 *
 * Aggregates all available scoring data into a one-page board-level summary.
 * Pure aggregation — all data already computed by other enrichment modules.
 */
import { createLogger } from "../logger";
import { storage } from "../storage";
import { generateAllComplianceReports } from "../compliance-mapper";
import { computeSecurityScore } from "@shared/scoring";

const log = createLogger("enrichment:executive-scorecard");

export interface ComplianceSummary {
  framework: string;
  score: number;
  delta: number | null; // vs last scan
}

export interface TopAsset {
  hostname: string;
  riskScore: number;
  criticalFindings: number;
}

export interface SuggestedFix {
  title: string;
  impact: string;
  effort: "low" | "medium" | "high";
  affectedAssets: number;
}

export interface ExecutiveScorecard {
  generatedAt: string;
  workspaceId: string;
  target: string;
  // Current posture
  securityScore: number;
  securityScoreDelta: number | null; // vs previous snapshot
  // Finding summary
  totalOpenFindings: number;
  criticalOpen: number;
  highOpen: number;
  // MTTR
  avgMttrHours: number | null;
  slaBreach: number; // count of findings with slaBreached=true
  // Compliance
  compliance: ComplianceSummary[];
  // Top risky assets
  topRiskyAssets: TopAsset[];
  // Suggested fixes (max 3)
  suggestedFixes: SuggestedFix[];
  // Trend direction
  trend: "improving" | "stable" | "degrading";
}

export async function buildExecutiveScorecard(workspaceId: string): Promise<ExecutiveScorecard> {
  const [workspace, { data: findings }, snapshots] = await Promise.all([
    storage.getWorkspace(workspaceId),
    storage.getFindings(workspaceId, { limit: 5000 }),
    storage.getPostureHistory(workspaceId, 10),
  ]);

  const target = workspace?.name ?? workspaceId;
  const openFindings = findings.filter((f) => f.status === "open" || f.status === "in_review");

  // Security score
  const securityScore = computeSecurityScore(findings);
  const prevSnapshot = snapshots[1]; // [0] is most recent
  const securityScoreDelta = prevSnapshot?.securityScore != null
    ? securityScore - prevSnapshot.securityScore
    : null;

  // Trend
  const recentSnapshots = snapshots.slice(0, 5);
  const trend: "improving" | "stable" | "degrading" = (() => {
    if (recentSnapshots.length < 2) return "stable";
    const first = recentSnapshots[recentSnapshots.length - 1].securityScore ?? 50;
    const last = recentSnapshots[0].securityScore ?? 50;
    if (last - first >= 5) return "improving";
    if (first - last >= 5) return "degrading";
    return "stable";
  })();

  // Finding counts
  const criticalOpen = openFindings.filter((f) => f.severity?.toLowerCase() === "critical").length;
  const highOpen = openFindings.filter((f) => f.severity?.toLowerCase() === "high").length;
  const slaBreach = findings.filter((f) => f.slaBreached).length;

  // MTTR
  const resolved = findings.filter((f) => f.status === "resolved" && f.resolvedAt && f.discoveredAt);
  const avgMttrHours = resolved.length > 0
    ? Math.round(
        resolved.reduce((sum, f) => {
          return sum + (new Date(f.resolvedAt!).getTime() - new Date(f.discoveredAt!).getTime()) / 3_600_000;
        }, 0) / resolved.length * 10,
      ) / 10
    : null;

  // Compliance
  const allReports = generateAllComplianceReports(findings);
  const compliance: ComplianceSummary[] = Object.entries(allReports).map(([, report]) => ({
    framework: report.framework,
    score: report.score,
    delta: null, // would need historical compliance data
  }));

  // Top risky assets (based on critical/high finding counts per asset)
  const assetMap = new Map<string, { criticalFindings: number; riskScore: number }>();
  for (const f of openFindings) {
    const host = f.affectedAsset ?? "unknown";
    const entry = assetMap.get(host) ?? { criticalFindings: 0, riskScore: 0 };
    const sev = f.severity?.toLowerCase();
    if (sev === "critical") { entry.criticalFindings++; entry.riskScore += 10; }
    else if (sev === "high") { entry.riskScore += 7; }
    else if (sev === "medium") { entry.riskScore += 4; }
    assetMap.set(host, entry);
  }
  const topRiskyAssets: TopAsset[] = Array.from(assetMap.entries())
    .sort(([, a], [, b]) => b.riskScore - a.riskScore)
    .slice(0, 5)
    .map(([hostname, data]) => ({ hostname, ...data }));

  // Suggested fixes — top categories by finding count with estimated impact
  const catMap = new Map<string, number>();
  for (const f of openFindings) {
    catMap.set(f.category, (catMap.get(f.category) ?? 0) + 1);
  }
  const topCats = Array.from(catMap.entries())
    .sort(([, a], [, b]) => b - a)
    .slice(0, 3);

  const suggestedFixes: SuggestedFix[] = topCats.map(([cat, count]) => ({
    title: `Remediate ${cat.replace(/_/g, " ")} findings`,
    impact: `Resolving ${count} finding${count !== 1 ? "s" : ""} in this category`,
    effort: count > 10 ? "high" : count > 3 ? "medium" : "low",
    affectedAssets: new Set(
      openFindings.filter((f) => f.category === cat).map((f) => f.affectedAsset),
    ).size,
  }));

  return {
    generatedAt: new Date().toISOString(),
    workspaceId,
    target,
    securityScore,
    securityScoreDelta,
    totalOpenFindings: openFindings.length,
    criticalOpen,
    highOpen,
    avgMttrHours,
    slaBreach,
    compliance,
    topRiskyAssets,
    suggestedFixes,
    trend,
  };
}
