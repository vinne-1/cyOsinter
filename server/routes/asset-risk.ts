/**
 * Asset risk scoring routes.
 */

import { Router } from "express";
import { sendError, sendNotFound } from "./response";
import { storage } from "../storage";
import { requireAuth, requireWorkspaceRole } from "./auth-middleware";
import { createLogger } from "../logger";

const log = createLogger("asset-risk-routes");

export const assetRiskRouter = Router();

// GET /api/asset-risk — get risk scores for all assets in workspace
assetRiskRouter.get("/asset-risk", requireAuth, requireWorkspaceRole("owner", "admin", "analyst", "viewer"), async (req, res) => {
  try {
    const workspaceId = req.query.workspaceId as string;
    if (!workspaceId) {
      return sendError(res, 400, "workspaceId query parameter is required");
    }

    const { calculateAssetRisk } = await import("../asset-risk-scoring");
    const scores = await calculateAssetRisk(workspaceId);
    res.json(scores);
  } catch (err) {
    log.error({ err }, "Asset risk calculation failed");
    sendError(res, 500, "Internal server error");
  }
});

/**
 * POST /api/asset-risk/explain — GLM narrates which risk factor(s) are
 * systemically driving the estate's score. Aggregated server-side (band
 * counts, most-common contributing factors) before the model ever sees it —
 * never a per-asset listing, since an estate can hold hundreds of assets.
 * Ephemeral, matching every other explain endpoint this session: the
 * underlying score is cheap to recompute, nothing to cache the narrative
 * against.
 */
assetRiskRouter.post("/asset-risk/explain", requireAuth, requireWorkspaceRole("owner", "admin", "analyst", "viewer"), async (req, res) => {
  try {
    const workspaceId = (req.query.workspaceId as string) || (req.body?.workspaceId as string);
    if (!workspaceId) {
      return sendError(res, 400, "workspaceId query parameter is required");
    }

    const { calculateAssetRisk } = await import("../asset-risk-scoring");
    const scores = await calculateAssetRisk(workspaceId);

    // Same rule as the page's own "Average Score" tile: an asset with zero
    // findings was never assessed, not scored clean, so it is excluded from
    // every aggregate below rather than dragging the estate toward 0.
    const scored = scores.filter((a) => a.findingCount > 0);

    const bandCounts = {
      critical: scored.filter((a) => a.overallScore >= 80).length,
      high: scored.filter((a) => a.overallScore >= 60 && a.overallScore < 80).length,
      medium: scored.filter((a) => a.overallScore >= 40 && a.overallScore < 60).length,
      low: scored.filter((a) => a.overallScore < 40).length,
    };

    // A factor "contributes" to an asset when it scored above 0 — a factor
    // present with a 0 score did not push that asset's risk up.
    const factorCounts = new Map<string, number>();
    for (const asset of scored) {
      for (const factor of asset.factors) {
        if (factor.score > 0) {
          factorCounts.set(factor.name, (factorCounts.get(factor.name) ?? 0) + 1);
        }
      }
    }
    const topFactors = Array.from(factorCounts.entries())
      .sort(([, a], [, b]) => b - a)
      .map(([name, assetCount]) => ({ name, assetCount }));

    const trendCounts = {
      improving: scored.filter((a) => a.trend === "improving").length,
      stable: scored.filter((a) => a.trend === "stable").length,
      degrading: scored.filter((a) => a.trend === "degrading").length,
      unknown: scored.filter((a) => a.trend === "unknown").length,
    };

    const averageScore = scored.length > 0
      ? scored.reduce((sum, a) => sum + a.overallScore, 0) / scored.length
      : 0;

    const { explainAssetRisk } = await import("../ai-service.js");
    const narrative = await explainAssetRisk({
      totalAssets: scores.length,
      scoredAssets: scored.length,
      averageScore,
      bandCounts,
      topFactors,
      trendCounts,
    });
    res.json(narrative);
  } catch (err) {
    log.warn({ err }, "Asset risk explanation failed");
    sendError(res, 500, "GLM did not answer. Try again.");
  }
});

// GET /api/asset-risk/:assetId/history — get risk history for an asset
assetRiskRouter.get("/asset-risk/:assetId/history", requireAuth, async (req, res) => {
  try {
    // Bare-ID route: the path carries no `:workspaceId`, so
    // `requireWorkspaceRole` cannot help and membership has to be proven here.
    // Without this, any authenticated user could read the risk history of any
    // asset in the deployment — `getAssetRiskHistory` resolves the asset, takes
    // its `workspaceId`, and reads that workspace's findings, never consulting
    // the caller.
    const asset = await storage.getAsset(req.params.assetId as string);
    // 404 rather than 403: a distinct "forbidden" would confirm the asset id
    // belongs to somebody, which is the enumeration oracle 404 exists to close.
    if (!asset) return sendNotFound(res, "Asset");
    if (req.user!.role !== "superadmin") {
      const membership = await storage.getWorkspaceMember(asset.workspaceId, req.user!.id);
      if (!membership) return sendNotFound(res, "Asset");
    }

    const { getAssetRiskHistory } = await import("../asset-risk-scoring");
    const history = await getAssetRiskHistory(req.params.assetId as string);
    res.json(history);
  } catch (err) {
    log.error({ err }, "Asset risk history lookup failed");
    sendError(res, 500, "Internal server error");
  }
});
