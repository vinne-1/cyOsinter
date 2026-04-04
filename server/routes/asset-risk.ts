/**
 * Asset risk scoring routes.
 */

import { Router } from "express";
import { sendError } from "./response";
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

// GET /api/asset-risk/:assetId/history — get risk history for an asset
assetRiskRouter.get("/asset-risk/:assetId/history", requireAuth, async (req, res) => {
  try {
    const { getAssetRiskHistory } = await import("../asset-risk-scoring");
    const history = await getAssetRiskHistory(req.params.assetId as string);
    res.json(history);
  } catch (err) {
    log.error({ err }, "Asset risk history lookup failed");
    sendError(res, 500, "Internal server error");
  }
});
