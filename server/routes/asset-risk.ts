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
