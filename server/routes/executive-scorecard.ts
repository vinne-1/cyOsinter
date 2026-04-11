import { Router } from "express";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";
import { buildExecutiveScorecard } from "../enrichment/executive-scorecard";
import { sendError } from "./response";

const log = createLogger("routes:executive-scorecard");
export const executiveScorecardRouter = Router();

// GET /api/workspaces/:workspaceId/scorecard
executiveScorecardRouter.get(
  "/workspaces/:workspaceId/scorecard",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const scorecard = await buildExecutiveScorecard(workspaceId);
      res.json(scorecard);
    } catch (err) {
      log.error({ err }, "Executive scorecard error");
      return sendError(res, 500, "Internal error");
    }
  },
);
