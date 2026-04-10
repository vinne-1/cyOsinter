import { Router } from "express";
import { createLogger } from "../logger";
import { getComplianceDrift } from "../compliance-workflows";
import { requireWorkspaceRole } from "./auth-middleware";

const log = createLogger("routes:compliance-drift");

export const complianceDriftRouter = Router();

complianceDriftRouter.get(
  "/workspaces/:workspaceId/compliance-drift",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const report = await getComplianceDrift(workspaceId);
      res.json(report);
    } catch (err) {
      log.error({ err }, "Compliance drift fetch failed");
      res.status(500).json({ message: "Internal error" });
    }
  },
);

