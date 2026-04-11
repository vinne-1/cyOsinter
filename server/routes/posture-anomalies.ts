import { Router } from "express";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";
import { buildForecast } from "../enrichment/posture-anomaly";
import { sendError } from "./response";

const log = createLogger("routes:posture-anomalies");
export const postureAnomaliesRouter = Router();

const VALID_METRICS = ["securityScore", "criticalCount", "openPortsCount", "wafCoverage"] as const;
type Metric = typeof VALID_METRICS[number];

// GET /api/workspaces/:workspaceId/anomalies
postureAnomaliesRouter.get(
  "/workspaces/:workspaceId/anomalies",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const limit = Math.min(parseInt(String(req.query.limit ?? "20"), 10) || 20, 100);
      const anomalies = await storage.getPostureAnomalies(workspaceId, limit);
      res.json(anomalies);
    } catch (err) {
      log.error({ err }, "Get anomalies error");
      return sendError(res, 500, "Internal error");
    }
  },
);

// POST /api/workspaces/:workspaceId/anomalies/:id/acknowledge
postureAnomaliesRouter.post(
  "/workspaces/:workspaceId/anomalies/:id/acknowledge",
  requireWorkspaceRole("owner", "admin", "analyst"),
  async (req, res) => {
    try {
      await storage.acknowledgePostureAnomaly(String(req.params.id));
      res.json({ acknowledged: true });
    } catch (err) {
      log.error({ err }, "Acknowledge anomaly error");
      return sendError(res, 500, "Internal error");
    }
  },
);

// GET /api/workspaces/:workspaceId/forecast
postureAnomaliesRouter.get(
  "/workspaces/:workspaceId/forecast",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const metric = (req.query.metric as string) ?? "securityScore";
      const days = Math.min(parseInt(String(req.query.days ?? "30"), 10) || 30, 90);

      if (!VALID_METRICS.includes(metric as Metric)) {
        return sendError(res, 400, `Invalid metric. Use: ${VALID_METRICS.join(", ")}`);
      }

      const snapshots = await storage.getPostureHistory(workspaceId, 30);
      const forecast = buildForecast(snapshots, metric as Metric, days);
      res.json({ metric, daysAhead: days, forecast });
    } catch (err) {
      log.error({ err }, "Forecast error");
      return sendError(res, 500, "Internal error");
    }
  },
);
