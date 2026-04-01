import { Router } from "express";
import { storage } from "../storage";
import { createLogger } from "../logger";

const log = createLogger("routes:alerts");

export const alertsRouter = Router();

// GET /api/workspaces/:workspaceId/alerts
alertsRouter.get("/workspaces/:workspaceId/alerts", async (req, res) => {
  try {
    const limit = Math.min(parseInt(String(req.query.limit) || "50", 10) || 50, 200);
    const alertsList = await storage.getAlerts(req.params.workspaceId, limit);
    res.json(alertsList);
  } catch (err) {
    log.error({ err }, "Get alerts error");
    res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
  }
});

// GET /api/workspaces/:workspaceId/alerts/unread-count
alertsRouter.get("/workspaces/:workspaceId/alerts/unread-count", async (req, res) => {
  try {
    const count = await storage.getUnreadAlertCount(req.params.workspaceId);
    res.json({ count });
  } catch (err) {
    log.error({ err }, "Get unread alert count error");
    res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
  }
});

// PATCH /api/alerts/:id/read
alertsRouter.patch("/alerts/:id/read", async (req, res) => {
  try {
    const alert = await storage.markAlertRead(req.params.id);
    if (!alert) return res.status(404).json({ message: "Alert not found" });
    res.json(alert);
  } catch (err) {
    log.error({ err }, "Mark alert read error");
    res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
  }
});

// POST /api/workspaces/:workspaceId/alerts/mark-all-read
alertsRouter.post("/workspaces/:workspaceId/alerts/mark-all-read", async (req, res) => {
  try {
    await storage.markAllAlertsRead(req.params.workspaceId);
    res.json({ success: true });
  } catch (err) {
    log.error({ err }, "Mark all alerts read error");
    res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
  }
});

// DELETE /api/alerts/:id
alertsRouter.delete("/alerts/:id", async (req, res) => {
  try {
    await storage.deleteAlert(req.params.id);
    res.status(204).send();
  } catch (err) {
    log.error({ err }, "Delete alert error");
    res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
  }
});
