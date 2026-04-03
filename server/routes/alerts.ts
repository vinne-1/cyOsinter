import { Router } from "express";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";

const log = createLogger("routes:alerts");

const wsAuth = requireWorkspaceRole("owner", "admin", "analyst", "viewer");
const wsWrite = requireWorkspaceRole("owner", "admin", "analyst");

export const alertsRouter = Router();

// GET /api/workspaces/:workspaceId/alerts
alertsRouter.get("/workspaces/:workspaceId/alerts", wsAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(String(req.query.limit) || "50", 10) || 50, 200);
    const alertsList = await storage.getAlerts(req.params.workspaceId as string, limit);
    res.json(alertsList);
  } catch (err) {
    log.error({ err }, "Get alerts error");
    res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
  }
});

// GET /api/workspaces/:workspaceId/alerts/unread-count
alertsRouter.get("/workspaces/:workspaceId/alerts/unread-count", wsAuth, async (req, res) => {
  try {
    const count = await storage.getUnreadAlertCount(req.params.workspaceId as string);
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
alertsRouter.post("/workspaces/:workspaceId/alerts/mark-all-read", wsWrite, async (req, res) => {
  try {
    await storage.markAllAlertsRead(req.params.workspaceId as string);
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
