/**
 * Attack simulation playbook routes.
 */

import { Router } from "express";
import { sendError, sendNotFound } from "./response";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";

const log = createLogger("playbooks-routes");

export const playbooksRouter = Router();

// GET /api/playbooks — list all available playbooks
playbooksRouter.get("/playbooks", async (_req, res) => {
  try {
    const { getPlaybooks } = await import("../attack-simulation");
    res.json(getPlaybooks());
  } catch (err) {
    sendError(res, 500, err instanceof Error ? err.message : "Internal error");
  }
});

// GET /api/playbooks/:id — get single playbook
playbooksRouter.get("/playbooks/:id", async (req, res) => {
  try {
    const { getPlaybooks } = await import("../attack-simulation");
    const playbook = getPlaybooks().find((p) => p.id === req.params.id);
    if (!playbook) return sendNotFound(res, "Playbook");
    res.json(playbook);
  } catch (err) {
    sendError(res, 500, err instanceof Error ? err.message : "Internal error");
  }
});

const wsAuth = requireWorkspaceRole("owner", "admin", "analyst", "viewer");

// POST /api/playbooks/:id/simulate — run attack simulation
playbooksRouter.post("/playbooks/:id/simulate", wsAuth, async (req, res) => {
  try {
    const workspaceId = (req.query.workspaceId as string) || (req.body?.workspaceId as string);
    if (!workspaceId) {
      return sendError(res, 400, "workspaceId is required");
    }

    const { simulateAttack } = await import("../attack-simulation");
    const result = await simulateAttack(workspaceId, req.params.id as string);
    res.json(result);
  } catch (err) {
    log.error({ err }, "Playbook simulation failed");
    if (err instanceof Error && err.message.includes("not found")) {
      return sendNotFound(res, "Playbook");
    }
    sendError(res, 500, err instanceof Error ? err.message : "Internal error");
  }
});
