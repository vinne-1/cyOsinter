import { Router } from "express";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";
import { recomputeFindingPriorities } from "../enrichment/finding-priority";
import { sendError } from "./response";

const log = createLogger("routes:smart-priority");
export const smartPriorityRouter = Router();

// GET /api/workspaces/:workspaceId/priorities
smartPriorityRouter.get(
  "/workspaces/:workspaceId/priorities",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const limit = Math.min(parseInt(String(req.query.limit ?? "50"), 10) || 50, 200);
      const priorities = await storage.getFindingPriorities(workspaceId, limit);

      res.json(priorities.map((p) => ({
        findingId: p.findingId,
        rank: p.rank,
        compositeScore: parseFloat(String(p.compositeScore)),
        components: {
          cvss: parseFloat(String(p.cvssComponent ?? 0)),
          epss: parseFloat(String(p.epssComponent ?? 0)),
          kev: p.kevComponent ?? 0,
          exposure: parseFloat(String(p.exposureComponent ?? 0)),
          age: parseFloat(String(p.ageComponent ?? 0)),
        },
        computedAt: p.computedAt,
        finding: {
          id: p.finding.id,
          title: p.finding.title,
          severity: p.finding.severity,
          category: p.finding.category,
          affectedAsset: p.finding.affectedAsset,
          status: p.finding.status,
          cvssScore: p.finding.cvssScore,
          discoveredAt: p.finding.discoveredAt,
        },
      })));
    } catch (err) {
      log.error({ err }, "Get priorities error");
      return sendError(res, 500, "Internal error");
    }
  },
);

// POST /api/workspaces/:workspaceId/priorities/refresh
smartPriorityRouter.post(
  "/workspaces/:workspaceId/priorities/refresh",
  requireWorkspaceRole("owner", "admin", "analyst"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      recomputeFindingPriorities(workspaceId).catch((err) =>
        log.warn({ err, workspaceId }, "Manual priority refresh failed"),
      );
      res.json({ message: "Priority computation started" });
    } catch (err) {
      log.error({ err }, "Priority refresh trigger error");
      return sendError(res, 500, "Internal error");
    }
  },
);
