import { Router } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";
import { sendError } from "./response";

const log = createLogger("routes:evidence-search");
export const evidenceSearchRouter = Router();

const searchQuerySchema = z.object({
  q: z.string().min(2).max(200),
  type: z.enum(["finding", "recon", "all"]).default("all"),
  limit: z.coerce.number().int().min(1).max(100).default(50),
});

// GET /api/workspaces/:workspaceId/search?q=...&type=all&limit=50
evidenceSearchRouter.get(
  "/workspaces/:workspaceId/search",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const parsed = searchQuerySchema.safeParse(req.query);
      if (!parsed.success) {
        return sendError(res, 400, parsed.error.errors[0]?.message ?? "Invalid query");
      }
      const { q, limit } = parsed.data;

      const results = await storage.searchEvidence(workspaceId, q, limit);
      res.json({ query: q, total: results.length, results });
    } catch (err) {
      log.error({ err }, "Evidence search error");
      return sendError(res, 500, "Internal error");
    }
  },
);
