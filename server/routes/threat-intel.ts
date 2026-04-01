/**
 * Threat intelligence routes.
 */

import { Router } from "express";
import { z } from "zod";
import { sendError, sendValidationError } from "./response";
import { createLogger } from "../logger";

const log = createLogger("threat-intel-routes");

export const threatIntelRouter = Router();

const lookupSchema = z.object({
  target: z.string().min(1, "Target is required"),
});

// POST /api/threat-intel/lookup — lookup threat intel for a target
threatIntelRouter.post("/threat-intel/lookup", async (req, res) => {
  try {
    const { target } = lookupSchema.parse(req.body);
    const { lookupThreatIntel } = await import("../threat-intel");
    const report = await lookupThreatIntel(target);
    res.json(report);
  } catch (err) {
    if (err instanceof z.ZodError) return sendValidationError(res, err.errors[0]?.message ?? "Validation error");
    log.error({ err }, "Threat intel lookup failed");
    sendError(res, 500, err instanceof Error ? err.message : "Internal error");
  }
});

// POST /api/threat-intel/enrich — enrich workspace findings with threat intel
threatIntelRouter.post("/threat-intel/enrich", async (req, res) => {
  try {
    const workspaceId = (req.query.workspaceId as string) || (req.body?.workspaceId as string);
    if (!workspaceId) {
      return sendError(res, 400, "workspaceId is required");
    }

    const { enrichFindingsWithThreatIntel } = await import("../threat-intel");
    const enrichedCount = await enrichFindingsWithThreatIntel(workspaceId);
    res.json({ success: true, enrichedCount });
  } catch (err) {
    log.error({ err }, "Threat intel enrichment failed");
    sendError(res, 500, err instanceof Error ? err.message : "Internal error");
  }
});
