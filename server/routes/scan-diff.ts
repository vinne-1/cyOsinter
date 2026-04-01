/**
 * Scan differential reporting routes.
 */

import { Router } from "express";
import { sendError, sendNotFound } from "./response";
import { createLogger } from "../logger";

const log = createLogger("scan-diff-routes");

export const scanDiffRouter = Router();

// GET /api/scans/:id1/diff/:id2 — compare two scans
scanDiffRouter.get("/scans/:id1/diff/:id2", async (req, res) => {
  try {
    const { compareScanFindings } = await import("../differential-reporting");
    const diff = await compareScanFindings(req.params.id1, req.params.id2);
    res.json(diff);
  } catch (err) {
    log.error({ err }, "Scan diff failed");
    if (err instanceof Error && err.message.includes("not found")) {
      return sendNotFound(res, "Scan");
    }
    sendError(res, 500, err instanceof Error ? err.message : "Internal error");
  }
});
