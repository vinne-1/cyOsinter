/**
 * Scan differential reporting routes.
 *
 * ## Authorization
 *
 * This route takes two scan ids straight from the URL and returns the full
 * finding objects behind them — titles, descriptions, affected assets. It had
 * no authorization beyond `requireAuth`, so ANY authenticated user could diff
 * ANY two scans in the deployment and read another tenant's findings. The
 * caller's identity was never consulted: `compareScanFindings` resolves each
 * scan, reads `scan.workspaceId`, and fetches that workspace's findings.
 *
 * It is a bare-ID route — the path carries no `:workspaceId` — so
 * `requireWorkspaceRole` cannot help and the handler has to prove membership
 * itself, which is the rule every other bare-ID route in this codebase already
 * follows.
 *
 * Both scans are checked, not just the first: diffing your own scan against a
 * stranger's would otherwise leak the stranger's half of the comparison.
 */

import { Router } from "express";
import { storage } from "../storage";
import { sendError, sendNotFound } from "./response";
import { createLogger } from "../logger";

const log = createLogger("scan-diff-routes");

export const scanDiffRouter = Router();

// GET /api/scans/:id1/diff/:id2 — compare two scans
scanDiffRouter.get("/scans/:id1/diff/:id2", async (req, res) => {
  try {
    const [scan1, scan2] = await Promise.all([
      storage.getScan(req.params.id1 as string),
      storage.getScan(req.params.id2 as string),
    ]);
    // 404 rather than 403 throughout: a distinct "exists but forbidden" reply
    // would confirm a scan id belongs to somebody, which is the enumeration
    // oracle the 404 convention exists to close.
    if (!scan1 || !scan2) return sendNotFound(res, "Scan");

    // Superadmins are not workspace members but may read any workspace, matching
    // how `requireWorkspaceRole` treats them.
    if (req.user!.role !== "superadmin") {
      const [m1, m2] = await Promise.all([
        storage.getWorkspaceMember(scan1.workspaceId, req.user!.id),
        storage.getWorkspaceMember(scan2.workspaceId, req.user!.id),
      ]);
      if (!m1 || !m2) return sendNotFound(res, "Scan");
    }

    // A cross-workspace diff is meaningless — two different targets produce a
    // diff of unrelated findings — and allowing it is a way to smuggle one
    // workspace's data into a response about another.
    if (scan1.workspaceId !== scan2.workspaceId) {
      return sendError(res, 400, "Both scans must belong to the same workspace");
    }

    const { compareScanFindings } = await import("../differential-reporting");
    const diff = await compareScanFindings(req.params.id1 as string, req.params.id2 as string);
    res.json(diff);
  } catch (err) {
    log.error({ err }, "Scan diff failed");
    if (err instanceof Error && err.message.includes("not found")) {
      return sendNotFound(res, "Scan");
    }
    sendError(res, 500, "Internal server error");
  }
});

// POST /api/scans/:id1/diff/:id2/explain — GLM narrates the diff above.
// Same bare-ID authorization as the GET: both scans resolved, both
// memberships checked, workspace match enforced, before anything is read.
scanDiffRouter.post("/scans/:id1/diff/:id2/explain", async (req, res) => {
  try {
    const [scan1, scan2] = await Promise.all([
      storage.getScan(req.params.id1 as string),
      storage.getScan(req.params.id2 as string),
    ]);
    if (!scan1 || !scan2) return sendNotFound(res, "Scan");

    if (req.user!.role !== "superadmin") {
      const [m1, m2] = await Promise.all([
        storage.getWorkspaceMember(scan1.workspaceId, req.user!.id),
        storage.getWorkspaceMember(scan2.workspaceId, req.user!.id),
      ]);
      if (!m1 || !m2) return sendNotFound(res, "Scan");
    }
    if (scan1.workspaceId !== scan2.workspaceId) {
      return sendError(res, 400, "Both scans must belong to the same workspace");
    }

    const { compareScanFindings } = await import("../differential-reporting");
    const diff = await compareScanFindings(req.params.id1 as string, req.params.id2 as string);
    const { explainScanDiff } = await import("../ai-service.js");
    const narrative = await explainScanDiff({
      target: scan1.target,
      scan1Date: scan1.completedAt?.toISOString?.() ?? String(scan1.completedAt ?? scan1.startedAt ?? ""),
      scan2Date: scan2.completedAt?.toISOString?.() ?? String(scan2.completedAt ?? scan2.startedAt ?? ""),
      riskDelta: diff.riskDelta,
      newFindings: diff.newFindings.map((f) => ({ title: f.title, severity: f.severity, category: f.category })),
      fixedFindings: diff.fixedFindings.map((f) => ({ title: f.title, severity: f.severity, category: f.category })),
      persistingCount: diff.persistingFindings.length,
    });
    res.json(narrative);
  } catch (err) {
    log.warn({ err }, "Scan diff explanation failed");
    sendError(res, 500, "GLM did not answer. Try again.");
  }
});
