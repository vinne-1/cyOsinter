/**
 * Attack simulation playbook routes.
 */

import { Router } from "express";
import { sendError, sendNotFound } from "./response";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";
import { storage, FULL_SET_LIMIT } from "../storage";

const log = createLogger("playbooks-routes");

export const playbooksRouter = Router();

// GET /api/playbooks — list all available playbooks
playbooksRouter.get("/playbooks", async (_req, res) => {
  try {
    const { getPlaybooks } = await import("../attack-simulation");
    res.json(getPlaybooks());
  } catch (err) {
    sendError(res, 500, "Internal server error");
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
    sendError(res, 500, "Internal server error");
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
    sendError(res, 500, "Internal server error");
  }
});

/**
 * GET /api/workspaces/:workspaceId/attack-paths — every playbook that
 * matches at least one real, open, security finding in this workspace,
 * sorted by risk.
 *
 * This is the same `attack-simulation.ts` engine the Playbooks page already
 * uses (tested, MITRE-mapped, normalized category matching) — not a second,
 * hand-rolled heuristic. The client used to build its own attack-chain
 * buckets from a hardcoded category list that had drifted from the real
 * taxonomy (`dns_security` and `ssl_tls` do not exist; the real categories
 * are `dns_misconfiguration` and `ssl_issue`), so entire chains could never
 * fire no matter what the workspace held.
 *
 * Response is `{ chains, suppressedCount, hasFindings }`, not a bare array.
 * A chain scoring below `MIN_DISPLAY_RISK_SCORE` is withheld (see that
 * constant's comment — one weak finding stretched across steps is not a
 * chain worth presenting), and that withholding must stay visible as its own
 * state. Collapsing "nothing matched at all" and "something matched but
 * wasn't confident enough to show" into one empty array reads as "no data
 * here", which is exactly the three-states-collapsed-into-two failure this
 * codebase's own conventions warn about — the previous version told an
 * operator with a scanned, populated workspace to "run a scan", which was
 * simply wrong.
 */
playbooksRouter.get("/workspaces/:workspaceId/attack-paths", wsAuth, async (req, res) => {
  try {
    const workspaceId = req.params.workspaceId as string;
    const { getPlaybooks, matchPlaybook, actionableFindings, MIN_DISPLAY_RISK_SCORE } = await import("../attack-simulation");
    // Fetched ONCE and matched against every playbook in memory, rather than
    // `simulateAttack`'s one findings query per playbook — this route checks
    // all 6, so that was 6 full-findings fetches (up to 10,000 rows each) for
    // one page load.
    const { data } = await storage.getFindings(workspaceId, { limit: FULL_SET_LIMIT });
    const actionable = actionableFindings(data);
    const results = getPlaybooks().map((p) => matchPlaybook(p, actionable));
    // Below the floor, the chain's evidence is too thin to present as an
    // actionable finding — e.g. one weak, generic finding (a robots.txt hint)
    // reused as "proof" of several unrelated steps. Showing it at a confident-
    // looking risk number is worse than omitting it — but omitting it
    // SILENTLY is the same mistake in the other direction, so the count of
    // what was withheld travels with the response.
    const withEvidence = results.filter((r) => r.matchedSteps.length > 0);
    const chains = withEvidence.filter((r) => r.riskScore >= MIN_DISPLAY_RISK_SCORE).sort((a, b) => b.riskScore - a.riskScore);
    const suppressedCount = withEvidence.length - chains.length;
    res.json({ chains, suppressedCount, hasFindings: actionable.length > 0 });
  } catch (err) {
    log.error({ err }, "Attack path listing failed");
    sendError(res, 500, "Internal server error");
  }
});

/**
 * POST /api/workspaces/:workspaceId/attack-paths/:playbookId/explain —
 * GLM narrates and prioritizes ONE already-matched chain. Not persisted:
 * this is an exploratory read over data that is itself derived live from
 * current findings, so there is nothing stable to cache it against — the
 * same reasoning `analyzeFindingDetails` does NOT apply here (that one
 * attaches to a specific finding row that exists to be annotated).
 *
 * Before asking GLM to judge the chain, it runs the same live "manual recon"
 * checks (`runVerificationChecks`, shared with AI Follow-up / AI Insights)
 * against the hosts actually involved — so the narrative is grounded in a
 * fresh probe of the target, not only in static category-string matching
 * against findings that may be stale or, as with a bare robots.txt hint,
 * weak evidence stretched across steps it does not really support.
 */
playbooksRouter.post("/workspaces/:workspaceId/attack-paths/:playbookId/explain", wsAuth, async (req, res) => {
  try {
    const workspaceId = req.params.workspaceId as string;
    const { simulateAttack } = await import("../attack-simulation");
    const { explainAttackChain } = await import("../ai-service.js");
    const { runVerificationChecks, resolveVerifiableTarget } = await import("../ai-follow-up.js");
    const result = await simulateAttack(workspaceId, req.params.playbookId as string);
    if (result.matchedSteps.length === 0) {
      return sendError(res, 400, "This chain has no matched findings to explain");
    }

    const allMatchedFindings = result.matchedSteps.flatMap((s) => s.matchingFindings);
    const ws = await storage.getWorkspace(workspaceId);
    // `workspace.domain` is frequently unset and `workspace.name` is a label,
    // not a domain (documented in CLAUDE.md: "Half the workspaces have no
    // domain — the fallback is a NAME"). `resolveVerifiableTarget` falls back
    // to the host already on the matched findings' `affectedAsset`.
    const domain = resolveVerifiableTarget([ws?.domain, ws?.name], allMatchedFindings);
    let verification: Array<{ label: string; status: string; summary: string }> = [];
    if (domain) {
      try {
        const checks = await runVerificationChecks(
          domain,
          allMatchedFindings.map((f) => ({
            id: f.id,
            title: f.title,
            severity: f.severity,
            category: f.category ?? "unclassified",
            affectedAsset: f.affectedAsset,
          })),
        );
        verification = checks.map((c) => ({ label: c.label, status: c.status, summary: c.summary }));
      } catch (err) {
        log.warn({ err, workspaceId }, "Live verification before attack-chain explanation failed; continuing without it");
      }
    }

    const narrative = await explainAttackChain({
      playbookName: result.playbook.name,
      mitreTactics: result.playbook.mitreTactics,
      matchedSteps: result.matchedSteps.map(({ step, matchingFindings }) => ({
        order: step.order,
        action: step.action,
        matchingFindingTitles: matchingFindings.map((f) => f.title),
      })),
      riskScore: result.riskScore,
      lowConfidence: result.lowConfidence,
      verification,
    });
    res.json({ ...narrative, lowConfidence: result.lowConfidence, verification });
  } catch (err) {
    log.warn({ err }, "Attack chain explanation failed");
    if (err instanceof Error && err.message.includes("not found")) {
      return sendNotFound(res, "Playbook");
    }
    sendError(res, 500, "GLM did not answer. Try again.");
  }
});
