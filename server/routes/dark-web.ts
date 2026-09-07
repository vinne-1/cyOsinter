import { Router } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";
import { sendError, sendValidationError } from "./response";
import { monitorDarkWeb } from "../scanner/dark-web-monitor";
import { isTorAvailable } from "../scanner/tor-fetch";
import type { VerifiedFinding } from "../scanner/types";

const log = createLogger("dark-web-route");

export const darkWebRouter = Router();

const MODULE_TYPE = "dark_web_monitoring";

const wsRead = requireWorkspaceRole("owner", "admin", "analyst", "viewer");
const wsWrite = requireWorkspaceRole("owner", "admin", "analyst");

const scanSchema = z.object({
  target: z
    .string()
    .min(3)
    .refine((v) => /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(v.trim()), {
      message: "Target must be a valid domain name (e.g. example.com)",
    })
    .optional(),
  /** Extra domains belonging to the same organisation. */
  aliases: z.array(z.string()).max(500).optional(),
  /** Organisation name for the lower-confidence name tier. */
  organisationName: z.string().max(200).optional(),
  /** Force a fresh scan, bypassing the cache. */
  force: z.boolean().optional(),
});

/**
 * GET the most recent dark web monitoring scan for a workspace.
 * Returns 200 with `null` data when no scan has run.
 */
darkWebRouter.get("/workspaces/:workspaceId/dark-web", wsRead, async (req, res) => {
  try {
    const modules = await storage.getReconModulesByType(
      req.params.workspaceId as string,
      MODULE_TYPE,
    );
    const latest = [...modules].sort(
      (a, b) => new Date(b.generatedAt ?? 0).getTime() - new Date(a.generatedAt ?? 0).getTime(),
    )[0];

    res.json(latest ?? null);
  } catch (err) {
    log.error({ err }, "Failed to load dark web monitoring results");
    sendError(res, 500, "Failed to load dark web monitoring results");
  }
});

/**
 * GET the Tor proxy status — lets the UI explain why .onion sources
 * were not checked without triggering a scan.
 */
darkWebRouter.get("/workspaces/:workspaceId/dark-web/status", wsRead, async (_req, res) => {
  try {
    const available = await isTorAvailable();
    res.json({ torAvailable: available });
  } catch (err) {
    log.error({ err }, "Failed to check Tor status");
    res.json({ torAvailable: false });
  }
});

/**
 * Trigger a dark web monitoring scan for the workspace's target.
 *
 * Sources checked:
 *   - Ahmia.fi (clearnet API) — .onion content search
 *   - Onion.live (clearnet API) — .onion service directory
 *   - Dark paste sites (.onion via Tor) — leaked credentials
 *   - Credential dump aggregators (.onion via Tor) — breach data
 */
darkWebRouter.post("/workspaces/:workspaceId/dark-web", wsWrite, async (req, res) => {
  try {
    const parsed = scanSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
    }

    const workspaceId = req.params.workspaceId as string;
    const workspace = await storage.getWorkspace(workspaceId);
    if (!workspace) return sendError(res, 404, "Workspace not found");

    const target = (parsed.data.target ?? workspace.domain ?? workspace.name ?? "").trim().toLowerCase();
    if (!target) return sendValidationError(res, "No target domain set for this workspace");

    const result = await monitorDarkWeb(target, {
      aliases: parsed.data.aliases,
      organisationName: parsed.data.organisationName,
      force: parsed.data.force,
    });

    // A complete failure (all clearnet sources down + Tor unavailable) must not
    // be stored as a clean result.
    if (
      result.error ||
      (result.sourcesChecked.length === 0 && result.sourcesFailed.length > 0)
    ) {
      return sendError(
        res,
        503,
        result.error ?? "All dark web sources are currently unreachable",
      );
    }

    const module = await storage.createReconModule({
      workspaceId,
      scanId: null,
      target,
      moduleType: MODULE_TYPE,
      data: { ...result },
      // A domain match in a dark web listing is a direct observation — the
      // highest confidence the platform assigns.
      confidence:
        result.counts.confirmedMentions > 0 || result.counts.leakDumps > 0
          ? 95
          : result.counts.possibleMentions > 0
            ? 75
            : 60,
    });

    // Create findings for confirmed dark web mentions and credential dumps so
    // they reach the findings inbox, affect the posture score, and trigger
    // alerts/SIEM/webhooks. A possible match is a lead, not a finding.
    const findings: VerifiedFinding[] = [];

    for (const mention of result.mentions) {
      if (mention.confidence !== "confirmed") continue;

      findings.push({
        title: `Dark web mention: ${mention.title}`,
        description:
          `${mention.reason}\n\nSource: ${mention.source}\n` +
          (mention.snippet ? `Snippet: ${mention.snippet.slice(0, 300)}\n` : "") +
          (mention.url ? `URL: ${mention.url}\n` : ""),
        severity: "high",
        category: "dark_web",
        kind: "security",
        affectedAsset: target,
        cvssScore: "7.5",
        remediation:
          "Investigate the source listing. If credentials are exposed, rotate them immediately. " +
          "Check whether the data is still live and request takedown where possible.",
        evidence: [
          {
            type: "dark_web_mention",
            description: mention.reason,
            url: mention.url ?? undefined,
            snippet: mention.snippet ?? undefined,
            source: mention.source,
            verifiedAt: result.scannedAt,
          },
        ],
      });
    }

    for (const dump of result.leakDumps) {
      if (!dump.confirmed) continue;

      findings.push({
        title: `Credential dump contains ${target} data`,
        description:
          `${dump.reason}\n\nSource: ${dump.source}\n` +
          `Data types: ${dump.dataTypes.join(", ")}\n` +
          (dump.recordCount != null ? `Records: ${dump.recordCount.toLocaleString()}\n` : ""),
        severity: "critical",
        category: "dark_web",
        kind: "security",
        affectedAsset: target,
        cvssScore: "9.1",
        remediation:
          "Treat as an active credential compromise. Rotate all credentials associated with " +
          "this domain. Investigate the dump scope and notify affected users.",
        evidence: [
          {
            type: "dark_web_credential_dump",
            description: dump.reason,
            url: dump.url ?? undefined,
            source: dump.source,
            verifiedAt: result.scannedAt,
          },
        ],
      });
    }

    // Persist findings alongside the recon module.
    for (const f of findings) {
      await storage.createFinding({
        workspaceId,
        scanId: null,
        title: f.title,
        description: f.description,
        severity: f.severity,
        status: "open",
        category: f.category,
        kind: f.kind ?? "security",
        affectedAsset: f.affectedAsset,
        cvssScore: f.cvssScore,
        remediation: f.remediation,
        evidence: f.evidence,
      });
    }

    if (findings.length > 0) {
      log.info(
        { workspaceId, target, findingsCreated: findings.length },
        "Dark web findings created",
      );
    }

    log.info(
      {
        workspaceId,
        target,
        sourcesChecked: result.sourcesChecked.length,
        ...result.counts,
      },
      "Dark web monitoring scan complete",
    );
    res.status(201).json(module);
  } catch (err) {
    log.error({ err }, "Dark web monitoring scan failed");
    sendError(res, 500, "Dark web monitoring scan failed");
  }
});
