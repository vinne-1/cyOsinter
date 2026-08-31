import { Router } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";
import { sendError, sendValidationError } from "./response";
import { scanForLookalikes } from "../scanner/typosquat";
import { checkRansomwareExposure } from "../scanner/ransomware-watch";
import { watchForCodeLeaks, isCodeLeakConfigured } from "../scanner/code-leak-watch";

const log = createLogger("brand-threats");

export const brandThreatsRouter = Router();

const MODULE_TYPE = "brand_threats";
const RANSOMWARE_MODULE_TYPE = "ransomware_exposure";
const CODE_LEAK_MODULE_TYPE = "code_leak";

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
  /**
   * Domains the organisation owns. A brand often legitimately holds its own
   * ccTLD and defensive registrations; without an allowlist those dominate the
   * results and train the operator to ignore the page.
   */
  ownedDomains: z.array(z.string()).max(500).optional(),
  limit: z.coerce.number().int().min(50).max(3000).default(1200),
});

/**
 * GET the most recent lookalike sweep for a workspace.
 * Returns 200 with `null` data rather than 404 when no sweep has run, so the
 * client can render an empty state instead of treating it as an error.
 */
brandThreatsRouter.get("/workspaces/:workspaceId/brand-threats", wsRead, async (req, res) => {
  try {
    // getReconModulesByType queries by type directly, rather than paging the
    // whole module set and filtering in memory.
    const modules = await storage.getReconModulesByType(req.params.workspaceId as string, MODULE_TYPE);
    const latest = [...modules].sort(
      (a, b) => new Date(b.generatedAt ?? 0).getTime() - new Date(a.generatedAt ?? 0).getTime(),
    )[0];

    res.json(latest ?? null);
  } catch (err) {
    log.error({ err }, "Failed to load brand threats");
    sendError(res, 500, "Failed to load brand threats");
  }
});

/**
 * Run a lookalike-domain sweep for the workspace's target.
 *
 * This is DNS-only and touches no third-party API, but it does fan out a few
 * hundred resolutions, so it is rate limited alongside the other scan routes.
 */
brandThreatsRouter.post("/workspaces/:workspaceId/brand-threats", wsWrite, async (req, res) => {
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

    const owned = new Set(
      (parsed.data.ownedDomains ?? []).map((d) => d.trim().toLowerCase()).filter(Boolean),
    );

    const result = await scanForLookalikes(target, { limit: parsed.data.limit, concurrency: 40 });

    // Drop the organisation's own defensive registrations before scoring.
    const registered = result.registered.filter((r) => !owned.has(r.domain));
    const counts = {
      high: registered.filter((r) => r.risk === "high").length,
      medium: registered.filter((r) => r.risk === "medium").length,
      low: registered.filter((r) => r.risk === "low").length,
    };

    const data = {
      target,
      generated: result.generated,
      checked: result.checked,
      registered,
      counts,
      ownedExcluded: result.registered.length - registered.length,
      scannedAt: new Date().toISOString(),
    };

    // Confidence reflects method, not findings: DNS resolution is a direct
    // observation, so a positive is near-certain — but ownership is not proven.
    const module = await storage.createReconModule({
      workspaceId,
      scanId: null,
      target,
      moduleType: MODULE_TYPE,
      data,
      confidence: 90,
    });

    log.info(
      { workspaceId, target, generated: data.generated, registered: registered.length, high: counts.high },
      "Brand threat sweep complete",
    );

    res.status(201).json(module);
  } catch (err) {
    log.error({ err }, "Brand threat sweep failed");
    sendError(res, 500, "Brand threat sweep failed");
  }
});

const ransomwareSchema = z.object({
  /** Additional domains belonging to the same organisation. */
  aliases: z.array(z.string()).max(100).optional(),
  /** Enables the lower-confidence name-match tier. */
  organisationName: z.string().max(200).optional(),
});

/** Most recent ransomware leak-site check for the workspace, or null. */
brandThreatsRouter.get("/workspaces/:workspaceId/ransomware-exposure", wsRead, async (req, res) => {
  try {
    const modules = await storage.getReconModulesByType(
      req.params.workspaceId as string,
      RANSOMWARE_MODULE_TYPE,
    );
    const latest = [...modules].sort(
      (a, b) => new Date(b.generatedAt ?? 0).getTime() - new Date(a.generatedAt ?? 0).getTime(),
    )[0];
    res.json(latest ?? null);
  } catch (err) {
    log.error({ err }, "Failed to load ransomware exposure");
    sendError(res, 500, "Failed to load ransomware exposure");
  }
});

/**
 * Checks the workspace target against public ransomware leak-site postings.
 *
 * Reads one aggregated public dataset — it does not touch Tor, and never
 * fetches the .onion URLs it reports.
 */
brandThreatsRouter.post("/workspaces/:workspaceId/ransomware-exposure", wsWrite, async (req, res) => {
  try {
    const parsed = ransomwareSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
    }

    const workspaceId = req.params.workspaceId as string;
    const workspace = await storage.getWorkspace(workspaceId);
    if (!workspace) return sendError(res, 404, "Workspace not found");

    const target = (workspace.domain ?? workspace.name ?? "").trim().toLowerCase();
    if (!target) return sendValidationError(res, "No target domain set for this workspace");

    const result = await checkRansomwareExposure(target, {
      aliases: parsed.data.aliases,
      organisationName: parsed.data.organisationName,
    });

    // A feed outage must not be recorded as a clean result — that would read as
    // "you are not on any leak site", which we did not establish.
    if (result.error) {
      return sendError(res, 503, result.error);
    }

    const module = await storage.createReconModule({
      workspaceId,
      scanId: null,
      target,
      moduleType: RANSOMWARE_MODULE_TYPE,
      data: { ...result, scannedAt: new Date().toISOString() },
      // A domain match against a published victim listing is a direct
      // observation, not an inference.
      confidence: result.counts.confirmed > 0 ? 95 : 80,
    });

    log.info(
      { workspaceId, target, records: result.recordsChecked, ...result.counts },
      "Ransomware exposure check complete",
    );
    res.status(201).json(module);
  } catch (err) {
    log.error({ err }, "Ransomware exposure check failed");
    sendError(res, 500, "Ransomware exposure check failed");
  }
});

const codeLeakSchema = z.object({
  /** Extra identifiers: internal hostnames, product code names. */
  aliases: z.array(z.string()).max(50).optional(),
});

/** Most recent source-code leak sweep, or null. */
brandThreatsRouter.get("/workspaces/:workspaceId/code-leaks", wsRead, async (req, res) => {
  try {
    const modules = await storage.getReconModulesByType(
      req.params.workspaceId as string,
      CODE_LEAK_MODULE_TYPE,
    );
    const latest = [...modules].sort(
      (a, b) => new Date(b.generatedAt ?? 0).getTime() - new Date(a.generatedAt ?? 0).getTime(),
    )[0];
    // `configured` lets the UI explain WHY there is nothing here, rather than
    // showing an empty state that looks like a clean result.
    res.json({ module: latest ?? null, configured: isCodeLeakConfigured() });
  } catch (err) {
    log.error({ err }, "Failed to load code leaks");
    sendError(res, 500, "Failed to load code leaks");
  }
});

/** Searches public code for the workspace's identifiers. */
brandThreatsRouter.post("/workspaces/:workspaceId/code-leaks", wsWrite, async (req, res) => {
  try {
    const parsed = codeLeakSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
    }

    const workspaceId = req.params.workspaceId as string;
    const workspace = await storage.getWorkspace(workspaceId);
    if (!workspace) return sendError(res, 404, "Workspace not found");

    const target = (workspace.domain ?? workspace.name ?? "").trim().toLowerCase();
    if (!target) return sendValidationError(res, "No target domain set for this workspace");

    const result = await watchForCodeLeaks(target, { aliases: parsed.data.aliases });

    // A sweep that could not run must not be stored as a clean result.
    if (result.error) return sendError(res, 503, result.error);

    const module = await storage.createReconModule({
      workspaceId,
      scanId: null,
      target,
      moduleType: CODE_LEAK_MODULE_TYPE,
      data: { ...result },
      // A pattern match in retrieved source is a direct observation; whether the
      // credential is still live is not established.
      confidence: result.counts.withSecrets > 0 ? 85 : 70,
    });

    log.info({ workspaceId, target, ...result.counts }, "Code leak sweep complete");
    res.status(201).json(module);
  } catch (err) {
    log.error({ err }, "Code leak sweep failed");
    sendError(res, 500, "Code leak sweep failed");
  }
});
