/**
 * Post-Scan Hook Dispatcher
 *
 * Called once after a scan completes successfully. Runs all enrichment hooks
 * in parallel via Promise.allSettled — a failed hook never blocks scan completion.
 */
import { createLogger } from "./logger";
import { storage } from "./storage";
import { rebuildCertInventory } from "./enrichment/cert-inventory";
import { rebuildTechInventory } from "./enrichment/tech-inventory";
import { recomputeFindingPriorities } from "./enrichment/finding-priority";
import { refreshEpssForWorkspace } from "./enrichment/epss-feed";
import { detectPostureAnomalies } from "./enrichment/posture-anomaly";
import { refreshCtLogCerts } from "./enrichment/ct-log";
import { enrichTechWithCpeCves } from "./enrichment/cpe-cve";

const log = createLogger("post-scan-hooks");

export async function runPostScanHooks(workspaceId: string): Promise<void> {
  // Resolve domain from workspace so CT log and CPE enrichment know the target
  const workspace = await storage.getWorkspace(workspaceId).catch(() => null);
  const domain = workspace?.name ?? "";

  const hooks = [
    { name: "cert-inventory", fn: () => rebuildCertInventory(workspaceId) },
    { name: "ct-log", fn: () => domain ? refreshCtLogCerts(workspaceId, domain) : Promise.resolve() },
    { name: "tech-inventory", fn: () => rebuildTechInventory(workspaceId) },
    { name: "epss-refresh", fn: () => refreshEpssForWorkspace(workspaceId) },
    { name: "cpe-cve", fn: () => enrichTechWithCpeCves(workspaceId) },
    { name: "finding-priority", fn: () => recomputeFindingPriorities(workspaceId) },
    { name: "posture-anomaly", fn: () => detectPostureAnomalies(workspaceId) },
  ];

  const results = await Promise.allSettled(hooks.map((h) => h.fn()));

  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    if (result.status === "rejected") {
      log.warn(
        { hook: hooks[i].name, workspaceId, err: result.reason },
        "Post-scan hook failed",
      );
    }
  }

  log.info(
    {
      workspaceId,
      passed: results.filter((r) => r.status === "fulfilled").length,
      failed: results.filter((r) => r.status === "rejected").length,
    },
    "Post-scan hooks complete",
  );
}
