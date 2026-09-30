/**
 * One place that generates AND persists a workspace's AI Insights synthesis.
 *
 * Three callers need this exact sequence — findings, recon and CVE context,
 * live verification against the workspace's real hosts, GLM synthesis, then
 * a snapshot written to `ai_insights_snapshots` — and it must be the SAME
 * sequence in all three, or the manual "Generate" button, the AI-enriched
 * scan's auto-trigger, and the Intelligence panel could each show a different
 * idea of "the workspace's current AI insights":
 *   - `POST /workspaces/:id/ai-insights/summary` (manual)
 *   - scan completion, when the scan was launched with AI enrichment on
 *   - (read-only) the Intelligence panel and the AI Insights page both just
 *     read the snapshot this writes
 */
import { storage, FULL_SET_LIMIT } from "./storage";
import { generateWorkspaceInsights, fetchCVEContextForInsights, type WorkspaceInsightsResult } from "./ai-service";
import { runVerificationChecks, resolveVerifiableTarget } from "./ai-follow-up";
import { searchThreatIntel } from "./tavily-service";
import { isSecurityFinding } from "./scanner/finding-taxonomy";
import { createLogger } from "./logger";

const log = createLogger("workspace-insights");

/** Terminal statuses — mirrors the set in routes/findings.ts. */
const CLOSED_STATUSES = new Set(["resolved", "false_positive", "accepted_risk", "closed"]);

/** Open security findings only — recon facts and working controls are not work to synthesize. */
export function insightFindings<T extends { kind?: string | null; status?: string | null }>(rows: T[]): T[] {
  return rows.filter((f) => isSecurityFinding(f) && !CLOSED_STATUSES.has(f.status ?? "open"));
}

export async function generateAndPersistWorkspaceInsights(
  workspaceId: string,
  opts?: { knownTarget?: string },
): Promise<WorkspaceInsightsResult> {
  const ws = await storage.getWorkspace(workspaceId);
  if (!ws) throw new Error("Workspace not found");
  const [findingsResult, modulesResult] = await Promise.all([
    storage.getFindings(workspaceId, { limit: FULL_SET_LIMIT }),
    storage.getReconModules(workspaceId),
  ]);
  const findings = insightFindings(findingsResult.data);
  const modules = modulesResult.data;
  /*
   * A caller that just ran a scan KNOWS the real target that was probed — try
   * it before the workspace record. Half the workspaces in this product have
   * no `domain` set (the fallback used everywhere else is the workspace NAME,
   * which is a label, not a hostname), so a workspace named "zepto" scanned
   * against "zepto.com" would otherwise verify against the unusable label
   * "zepto" and silently report zero live checks — not because there was
   * nothing to check, but because the only target this function tried was
   * never a domain. `resolveVerifiableTarget`'s last resort is the host
   * already sitting on the workspace's own findings (`affectedAsset`), which
   * is exactly how a manual "Regenerate" — with no `knownTarget` to pass —
   * still finds "zepto.com" for this same workspace.
   */
  const resolved = resolveVerifiableTarget([opts?.knownTarget, ws.domain, ws.name], findings);
  const wsTarget = resolved ?? (ws.domain || ws.name);

  const [cveContext, webSearchContext, verification] = await Promise.all([
    fetchCVEContextForInsights(findings, modules, 2),
    searchThreatIntel(wsTarget),
    runVerificationChecks(
      wsTarget,
      findings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        category: f.category,
        affectedAsset: f.affectedAsset,
      })),
    ),
  ]);

  const result = await generateWorkspaceInsights(findings, modules, wsTarget, {
    cveContext,
    webSearchContext,
    verification,
  });

  await storage.upsertAiInsightsSnapshot(workspaceId, result as unknown as Record<string, unknown>).catch((err) => {
    log.warn({ err, workspaceId }, "Failed to persist AI insights snapshot");
  });

  return result;
}
