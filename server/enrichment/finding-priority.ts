/**
 * SmartPriority — composite finding prioritization.
 *
 * Score = 100 × (0.30×cvss + 0.25×epss + 0.20×kev + 0.15×exposure + 0.10×age)
 *
 * Each component is normalized to [0,1]:
 *   cvss       = cvssScore / 10
 *   epss       = raw EPSS probability (already 0–1)
 *   kev        = 1 if in CISA KEV, else 0
 *   exposure   = 1 if public-facing asset, else 0.3
 *   age        = min(1, daysSinceDiscovery / 90)
 */
import { createLogger } from "../logger";
import { storage } from "../storage";
import { extractCveIds, fetchEpssScores } from "./epss-feed";
import type { Finding } from "@shared/schema";

const log = createLogger("enrichment:finding-priority");

// Weights must sum to 1.0
const W_CVSS = 0.30;
const W_EPSS = 0.25;
const W_KEV = 0.20;
const W_EXPOSURE = 0.15;
const W_AGE = 0.10;

// Severity → default CVSS baseline when no cvssScore is stored
const SEVERITY_CVSS: Record<string, number> = {
  critical: 9.0,
  high: 7.5,
  medium: 5.5,
  low: 3.0,
  info: 1.0,
};

// Known-public-facing category patterns
const PUBLIC_EXPOSURE_CATEGORIES = new Set([
  "open_redirect", "cors_misconfiguration", "xss", "api_exposure",
  "information_disclosure", "exposed_credentials", "secret_exposure",
  "subdomain_takeover", "transport_security", "ssl_tls", "dns_security",
  "certificate_expiry",
]);

export interface PriorityComponents {
  cvssComponent: number;
  epssComponent: number;
  kevComponent: number;
  exposureComponent: number;
  ageComponent: number;
  compositeScore: number;
}

export function computeComponents(
  finding: Finding,
  epssProb: number | null,
  inKev: boolean,
): PriorityComponents {
  // CVSS component
  const rawCvss = finding.cvssScore ? parseFloat(finding.cvssScore) : null;
  const cvssBase = rawCvss != null && !isNaN(rawCvss)
    ? rawCvss
    : SEVERITY_CVSS[(finding.severity ?? "info").toLowerCase()] ?? 1.0;
  const cvssComponent = Math.min(1, cvssBase / 10);

  // EPSS component
  const epssComponent = epssProb != null ? Math.min(1, Math.max(0, epssProb)) : 0;

  // KEV component
  const kevComponent = inKev ? 1 : 0;

  // Exposure component
  const exposureComponent = PUBLIC_EXPOSURE_CATEGORIES.has(
    (finding.category ?? "").toLowerCase().replace(/ /g, "_"),
  ) ? 1.0 : 0.3;

  // Age component (max out at 90 days)
  const discoveredMs = finding.discoveredAt ? new Date(finding.discoveredAt).getTime() : Date.now();
  const agedays = (Date.now() - discoveredMs) / 86_400_000;
  const ageComponent = Math.min(1, agedays / 90);

  const compositeScore = Math.round(
    (W_CVSS * cvssComponent +
      W_EPSS * epssComponent +
      W_KEV * kevComponent +
      W_EXPOSURE * exposureComponent +
      W_AGE * ageComponent) * 1000,
  ) / 10; // one decimal place, 0–100

  return { cvssComponent, epssComponent, kevComponent, exposureComponent, ageComponent, compositeScore };
}

/** Recompute SmartPriority for all open findings in a workspace. */
export async function recomputeFindingPriorities(workspaceId: string): Promise<void> {
  try {
    const { data: findings } = await storage.getFindings(workspaceId, { limit: 5000 });
    const openFindings = findings.filter((f) => f.status === "open" || f.status === "in_review");

    if (openFindings.length === 0) return;

    // Gather all CVE IDs and fetch EPSS in batch
    const cveMap = new Map<string, string[]>(); // findingId → cveIds
    const allCveIds = new Set<string>();

    for (const f of openFindings) {
      const cves = extractCveIds(`${f.title} ${f.description ?? ""}`);
      cveMap.set(f.id, cves);
      cves.forEach((c) => allCveIds.add(c));
    }

    // Fetch EPSS scores for all CVEs at once
    const epssEntries = await fetchEpssScores(Array.from(allCveIds));
    const epssById = new Map(epssEntries.map((e) => [e.cveId, e.epss]));

    // Fetch cached EPSS from DB (for CVEs already known)
    const epssFromDb = await Promise.all(
      Array.from(allCveIds).map((id) => storage.getEpssScore(id)),
    );
    for (const score of epssFromDb) {
      if (score && !epssById.has(score.cveId)) {
        epssById.set(score.cveId, parseFloat(score.epss));
      }
    }

    // Compute composite score for each finding
    const scored = openFindings.map((f) => {
      const fCves = cveMap.get(f.id) ?? [];
      const maxEpss = fCves.length > 0
        ? Math.max(...fCves.map((c) => epssById.get(c) ?? 0))
        : null;

      // KEV check: crude check for common KEV markers in finding text
      const text = `${f.title} ${f.description ?? ""}`.toLowerCase();
      const inKev = text.includes("cisa kev") || text.includes("known exploited") || f.cvssScore === "kev";

      return {
        finding: f,
        components: computeComponents(f, maxEpss, inKev),
      };
    });

    // Sort by compositeScore desc → assign rank
    scored.sort((a, b) => b.components.compositeScore - a.components.compositeScore);

    for (let i = 0; i < scored.length; i++) {
      const { finding, components } = scored[i];
      await storage.upsertFindingPriority({
        findingId: finding.id,
        cvssComponent: String(Math.round(components.cvssComponent * 1000) / 1000),
        epssComponent: String(Math.round(components.epssComponent * 1000) / 1000),
        kevComponent: components.kevComponent,
        exposureComponent: String(Math.round(components.exposureComponent * 1000) / 1000),
        ageComponent: String(Math.round(components.ageComponent * 1000) / 1000),
        compositeScore: String(components.compositeScore),
        rank: i + 1,
      });
    }

    log.info({ workspaceId, scored: scored.length }, "Finding priorities recomputed");
  } catch (err) {
    log.error({ err, workspaceId }, "Finding priority computation failed");
  }
}
