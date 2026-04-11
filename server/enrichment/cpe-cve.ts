/**
 * CPE-to-CVE Enrichment
 *
 * After tech-inventory is rebuilt, for each detected technology with a CPE string,
 * queries the NVD REST API to find relevant CVEs and attaches them to findings
 * for the affected host. EPSS scores are then refreshed in the next hook step.
 *
 * NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
 * - No auth required (rate-limited to ~5 req/30s without key)
 * - We throttle to stay well within limits
 */
import { createLogger } from "../logger";
import { storage } from "../storage";
import { analyzeHosts } from "./wappalyzer-engine";
import type { ReconModule } from "@shared/schema";

const log = createLogger("enrichment:cpe-cve");

const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_TIMEOUT_MS = 15_000;
/** NVD free tier: 5 requests per 30 seconds. We aim for 1 req/7s to be safe. */
const NVD_DELAY_MS = 7_000;
const MAX_CVE_PER_PRODUCT = 5;

interface AttackSurfaceData {
  rawHeadersByHost?: Record<string, Record<string, string>>;
  htmlByHost?: Record<string, string>;
}

/** Fetch top CVEs for a CPE string from NVD. */
async function fetchCvesByCpe(cpe: string, version: string | null): Promise<string[]> {
  // Build a versioned CPE by replacing the wildcard version segment if we have a version
  let cpeName = cpe;
  if (version && cpe.includes(":*:*:*:*:*:*:*")) {
    // Replace first wildcard after vendor:product: with the actual version
    cpeName = cpe.replace(/:([^:]+):(\*):(\*):/, `:$1:${version}:`);
  }

  const url = `${NVD_API}?cpeName=${encodeURIComponent(cpeName)}&resultsPerPage=${MAX_CVE_PER_PRODUCT}`;

  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(NVD_TIMEOUT_MS),
      headers: { "User-Agent": "CyberShieldPro/1.0", Accept: "application/json" },
    });

    if (res.status === 429) {
      log.warn({ cpe: cpeName }, "NVD API rate limited — skipping");
      return [];
    }
    if (!res.ok) return [];

    const data = await res.json() as {
      vulnerabilities?: Array<{ cve: { id: string; metrics?: { cvssMetricV31?: Array<{ cvssData: { baseScore: number } }> } } }>;
    };

    return (data.vulnerabilities ?? [])
      .filter((v) => {
        // Only include CVEs with CVSS ≥ 5.0 (medium+)
        const score = v.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? 0;
        return score >= 5.0;
      })
      .map((v) => v.cve.id);
  } catch (err) {
    log.warn({ err, cpe: cpeName }, "NVD CPE lookup failed");
    return [];
  }
}

/** Sleep helper to respect NVD rate limits. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * For each tech with a CPE in the workspace's tech_inventory,
 * look up relevant CVEs from NVD and attach them to open findings
 * for the same host as cveIds. Findings are updated in-place.
 */
export async function enrichTechWithCpeCves(workspaceId: string): Promise<void> {
  try {
    const inventory = await storage.getTechInventory(workspaceId);
    if (inventory.length === 0) return;

    // Only process entries with a CPE — Wappalyzer provides this
    // (fall back to building a basic CPE from product name/version)
    const withCpe = inventory.filter((item) => {
      // tech_inventory may not have a cpe column — we re-detect via wappalyzer
      return true; // we'll derive CPE from wappalyzer results below
    });

    // Re-run Wappalyzer on the latest attack_surface module to get fresh CPEs
    const surfaceModules = await storage.getReconModulesByType(workspaceId, "attack_surface");
    if (surfaceModules.length === 0) return;

    const latestModule = surfaceModules[0] as ReconModule;
    const data = latestModule.data as AttackSurfaceData;
    const rawHeaders = data.rawHeadersByHost ?? {};
    const htmlByHost = data.htmlByHost ?? {};

    if (Object.keys(rawHeaders).length === 0) {
      log.info({ workspaceId }, "No rawHeadersByHost in attack_surface — skipping CPE-CVE enrichment");
      return;
    }

    const wapResults = await analyzeHosts(rawHeaders, htmlByHost);
    if (wapResults.size === 0) return;

    // Build host → cpe → version map from Wappalyzer results
    const cpesToCheck: Array<{ host: string; cpe: string; version: string | null; product: string }> = [];
    for (const [host, techs] of Array.from(wapResults.entries())) {
      for (const tech of techs) {
        if (tech.cpe && tech.confidence >= 50) {
          cpesToCheck.push({ host, cpe: tech.cpe, version: tech.version, product: tech.slug });
        }
      }
    }

    if (cpesToCheck.length === 0) return;

    log.info({ workspaceId, count: cpesToCheck.length }, "Starting CPE-CVE lookups");

    for (const { host, cpe, version, product } of cpesToCheck) {
      const cveIds = await fetchCvesByCpe(cpe, version);

      if (cveIds.length === 0) {
        await sleep(NVD_DELAY_MS);
        continue;
      }

      log.info({ workspaceId, host, product, cveIds }, "Found CVEs via CPE lookup");

      // Find open findings for this host and prepend CVE IDs to their description
      // so that EPSS refresh (next hook) picks them up
      const { data: findings } = await storage.getFindings(workspaceId, { limit: 1000 });
      const hostFindings = findings.filter(
        (f) => f.status === "open" && (f.affectedAsset === host || f.affectedAsset === latestModule.target),
      );

      for (const finding of hostFindings) {
        // Only update if this finding doesn't already mention these CVEs
        const existing = `${finding.title} ${finding.description ?? ""}`;
        const newCves = cveIds.filter((id) => !existing.toUpperCase().includes(id));
        if (newCves.length === 0) continue;

        const cveNote = `Related CVEs for ${product}${version ? ` ${version}` : ""} on ${host}: ${newCves.join(", ")}`;
        await storage.updateFinding(finding.id, {
          description: finding.description
            ? `${finding.description}\n\n${cveNote}`
            : cveNote,
        });
      }

      await sleep(NVD_DELAY_MS);
    }

    log.info({ workspaceId }, "CPE-CVE enrichment complete");
  } catch (err) {
    log.error({ err, workspaceId }, "CPE-CVE enrichment failed");
  }
}
