/**
 * EPSS Feed — downloads and caches EPSS scores from FIRST.org API.
 * EPSS = Exploit Prediction Scoring System (probability a CVE will be exploited).
 * API: https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYY (no auth required)
 */
import { createLogger } from "../logger";
import { storage } from "../storage";

const log = createLogger("enrichment:epss-feed");

const EPSS_BATCH_API = "https://api.first.org/data/v1/epss";
const BATCH_SIZE = 100; // API supports up to 100 CVEs per call

export interface EpssEntry {
  cveId: string;
  epss: number;
  percentile: number;
}

/** Fetch EPSS scores for a list of CVE IDs from FIRST.org API. */
export async function fetchEpssScores(cveIds: string[]): Promise<EpssEntry[]> {
  if (cveIds.length === 0) return [];

  const results: EpssEntry[] = [];

  // Process in batches
  for (let i = 0; i < cveIds.length; i += BATCH_SIZE) {
    const batch = cveIds.slice(i, i + BATCH_SIZE);
    const url = `${EPSS_BATCH_API}?cve=${batch.join(",")}`;

    try {
      const res = await fetch(url, {
        signal: AbortSignal.timeout(10_000),
        headers: { "User-Agent": "CyberShieldPro/1.0" },
      });

      if (!res.ok) {
        log.warn({ status: res.status, batch: batch.length }, "EPSS API returned non-200");
        continue;
      }

      const json = await res.json() as {
        data?: Array<{ cve: string; epss: string; percentile: string }>;
      };

      for (const entry of json.data ?? []) {
        const epss = parseFloat(entry.epss);
        const percentile = parseFloat(entry.percentile);
        if (!isNaN(epss) && !isNaN(percentile)) {
          results.push({ cveId: entry.cve, epss, percentile });
        }
      }
    } catch (err) {
      log.warn({ err, batch: batch.length }, "EPSS batch fetch failed — skipping batch");
    }
  }

  return results;
}

/** Extract CVE IDs from finding text (title + description). */
export function extractCveIds(text: string): string[] {
  const matches = text.match(/CVE-\d{4}-\d{4,7}/gi) ?? [];
  return Array.from(new Set(matches.map((m) => m.toUpperCase())));
}

/** Refresh EPSS scores for all CVEs referenced in a workspace's findings. */
export async function refreshEpssForWorkspace(workspaceId: string): Promise<void> {
  try {
    const { data: findings } = await storage.getFindings(workspaceId, { limit: 5000 });

    const cveSet = new Set<string>();
    for (const f of findings) {
      const text = `${f.title} ${f.description ?? ""}`;
      for (const cve of extractCveIds(text)) {
        cveSet.add(cve);
      }
    }

    if (cveSet.size === 0) {
      log.info({ workspaceId }, "No CVEs found in findings — skipping EPSS refresh");
      return;
    }

    const entries = await fetchEpssScores(Array.from(cveSet));

    for (const entry of entries) {
      await storage.upsertEpssScore({
        cveId: entry.cveId,
        epss: String(entry.epss),
        percentile: String(entry.percentile),
      });
    }

    log.info({ workspaceId, cves: cveSet.size, fetched: entries.length }, "EPSS scores refreshed");
  } catch (err) {
    log.error({ err, workspaceId }, "EPSS refresh failed");
  }
}
