import { createLogger } from "./logger";
import { storage } from "./storage";

const log = createLogger("threat-intel");

const OTX_BASE_URL = "https://otx.alienvault.com/api/v1";

export interface ThreatIndicator {
  type: "ip" | "domain" | "hash" | "url";
  value: string;
  pulseCount: number;
  reputation: number;
  tags: string[];
  lastSeen: string | null;
  source: string;
}

export interface ThreatIntelReport {
  target: string;
  indicators: ThreatIndicator[];
  riskLevel: "critical" | "high" | "medium" | "low" | "none";
  summary: string;
}

function getOtxHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    "Accept": "application/json",
    "User-Agent": "CyberShieldPro/1.0",
  };

  const apiKey = process.env.OTX_API_KEY;
  if (apiKey) {
    headers["X-OTX-API-KEY"] = apiKey;
  }

  return headers;
}

function isIpAddress(value: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value);
}

function isDomain(value: string): boolean {
  return /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(value);
}

function determineRiskLevel(indicators: readonly ThreatIndicator[]): ThreatIntelReport["riskLevel"] {
  if (indicators.length === 0) {
    return "none";
  }

  const maxReputation = Math.max(...indicators.map((i) => i.reputation));
  const totalPulses = indicators.reduce((sum, i) => sum + i.pulseCount, 0);

  if (maxReputation >= 80 || totalPulses >= 50) {
    return "critical";
  }
  if (maxReputation >= 60 || totalPulses >= 20) {
    return "high";
  }
  if (maxReputation >= 40 || totalPulses >= 5) {
    return "medium";
  }
  if (totalPulses > 0) {
    return "low";
  }
  return "none";
}

function buildSummary(
  target: string,
  indicators: readonly ThreatIndicator[],
  riskLevel: ThreatIntelReport["riskLevel"],
): string {
  if (indicators.length === 0) {
    return `No threat intelligence data found for ${target}. The target does not appear in known threat feeds.`;
  }

  const totalPulses = indicators.reduce((sum, i) => sum + i.pulseCount, 0);
  const allTags = Array.from(new Set(indicators.flatMap((i) => i.tags)));
  const tagSummary = allTags.length > 0 ? ` Associated tags: ${allTags.slice(0, 10).join(", ")}.` : "";

  return `${target} has ${riskLevel.toUpperCase()} risk level with ${totalPulses} threat pulse(s) across ${indicators.length} indicator(s).${tagSummary}`;
}

async function fetchOtxIndicator(
  indicatorType: string,
  value: string,
  section: string,
): Promise<Record<string, unknown> | null> {
  const url = `${OTX_BASE_URL}/indicators/${indicatorType}/${encodeURIComponent(value)}/${section}`;

  try {
    const response = await fetch(url, { headers: getOtxHeaders() });

    if (!response.ok) {
      if (response.status === 404) {
        log.debug({ indicatorType, value, section }, "OTX indicator not found");
        return null;
      }
      log.warn(
        { indicatorType, value, section, status: response.status },
        "OTX API returned non-OK status",
      );
      return null;
    }

    return (await response.json()) as Record<string, unknown>;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    log.warn({ indicatorType, value, error: message }, "Failed to fetch OTX indicator");
    return null;
  }
}

function parseOtxGeneralResponse(
  data: Record<string, unknown>,
  type: ThreatIndicator["type"],
  value: string,
): ThreatIndicator {
  const pulseInfo = data.pulse_info as Record<string, unknown> | undefined;
  const pulseCount = typeof pulseInfo?.count === "number" ? pulseInfo.count : 0;
  const pulses = Array.isArray(pulseInfo?.pulses) ? pulseInfo.pulses as Record<string, unknown>[] : [];

  const reputation = typeof data.reputation === "number" ? data.reputation : 0;

  const tags: string[] = [];
  for (const pulse of pulses.slice(0, 20)) {
    const pulseTags = Array.isArray(pulse.tags) ? pulse.tags as string[] : [];
    tags.push(...pulseTags);
  }

  const uniqueTags = Array.from(new Set(tags));

  const lastPulse = pulses.length > 0 ? pulses[0] : null;
  const lastSeen = lastPulse && typeof (lastPulse as Record<string, unknown>).modified === "string"
    ? (lastPulse as Record<string, unknown>).modified as string
    : null;

  return {
    type,
    value,
    pulseCount,
    reputation,
    tags: uniqueTags,
    lastSeen,
    source: "AlienVault OTX",
  };
}

async function lookupIp(ip: string): Promise<ThreatIndicator | null> {
  const data = await fetchOtxIndicator("IPv4", ip, "general");
  if (!data) {
    return null;
  }
  return parseOtxGeneralResponse(data, "ip", ip);
}

async function lookupDomain(domain: string): Promise<ThreatIndicator | null> {
  const data = await fetchOtxIndicator("domain", domain, "general");
  if (!data) {
    return null;
  }
  return parseOtxGeneralResponse(data, "domain", domain);
}

/**
 * Look up threat intelligence for an IP address or domain.
 */
export async function lookupThreatIntel(target: string): Promise<ThreatIntelReport> {
  try {
    log.info({ target }, "Looking up threat intelligence");

    const indicators: ThreatIndicator[] = [];
    const trimmedTarget = target.trim();

    if (isIpAddress(trimmedTarget)) {
      const indicator = await lookupIp(trimmedTarget);
      if (indicator) {
        indicators.push(indicator);
      }
    } else if (isDomain(trimmedTarget)) {
      const indicator = await lookupDomain(trimmedTarget);
      if (indicator) {
        indicators.push(indicator);
      }
    } else {
      // Try both IP and domain lookups for ambiguous targets
      const [ipResult, domainResult] = await Promise.all([
        lookupIp(trimmedTarget).catch(() => null),
        lookupDomain(trimmedTarget).catch(() => null),
      ]);
      if (ipResult) indicators.push(ipResult);
      if (domainResult) indicators.push(domainResult);
    }

    const riskLevel = determineRiskLevel(indicators);
    const summary = buildSummary(trimmedTarget, indicators, riskLevel);

    log.info(
      { target: trimmedTarget, indicatorCount: indicators.length, riskLevel },
      "Threat intelligence lookup complete",
    );

    return { target: trimmedTarget, indicators, riskLevel, summary };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    log.error({ target, error: message }, "Threat intelligence lookup failed");
    throw new Error(`Threat intelligence lookup failed: ${message}`);
  }
}

/**
 * Enrich workspace findings with threat intelligence data.
 * Looks up affected assets in threat feeds and updates findings' aiEnrichment field.
 * Returns count of enriched findings.
 */
export async function enrichFindingsWithThreatIntel(
  workspaceId: string,
): Promise<number> {
  try {
    const result = await storage.getFindings(workspaceId, { limit: 10000 });
    const allFindings = result.data;

    log.info(
      { workspaceId, findingCount: allFindings.length },
      "Starting threat intel enrichment",
    );

    // Deduplicate affected assets to minimize API calls
    const uniqueAssets = Array.from(new Set(
      allFindings
        .map((f) => f.affectedAsset)
        .filter((a): a is string => a !== null && a !== undefined && a.trim() !== ""),
    ));

    // Look up threat intel for each unique asset
    const threatCache = new Map<string, ThreatIntelReport>();
    for (const asset of uniqueAssets) {
      try {
        const report = await lookupThreatIntel(asset);
        threatCache.set(asset, report);
      } catch {
        log.debug({ asset }, "Skipping asset that failed threat intel lookup");
      }
    }

    let enrichedCount = 0;

    for (const finding of allFindings) {
      const asset = finding.affectedAsset;
      if (!asset || !threatCache.has(asset)) {
        continue;
      }

      const report = threatCache.get(asset)!;
      if (report.indicators.length === 0) {
        continue;
      }

      const existingEnrichment = finding.aiEnrichment ?? {};
      const updatedEnrichment: Record<string, unknown> = {
        ...existingEnrichment,
        threatIntel: {
          riskLevel: report.riskLevel,
          summary: report.summary,
          indicatorCount: report.indicators.length,
          totalPulses: report.indicators.reduce((sum, i) => sum + i.pulseCount, 0),
          tags: Array.from(new Set(report.indicators.flatMap((i) => i.tags))).slice(0, 20),
          lastChecked: new Date().toISOString(),
          source: "AlienVault OTX",
        },
      };

      await storage.updateFinding(finding.id, {
        aiEnrichment: updatedEnrichment,
      });
      enrichedCount++;
    }

    log.info(
      { workspaceId, enrichedCount, totalFindings: allFindings.length },
      "Threat intel enrichment complete",
    );

    return enrichedCount;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    log.error({ workspaceId, error: message }, "Threat intel enrichment failed");
    throw new Error(`Threat intel enrichment failed: ${message}`);
  }
}
