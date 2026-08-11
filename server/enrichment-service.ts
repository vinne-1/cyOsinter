/**
 * Auto re-enrichment of already-scanned data with newly-available API keys.
 *
 * Threat-intel (AbuseIPDB / VirusTotal / BGP / Shodan) is gathered inline during a
 * scan using whatever keys are configured at that moment. If a key is saved WHILE a
 * scan runs (after its enrichment step) or AFTER a scan completes, the stored data
 * would miss that provider. This module retroactively fills those gaps: it re-runs
 * IP enrichment for a workspace's attack_surface module and updates it in place.
 *
 * Triggered from (1) scan completion — catches keys saved mid-scan; and
 * (2) key save — catches keys saved after a scan finished.
 */

import { storage } from "./storage";
import { enrichIP, fetchBGPView, shodanHostLookup, getIntegrationsStatus, type ShodanHostResult } from "./api-integrations";
import { createLogger } from "./logger";

const log = createLogger("enrichment");

const MAX_IPS_PER_MODULE = 10;
const RECENT_WINDOW_MS = 60 * 60 * 1000; // 1 hour

/** Collect candidate IPv4 addresses from an attack_surface module's data. */
function collectIps(data: Record<string, unknown>): string[] {
  const ips = new Set<string>();
  const rep = data.ipReputation as Record<string, unknown> | undefined;
  if (rep) for (const ip of Object.keys(rep)) ips.add(ip);
  const publicIPs = data.publicIPs as Array<{ ip?: string }> | undefined;
  if (publicIPs) for (const p of publicIPs) if (p.ip) ips.add(p.ip);
  const dns = data.dns as { ips?: string[] } | undefined;
  if (dns?.ips) for (const ip of dns.ips) ips.add(ip);
  return Array.from(ips).filter((ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip));
}

function domainOf(data: Record<string, unknown>): string {
  const inv = data.assetInventory as { domain?: string } | undefined;
  return inv?.domain ?? "the target";
}

interface IpRepEntry {
  abuseipdb?: unknown;
  virustotal?: unknown;
  bgp?: unknown;
  shodan?: ShodanHostResult;
}

async function upsertShodanFinding(
  workspaceId: string,
  scanId: string | null,
  ip: string,
  domain: string,
  shodan: ShodanHostResult,
): Promise<void> {
  const hasVulns = shodan.vulns.length > 0;
  const title = `Shodan-indexed exposure for ${ip}`; // stable title → dedups vs the scan's own finding
  const category = hasVulns ? "vulnerability" : "network_exposure";
  try {
    if (await storage.findingExists(workspaceId, title, ip, category)) return;
    await storage.createFinding({
      workspaceId,
      scanId: scanId ?? undefined,
      title,
      description: `Shodan has indexed ${ip} (${domain}) with ${shodan.ports.length} open port(s)${shodan.products.length ? ` running ${shodan.products.slice(0, 8).join(", ")}` : ""}.${hasVulns ? ` Shodan associates ${shodan.vulns.length} known CVE(s) with this host: ${shodan.vulns.slice(0, 15).join(", ")}.` : ""}`,
      severity: hasVulns ? "high" : "info",
      category,
      affectedAsset: ip,
      cvssScore: hasVulns ? "7.5" : "1.0",
      remediation: hasVulns
        ? "Review the CVEs Shodan associates with this host, patch affected services, and restrict unnecessary exposed ports."
        : "Review whether all Shodan-indexed open ports are intended to be internet-facing.",
      status: "open",
      evidence: [{
        type: "shodan",
        description: "Shodan host lookup (auto-enrichment)",
        snippet: `IP: ${ip}\nPorts: ${shodan.ports.join(", ") || "none"}\nProducts: ${shodan.products.join(", ") || "n/a"}\nCVEs: ${shodan.vulns.join(", ") || "none"}`,
        source: "Shodan API",
        verifiedAt: new Date().toISOString(),
      }],
    });
  } catch (err) {
    log.warn({ err, ip }, "Failed to upsert Shodan finding");
  }
}

/**
 * Re-run threat-intel enrichment for a workspace's attack_surface module(s) using
 * currently-configured keys, filling any gaps and updating the module in place.
 * No-op when no keyed provider is configured. Returns the number of modules updated.
 */
export async function reEnrichWorkspaceThreatIntel(workspaceId: string): Promise<number> {
  const status = getIntegrationsStatus();
  const wantKeyed = status.abuseipdb.configured || status.virustotal.configured || status.shodan.configured;
  if (!wantKeyed) return 0; // nothing a key would add beyond what the scan already gathered keylessly

  const modules = await storage.getReconModulesByType(workspaceId, "attack_surface");
  let updated = 0;
  for (const mod of modules) {
    const data = { ...(mod.data as Record<string, unknown>) };
    const ipRep: Record<string, IpRepEntry> = { ...((data.ipReputation as Record<string, IpRepEntry>) ?? {}) };
    const domain = domainOf(data);
    let changed = false;

    for (const ip of collectIps(data).slice(0, MAX_IPS_PER_MODULE)) {
      const entry: IpRepEntry = { ...(ipRep[ip] ?? {}) };
      try {
        // Caches were cleared on key save, so this fetches with the new key.
        const enr = await enrichIP(ip);
        if (enr.abuseipdb) entry.abuseipdb = enr.abuseipdb;
        if (enr.virustotal) entry.virustotal = enr.virustotal;
        if (!entry.bgp) entry.bgp = await fetchBGPView(ip);
        if (status.shodan.configured && !entry.shodan) {
          const s = await shodanHostLookup(ip);
          if (s) {
            entry.shodan = s;
            if (s.ports.length > 0 || s.vulns.length > 0) await upsertShodanFinding(workspaceId, mod.scanId, ip, domain, s);
          }
        }
        ipRep[ip] = entry;
        changed = true;
      } catch (err) {
        log.warn({ err, ip }, "IP re-enrichment failed (non-fatal)");
      }
    }

    if (changed) {
      await storage.updateReconModule(mod.id, { data: { ...data, ipReputation: ipRep, reEnrichedAt: new Date().toISOString() } });
      updated++;
    }
  }
  if (updated > 0) log.info({ workspaceId, updated }, "Auto re-enrichment updated recon modules with new API keys");
  return updated;
}

/**
 * Re-enrich every workspace whose latest scan is running or completed within the
 * last hour. Called after a threat-intel key is saved. Best-effort, sequential to
 * respect provider rate limits.
 */
export async function reEnrichRecentWorkspaces(): Promise<void> {
  try {
    const workspaces = await storage.getWorkspaces();
    for (const ws of workspaces) {
      try {
        const { data: scans } = await storage.getScans(ws.id, { limit: 1, offset: 0 });
        const latest = scans[0];
        if (!latest) continue;
        const running = latest.status === "running" || latest.status === "pending";
        const completedAt = latest.completedAt ? new Date(latest.completedAt).getTime() : 0;
        const recent = completedAt > 0 && Date.now() - completedAt < RECENT_WINDOW_MS;
        if (running || recent) await reEnrichWorkspaceThreatIntel(ws.id);
      } catch (err) {
        log.warn({ err, workspaceId: ws.id }, "Re-enrichment skipped for workspace");
      }
    }
  } catch (err) {
    log.warn({ err }, "reEnrichRecentWorkspaces failed");
  }
}
