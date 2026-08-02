import dns from "dns/promises";
import { createLogger } from "../logger.js";
import { fetchJSON, fetchText } from "./http.js";

/**
 * Free, keyless passive OSINT sources.
 *
 * Aggregates subdomain names and historical URLs from public third-party APIs
 * that require no API key: certificate transparency mirrors, passive-DNS
 * databases, and web archives. Every collector is best-effort and fail-soft —
 * a source that is down, rate-limited, or changes its format simply contributes
 * nothing rather than failing the scan. All HTTP goes through the shared
 * (stealth-paced) fetch helpers in http.ts.
 *
 * NOTE: several of these services rate-limit aggressively for unauthenticated
 * use (HackerTarget ~50/day, urlscan, Certspotter). That is acceptable for a
 * self-hosted scanner and keeps the tool dependency-free and cost-free.
 */

const log = createLogger("passive-sources");

const HOSTNAME_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;

/** Normalize + validate a candidate name against the target apex domain. */
export function normalizeHost(raw: string, domain: string): string | null {
  let name = raw.trim().toLowerCase();
  if (!name) return null;
  name = name.replace(/^\*\./, "").replace(/\.$/, "");
  // Strip scheme/path if a URL slipped through.
  name = name.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  if (name === domain) return null; // apex is not a subdomain
  if (!name.endsWith(`.${domain}`)) return null;
  if (!HOSTNAME_RE.test(name)) return null;
  return name;
}

/** Pull every `something.domain` token out of an arbitrary text body. */
export function extractHostsFromText(text: string, domain: string): string[] {
  const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`([a-z0-9_-]+\\.)+${escaped}`, "gi");
  const found = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const n = normalizeHost(m[0], domain);
    if (n) found.add(n);
  }
  return Array.from(found);
}

type Collector = { name: string; run: () => Promise<string[]> };

/** HackerTarget hostsearch — "host,ip" lines. */
function hackerTarget(domain: string): Collector {
  return {
    name: "hackertarget",
    run: async () => {
      const text = await fetchText(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, 15000);
      if (!text || /error|api count exceeded/i.test(text)) return [];
      return extractHostsFromText(text, domain);
    },
  };
}

/** AlienVault OTX passive DNS. */
function alienVaultOtx(domain: string): Collector {
  return {
    name: "otx",
    run: async () => {
      const data = await fetchJSON(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`, 15000);
      const rows: unknown = data?.passive_dns;
      if (!Array.isArray(rows)) return [];
      const out = new Set<string>();
      for (const r of rows) {
        const n = normalizeHost(String((r as { hostname?: string })?.hostname ?? ""), domain);
        if (n) out.add(n);
      }
      return Array.from(out);
    },
  };
}

/** Certspotter certificate issuances (CT). */
function certspotter(domain: string): Collector {
  return {
    name: "certspotter",
    run: async () => {
      const data = await fetchJSON(
        `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`,
        15000,
      );
      if (!Array.isArray(data)) return [];
      const out = new Set<string>();
      for (const issuance of data) {
        const names: unknown = (issuance as { dns_names?: string[] })?.dns_names;
        if (Array.isArray(names)) {
          for (const dn of names) {
            const n = normalizeHost(String(dn), domain);
            if (n) out.add(n);
          }
        }
      }
      return Array.from(out);
    },
  };
}

/** Anubis (jldc.me) subdomain DB — JSON array of names. */
function anubis(domain: string): Collector {
  return {
    name: "anubis",
    run: async () => {
      const data = await fetchJSON(`https://jldc.me/anubis/subdomains/${encodeURIComponent(domain)}`, 15000);
      if (!Array.isArray(data)) return [];
      const out = new Set<string>();
      for (const d of data) {
        const n = normalizeHost(String(d), domain);
        if (n) out.add(n);
      }
      return Array.from(out);
    },
  };
}

/** ThreatMiner passive DNS (rt=5 → subdomains). */
function threatMiner(domain: string): Collector {
  return {
    name: "threatminer",
    run: async () => {
      const data = await fetchJSON(`https://api.threatminer.org/v2/domain.php?q=${encodeURIComponent(domain)}&rt=5`, 15000);
      const rows: unknown = data?.results;
      if (!Array.isArray(rows)) return [];
      const out = new Set<string>();
      for (const r of rows) {
        const n = normalizeHost(String(r), domain);
        if (n) out.add(n);
      }
      return Array.from(out);
    },
  };
}

/** urlscan.io search — collect domains seen in scans. */
function urlscan(domain: string): Collector {
  return {
    name: "urlscan",
    run: async () => {
      const data = await fetchJSON(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=1000`, 15000);
      const rows: unknown = data?.results;
      if (!Array.isArray(rows)) return [];
      const out = new Set<string>();
      for (const r of rows) {
        const page = (r as { page?: { domain?: string } })?.page?.domain;
        const task = (r as { task?: { domain?: string } })?.task?.domain;
        for (const cand of [page, task]) {
          const n = cand ? normalizeHost(String(cand), domain) : null;
          if (n) out.add(n);
        }
      }
      return Array.from(out);
    },
  };
}

/** RapidDNS subdomain table (HTML scrape via generic host regex). */
function rapidDns(domain: string): Collector {
  return {
    name: "rapiddns",
    run: async () => {
      const text = await fetchText(`https://rapiddns.io/subdomain/${encodeURIComponent(domain)}?full=1`, 15000);
      if (!text) return [];
      return extractHostsFromText(text, domain);
    },
  };
}

/**
 * Aggregate subdomains from all free passive sources. Returns a sorted, deduped
 * list plus a per-source breakdown (for evidence/reporting).
 */
export async function fetchSubdomainsFromFreeSources(
  domain: string,
): Promise<{ subdomains: string[]; bySource: Record<string, number> }> {
  const collectors: Collector[] = [
    hackerTarget(domain),
    alienVaultOtx(domain),
    certspotter(domain),
    anubis(domain),
    threatMiner(domain),
    urlscan(domain),
    rapidDns(domain),
  ];

  const merged = new Set<string>();
  const bySource: Record<string, number> = {};

  const settled = await Promise.allSettled(
    collectors.map(async (c) => {
      const hosts = await c.run();
      return { name: c.name, hosts };
    }),
  );

  for (const s of settled) {
    if (s.status === "fulfilled") {
      bySource[s.value.name] = s.value.hosts.length;
      for (const h of s.value.hosts) merged.add(h);
    } else {
      log.warn({ err: s.reason }, "Passive source collector failed");
    }
  }

  const subdomains = Array.from(merged).sort();
  log.info({ domain, total: subdomains.length, bySource }, "Free passive sources aggregated");
  return { subdomains, bySource };
}

/**
 * Historical URLs for the domain from the Wayback Machine CDX API (keyless).
 * Useful for discovering old/forgotten endpoints and parameters.
 */
export async function fetchWaybackUrls(domain: string, limit = 1000): Promise<string[]> {
  try {
    const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const data = await fetchJSON(
      `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&limit=${limit}`,
      20000,
    );
    if (!Array.isArray(data) || data.length <= 1) return [];
    // First row is the header (["original"]); the rest are single-element rows.
    const onDomain = new RegExp(`^https?://([a-z0-9_-]+\\.)*${escaped}(?::\\d+)?/`, "i");
    const urls = new Set<string>();
    for (let i = 1; i < data.length; i++) {
      const u = Array.isArray(data[i]) ? String(data[i][0]) : String(data[i]);
      if (onDomain.test(u)) urls.add(u);
    }
    return Array.from(urls).slice(0, limit);
  } catch (err) {
    log.warn({ err, domain }, "Wayback URL fetch failed");
    return [];
  }
}

/** Reverse-DNS (PTR) lookups for a set of IPs. Fail-soft per IP. */
export async function reverseDnsLookup(ips: string[]): Promise<Record<string, string[]>> {
  const out: Record<string, string[]> = {};
  for (const ip of ips) {
    try {
      const names = await dns.reverse(ip);
      if (names.length > 0) out[ip] = names;
    } catch {
      /* no PTR record — skip */
    }
  }
  return out;
}
