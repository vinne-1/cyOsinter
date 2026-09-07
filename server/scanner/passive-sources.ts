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

/**
 * A discovery source.
 *
 * `run` returns `null` when the source did NOT answer — offline, rate-limited,
 * timed out, or shape-changed — and `[]` only when it answered and genuinely
 * had nothing. The distinction is load-bearing: `fetchJSON`/`fetchText` return
 * null on both an error and an empty body, so collapsing the two recorded a
 * timed-out crt.sh as "crtsh: 0 subdomains found". A live run against a domain
 * with hundreds of certificates reported exactly that, which is the same
 * "reported clean for a check that did not run" failure the rest of the scanner
 * is built to avoid.
 */
type Collector = { name: string; run: () => Promise<string[] | null> };

/** HackerTarget hostsearch — "host,ip" lines. */
function hackerTarget(domain: string): Collector {
  return {
    name: "hackertarget",
    run: async () => {
      const text = await fetchText(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, 15000);
      if (text === null) return null;
      // HackerTarget answers 200 with an error sentence when rate-limited.
      if (/error|api count exceeded/i.test(text)) return null;
      return extractHostsFromText(text, domain);
    },
  };
}

/**
 * AlienVault OTX passive DNS.
 *
 * **Keyed now, not keyless.** OTX ended anonymous access to this endpoint: it
 * answers `429 {"detail": "Anonymous access to this endpoint is limited."}` on
 * every unauthenticated request, verified over repeated attempts in November
 * 2026. Left in the keyless set it failed on every single scan, which put a
 * permanent entry in `sourcesFailed` and conflated two different facts — "the
 * operator has no key" and "this source did not answer" — which is precisely
 * the distinction the keyed-source gating below exists to preserve.
 *
 * The key is free (an OTX account). Without one the collector is not attempted.
 */
function alienVaultOtx(domain: string, apiKey: string): Collector {
  return {
    name: "otx",
    run: async () => {
      const data = await fetchJSON(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`, 15000, { "X-OTX-API-KEY": apiKey });
      if (data === null) return null;
      const rows: unknown = data?.passive_dns;
      if (!Array.isArray(rows)) return null;
      const out = new Set<string>();
      for (const r of rows) {
        const n = normalizeHost(String((r as { hostname?: string })?.hostname ?? ""), domain);
        if (n) out.add(n);
      }
      return Array.from(out);
    },
  };
}

/* ── Keyed sources ───────────────────────────────────────────────────────────
 *
 * These need an API key and are only added to the collector list when their key
 * is set. That is deliberate: an unconfigured source must not appear in
 * `sourcesFailed`, because "the operator has no key for this" and "this source
 * did not answer" are different facts and only the second one says anything
 * about the target. Same reasoning as `code-leak-watch` reporting "not
 * configured" rather than an empty result.
 *
 * Each still honours the `string[] | null` contract: null when the source did
 * not answer, `[]` when it answered and had nothing.
 */

/**
 * ProjectDiscovery Chaos — a curated public-bug-bounty subdomain dataset.
 *
 * Returns bare LABELS, not FQDNs (`{"subdomains":["www","api"]}`), so each is
 * joined to the domain here. Emitting the labels raw would put `www` into the
 * asset inventory as a hostname.
 */
function chaos(domain: string, key: string): Collector {
  return {
    name: "chaos",
    run: async () => {
      const data = await fetchJSON(
        `https://dns.projectdiscovery.io/dns/${encodeURIComponent(domain)}/subdomains`,
        20000,
        { Authorization: key },
      );
      if (data === null) return null;
      const rows: unknown = data?.subdomains;
      if (!Array.isArray(rows)) return null;
      const out = new Set<string>();
      for (const label of rows) {
        const raw = String(label ?? "").trim();
        if (!raw) continue;
        const n = normalizeHost(raw.includes(".") && raw.endsWith(domain) ? raw : `${raw}.${domain}`, domain);
        if (n) out.add(n);
      }
      return Array.from(out);
    },
  };
}

/** SecurityTrails subdomains. Also returns labels rather than FQDNs. */
function securityTrails(domain: string, key: string): Collector {
  return {
    name: "securitytrails",
    run: async () => {
      const data = await fetchJSON(
        `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains?children_only=false`,
        20000,
        { APIKEY: key },
      );
      if (data === null) return null;
      const rows: unknown = data?.subdomains;
      if (!Array.isArray(rows)) return null;
      const out = new Set<string>();
      for (const label of rows) {
        const raw = String(label ?? "").trim();
        if (!raw) continue;
        const n = normalizeHost(`${raw}.${domain}`, domain);
        if (n) out.add(n);
      }
      return Array.from(out);
    },
  };
}

/**
 * BeVigil — hostnames extracted from published MOBILE APPS.
 *
 * Worth having precisely because its input is unlike every other source here:
 * an endpoint hardcoded in an APK has often never appeared in a certificate, a
 * wordlist, or a crawl, so it is invisible to the other nine. Returns FQDNs.
 */
function bevigil(domain: string, key: string): Collector {
  return {
    name: "bevigil",
    run: async () => {
      const data = await fetchJSON(
        `https://osint.bevigil.com/api/${encodeURIComponent(domain)}/subdomains/`,
        20000,
        { "X-Access-Token": key },
      );
      if (data === null) return null;
      const rows: unknown = data?.subdomains;
      if (!Array.isArray(rows)) return null;
      const out = new Set<string>();
      for (const host of rows) {
        const n = normalizeHost(String(host ?? ""), domain);
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
      // The endpoint works without a key; a key only raises the rate limit,
      // so this stays a single collector rather than a keyed duplicate.
      const csKey = process.env.CERTSPOTTER_API_KEY?.trim();
      const data = await fetchJSON(
        `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`,
        15000,
        csKey ? { Authorization: `Bearer ${csKey}` } : undefined,
      );
      if (!Array.isArray(data)) return null;
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
      if (!Array.isArray(data)) return null;
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
      if (data === null) return null;
      const rows: unknown = data?.results;
      if (!Array.isArray(rows)) return null;
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
      if (data === null) return null;
      const rows: unknown = data?.results;
      if (!Array.isArray(rows)) return null;
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
      if (text === null) return null;
      return extractHostsFromText(text, domain);
    },
  };
}

/**
 * crt.sh certificate transparency search.
 *
 * Folded in here so every discovery source shares one normalisation path and
 * one provenance record. crt.sh is the broadest free CT index but also the
 * least reliable — it times out under load often enough that it must never be
 * the only CT source, which is why `certspotter` runs alongside it.
 */
function crtSh(domain: string): Collector {
  return {
    name: "crtsh",
    run: async () => {
      const data = await fetchJSON(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, 20000);
      if (!Array.isArray(data)) return null;
      const out = new Set<string>();
      for (const entry of data) {
        const raw = String((entry as { name_value?: string; common_name?: string })?.name_value
          ?? (entry as { common_name?: string })?.common_name ?? "");
        for (const line of raw.split(/\r?\n/)) {
          const n = normalizeHost(line, domain);
          if (n) out.add(n);
        }
      }
      return Array.from(out);
    },
  };
}

/**
 * Hostnames mined out of the Wayback Machine's URL index.
 *
 * The archive was already being fetched for historical URLs and then used only
 * for those URLs. The same response names every host the crawler ever saw on
 * this domain — including ones that no longer resolve and no current CT entry
 * or DNS record mentions. That is free coverage from a request already paid
 * for, and it is the source most likely to surface a forgotten host.
 */
function waybackHosts(domain: string): Collector {
  return {
    name: "wayback",
    run: async () => {
      const data = await fetchJSON(
        `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&limit=5000`,
        20000,
      );
      if (!Array.isArray(data)) return null;
      const out = new Set<string>();
      for (let i = 1; i < data.length; i++) {
        const u = Array.isArray(data[i]) ? String(data[i][0]) : String(data[i]);
        const n = normalizeHost(u, domain);
        if (n) out.add(n);
      }
      return Array.from(out);
    },
  };
}

export interface PassiveDiscovery {
  /** Every distinct hostname found, sorted. */
  subdomains: string[];
  /** How many names each source contributed (for evidence and diagnostics). */
  bySource: Record<string, number>;
  /**
   * Which sources named each host.
   *
   * The merged set alone throws away the single most useful quality signal
   * available for free: whether independent collectors agree. A name that four
   * unrelated indexes report is very likely real; one that a single HTML scrape
   * produced and nothing else corroborates is as likely to be a parsing
   * artefact. Keeping the attribution lets callers rank rather than guess, and
   * lets a report say WHERE a host came from instead of asserting it exists.
   */
  provenance: Record<string, string[]>;
  /** Sources that failed or returned nothing, so "we did not look" stays visible. */
  sourcesFailed: string[];
}

/** Confidence in a discovered hostname, from how many sources agree. */
export type DiscoveryConfidence = "high" | "medium" | "low";

/**
 * Corroboration alone, before any DNS resolution.
 *
 * Deliberately conservative: a single source is `low` even when that source is
 * usually reliable, because the point of the signal is independence. Callers
 * that go on to resolve the name should treat a successful resolution as
 * stronger evidence than any number of indexes agreeing — an index can be
 * stale, DNS cannot.
 */
export function confidenceFromSources(sources: readonly string[]): DiscoveryConfidence {
  if (sources.length >= 3) return "high";
  if (sources.length === 2) return "medium";
  return "low";
}

/**
 * Aggregate subdomains from all free passive sources. Returns a sorted, deduped
 * list, a per-source breakdown, and the per-host provenance.
 */
export async function fetchSubdomainsFromFreeSources(
  domain: string,
): Promise<PassiveDiscovery> {
  const collectors: Collector[] = [
    crtSh(domain),
    certspotter(domain),
    hackerTarget(domain),
    anubis(domain),
    threatMiner(domain),
    urlscan(domain),
    rapidDns(domain),
    waybackHosts(domain),
  ];

  // Keyed sources join the list only when configured — an absent key is not a
  // failed source.
  const otxKey = process.env.OTX_API_KEY?.trim();
  if (otxKey) collectors.push(alienVaultOtx(domain, otxKey));
  const chaosKey = process.env.CHAOS_API_KEY?.trim();
  if (chaosKey) collectors.push(chaos(domain, chaosKey));
  const stKey = process.env.SECURITYTRAILS_API_KEY?.trim();
  if (stKey) collectors.push(securityTrails(domain, stKey));
  const bevigilKey = process.env.BEVIGIL_API_KEY?.trim();
  if (bevigilKey) collectors.push(bevigil(domain, bevigilKey));

  const merged = new Set<string>();
  const bySource: Record<string, number> = {};
  const provenance: Record<string, string[]> = {};
  const sourcesFailed: string[] = [];

  const settled = await Promise.allSettled(
    collectors.map(async (c) => {
      const hosts = await c.run();
      return { name: c.name, hosts };
    }),
  );

  for (let i = 0; i < settled.length; i++) {
    const s = settled[i];
    if (s.status !== "fulfilled") {
      // A source that threw is NOT a source that found nothing. Recording the
      // difference keeps "we could not look here" out of "there was nothing
      // here" — the same rule the scanner applies to every other check.
      sourcesFailed.push(collectors[i].name);
      log.warn({ err: s.reason, source: collectors[i].name }, "Passive source collector failed");
      continue;
    }
    if (s.value.hosts === null) {
      sourcesFailed.push(s.value.name);
      log.warn({ source: s.value.name }, "passive source did not answer — recorded as unavailable, not as empty");
      continue;
    }
    bySource[s.value.name] = s.value.hosts.length;
    for (const h of s.value.hosts) {
      merged.add(h);
      (provenance[h] ??= []).push(s.value.name);
    }
  }

  for (const h of Object.keys(provenance)) provenance[h].sort();
  const subdomains = Array.from(merged).sort();
  log.info(
    { domain, total: subdomains.length, bySource, failed: sourcesFailed },
    "Free passive sources aggregated",
  );
  return { subdomains, bySource, provenance, sourcesFailed };
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

/**
 * Reverse-IP lookup: OTHER domains hosted on the same IP address (virtual-host
 * neighbours), via HackerTarget's free keyless reverse-IP endpoint. This is
 * distinct from reverse DNS (PTR): it surfaces co-hosted sites that share the
 * target's server — useful for shared-hosting attack-surface expansion and for
 * spotting unexpected neighbours on a supposedly dedicated host.
 *
 * Fail-soft: a rate-limited / errored source contributes nothing. Results are
 * capped and IP-literals / the target's own apex are filtered out.
 */
export async function reverseIpLookup(
  ips: string[],
  targetDomain: string,
  perIpCap = 100,
): Promise<Record<string, string[]>> {
  const out: Record<string, string[]> = {};
  const apex = targetDomain.toLowerCase();
  for (const ip of ips) {
    try {
      const text = await fetchText(`https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}`, 15000);
      if (!text) continue;
      // The API returns an error sentence (e.g. "API count exceeded", "No DNS A
      // records found") rather than a hostname list when it has nothing useful.
      if (/error|api count|no records|no dns|not found|invalid/i.test(text) && !text.includes("\n") && !HOSTNAME_RE.test(text.trim())) continue;
      const hosts = Array.from(new Set(
        text.split(/\r?\n/)
          .map((l) => l.trim().toLowerCase())
          .filter((h) => HOSTNAME_RE.test(h))
          // Exclude the target's own apex/subdomains — those are already ours.
          .filter((h) => h !== apex && !h.endsWith(`.${apex}`)),
      )).slice(0, perIpCap);
      if (hosts.length > 0) out[ip] = hosts;
    } catch {
      /* reverse-IP source unavailable — skip */
    }
  }
  return out;
}
