/**
 * API integrations for threat intelligence: AbuseIPDB, VirusTotal.
 * AI: Ollama (DeepSeek R1 Abliterated).
 * Keys/config are read from: 1) in-memory (set via UI), 2) .local/integrations.json, 3) environment variables.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { createLogger } from "./logger";

const log = createLogger("integrations");

const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

const INTEGRATIONS_CONFIG_PATH = join(process.cwd(), ".local", "integrations.json");

const apiKeysFromUI: Record<string, string> = {};
const ollamaConfigFromUI: { baseUrl?: string; model?: string; enabled?: boolean } = {};

type ApiKeyProvider = "abuseipdb" | "virustotal" | "tavily";

function loadIntegrationsConfig(): void {
  try {
    if (!existsSync(INTEGRATIONS_CONFIG_PATH)) return;
    const raw = readFileSync(INTEGRATIONS_CONFIG_PATH, "utf-8");
    const data = JSON.parse(raw) as {
      ollama?: { baseUrl?: string; model?: string; enabled?: boolean };
      apiKeys?: Record<ApiKeyProvider, string>;
    };
    if (data.ollama) {
      if (data.ollama.baseUrl !== undefined) ollamaConfigFromUI.baseUrl = data.ollama.baseUrl;
      if (data.ollama.model !== undefined) ollamaConfigFromUI.model = data.ollama.model;
      // Default enabled to true when baseUrl is set (Ollama configured) unless explicitly false
      ollamaConfigFromUI.enabled = data.ollama.enabled !== undefined ? !!data.ollama.enabled : true;
    }
    if (data.apiKeys && typeof data.apiKeys === "object") {
      for (const p of ["abuseipdb", "virustotal", "tavily"] as ApiKeyProvider[]) {
        const v = data.apiKeys[p];
        if (typeof v === "string" && v.trim()) apiKeysFromUI[p] = v.trim();
      }
    }
  } catch {
    // Ignore parse errors or missing file
  }
}

function saveIntegrationsConfig(): void {
  try {
    const dir = join(process.cwd(), ".local");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const apiKeys: Record<string, string> = {};
    for (const p of ["abuseipdb", "virustotal", "tavily"] as ApiKeyProvider[]) {
      const v = apiKeysFromUI[p];
      if (v?.trim()) apiKeys[p] = v.trim();
    }
    const data = {
      ollama: {
        baseUrl: ollamaConfigFromUI.baseUrl,
        model: ollamaConfigFromUI.model,
        enabled: ollamaConfigFromUI.enabled,
      },
      apiKeys: Object.keys(apiKeys).length ? apiKeys : undefined,
    };
    writeFileSync(INTEGRATIONS_CONFIG_PATH, JSON.stringify(data, null, 2), "utf-8");
  } catch (err) {
    log.warn({ err }, "Failed to persist config");
  }
}

loadIntegrationsConfig();

if (ollamaConfigFromUI.baseUrl) {
  // Log only that config was loaded, not the actual URL (security)
}

function normalizeOllamaBaseUrl(url: string): string {
  const u = url?.trim() || "";
  if (!u) return "http://127.0.0.1:11434";
  return u.replace(/localhost(?=:\d|$)/i, "127.0.0.1");
}

function parseOllamaEnabled(val: string | undefined): boolean {
  if (val === undefined) return true; // not set = use UI/config default
  const v = String(val).trim().toLowerCase();
  if (v === "false" || v === "0" || v === "no" || v === "off") return false;
  return v.length > 0; // "true", "1", "yes" = true
}

export function getOllamaConfig(): { baseUrl: string; model: string; enabled: boolean } {
  const baseUrl = normalizeOllamaBaseUrl(process.env.OLLAMA_BASE_URL || ollamaConfigFromUI.baseUrl || "http://localhost:11434");
  const model = process.env.OLLAMA_MODEL?.trim() || ollamaConfigFromUI.model?.trim() || "tinyllama";
  const enabled =
    process.env.OLLAMA_ENABLED !== undefined
      ? parseOllamaEnabled(process.env.OLLAMA_ENABLED)
      : (ollamaConfigFromUI.enabled ?? true); // default true when Ollama baseUrl is configured
  return { baseUrl, model, enabled };
}

/** Validates that an Ollama base URL points to a safe local/known host */
function isValidOllamaUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    if (!["http:", "https:"].includes(u.protocol)) return false;
    const host = u.hostname.toLowerCase();
    // Only allow localhost, 127.0.0.1, or explicit private network Ollama hosts
    const allowed = ["localhost", "127.0.0.1", "::1", "ollama", "host.docker.internal"];
    return allowed.some((a) => host === a || host.endsWith(`.${a}`));
  } catch {
    return false;
  }
}

export function setOllamaConfig(config: { baseUrl?: string; model?: string; enabled?: boolean }): void {
  if (config.baseUrl !== undefined) {
    if (config.baseUrl && !isValidOllamaUrl(config.baseUrl)) {
      throw new Error("Invalid Ollama base URL: must point to localhost or a known internal host");
    }
    ollamaConfigFromUI.baseUrl = config.baseUrl;
  }
  if (config.model !== undefined) ollamaConfigFromUI.model = config.model;
  if (config.enabled !== undefined) ollamaConfigFromUI.enabled = config.enabled;
  saveIntegrationsConfig();
}

function getApiKey(provider: "abuseipdb" | "virustotal" | "tavily"): string | undefined {
  const fromUI = apiKeysFromUI[provider]?.trim();
  if (fromUI) return fromUI;
  const fromEnv =
    provider === "abuseipdb"
      ? process.env.ABUSEIPDB_API_KEY
      : provider === "virustotal"
        ? process.env.VIRUSTOTAL_API_KEY
        : process.env.TAVILY_API_KEY;
  return fromEnv?.trim();
}

export function setApiKey(provider: "abuseipdb" | "virustotal" | "tavily", key: string): void {
  const trimmed = key?.trim();
  if (trimmed) {
    apiKeysFromUI[provider] = trimmed;
  } else {
    delete apiKeysFromUI[provider];
  }
  saveIntegrationsConfig();
}

export function getTavilyKey(): string | undefined {
  return getApiKey("tavily");
}
const MAX_IPS_PER_BATCH = 10;
const VIRUSTOTAL_DELAY_MS = 1500; // ~4 req/min for free tier

interface CacheEntry {
  abuseipdb: AbuseIPDBResult | null;
  virustotal: VirusTotalResult | null;
  fetchedAt: number;
}

const enrichmentCache = new Map<string, CacheEntry>();

function isPrivateIP(ip: string): boolean {
  if (ip === "::1" || ip === "localhost") return true;
  if (ip.startsWith("127.")) return true;
  if (ip.startsWith("10.")) return true;
  if (ip.startsWith("192.168.")) return true;
  if (ip.startsWith("172.")) {
    const second = parseInt(ip.split(".")[1] || "0", 10);
    if (second >= 16 && second <= 31) return true;
  }
  if (ip.includes(":") && (ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe80"))) return true;
  return false;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export interface AbuseIPDBResult {
  ipAddress: string;
  abuseConfidenceScore: number;
  totalReports: number;
  countryCode?: string;
  countryName?: string;
  isp?: string;
  usageType?: string;
  domain?: string;
}

export interface VirusTotalResult {
  ip: string;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  as_owner?: string;
  country?: string;
  continent?: string;
}

export async function fetchAbuseIPDB(ip: string): Promise<AbuseIPDBResult | null> {
  const key = getApiKey("abuseipdb");
  if (!key) return null;

  try {
    const url = new URL("https://api.abuseipdb.com/api/v2/check");
    url.searchParams.set("ipAddress", ip);
    url.searchParams.set("maxAgeInDays", "90");

    const res = await fetch(url.toString(), {
      method: "GET",
      headers: {
        Key: key,
        Accept: "application/json",
      },
    });

    if (!res.ok) {
      if (res.status === 429) log.warn({ ip }, "AbuseIPDB rate limit hit");
      return null;
    }

    const json = (await res.json()) as { data?: Record<string, unknown> };
    const d = json.data;
    if (!d) return null;

    return {
      ipAddress: String(d.ipAddress ?? ip),
      abuseConfidenceScore: Number(d.abuseConfidenceScore ?? 0),
      totalReports: Number(d.totalReports ?? 0),
      countryCode: d.countryCode as string | undefined,
      countryName: d.countryName as string | undefined,
      isp: d.isp as string | undefined,
      usageType: d.usageType as string | undefined,
      domain: d.domain as string | undefined,
    };
  } catch (err) {
    log.error({ err, ip }, "AbuseIPDB error");
    return null;
  }
}

export async function fetchVirusTotal(ip: string): Promise<VirusTotalResult | null> {
  const key = getApiKey("virustotal");
  if (!key) return null;

  try {
    const encodedIp = encodeURIComponent(ip);
    const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${encodedIp}`, {
      method: "GET",
      headers: {
        "x-apikey": key,
        Accept: "application/json",
      },
    });

    if (!res.ok) {
      if (res.status === 429) log.warn({ ip }, "VirusTotal rate limit hit");
      return null;
    }

    const json = (await res.json()) as { data?: { attributes?: Record<string, unknown>; id?: string }; id?: string };
    const attrs = json.data?.attributes;
    if (!attrs) return null;

    const stats = attrs.last_analysis_stats as Record<string, number> | undefined;
    return {
      ip: json.data?.id ?? ip,
      malicious: stats?.malicious ?? 0,
      suspicious: stats?.suspicious ?? 0,
      harmless: stats?.harmless ?? 0,
      undetected: stats?.undetected ?? 0,
      as_owner: attrs.as_owner as string | undefined,
      country: attrs.country as string | undefined,
      continent: attrs.continent as string | undefined,
    };
  } catch (err) {
    log.error({ err, ip }, "VirusTotal error");
    return null;
  }
}

export interface IPEnrichment {
  abuseipdb: AbuseIPDBResult | null;
  virustotal: VirusTotalResult | null;
}

export async function enrichIP(ip: string): Promise<IPEnrichment> {
  if (isPrivateIP(ip)) {
    return { abuseipdb: null, virustotal: null };
  }

  const cacheKey = ip;
  const cached = enrichmentCache.get(cacheKey);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return { abuseipdb: cached.abuseipdb, virustotal: cached.virustotal };
  }

  const abuseipdb = await fetchAbuseIPDB(ip);
  await sleep(VIRUSTOTAL_DELAY_MS);
  const virustotal = await fetchVirusTotal(ip);

  const entry: CacheEntry = {
    abuseipdb,
    virustotal,
    fetchedAt: Date.now(),
  };
  enrichmentCache.set(cacheKey, entry);

  return { abuseipdb, virustotal };
}

export async function enrichIPs(ips: string[]): Promise<Record<string, IPEnrichment>> {
  const unique = Array.from(new Set(ips)).filter((ip) => !isPrivateIP(ip)).slice(0, MAX_IPS_PER_BATCH);
  const result: Record<string, IPEnrichment> = {};

  for (const ip of unique) {
    result[ip] = await enrichIP(ip);
    await sleep(500); // Small delay between IPs to avoid rate limits
  }

  return result;
}

// --- BGPView API (free, no API key) ---
// Fallback: ip-api.com when BGPView is unreachable (e.g. DNS NXDOMAIN)

export interface BGPViewPrefix {
  prefix: string;
  cidr?: number;
  asn?: { asn: number; name?: string; description?: string; country_code?: string };
  name?: string;
  description?: string;
  country_code?: string;
}

export interface BGPViewResult {
  ip: string;
  ptr_record?: string | null;
  prefixes?: BGPViewPrefix[];
  rir_allocation?: {
    rir_name?: string;
    country_code?: string;
    prefix?: string;
    date_allocated?: string;
    allocation_status?: string;
  } | null;
  maxmind?: { country_code?: string; city?: string | null } | null;
}

const BGPVIEW_DELAY_MS = 300;
const bgpViewCache = new Map<string, { data: BGPViewResult | null; fetchedAt: number }>();

/** ip-api.com fallback when BGPView is unreachable. Free, no key, 45 req/min. */
async function fetchIPApiFallback(ip: string): Promise<BGPViewResult | null> {
  try {
    const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,city,isp,org,as,asname,query`;
    const res = await fetch(url, { method: "GET", headers: { Accept: "application/json" } });
    if (!res.ok) return null;
    const d = (await res.json()) as { status?: string; as?: string; asname?: string; org?: string; countryCode?: string; city?: string; query?: string };
    if (d.status !== "success") return null;
    const asMatch = (d.as ?? "").match(/^AS(\d+)\s*(.*)$/);
    const asn = asMatch ? parseInt(asMatch[1], 10) : 0;
    const asName = (asMatch?.[2] ?? d.org ?? d.asname ?? "").trim() || undefined;
    return {
      ip: d.query ?? ip,
      prefixes: asn > 0
        ? [{ prefix: "", asn: { asn, name: asName, country_code: d.countryCode } }]
        : [],
      rir_allocation: d.countryCode ? { country_code: d.countryCode } : null,
      maxmind: d.countryCode || d.city ? { country_code: d.countryCode ?? undefined, city: d.city ?? null } : null,
    };
  } catch (err) {
    log.error({ err, ip }, "ip-api fallback error");
    return null;
  }
}

const BGPVIEW_TIMEOUT_MS = 10000;

export async function fetchBGPView(ip: string): Promise<BGPViewResult | null> {
  if (isPrivateIP(ip)) return null;

  const cached = bgpViewCache.get(ip);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return cached.data;
  }

  let result: BGPViewResult | null = null;

  const doFetch = async (): Promise<BGPViewResult | null> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), BGPVIEW_TIMEOUT_MS);
    try {
      const res = await fetch(`https://api.bgpview.io/ip/${encodeURIComponent(ip)}`, {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (res.ok) {
        const json = (await res.json()) as { data?: Record<string, unknown> };
        const d = json.data;
        if (d) {
          const prefixes = (d.prefixes as BGPViewPrefix[] | undefined) ?? [];
          const rir = d.rir_allocation as BGPViewResult["rir_allocation"];
          const maxmind = d.maxmind as BGPViewResult["maxmind"];
          return {
            ip: String(d.ip ?? ip),
            ptr_record: (d.ptr_record as string | null) ?? null,
            prefixes: prefixes.map((p) => ({
              prefix: String(p.prefix ?? ""),
              cidr: typeof p.cidr === "number" ? p.cidr : undefined,
              asn: p.asn
                ? {
                    asn: Number(p.asn.asn ?? 0),
                    name: p.asn.name as string | undefined,
                    description: p.asn.description as string | undefined,
                    country_code: p.asn.country_code as string | undefined,
                  }
                : undefined,
              name: p.name as string | undefined,
              description: p.description as string | undefined,
              country_code: p.country_code as string | undefined,
            })),
            rir_allocation: rir ?? null,
            maxmind: maxmind ?? null,
          };
        }
      } else if (res.status === 429) {
        log.warn({ ip }, "BGPView rate limit hit");
      }
      return null;
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  };

  try {
    result = await doFetch();
  } catch (err) {
    try {
      result = await doFetch();
    } catch (retryErr) {
      log.warn({ err, ip }, "BGPView unreachable, trying ip-api fallback");
    }
  }

  if (!result) {
    result = await fetchIPApiFallback(ip);
  }

  bgpViewCache.set(ip, { data: result, fetchedAt: Date.now() });
  return result;
}

export async function fetchBGPViewForIPs(ips: string[]): Promise<Record<string, BGPViewResult | null>> {
  const unique = Array.from(new Set(ips)).filter((ip) => !isPrivateIP(ip));
  const result: Record<string, BGPViewResult | null> = {};

  for (const ip of unique) {
    result[ip] = await fetchBGPView(ip);
    await sleep(BGPVIEW_DELAY_MS);
  }

  return result;
}

export function getIntegrationsStatus(): {
  abuseipdb: { configured: boolean };
  virustotal: { configured: boolean };
  tavily: { configured: boolean };
  ollama: { configured: boolean; model: string; enabled: boolean };
} {
  const ollama = getOllamaConfig();
  return {
    abuseipdb: { configured: !!getApiKey("abuseipdb") },
    virustotal: { configured: !!getApiKey("virustotal") },
    tavily: { configured: !!getApiKey("tavily") },
    ollama: { configured: true, model: ollama.model, enabled: ollama.enabled },
  };
}
