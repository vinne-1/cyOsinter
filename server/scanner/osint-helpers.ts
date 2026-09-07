import whoisPkg from "whois";
import { createLogger } from "../logger.js";
import { fetchJSON } from "./http.js";
import { runWithConcurrency } from "./utils.js";

// Credential detection and redaction live in their own module now; the old
// inline heuristic matched every UUID and every high-entropy token on a page.
// Re-exported here so existing importers and the scanner barrel keep working.
export {
  shannonEntropy,
  hasCredentialPattern,
  findCredentialIndicators,
  redactCredentialValues,
  maskValue,
  isPlaceholderValue,
  isBenignHighEntropy,
  STRONG_KEY_PATTERNS,
} from "./credential-detection.js";
export type { CredentialIndicator } from "./credential-detection.js";
import { shannonEntropy } from "./credential-detection.js";

const log = createLogger("scanner");
const whoisLookup = (whoisPkg as any)?.lookup ?? (whoisPkg as any)?.default?.lookup ?? (() => {});

export function extractEmailsFromText(text: string, domain: string): string[] {
  const emails = new Set<string>();
  const mailtoRegex = /mailto:([^"'\s>]+)/gi;
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  let m: RegExpExecArray | null;
  while ((m = mailtoRegex.exec(text)) !== null) {
    const addr = m[1].trim().toLowerCase();
    if (addr.includes("@")) emails.add(addr);
  }
  while ((m = emailRegex.exec(text)) !== null) {
    emails.add(m[0].toLowerCase());
  }
  const domainLower = domain.toLowerCase();
  const domainParts = domainLower.split(".");
  const baseDomain = domainParts.length >= 2 ? domainParts.slice(-2).join(".") : domainLower;
  return Array.from(emails).filter((e) => {
    const atDomain = e.split("@")[1] || "";
    return atDomain === domainLower || atDomain.endsWith(`.${domainLower}`) || atDomain === baseDomain || atDomain.endsWith(`.${baseDomain}`);
  });
}

export function generateBackupFilePaths(domain: string, gold: boolean): string[] {
  const domainNoTLD = domain.split(".")[0];
  const bases = [domain, domainNoTLD, "backup", "db", "dump", "data", "site", "www", "archive", "export"];
  const exts = [".sql", ".sql.gz", ".zip", ".tar.gz", ".tar", ".bak", ".old", ".dump", ".rar", ".7z"];
  const paths: string[] = [];
  for (const base of bases) {
    for (const ext of exts) {
      paths.push(`/${base}${ext}`);
    }
  }
  if (gold) {
    const prefixes = ["/backup/", "/backups/", "/data/", "/dump/"];
    for (const prefix of prefixes) {
      for (const base of [domain, domainNoTLD, "backup", "db"]) {
        for (const ext of exts) {
          paths.push(`${prefix}${base}${ext}`);
        }
      }
    }
  }
  return paths;
}

export function extractSensitiveRobotsPaths(robotsTxt: string): string[] {
  const sensitivePattern = /admin|backup|internal|private|secret|config|database|data|dump|export|log|report|archive|temp|upload|hidden|restricted|confidential/i;
  const paths: string[] = [];
  for (const line of robotsTxt.split("\n")) {
    const trimmed = line.trim().toLowerCase();
    if (!trimmed.startsWith("disallow:")) continue;
    const path = line.split(":").slice(1).join(":").trim();
    if (path && path !== "/" && path !== "" && sensitivePattern.test(path)) {
      paths.push(path.startsWith("/") ? path : `/${path}`);
    }
  }
  return Array.from(new Set(paths));
}

export function extractEmailsFromWhois(domainInfo: Record<string, string> | null): string[] {
  if (!domainInfo) return [];
  const emails: string[] = [];
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  for (const [key, value] of Object.entries(domainInfo)) {
    if (/email|contact|abuse/i.test(key) && typeof value === "string") {
      const matches = value.match(emailRegex);
      if (matches) emails.push(...matches.map(e => e.toLowerCase()));
    }
  }
  return Array.from(new Set(emails));
}

export async function checkHIBPPasswords(values: string[], gold: boolean): Promise<Array<{ redacted: string; breachCount: number }>> {
  const { createHash } = await import("node:crypto");
  const results: Array<{ redacted: string; breachCount: number }> = [];
  const limit = gold ? 20 : 5;
  const delay = gold ? 200 : 500;
  for (const val of values.slice(0, limit)) {
    try {
      const sha1 = createHash("sha1").update(val).digest("hex").toUpperCase();
      const prefix = sha1.slice(0, 5);
      const suffix = sha1.slice(5);
      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { "User-Agent": "CyShield-Scanner/1.0", "Add-Padding": "true" },
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) continue;
      const text = await res.text();
      for (const line of text.split("\n")) {
        const [hashSuffix, count] = line.trim().split(":");
        if (hashSuffix === suffix && parseInt(count, 10) > 0) {
          const redacted = val.length > 4 ? `${val.slice(0, 2)}${"*".repeat(Math.min(val.length - 2, 8))}` : "****";
          results.push({ redacted, breachCount: parseInt(count, 10) });
          break;
        }
      }
      await new Promise(r => setTimeout(r, delay));
    } catch (err) {
      log.warn({ err }, "HIBP check failed for a value");
    }
  }
  return results;
}

export async function checkS3Buckets(domain: string, gold: boolean): Promise<Array<{ bucket: string; listable: boolean }>> {
  const domainNoTLD = domain.split(".")[0];
  const baseBuckets = [domain, domainNoTLD, `${domainNoTLD}-backup`, `${domainNoTLD}-uploads`, `${domainNoTLD}-data`, `${domainNoTLD}-assets`];
  const extraBuckets = [`${domainNoTLD}-public`, `${domainNoTLD}-static`, `${domainNoTLD}-media`, `${domainNoTLD}-files`, `${domainNoTLD}-dev`, `${domainNoTLD}-staging`, `${domainNoTLD}-prod`];
  const buckets = gold ? [...baseBuckets, ...extraBuckets] : baseBuckets;
  const found: Array<{ bucket: string; listable: boolean }> = [];
  const s3Results = await runWithConcurrency(buckets, 4, async (bucket) => {
    try {
      const res = await fetch(`https://${bucket}.s3.amazonaws.com/`, {
        method: "GET",
        signal: AbortSignal.timeout(8000),
        redirect: "follow",
      });
      if (res.status === 200) {
        const body = await res.text();
        return { bucket, listable: body.includes("<ListBucketResult") };
      }
      return null;
    } catch {
      return null;
    }
  });
  for (const r of s3Results) {
    if (r) found.push(r);
  }
  return found;
}

export async function searchPGPKeyServer(domain: string): Promise<string[]> {
  try {
    const res = await fetch(`https://keys.openpgp.org/pks/lookup?op=index&search=${encodeURIComponent(domain)}&options=mr`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return [];
    const text = await res.text();
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const matches = text.match(emailRegex);
    return matches ? Array.from(new Set(matches.map(e => e.toLowerCase()))) : [];
  } catch (err) {
    log.warn({ err }, "PGP key server search failed");
    return [];
  }
}

export async function extractEmailsFromCrtSh(domain: string): Promise<string[]> {
  try {
    const data = await fetchJSON(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, 15000);
    if (!Array.isArray(data)) return [];
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const emails = new Set<string>();
    for (const entry of data) {
      const nameValue = String(entry.name_value ?? "");
      const matches = nameValue.match(emailRegex);
      if (matches) for (const m of matches) emails.add(m.toLowerCase());
    }
    return Array.from(emails);
  } catch (err) {
    log.warn({ err }, "crt.sh email extraction failed");
    return [];
  }
}

export async function getServerLocation(ip: string): Promise<{ country?: string; region?: string; city?: string; org?: string; lat?: number; lon?: number } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(`https://ipapi.co/${ip}/json/`, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (data.country_name === undefined && data.region === undefined) return null;
    return {
      country: data.country_name,
      region: data.region,
      city: data.city,
      org: data.org,
      lat: data.latitude,
      lon: data.longitude,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function whoisLookupAsync(domain: string): Promise<string> {
  return new Promise((resolve, reject) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (whoisLookup as any)(domain, { timeout: 10000 }, (err: Error | null, data: string) => {
      if (err) reject(err);
      else resolve(data);
    });
  });
}

export function parseWhois(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  const lines = raw.split("\n").map(l => l.trim());
  for (const line of lines) {
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const key = line.slice(0, colon).trim().replace(/\s+/g, " ");
    const value = line.slice(colon + 1).trim();
    if (key && value && !out[key]) out[key] = value;
  }
  return out;
}

export async function getWhois(domain: string): Promise<Record<string, string> | null> {
  try {
    const raw = await whoisLookupAsync(domain);
    return parseWhois(raw);
  } catch {
    return null;
  }
}
