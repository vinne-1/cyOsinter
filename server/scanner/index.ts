import { spawn } from "child_process";
import dns from "dns/promises";
import fs from "fs/promises";
import net from "net";
import os from "os";
import path from "path";
import tls from "tls";
import whoisPkg from "whois";
import { computeSurfaceRiskScore, gradeToRisk } from "../scoring.js";
import { enrichIP, fetchBGPView } from "../api-integrations.js";
import { checkCISAKEV } from "../cve-service.js";
// Types are defined inline in this file; canonical types also in ./types.ts for external consumers
const whoisLookup = (whoisPkg as any)?.lookup ?? (whoisPkg as any)?.default?.lookup ?? (() => {});

const SUBDOMAIN_WORDLIST_SOURCE = "SecLists/Discovery/DNS/subdomains-top1million-5000.txt";
const DIRECTORY_WORDLIST_SOURCE = "SecLists/Discovery/Web-Content/common.txt";

const STANDARD_SUBDOMAIN_WORDLIST_CAP = 2000;
const STANDARD_PROBE_BATCH = 150;
const STANDARD_NUCLEI_DOMAINS = 50;
const STANDARD_DIRECTORY_CAP = 1000;
const STANDARD_SITEMAP_LIMIT = 500;
const STANDARD_SUBDOMAIN_CERT_CHECK = 3;

const GOLD_SUBDOMAIN_WORDLIST_CAP = 0; // 0 = no cap (use full wordlist)
const GOLD_PROBE_BATCH = 0;
const GOLD_NUCLEI_DOMAINS = 0;
const GOLD_DIRECTORY_CAP = 0;
const GOLD_SITEMAP_LIMIT = 5000;
const GOLD_SUBDOMAIN_CERT_CHECK = 0;

const STANDARD_PORTS = [
  // Core web & infra
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
  // Remote access & file transfer
  3389, 5900,
  // Databases
  1433, 1521, 3306, 5432, 5984, 6379, 9042, 27017, 28017,
  // Web alternates
  8000, 8008, 8080, 8088, 8443, 8888, 9090,
  // Cloud / container / orchestration
  2375, 2376, 4243, 6443, 10250,
  // Services
  389, 636, 3000, 4444, 4848, 5000, 5601, 6000, 7000, 7077, 8161, 8172, 8983, 9000, 9200, 9300, 9418, 11211, 15672, 50070,
];
const GOLD_PORTS = [
  // All standard ports
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
  3389, 5900, 1433, 1521, 3306, 5432, 5984, 6379, 9042, 27017, 28017,
  8000, 8008, 8080, 8088, 8443, 8888, 9090,
  2375, 2376, 4243, 6443, 10250,
  389, 636, 3000, 4444, 4848, 5000, 5601, 6000, 7000, 7077, 8161, 8172, 8983, 9000, 9200, 9300, 9418, 11211, 15672, 50070,
  // Additional gold-tier ports
  20, 69, 79, 102, 111, 119, 135, 137, 138, 139, 161, 162, 177, 194,
  220, 264, 318, 381, 383, 411, 412, 427, 444, 500, 512, 513, 514, 515,
  520, 554, 563, 593, 631, 666, 749, 750, 829, 873, 902, 989, 990,
  1080, 1194, 1214, 1241, 1311, 1434, 1494, 1512, 1524, 1533, 1589,
  1701, 1723, 1755, 1812, 1813, 1863, 2049, 2082, 2083, 2086, 2087,
  2095, 2096, 2181, 2222, 3128, 3268, 3269, 3478, 3690, 4000, 4001,
  4045, 4190, 4333, 4500, 4567, 4899, 4949, 5353, 5432, 5555, 5800,
  6514, 6665, 6666, 6667, 6668, 6669, 7070, 7474, 7676, 7777, 8009,
  8069, 8100, 8180, 8400, 8500, 8880, 9001, 9080, 9090, 9100, 9160,
  9999, 10000, 10443, 11000, 16010, 20000, 27015, 28015, 50000,
];

const FALLBACK_SUBDOMAINS = "www mail ftp smtp api dev admin staging test portal cpanel webmail ns1 ns2 mx git blog shop app cdn cloud support help docs static media img assets upload files backup db mysql admin panel login secure vpn mail2 ns".split(" ");
const FALLBACK_DIRECTORIES = "/admin /api /.git /.env /robots.txt /.well-known/security.txt /sitemap.xml /wp-login.php /server-status /backup /.htaccess /config /login /dashboard /phpmyadmin /swagger.json /.aws /debug".split(" ");

const OSINT_CREDENTIAL_PATHS = [
  // Original paths
  "/config.php", "/wp-config.php", "/configuration.php", "/credentials.json", "/secrets.json",
  "/config.json", "/passwords.txt", "/passwords.csv", "/.aws/credentials", "/id_rsa", "/id_rsa.pub",
  "/.env.local", "/.env.production",
  // Env variants
  "/.env.backup", "/.env.bak", "/.env.old", "/.env.dev", "/.env.staging", "/.env.example",
  // Package manager configs
  "/.npmrc", "/.yarnrc",
  // Docker/CI
  "/.docker/config.json", "/.travis.yml", "/.circleci/config.yml", "/Jenkinsfile",
  // Python
  "/settings.py", "/local_settings.py",
  // PHP
  "/wp-config.php.bak", "/wp-config.php~", "/config.php.bak",
  // Database configs
  "/.htpasswd", "/.pgpass", "/my.cnf", "/.my.cnf",
  // YAML configs
  "/database.yml", "/secrets.yml", "/connection.yml",
  // .NET / Java / XML
  "/appsettings.json", "/web.config", "/applicationContext.xml",
  // SSH/Auth
  "/.ssh/authorized_keys", "/.netrc", "/.git-credentials", "/.bash_history",
  // Deployment
  "/sftp-config.json", "/filezilla.xml",
];
const OSINT_DOCUMENT_PATHS = [
  // Original paths
  "/documents", "/docs", "/files", "/downloads", "/uploads", "/backup", "/backups",
  "/report.pdf", "/data.xlsx", "/contacts.csv",
  // Backup files
  "/backup.sql", "/backup.zip", "/backup.tar.gz", "/db.sql", "/database.sql",
  "/dump.sql", "/data.sql", "/site.zip", "/www.zip",
  // Log files
  "/debug.log", "/error.log", "/access.log", "/wp-content/debug.log",
  "/logs/error.log", "/logs/access.log", "/storage/logs/laravel.log",
  // Admin panels
  "/phpMyAdmin", "/adminer.php", "/phpmyadmin/index.php",
  // Data directories
  "/db", "/sql", "/data", "/export", "/reports", "/archive",
  "/temp", "/tmp", "/cache", "/private", "/internal",
  // CMS specific
  "/wp-content/uploads", "/sites/default/files", "/media", "/static/admin",
  // Presentations/Spreadsheets
  "/spreadsheet", "/presentations",
];
const OSINT_INFRA_PATHS = "/phpinfo.php /info.php /server-status /api-docs /openapi.json /debug /trace /actuator /actuator/health /admin/login /wp-admin /administrator /manager /console /config.yml /docker-compose.yml /.dockerignore /kubernetes /health /metrics /graphql /api/v1 /api/v2 /swagger-ui /redoc /.terraform /terraform.tfstate".split(" ");
const CREDENTIAL_PATTERN = /(?:password|passwd|api_key|apikey|secret|token|auth_token|db_pass|database_url|private_key)\s*[=:]\s*["']?[^\s"']+["']?/gi;
const DOCUMENT_EXTENSIONS = /\.(pdf|doc|docx|xlsx|xls|csv|sql|zip|tar|tar\.gz|bak|old|log|dump)$/i;

const SOFT_404_PATTERNS = /not found|404|page does not exist|file not found|does not exist/i;
const FORBIDDEN_PATTERNS = /403|forbidden|access denied|permission denied/i;
const UNAUTHORIZED_PATTERNS = /401|unauthorized|login|sign in|authentication/i;
const LOGIN_PATH_PATTERNS = /\/login|\/auth|\/signin|\/wp-login/i;
const SERVER_ERROR_PATTERNS = /500|server error|internal error|service unavailable/i;
const NOT_FOUND_PATTERNS = /404|not found|file not found|page not found/i;

export function classifyPathResponse(status: number): { responseType: string; severity: string } {
  if (status === 404) return { responseType: "not_found", severity: "info" };
  if (status === 403) return { responseType: "forbidden", severity: "medium" };
  if (status === 401) return { responseType: "unauthorized", severity: "low" };
  if (status >= 200 && status < 300) return { responseType: "success", severity: "low" };
  if ([301, 302, 307, 308].includes(status)) return { responseType: "redirect", severity: "low" };
  if (status >= 500) return { responseType: "server_error", severity: "low" };
  return { responseType: "other", severity: "info" };
}

function validatePathResponse(
  status: number,
  body: string,
  finalUrl: string,
  requestedPath: string,
): { responseType: string; severity: string; validated: boolean; confidence: "high" | "medium" | "low"; redirectTarget?: string } {
  const bodyLower = (body || "").toLowerCase();
  let finalPath = "";
  try {
    finalPath = new URL(finalUrl).pathname;
  } catch {
    finalPath = finalUrl;
  }

  if (status === 404) {
    const validated = NOT_FOUND_PATTERNS.test(bodyLower);
    return { responseType: "not_found", severity: "info", validated, confidence: validated ? "high" : "medium" };
  }

  if (status === 403) {
    const validated = FORBIDDEN_PATTERNS.test(bodyLower);
    return { responseType: "forbidden", severity: "medium", validated, confidence: validated ? "high" : "medium" };
  }

  if (status === 401) {
    const bodyMatch = UNAUTHORIZED_PATTERNS.test(bodyLower);
    const urlMatch = LOGIN_PATH_PATTERNS.test(finalPath);
    const validated = bodyMatch || urlMatch;
    return { responseType: "unauthorized", severity: "low", validated, confidence: validated ? "high" : "medium", redirectTarget: urlMatch ? finalPath : undefined };
  }

  if (status >= 200 && status < 300) {
    if (SOFT_404_PATTERNS.test(bodyLower)) {
      return { responseType: "soft_404", severity: "info", validated: true, confidence: "high" };
    }
    if (requestedPath !== finalPath && LOGIN_PATH_PATTERNS.test(finalPath)) {
      return { responseType: "redirect_to_login", severity: "low", validated: true, confidence: "high", redirectTarget: finalPath };
    }
    return { responseType: "success", severity: "low", validated: true, confidence: "high" };
  }

  if ([301, 302, 307, 308].includes(status)) {
    const isLoginRedirect = LOGIN_PATH_PATTERNS.test(finalPath);
    return {
      responseType: isLoginRedirect ? "redirect_to_login" : "redirect",
      severity: "low",
      validated: true,
      confidence: "high",
      redirectTarget: isLoginRedirect ? finalPath : undefined,
    };
  }

  if (status >= 500) {
    const validated = SERVER_ERROR_PATTERNS.test(bodyLower);
    return { responseType: "server_error", severity: "low", validated, confidence: validated ? "high" : "medium" };
  }

  return { responseType: "other", severity: "info", validated: false, confidence: "low" };
}

let cachedSubdomainWordlist: string[] | null = null;
let cachedDirectoryWordlist: string[] | null = null;

let fullSubdomainWordlist: string[] | null = null;

async function loadSubdomainWordlist(cap = STANDARD_SUBDOMAIN_WORDLIST_CAP): Promise<string[]> {
  if (!fullSubdomainWordlist) {
    try {
      const p = path.join(path.dirname(__dirname), "server", "wordlists", "subdomains.txt");
      const content = await fs.readFile(p, "utf-8");
      fullSubdomainWordlist = Array.from(new Set(content.split(/\r?\n/).map((l) => l.trim().toLowerCase()).filter((l) => l && !l.startsWith("#"))));
    } catch {
      try {
        const p = path.join(__dirname, "wordlists", "subdomains.txt");
        const content = await fs.readFile(p, "utf-8");
        fullSubdomainWordlist = Array.from(new Set(content.split(/\r?\n/).map((l) => l.trim().toLowerCase()).filter((l) => l && !l.startsWith("#"))));
      } catch {
        fullSubdomainWordlist = FALLBACK_SUBDOMAINS;
      }
    }
  }
  if (cap <= 0) return fullSubdomainWordlist;
  cachedSubdomainWordlist = fullSubdomainWordlist.slice(0, cap);
  return cachedSubdomainWordlist;
}

let fullDirectoryWordlist: string[] | null = null;

async function loadDirectoryWordlist(cap = STANDARD_DIRECTORY_CAP): Promise<string[]> {
  if (!fullDirectoryWordlist) {
    try {
      const p = path.join(path.dirname(__dirname), "server", "wordlists", "directories.txt");
      const content = await fs.readFile(p, "utf-8");
      const lines = content.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
      fullDirectoryWordlist = Array.from(new Set(lines.map((l) => (l.startsWith("/") ? l : `/${l}`))));
    } catch {
      try {
        const p = path.join(__dirname, "wordlists", "directories.txt");
        const content = await fs.readFile(p, "utf-8");
        const lines = content.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
        fullDirectoryWordlist = Array.from(new Set(lines.map((l) => (l.startsWith("/") ? l : `/${l}`))));
      } catch {
        fullDirectoryWordlist = FALLBACK_DIRECTORIES;
      }
    }
  }
  if (cap <= 0) return fullDirectoryWordlist;
  cachedDirectoryWordlist = fullDirectoryWordlist.slice(0, cap);
  return cachedDirectoryWordlist;
}

async function runWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<R>,
  signal?: AbortSignal,
): Promise<R[]> {
  const results: R[] = [];
  let i = 0;
  async function worker(): Promise<void> {
    while (i < items.length) {
      if (signal?.aborted) throw new Error("Scan aborted");
      const idx = i++;
      const item = items[idx];
      try {
        results[idx] = await fn(item);
      } catch (err) {
        if (err instanceof Error && err.message === "Scan aborted") throw err;
        results[idx] = undefined as any;
      }
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

async function checkDNSWildcard(domain: string): Promise<{ isWildcard: boolean; wildcardIPs: Set<string> }> {
  const random = Math.random().toString(36).slice(2, 12);
  const testHost = `nxdomain-${random}.${domain}`;
  try {
    const ips = await dns.resolve4(testHost);
    if (ips.length > 0) {
      return { isWildcard: true, wildcardIPs: new Set(ips) };
    }
  } catch {
    // NXDOMAIN or DNS error = no wildcard
  }
  return { isWildcard: false, wildcardIPs: new Set() };
}

async function enumerateSubdomainsBruteforce(
  domain: string,
  cap = 1000,
  concurrency = 20,
  signal?: AbortSignal,
  excludeIPs?: Set<string>,
): Promise<{ resolved: string[]; tried: number; wildcardDetected: boolean }> {
  const { isWildcard, wildcardIPs } = excludeIPs
    ? { isWildcard: excludeIPs.size > 0, wildcardIPs: excludeIPs }
    : await checkDNSWildcard(domain);

  if (isWildcard) {
    console.log(`[Scanner] Wildcard DNS detected for ${domain} (IPs: ${Array.from(wildcardIPs).join(", ")}) — filtering false positives`);
  }

  const prefixes = await loadSubdomainWordlist();
  const toTry = prefixes.slice(0, cap).map((prefix) => `${prefix}.${domain}`);
  const resolved: string[] = [];
  const results = await runWithConcurrency(
    toTry,
    concurrency,
    async (hostname) => {
      const d = await resolveDNS(hostname);
      if (d.ips.length === 0 && d.cnames.length === 0) return null;
      // Skip if all resolved IPs match the wildcard (false positive)
      if (isWildcard && d.ips.length > 0 && d.ips.every((ip) => wildcardIPs.has(ip))) return null;
      return hostname;
    },
    signal,
  );
  for (const r of results) {
    if (r) resolved.push(r);
  }
  return { resolved: Array.from(new Set(resolved)).sort(), tried: toTry.length, wildcardDetected: isWildcard };
}

interface EvidenceItem {
  [key: string]: unknown;
  type: string;
  description: string;
  url?: string;
  snippet?: string;
  source?: string;
  verifiedAt?: string;
  raw?: Record<string, unknown>;
}

interface VerifiedFinding {
  title: string;
  description: string;
  severity: string;
  category: string;
  affectedAsset: string;
  cvssScore: string;
  remediation: string;
  evidence: EvidenceItem[];
}

interface ScanResults {
  subdomains: string[];
  assets: Array<{ type: string; value: string; tags: string[] }>;
  findings: VerifiedFinding[];
  reconData: Record<string, Record<string, unknown>>;
}

export type ScanProgressCallback = (msg: string, percent: number, step: string, etaSeconds?: number) => Promise<void>;

export interface ScanOptions {
  signal?: AbortSignal;
  mode?: "standard" | "gold";
}

function isGold(options?: ScanOptions): boolean {
  return options?.mode === "gold";
}

function checkAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new Error("Scan aborted");
}

async function fetchJSON(url: string, timeoutMs = 10000): Promise<any> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function fetchText(url: string, timeoutMs = 10000): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
      redirect: "follow",
    });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function httpHead(url: string, timeoutMs = 8000): Promise<{ status: number; headers: Record<string, string>; redirectUrl?: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "HEAD",
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
      redirect: "follow",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    return { status: res.status, headers, redirectUrl: res.url !== url ? res.url : undefined };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function httpGet(url: string, timeoutMs = 8000): Promise<{ status: number; headers: Record<string, string>; body: string; finalUrl: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
      redirect: "follow",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const body = await res.text();
    return { status: res.status, headers, body: body.substring(0, 5000), finalUrl: res.url };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function getCertificateInfo(hostname: string, port = 443): Promise<{
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  serialNumber: string;
  altNames: string[];
  protocol: string;
} | null> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => { resolve(null); }, 8000);
    try {
      const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false }, () => {
        try {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() || "unknown";
          if (!cert || !cert.valid_from) {
            socket.destroy();
            clearTimeout(timer);
            resolve(null);
            return;
          }
          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const daysRemaining = Math.floor((validTo.getTime() - now.getTime()) / 86400000);
          const altNames = cert.subjectaltname
            ? cert.subjectaltname.split(", ").map((s: string) => s.replace("DNS:", ""))
            : [];
          socket.destroy();
          clearTimeout(timer);
          resolve({
            subject: typeof cert.subject === "object" ? (cert.subject as any).CN || JSON.stringify(cert.subject) : String(cert.subject),
            issuer: typeof cert.issuer === "object" ? ((cert.issuer as any).O || (cert.issuer as any).CN || JSON.stringify(cert.issuer)) : String(cert.issuer),
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysRemaining,
            serialNumber: cert.serialNumber || "",
            altNames,
            protocol,
          });
        } catch {
          socket.destroy();
          clearTimeout(timer);
          resolve(null);
        }
      });
      socket.on("error", () => { clearTimeout(timer); resolve(null); });
    } catch {
      clearTimeout(timer);
      resolve(null);
    }
  });
}

async function enumerateSubdomainsCrtSh(domain: string): Promise<string[]> {
  const data = await fetchJSON(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, 15000);
  if (!data || !Array.isArray(data)) return [];
  const subdomains = new Set<string>();
  for (const entry of data) {
    const name = entry.name_value || entry.common_name || "";
    const names = name.split("\n");
    for (const n of names) {
      const cleaned = n.trim().toLowerCase().replace(/^\*\./, "");
      if (cleaned.endsWith(`.${domain}`) || cleaned === domain) {
        if (!cleaned.includes("*") && !cleaned.includes(" ")) {
          subdomains.add(cleaned);
        }
      }
    }
  }
  return Array.from(subdomains).sort();
}

async function resolveDNS(hostname: string): Promise<{ ips: string[]; cnames: string[] }> {
  const result = { ips: [] as string[], cnames: [] as string[] };
  try {
    const addresses = await dns.resolve4(hostname);
    result.ips = addresses;
  } catch (e) {
    console.warn(`[Scanner] DNS lookup failed for ${hostname}:`, e instanceof Error ? e.message : e);
  }
  try {
    const cnames = await dns.resolveCname(hostname);
    result.cnames = cnames;
  } catch (e) {
    console.warn(`[Scanner] DNS lookup failed for ${hostname}:`, e instanceof Error ? e.message : e);
  }
  return result;
}

async function getDNSTxtRecords(domain: string): Promise<string[][]> {
  try {
    return await dns.resolveTxt(domain);
  } catch (e) {
    console.warn(`[Scanner] DNS lookup failed for ${domain}:`, e instanceof Error ? e.message : e);
    return [];
  }
}

async function getMXRecords(domain: string): Promise<Array<{ priority: number; exchange: string }>> {
  try {
    return await dns.resolveMx(domain);
  } catch (e) {
    console.warn(`[Scanner] DNS lookup failed for ${domain}:`, e instanceof Error ? e.message : e);
    return [];
  }
}

async function getNSRecords(domain: string): Promise<string[]> {
  try {
    return await dns.resolveNs(domain);
  } catch (e) {
    console.warn(`[Scanner] DNS lookup failed for ${domain}:`, e instanceof Error ? e.message : e);
    return [];
  }
}

async function getFullDNSRecords(domain: string): Promise<{
  a: string[];
  aaaa: string[];
  cname: string[];
  soa: { nsname: string; hostmaster: string; serial: number; refresh: number; retry: number; expire: number; minttl: number } | null;
  txt: string[][];
  mx: Array<{ priority: number; exchange: string }>;
  ns: string[];
  caa: Array<{ tag: string; value: string }>;
}> {
  const out = { a: [] as string[], aaaa: [] as string[], cname: [] as string[], soa: null as any, txt: [] as string[][], mx: [] as Array<{ priority: number; exchange: string }>, ns: [] as string[], caa: [] as Array<{ tag: string; value: string }> };
  try { out.a = await dns.resolve4(domain); } catch (e) { console.warn(`[Scanner] DNS lookup failed for ${domain}:`, e instanceof Error ? e.message : e); }
  try { out.aaaa = await dns.resolve6(domain); } catch (e) { console.warn(`[Scanner] DNS lookup failed for ${domain}:`, e instanceof Error ? e.message : e); }
  try { out.cname = await dns.resolveCname(domain); } catch (e) { console.warn(`[Scanner] DNS lookup failed for ${domain}:`, e instanceof Error ? e.message : e); }
  try { out.soa = await dns.resolveSoa(domain); } catch (e) { console.warn(`[Scanner] DNS lookup failed for ${domain}:`, e instanceof Error ? e.message : e); }
  try { out.txt = await dns.resolveTxt(domain); } catch (e) { console.warn(`[Scanner] DNS lookup failed for ${domain}:`, e instanceof Error ? e.message : e); }
  try { out.mx = await dns.resolveMx(domain); } catch (e) { console.warn(`[Scanner] DNS lookup failed for ${domain}:`, e instanceof Error ? e.message : e); }
  try { out.ns = await dns.resolveNs(domain); } catch (e) { console.warn(`[Scanner] DNS lookup failed for ${domain}:`, e instanceof Error ? e.message : e); }
  try {
    const resolveCaa = (dns as any).resolveCaa;
    if (typeof resolveCaa === "function") {
      const caa = await resolveCaa(domain);
      if (Array.isArray(caa)) out.caa = caa.map((r: { tag: string; value: string }) => ({ tag: r.tag, value: r.value }));
    }
  } catch (e) {
    console.warn(`[Scanner] DNS lookup failed for ${domain}:`, e instanceof Error ? e.message : e);
  }
  return out;
}

async function httpGetNoRedirect(url: string, timeoutMs = 6000): Promise<{ status: number; headers: Record<string, string>; location?: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
      redirect: "manual",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const location = res.headers.get("location") ?? undefined;
    return { status: res.status, headers, location };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function getRedirectChain(initialUrl: string, maxHops = 10): Promise<Array<{ status: number; url: string; location?: string }>> {
  const chain: Array<{ status: number; url: string; location?: string }> = [];
  let url: string | undefined = initialUrl;
  const seen = new Set<string>();
  while (url && chain.length < maxHops) {
    const u = url.toLowerCase();
    if (seen.has(u)) break;
    seen.add(u);
    const res = await httpGetNoRedirect(url);
    if (!res) break;
    chain.push({ status: res.status, url, location: res.location });
    if (res.status >= 300 && res.status < 400 && res.location) {
      try {
        url = res.location.startsWith("http") ? res.location : new URL(res.location, url).href;
      } catch { break; }
    } else {
      break;
    }
  }
  return chain;
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

function parseWhois(raw: string): Record<string, string> {
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

async function getWhois(domain: string): Promise<Record<string, string> | null> {
  try {
    const raw = await whoisLookupAsync(domain);
    return parseWhois(raw);
  } catch {
    return null;
  }
}

async function getServerLocation(ip: string): Promise<{ country?: string; region?: string; city?: string; org?: string; lat?: number; lon?: number } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=country,regionName,city,org,lat,lon`, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (data.country === undefined && data.regionName === undefined) return null;
    return {
      country: data.country,
      region: data.regionName,
      city: data.city,
      org: data.org,
      lat: data.lat,
      lon: data.lon,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function httpGetMainPage(url: string, timeoutMs = 10000): Promise<{ status: number; body: string; headers: Record<string, string>; setCookieStrings: string[]; finalUrl: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
      redirect: "follow",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const setCookieStrings = typeof (res.headers as any).getSetCookie === "function" ? (res.headers as any).getSetCookie() : (headers["set-cookie"] ? [headers["set-cookie"]] : []);
    const body = await res.text();
    return { status: res.status, body: body.substring(0, 100000), headers, setCookieStrings, finalUrl: res.url };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function parseSetCookie(setCookieStrings: string[]): Array<{ name: string; secure?: boolean; httpOnly?: boolean; sameSite?: string; path?: string }> {
  const cookies: Array<{ name: string; secure?: boolean; httpOnly?: boolean; sameSite?: string; path?: string }> = [];
  for (const raw of setCookieStrings) {
    const parts = raw.split(";").map(p => p.trim());
    const nameValue = parts[0];
    const eq = nameValue.indexOf("=");
    const name = eq >= 0 ? nameValue.slice(0, eq).trim() : nameValue;
    const cookie: { name: string; secure?: boolean; httpOnly?: boolean; sameSite?: string; path?: string } = { name };
    for (let i = 1; i < parts.length; i++) {
      const p = parts[i].toLowerCase();
      if (p === "secure") cookie.secure = true;
      else if (p === "httponly") cookie.httpOnly = true;
      else if (p.startsWith("samesite=")) cookie.sameSite = p.slice(9).trim();
      else if (p.startsWith("path=")) cookie.path = p.slice(5).trim();
    }
    cookies.push(cookie);
  }
  return cookies;
}

function parseSecurityTxt(body: string): Record<string, string> {
  const out: Record<string, string> = {};
  const lines = body.split(/\r?\n/);
  for (const line of lines) {
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (key && value && ["contact", "expires", "canonical", "preferred-languages", "encryption", "acknowledgments", "policy", "hiring"].includes(key)) {
      out[key] = value;
    }
  }
  return out;
}

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

function redactCredentialValues(text: string): string {
  return text.replace(CREDENTIAL_PATTERN, (m) => m.replace(/[=:]\s*["']?[^\s"']+["']?/i, "=****REDACTED****"));
}

// Shannon entropy for detecting high-entropy strings (API keys, tokens)
export function shannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const c of str) freq[c] = (freq[c] ?? 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / len;
    return sum + p * Math.log2(p);
  }, 0);
}

// Known key format patterns
const KNOWN_KEY_PATTERNS = [
  /AKIA[0-9A-Z]{16}/,            // AWS Access Key ID
  /sk-[a-zA-Z0-9]{32,}/,          // OpenAI API Key
  /ghp_[a-zA-Z0-9]{36}/,          // GitHub Personal Access Token
  /ghs_[a-zA-Z0-9]{36}/,          // GitHub App Token
  /xox[baprs]-[0-9a-zA-Z\-]{16,}/, // Slack Tokens
  /AIza[0-9A-Za-z_\-]{35}/,       // Google API Key
  /[0-9a-f]{32}:[0-9a-f]{32}/,    // Stripe-style key pair
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/i, // Bearer tokens
  // -- New patterns --
  /SK[a-f0-9]{32}/,               // Twilio API Key
  /AC[a-f0-9]{32}/,               // Twilio Account SID
  /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/, // SendGrid API Key
  /key-[a-f0-9]{32}/,             // Mailgun API Key
  /sk_live_[a-zA-Z0-9]{24,}/,     // Stripe Secret Key
  /pk_live_[a-zA-Z0-9]{24,}/,     // Stripe Publishable Key
  /rk_live_[a-zA-Z0-9]{24,}/,     // Stripe Restricted Key
  /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/, // JWT Token
  /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/, // PEM Private Key
  /sq0[a-z]{3}-[a-zA-Z0-9_-]{22,}/, // Square API Key
  /EAACEdEose0cBA[a-zA-Z0-9]+/,   // Facebook Access Token
  /ya29\.[a-zA-Z0-9_-]{25,}/,     // Google OAuth Token
  /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i, // Heroku/Generic API Key (UUID format)
];

export function hasCredentialPattern(text: string): boolean {
  // Named-key pattern match
  if (/(?:password|passwd|api_key|apikey|secret|token|auth_token|db_pass|database_url|private_key)\s*[=:]\s*["']?[^\s"']+["']?/i.test(text)) return true;
  // Known key format patterns
  for (const pattern of KNOWN_KEY_PATTERNS) {
    if (pattern.test(text)) return true;
  }
  // High-entropy token detection (tokens >= 20 chars, entropy >= 4.5)
  const tokens = text.split(/[\s,;=:"'<>()\[\]{}\r\n]+/);
  for (const token of tokens) {
    if (token.length >= 20 && /[A-Za-z]/.test(token) && /[0-9]/.test(token) && shannonEntropy(token) >= 4.5) {
      return true;
    }
  }
  return false;
}

function parseSitemapUrls(body: string, limit = 500): string[] {
  const urls: string[] = [];
  const locRegex = /<loc>\s*([^<]+)\s*<\/loc>/gi;
  let m: RegExpExecArray | null;
  while ((m = locRegex.exec(body)) !== null && urls.length < limit) {
    urls.push(m[1].trim());
  }
  return urls;
}

async function fetchSitemapUrls(domain: string, limit = STANDARD_SITEMAP_LIMIT): Promise<string[]> {
  const base = `https://${domain}`;
  const sitemapPaths = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap1.xml", "/sitemap-index.xml"];
  let res = null;
  for (const p of sitemapPaths) {
    res = await httpGet(`${base}${p}`);
    if (res && res.status === 200 && res.body) break;
  }
  if (!res || res.status !== 200 || !res.body) return [];
  const body = res.body;
  if (/<sitemapindex/i.test(body)) {
    const sitemapLocs = parseSitemapUrls(body, 20);
    const all: string[] = [];
    for (const loc of sitemapLocs) {
      const sub = await httpGet(loc);
      if (sub && sub.status === 200 && sub.body) all.push(...parseSitemapUrls(sub.body, Math.min(limit, 500)));
      if (all.length >= limit) break;
    }
    return all.slice(0, limit);
  }
  return parseSitemapUrls(body, limit);
}

function checkDNSSEC(domain: string): Promise<{ soaPresent: boolean }> {
  return dns.resolveSoa(domain).then(() => ({ soaPresent: true })).catch(() => ({ soaPresent: false }));
}

function detectTechStack(html: string, headers: Record<string, string>): Array<{ name: string; source: string }> {
  const techs: Array<{ name: string; source: string }> = [];
  const seen = new Set<string>();
  const add = (name: string, source: string) => {
    const key = name.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      techs.push({ name, source });
    }
  };
  const h = (k: string) => headers[k.toLowerCase()] ?? headers[k];

  if (h("x-powered-by")) add(h("x-powered-by"), "X-Powered-By header");
  if (h("server") && String(h("server")).toLowerCase() !== "cloudflare") add(h("server"), "Server header");
  if (h("x-aspnet-version")) add(`ASP.NET ${h("x-aspnet-version")}`, "X-AspNet-Version header");
  if (h("x-aspnetmvc-version")) add(`ASP.NET MVC ${h("x-aspnetmvc-version")}`, "X-AspNetMvc-Version header");
  if (h("x-runtime")) add(h("x-runtime"), "X-Runtime header");
  if (h("x-generator")) add(h("x-generator"), "X-Generator header");
  if (h("x-drupal-cache")) add("Drupal", "X-Drupal-Cache header");
  if (h("x-varnish")) add("Varnish", "X-Varnish header");
  if (h("x-request-id")) add("Request ID", "X-Request-Id header");
  if (h("cf-ray")) add("Cloudflare", "cf-ray header");
  const amzHeader = Object.keys(headers).find((k) => k.toLowerCase().startsWith("x-amz-"));
  if (amzHeader) add("AWS", "amz header");

  const gen = html.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i);
  if (gen) add(gen[1], "meta generator");
  const framework = html.match(/<meta\s+name=["']framework["']\s+content=["']([^"']+)["']/i);
  if (framework) add(framework[1], "meta framework");
  const appName = html.match(/<meta\s+name=["']application-name["']\s+content=["']([^"']+)["']/i);
  if (appName) add(appName[1], "meta application-name");

  if (/wp-includes|wp-content|wordpress/i.test(html)) add("WordPress", "HTML");
  if (/__NEXT_DATA__/i.test(html)) add("Next.js", "HTML");
  if (/__NUXT__/i.test(html)) add("Nuxt", "HTML");
  if (/__sveltekit/i.test(html)) add("SvelteKit", "HTML");
  if (/react|createelement/i.test(html)) add("React", "HTML");
  if (/vue\.js|v-bind|v-model|vue/i.test(html)) add("Vue.js", "HTML");
  if (/angular/i.test(html)) add("Angular", "HTML");
  if (/jquery/i.test(html)) add("jQuery", "HTML");
  if (/csrfmiddlewaretoken|django/i.test(html)) add("Django", "HTML");
  if (/laravel_session|laravel/i.test(html)) add("Laravel", "HTML");
  if (/express/i.test(html)) add("Express", "HTML");
  if (/drupal/i.test(html)) add("Drupal", "HTML");
  if (/joomla/i.test(html)) add("Joomla", "HTML");
  if (/shopify/i.test(html)) add("Shopify", "HTML");
  if (/ghost/i.test(html)) add("Ghost", "HTML");
  if (/hugo/i.test(html)) add("Hugo", "HTML");
  if (/gatsby/i.test(html)) add("Gatsby", "HTML");

  const scriptSrc = html.match(/<script[^>]+src=["']([^"']+)["']/gi);
  if (scriptSrc) {
    for (const s of scriptSrc) {
      const srcMatch = s.match(/src=["']([^"']+)["']/i);
      const src = srcMatch?.[1] ?? "";
      if (/react|react-dom/i.test(src)) add("React", "script src");
      if (/vue/i.test(src)) add("Vue.js", "script src");
      if (/angular/i.test(src)) add("Angular", "script src");
      if (/jquery/i.test(src)) add("jQuery", "script src");
      if (/bootstrap/i.test(src)) add("Bootstrap", "script src");
      if (/tailwind/i.test(src)) add("Tailwind CSS", "script src");
      if (/webpack/i.test(src)) add("Webpack", "script src");
      if (/vite/i.test(src)) add("Vite", "script src");
    }
  }

  return techs;
}

function scanOpenPorts(host: string, ports: number[], timeoutMs = 2000, concurrency = 25): Promise<number[]> {
  const tryPort = (port: number) =>
    new Promise<boolean>((resolve) => {
      const socket = new net.Socket();
      const timer = setTimeout(() => { socket.destroy(); resolve(false); }, timeoutMs);
      socket.on("connect", () => { clearTimeout(timer); socket.destroy(); resolve(true); });
      socket.on("error", () => { clearTimeout(timer); resolve(false); });
      socket.connect(port, host);
    });
  return runWithConcurrency(ports, concurrency, async (p) => ((await tryPort(p)) ? p : 0)).then((results) => results.filter((p) => p > 0));
}

function parseSocialTags(html: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of Array.from(html.matchAll(/<meta\s+property=["']og:([^"']+)["']\s+content=["']([^"']*)["']/gi))) out[`og:${m[1].toLowerCase()}`] = m[2];
  for (const m of Array.from(html.matchAll(/<meta\s+name=["']twitter:([^"']+)["']\s+content=["']([^"']*)["']/gi))) out[`twitter:${m[1].toLowerCase()}`] = m[2];
  return out;
}

function analyzeSPF(txtRecords: string[][]): { found: boolean; record: string; issues: string[] } {
  const spfRecords = txtRecords.flat().filter(r => r.startsWith("v=spf1"));
  if (spfRecords.length === 0) return { found: false, record: "", issues: ["No SPF record found"] };
  const record = spfRecords[0];
  const issues: string[] = [];
  if (record.includes("+all")) issues.push("SPF uses +all (allows any sender)");
  if (record.includes("?all")) issues.push("SPF uses ?all (neutral policy - no enforcement)");
  if (!record.includes("-all") && !record.includes("~all")) {
    if (!record.includes("+all") && !record.includes("?all")) {
      issues.push("SPF record may not have a restrictive -all or ~all terminator");
    }
  }
  if (spfRecords.length > 1) issues.push("Multiple SPF records found (RFC violation)");
  return { found: true, record, issues };
}

function analyzeDMARC(txtRecords: string[][]): { found: boolean; record: string; issues: string[] } {
  const dmarcRecords = txtRecords.flat().filter(r => r.startsWith("v=DMARC1"));
  if (dmarcRecords.length === 0) return { found: false, record: "", issues: ["No DMARC record found"] };
  const record = dmarcRecords[0];
  const issues: string[] = [];
  if (record.includes("p=none")) issues.push("DMARC policy is 'none' (monitoring only, no enforcement)");
  const pctMatch = record.match(/pct=(\d+)/);
  if (pctMatch && parseInt(pctMatch[1]) < 100) issues.push(`DMARC only applies to ${pctMatch[1]}% of messages`);
  return { found: true, record, issues };
}

function extractCloudProvidersFromSPF(spfRecord: string, mxRecords: Array<{ exchange: string }>): Array<{ provider: string; confidence: number; evidence: string[] }> {
  const providers: Array<{ provider: string; confidence: number; evidence: string[] }> = [];
  const record = (spfRecord || "").toLowerCase();
  const mxHosts = (mxRecords || []).map((m) => m.exchange?.toLowerCase() ?? "").join(" ");
  if (record.includes("include:_spf.google.com") || record.includes("include:spf.google.com") || mxHosts.includes("google")) providers.push({ provider: "Google Workspace", confidence: 90, evidence: ["SPF include or MX"] });
  if (record.includes("include:amazonses.com") || record.includes("include:spf.amazonses.com")) providers.push({ provider: "AWS SES", confidence: 95, evidence: ["SPF include"] });
  if (record.includes("include:sendgrid.net") || record.includes("include:spf.sendgrid.net")) providers.push({ provider: "SendGrid", confidence: 95, evidence: ["SPF include"] });
  if (record.includes("include:mailgun.org") || record.includes("include:spf.mailgun.org")) providers.push({ provider: "Mailgun", confidence: 95, evidence: ["SPF include"] });
  if (record.includes("include:zoho.com") || record.includes("include:spf.zoho.com")) providers.push({ provider: "Zoho", confidence: 95, evidence: ["SPF include"] });
  if (record.includes("include:outlook.com") || record.includes("include:spf.protection.outlook.com") || mxHosts.includes("outlook") || mxHosts.includes("microsoft")) providers.push({ provider: "Microsoft 365", confidence: 90, evidence: ["SPF include or MX"] });
  if (record.includes("include:spf.mailjet.com") || record.includes("include:mailjet.com")) providers.push({ provider: "Mailjet", confidence: 95, evidence: ["SPF include"] });
  if (record.includes("include:spf.mandrillapp.com") || record.includes("include:mandrillapp.com")) providers.push({ provider: "Mandrill", confidence: 95, evidence: ["SPF include"] });
  return providers;
}

/** OWASP/securityheaders.com recommended headers with value validation. */
const SECURITY_HEADER_CHECKS = [
  { header: "strict-transport-security", label: "Strict-Transport-Security (HSTS)" },
  { header: "content-security-policy", label: "Content-Security-Policy (CSP)" },
  { header: "x-frame-options", label: "X-Frame-Options" },
  { header: "x-content-type-options", label: "X-Content-Type-Options" },
  { header: "permissions-policy", label: "Permissions-Policy" },
  { header: "referrer-policy", label: "Referrer-Policy" },
  { header: "x-xss-protection", label: "X-XSS-Protection" },
  { header: "cross-origin-embedder-policy", label: "Cross-Origin-Embedder-Policy" },
  { header: "cross-origin-opener-policy", label: "Cross-Origin-Opener-Policy" },
  { header: "cross-origin-resource-policy", label: "Cross-Origin-Resource-Policy" },
  { header: "x-dns-prefetch-control", label: "X-DNS-Prefetch-Control" },
] as const;

function gradeHeader(header: string, value: string): "A" | "B" | "C" | "N/A" {
  const v = value.toLowerCase().trim();
  switch (header) {
    case "strict-transport-security": {
      const maxAge = v.match(/max-age\s*=\s*(\d+)/i)?.[1];
      if (!maxAge) return "C";
      const age = parseInt(maxAge, 10);
      return age >= 31536000 ? "A" : age >= 0 ? "B" : "C";
    }
    case "x-frame-options":
      return /^(deny|sameorigin|same-origin)$/i.test(v) ? "A" : "C";
    case "x-content-type-options":
      return /nosniff/i.test(v) ? "A" : "C";
    case "content-security-policy":
      return /default-src|script-src|frame-ancestors/i.test(v) ? "A" : "B";
    default:
      return v ? "A" : "N/A";
  }
}

function checkSecurityHeaders(headers: Record<string, string>): Array<{ header: string; present: boolean; value?: string; issue?: string; grade: "A" | "B" | "C" | "N/A" }> {
  return SECURITY_HEADER_CHECKS.map(({ header, label }) => {
    const value = headers[header] ?? headers[header.toLowerCase()];
    if (!value) return { header: label, present: false, issue: `Missing ${label} header`, grade: "N/A" as const };
    const grade = gradeHeader(header, value);
    return { header: label, present: true, value, grade };
  });
}

function detectServerInfo(headers: Record<string, string>): string[] {
  const leaks: string[] = [];
  const h = (k: string) => headers[k.toLowerCase()] ?? headers[k];
  if (h("server") && String(h("server")).toLowerCase() !== "cloudflare") leaks.push(`Server: ${h("server")}`);
  if (h("x-powered-by")) leaks.push(`X-Powered-By: ${h("x-powered-by")}`);
  if (h("x-aspnet-version")) leaks.push(`X-AspNet-Version: ${h("x-aspnet-version")}`);
  if (h("x-aspnetmvc-version")) leaks.push(`X-AspNetMvc-Version: ${h("x-aspnetmvc-version")}`);
  if (h("x-runtime")) leaks.push(`X-Runtime: ${h("x-runtime")}`);
  return leaks;
}

function detectWAF(headers: Record<string, string>): { detected: boolean; provider: string } {
  const h = (k: string) => (headers[k.toLowerCase()] ?? headers[k] ?? "").toLowerCase();
  const server = h("server");

  if (server.includes("cloudflare") || h("cf-ray")) return { detected: true, provider: "Cloudflare" };
  if (h("x-sucuri-id") || h("x-sucuri-cache")) return { detected: true, provider: "Sucuri" };
  if (server.includes("akamaighost") || h("x-akamai-transformed")) return { detected: true, provider: "Akamai" };
  if (h("x-datadome")) return { detected: true, provider: "DataDome" };
  if (server.includes("imperva") || h("x-iinfo")) return { detected: true, provider: "Imperva" };
  if (server.includes("barracuda") || h("barra_counter_session")) return { detected: true, provider: "Barracuda" };
  if (h("x-cdn") === "incapsula" || h("x-cdn") === "imperva") return { detected: true, provider: "Imperva/Incapsula" };
  if (server.includes("awselb") || server.includes("awsalb")) return { detected: true, provider: "AWS WAF" };
  if (h("x-azure-ref")) return { detected: true, provider: "Azure Front Door" };
  return { detected: false, provider: "" };
}

function detectCDN(headers: Record<string, string>): string {
  const h = (k: string) => (headers[k.toLowerCase()] ?? headers[k] ?? "").toLowerCase();
  const server = h("server");

  if (server.includes("cloudflare") || h("cf-ray") || h("cf-cache-status")) return "Cloudflare";
  if (server.includes("cloudfront") || h("x-amz-cf-id") || h("x-amz-cf-pop")) return "CloudFront";
  if (server.includes("akamaighost") || h("x-akamai-transformed")) return "Akamai";
  if (h("x-fastly-request-id") || h("fastly-debug-digest") || server.includes("fastly")) return "Fastly";
  if (h("x-vercel-id") || server.includes("vercel")) return "Vercel";
  if (h("x-served-by") && h("x-served-by").includes("cache-")) return "Fastly";
  if (h("x-cdn") === "bunny" || server.includes("bunnycdn")) return "BunnyCDN";
  if (h("x-azure-ref") || server.includes("azure")) return "Azure CDN";
  if (h("x-cache") && (h("via") || "").includes("squid")) return "Squid/Proxy";
  if (h("x-cache") || h("x-cache-hits")) return "CDN (unknown)";
  return "None";
}

export async function runEASMScan(domain: string, onProgress?: ScanProgressCallback, options?: ScanOptions): Promise<ScanResults> {
  const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (!domain || !DOMAIN_RE.test(domain)) throw new Error(`Invalid domain: ${domain}`);
  const signal = options?.signal;
  const gold = isGold(options);
  const results: ScanResults = { subdomains: [], assets: [], findings: [], reconData: {} };
  const now = new Date().toISOString();
  const report = async (msg: string, pct: number, step: string, eta?: number) => {
    checkAborted(signal);
    if (onProgress) await onProgress(msg, pct, step, eta);
  };

  const subdomainCap = gold ? GOLD_SUBDOMAIN_WORDLIST_CAP : STANDARD_SUBDOMAIN_WORDLIST_CAP;
  const probeBatchSize = gold ? GOLD_PROBE_BATCH : STANDARD_PROBE_BATCH;
  const certCheckLimit = gold ? GOLD_SUBDOMAIN_CERT_CHECK : STANDARD_SUBDOMAIN_CERT_CHECK;
  const portList = gold ? GOLD_PORTS : STANDARD_PORTS;

  checkAborted(signal);
  console.log(`[Scanner] Starting EASM scan for: ${domain} (mode: ${gold ? "gold" : "standard"})`);
  await report("Enumerating subdomains (crt.sh + bruteforce)...", 0, "enumerate_subdomains", 180);

  const [crtShSubdomains, mainDns, certInfo, nsRecords, bruteforceResult] = await Promise.all([
    enumerateSubdomainsCrtSh(domain),
    resolveDNS(domain),
    getCertificateInfo(domain),
    getNSRecords(domain),
    enumerateSubdomainsBruteforce(domain, subdomainCap === 0 ? 99999 : subdomainCap, 20, signal),
  ]);

  checkAborted(signal);
  const bruteforceSet = new Set(bruteforceResult.resolved);
  const combinedSubdomains = Array.from(new Set([...crtShSubdomains, ...bruteforceResult.resolved])).sort();
  results.subdomains = combinedSubdomains;
  if (bruteforceResult.wildcardDetected) {
    console.log(`[Scanner] Wildcard DNS filtering applied for ${domain} — bruteforce results de-duplicated against wildcard IPs`);
  }
  await report(`Found ${combinedSubdomains.length} subdomains${bruteforceResult.wildcardDetected ? " (wildcard DNS detected)" : ""}. Probing live hosts...`, 15, "enumerate_subdomains", 150);

  if (mainDns.ips.length > 0) {
    results.assets.push({ type: "domain", value: domain, tags: ["primary", "resolved"] });
    for (const ip of mainDns.ips) {
      results.assets.push({ type: "ip", value: ip, tags: ["resolved-from-domain"] });
    }
  }

  const subdomainProbes: Array<{ subdomain: string; dns: { ips: string[]; cnames: string[] }; httpResult: any; httpsResult: any }> = [];

  const probeBatch = probeBatchSize <= 0 ? combinedSubdomains : combinedSubdomains.slice(0, probeBatchSize);
  console.log(`[Scanner] Probing ${probeBatch.length} subdomains (crt.sh + bruteforce: ${bruteforceResult.tried} tried, ${bruteforceResult.resolved.length} resolved)...`);

  const probeResults = await runWithConcurrency(
    probeBatch,
    20,
    async (sub) => {
      const subDns = await resolveDNS(sub);
      let httpResult = null;
      let httpsResult = null;
      if (subDns.ips.length > 0 || subDns.cnames.length > 0) {
        [httpsResult, httpResult] = await Promise.all([
          httpHead(`https://${sub}`).catch(() => null),
          httpHead(`http://${sub}`).catch(() => null),
        ]);
      }
      return { subdomain: sub, dns: subDns, httpResult, httpsResult };
    },
    signal,
  );

  for (const r of probeResults) {
    if (r) {
      const probe = r;
      subdomainProbes.push(probe);
      if (probe.dns.ips.length > 0 || probe.dns.cnames.length > 0) {
        results.assets.push({
          type: "subdomain",
          value: probe.subdomain,
          tags: [
            ...(bruteforceSet.has(probe.subdomain) ? ["bruteforce"] : ["crt.sh"]),
            ...(probe.httpsResult ? ["https-live"] : []),
            ...(probe.httpResult ? ["http-live"] : []),
            ...(probe.dns.cnames.length > 0 ? ["has-cname"] : []),
          ],
        });
        for (const ip of probe.dns.ips) {
          if (!results.assets.find(a => a.value === ip)) {
            results.assets.push({ type: "ip", value: ip, tags: ["subdomain-resolution"] });
          }
        }
      }
    }
  }

  checkAborted(signal);
  const liveSubdomains = subdomainProbes.filter(p => p.httpsResult || p.httpResult);
  await report(`Probed ${probeBatch.length} subdomains, ${liveSubdomains.length} live. Analyzing TLS and headers...`, 55, "probe_subdomains", 90);

  const bruteforceLiveWithHttp = liveSubdomains.filter(p => bruteforceSet.has(p.subdomain)).map(p => p.subdomain);
  (results.reconData as any).subdomainBruteforce = {
    wordlistSource: SUBDOMAIN_WORDLIST_SOURCE,
    tried: bruteforceResult.tried,
    resolved: bruteforceResult.resolved,
    liveWithHttp: bruteforceLiveWithHttp,
  };

  for (const live of liveSubdomains) {
    const proto = live.httpsResult ? "https" : "http";
    const port = proto === "https" ? 443 : 80;
    results.assets.push({ type: "service", value: `${proto}://${live.subdomain}:${port}`, tags: ["auto-discovered"] });
  }

  (results.reconData as any).discoveredDomains = liveSubdomains.map((p) => {
    const respHeaders = (p.httpsResult?.headers || p.httpResult?.headers || {}) as Record<string, string>;
    const wafInfo = detectWAF(respHeaders);
    const cdnName = detectCDN(respHeaders);
    return {
      domain: p.subdomain,
      ip: p.dns.ips[0] || p.dns.cnames[0] || "-",
      cdn: cdnName,
      waf: wafInfo.detected,
      wafProvider: wafInfo.provider,
      newSinceLastRun: false,
    };
  });

  const TAKEOVER_PRONE_PATTERNS = /\.(s3\.amazonaws\.com|cloudfront\.net|herokuapp\.com|herokussl\.com|github\.io|azurewebsites\.net|elasticbeanstalk\.com|trafficmanager\.net|zendesk\.com|fastly\.net|ghost\.io|helpscoutdocs\.com|cargo\.site|surge\.sh|bitbucket\.io|pantheon\.site|wpengine\.com|readme\.io|intercom\.io|statuspage\.io|uservoice\.com|feedpress\.me|freshdesk\.com|helpjuice\.com|helpscout\.com|pingdom\.com|tictail\.com|shopify\.com|teamwork\.com|unbounce\.com|tumblr\.com|wordpress\.com|desk\.com|service-now\.com|acquia\.cloud|myshopify\.com)\.?$/i;
  const danglingCnames = subdomainProbes.filter(p => {
    if (p.dns.cnames.length === 0) return false;
    if (p.dns.ips.length > 0) return false;
    return true;
  });

  for (const dc of danglingCnames) {
    const cnameTarget = dc.dns.cnames[0] || "";
    const isTakeoverProne = TAKEOVER_PRONE_PATTERNS.test(cnameTarget);
    results.findings.push({
      title: isTakeoverProne ? `High-Risk Subdomain Takeover: ${dc.subdomain}` : `Potential Subdomain Takeover: ${dc.subdomain}`,
      description: isTakeoverProne
        ? `The subdomain ${dc.subdomain} has a CNAME pointing to ${cnameTarget} (known takeover-prone service) but the target does not resolve. This is a high-risk dangling DNS record.`
        : `The subdomain ${dc.subdomain} has a CNAME record pointing to ${cnameTarget} but the target does not resolve to any IP address. This may indicate a dangling DNS record that could be vulnerable to subdomain takeover.`,
      severity: isTakeoverProne ? "critical" : "high",
      category: "subdomain_takeover",
      affectedAsset: dc.subdomain,
      cvssScore: isTakeoverProne ? "9.1" : "8.2",
      remediation: "Remove the dangling CNAME record if the service is no longer in use, or reclaim the underlying service.",
      evidence: [
        {
          type: "dns_record",
          description: `CNAME record points to unresolvable target`,
          snippet: `${dc.subdomain} CNAME ${dc.dns.cnames[0]}\n; Target does not resolve - potential takeover risk`,
          source: "DNS resolution",
          verifiedAt: now,
        },
      ],
    });
  }

  checkAborted(signal);
  await report("Analyzing TLS certificate and security posture...", 65, "analyze_tls", 60);

  if (certInfo) {
    results.assets.push({
      type: "certificate",
      value: `${certInfo.subject} (${certInfo.issuer})`,
      tags: [`expires-in-${certInfo.daysRemaining}d`, certInfo.protocol],
    });

    if (certInfo.daysRemaining <= 30 && certInfo.daysRemaining > 0) {
      results.findings.push({
        title: `SSL Certificate Expiring in ${certInfo.daysRemaining} Days`,
        description: `The SSL/TLS certificate for ${domain} (issued by ${certInfo.issuer}) will expire on ${certInfo.validTo}. This is ${certInfo.daysRemaining} days from now.`,
        severity: certInfo.daysRemaining <= 7 ? "critical" : certInfo.daysRemaining <= 14 ? "high" : "medium",
        category: "ssl_issue",
        affectedAsset: domain,
        cvssScore: certInfo.daysRemaining <= 7 ? "8.1" : certInfo.daysRemaining <= 14 ? "6.5" : "4.3",
        remediation: `Renew the SSL/TLS certificate for ${domain} before ${certInfo.validTo}.`,
        evidence: [
          {
            type: "certificate_info",
            description: "Live certificate inspection",
            snippet: `Subject: ${certInfo.subject}\nIssuer: ${certInfo.issuer}\nValid From: ${certInfo.validFrom}\nValid To: ${certInfo.validTo}\nDays Remaining: ${certInfo.daysRemaining}\nProtocol: ${certInfo.protocol}\nSerial: ${certInfo.serialNumber}`,
            source: `TLS connection to ${domain}:443`,
            verifiedAt: now,
          },
        ],
      });
    }

    if (certInfo.daysRemaining <= 0) {
      results.findings.push({
        title: `SSL Certificate Has Expired for ${domain}`,
        description: `The SSL/TLS certificate for ${domain} expired on ${certInfo.validTo}. Visitors will see security warnings.`,
        severity: "critical",
        category: "ssl_issue",
        affectedAsset: domain,
        cvssScore: "9.1",
        remediation: `Immediately renew the SSL/TLS certificate for ${domain}.`,
        evidence: [
          {
            type: "certificate_info",
            description: "Expired certificate detected via TLS connection",
            snippet: `Subject: ${certInfo.subject}\nIssuer: ${certInfo.issuer}\nExpired: ${certInfo.validTo}\nDays Past Expiry: ${Math.abs(certInfo.daysRemaining)}`,
            source: `TLS connection to ${domain}:443`,
            verifiedAt: now,
          },
        ],
      });
    }

    results.reconData.ssl = {
      subject: certInfo.subject,
      issuer: certInfo.issuer,
      validFrom: certInfo.validFrom,
      validTo: certInfo.validTo,
      daysRemaining: certInfo.daysRemaining,
      protocol: certInfo.protocol,
      altNames: certInfo.altNames,
    };
  }

  checkAborted(signal);
  const certCheckSubs = certCheckLimit <= 0 ? liveSubdomains : liveSubdomains.slice(0, certCheckLimit);
  for (const live of certCheckSubs) {
    const subCert = await getCertificateInfo(live.subdomain);
    if (subCert && (subCert.daysRemaining <= 30 || subCert.daysRemaining <= 0)) {
      results.findings.push({
        title: `SSL Certificate Issue on ${live.subdomain}`,
        description: subCert.daysRemaining <= 0
          ? `The SSL certificate for ${live.subdomain} has expired.`
          : `The SSL certificate for ${live.subdomain} expires in ${subCert.daysRemaining} days.`,
        severity: subCert.daysRemaining <= 0 ? "critical" : subCert.daysRemaining <= 7 ? "high" : "medium",
        category: "ssl_issue",
        affectedAsset: live.subdomain,
        cvssScore: subCert.daysRemaining <= 0 ? "9.1" : subCert.daysRemaining <= 7 ? "8.1" : "5.3",
        remediation: "Renew the SSL certificate for this subdomain.",
        evidence: [
          {
            type: "certificate_info",
            description: "TLS certificate inspection",
            snippet: `Subject: ${subCert.subject}\nIssuer: ${subCert.issuer}\nDays Remaining: ${subCert.daysRemaining}`,
            source: `TLS connection to ${live.subdomain}:443`,
            verifiedAt: now,
          },
        ],
      });
    }
  }

  await report("Checking security headers and HTTP configuration...", 75, "check_headers", 30);

  const mainHttps = await httpGet(`https://${domain}`);
  if (mainHttps) {
    const headerChecks = checkSecurityHeaders(mainHttps.headers);
    const missingHeaders = headerChecks.filter(h => !h.present);
    const serverLeaks = detectServerInfo(mainHttps.headers);

    if (missingHeaders.length >= 3) {
      results.findings.push({
        title: `Multiple Missing Security Headers on ${domain}`,
        description: `${missingHeaders.length} security headers are missing from the HTTP response on ${domain}. Missing headers: ${missingHeaders.map(h => h.header).join(", ")}.`,
        severity: missingHeaders.length >= 5 ? "medium" : "low",
        category: "security_headers",
        affectedAsset: domain,
        cvssScore: missingHeaders.length >= 5 ? "5.0" : "3.5",
        remediation: "Configure the web server to include the missing security headers.",
        evidence: [
          {
            type: "http_headers",
            description: "Security header analysis of live HTTP response",
            snippet: headerChecks.map(h => `${h.present ? "[PASS]" : "[MISS]"} ${h.header}${h.value ? `: ${h.value}` : ""}`).join("\n"),
            url: `https://${domain}`,
            source: "HTTP response headers",
            verifiedAt: now,
          },
        ],
      });
    }

    if (serverLeaks.length > 0) {
      results.findings.push({
        title: `Server Version Information Disclosed on ${domain}`,
        description: `The web server at ${domain} exposes version information in HTTP response headers, which could help attackers identify specific vulnerabilities.`,
        severity: "low",
        category: "information_disclosure",
        affectedAsset: domain,
        cvssScore: "3.0",
        remediation: "Configure the web server to suppress version information in headers.",
        evidence: [
          {
            type: "http_headers",
            description: "Server information leak in HTTP response headers",
            snippet: serverLeaks.join("\n"),
            url: `https://${domain}`,
            source: "HTTP response headers",
            verifiedAt: now,
          },
        ],
      });
    }

    if (!mainHttps.headers["strict-transport-security"]) {
      const httpPlain = await httpGet(`http://${domain}`);
      if (httpPlain && httpPlain.status === 200) {
        results.findings.push({
          title: `No HSTS and HTTP Available on ${domain}`,
          description: `${domain} serves content over plain HTTP (port 80) and does not set the Strict-Transport-Security header on HTTPS responses. This allows potential downgrade attacks.`,
          severity: "medium",
          category: "ssl_issue",
          affectedAsset: domain,
          cvssScore: "4.8",
          remediation: "Enable HSTS header on all HTTPS responses and redirect HTTP to HTTPS.",
          evidence: [
            {
              type: "http_response",
              description: "HTTP (non-TLS) responds successfully without HSTS enforcement",
              snippet: `HTTP Request: http://${domain}\nStatus: ${httpPlain.status}\nHSTS Header: Not Present\nHTTPS Redirect: ${httpPlain.finalUrl.startsWith("https") ? "Yes (redirect exists but no HSTS)" : "No redirect to HTTPS"}`,
              url: `http://${domain}`,
              source: "HTTP probe",
              verifiedAt: now,
            },
          ],
        });
      }
    }

    results.reconData.securityHeaders = Object.fromEntries(
      headerChecks.map(h => [h.header, { present: h.present, value: h.value || null, grade: h.grade }])
    );
    results.reconData.serverInfo = { leaks: serverLeaks, allHeaders: mainHttps.headers };
  }

  if (gold && liveSubdomains.length > 0) {
    checkAborted(signal);
    await report("Running per-asset TLS, headers, and leak analysis...", 82, "per_asset_analysis", 45);

    const perAssetTls: Record<string, { subject?: string; issuer?: string; daysRemaining?: number; protocol?: string } | null> = {};
    const perAssetHeaders: Record<string, Record<string, { present: boolean; value: string | null }>> = {};
    const perAssetLeaks: Record<string, string[]> = {};
    const wafByHost: Record<string, { waf: boolean; wafProvider: string; cdn: string }> = {};

    const perAssetBatch = gold ? liveSubdomains : liveSubdomains.slice(0, 30);
    const perAssetResults = await runWithConcurrency(
      perAssetBatch,
      10,
      async (live) => {
        const host = live.subdomain;
        const cert = await getCertificateInfo(host);
        const resp = await httpGet(`https://${host}`);
        return { host, cert, resp };
      },
      signal,
    );

    for (const r of perAssetResults) {
      if (!r) continue;
      const { host, cert, resp } = r;
      if (cert) {
        perAssetTls[host] = { subject: cert.subject, issuer: cert.issuer, daysRemaining: cert.daysRemaining, protocol: cert.protocol };
      } else {
        perAssetTls[host] = null;
      }
      if (resp) {
        const hdrs = checkSecurityHeaders(resp.headers);
        perAssetHeaders[host] = Object.fromEntries(hdrs.map(h => [h.header, { present: h.present, value: h.value || null }]));
        perAssetLeaks[host] = detectServerInfo(resp.headers);
        const w = detectWAF(resp.headers);
        const c = detectCDN(resp.headers);
        wafByHost[host] = { waf: w.detected, wafProvider: w.provider, cdn: c };
      }
    }

    (results.reconData as any).perAssetTls = perAssetTls;
    (results.reconData as any).perAssetHeaders = perAssetHeaders;
    (results.reconData as any).perAssetLeaks = perAssetLeaks;
    (results.reconData as any).wafByHost = wafByHost;
  }

  if (mainDns.ips.length > 0) {
    const mainIp = mainDns.ips[0];
    const openPorts = await scanOpenPorts(mainIp, portList);
    (results.reconData as any).openPorts = openPorts;

    if (gold) {
      const allIps = Array.from(new Set(subdomainProbes.flatMap(p => p.dns.ips)));
      const otherIps = allIps.filter(ip => ip !== mainIp);
      const openPortsByIp: Record<string, number[]> = { [mainIp]: openPorts };
      for (const ip of otherIps) {
        openPortsByIp[ip] = await scanOpenPorts(ip, portList);
      }
      (results.reconData as any).openPortsByIp = openPortsByIp;
    }

    // Threat intel enrichment for the primary IP (and subdomain IPs in gold mode)
    try {
      const [abuseResult, bgpResult] = await Promise.all([
        enrichIP(mainIp),
        fetchBGPView(mainIp),
      ]);
      (results.reconData as any).threatIntel = {
        [mainIp]: { abuseipdb: abuseResult.abuseipdb, virustotal: abuseResult.virustotal, bgp: bgpResult },
      };
      if (abuseResult.abuseipdb && abuseResult.abuseipdb.abuseConfidenceScore >= 50) {
        results.findings.push({
          title: `High Abuse Score for Primary IP ${mainIp}`,
          description: `The primary IP address ${mainIp} for ${domain} has an AbuseIPDB confidence score of ${abuseResult.abuseipdb.abuseConfidenceScore}% (${abuseResult.abuseipdb.totalReports} reports). This indicates the IP has been reported for malicious activity.`,
          severity: abuseResult.abuseipdb.abuseConfidenceScore >= 80 ? "high" : "medium",
          category: "threat_intelligence",
          affectedAsset: mainIp,
          cvssScore: abuseResult.abuseipdb.abuseConfidenceScore >= 80 ? "7.5" : "5.3",
          remediation: "Investigate the reported abuse activity. Consider changing IP address or contacting the hosting provider.",
          evidence: [
            {
              type: "threat_intel",
              description: "AbuseIPDB IP reputation check",
              snippet: `IP: ${mainIp}\nAbuse Score: ${abuseResult.abuseipdb.abuseConfidenceScore}%\nTotal Reports: ${abuseResult.abuseipdb.totalReports}\nISP: ${abuseResult.abuseipdb.isp ?? "unknown"}\nCountry: ${abuseResult.abuseipdb.countryCode ?? "unknown"}`,
              source: "AbuseIPDB API",
              verifiedAt: now,
            },
          ],
        });
      }
      if (gold) {
        const allSubIps = Array.from(new Set(subdomainProbes.flatMap(p => p.dns.ips))).filter(ip => ip !== mainIp).slice(0, 10);
        for (const ip of allSubIps) {
          try {
            const [subAbuse, subBgp] = await Promise.all([enrichIP(ip), fetchBGPView(ip)]);
            (results.reconData as any).threatIntel[ip] = { abuseipdb: subAbuse.abuseipdb, virustotal: subAbuse.virustotal, bgp: subBgp };
          } catch (err) {
            console.warn("[Scanner] Threat intel enrichment failed for", ip, (err as Error).message);
          }
        }
      }
    } catch (err) {
      console.warn("[Scanner] Threat intel enrichment failed for", mainIp, (err as Error).message);
    }
  }

  results.reconData.dns = {
    ips: mainDns.ips,
    cnames: mainDns.cnames,
    ns: nsRecords,
    subdomainsFound: crtShSubdomains.length,
    liveSubdomains: liveSubdomains.map(s => s.subdomain),
    danglingCnames: danglingCnames.map(d => ({ subdomain: d.subdomain, cname: d.dns.cnames[0] })),
  };

  await report("EASM scan complete.", 100, "build_modules", 0);
  console.log(`[Scanner] EASM scan complete for ${domain}: ${results.subdomains.length} subdomains, ${results.assets.length} assets, ${results.findings.length} verified findings`);
  return results;
}

function generateBackupFilePaths(domain: string, gold: boolean): string[] {
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

function extractSensitiveRobotsPaths(robotsTxt: string): string[] {
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

function extractEmailsFromDNS(txtRecords: string[][], dmarcTxt: string[][]): string[] {
  const emails: string[] = [];
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  // DMARC rua/ruf mailto
  for (const rec of dmarcTxt.flat()) {
    const matches = rec.match(/(?:rua|ruf)=mailto:([^;,\s]+)/gi);
    if (matches) {
      for (const m of matches) {
        const email = m.replace(/(?:rua|ruf)=mailto:/i, "");
        if (email) emails.push(email.toLowerCase());
      }
    }
  }
  // General TXT records
  for (const rec of txtRecords.flat()) {
    const matches = rec.match(emailRegex);
    if (matches) emails.push(...matches.map(e => e.toLowerCase()));
  }
  return Array.from(new Set(emails));
}

function extractEmailsFromWhois(domainInfo: Record<string, string> | null): string[] {
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

async function checkHIBPPasswords(values: string[], gold: boolean): Promise<Array<{ redacted: string; breachCount: number }>> {
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
      console.warn("[Scanner] HIBP check failed for a value:", err instanceof Error ? err.message : err);
    }
  }
  return results;
}

async function checkS3Buckets(domain: string, gold: boolean): Promise<Array<{ bucket: string; listable: boolean }>> {
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

async function searchPGPKeyServer(domain: string): Promise<string[]> {
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
    console.warn("[Scanner] PGP key server search failed:", err instanceof Error ? err.message : err);
    return [];
  }
}

async function extractEmailsFromCrtSh(domain: string): Promise<string[]> {
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
    console.warn("[Scanner] crt.sh email extraction failed:", err instanceof Error ? err.message : err);
    return [];
  }
}

export async function runOSINTScan(domain: string, onProgress?: ScanProgressCallback, options?: ScanOptions): Promise<ScanResults> {
  const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (!domain || !DOMAIN_RE.test(domain)) throw new Error(`Invalid domain: ${domain}`);
  const signal = options?.signal;
  const gold = isGold(options);
  const results: ScanResults = { subdomains: [], assets: [], findings: [], reconData: {} };
  const now = new Date().toISOString();
  const report = async (msg: string, pct: number, step: string, eta?: number) => {
    checkAborted(signal);
    if (onProgress) await onProgress(msg, pct, step, eta);
  };

  const directoryCap = gold ? GOLD_DIRECTORY_CAP : STANDARD_DIRECTORY_CAP;
  const sitemapLimit = gold ? GOLD_SITEMAP_LIMIT : STANDARD_SITEMAP_LIMIT;

  checkAborted(signal);
  console.log(`[Scanner] Starting OSINT scan for: ${domain} (mode: ${gold ? "gold" : "standard"})`);
  await report("Fetching DNS, SPF, DMARC, WHOIS...", 0, "dns_email", 120);

  const [txtRecords, dmarcTxt, dkimTxt, mxRecords, nsRecords, dnsRecords, redirectChain, domainInfo] = await Promise.all([
    getDNSTxtRecords(domain),
    getDNSTxtRecords(`_dmarc.${domain}`),
    getDNSTxtRecords(`default._domainkey.${domain}`),
    getMXRecords(domain),
    getNSRecords(domain),
    getFullDNSRecords(domain),
    getRedirectChain(`https://${domain}`),
    getWhois(domain),
  ]);

  results.reconData.dnsRecords = dnsRecords as any;
  results.reconData.redirectChain = redirectChain as any;
  results.reconData.domainInfo = domainInfo as any;

  const spfAnalysis = analyzeSPF(txtRecords);
  const dmarcAnalysis = analyzeDMARC(dmarcTxt);

  if (!spfAnalysis.found) {
    results.findings.push({
      title: `No SPF Record Found for ${domain}`,
      description: `The domain ${domain} does not have an SPF (Sender Policy Framework) DNS record. This means any server can send emails claiming to be from ${domain}, enabling email spoofing attacks.`,
      severity: "medium",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation: "Add an SPF TXT record to the domain's DNS configuration to specify authorized email senders.",
      evidence: [
        {
          type: "dns_query",
          description: "DNS TXT record lookup returned no SPF record",
          snippet: `Domain: ${domain}\nQuery: TXT records\nSPF Record: Not Found\n\nAll TXT records found:\n${txtRecords.flat().length > 0 ? txtRecords.flat().join("\n") : "(none)"}`,
          source: "DNS TXT record lookup",
          verifiedAt: now,
        },
      ],
    });
  } else if (spfAnalysis.issues.length > 0) {
    results.findings.push({
      title: `SPF Record Issues for ${domain}`,
      description: `The SPF record for ${domain} has configuration issues that may weaken email authentication: ${spfAnalysis.issues.join("; ")}.`,
      severity: spfAnalysis.record.includes("+all") ? "high" : "low",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: spfAnalysis.record.includes("+all") ? "7.1" : "3.5",
      remediation: "Update the SPF record to use '-all' or '~all' to restrict unauthorized senders.",
      evidence: [
        {
          type: "dns_query",
          description: "SPF record analysis",
          snippet: `Domain: ${domain}\nSPF Record: ${spfAnalysis.record}\n\nIssues:\n${spfAnalysis.issues.map(i => `- ${i}`).join("\n")}`,
          source: "DNS TXT record lookup",
          verifiedAt: now,
        },
      ],
    });
  }

  if (!dmarcAnalysis.found) {
    results.findings.push({
      title: `No DMARC Record Found for ${domain}`,
      description: `The domain ${domain} does not have a DMARC (Domain-based Message Authentication) DNS record at _dmarc.${domain}. Without DMARC, there is no policy to handle emails that fail SPF/DKIM checks.`,
      severity: "medium",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation: "Add a DMARC TXT record at _dmarc.${domain} with at least a 'p=quarantine' policy.",
      evidence: [
        {
          type: "dns_query",
          description: "DNS TXT record lookup for _dmarc subdomain returned no DMARC record",
          snippet: `Domain: _dmarc.${domain}\nQuery: TXT records\nDMARC Record: Not Found`,
          source: "DNS TXT record lookup",
          verifiedAt: now,
        },
      ],
    });
  } else if (dmarcAnalysis.issues.length > 0) {
    results.findings.push({
      title: `DMARC Policy Weakness for ${domain}`,
      description: `The DMARC record for ${domain} has a weak configuration: ${dmarcAnalysis.issues.join("; ")}.`,
      severity: "low",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: "3.5",
      remediation: "Update the DMARC policy to 'quarantine' or 'reject' and set pct=100.",
      evidence: [
        {
          type: "dns_query",
          description: "DMARC record analysis",
          snippet: `Domain: _dmarc.${domain}\nDMARC Record: ${dmarcAnalysis.record}\n\nIssues:\n${dmarcAnalysis.issues.map(i => `- ${i}`).join("\n")}`,
          source: "DNS TXT record lookup",
          verifiedAt: now,
        },
      ],
    });
  }

  checkAborted(signal);
  await report("Analyzed SPF/DMARC. Running directory bruteforce...", 25, "dns_email", 90);

  // Establish soft-404 baseline fingerprint to detect custom error pages
  const soft404Fingerprint = await (async () => {
    const random = Math.random().toString(36).slice(2, 10);
    const testPath = `/nxtest-${random}-doesnotexist`;
    try {
      const r = await httpGet(`https://${domain}${testPath}`);
      if (r && r.status === 200 && r.body) {
        return `${r.body.length}:${r.body.slice(0, 100).replace(/\s+/g, "")}`;
      }
    } catch {}
    return null;
  })();
  if (soft404Fingerprint) {
    console.log(`[Scanner] Soft-404 fingerprint established for ${domain}`);
  }

  const baseDirPaths = await loadDirectoryWordlist(directoryCap);
  const backupPaths = generateBackupFilePaths(domain, gold);
  const osintPaths = Array.from(new Set([...baseDirPaths, ...OSINT_CREDENTIAL_PATHS, ...OSINT_DOCUMENT_PATHS, ...OSINT_INFRA_PATHS, ...backupPaths, "/.git/config"]));
  const dirPaths = osintPaths;
  const pathCheckResultsRaw = await runWithConcurrency(
    dirPaths,
    8,
    async (path) => {
      const res = await httpGet(`https://${domain}${path}`);
      return { path, label: path, result: res };
    },
    signal,
  );
  const pathCheckResults = pathCheckResultsRaw.filter((r): r is { path: string; label: string; result: { status: number; headers: Record<string, string>; body: string; finalUrl: string } | null } => r != null);
  (results.reconData as any).directoryBruteforce = {
    wordlistSource: DIRECTORY_WORDLIST_SOURCE,
    tried: dirPaths.length,
    hits: pathCheckResults
      .filter((r) => r.result)
      .map((r) => {
        const { status, body, finalUrl } = r.result!;
        const v = validatePathResponse(status, body, finalUrl, r.path);
        return { path: r.path, status, responseType: v.responseType, severity: v.severity, validated: v.validated, confidence: v.confidence, redirectTarget: v.redirectTarget };
      }),
  };
  await report(`Checked ${dirPaths.length} paths. Processing sitemap and main page...`, 65, "directory_bruteforce", 45);

  const exposedPaths: Array<{ path: string; label: string; status: number; snippet: string }> = [];

  for (const r of pathCheckResults) {
    if (!r.result) continue;
    const { path, label, result } = r;
    const pathValidation = validatePathResponse(result.status, result.body, result.finalUrl, path);
    if (result.status !== 200) continue;
    // Soft-404 fingerprint check: skip if body matches baseline 404 page
    if (soft404Fingerprint && result.body) {
      const bodyFingerprint = `${result.body.length}:${result.body.slice(0, 100).replace(/\s+/g, "")}`;
      if (bodyFingerprint === soft404Fingerprint) continue;
    }

    if (path === "/.env" && result.body) {
      const hasSecrets = hasCredentialPattern(result.body);
      const redacted = redactCredentialValues(result.body.substring(0, 500));
      results.findings.push({
        title: `Exposed Environment File (.env) on ${domain}`,
        description: hasSecrets
          ? `The .env file at ${domain}/.env is publicly accessible and appears to contain sensitive configuration values (passwords, API keys, tokens).`
          : `The .env file at ${domain}/.env is publicly accessible. It may contain sensitive configuration.`,
        severity: hasSecrets ? "critical" : "high",
        category: hasSecrets ? "leaked_credential" : "data_leak",
        affectedAsset: domain,
        cvssScore: hasSecrets ? "9.8" : "7.5",
        remediation: "Immediately block public access to .env files. Rotate all exposed credentials. Configure web server to deny access to dotfiles.",
        evidence: [
          {
            type: "http_response",
            description: hasSecrets ? "Publicly accessible .env file with sensitive data patterns" : "Publicly accessible .env file",
            url: `https://${domain}${path}`,
            snippet: `HTTP Status: 200 OK\nSensitive patterns detected: ${hasSecrets ? "Yes" : "No"}\n\nRedacted content preview:\n${redacted}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if (path === "/.git/config" && result.body.includes("[core]")) {
      const hasSecrets = hasCredentialPattern(result.body);
      const snippet = hasSecrets ? redactCredentialValues(result.body.substring(0, 300)) : result.body.substring(0, 300);
      results.findings.push({
        title: `Exposed Git Repository on ${domain}`,
        description: hasSecrets
          ? `The .git directory at ${domain}/.git/config is publicly accessible and contains credential-like patterns. This can expose source code, commit history, and sensitive configuration.`
          : `The .git directory at ${domain}/.git/config is publicly accessible. This can expose source code, commit history, and potentially sensitive files.`,
        severity: hasSecrets ? "critical" : "high",
        category: hasSecrets ? "leaked_credential" : "data_leak",
        affectedAsset: domain,
        cvssScore: hasSecrets ? "9.0" : "7.5",
        remediation: "Block public access to .git directories. Configure web server rules to deny access to all dotfiles and directories.",
        evidence: [
          {
            type: "http_response",
            description: "Git configuration file publicly accessible",
            url: `https://${domain}${path}`,
            snippet: `HTTP Status: 200 OK\n\nContent preview:\n${snippet}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if (OSINT_CREDENTIAL_PATHS.includes(path) && result.body && hasCredentialPattern(result.body)) {
      const redacted = redactCredentialValues(result.body.substring(0, 500));
      results.findings.push({
        title: `Exposed Credential File (${path}) on ${domain}`,
        description: `The file ${path} at ${domain} is publicly accessible and contains credential-like patterns (passwords, API keys, tokens).`,
        severity: "critical",
        category: "leaked_credential",
        affectedAsset: domain,
        cvssScore: "9.8",
        remediation: "Immediately block public access to credential and configuration files. Rotate all exposed credentials.",
        evidence: [
          {
            type: "http_response",
            description: "Publicly accessible credential file with sensitive data patterns",
            url: `https://${domain}${path}`,
            snippet: `HTTP Status: 200 OK\n\nRedacted content preview:\n${redacted}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if (path === "/server-status" && result.body.includes("Apache Server Status")) {
      results.findings.push({
        title: `Apache Server Status Page Exposed on ${domain}`,
        description: `The Apache server-status page is publicly accessible at ${domain}/server-status. This reveals server internals including active connections, request details, and server configuration.`,
        severity: "medium",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Restrict access to /server-status to internal networks or specific IP addresses only.",
        evidence: [
          {
            type: "http_response",
            description: "Apache server-status page publicly accessible",
            url: `https://${domain}${path}`,
            snippet: `HTTP Status: 200 OK\nContent includes: Apache Server Status\n\nPreview:\n${result.body.substring(0, 300)}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if ((path === "/actuator" || path === "/actuator/health") && result.body && (result.body.includes('"status"') || result.body.includes("UP"))) {
      results.findings.push({
        title: `Spring Boot Actuator Exposed on ${domain}`,
        description: `The actuator endpoint at ${domain}${path} is publicly accessible. This may expose application health, metrics, and internal state.`,
        severity: "medium",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Restrict access to actuator endpoints. Use Spring Security to protect /actuator.",
        evidence: [
          {
            type: "http_response",
            description: "Spring Boot actuator publicly accessible",
            url: `https://${domain}${path}`,
            snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 300)}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if ((path === "/phpinfo.php" || path === "/info.php") && (result.body.includes("PHP Version") || result.body.includes("phpinfo()"))) {
      results.findings.push({
        title: `PHP Info Page Exposed on ${domain}`,
        description: `The phpinfo page at ${domain}${path} is publicly accessible. This reveals PHP version, loaded modules, environment variables, and server configuration.`,
        severity: "medium",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Remove or restrict access to phpinfo pages. Use them only in development environments.",
        evidence: [
          {
            type: "http_response",
            description: "phpinfo page publicly accessible",
            url: `https://${domain}${path}`,
            snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 300)}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if (result.body && (result.body.includes("Index of /") || result.body.includes("Directory listing"))) {
      results.findings.push({
        title: `Directory Listing Exposed on ${domain}${path}`,
        description: `Directory listing is enabled at ${domain}${path}. This exposes file structure and potentially sensitive files to enumeration.`,
        severity: "medium",
        category: "data_leak",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Disable directory listing in web server configuration.",
        evidence: [
          {
            type: "http_response",
            description: "Directory listing detected",
            url: `https://${domain}${path}`,
            snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 400)}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if (OSINT_DOCUMENT_PATHS.includes(path)) {
      results.findings.push({
        title: `Exposed Document Path (${path}) on ${domain}`,
        description: `The path ${path} at ${domain} is publicly accessible. This may expose documents, backups, or uploads.`,
        severity: "medium",
        category: "data_leak",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Restrict access to document directories. Ensure sensitive files are not publicly accessible.",
        evidence: [
          {
            type: "http_response",
            description: "Document path publicly accessible",
            url: `https://${domain}${path}`,
            snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 400)}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }

    if (path === "/robots.txt" && result.body) {
      const disallowLines = result.body.split("\n").filter(l => l.trim().toLowerCase().startsWith("disallow:"));
      const sensitiveDisallows = disallowLines.filter(l => {
        const path = l.split(":").slice(1).join(":").trim().toLowerCase();
        return /admin|backup|internal|private|secret|config|database|wp-admin|phpmyadmin|dashboard|api|debug/.test(path);
      });
      if (sensitiveDisallows.length > 0) {
        exposedPaths.push({ path, label, status: 200, snippet: result.body.substring(0, 500) });
      }
    }

    if ((path === "/swagger.json" || path === "/api/docs" || path === "/openapi.json") && result.body.length > 50) {
      results.findings.push({
        title: `Exposed API Documentation (Swagger/OpenAPI) on ${domain}`,
        description: `${path} at ${domain} is publicly accessible. This exposes API structure, endpoints, and potentially sensitive schema details.`,
        severity: "low",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "3.1",
        remediation: `Restrict access to ${path} or ensure it does not expose sensitive API details.`,
        evidence: [
          {
            type: "http_response",
            description: "Swagger/OpenAPI documentation publicly accessible",
            url: `https://${domain}${path}`,
            snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 400)}`,
            source: "HTTP GET request",
            verifiedAt: now,
            validated: pathValidation.validated,
            confidence: pathValidation.confidence,
          },
        ],
      });
      continue;
    }
  }

  if (exposedPaths.length > 0) {
    for (const ep of exposedPaths) {
      if (ep.path === "/robots.txt") {
        results.findings.push({
          title: `Robots.txt Reveals Sensitive Paths on ${domain}`,
          description: `The robots.txt file on ${domain} contains Disallow entries that hint at sensitive internal paths (admin panels, backups, databases, etc.). While robots.txt is informational, it gives attackers a map of hidden endpoints.`,
          severity: "info",
          category: "information_disclosure",
          affectedAsset: domain,
          cvssScore: "2.0",
          remediation: "Review robots.txt entries. Ensure listed paths are properly authenticated rather than relying on obscurity.",
          evidence: [
            {
              type: "http_response",
              description: "robots.txt reveals sensitive paths",
              url: `https://${domain}/robots.txt`,
              snippet: ep.snippet,
              source: "HTTP GET request",
              verifiedAt: now,
            },
          ],
        });
      } else {
        results.findings.push({
          title: `Publicly Accessible ${ep.label} on ${domain}`,
          description: `${ep.label} (${ep.path}) is publicly accessible at ${domain}. This may expose internal API structure or application details.`,
          severity: "low",
          category: "information_disclosure",
          affectedAsset: domain,
          cvssScore: "3.1",
          remediation: `Restrict access to ${ep.path} or ensure it does not expose sensitive information.`,
          evidence: [
            {
              type: "http_response",
              description: `${ep.label} publicly accessible`,
              url: `https://${domain}${ep.path}`,
              snippet: `HTTP Status: ${ep.status}\n\nPreview:\n${ep.snippet}`,
              source: "HTTP GET request",
              verifiedAt: now,
            },
          ],
        });
      }
    }
  }

  const dkimRecord = dkimTxt?.flat().find((r) => r.startsWith("v=DKIM1") || r.includes("p="));
  const cloudProviders = extractCloudProvidersFromSPF(spfAnalysis.record, mxRecords);
  results.reconData.emailSecurity = {
    spf: spfAnalysis,
    dmarc: dmarcAnalysis,
    dkim: {
      found: !!dkimRecord,
      selector: "default",
      record: dkimRecord ? dkimRecord.substring(0, 200) : undefined,
    },
    cloudProviders,
    mx: mxRecords,
    ns: nsRecords,
    txtRecords: txtRecords.flat(),
  };

  results.reconData.pathChecks = Object.fromEntries(
    pathCheckResults
      .filter((r) => r.result)
      .map((r) => {
        const { status, body, finalUrl } = r.result!;
        const validated = validatePathResponse(status, body, finalUrl, r.path);
        return [
          r.path,
          {
            status,
            accessible: validated.responseType === "success",
            responseType: validated.responseType,
            severity: validated.severity,
            validated: validated.validated,
            confidence: validated.confidence,
            redirectTarget: validated.redirectTarget,
          },
        ];
      }),
  );

  for (const r of pathCheckResults) {
    if (!r.result) continue;
    const { path, result } = r;
    if (path === "/robots.txt" && result.status === 200 && result.body) {
      (results.reconData as any).robotsTxt = result.body;
      break;
    }
  }
  for (const r of pathCheckResults) {
    if (!r.result) continue;
    const { path, result } = r;
    if (path === "/.well-known/security.txt" && result.status === 200 && result.body) {
      (results.reconData as any).securityTxt = { raw: result.body, parsed: parseSecurityTxt(result.body) };
      break;
    }
  }

  // Probe sensitive paths from robots.txt
  const robotsTxtContent = (results.reconData as any).robotsTxt as string | undefined;
  if (robotsTxtContent) {
    const sensitiveRobotPaths = extractSensitiveRobotsPaths(robotsTxtContent);
    const robotsProbeLimit = gold ? 50 : 15;
    const robotsToProbe = sensitiveRobotPaths.filter(p => !osintPaths.includes(p)).slice(0, robotsProbeLimit);
    if (robotsToProbe.length > 0) {
      console.log(`[Scanner] Probing ${robotsToProbe.length} sensitive paths from robots.txt for ${domain}`);
      const robotsResults = await runWithConcurrency(robotsToProbe, 4, async (p) => {
        const res = await httpGet(`https://${domain}${p}`);
        return { path: p, result: res };
      }, signal);
      for (const { path, result } of robotsResults.filter(r => r != null)) {
        if (!result || result.status !== 200 || !result.body) continue;
        if (soft404Fingerprint) {
          const fp = `${result.body.length}:${result.body.slice(0, 100).replace(/\s+/g, "")}`;
          if (fp === soft404Fingerprint) continue;
        }
        results.findings.push({
          title: `Sensitive Path from robots.txt Accessible on ${domain}: ${path}`,
          description: `A path listed in robots.txt (${path}) is publicly accessible. This path was hidden from crawlers but responds with content, potentially exposing sensitive data.`,
          severity: "medium",
          category: "data_leak",
          affectedAsset: domain,
          cvssScore: "5.3",
          remediation: `Restrict access to ${path} with proper authentication instead of relying on robots.txt.`,
          evidence: [{
            type: "http_response",
            description: "Path listed in robots.txt is publicly accessible",
            url: `https://${domain}${path}`,
            snippet: `HTTP Status: 200\nSource: robots.txt Disallow entry\nPreview:\n${result.body.substring(0, 300)}`,
            source: "robots.txt + HTTP GET",
            verifiedAt: now,
          }],
        });
      }
    }
  }

  checkAborted(signal);
  await report("Fetching sitemap and main page...", 80, "path_checks", 25);

  const sitemapUrls = await fetchSitemapUrls(domain, sitemapLimit);
  (results.reconData as any).sitemapUrls = sitemapUrls;

  const docUrls = sitemapUrls.filter((u) => {
    try {
      return DOCUMENT_EXTENSIONS.test(new URL(u).pathname);
    } catch {
      return false;
    }
  }).slice(0, gold ? 200 : 30);
  const docResults = await runWithConcurrency(
    docUrls,
    4,
    async (url) => {
      const res = await httpGet(url);
      return res && res.status === 200 ? { url, status: res.status } : null;
    },
    signal,
  );
  for (const dr of docResults) {
    if (dr) {
      results.findings.push({
        title: `Exposed Document in Sitemap on ${domain}`,
        description: `A document URL from the sitemap is publicly accessible: ${dr.url}. This may expose sensitive data.`,
        severity: "medium",
        category: "data_leak",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Restrict access to document files. Ensure sensitive documents are not linked in public sitemaps.",
        evidence: [
          {
            type: "http_response",
            description: "Document from sitemap publicly accessible",
            url: dr.url,
            snippet: `HTTP Status: ${dr.status} OK`,
            source: "HTTP GET request",
            verifiedAt: now,
          },
        ],
      });
    }
  }

  const mainPage = await httpGetMainPage(`https://${domain}`);
  if (mainPage) {
    (results.reconData as any).cookies = parseSetCookie(mainPage.setCookieStrings);
    (results.reconData as any).responseHeaders = mainPage.headers;
    (results.reconData as any).techStack = detectTechStack(mainPage.body, mainPage.headers);
    (results.reconData as any).socialTags = parseSocialTags(mainPage.body);
  }

  // Email harvesting with source attribution
  const emailSources = new Map<string, Set<string>>();
  function addEmail(email: string, source: string) {
    const lower = email.toLowerCase();
    if (!emailSources.has(lower)) emailSources.set(lower, new Set());
    emailSources.get(lower)!.add(source);
  }

  if (mainPage?.body) {
    for (const e of extractEmailsFromText(mainPage.body, domain)) addEmail(e, "Main page");
  }
  const securityTxtData = (results.reconData as any).securityTxt;
  if (securityTxtData?.raw) {
    for (const e of extractEmailsFromText(securityTxtData.raw, domain)) addEmail(e, "security.txt");
  }
  const sitemapSample = sitemapUrls.slice(0, gold ? 50 : 10);
  for (const surl of sitemapSample) {
    const res = await httpGet(surl);
    if (res?.body && res.status === 200) {
      for (const e of extractEmailsFromText(res.body, domain)) addEmail(e, "Sitemap");
    }
  }
  const EMAIL_PAGES_STANDARD = ["/about", "/contact", "/team", "/people", "/staff"];
  const EMAIL_PAGES_GOLD = [...EMAIL_PAGES_STANDARD, "/leadership", "/careers", "/jobs", "/press", "/news",
    "/blog", "/support", "/help", "/legal", "/imprint", "/about-us", "/contact-us", "/our-team", "/who-we-are"];
  const emailPages = gold ? EMAIL_PAGES_GOLD : EMAIL_PAGES_STANDARD;
  const emailPageResults = await runWithConcurrency(emailPages, 4, async (p) => {
    const res = await httpGet(`https://${domain}${p}`);
    if (res?.body && res.status === 200) return { emails: extractEmailsFromText(res.body, domain), source: p };
    return { emails: [], source: p };
  });
  for (const { emails, source } of emailPageResults) {
    for (const e of emails) addEmail(e, `Web page (${source})`);
  }

  // DNS email extraction
  for (const e of extractEmailsFromDNS(txtRecords, dmarcTxt)) addEmail(e, "DNS records (SPF/DMARC)");

  // WHOIS email extraction
  const whoisEmails = extractEmailsFromWhois(domainInfo as Record<string, string> | null);
  for (const e of whoisEmails) addEmail(e, "WHOIS registration");

  // Filter to domain-relevant emails and build finding
  const domainEmails = new Map<string, Set<string>>();
  const otherEmails: string[] = [];
  for (const [email, sources] of Array.from(emailSources)) {
    if (email.endsWith(`@${domain}`) || email.endsWith(`.${domain}`)) {
      domainEmails.set(email, sources);
    } else {
      otherEmails.push(email);
    }
  }

  if (domainEmails.size > 0) {
    const sourceGroups = new Map<string, string[]>();
    for (const [email, sources] of Array.from(domainEmails)) {
      const redacted = `${email.split("@")[0].slice(0, 2)}***@${email.split("@")[1]}`;
      for (const src of Array.from(sources)) {
        if (!sourceGroups.has(src)) sourceGroups.set(src, []);
        sourceGroups.get(src)!.push(redacted);
      }
    }
    const sourceLines = Array.from(sourceGroups.entries())
      .map(([src, emails]) => `${src}: ${emails.slice(0, 3).join(", ")}${emails.length > 3 ? ` (+${emails.length - 3} more)` : ""}`)
      .join("\n");
    results.findings.push({
      title: `Discovered ${domainEmails.size} email address(es) for ${domain}`,
      description: `Email addresses associated with ${domain} were found across ${sourceGroups.size} source(s) including web pages, DNS records, and WHOIS data.`,
      severity: "info",
      category: "osint_exposure",
      affectedAsset: domain,
      cvssScore: "2.0",
      remediation: "Consider whether exposed emails should be public. Use contact forms instead of raw email addresses where possible.",
      evidence: [{
        type: "osint",
        description: "Email addresses discovered from public sources",
        snippet: `Found ${domainEmails.size} email(s) from ${sourceGroups.size} source(s):\n${sourceLines}`,
        source: Array.from(sourceGroups.keys()).join(", "),
        verifiedAt: now,
      }],
    });
  }

  if (otherEmails.length > 0) {
    results.findings.push({
      title: `WHOIS/DNS Contact Emails Discovered for ${domain}`,
      description: `${otherEmails.length} contact email(s) not matching the target domain were found in WHOIS or DNS records.`,
      severity: "info",
      category: "osint_exposure",
      affectedAsset: domain,
      cvssScore: "2.0",
      remediation: "Review WHOIS privacy settings. Consider using domain privacy protection.",
      evidence: [{
        type: "osint",
        description: "Non-domain contact emails from WHOIS/DNS",
        snippet: `Contact emails: ${otherEmails.slice(0, 5).join(", ")}${otherEmails.length > 5 ? ` (+${otherEmails.length - 5} more)` : ""}`,
        source: "WHOIS lookup, DNS records",
        verifiedAt: now,
      }],
    });
  }

  // --- Phase 3: External API integrations ---
  checkAborted(signal);
  await report("Checking credential leaks (HIBP, dorks)...", 75, "credential_apis", 40);

  // 3A: Tavily Google dork for credentials
  try {
    const { searchTavilyDork } = await import("../tavily-service.js");
    const credDorkQueries = gold
      ? [`site:pastebin.com "${domain}" password OR api_key`, `site:github.com "${domain}" password OR secret`, `"${domain}" filetype:env password`]
      : [`site:pastebin.com "${domain}" password OR api_key OR token`];
    for (const query of credDorkQueries) {
      const dorkResults = await searchTavilyDork(query);
      for (const r of dorkResults) {
        if (!r.url || !r.title) continue;
        results.findings.push({
          title: `Potential Credential Leak Found via Google Dorking for ${domain}`,
          description: `A search result mentioning ${domain} with credential-related keywords was found on ${new URL(r.url).hostname}.`,
          severity: "medium",
          category: "leaked_credential",
          affectedAsset: domain,
          cvssScore: "5.3",
          remediation: "Investigate the URL for exposed credentials. Request takedown if confirmed.",
          evidence: [{
            type: "osint",
            description: "Google dork result mentioning credentials",
            url: r.url,
            snippet: `Title: ${r.title}\nURL: ${r.url}\nExcerpt: ${r.content.slice(0, 300)}`,
            source: "Tavily Google Dork Search",
            verifiedAt: now,
          }],
        });
      }
    }
  } catch (err) {
    console.warn("[Scanner] Tavily credential dork failed:", err instanceof Error ? err.message : err);
  }

  // 3A: Tavily Google dork for documents
  try {
    const { searchTavilyDork } = await import("../tavily-service.js");
    const docDorkQueries = gold
      ? [`site:${domain} filetype:pdf OR filetype:doc OR filetype:xlsx OR filetype:csv`, `site:${domain} filetype:sql OR filetype:bak OR filetype:log`]
      : [`site:${domain} filetype:pdf OR filetype:doc OR filetype:xlsx`];
    for (const query of docDorkQueries) {
      const dorkResults = await searchTavilyDork(query);
      for (const r of dorkResults) {
        if (!r.url) continue;
        results.findings.push({
          title: `Exposed Document Found via Google Dorking for ${domain}`,
          description: `A document associated with ${domain} was found indexed by search engines.`,
          severity: "medium",
          category: "data_leak",
          affectedAsset: domain,
          cvssScore: "5.3",
          remediation: "Review the document for sensitive content. Remove from public access if needed.",
          evidence: [{
            type: "osint",
            description: "Document found via Google dork search",
            url: r.url,
            snippet: `Title: ${r.title}\nURL: ${r.url}\nExcerpt: ${r.content.slice(0, 300)}`,
            source: "Tavily Google Dork Search",
            verifiedAt: now,
          }],
        });
      }
    }
  } catch (err) {
    console.warn("[Scanner] Tavily document dork failed:", err instanceof Error ? err.message : err);
  }

  // 3B: HIBP Pwned Passwords check on any extracted credential values
  const credentialValues: string[] = [];
  for (const r of pathCheckResults) {
    if (!r.result || r.result.status !== 200 || !r.result.body) continue;
    if (!OSINT_CREDENTIAL_PATHS.includes(r.path) && r.path !== "/.env" && r.path !== "/.git/config") continue;
    const matches = r.result.body.match(/(?:password|passwd|secret|token|api_key|apikey|db_pass|database_url)\s*[=:]\s*["']?([^\s"'\r\n]+)["']?/gi);
    if (matches) {
      for (const m of matches) {
        const val = m.split(/[=:]\s*["']?/)[1]?.replace(/["']$/, "");
        if (val && val.length >= 6 && val !== "null" && val !== "undefined" && val !== "true" && val !== "false") {
          credentialValues.push(val);
        }
      }
    }
  }
  if (credentialValues.length > 0) {
    console.log(`[Scanner] Checking ${Math.min(credentialValues.length, gold ? 20 : 5)} extracted credentials against HIBP...`);
    const hibpResults = await checkHIBPPasswords(credentialValues, gold);
    for (const { redacted, breachCount } of hibpResults) {
      results.findings.push({
        title: `Breached Password Detected in Exposed File on ${domain}`,
        description: `A password extracted from an exposed configuration file has been found in ${breachCount.toLocaleString()} known data breach(es). This indicates the credential is compromised.`,
        severity: "critical",
        category: "leaked_credential",
        affectedAsset: domain,
        cvssScore: "9.8",
        remediation: "Immediately rotate this credential. Audit all systems using this password.",
        evidence: [{
          type: "osint",
          description: "Password found in known data breaches",
          snippet: `Redacted credential: ${redacted}\nFound in ${breachCount.toLocaleString()} known breach(es)`,
          source: "Have I Been Pwned Pwned Passwords API (k-anonymity)",
          verifiedAt: now,
        }],
      });
    }
  }

  // 3C: S3 bucket enumeration
  checkAborted(signal);
  await report("Checking S3 bucket patterns...", 85, "s3_check", 20);
  try {
    const s3BucketResults = await checkS3Buckets(domain, gold);
    for (const { bucket, listable } of s3BucketResults) {
      results.findings.push({
        title: listable ? `Publicly Listable S3 Bucket Found: ${bucket}` : `S3 Bucket Exists for ${domain}: ${bucket}`,
        description: listable
          ? `The S3 bucket "${bucket}" is publicly listable, potentially exposing all stored files and data.`
          : `An S3 bucket named "${bucket}" exists and is associated with ${domain}.`,
        severity: listable ? "high" : "info",
        category: "data_leak",
        affectedAsset: domain,
        cvssScore: listable ? "7.5" : "2.0",
        remediation: listable
          ? "Immediately disable public access on this S3 bucket. Review bucket policies and ACLs."
          : "Verify this bucket's access policies are properly configured.",
        evidence: [{
          type: "osint",
          description: listable ? "S3 bucket is publicly listable" : "S3 bucket exists",
          url: `https://${bucket}.s3.amazonaws.com/`,
          snippet: listable ? "Bucket returns ListBucketResult XML — all objects are publicly enumerable" : "Bucket exists but is not publicly listable",
          source: "S3 bucket enumeration",
          verifiedAt: now,
        }],
      });
    }
  } catch (err) {
    console.warn("[Scanner] S3 bucket check failed:", err instanceof Error ? err.message : err);
  }

  // 3D+3E: PGP key server + crt.sh email extraction (gold only)
  if (gold) {
    try {
      const [pgpEmails, crtEmails] = await Promise.all([
        searchPGPKeyServer(domain),
        extractEmailsFromCrtSh(domain),
      ]);
      for (const e of pgpEmails) addEmail(e, "PGP key server");
      for (const e of crtEmails) addEmail(e, "Certificate Transparency (crt.sh)");
      // Check if these added new domain emails not already in findings
      const newDomainEmails: string[] = [];
      for (const e of [...pgpEmails, ...crtEmails]) {
        if ((e.endsWith(`@${domain}`) || e.endsWith(`.${domain}`)) && !domainEmails.has(e.toLowerCase())) {
          newDomainEmails.push(e);
        }
      }
      if (newDomainEmails.length > 0) {
        results.findings.push({
          title: `${newDomainEmails.length} Additional Email(s) Found via PGP/Certificate Transparency for ${domain}`,
          description: `Additional email addresses were discovered through PGP key servers and Certificate Transparency logs.`,
          severity: "info",
          category: "osint_exposure",
          affectedAsset: domain,
          cvssScore: "2.0",
          remediation: "Review whether these email addresses should be publicly associated with your domain.",
          evidence: [{
            type: "osint",
            description: "Emails from PGP key servers and certificate transparency",
            snippet: `Emails: ${newDomainEmails.slice(0, 5).map(e => `${e.split("@")[0].slice(0, 2)}***@${e.split("@")[1]}`).join(", ")}`,
            source: "PGP key server, crt.sh",
            verifiedAt: now,
          }],
        });
      }
    } catch (err) {
      console.warn("[Scanner] PGP/crt.sh email search failed:", err instanceof Error ? err.message : err);
    }
  }

  const firstIp = dnsRecords.a && dnsRecords.a[0];
  const osintPortList = gold ? GOLD_PORTS : [21, 22, 80, 443, 8080, 8443, 3306, 5432, 27017, 6379, 5984];
  const nonHttpPorts = [21, 22, 25, 53, 110, 143, 445, 993, 995, 1433, 3306, 5432, 27017, 6379, 5984, 11211];
  if (firstIp) {
    const [location, openPorts] = await Promise.all([
      getServerLocation(firstIp),
      scanOpenPorts(firstIp, osintPortList),
    ]);
    if (location) (results.reconData as any).serverLocation = location;
    (results.reconData as any).openPorts = openPorts;
    const exposedNonHttp = openPorts.filter((p) => nonHttpPorts.includes(p));
    if (exposedNonHttp.length > 0) {
      const portNames: Record<number, string> = { 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 5984: "CouchDB", 11211: "Memcached", 27017: "MongoDB" };
      results.findings.push({
        title: `Exposed Non-HTTP Ports on ${domain}`,
        description: `Non-HTTP ports are open on ${firstIp}: ${exposedNonHttp.map((p) => `${p} (${portNames[p] || "unknown"})`).join(", ")}. This reveals infrastructure details.`,
        severity: "medium",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Restrict access to database and management ports. Use firewall rules to limit exposure.",
        evidence: [
          {
            type: "port_scan",
            description: "Open non-HTTP ports detected",
            snippet: `Open ports: ${exposedNonHttp.join(", ")}`,
            source: "TCP port scan",
            verifiedAt: now,
          },
        ],
      });
    }
  }
  const dnssec = await checkDNSSEC(domain);
  (results.reconData as any).dnssec = dnssec;

  await report("OSINT scan complete.", 100, "build_modules", 0);
  console.log(`[Scanner] OSINT scan complete for ${domain}: ${results.findings.length} verified findings`);
  return results;
}

export interface NucleiHit {
  templateId: string;
  templateName?: string;
  severity: string;
  host: string;
  matchedAt?: string;
  type?: string;
  info?: { name?: string; description?: string };
  matcherName?: string;
  extractedResults?: string[];
}

export interface NucleiScanResult {
  findings: VerifiedFinding[];
  nucleiResults: NucleiHit[];
  templateCount?: number;
  skipped?: boolean;
  reason?: string;
}

export async function runNucleiScan(
  domain: string,
  urls: string[],
  onProgress?: ScanProgressCallback,
  options?: ScanOptions,
): Promise<NucleiScanResult> {
  const signal = options?.signal;
  const report = async (msg: string, pct: number, step: string, eta?: number) => {
    checkAborted(signal);
    if (onProgress) await onProgress(msg, pct, step, eta);
  };

  const targetUrls = Array.from(new Set(urls.length > 0 ? urls : [`https://${domain}`, `http://${domain}`]));
  const targetUrlsNormalized = targetUrls.map((u) => {
    try {
      const parsed = new URL(u.startsWith("http") ? u : `https://${u}`);
      return parsed.origin;
    } catch {
      return u.startsWith("http") ? u : `https://${u}`;
    }
  });

  const goBin = path.join(os.homedir(), "go", "bin");
  const pathWithGo = [goBin, process.env.PATH].filter(Boolean).join(path.delimiter);
  const spawnEnv = { ...process.env, PATH: pathWithGo };

  const checkNuclei = (nucleiPath: string): Promise<boolean> =>
    new Promise((resolve) => {
      const proc = spawn(nucleiPath, ["-version"], { stdio: ["ignore", "pipe", "pipe"], env: spawnEnv });
      proc.stdout?.on("data", () => {});
      proc.stderr?.on("data", () => {});
      proc.on("close", (code) => resolve(code === 0));
      proc.on("error", () => resolve(false));
    });

  let nucleiPath = "nuclei";
  if (!(await checkNuclei("nuclei"))) {
    const altPath = path.join(goBin, "nuclei");
    if (await checkNuclei(altPath)) {
      nucleiPath = altPath;
    }
  }
  const isAvailable = await checkNuclei(nucleiPath);
  if (!isAvailable) {
    throw new Error(
      "Nuclei is required for full scans but is not installed or not in PATH. " +
      "Use Docker: docker compose up -d (app image includes Nuclei). " +
      "Or install locally: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    );
  }

  const isGoldScan = options?.mode === "gold";
  // Standard: 8 min cap (severity + http-only); Gold: 30 min full scan
  const NUCLEI_MAX_DURATION_MS = isGoldScan ? 30 * 60 * 1000 : 8 * 60 * 1000;
  await report(`Running Nuclei scan against ${targetUrls.length} target(s)...`, 0, "nuclei_scan", 300);
  const tempFile = path.join(os.tmpdir(), `nuclei-targets-${Date.now()}-${Math.random().toString(36).slice(2)}.txt`);
  try {
    await fs.writeFile(tempFile, targetUrlsNormalized.join("\n"), "utf-8");
  } catch (err) {
    console.error("[Scanner] Failed to write Nuclei targets file:", err);
    throw new Error("Failed to write Nuclei targets file: " + (err instanceof Error ? err.message : String(err)));
  }

  const nucleiResults: NucleiHit[] = [];
  const findings: VerifiedFinding[] = [];
  const now = new Date().toISOString();

  let procRef: ReturnType<typeof spawn> | null = null;
  const nucleiPromise = new Promise<NucleiScanResult>((resolve, reject) => {
    const args = [
      "-l", tempFile, "-jsonl", "-silent", "-no-color",
      "-timeout", "30",
      "-rate-limit", isGoldScan ? "150" : "100",
      "-bulk-size", isGoldScan ? "25" : "15",
      "-concurrency", isGoldScan ? "25" : "15",
      // Standard: targeted template dirs (~2.5k templates) — fast + relevant for EASM
      // Gold: all templates, all severities (full 12k+ templates)
      ...(isGoldScan
        ? []
        : ["-t", "http/technologies/", "-t", "http/misconfiguration/", "-t", "http/exposures/"]),
    ];
    const proc = spawn(nucleiPath, args, { stdio: ["ignore", "pipe", "pipe"], env: spawnEnv });
    procRef = proc;
    let buffer = "";
    let templatesSeen = 0;
    let lastProgressReport = Date.now();

    proc.stdout?.on("data", (chunk: Buffer) => {
      buffer += chunk.toString();
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const j = JSON.parse(line) as Record<string, unknown>;
          const templateId = String(j["template-id"] ?? j.templateID ?? "");
          const info = j.info as Record<string, unknown> | undefined;
          const hit: NucleiHit = {
            templateId,
            templateName: (info?.name as string) ?? (j["template-name"] as string),
            severity: String(info?.severity ?? j.severity ?? "info").toLowerCase(),
            host: String(j.host ?? j["matched-at"] ?? ""),
            matchedAt: j["matched-at"] ? String(j["matched-at"]) : (j.matched ? String(j.matched) : undefined),
            type: j.type as string | undefined,
            info: info ? { name: info.name as string, description: info.description as string } : undefined,
            matcherName: j["matcher-name"] as string | undefined,
            extractedResults: j["extracted-results"] as string[] | undefined,
          };
          nucleiResults.push(hit);
          templatesSeen++;

          // Report progress every 30 seconds
          const now2 = Date.now();
          if (now2 - lastProgressReport > 30000) {
            lastProgressReport = now2;
            report(`Nuclei scanning... ${templatesSeen} template hit(s) so far on ${targetUrls.length} target(s)`, 50, "nuclei_scan").catch(() => {});
          }

          const severityMap: Record<string, string> = {
            critical: "critical",
            high: "high",
            medium: "medium",
            low: "low",
            info: "info",
          };
          const severity = severityMap[hit.severity] ?? "info";
          // Many Nuclei template IDs encode the CVE directly, e.g. "CVE-2021-44228"
          const cveMatch = templateId.match(/\b(CVE-\d{4}-\d+)\b/i);
          const detectedCveId = cveMatch ? cveMatch[1].toUpperCase() : undefined;
          findings.push({
            title: `${(info?.name as string) ?? templateId} on ${hit.host}`,
            description: (info?.description as string) ?? `Nuclei template ${templateId} matched at ${hit.host}`,
            severity,
            category: "vulnerability",
            affectedAsset: hit.host,
            cvssScore: severity === "critical" ? "9.0" : severity === "high" ? "7.5" : severity === "medium" ? "5.5" : "3.0",
            remediation: "Review the vulnerability and apply patches or mitigations as recommended by the template.",
            evidence: [
              {
                type: "nuclei",
                description: `Nuclei template ${templateId} matched`,
                snippet: hit.matchedAt ? `Matched at: ${hit.matchedAt}` : hit.templateName ?? templateId,
                source: "Nuclei scanner",
                verifiedAt: now,
                ...(detectedCveId ? { cveId: detectedCveId } : {}),
              },
            ],
          });
        } catch {
          // Skip malformed JSONL lines
        }
      }
    });

    let stderrBuf = "";
    proc.stderr?.on("data", (d) => {
      stderrBuf += d.toString();
      const lines = stderrBuf.split("\n");
      stderrBuf = lines.pop() ?? "";
      for (const line of lines) {
        const clean = line.replace(/\x1b\[[0-9;]*m/g, "").trim(); // strip ANSI codes
        if (!clean) continue;
        // Show nuclei template load/scan progress
        if (clean.includes("templates") || clean.includes("Executing") || clean.includes("INF")) {
          console.log("[Nuclei]", clean);
        }
      }
    });

    proc.on("close", (code, sig) => {
      fs.unlink(tempFile).catch(() => {});
      if (signal?.aborted) {
        reject(new Error("Scan aborted"));
        return;
      }
      if (code !== 0 && code !== null && nucleiResults.length === 0) {
        console.warn("[Scanner] Nuclei exited with code", code, "signal", sig);
      }
      resolve({
        findings,
        nucleiResults,
        templateCount: nucleiResults.length,
      });
    });

    proc.on("error", (err) => {
      fs.unlink(tempFile).catch(() => {});
      reject(err);
    });

    signal?.addEventListener?.("abort", () => {
      try {
        proc.kill("SIGTERM");
      } catch {}
    });
  });

  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  const timeoutPromise = new Promise<NucleiScanResult>((resolve) => {
    timeoutId = setTimeout(() => {
      timeoutId = null;
      if (procRef) {
        console.warn(`[Scanner] Nuclei scan exceeded max duration (${Math.round(NUCLEI_MAX_DURATION_MS / 60000)} min), terminating`);
        try {
          procRef.kill("SIGTERM");
          // Give 3s for graceful shutdown before SIGKILL
          setTimeout(() => { try { procRef?.kill("SIGKILL"); } catch {} }, 3000);
        } catch {}
      }
      // Wait 4s for final stdout flush before resolving
      setTimeout(() => {
        procRef = null;
        fs.unlink(tempFile).catch(() => {});
        resolve({
          findings,
          nucleiResults,
          templateCount: nucleiResults.length,
        });
      }, 4000);
    }, NUCLEI_MAX_DURATION_MS);
  });

  const result = await Promise.race([nucleiPromise, timeoutPromise]).finally(() => {
    if (timeoutId) clearTimeout(timeoutId);
  });

  // Enrich Nuclei findings that contain a CVE ID with CISA KEV data
  const kevEnrichments = result.findings.map(async (finding) => {
    const evidence = finding.evidence ?? [];
    for (const ev of evidence) {
      const cveId = ev.cveId as string | undefined;
      if (!cveId) continue;
      try {
        const kevInfo = await checkCISAKEV(cveId);
        if (kevInfo?.inKEV) {
          ev.kev = {
            inKEV: true,
            dueDate: kevInfo.dueDate,
            knownRansomware: kevInfo.knownRansomware,
            notes: kevInfo.notes,
          };
          // Flag the finding description so it's visible without drilling into evidence
          finding.description = `[CISA KEV] ${finding.description}`;
        }
      } catch {
        // KEV enrichment failure is non-fatal
      }
    }
  });
  await Promise.allSettled(kevEnrichments);

  return result;
}

export async function buildReconModules(
  domain: string,
  easmResults: ScanResults | null,
  osintResults: ScanResults | null,
): Promise<Array<{ moduleType: string; data: Record<string, unknown>; confidence: number }>> {
  const modules: Array<{ moduleType: string; data: Record<string, unknown>; confidence: number }> = [];

  if (easmResults) {
    const dnsRecon = easmResults.reconData.dns as any;
    const discoveredDomains = (easmResults.reconData as any).discoveredDomains || [];
    const liveCount = discoveredDomains.length || (dnsRecon?.liveSubdomains || []).length;
    modules.push({
      moduleType: "web_presence",
      confidence: 95,
      data: {
        source: "Certificate Transparency (crt.sh) + DNS resolution + HTTP probing + subdomain bruteforce",
        totalSubdomains: easmResults.subdomains.length,
        totalSubdomainsEnumerated: easmResults.subdomains.length,
        liveServices: liveCount,
        newSinceLastRun: 0,
        screenshots: [],
        discoveredDomains,
        liveSubdomains: dnsRecon?.liveSubdomains || [],
        danglingCnames: dnsRecon?.danglingCnames || [],
        subdomainBruteforce: easmResults.reconData.subdomainBruteforce || null,
        verifiedAt: new Date().toISOString(),
      },
    });

    if (easmResults.reconData.ssl) {
      const ssl = easmResults.reconData.ssl as { daysRemaining?: number; protocol?: string };
      let tlsGrade = "F";
      if (ssl.daysRemaining != null && ssl.daysRemaining <= 0) tlsGrade = "F";
      else if (ssl.daysRemaining != null && ssl.daysRemaining > 0) {
        const proto = (ssl.protocol || "").toLowerCase();
        if ((proto === "tlsv1.2" || proto === "tlsv1.3") && ssl.daysRemaining > 30) tlsGrade = "A";
        else if (proto === "tlsv1.2" || proto === "tlsv1.3") tlsGrade = "B";
        else tlsGrade = "C";
      }
      const rawHeaders = easmResults.reconData.securityHeaders as Record<string, { present?: boolean; value?: string | null; grade?: string }> | undefined;
      const securityHeaders: Record<string, { present: boolean; value: string | null; grade: string }> = {};
      if (rawHeaders) {
        for (const [k, v] of Object.entries(rawHeaders)) {
          const present = !!v?.present;
          securityHeaders[k] = { present, value: v?.value ?? null, grade: v?.grade ?? (present ? "A" : "N/A") };
        }
      }
      const ips = (dnsRecon?.ips || []) as string[];
      const openPorts = (easmResults.reconData as any).openPorts as number[] | undefined;
      const openPortsByIp = (easmResults.reconData as any).openPortsByIp as Record<string, number[]> | undefined;
      const PORT_SERVICES: Record<number, string> = { 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 11211: "Memcached", 27017: "MongoDB" };
      const publicIPs = ips.map((ip) => ({
        ip,
        banner: "",
        services: ((openPortsByIp?.[ip] ?? openPorts) || []).map((p) => PORT_SERVICES[p] || `Port ${p}`),
        openPorts: openPortsByIp?.[ip] ?? openPorts ?? [],
      }));

      const mainHeaders = (easmResults.reconData.serverInfo as any)?.allHeaders as Record<string, string> | undefined;
      const mainWaf = mainHeaders ? detectWAF(mainHeaders) : { detected: false, provider: "" };
      const mainCdn = mainHeaders ? detectCDN(mainHeaders) : "None";

      const wafByHost: Record<string, { waf: boolean; wafProvider: string; cdn: string }> = {};
      if (mainHeaders) wafByHost[domain] = { waf: mainWaf.detected, wafProvider: mainWaf.provider, cdn: mainCdn };
      for (const d of discoveredDomains) {
        wafByHost[d.domain] = { waf: d.waf, wafProvider: d.wafProvider || "", cdn: d.cdn || "None" };
      }

      const wafCoverage = Object.values(wafByHost).filter(v => v.waf).length;
      const totalHosts = Object.keys(wafByHost).length;

      const serverLeaks = ((easmResults.reconData.serverInfo as any)?.leaks || []) as string[];
      const { score: surfaceRiskScore, breakdown: riskBreakdown } = computeSurfaceRiskScore(tlsGrade, securityHeaders, serverLeaks);

      const perAssetTls = (easmResults.reconData as any).perAssetTls as Record<string, { daysRemaining?: number; protocol?: string; issuer?: string } | null> | undefined;
      const perAssetHeaders = (easmResults.reconData as any).perAssetHeaders as Record<string, Record<string, { present?: boolean }>> | undefined;
      const perAssetLeaks = (easmResults.reconData as any).perAssetLeaks as Record<string, string[]> | undefined;

      const domainToIp = new Map<string, string>();
      domainToIp.set(domain, ips[0] || "-");
      for (const d of discoveredDomains) {
        domainToIp.set(d.domain, (d as any).ip || "-");
      }

      const assetInventory: Array<{ host: string; ip: string; category: string; riskScore: number; tlsGrade: string; waf: string; cdn: string }> = [];
      for (const host of Object.keys(wafByHost)) {
        const wafInfo = wafByHost[host];
        const hostTls = perAssetTls?.[host];
        const hostHeaders = perAssetHeaders?.[host];
        const hostLeaks = perAssetLeaks?.[host] || [];
        let hostTlsGrade = tlsGrade;
        if (hostTls) {
          const proto = (hostTls.protocol || "").toLowerCase();
          if (hostTls.daysRemaining != null && hostTls.daysRemaining > 0) {
            if ((proto === "tlsv1.2" || proto === "tlsv1.3") && hostTls.daysRemaining > 30) hostTlsGrade = "A";
            else if (proto === "tlsv1.2" || proto === "tlsv1.3") hostTlsGrade = "B";
            else hostTlsGrade = "C";
          } else hostTlsGrade = "F";
        }
        const missingHdrs = hostHeaders ? Object.values(hostHeaders).filter((h) => !h?.present).length : 7;
        const hostRisk = gradeToRisk(hostTlsGrade) + Math.min(40, missingHdrs * 8) + Math.min(30, hostLeaks.length * 10);
        const riskScore = Math.min(100, hostRisk);
        const category = /api\.|app\.|dev\.|staging\./i.test(host) ? "api" : "web_app";
        assetInventory.push({
          host,
          ip: domainToIp.get(host) || "-",
          category,
          riskScore,
          tlsGrade: hostTlsGrade,
          waf: wafInfo.waf ? wafInfo.wafProvider : "",
          cdn: wafInfo.cdn !== "None" ? wafInfo.cdn : "",
        });
      }
      if (assetInventory.length === 0 && ips.length > 0) {
        assetInventory.push({
          host: domain,
          ip: ips[0],
          category: "web_app",
          riskScore: surfaceRiskScore,
          tlsGrade,
          waf: mainWaf.detected ? mainWaf.provider : "",
          cdn: mainCdn !== "None" ? mainCdn : "",
        });
      }

      modules.push({
        moduleType: "attack_surface",
        confidence: 95,
        data: {
          source: "TLS connection + HTTP header analysis + WAF/CDN detection",
          ssl: easmResults.reconData.ssl,
          tlsPosture: { grade: tlsGrade },
          securityHeaders,
          serverInfo: easmResults.reconData.serverInfo ? { leaks: serverLeaks } : {},
          dns: { ns: dnsRecon?.ns || [], ips },
          publicIPs,
          openPortsByIp: openPortsByIp || {},
          surfaceRiskScore,
          riskBreakdown,
          wafDetection: mainWaf,
          cdnDetection: mainCdn,
          wafByHost,
          wafCoverage: { protected: wafCoverage, total: totalHosts },
          perAssetTls: perAssetTls || {},
          perAssetHeaders: perAssetHeaders || {},
          perAssetLeaks: perAssetLeaks || {},
          assetInventory,
          verifiedAt: new Date().toISOString(),
        },
      });
    } else if (easmResults && (dnsRecon?.ips?.length || 0) > 0) {
      const ips = (dnsRecon?.ips || []) as string[];
      const openPorts = (easmResults.reconData as any).openPorts as number[] | undefined;
      const PORT_SERVICES: Record<number, string> = { 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 11211: "Memcached", 27017: "MongoDB" };
      const publicIPs = ips.map((ip) => ({
        ip,
        banner: "",
        services: (openPorts || []).map((p) => PORT_SERVICES[p] || `Port ${p}`),
      }));
      modules.push({
        moduleType: "attack_surface",
        confidence: 70,
        data: {
          source: "DNS resolution (TLS check unavailable)",
          securityHeaders: {},
          publicIPs,
          surfaceRiskScore: 50,
          riskBreakdown: [{ category: "TLS/Certificate", score: 50, maxScore: 100 }],
          wafDetection: { detected: false, provider: "" },
          cdnDetection: "None",
          dns: { ns: dnsRecon?.ns || [], ips },
          verifiedAt: new Date().toISOString(),
        },
      });
    }
  }

  if (osintResults) {
    const emailSec = osintResults.reconData.emailSecurity as any;
    if (emailSec) {
      const spf = emailSec.spf as { found: boolean; record: string; issues: string[] } | undefined;
      const dmarc = emailSec.dmarc as { found: boolean; record: string; issues: string[] } | undefined;
      const dkim = emailSec.dkim as { found: boolean; selector?: string; record?: string } | undefined;
      const cloudProviders = (emailSec.cloudProviders as Array<{ provider: string; confidence: number; evidence: string[] }>) ?? [];
      const spfGrade = !spf?.found ? "F" : (spf.issues?.length ?? 0) === 0 ? "A" : spf.record?.includes("+all") ? "D" : "B";
      const dmarcGrade = !dmarc?.found ? "F" : (dmarc.issues?.length ?? 0) === 0 ? "A" : dmarc.record?.includes("p=none") ? "C" : "B";
      const dkimGrade = dkim?.found ? "A" : "N/A";
      const gradeNum = (g: string) => ({ A: 4, B: 3, C: 2, D: 1, F: 0 }[g] ?? 0);
      const overallNum = dkimGrade === "N/A"
        ? (gradeNum(spfGrade) + gradeNum(dmarcGrade)) / 2
        : (gradeNum(spfGrade) + gradeNum(dmarcGrade) + gradeNum(dkimGrade)) / 3;
      const overallGrade = overallNum >= 3.5 ? "A" : overallNum >= 2.5 ? "B" : overallNum >= 1.5 ? "C" : overallNum >= 0.5 ? "D" : "F";
      modules.push({
        moduleType: "cloud_footprint",
        confidence: 90,
        data: {
          source: "DNS MX/TXT record analysis",
          grades: { spf: spfGrade, dmarc: dmarcGrade, dkim: dkimGrade, overall: overallGrade },
          emailSecurity: {
            spf: spf ? { status: spf.found && (spf.issues?.length ?? 0) === 0 ? "pass" : spf.found ? "fail" : "none", record: spf.record || "", issue: (spf.issues?.length ? spf.issues.join("; ") : undefined) } : undefined,
            dmarc: dmarc ? { status: dmarc.found && (dmarc.issues?.length ?? 0) === 0 ? "pass" : dmarc.found ? "fail" : "none", record: dmarc.record || "", issue: (dmarc.issues?.length ? dmarc.issues.join("; ") : undefined) } : undefined,
            dkim: dkim ? { status: dkim.found ? "pass" : "none", selector: dkim.selector, record: dkim.record } : undefined,
            mx: emailSec.mx,
          },
          cloudProviders,
          verifiedAt: new Date().toISOString(),
        },
      });
    }

    const pathChecks = osintResults.reconData.pathChecks as Record<string, { status: number; accessible: boolean; responseType?: string; severity?: string; validated?: boolean; confidence?: string; redirectTarget?: string }> | undefined;
    const rawDirBrute = osintResults.reconData.directoryBruteforce as { wordlistSource: string; tried: number; hits: Array<{ path: string; status: number; responseType?: string; severity?: string; validated?: boolean; confidence?: string; redirectTarget?: string }> } | undefined;
    const directoryBruteforce = rawDirBrute
      ? {
          ...rawDirBrute,
          hits: (rawDirBrute.hits || []).map((h) => ({
            ...h,
            evidenceUrl: `https://${domain}${h.path}`,
          })),
        }
      : null;
    if (pathChecks || directoryBruteforce) {
      const now = new Date().toISOString();
      const publicFiles = pathChecks ? Object.entries(pathChecks).map(([path, v]) => ({
        path,
        type: path.replace(/^\//, "").replace(/\//g, " ") || "path",
        severity: v.severity ?? (v.accessible ? "low" : "info"),
        responseType: v.responseType ?? "other",
        validated: v.validated,
        confidence: v.confidence,
        redirectTarget: v.redirectTarget,
        firstSeen: now,
        evidenceUrl: `https://${domain}${path}`,
      })) : [];
      modules.push({
        moduleType: "exposed_content",
        confidence: 95,
        data: {
          source: "HTTP path probing + directory bruteforce",
          pathChecks: pathChecks || {},
          publicFiles,
          directoryBruteforce,
          verifiedAt: now,
        },
      });
    }

    if (osintResults.reconData.dnsRecords) {
      modules.push({
        moduleType: "dns_overview",
        confidence: 95,
        data: {
          source: "DNS resolution",
          dnsRecords: osintResults.reconData.dnsRecords,
          dnssec: osintResults.reconData.dnssec,
          verifiedAt: new Date().toISOString(),
        },
      });
    }
    if (osintResults.reconData.redirectChain && (osintResults.reconData.redirectChain as unknown as any[]).length > 0) {
      modules.push({
        moduleType: "redirect_chain",
        confidence: 95,
        data: {
          source: "HTTP redirect chain",
          redirectChain: osintResults.reconData.redirectChain,
          verifiedAt: new Date().toISOString(),
        },
      });
    }
    if (osintResults.reconData.domainInfo && Object.keys(osintResults.reconData.domainInfo as object).length > 0) {
      modules.push({
        moduleType: "domain_info",
        confidence: 90,
        data: {
          source: "WHOIS lookup",
          domainInfo: osintResults.reconData.domainInfo,
          verifiedAt: new Date().toISOString(),
        },
      });
    }
    const techStack = (osintResults.reconData as any).techStack as Array<{ name: string; source: string }> | undefined;
    if (techStack && techStack.length > 0) {
      const frontendKeywords = /react|vue|angular|jquery|bootstrap|tailwind|next\.js|nuxt|svelte|gatsby|vite|webpack/i;
      const backendKeywords = /django|laravel|express|wordpress|drupal|joomla|asp\.net|php|ruby|rails/i;
      const frontend = techStack.filter((t) => frontendKeywords.test(t.name)).map((t) => ({ name: t.name, source: t.source, confidence: 85 }));
      const backend = techStack.filter((t) => backendKeywords.test(t.name) || !frontendKeywords.test(t.name)).map((t) => ({ name: t.name, source: t.source, confidence: 85 }));
      if (frontend.length > 0 || backend.length > 0) {
        modules.push({
          moduleType: "tech_stack",
          confidence: 90,
          data: {
            source: "HTTP headers + HTML analysis",
            frontend,
            backend,
            totalTechnologies: techStack.length,
            thirdParty: [],
            riskFlags: [],
            verifiedAt: new Date().toISOString(),
          },
        });
      }
    }
    const w = osintResults.reconData as any;
    if (w.serverLocation || w.cookies || w.responseHeaders || w.securityTxt || w.sitemapUrls || w.robotsTxt || (w.techStack && w.techStack.length) || (w.socialTags && Object.keys(w.socialTags).length) || (w.openPorts && w.openPorts.length) || w.dnssec) {
      modules.push({
        moduleType: "website_overview",
        confidence: 90,
        data: {
          source: "HTTP + path probes",
          serverLocation: w.serverLocation,
          cookies: w.cookies || [],
          responseHeaders: w.responseHeaders || {},
          securityTxt: w.securityTxt,
          sitemapUrls: w.sitemapUrls || [],
          robotsTxt: w.robotsTxt,
          techStack: w.techStack || [],
          socialTags: w.socialTags || {},
          openPorts: w.openPorts || [],
          dnssec: w.dnssec,
          verifiedAt: new Date().toISOString(),
        },
      });
    }
  }

  return modules;
}
