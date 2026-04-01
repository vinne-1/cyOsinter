import fs from "fs/promises";
import path from "path";
import type { ReconData } from "./types.js";

export const SUBDOMAIN_WORDLIST_SOURCE = "SecLists/Discovery/DNS/subdomains-top1million-5000.txt";
export const DIRECTORY_WORDLIST_SOURCE = "SecLists/Discovery/Web-Content/common.txt";

export const STANDARD_SUBDOMAIN_WORDLIST_CAP = 2000;
export const STANDARD_PROBE_BATCH = 150;
export const STANDARD_NUCLEI_DOMAINS = 50;
export const STANDARD_DIRECTORY_CAP = 1000;
export const STANDARD_SITEMAP_LIMIT = 500;
export const STANDARD_SUBDOMAIN_CERT_CHECK = 3;

export const GOLD_SUBDOMAIN_WORDLIST_CAP = 0; // 0 = no cap (use full wordlist)
export const GOLD_PROBE_BATCH = 0;
export const GOLD_NUCLEI_DOMAINS = 0;
export const GOLD_DIRECTORY_CAP = 0;
export const GOLD_SITEMAP_LIMIT = 5000;
export const GOLD_SUBDOMAIN_CERT_CHECK = 0;

export const STANDARD_PORTS = [
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
const GOLD_EXTRA_PORTS = [
  20, 69, 79, 102, 111, 119, 135, 137, 138, 139, 161, 162, 177, 194,
  220, 264, 318, 381, 383, 411, 412, 427, 444, 500, 512, 513, 514, 515,
  520, 554, 563, 593, 631, 666, 749, 750, 829, 873, 902, 989, 990,
  1080, 1194, 1214, 1241, 1311, 1434, 1494, 1512, 1524, 1533, 1589,
  1701, 1723, 1755, 1812, 1813, 1863, 2049, 2082, 2083, 2086, 2087,
  2095, 2096, 2181, 2222, 3128, 3268, 3269, 3478, 3690, 4000, 4001,
  4045, 4190, 4333, 4500, 4567, 4899, 4949, 5353, 5555, 5800,
  6514, 6665, 6666, 6667, 6668, 6669, 7070, 7474, 7676, 7777, 8009,
  8069, 8100, 8180, 8400, 8500, 8880, 9001, 9080, 9100, 9160,
  9999, 10000, 10443, 11000, 16010, 20000, 27015, 28015, 50000,
];
export const GOLD_PORTS = [...STANDARD_PORTS, ...GOLD_EXTRA_PORTS];

export const FALLBACK_SUBDOMAINS = "www mail ftp smtp api dev admin staging test portal cpanel webmail ns1 ns2 mx git blog shop app cdn cloud support help docs static media img assets upload files backup db mysql admin panel login secure vpn mail2 ns".split(" ");
export const FALLBACK_DIRECTORIES = "/admin /api /.git /.env /robots.txt /.well-known/security.txt /sitemap.xml /wp-login.php /server-status /backup /.htaccess /config /login /dashboard /phpmyadmin /swagger.json /.aws /debug".split(" ");

export const OSINT_CREDENTIAL_PATHS = [
  "/config.php", "/wp-config.php", "/configuration.php", "/credentials.json", "/secrets.json",
  "/config.json", "/passwords.txt", "/passwords.csv", "/.aws/credentials", "/id_rsa", "/id_rsa.pub",
  "/.env.local", "/.env.production",
  "/.env.backup", "/.env.bak", "/.env.old", "/.env.dev", "/.env.staging", "/.env.example",
  "/.npmrc", "/.yarnrc",
  "/.docker/config.json", "/.travis.yml", "/.circleci/config.yml", "/Jenkinsfile",
  "/settings.py", "/local_settings.py",
  "/wp-config.php.bak", "/wp-config.php~", "/config.php.bak",
  "/.htpasswd", "/.pgpass", "/my.cnf", "/.my.cnf",
  "/database.yml", "/secrets.yml", "/connection.yml",
  "/appsettings.json", "/web.config", "/applicationContext.xml",
  "/.ssh/authorized_keys", "/.netrc", "/.git-credentials", "/.bash_history",
  "/sftp-config.json", "/filezilla.xml",
];
export const OSINT_DOCUMENT_PATHS = [
  "/documents", "/docs", "/files", "/downloads", "/uploads", "/backup", "/backups",
  "/report.pdf", "/data.xlsx", "/contacts.csv",
  "/backup.sql", "/backup.zip", "/backup.tar.gz", "/db.sql", "/database.sql",
  "/dump.sql", "/data.sql", "/site.zip", "/www.zip",
  "/debug.log", "/error.log", "/access.log", "/wp-content/debug.log",
  "/logs/error.log", "/logs/access.log", "/storage/logs/laravel.log",
  "/phpMyAdmin", "/adminer.php", "/phpmyadmin/index.php",
  "/db", "/sql", "/data", "/export", "/reports", "/archive",
  "/temp", "/tmp", "/cache", "/private", "/internal",
  "/wp-content/uploads", "/sites/default/files", "/media", "/static/admin",
  "/spreadsheet", "/presentations",
];
export const OSINT_INFRA_PATHS = "/phpinfo.php /info.php /server-status /api-docs /openapi.json /debug /trace /actuator /actuator/health /admin/login /wp-admin /administrator /manager /console /config.yml /docker-compose.yml /.dockerignore /kubernetes /health /metrics /graphql /api/v1 /api/v2 /swagger-ui /redoc /.terraform /terraform.tfstate".split(" ");
export const DOCUMENT_EXTENSIONS = /\.(pdf|doc|docx|xlsx|xls|csv|sql|zip|tar|tar\.gz|bak|old|log|dump)$/i;

export interface EvidenceItem {
  [key: string]: unknown;
  type: string;
  description: string;
  url?: string;
  snippet?: string;
  source?: string;
  verifiedAt?: string;
  raw?: Record<string, unknown>;
}

export interface VerifiedFinding {
  title: string;
  description: string;
  severity: string;
  category: string;
  affectedAsset: string;
  cvssScore: string;
  remediation: string;
  evidence: EvidenceItem[];
}

export interface ScanResults {
  subdomains: string[];
  assets: Array<{ type: string; value: string; tags: string[] }>;
  findings: VerifiedFinding[];
  reconData: ReconData;
}

export type ScanProgressCallback = (msg: string, percent: number, step: string, etaSeconds?: number) => Promise<void>;

export interface ScanOptions {
  signal?: AbortSignal;
  mode?: "standard" | "gold";
}

export function isGold(options?: ScanOptions): boolean {
  return options?.mode === "gold";
}

export function checkAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new Error("Scan aborted");
}

let fullSubdomainWordlist: string[] | null = null;
let cachedSubdomainWordlist: string[] | null = null;

export async function loadSubdomainWordlist(cap = STANDARD_SUBDOMAIN_WORDLIST_CAP): Promise<string[]> {
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
let cachedDirectoryWordlist: string[] | null = null;

export async function loadDirectoryWordlist(cap = STANDARD_DIRECTORY_CAP): Promise<string[]> {
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
