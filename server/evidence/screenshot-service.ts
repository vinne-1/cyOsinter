import { createLogger } from "../logger";

/**
 * Headless-browser evidence capture. Given a domain and its findings, captures
 * screenshots that illustrate EVERY finding: relevant third-party corroboration
 * (crt.sh, Google Public DNS, who.is, Shodan), the live target pages, the actual
 * exposed-path URL for path findings, and a self-rendered HTTP-security-headers
 * card. Each finding is mapped to the best available shot, with the homepage as
 * a guaranteed fallback so no finding is left without evidence.
 *
 * Entirely FAIL-SOFT: if Playwright/Chromium is unavailable or a page blocks
 * automation, that shot is skipped and the report still generates (text-only for
 * any finding whose shot could not be captured).
 */

const log = createLogger("evidence");

export interface EvidenceFinding {
  id: string;
  category: string;
  title: string;
  affectedAsset?: string;
  /** An on-target URL drawn from the finding's evidence, screenshotted directly. */
  evidenceUrl?: string;
}

export interface CaptureOptions {
  ip?: string;
  timeoutMs?: number;
  maxShots?: number;
}

const SECURITY_HEADERS: Array<[string, string]> = [
  ["strict-transport-security", "Strict-Transport-Security (HSTS)"],
  ["content-security-policy", "Content-Security-Policy"],
  ["x-frame-options", "X-Frame-Options"],
  ["x-content-type-options", "X-Content-Type-Options"],
  ["referrer-policy", "Referrer-Policy"],
  ["permissions-policy", "Permissions-Policy"],
];

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
}

/** Self-rendered "HTTP security headers" evidence card from the live response headers. */
function headersCardHtml(domain: string, headers: Record<string, string>): string {
  const rows = SECURITY_HEADERS.map(([k, label]) => {
    const present = !!headers[k];
    const val = present ? escapeHtml(String(headers[k]).slice(0, 90)) : "&mdash;";
    return `<tr><td>${label}</td><td class="${present ? "ok" : "bad"}">${present ? "PRESENT" : "MISSING"}</td><td class="v">${val}</td></tr>`;
  }).join("");
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    body{font-family:'Segoe UI',Arial,sans-serif;background:#0b1220;color:#e6edf3;margin:0;padding:28px}
    h1{font-size:19px;color:#58a6ff;margin:0 0 4px} .sub{color:#8b949e;font-size:12px;margin-bottom:18px}
    table{border-collapse:collapse;width:100%;font-size:13px} td,th{border:1px solid #30363d;padding:9px 12px;text-align:left}
    th{background:#161b22;color:#c9d1d9} .ok{color:#3fb950;font-weight:700} .bad{color:#f85149;font-weight:700} .v{color:#8b949e;font-family:Consolas,monospace}
    .server{margin-top:16px;color:#8b949e;font-size:12px}
  </style></head><body>
    <h1>HTTP Security Headers &mdash; ${escapeHtml(domain)}</h1>
    <div class="sub">Live response-header analysis of https://${escapeHtml(domain)}/</div>
    <table><tr><th>Header</th><th>Status</th><th>Value</th></tr>${rows}</table>
    <div class="server">Server: ${escapeHtml(String(headers["server"] || "—"))}</div>
  </body></html>`;
}

/** Map a finding to the semantic evidence key that best illustrates it. */
export function evidenceKeyForFinding(category: string, title: string, hasIp: boolean): string {
  const s = `${category} ${title}`.toLowerCase();
  if (/enumeration|wp-?json|user account|author/.test(s)) return "wpusers";
  if (/dmarc/.test(s)) return "dmarc";
  if (/\bspf\b|sender policy/.test(s)) return "spf";
  if (/email|dkim|mail|dns_misconfig/.test(s)) return "dmarc";
  if (/header|clickjack|hsts|csp|x-frame|content-security|transport_security|referrer/.test(s)) return "headers";
  if (/network_exposure|db_exposure|database|\bport\b|outdated_software|infrastructure_disclosure|mysql|openssh|\bssh\b|ftp|redis|mongo/.test(s) && hasIp) return "shodan";
  if (/xmlrpc|wordpress|web_application|login|admin/.test(s)) return "wplogin";
  if (/subdomain|certificate|transparency|\btls\b|\bssl\b|takeover/.test(s)) return "crtsh";
  if (/whois|registration|domain_info/.test(s)) return "whois";
  if (/robots/.test(s)) return "robots";
  return "homepage"; // guaranteed fallback
}

interface Target { key: string; url: string; fullPage?: boolean }

/** The semantic (non per-finding) shots we may need, keyed by name. */
function semanticTargets(domain: string, ip: string | undefined, neededKeys: Set<string>): Target[] {
  const all: Record<string, Target> = {
    homepage: { key: "homepage", url: `https://${domain}/` },
    robots: { key: "robots", url: `https://${domain}/robots.txt` },
    wplogin: { key: "wplogin", url: `https://${domain}/wp-login.php` },
    wpusers: { key: "wpusers", url: `https://${domain}/wp-json/wp/v2/users` },
    crtsh: { key: "crtsh", url: `https://crt.sh/?q=${encodeURIComponent(domain)}`, fullPage: true },
    whois: { key: "whois", url: `https://who.is/whois/${encodeURIComponent(domain)}`, fullPage: true },
    dmarc: { key: "dmarc", url: `https://dns.google/query?name=_dmarc.${encodeURIComponent(domain)}&type=TXT`, fullPage: true },
    spf: { key: "spf", url: `https://dns.google/query?name=${encodeURIComponent(domain)}&type=TXT`, fullPage: true },
    ...(ip ? { shodan: { key: "shodan", url: `https://www.shodan.io/host/${ip}`, fullPage: true } } : {}),
  };
  // Always try the homepage (used as the universal fallback). "headers" is
  // rendered from the homepage response, so it needs no URL of its own.
  neededKeys.add("homepage");
  return Object.values(all).filter((t) => neededKeys.has(t.key));
}

export async function captureEvidence(
  domain: string,
  findings: EvidenceFinding[],
  opts: CaptureOptions = {},
): Promise<Record<string, Buffer>> {
  const result: Record<string, Buffer> = {};
  const timeoutMs = opts.timeoutMs ?? 15000;
  const maxShots = opts.maxShots ?? 24;

  // Which semantic keys are needed, and per-finding specific on-domain URLs.
  const neededKeys = new Set<string>();
  const findingKey = new Map<string, string>(); // findingId -> semantic key
  const findingUrl = new Map<string, string>(); // findingId -> specific url
  const specificUrls = new Map<string, string>(); // url -> shot key
  const wantHeaders = findings.some((f) => /header|clickjack|hsts|csp|x-frame|transport_security|referrer/.test(`${f.category} ${f.title}`.toLowerCase()));

  for (const f of findings) {
    const key = evidenceKeyForFinding(f.category, f.title, !!opts.ip);
    findingKey.set(f.id, key);
    neededKeys.add(key);
    // Directly screenshot the exposed-path URL when the finding carries one.
    if (f.evidenceUrl && specificUrls.size < 12) {
      try {
        const u = new URL(f.evidenceUrl);
        const onDomain = u.hostname === domain || u.hostname.endsWith(`.${domain}`);
        if (onDomain && /^https?:$/.test(u.protocol) && u.pathname !== "/") {
          const sk = `path:${u.pathname}`;
          if (!specificUrls.has(f.evidenceUrl)) specificUrls.set(f.evidenceUrl, sk);
          findingUrl.set(f.id, f.evidenceUrl);
        }
      } catch { /* bad url */ }
    }
  }

  let chromium: typeof import("playwright").chromium;
  try {
    ({ chromium } = await import("playwright"));
  } catch (err) {
    log.warn({ err }, "Playwright not available — report will be text-only");
    return result;
  }

  let browser: import("playwright").Browser | null = null;
  const shots: Record<string, Buffer> = {};
  try {
    const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined;
    browser = await chromium.launch({ headless: true, executablePath, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
    const ctx = await browser.newContext({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
      viewport: { width: 1280, height: 800 },
      ignoreHTTPSErrors: true,
    });

    const grab = async (key: string, url: string, fullPage = false, headersFor?: string): Promise<void> => {
      if (Object.keys(shots).length >= maxShots || shots[key]) return;
      const page = await ctx.newPage();
      try {
        const resp = await page.goto(url, { waitUntil: "domcontentloaded", timeout: timeoutMs });
        shots[key] = await page.screenshot({ type: "png", fullPage });
        // Render the security-headers card from the homepage's live headers.
        if (headersFor && resp && wantHeaders && !shots["headers"]) {
          const h = resp.headers();
          await page.setContent(headersCardHtml(headersFor, h), { waitUntil: "domcontentloaded" });
          shots["headers"] = await page.screenshot({ type: "png" });
        }
        log.info({ key, url }, "Captured evidence screenshot");
      } catch (err) {
        log.warn({ key, url, err: err instanceof Error ? err.message : String(err) }, "Evidence shot failed (skipped)");
      } finally {
        await page.close().catch(() => {});
      }
    };

    // Homepage first (also yields the headers card).
    await grab("homepage", `https://${domain}/`, false, domain);
    // Remaining semantic shots.
    for (const t of semanticTargets(domain, opts.ip, neededKeys)) {
      if (t.key === "homepage") continue;
      await grab(t.key, t.url, t.fullPage);
    }
    // Per-finding specific exposed-path URLs.
    for (const [url, sk] of Array.from(specificUrls.entries())) {
      await grab(sk, url, false);
    }
  } catch (err) {
    log.warn({ err: err instanceof Error ? err.message : String(err) }, "Evidence browser launch failed — report will be text-only");
  } finally {
    if (browser) await browser.close().catch(() => {});
  }

  // Assign each finding the best available shot (specific path → semantic →
  // homepage), guaranteeing every finding that can be illustrated gets an image.
  for (const f of findings) {
    const specific = findingUrl.get(f.id);
    const specificKey = specific ? specificUrls.get(specific) : undefined;
    const semantic = findingKey.get(f.id);
    const buf = (specificKey && shots[specificKey])
      || (semantic === "headers" && shots["headers"])
      || (semantic && shots[semantic])
      || shots["homepage"];
    if (buf) result[f.id] = buf;
  }
  return result;
}
