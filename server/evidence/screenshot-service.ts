import { createLogger } from "../logger";

/**
 * Headless-browser evidence capture. Given a domain and its findings, navigates
 * to the live target and to free third-party corroboration sources (crt.sh,
 * Google Public DNS, who.is) and returns PNG screenshots keyed by a semantic
 * name. Entirely FAIL-SOFT: if Playwright/Chromium is unavailable or a page
 * blocks automation, that shot is skipped and the report still generates.
 */

const log = createLogger("evidence");

export interface EvidenceShots {
  [key: string]: Buffer;
}

interface EvidenceTarget {
  key: string;
  url: string;
  fullPage?: boolean;
  waitMs?: number;
}

/** Build the list of evidence URLs relevant to this domain + findings. */
export function buildEvidenceTargets(domain: string, findingCategories: string[]): EvidenceTarget[] {
  const cats = Array.from(new Set(findingCategories.map((c) => (c || "").toLowerCase())));
  const targets: EvidenceTarget[] = [
    { key: "homepage", url: `https://${domain}/` },
    { key: "robots", url: `https://${domain}/robots.txt` },
    { key: "crtsh", url: `https://crt.sh/?q=${encodeURIComponent(domain)}`, fullPage: true },
    { key: "whois", url: `https://who.is/whois/${encodeURIComponent(domain)}`, fullPage: true },
  ];
  // Email-auth evidence when relevant.
  if (cats.some((c) => /email|dmarc|spf|dns_misconfig/.test(c))) {
    targets.push({ key: "dmarc", url: `https://dns.google/query?name=_dmarc.${encodeURIComponent(domain)}&type=TXT`, fullPage: true });
    targets.push({ key: "spf", url: `https://dns.google/query?name=${encodeURIComponent(domain)}&type=TXT`, fullPage: true });
  }
  // WordPress user-enumeration evidence.
  if (cats.some((c) => /disclosure|enumeration|web_application/.test(c))) {
    targets.push({ key: "wp-users", url: `https://${domain}/wp-json/wp/v2/users` });
  }
  return targets;
}

/**
 * Map a finding (by category/title) to the semantic evidence key that best
 * illustrates it, so the DOCX can embed the right screenshot per finding.
 */
export function evidenceKeyForFinding(category: string, title: string): string | undefined {
  const c = (category || "").toLowerCase();
  const t = (title || "").toLowerCase();
  if (/enumeration|wp.?json|user/.test(t)) return "wp-users";
  if (/dmarc/.test(t) || /email|dns_misconfig/.test(c)) return "dmarc";
  if (/subdomain|certificate|transparency/.test(t)) return "crtsh";
  if (/whois|registration/.test(t)) return "whois";
  return undefined;
}

export async function captureEvidence(
  domain: string,
  findingCategories: string[],
  opts: { timeoutMs?: number; maxShots?: number } = {},
): Promise<EvidenceShots> {
  const shots: EvidenceShots = {};
  const timeoutMs = opts.timeoutMs ?? 15000;
  const targets = buildEvidenceTargets(domain, findingCategories).slice(0, opts.maxShots ?? 10);

  let chromium: typeof import("playwright").chromium;
  try {
    ({ chromium } = await import("playwright"));
  } catch (err) {
    log.warn({ err }, "Playwright not available — skipping screenshot evidence (report will be text-only)");
    return shots;
  }

  let browser: import("playwright").Browser | null = null;
  try {
    // In the Alpine container Playwright's bundled Chromium is unavailable, so
    // point it at the system chromium via PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH.
    // Locally (env unset) Playwright's own browser is used.
    const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined;
    browser = await chromium.launch({ headless: true, executablePath, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
    const ctx = await browser.newContext({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
      viewport: { width: 1280, height: 800 },
      ignoreHTTPSErrors: true,
    });
    for (const tgt of targets) {
      const page = await ctx.newPage();
      try {
        await page.goto(tgt.url, { waitUntil: "domcontentloaded", timeout: timeoutMs });
        if (tgt.waitMs) await page.waitForTimeout(tgt.waitMs);
        const buf = await page.screenshot({ type: "png", fullPage: tgt.fullPage ?? false });
        shots[tgt.key] = buf;
        log.info({ key: tgt.key, url: tgt.url }, "Captured evidence screenshot");
      } catch (err) {
        log.warn({ key: tgt.key, url: tgt.url, err: err instanceof Error ? err.message : String(err) }, "Evidence shot failed (skipped)");
      } finally {
        await page.close().catch(() => {});
      }
    }
  } catch (err) {
    log.warn({ err: err instanceof Error ? err.message : String(err) }, "Evidence browser launch failed — report will be text-only");
  } finally {
    if (browser) await browser.close().catch(() => {});
  }

  return shots;
}
