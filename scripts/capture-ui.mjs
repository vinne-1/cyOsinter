/**
 * Capture annotated UI screenshots for the architecture document.
 *
 * Screenshots are taken against the running app with REAL data (the seeded
 * workspaces and their findings), not fixtures — the document is meant to show
 * how the product actually stands today.
 *
 * Feature callouts are drawn into the page before the screenshot rather than
 * added afterwards, so a numbered badge stays anchored to the element it
 * describes even as the layout reflows at a different viewport.
 *
 *   node scripts/capture-ui.mjs [--theme dark|light] [--out docs/screenshots]
 */
import { chromium } from "playwright";
import fs from "fs/promises";
import path from "path";

const BASE = process.env.APP_URL || "http://localhost:5050";
const EMAIL = process.env.SEED_ADMIN_EMAIL || "admin@cyshield.local";
const PASSWORD = process.env.SEED_ADMIN_PASSWORD || "ChangeMe123!";

const args = process.argv.slice(2);
const argOf = (flag, fallback) => {
  const i = args.indexOf(flag);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};
const THEME = argOf("--theme", "dark");
const OUT = argOf("--out", "docs/screenshots");

/**
 * The screens to capture, with the features to call out on each.
 *
 * `sel` is tried in order and the first match that is visible wins, so a screen
 * whose markup differs slightly between empty and populated states still gets
 * its callout rather than silently losing it.
 */
const SCREENS = [
  {
    file: "01-dashboard",
    route: "/",
    title: "Executive dashboard",
    callouts: [
      { sel: ["[data-testid='bento-hero']", "[class*='col-span-2'][class*='row-span-2']"], label: "Posture score — severity-banded, not a linear sum" },
      { sel: ["[data-testid='workspace-switcher']", "button:has-text('Bigbaskt')"], label: "Workspace switcher (multi-tenant isolation)" },
      { sel: ["a[href='/findings']", "[data-testid='tile-open-findings']"], label: "Open findings — real total, not page size" },
    ],
  },
  { file: "02-easm", route: "/easm", title: "External attack surface", callouts: [
    { sel: ["button:has-text('Start Scan')", "button:has-text('Scan')"], label: "Scan trigger — gated by a Postgres advisory-lock slot" },
    { sel: ["[role='tablist']"], label: "Discovered assets, subdomains, ports, TLS" },
  ] },
  { file: "03-osint", route: "/osint", title: "OSINT collection", callouts: [
    { sel: ["[role='tablist']", "main"], label: "Passive sources: CT logs, DNS, wayback, PGP, WHOIS" },
  ] },
  { file: "04-findings", route: "/findings", title: "Finding triage inbox", callouts: [
    { sel: ["input[placeholder*='earch']"], label: "Search + facet filters" },
    { sel: ["button:has-text('Severity')", "[data-testid='filter-severity']"], label: "Severity facet — only kind=security reaches this inbox" },
  ] },
  { file: "05-cases", route: "/cases", title: "Case management", callouts: [
    { sel: ["button:has-text('New Case')", "button:has-text('Create')"], label: "Cases group findings into units of work with their own SLA" },
  ] },
  { file: "06-attack-paths", route: "/attack-paths", title: "Attack path analysis" },
  { file: "07-asset-risk", route: "/asset-risk", title: "Asset risk scoring" },
  { file: "08-compliance", route: "/compliance", title: "Compliance mapping" },
  { file: "09-brand-threats", route: "/brand-threats", title: "Brand & typosquat monitoring" },
  { file: "10-intelligence", route: "/intelligence", title: "Threat intelligence" },
  { file: "11-reports", route: "/reports", title: "Reporting & export" },
  { file: "12-integrations", route: "/integrations", title: "Integrations" },
  { file: "13-scheduled-scans", route: "/scheduled-scans", title: "Continuous monitoring" },
  { file: "14-audit-log", route: "/audit-log", title: "Audit trail" },
  { file: "15-trends", route: "/trends", title: "Posture trends" },
  { file: "16-ai-insights", route: "/ai-insights", title: "AI enrichment" },
  { file: "17-threat-intel", route: "/threat-intel", title: "Threat intel feeds" },
  { file: "18-api-keys", route: "/api-keys", title: "API keys" },
  { file: "19-account", route: "/account", title: "Account security" },
];

/** Draw numbered callouts over the elements a screen wants to highlight. */
async function annotate(page, callouts) {
  if (!callouts?.length) return [];
  const resolved = [];
  for (let i = 0; i < callouts.length; i++) {
    const { sel, label } = callouts[i];
    let box = null;
    for (const s of sel) {
      try {
        const loc = page.locator(s).first();
        if ((await loc.count()) === 0) continue;
        box = await loc.boundingBox();
        if (box && box.width > 8 && box.height > 8) break;
        box = null;
      } catch { /* selector did not apply on this screen */ }
    }
    if (!box) continue;
    resolved.push({ n: resolved.length + 1, label });
    await page.evaluate(
      ({ box, n }) => {
        const ring = document.createElement("div");
        Object.assign(ring.style, {
          position: "absolute",
          left: `${box.x + window.scrollX - 3}px`,
          top: `${box.y + window.scrollY - 3}px`,
          width: `${box.width + 6}px`,
          height: `${box.height + 6}px`,
          border: "3px solid #f59e0b",
          borderRadius: "10px",
          boxShadow: "0 0 0 3px rgba(245,158,11,.25)",
          pointerEvents: "none",
          zIndex: "2147483646",
        });
        const badge = document.createElement("div");
        badge.textContent = String(n);
        Object.assign(badge.style, {
          position: "absolute",
          left: `${box.x + window.scrollX - 16}px`,
          top: `${box.y + window.scrollY - 16}px`,
          width: "30px",
          height: "30px",
          lineHeight: "30px",
          textAlign: "center",
          borderRadius: "999px",
          background: "#f59e0b",
          color: "#1c1200",
          font: "700 16px system-ui, sans-serif",
          boxShadow: "0 2px 8px rgba(0,0,0,.45)",
          pointerEvents: "none",
          zIndex: "2147483647",
        });
        document.body.append(ring, badge);
      },
      { box, n: resolved.length },
    );
  }
  return resolved;
}

async function main() {
  await fs.mkdir(OUT, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1600, height: 1000 },
    deviceScaleFactor: 2, // crisp enough to embed in a document
    ignoreHTTPSErrors: true,
  });
  const page = await context.newPage();

  // ── sign in ──
  await page.goto(`${BASE}/auth`, { waitUntil: "networkidle" });
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(OUT, "00-login.png") });

  await page.locator("#login-email").fill(EMAIL);
  await page.locator("#login-password").fill(PASSWORD);
  await Promise.all([
    page.waitForResponse((r) => r.url().includes("/api/auth/login")),
    page.getByRole("button", { name: /sign in/i }).click(),
  ]);
  await page.waitForTimeout(2000);

  // Pin the theme and the workspace that actually has findings, so every screen
  // shows a populated product rather than an empty state.
  const token = await page.evaluate(() => localStorage.getItem("auth_token"));
  if (!token) throw new Error("login did not store a token");
  const wsRes = await page.evaluate(async (t) => {
    const r = await fetch("/api/workspaces?limit=100", { headers: { Authorization: `Bearer ${t}` } });
    return r.json();
  }, token);
  const workspaces = Array.isArray(wsRes) ? wsRes : (wsRes.data ?? []);

  let best = workspaces[0];
  let bestCount = -1;
  for (const w of workspaces) {
    const c = await page.evaluate(
      async ({ t, id }) => {
        // `pageSize`, NOT `limit`. This endpoint pages with page/pageSize, and
        // asking for `limit` leaves it unpaged — which returns a bare ARRAY with
        // no `total`, so the count came back 0 and the script picked an empty
        // workspace to photograph. Every screen was captured on a workspace with
        // no findings because of one wrong query parameter.
        const r = await fetch(`/api/workspaces/${id}/findings?pageSize=1`, { headers: { Authorization: `Bearer ${t}` } });
        const j = await r.json();
        return typeof j.total === "number" ? j.total : (Array.isArray(j) ? j.length : 0);
      },
      { t: token, id: w.id },
    );
    if (c > bestCount) { bestCount = c; best = w; }
  }
  console.log(`Using workspace "${best?.name}" (${bestCount} findings)`);

  await page.evaluate(
    ({ id, theme }) => {
      localStorage.setItem("selectedWorkspaceId", id);
      localStorage.setItem("theme", theme);
      localStorage.setItem("vite-ui-theme", theme);
    },
    { id: best.id, theme: THEME },
  );

  const manifest = [];
  for (const screen of SCREENS) {
    try {
      await page.goto(`${BASE}${screen.route}`, { waitUntil: "networkidle", timeout: 45000 });
      // Charts and lazy panels settle after the network does.
      await page.waitForTimeout(2600);
      const callouts = await annotate(page, screen.callouts);
      const file = `${screen.file}.png`;
      await page.screenshot({ path: path.join(OUT, file) });
      manifest.push({ file, title: screen.title, route: screen.route, callouts });
      console.log(`captured ${file}  (${callouts.length} callout(s))`);
    } catch (err) {
      console.log(`SKIPPED ${screen.file}: ${err.message}`);
    }
  }

  await fs.writeFile(path.join(OUT, "manifest.json"), JSON.stringify(manifest, null, 2));
  await browser.close();
  console.log(`\n${manifest.length} screen(s) captured into ${OUT}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
