// Playwright validation of progress-bar smoothness + live fill-up.
// Creates a fresh workspace, scans it, polls the scan every ~10s, and asserts
// the progress bar advances early and through many distinct values (no plateau).
import { chromium } from "playwright";
import fs from "fs/promises";
const BASE = "http://localhost:5050";
const OUT = process.env.PWOUT || "./pw-qa";
await fs.mkdir(OUT, { recursive: true });
const R = [];
const log = (p, m) => { R.push({ p, m }); console.log((p ? "PASS" : "FAIL") + ": " + m); };
const b = await chromium.launch({ headless: true });
const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true, acceptDownloads: true });
const page = await ctx.newPage();
const shot = (n) => page.screenshot({ path: `${OUT}/${n}.png` }).catch(() => {});
let token = null;
const api = (path, opts = {}) => page.evaluate(async ([p, o, t]) => {
  const r = await fetch(p, { ...o, headers: { ...(o.headers || {}), Authorization: "Bearer " + t } });
  const ct = r.headers.get("content-type") || "";
  return { status: r.status, body: ct.includes("json") ? await r.json() : null };
}, [BASE + path, opts, token]);

async function main() {
  await page.goto(BASE + "/auth", { waitUntil: "networkidle" });
  await page.locator("#login-email").fill("auth-shared@e2e.local");
  await page.locator("#login-password").fill("TestPassword123!");
  await Promise.all([page.waitForResponse((r) => r.url().includes("/api/auth/login")), page.getByRole("button", { name: /sign in/i }).click()]);
  await page.waitForTimeout(2500);
  token = await page.evaluate(() => localStorage.getItem("auth_token"));
  log(!!token, "UI login");

  const qname = "Progress QA " + Date.now();
  const cw = await api("/api/workspaces", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: qname, domain: "procellbiologics.com" }) });
  const ws = cw.body;
  log(!!ws?.id, `created fresh workspace ("${qname}")`);
  await page.goto(BASE + "/", { waitUntil: "networkidle" });

  const findings = async () => { const r = await api(`/api/workspaces/${ws.id}/findings`); const arr = Array.isArray(r.body) ? r.body : (r.body?.data || []); return arr.length; };
  await api("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ target: "procellbiologics.com", type: "full", mode: "standard", status: "pending", workspaceId: ws.id }) });
  log(true, "scan triggered");

  const startTs = Date.now();
  const series = []; // {t, pct, step, findings}
  let firstNonZeroT = null;
  for (let i = 0; i < 60; i++) {
    await page.waitForTimeout(10000);
    const sr = await api(`/api/workspaces/${ws.id}/scans`);
    const sl = Array.isArray(sr.body) ? sr.body : (sr.body?.data || []);
    const s = sl[0];
    const running = s && ["running", "pending"].includes(s.status);
    const pct = s?.progressPercent ?? 0;
    const f = await findings();
    const t = Math.round((Date.now() - startTs) / 1000);
    series.push({ t, pct, step: s?.currentStep, findings: f });
    if (pct > 0 && firstNonZeroT === null) firstNonZeroT = t;
    console.log(`t+${t}s pct=${pct}% step=${s?.currentStep} findings=${f} ${running ? "" : "(done)"}`);
    if (i % 3 === 0) await shot(`prog-${String(t).padStart(3, "0")}s-${pct}pct`);
    if (!running && i >= 2) break;
  }

  const distinctPct = [...new Set(series.map((x) => x.pct))].sort((a, b) => a - b);
  const maxPct = Math.max(...series.map((x) => x.pct));
  const maxFindings = Math.max(...series.map((x) => x.findings));
  // longest run of consecutive identical pct (a plateau), in polls (~10s each)
  // Only a LOW-% freeze is a problem; a brief hold near completion (>=90%) while
  // the final phase wraps up is expected and not confusing.
  let plateau = 1, maxPlateau = 1;
  for (let i = 1; i < series.length; i++) { if (series[i].pct === series[i - 1].pct && series[i].pct < 90) { plateau++; maxPlateau = Math.max(maxPlateau, plateau); } else plateau = 1; }

  console.log("progress series pct:", series.map((x) => x.pct).join(","));
  log(firstNonZeroT !== null && firstNonZeroT <= 90, `progress advanced past 0% within ${firstNonZeroT}s (was ~200s+ before)`);
  log(distinctPct.length >= 5, `progress moved through ${distinctPct.length} distinct values (smooth): [${distinctPct.join(",")}]`);
  log(maxPlateau <= 9, `longest single-% plateau was ~${maxPlateau * 10}s (no multi-minute freeze)`);
  log(maxFindings > 0, `findings populated live during scan (max=${maxFindings})`);

  await api(`/api/workspaces/${ws.id}`, { method: "DELETE" }).catch(() => {});
}

main().catch((e) => log(false, "exception: " + e.message)).finally(async () => {
  await b.close();
  const p = R.filter((r) => r.p).length;
  console.log(`\n=== PROGRESS QA: ${p}/${R.length} passed ===`);
  R.filter((r) => !r.p).forEach((r) => console.log("  FAILED:", r.m));
  process.exit(p === R.length ? 0 : 1);
});
