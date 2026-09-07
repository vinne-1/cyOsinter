// Playwright live-behavior QA: real browser + real UI. Creates a FRESH workspace
// (arbitrary name + target domain), scans it, and watches findings fill up live
// from zero, then validates the DOCX download through the UI.
import { chromium } from "playwright";
import fs from "fs/promises";

const BASE = "http://localhost:5050";
const OUT = process.env.PWOUT || "./pw-qa";
await fs.mkdir(OUT, { recursive: true });
const R = [];
const log = (p, m) => { R.push({ p, m }); console.log((p ? "PASS" : "FAIL") + ": " + m); };

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
const page = await ctx.newPage();
const shot = (n) => page.screenshot({ path: `${OUT}/${n}.png` }).catch(() => {});
let token = null;
const api = (path, opts = {}) => page.evaluate(async ([p, o, t]) => {
  const r = await fetch(p, { ...o, headers: { ...(o.headers || {}), Authorization: "Bearer " + t } });
  const ct = r.headers.get("content-type") || "";
  return { status: r.status, body: ct.includes("json") ? await r.json() : null };
}, [BASE + path, opts, token]);

async function main() {
  // ── UI login ──
  await page.goto(BASE + "/auth", { waitUntil: "networkidle" });
  await page.locator("#login-email").fill("auth-shared@e2e.local");
  await page.locator("#login-password").fill("TestPassword123!");
  await Promise.all([
    page.waitForResponse((r) => r.url().includes("/api/auth/login") && r.request().method() === "POST"),
    page.getByRole("button", { name: /sign in/i }).click(),
  ]);
  await page.waitForTimeout(2500);
  token = await page.evaluate(() => localStorage.getItem("auth_token"));
  log(!!token, "UI login (auth_token set)");
  await shot("live-00-dashboard");

  // ── Create a FRESH workspace via the real UI: arbitrary name + target domain ──
  const qname = "Live QA " + Date.now();
  await page.getByTestId("button-domain-selector").click();
  await page.getByTestId("button-create-workspace").click();
  await page.getByTestId("input-workspace-domain").fill(qname);
  await page.getByTestId("input-workspace-target-domain").fill("procellbiologics.com");
  await shot("live-01-create-workspace");
  const [wsResp] = await Promise.all([
    page.waitForResponse((r) => r.url().includes("/api/workspaces") && r.request().method() === "POST"),
    page.getByTestId("button-confirm-create-workspace").click(),
  ]);
  log(wsResp.ok(), `create workspace via UI (arbitrary name "${qname}" + domain) -> ${wsResp.status()}`);
  await page.waitForTimeout(1500);

  const wsr = await api("/api/workspaces");
  const L = Array.isArray(wsr.body) ? wsr.body : (wsr.body?.data || []);
  const ws = L.find((w) => w.name === qname);
  if (!ws) { log(false, "fresh workspace not found after create"); return; }
  log(ws.domain === "procellbiologics.com", `workspace stores target domain separately (name="${ws.name}", domain="${ws.domain}")`);

  await page.goto(BASE + "/", { waitUntil: "networkidle" });
  await page.waitForTimeout(1500);

  const countFindings = async () => {
    const r = await api(`/api/workspaces/${ws.id}/findings`);
    const b = r.body; const arr = Array.isArray(b) ? b : (b?.data || []);
    return arr.length;
  };

  // ── Trigger scan and WATCH findings fill up from zero ──
  const before = await countFindings();
  log(before === 0, `fresh workspace starts empty (findings=${before})`);
  const trig = await api("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ target: "procellbiologics.com", type: "full", mode: "standard", status: "pending", workspaceId: ws.id }) });
  log(trig.status === 201 || trig.status === 200, `scan triggered via API (${trig.status})`);

  const counts = [before]; let increases = 0; let sawData = false;
  for (let i = 0; i < 30; i++) {
    await page.waitForTimeout(30000);
    await page.reload({ waitUntil: "networkidle" }).catch(() => {});
    const c = await countFindings();
    const sr = await api(`/api/workspaces/${ws.id}/scans`);
    const sl = Array.isArray(sr.body) ? sr.body : (sr.body?.data || []);
    const running = sl.find((s) => ["running", "pending"].includes(s.status));
    console.log(`t+${(i + 1) * 30}s findings=${c} scan=${running ? running.progressPercent + "% " + running.currentStep : "DONE"}`);
    await shot(`live-${String(i + 2).padStart(2, "0")}-findings-${c}`);
    if (c > counts[counts.length - 1]) increases++;
    if (c > 0) sawData = true;
    counts.push(c);
    if (increases >= 2 && (i >= 5 || !running)) break;   // clear live fill-up captured
    if (!running && i >= 2) break;                          // scan done
  }
  const maxc = Math.max(...counts);
  log(sawData && maxc > before, `findings populated LIVE during scan (0 -> ${maxc}, series=[${counts.join(",")}])`);
  log(increases >= 2, `findings count increased ${increases}x mid-scan (incremental fill-up)`);

  // ── DOCX download through the real UI (validates the auth fix) ──
  const rep = await api(`/api/workspaces/${ws.id}/reports`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ title: "Live QA Report", type: "full_report", workspaceId: ws.id }) });
  const repId = rep.body?.id;
  let rs;
  for (let i = 0; i < 25; i++) { await page.waitForTimeout(2000); const g = await api(`/api/reports/${repId}`); rs = g.body?.status; if (rs === "completed") break; }
  log(rs === "completed", `report generated (${rs})`);
  await page.goto(BASE + "/reports", { waitUntil: "networkidle" });
  await page.waitForTimeout(2000);
  await shot("live-90-reports");
  // The export control lives inside the report detail dialog — open a card first.
  const cards = page.locator('[data-testid^="card-report-"]');
  if (await cards.count()) { await cards.first().click(); await page.waitForTimeout(1000); }
  const exportBtn = page.getByTestId("button-export").first();
  if (await exportBtn.count()) {
    await exportBtn.click();
    await page.waitForTimeout(600);
    const hasDocx = await page.getByTestId("button-export-docx").count() > 0;
    log(hasDocx, "export menu shows Word (.docx) option");
    await shot("live-91-export-menu");
    if (hasDocx) {
      const [dl] = await Promise.all([
        page.waitForEvent("download", { timeout: 40000 }).catch(() => null),
        page.getByTestId("button-export-docx").first().click(),
      ]);
      if (dl) {
        const p = `${OUT}/report-ui.docx`; await dl.saveAs(p);
        const st = await fs.stat(p); const head = (await fs.readFile(p)).subarray(0, 2).toString("latin1");
        log(head === "PK" && st.size > 2000, `DOCX downloaded via UI, auth OK (${st.size} bytes, PK=${head})`);
      } else log(false, "DOCX download event did not fire (auth?)");
    }
  } else log(false, "no export control on reports page");

  // ── cleanup ──
  await api(`/api/workspaces/${ws.id}`, { method: "DELETE" }).catch(() => {});
}

main().catch((e) => log(false, "exception: " + e.message)).finally(async () => {
  await shot("live-99-final").catch(() => {});
  await browser.close();
  const passed = R.filter((r) => r.p).length;
  console.log(`\n=== PLAYWRIGHT LIVE QA: ${passed}/${R.length} passed ===`);
  R.filter((r) => !r.p).forEach((r) => console.log("  FAILED:", r.m));
  process.exit(passed === R.length ? 0 : 1);
});
