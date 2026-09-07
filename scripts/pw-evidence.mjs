// Playwright: download the "Word + live evidence" DOCX via the real UI and
// verify it embeds screenshots (large file => images present).
import { chromium } from "playwright";
import fs from "fs/promises";
import { execSync } from "child_process";
const BASE = "http://localhost:5050";
const OUT = process.env.PWOUT || "./pw-qa";
await fs.mkdir(OUT, { recursive: true });
const R = [];
const log = (p, m) => { R.push({ p, m }); console.log((p ? "PASS" : "FAIL") + ": " + m); };
const b = await chromium.launch({ headless: true });
const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true, acceptDownloads: true });
const page = await ctx.newPage();
try {
  await page.goto(BASE + "/auth", { waitUntil: "networkidle" });
  await page.locator("#login-email").fill("auth-shared@e2e.local");
  await page.locator("#login-password").fill("TestPassword123!");
  await Promise.all([page.waitForResponse((r) => r.url().includes("/api/auth/login")), page.getByRole("button", { name: /sign in/i }).click()]);
  await page.waitForTimeout(2500);
  log(!!(await page.evaluate(() => localStorage.getItem("auth_token"))), "UI login");

  await page.goto(BASE + "/reports", { waitUntil: "networkidle" });
  await page.waitForTimeout(2500);
  const cards = page.locator('[data-testid^="card-report-"]');
  log(await cards.count() > 0, `reports listed (${await cards.count()})`);
  await cards.first().click();
  await page.waitForTimeout(1200);
  await page.getByTestId("button-export").click();
  await page.waitForTimeout(600);
  log(await page.getByTestId("button-export-docx-evidence").count() > 0, "'Word + live evidence' option present");

  console.log("clicking evidence export (captures screenshots, ~30-60s)...");
  const [dl] = await Promise.all([
    page.waitForEvent("download", { timeout: 120000 }).catch(() => null),
    page.getByTestId("button-export-docx-evidence").click(),
  ]);
  if (dl) {
    const p = `${OUT}/ui-evidence.docx`;
    await dl.saveAs(p);
    const st = await fs.stat(p);
    const head = (await fs.readFile(p)).subarray(0, 2).toString("latin1");
    // Count embedded media parts (word/media/*) via python-docx if available.
    let imgs = "?";
    try { imgs = execSync(`python -c "import docx;print(len(docx.Document(r'${p}').inline_shapes))"`).toString().trim(); } catch {}
    log(head === "PK" && st.size > 1_000_000, `evidence DOCX downloaded via UI (${st.size} bytes, ${imgs} screenshots, PK=${head})`);
  } else {
    log(false, "evidence download did not fire");
  }
} catch (e) {
  log(false, "exception: " + e.message);
} finally {
  await b.close();
  const p = R.filter((r) => r.p).length;
  console.log(`\n=== EVIDENCE DOCX UI QA: ${p}/${R.length} passed ===`);
  R.filter((r) => !r.p).forEach((r) => console.log("  FAILED:", r.m));
  process.exit(p === R.length ? 0 : 1);
}
