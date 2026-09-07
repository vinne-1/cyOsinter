// Focused Playwright check: DOCX download through the real UI (validates the
// authenticated-download fix). Uses existing completed reports — no scan needed.
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
  const n = await cards.count();
  log(n > 0, `reports listed (${n})`);
  if (n === 0) throw new Error("no reports to test");

  await cards.first().click();
  await page.waitForTimeout(1200);
  const exp = page.getByTestId("button-export");
  log(await exp.count() > 0, "Export control visible in report detail");
  await exp.click();
  await page.waitForTimeout(700);
  await shot("docx-01-export-menu");
  log(await page.getByTestId("button-export-docx").count() > 0, "Word (.docx) option present");

  const [dl] = await Promise.all([
    page.waitForEvent("download", { timeout: 40000 }).catch(() => null),
    page.getByTestId("button-export-docx").click(),
  ]);
  if (dl) {
    const p = `${OUT}/ui-report.docx`;
    await dl.saveAs(p);
    const st = await fs.stat(p);
    const head = (await fs.readFile(p)).subarray(0, 2).toString("latin1");
    log(head === "PK" && st.size > 2000, `DOCX downloaded via UI — auth fix works (${st.size} bytes, PK=${head})`);
  } else {
    log(false, "DOCX download event did not fire (auth?)");
  }
} catch (e) {
  log(false, "exception: " + e.message);
  await shot("docx-error");
} finally {
  await b.close();
  const p = R.filter((r) => r.p).length;
  console.log(`\n=== DOCX UI QA: ${p}/${R.length} passed ===`);
  R.filter((r) => !r.p).forEach((r) => console.log("  FAILED:", r.m));
  process.exit(p === R.length ? 0 : 1);
}
