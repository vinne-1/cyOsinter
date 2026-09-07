import { chromium } from "playwright";
const OUT = process.env.PWOUT || ".";
const b = await chromium.launch({ headless: true });
const page = await (await b.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true })).newPage();
const R = [];
const log = (p, m) => { R.push(p); console.log((p ? "PASS" : "FAIL") + ": " + m); };
try {
  await page.goto("http://localhost:5050/", { waitUntil: "networkidle" });
  await page.waitForTimeout(1500);
  log(/\/auth/.test(page.url()) || (await page.locator("#login-email").count()) > 0, `app served + shows sign-in at http://localhost:5050 (${page.url()})`);
  await page.locator("#login-email").fill("admin@cyshield.local");
  await page.locator("#login-password").fill("ChangeMe123!");
  await Promise.all([page.waitForResponse((r) => r.url().includes("/api/auth/login")), page.getByRole("button", { name: /sign in/i }).click()]);
  await page.waitForTimeout(2500);
  const tok = await page.evaluate(() => localStorage.getItem("auth_token"));
  log(!!tok, "logged in via UI with seeded admin (admin@cyshield.local)");
  await page.goto("http://localhost:5050/", { waitUntil: "networkidle" });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: OUT + "/turnkey-dashboard.png" });
  const bodyText = await page.evaluate(() => document.body.innerText.slice(0, 300));
  log(/Dashboard|Security Overview|Launch|Cyshield/i.test(bodyText), "dashboard renders after login");
} catch (e) {
  log(false, "exception: " + e.message);
} finally {
  await b.close();
  const p = R.filter(Boolean).length;
  console.log(`\n=== TURNKEY UI QA: ${p}/${R.length} passed ===`);
  process.exit(p === R.length ? 0 : 1);
}
