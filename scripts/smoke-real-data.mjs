/**
 * Render smoke test against the operator's REAL workspaces.
 *
 * This exists because the Playwright suite cannot catch a whole class of bug.
 * `tests/e2e/accessibility.spec.ts` sweeps every route and tab, but it logs in
 * as a throwaway `@e2e.local` account with **no data** — so every page renders
 * its empty state and any defect that only appears once rows arrive is
 * invisible to it.
 *
 * That is not hypothetical. `/asset-risk` shipped completely broken: a hook
 * placed after an early return threw "Rendered more hooks than during the
 * previous render" on the loading→loaded transition, React tore the page down,
 * and the whole suite stayed green. axe cannot report it either, because a page
 * that rendered nothing has no accessibility violations — an empty page looks
 * perfectly accessible.
 *
 * It is a SCRIPT rather than a test on purpose: it reads whatever workspaces
 * the operator happens to have, so it cannot assert fixed numbers and must not
 * gate CI. Run it after touching any page component.
 *
 *   node scripts/smoke-real-data.mjs
 *   node scripts/smoke-real-data.mjs --max-rows 60
 *
 * Exits non-zero if any page throws or renders an error boundary.
 */
import { chromium } from "playwright";

const BASE = process.env.APP_URL || "http://localhost:5050";
const EMAIL = process.env.SEED_ADMIN_EMAIL || "admin@cyshield.local";
const PASSWORD = process.env.SEED_ADMIN_PASSWORD || "ChangeMe123!";

const args = process.argv.slice(2);
const argOf = (flag, fallback) => {
  const i = args.indexOf(flag);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};
/** Above this, a list is a scroll rather than a view — see list-pager.tsx. */
const MAX_ROWS = Number(argOf("--max-rows", "120"));

const ROUTES = [
  "/", "/easm", "/osint", "/findings", "/intelligence", "/compliance",
  "/asset-risk", "/reports", "/cases", "/attack-paths", "/brand-threats",
  "/trends", "/finding-groups", "/scan-comparison",
];

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
const page = await ctx.newPage();

const problems = [];
let currentLabel = "(startup)";
page.on("pageerror", (e) => {
  const msg = String(e.message).split(String.fromCharCode(10))[0].trim();
  problems.push(`${currentLabel} — uncaught: ${msg}`);
});

await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
await page.fill('input[type="email"]', EMAIL);
await page.fill('input[type="password"]', PASSWORD);
await page.click('button[type="submit"]');
await page.waitForTimeout(3000);

const workspaces = await page.evaluate(async () => {
  const t = localStorage.getItem("auth_token");
  const r = await fetch("/api/workspaces", { headers: { Authorization: `Bearer ${t}` } });
  const j = await r.json();
  return (Array.isArray(j) ? j : (j.data ?? [])).map((w) => ({ id: w.id, name: w.name }));
});

if (workspaces.length === 0) {
  console.error("No workspaces visible — this script needs real data to be useful.");
  await browser.close();
  process.exit(1);
}

let biggest = { n: 0, where: "-" };
let checks = 0;

/** Everything measured at the current render: errors, boundary, list sizes. */
async function inspect(label) {
  currentLabel = label;
  checks++;

  if (await page.locator("text=Something went wrong").count()) {
    const detail = await page
      .locator("text=Something went wrong")
      .locator("xpath=following::p[1]")
      .innerText()
      .catch(() => "?");
    problems.push(`${label} — error boundary: ${detail}`);
  }

  const sizes = await page.locator("table tbody").evaluateAll((els) =>
    els.map((e) => e.querySelectorAll("tr").length),
  );
  const lists = await page.locator("ul, ol").evaluateAll((els) => els.map((e) => e.children.length));
  const n = Math.max(0, ...sizes, ...lists);
  if (n > biggest.n) biggest = { n, where: label };
  if (n > MAX_ROWS) problems.push(`${label} — renders ${n} rows in one list (cap ${MAX_ROWS})`);
}

for (const w of workspaces) {
  await page.evaluate((id) => localStorage.setItem("selectedWorkspaceId", id), w.id);
  for (const route of ROUTES) {
    await page.goto(BASE + route, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(2200);
    await inspect(`[${w.name}] ${route}`);

    // Tabbed content mounts one panel at a time, so an unvisited tab is
    // unmeasured — the same structural blind spot the a11y sweep documents.
    const tabCount = await page.locator("[role='tab']").count();
    for (let i = 0; i < tabCount; i++) {
      const tab = page.locator("[role='tab']").nth(i);
      if (!(await tab.isVisible().catch(() => false))) continue;
      await tab.click({ timeout: 5000 }).catch(() => { /* strip may scroll */ });
      await page.waitForTimeout(300);
      await inspect(`[${w.name}] ${route} [tab ${i}]`);
    }
  }
}

await browser.close();

console.log(`checked ${checks} render(s) across ${workspaces.length} workspace(s)`);
console.log(`largest single rendered list: ${biggest.n} rows @ ${biggest.where}`);

/*
 * Same guard as the other gates: a run that rendered nothing must not report
 * success. `inspect` counts every render it examines, so zero here means the
 * route loop never executed — a changed ROUTES list, a login that silently
 * failed — and the clean result would be meaningless.
 */
if (checks === 0) {
  problems.push("NO COVERAGE: no page was rendered — this run cannot have passed");
}

if (problems.length) {
  console.error(`\n${problems.length} problem(s):`);
  for (const p of [...new Set(problems)]) console.error(`  ${p}`);
  process.exit(1);
}
console.log("no render errors, no error boundaries, no oversized lists.");
