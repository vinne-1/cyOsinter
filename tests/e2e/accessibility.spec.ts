import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { injectCachedToken } from "./helpers";

/**
 * WCAG 2.1 A/AA sweep across every route.
 *
 * This existed only as a command someone remembered to run by hand, which means
 * it was really a one-off audit rather than a check: nothing stopped the next
 * UI change from reintroducing a contrast or label failure, and the result was
 * only ever as current as the last time somebody thought to look.
 *
 * Scope is deliberately serious + critical. axe's `minor` and `moderate` rules
 * include judgement calls that produce noise on a dense dashboard, and a gate
 * that cries wolf gets switched off. These two levels are the ones that
 * actually stop somebody using the page.
 */

const TEST_PASSWORD = "TestPassword123!";
const USER_EMAIL = "ws-user-a@e2e.local";

/** Every authenticated route, from App.tsx. */
const ROUTES = [
  "/", "/easm", "/osint", "/findings", "/intelligence", "/reports",
  "/integrations", "/imports", "/ai-insights", "/alerts", "/scheduled-scans",
  "/compliance", "/trends", "/scan-profiles", "/attack-paths", "/audit-log",
  "/webhook-config", "/api-keys", "/finding-groups", "/scan-comparison",
  "/threat-intel", "/retention", "/playbooks", "/asset-risk", "/brand-threats",
  "/cases", "/account",
];

test.describe("Accessibility (WCAG 2.1 A/AA)", () => {
  // One browser context for the whole sweep: 27 routes each paying a fresh
  // login would dominate the runtime and tell us nothing extra.
  test("every route is free of serious and critical violations", async ({ page, baseURL }) => {
    test.setTimeout(300_000);
    await injectCachedToken(page, baseURL!, USER_EMAIL, TEST_PASSWORD);

    const failures: string[] = [];

    /*
     * An uncaught render error is not an accessibility finding, but this is the
     * only test that visits every route AND every tab — so it is the only place
     * that can notice one, and it is worth the four lines.
     *
     * `/asset-risk` shipped completely broken: a hook placed after an early
     * return threw "Rendered more hooks than during the previous render" on the
     * loading→loaded transition, React tore the page down, and NOTHING in the
     * suite failed. axe cannot report it because a page that rendered nothing
     * has no violations, which is the trap — an empty page looks perfectly
     * accessible.
     */
    const pageErrors: string[] = [];
    page.on("pageerror", (e) => {
      // First line only: a React stack is long and the message is the signal.
      const msg = String(e.message).split(String.fromCharCode(10))[0]!.trim();
      if (!pageErrors.includes(msg)) pageErrors.push(msg);
    });
    let errorsSeen = 0;
    const notePageErrors = (label: string) => {
      for (let i = errorsSeen; i < pageErrors.length; i++) {
        failures.push(`${label} — [uncaught] ${pageErrors[i]}`);
      }
      errorsSeen = pageErrors.length;
    };

    const scan = async (label: string) => {
      notePageErrors(label);
      const results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();

      for (const v of results.violations) {
        if (v.impact !== "serious" && v.impact !== "critical") continue;
        // Name the element, not just the rule: "colour-contrast on 3 nodes" is
        // not something anyone can act on without hunting for them.
        const where = v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ");
        failures.push(`${label} — [${v.impact}] ${v.id}: ${v.help} (${v.nodes.length} node(s)) → ${where}`);
      }
    };

    for (const route of ROUTES) {
      await page.goto(`${baseURL}${route}`);
      await page.waitForLoadState("networkidle");
      await scan(route);

      // Tabbed content is mounted one panel at a time, so visiting the route
      // only ever measured the DEFAULT tab. That is a structural blind spot,
      // not a gap in coverage: two real defects — a 2.65:1 timestamp and a
      // scrollable region no keyboard could reach — lived in intelligence
      // panels the sweep had never once rendered. Activate each tab and measure
      // what it actually shows.
      const tabs = await page.locator("[role='tab']").all();
      for (let i = 0; i < tabs.length; i++) {
        // Re-query each time: activating a tab can re-render the strip.
        const tab = page.locator("[role='tab']").nth(i);
        if (!(await tab.isVisible().catch(() => false))) continue;
        const name = (await tab.getAttribute("data-testid")) ?? `tab-${i}`;
        await tab.click({ timeout: 5000 }).catch(() => { /* strip may scroll */ });
        await page.waitForTimeout(250);
        await scan(`${route} [${name}]`);
      }

      // Collapsed disclosures are the same blind spot as an unopened tab: the
      // risk-factor rows and the compliance controls render their findings only
      // once expanded, so everything inside them — severity chips, links,
      // scrollable panels — was never measured. Expanding is cheap and it is
      // where newly written markup lives.
      const toggles = await page
        .locator("[data-testid^='factor-toggle-'], [data-testid^='control-toggle-']")
        .all();
      if (toggles.length > 0) {
        for (let i = 0; i < Math.min(toggles.length, 6); i++) {
          const t = page
            .locator("[data-testid^='factor-toggle-'], [data-testid^='control-toggle-']")
            .nth(i);
          if (!(await t.isVisible().catch(() => false))) continue;
          await t.click({ timeout: 5000 }).catch(() => { /* layout may shift */ });
        }
        await page.waitForTimeout(300);
        await scan(`${route} [expanded]`);
      }
    }

    expect(failures, `Accessibility violations:\n${failures.join("\n")}`).toEqual([]);
  });

  test("the login page is accessible to an unauthenticated visitor", async ({ page, baseURL }) => {
    // The one route a user meets before they have an account, and the only one
    // the authenticated sweep above cannot reach.
    await page.goto(`${baseURL}/auth`);
    await page.waitForLoadState("networkidle");

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();

    const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
    expect(
      serious.map((v) => `[${v.impact}] ${v.id}: ${v.help}`),
      "Login page must be usable by everyone",
    ).toEqual([]);
  });
});
