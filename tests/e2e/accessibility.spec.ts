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
  "/cases",
];

test.describe("Accessibility (WCAG 2.1 A/AA)", () => {
  // One browser context for the whole sweep: 26 routes each paying a fresh
  // login would dominate the runtime and tell us nothing extra.
  test("every route is free of serious and critical violations", async ({ page, baseURL }) => {
    test.setTimeout(300_000);
    await injectCachedToken(page, baseURL!, USER_EMAIL, TEST_PASSWORD);

    const failures: string[] = [];

    for (const route of ROUTES) {
      await page.goto(`${baseURL}${route}`);
      await page.waitForLoadState("networkidle");

      const results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();

      for (const v of results.violations) {
        if (v.impact !== "serious" && v.impact !== "critical") continue;
        // Name the element, not just the rule: "colour-contrast on 3 nodes" is
        // not something anyone can act on without hunting for them.
        const where = v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ");
        failures.push(`${route} — [${v.impact}] ${v.id}: ${v.help} (${v.nodes.length} node(s)) → ${where}`);
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
