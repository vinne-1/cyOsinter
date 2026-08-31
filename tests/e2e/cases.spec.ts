import { test, expect, type Page } from "@playwright/test";
import { injectCachedToken, uniqueDomain } from "./helpers";

const TEST_PASSWORD = "TestPassword123!";
const USER_EMAIL = "ws-user-a@e2e.local";

/**
 * Browser coverage for the case lifecycle.
 *
 * Cases had unit tests for the transition table and API-level checks, but
 * nothing exercised the actual page — so a broken mutation, a mis-wired select
 * or a summary tile reading the wrong field would all have shipped green.
 *
 * These tests set up their own workspace through the API rather than the UI:
 * the workspace-creation journey is already covered in workspace.spec.ts, and
 * repeating it here would make a case failure look like a workspace failure.
 *
 * Each test removes the workspace it made. The global teardown only runs once
 * at the very end of the run, so without per-test cleanup these fixtures pile
 * up in the shared user's workspace switcher — which broke workspace.spec.ts,
 * whose delete flow has to hover the target row in that dropdown and could no
 * longer reach it in a longer list. A spec must not leave state for the next.
 */

/** Workspaces created by the current test, removed in afterEach. */
const createdWorkspaces: string[] = [];

/** Reads the bearer token the injected session is using. */
async function tokenOf(page: Page): Promise<string> {
  return page.evaluate(() => localStorage.getItem("auth_token") ?? "");
}

/** Creates a workspace directly, returning its id. */
async function createWorkspace(page: Page, baseURL: string): Promise<string> {
  const token = await tokenOf(page);
  const res = await page.request.post(`${baseURL}/api/workspaces`, {
    headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
    data: { name: uniqueDomain("cases"), description: "e2e cases fixture" },
  });
  expect(res.ok(), `workspace setup failed: ${res.status()}`).toBeTruthy();
  const id = (await res.json()).id as string;
  createdWorkspaces.push(id);
  return id;
}

/** Points the app at a workspace and opens the cases page. */
async function openCases(page: Page, baseURL: string, workspaceId: string): Promise<void> {
  await page.evaluate((id) => localStorage.setItem("selectedWorkspaceId", id), workspaceId);
  await page.goto(`${baseURL}/cases`);
  await page.waitForLoadState("networkidle");
}

test.describe("Case management", () => {
  test.afterEach(async ({ page, baseURL }) => {
    const token = await tokenOf(page).catch(() => "");
    while (createdWorkspaces.length) {
      const id = createdWorkspaces.pop()!;
      if (!token) continue;
      // Best effort: a cleanup failure must not fail an otherwise passing test.
      await page.request
        .delete(`${baseURL}/api/workspaces/${id}`, { headers: { Authorization: `Bearer ${token}` } })
        .catch(() => undefined);
    }
  });

  test("user can create a case and it appears in the list", async ({ page, baseURL }) => {
    await injectCachedToken(page, baseURL!, USER_EMAIL, TEST_PASSWORD);
    const workspaceId = await createWorkspace(page, baseURL!);
    await openCases(page, baseURL!, workspaceId);

    await page.getByTestId("button-new-case").click();
    await page.locator("#case-title").fill("Rotate exposed credentials");
    await page.getByRole("button", { name: /create case/i }).click();

    // The reference is allocated server-side per workspace, so a fresh
    // workspace must start at CASE-1.
    const row = page.getByTestId("case-CASE-1");
    await expect(row).toBeVisible({ timeout: 10_000 });
    await expect(row).toContainText("Rotate exposed credentials");
  });

  test("a new case starts unassigned and the summary says so", async ({ page, baseURL }) => {
    await injectCachedToken(page, baseURL!, USER_EMAIL, TEST_PASSWORD);
    const workspaceId = await createWorkspace(page, baseURL!);
    await openCases(page, baseURL!, workspaceId);

    await page.getByTestId("button-new-case").click();
    await page.locator("#case-title").fill("Unowned work");
    await page.getByRole("button", { name: /create case/i }).click();
    await expect(page.getByTestId("case-CASE-1")).toBeVisible({ timeout: 10_000 });

    // "Nobody is accountable" is the signal the page exists to surface.
    await expect(page.getByTestId("cases-unassigned-value")).toHaveText("1");
    await expect(page.getByTestId("case-CASE-1")).toContainText("Unassigned");
  });

  test("user can move a case through its lifecycle", async ({ page, baseURL }) => {
    await injectCachedToken(page, baseURL!, USER_EMAIL, TEST_PASSWORD);
    const workspaceId = await createWorkspace(page, baseURL!);
    await openCases(page, baseURL!, workspaceId);

    await page.getByTestId("button-new-case").click();
    await page.locator("#case-title").fill("Lifecycle walk");
    await page.getByRole("button", { name: /create case/i }).click();

    const row = page.getByTestId("case-CASE-1");
    await expect(row).toBeVisible({ timeout: 10_000 });

    // open -> investigating is the only legal first step; the server rejects
    // a jump straight to resolved.
    await row.getByRole("combobox").click();
    await page.getByRole("option", { name: "Investigating" }).click();

    await expect(row).toContainText("Investigating", { timeout: 10_000 });
  });

  test("case counts reflect what is actually open", async ({ page, baseURL }) => {
    await injectCachedToken(page, baseURL!, USER_EMAIL, TEST_PASSWORD);
    const workspaceId = await createWorkspace(page, baseURL!);
    await openCases(page, baseURL!, workspaceId);

    // A fresh workspace must read zero, not blank or NaN.
    await expect(page.getByTestId("cases-total-value")).toHaveText("0");
    await expect(page.getByTestId("cases-open-value")).toHaveText("0");

    await page.getByTestId("button-new-case").click();
    await page.locator("#case-title").fill("Counted case");
    await page.getByRole("button", { name: /create case/i }).click();

    await expect(page.getByTestId("cases-total-value")).toHaveText("1", { timeout: 10_000 });
    await expect(page.getByTestId("cases-open-value")).toHaveText("1");
  });

  test("empty state explains what a case is for", async ({ page, baseURL }) => {
    await injectCachedToken(page, baseURL!, USER_EMAIL, TEST_PASSWORD);
    const workspaceId = await createWorkspace(page, baseURL!);
    await openCases(page, baseURL!, workspaceId);

    // An empty page that just says "no data" teaches the user nothing.
    await expect(page.getByText("No cases yet")).toBeVisible();
    await expect(page.getByText(/when work spans several findings/i)).toBeVisible();
  });
});
