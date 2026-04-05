import { test, expect } from "@playwright/test";
import { WorkspacePage } from "./pages/WorkspacePage";
import { injectCachedToken, uniqueDomain } from "./helpers";
import fs from "fs";
import type { SharedAuthState } from "./global-setup";
import { SHARED_STATE_PATH } from "./global-setup";

const TEST_PASSWORD = "TestPassword123!";

// Accounts created in global-setup.ts — tokens cached in .auth-state.json
const USER_A_EMAIL = "ws-user-a@e2e.local";
const USER_B_EMAIL = "ws-user-b@e2e.local";

/** Read a token from the global auth state cache. */
function getCachedToken(email: string): string | null {
  try {
    const raw = fs.readFileSync(SHARED_STATE_PATH, "utf-8");
    const state = JSON.parse(raw) as SharedAuthState;
    return state.users[email]?.token ?? null;
  } catch {
    return null;
  }
}

test.describe("Workspace management", () => {
  test("user can create a workspace and it appears in the list", async ({ page, baseURL }) => {
    // This test USES the UI (DomainSelector) to verify the workspace appears.
    // Navigate to /easm instead of / to reduce API calls from dashboard queries.
    await injectCachedToken(page, baseURL!, USER_A_EMAIL, TEST_PASSWORD);

    await page.goto("/easm");
    await page.waitForLoadState("networkidle");

    const workspacePage = new WorkspacePage(page);
    const domain = uniqueDomain("ws-create");

    const response = await workspacePage.createWorkspace(domain);
    expect(response.status()).toBe(201);

    // After creation the UI auto-selects the new workspace
    await expect(workspacePage.domainSelectorButton).toContainText(domain, { timeout: 8000 });

    // Workspace should also appear in the dropdown list
    const names = await workspacePage.getVisibleWorkspaceNames();
    expect(names).toContain(domain);
  });

  test("workspace is NOT visible to a different user", async ({ page, baseURL }) => {
    // Pure API test — no browser navigation to the dashboard to avoid rate limits
    const tokenA = getCachedToken(USER_A_EMAIL);
    const tokenB = getCachedToken(USER_B_EMAIL);

    if (!tokenA || !tokenB) {
      throw new Error("Cached auth tokens not available — global-setup must run first");
    }

    // Navigate to establish origin for page.request
    await page.goto(`${baseURL}/auth`);

    const domain = uniqueDomain("ws-isolated");

    // User A creates a workspace via API
    const createResp = await page.request.post(`${baseURL}/api/workspaces`, {
      data: { name: domain },
      headers: { Authorization: `Bearer ${tokenA}` },
    });
    expect(createResp.status()).toBe(201);

    // User A should see it
    const listAsA = await page.request.get(`${baseURL}/api/workspaces`, {
      headers: { Authorization: `Bearer ${tokenA}` },
    });
    expect(listAsA.ok()).toBeTruthy();
    const workspacesA = (await listAsA.json()) as Array<{ name: string }>;
    expect(workspacesA.map((w) => w.name)).toContain(domain);

    // User B should NOT see it
    const listAsB = await page.request.get(`${baseURL}/api/workspaces`, {
      headers: { Authorization: `Bearer ${tokenB}` },
    });
    expect(listAsB.ok()).toBeTruthy();
    const workspacesB = (await listAsB.json()) as Array<{ name: string }>;
    expect(workspacesB.map((w) => w.name)).not.toContain(domain);
  });

  test("user can delete their workspace", async ({ page, baseURL }) => {
    // Create via API, delete via UI to test the UI delete flow
    const tokenA = getCachedToken(USER_A_EMAIL);
    if (!tokenA) {
      throw new Error("Cached auth token not available — global-setup must run first");
    }

    const domain = uniqueDomain("ws-delete");

    // Create workspace via API to avoid extra browser navigation
    const createResp = await page.request.post(`${baseURL}/api/workspaces`, {
      data: { name: domain },
      headers: { Authorization: `Bearer ${tokenA}` },
    });
    expect(createResp.status()).toBe(201);

    // Now inject token into browser and navigate to select the new workspace.
    // Use /easm to avoid the dashboard's extra queries.
    await injectCachedToken(page, baseURL!, USER_A_EMAIL, TEST_PASSWORD);
    await page.goto("/easm");
    await page.waitForLoadState("networkidle");

    // Delete the workspace via the UI using the per-workspace submenu option.
    // This avoids first selecting it as the active workspace.
    const workspacePage = new WorkspacePage(page);
    const deleteResp = await workspacePage.deleteWorkspaceByName(domain);
    expect(deleteResp.status()).toBe(204);

    // Confirm via API that the workspace is gone
    const listResp = await page.request.get(`${baseURL}/api/workspaces`, {
      headers: { Authorization: `Bearer ${tokenA}` },
    });
    const workspaces = (await listResp.json()) as Array<{ name: string }>;
    expect(workspaces.map((w) => w.name)).not.toContain(domain);
  });

  test("creating a workspace with a duplicate domain shows conflict error", async ({
    page,
    baseURL,
  }) => {
    // Pure API test for conflict detection
    const tokenA = getCachedToken(USER_A_EMAIL);
    if (!tokenA) {
      throw new Error("Cached auth token not available — global-setup must run first");
    }

    await page.goto(`${baseURL}/auth`);

    const domain = uniqueDomain("ws-dup");

    // Create the workspace for the first time
    const firstResp = await page.request.post(`${baseURL}/api/workspaces`, {
      data: { name: domain },
      headers: { Authorization: `Bearer ${tokenA}` },
    });
    expect(firstResp.status()).toBe(201);

    // Attempt to create the exact same domain again — expect 409 Conflict
    const duplicateResp = await page.request.post(`${baseURL}/api/workspaces`, {
      data: { name: domain },
      headers: { Authorization: `Bearer ${tokenA}` },
    });
    expect(duplicateResp.status()).toBe(409);

    const body = (await duplicateResp.json()) as { message: string };
    expect(body.message).toMatch(/already exists/i);
  });
});
