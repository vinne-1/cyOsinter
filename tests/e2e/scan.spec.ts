import { test, expect } from "@playwright/test";
import { ScanPage } from "./pages/ScanPage";
import { WorkspacePage } from "./pages/WorkspacePage";
import { injectCachedToken, uniqueDomain } from "./helpers";

const TEST_PASSWORD = "TestPassword123!";

// Reuse ws-user-a — created by global-setup.ts, token cached in .auth-state.json
const SHARED_EMAIL = "ws-user-a@e2e.local";

test.describe("Scan management", () => {
  test("user can trigger a scan from the EASM page", async ({ page, baseURL }) => {
    await injectCachedToken(page, baseURL!, SHARED_EMAIL, TEST_PASSWORD);

    // Create a workspace so the scan has a workspaceId context.
    // Navigate to /easm directly to avoid dashboard API overhead.
    await page.goto("/easm");
    await page.waitForLoadState("networkidle");

    const domain = uniqueDomain("scan-target");
    const workspacePage = new WorkspacePage(page);
    await workspacePage.createWorkspace(domain);
    await expect(workspacePage.domainSelectorButton).toContainText(domain, { timeout: 8000 });

    // Already on EASM page — just wait for it to fully load
    const scanPage = new ScanPage(page);
    await scanPage.waitForPageLoad();

    // Trigger the scan — target is pre-filled; override to ensure correct domain
    const scanResponse = await scanPage.triggerScan(domain);
    expect(scanResponse.status()).toBe(201);

    const body = (await scanResponse.json()) as { id: string; status: string; target: string };
    expect(body.target).toBe(domain);
    expect(["pending", "running"]).toContain(body.status);
  });

  test("triggered scan appears in the scan list with pending or running status", async ({
    page,
    baseURL,
  }) => {
    await injectCachedToken(page, baseURL!, SHARED_EMAIL, TEST_PASSWORD);

    await page.goto("/easm");
    await page.waitForLoadState("networkidle");

    const domain = uniqueDomain("scan-list");
    const workspacePage = new WorkspacePage(page);
    await workspacePage.createWorkspace(domain);
    await expect(workspacePage.domainSelectorButton).toContainText(domain, { timeout: 8000 });

    // Already on EASM page — just wait for it to fully load
    const scanPage = new ScanPage(page);
    await scanPage.waitForPageLoad();

    // Open dialog and fill in target
    await scanPage.openNewScanDialog();
    await scanPage.scanTargetInput.clear();
    await scanPage.scanTargetInput.fill(domain);

    // Wait for POST /api/scans response
    const scanRespPromise = page.waitForResponse(
      (resp) => resp.url().includes("/api/scans") && resp.request().method() === "POST",
      { timeout: 15000 },
    );
    await scanPage.startScanButton.click();
    const scanResp = await scanRespPromise;
    expect(scanResp.status()).toBe(201);

    // The EASM scans card only renders when scans exist for the selected workspace
    await expect(scanPage.easmScansCard).toBeVisible({ timeout: 10000 });

    // The card should contain the target domain text
    await expect(scanPage.easmScansCard).toContainText(domain, { timeout: 8000 });

    // The ScanStatusBadge component maps:
    //   "pending"  → label "Pending"
    //   "running"  → label "In Progress"
    //   "completed"→ label "Completed"
    // So we check for any active status text
    const cardText = await scanPage.easmScansCard.textContent();
    expect(cardText?.toLowerCase()).toMatch(/pending|in progress|running/);
  });
});
