/**
 * E2E flow: Navigate app, select workspace, run EASM scan, verify Intelligence & Reports.
 * Run: npx tsx script/e2e-flow.ts
 */
import { chromium } from "playwright";

const BASE_URL = process.env.E2E_BASE_URL || "http://localhost:8080";
const WORKSPACE = process.env.E2E_WORKSPACE || "tv9.com";

async function main() {
  const observations: string[] = [];
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
  const page = await context.newPage();

  try {
    // 1. Navigate to app
    await page.goto(BASE_URL, { waitUntil: "networkidle" });
    observations.push(`Navigated to ${BASE_URL}`);

    // 2. Select workspace
    await page.waitForSelector('[data-testid="button-domain-selector"]', { timeout: 15000 });
    await page.click('[data-testid="button-domain-selector"]');
    await page.waitForTimeout(500);
    const workspaceOpt = page.locator(`[data-testid="workspace-option-${WORKSPACE}"]`);
    const hasWorkspace = await workspaceOpt.count() > 0;
    if (!hasWorkspace) {
      observations.push(`Workspace "${WORKSPACE}" not found in selector. Available workspaces may differ.`);
    } else {
      await workspaceOpt.click();
      await page.waitForTimeout(300);
      const useActive = page.getByRole("menuitem", { name: /Use as active workspace/i });
      if (await useActive.isVisible()) {
        await useActive.click();
      }
      await page.waitForTimeout(300);
      observations.push(`Selected workspace: ${WORKSPACE}`);
    }
    // Close dropdown - press Escape and click main to dismiss
    await page.keyboard.press("Escape");
    await page.waitForTimeout(200);
    await page.click("main", { force: true }).catch(() => {});
    await page.waitForTimeout(200);

    // 3. Go to EASM page
    await page.goto(`${BASE_URL}/easm`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(2000);
    // Re-select workspace after navigation if needed (state may persist)
    const domainSelector = page.locator('[data-testid="button-domain-selector"]');
    if (await domainSelector.isVisible().catch(() => false)) {
      await domainSelector.click();
      await page.waitForTimeout(300);
      const wsOpt = page.locator(`[data-testid="workspace-option-${WORKSPACE}"]`);
      if ((await wsOpt.count()) > 0) {
        await wsOpt.click();
        await page.waitForTimeout(200);
        const useActive = page.getByRole("menuitem", { name: /Use as active workspace/i });
        if (await useActive.isVisible()) await useActive.click();
        await page.keyboard.press("Escape");
      }
      await page.waitForTimeout(300);
    }
    await page.waitForTimeout(500);
    observations.push("Navigated to EASM (Attack Surface) page");

    // 4. Click New Scan if visible (optional - may already have scans)
    const newScanBtn = page.getByRole("button", { name: /New Scan/i }).first();
    if (await newScanBtn.isVisible().catch(() => false)) {
      await newScanBtn.click();
      await page.waitForTimeout(500);

      // 5. Verify target, scan type, scan mode
      const targetInput = page.locator('[data-testid="input-scan-target"]');
      const targetVal = await targetInput.inputValue();
      const scanTypeSelect = page.locator('[data-testid="select-scan-type"]');
      const scanModeSelect = page.locator('[data-testid="select-scan-mode"]');
      const scanTypeText = await scanTypeSelect.textContent();
      const scanModeText = await scanModeSelect.textContent();

      observations.push(`Target: ${targetVal} (expected: ${WORKSPACE})`);
      observations.push(`Scan type: ${scanTypeText?.trim()} (expected: Full Scan (EASM + OSINT))`);
      observations.push(`Scan mode: ${scanModeText?.trim()} (expected: Gold (comprehensive, no limits))`);

      if (targetVal !== WORKSPACE) await targetInput.fill(WORKSPACE);

      await page.click('[data-testid="button-start-scan"]');
      await page.waitForTimeout(2000);

      const scanCard = page.locator('[data-testid="card-easm-scans"]');
      await scanCard.waitFor({ state: "visible", timeout: 5000 });
      const runningBadge = page.locator('[data-testid="badge-scan-status-running"], [data-testid="badge-scan-status-pending"]');
      await runningBadge.first().waitFor({ state: "visible", timeout: 15000 });
      observations.push("Scan started and shows as running/pending");
      await page.waitForTimeout(15000);
    } else {
      observations.push("New Scan button not visible, skipping scan start (may have existing scans)");
    }

    // 8. Navigate to Intelligence
    await page.goto(`${BASE_URL}/intelligence`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(2000);
    const ds2 = page.locator('[data-testid="button-domain-selector"]');
    if (await ds2.isVisible().catch(() => false)) await ds2.click();
    await page.waitForTimeout(200);
    const wsOpt2 = page.locator(`[data-testid="workspace-option-${WORKSPACE}"]`);
    if ((await wsOpt2.count()) > 0) {
      await wsOpt2.click();
      await page.waitForTimeout(200);
      const ua = page.getByRole("menuitem", { name: /Use as active workspace/i });
      if (await ua.isVisible()) await ua.click();
      await page.keyboard.press("Escape");
    }
    await page.waitForTimeout(3000);

    // 9. Verify Attack Surface panel shows per-asset data
    const attackSurfaceTab = page.locator('[data-testid="tab-attack_surface"]');
    if (await attackSurfaceTab.isVisible()) {
      await attackSurfaceTab.click();
      await page.waitForTimeout(1000);
    }
    const attackSurfacePanel = page.locator('[data-testid="panel-attack-surface"]');
    const panelVisible = await attackSurfacePanel.isVisible();
    observations.push(`Attack Surface panel visible: ${panelVisible}`);

    if (panelVisible) {
      const perAssetTitle = page.locator("text=Per-Asset Attack Surface").first();
      const hasPerAsset = await perAssetTitle.isVisible();
      observations.push(`Per-Asset Attack Surface section visible: ${hasPerAsset}`);
    } else {
      const noData = await page.locator("text=No intelligence data yet").isVisible();
      observations.push(`Intelligence shows 'No data yet': ${noData} (scan may still be running)`);
    }

    // 10. Navigate to Reports
    await page.goto(`${BASE_URL}/reports`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(2000);
    const ds3 = page.locator('[data-testid="button-domain-selector"]');
    if (await ds3.isVisible().catch(() => false)) await ds3.click();
    await page.waitForTimeout(200);
    const wsOpt3 = page.locator(`[data-testid="workspace-option-${WORKSPACE}"]`);
    if ((await wsOpt3.count()) > 0) {
      await wsOpt3.click();
      await page.waitForTimeout(200);
      const ua3 = page.getByRole("menuitem", { name: /Use as active workspace/i });
      if (await ua3.isVisible()) await ua3.click();
      await page.keyboard.press("Escape");
    }
    await page.waitForTimeout(300);
    observations.push("Navigated to Reports page");

    // 11. Create new report
    const newReportBtn = page.locator('[data-testid="button-new-report"]');
    if (await newReportBtn.isVisible().catch(() => false)) {
      await newReportBtn.click();
    await page.waitForTimeout(500);
      await page.fill('[data-testid="input-report-title"]', "E2E Test Report - " + new Date().toISOString().slice(0, 19));
      await page.click('[data-testid="button-generate-report"]');
      await page.waitForTimeout(3000);
    }

    // 12. Verify report includes attack surface summary
    const reportCards = page.locator('[data-testid^="card-report-"]');
    const reportCount = await reportCards.count();
    observations.push(`Reports created: ${reportCount}`);

    if (reportCount > 0) {
      await reportCards.first().click();
      await page.waitForTimeout(2000);
      // Check for attack surface content in report detail (use first match to avoid strict mode)
      const hasAttackSurfaceInReport =
        (await page.locator("text=Per-Asset Attack Surface").first().isVisible().catch(() => false)) ||
        (await page.locator("text=Surface Risk Score").first().isVisible().catch(() => false)) ||
        (await page.locator("text=Hosts").first().isVisible().catch(() => false));
      observations.push(`Report includes attack surface summary: ${hasAttackSurfaceInReport}`);
    }

    // Print summary
    console.log("\n=== E2E Flow Observations ===\n");
    observations.forEach((o) => console.log("•", o));
    console.log("\n=== End ===\n");
  } catch (err) {
    observations.push(`Error: ${(err as Error).message}`);
    console.error(err);
    try {
      await page.screenshot({ path: "e2e-failure.png" });
      observations.push("Screenshot saved to e2e-failure.png");
    } catch (_) {}
    console.log("\n=== Partial Observations ===\n");
    observations.forEach((o) => console.log("•", o));
  } finally {
    await browser.close();
  }
}

main();
