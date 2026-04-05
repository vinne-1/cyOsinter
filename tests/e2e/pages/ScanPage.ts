import { type Page, type Locator, expect } from "@playwright/test";

export class ScanPage {
  readonly page: Page;

  // New scan dialog trigger button
  readonly newScanButton: Locator;

  // Scan form fields
  readonly scanTargetInput: Locator;
  readonly scanTypeSelect: Locator;
  readonly startScanButton: Locator;

  // Scan list / cards
  readonly easmScansCard: Locator;

  constructor(page: Page) {
    this.page = page;

    this.newScanButton = page.getByTestId("button-new-easm-scan");
    this.scanTargetInput = page.getByTestId("input-scan-target");
    this.scanTypeSelect = page.getByTestId("select-scan-type");
    this.startScanButton = page.getByTestId("button-start-scan");
    this.easmScansCard = page.getByTestId("card-easm-scans");
  }

  async goto() {
    await this.page.goto("/easm");
    await this.page.waitForLoadState("networkidle");
  }

  async waitForPageLoad() {
    // Wait for EASM title to confirm the page rendered
    await expect(this.page.getByTestId("text-easm-title")).toBeVisible({ timeout: 15000 });
  }

  async openNewScanDialog() {
    await this.newScanButton.click();
    await expect(this.scanTargetInput).toBeVisible();
  }

  async triggerScan(target: string) {
    await this.openNewScanDialog();

    // Clear existing value and fill target
    await this.scanTargetInput.clear();
    await this.scanTargetInput.fill(target);

    const responsePromise = this.page.waitForResponse(
      (resp) => resp.url().includes("/api/scans") && resp.request().method() === "POST",
    );
    await this.startScanButton.click();
    return responsePromise;
  }

  async getScanStatuses(): Promise<string[]> {
    // Status badges rendered by ScanStatusBadge component
    const badges = this.page.locator("[data-testid='card-easm-scans'] .rounded-full, [data-testid='card-easm-scans'] [class*='badge']");
    const count = await badges.count();
    const statuses: string[] = [];
    for (let i = 0; i < count; i++) {
      const text = await badges.nth(i).textContent();
      if (text) statuses.push(text.trim().toLowerCase());
    }
    return statuses;
  }
}
