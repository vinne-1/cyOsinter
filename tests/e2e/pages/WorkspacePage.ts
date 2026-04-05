import { type Page, type Locator, expect } from "@playwright/test";

export class WorkspacePage {
  readonly page: Page;

  // Domain selector button in header
  readonly domainSelectorButton: Locator;

  // Create workspace flow
  readonly createWorkspaceMenuItem: Locator;
  readonly workspaceDomainInput: Locator;
  readonly confirmCreateButton: Locator;
  readonly cancelCreateButton: Locator;

  // Delete workspace flow
  readonly deleteWorkspaceMenuItem: Locator;
  readonly confirmDeleteButton: Locator;

  constructor(page: Page) {
    this.page = page;

    this.domainSelectorButton = page.getByTestId("button-domain-selector");
    this.createWorkspaceMenuItem = page.getByTestId("button-create-workspace");
    this.workspaceDomainInput = page.getByTestId("input-workspace-domain");
    this.confirmCreateButton = page.getByTestId("button-confirm-create-workspace");
    this.cancelCreateButton = page.getByTestId("button-cancel-workspace");
    this.deleteWorkspaceMenuItem = page.getByTestId("button-delete-workspace");

    // AlertDialog confirm delete button — label "Delete workspace"
    this.confirmDeleteButton = page.getByRole("button", { name: /^delete workspace$/i });
  }

  async goto() {
    await this.page.goto("/");
    await this.page.waitForLoadState("networkidle");
  }

  async openDomainSelector() {
    // Dismiss any open Radix dropdown or submenu before clicking the trigger.
    // A Radix sub-menu requires two Escape presses: first to close the sub-menu,
    // second to close the parent dropdown.  Pressing Escape when nothing is open
    // is a no-op.
    await this.page.keyboard.press("Escape");
    await this.page.keyboard.press("Escape");

    // Wait for the trigger to report "closed" (not "open") before clicking.
    await this.page.waitForFunction(
      () => {
        const el = document.querySelector('[data-testid="button-domain-selector"]');
        return !el || el.getAttribute("data-state") !== "open";
      },
      { timeout: 4000 },
    );

    await this.domainSelectorButton.click();
    await expect(this.createWorkspaceMenuItem).toBeVisible({ timeout: 5000 });
  }

  async createWorkspace(domain: string) {
    await this.openDomainSelector();
    await this.createWorkspaceMenuItem.click();
    await expect(this.workspaceDomainInput).toBeVisible();
    await this.workspaceDomainInput.fill(domain);

    const responsePromise = this.page.waitForResponse(
      (resp) => resp.url().includes("/api/workspaces") && resp.request().method() === "POST",
    );
    await this.confirmCreateButton.click();
    return responsePromise;
  }

  async deleteCurrentWorkspace() {
    await this.openDomainSelector();
    await this.deleteWorkspaceMenuItem.click();

    // Wait for the AlertDialog to appear
    await expect(this.page.getByRole("alertdialog")).toBeVisible();

    const responsePromise = this.page.waitForResponse(
      (resp) => resp.url().includes("/api/workspaces/") && resp.request().method() === "DELETE",
    );
    await this.confirmDeleteButton.click();
    return responsePromise;
  }

  async getVisibleWorkspaceNames(): Promise<string[]> {
    await this.openDomainSelector();
    // Each workspace shows as a sub-menu trigger with its domain name
    const workspaceItems = this.page.locator("[data-testid^='workspace-option-']");
    const count = await workspaceItems.count();
    const names: string[] = [];
    for (let i = 0; i < count; i++) {
      const testId = await workspaceItems.nth(i).getAttribute("data-testid");
      if (testId) {
        names.push(testId.replace("workspace-option-", ""));
      }
    }
    // Close dropdown
    await this.page.keyboard.press("Escape");
    return names;
  }

  async selectWorkspace(domain: string) {
    await this.openDomainSelector();
    const workspaceOption = this.page.getByTestId(`workspace-option-${domain}`);
    // Hover to open the submenu
    await workspaceOption.hover();
    // Click "Use as active workspace" from the submenu
    const useActiveItem = this.page.getByText("Use as active workspace");
    await useActiveItem.click();
  }

  async getSelectedWorkspaceName(): Promise<string> {
    const text = await this.domainSelectorButton.textContent();
    return text?.trim() ?? "";
  }

  /**
   * Delete a specific workspace by name using the per-workspace submenu delete option.
   * This does not require the workspace to be the active/selected workspace.
   */
  async deleteWorkspaceByName(domain: string) {
    await this.openDomainSelector();

    // Hover on the workspace sub-trigger to open its submenu
    const workspaceOption = this.page.getByTestId(`workspace-option-${domain}`);
    await workspaceOption.hover();

    // Click the per-workspace "Delete workspace" option in the submenu
    const deleteOption = this.page.getByTestId(`workspace-delete-${domain}`);
    await expect(deleteOption).toBeVisible({ timeout: 3000 });
    await deleteOption.click();

    // Wait for the AlertDialog to appear
    await expect(this.page.getByRole("alertdialog")).toBeVisible({ timeout: 5000 });

    const responsePromise = this.page.waitForResponse(
      (resp) => resp.url().includes("/api/workspaces/") && resp.request().method() === "DELETE",
    );
    await this.confirmDeleteButton.click();
    return responsePromise;
  }
}
