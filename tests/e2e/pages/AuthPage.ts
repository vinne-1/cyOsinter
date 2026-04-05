import { type Page, type Locator, expect } from "@playwright/test";

export class AuthPage {
  readonly page: Page;
  readonly loginTabTrigger: Locator;
  readonly registerTabTrigger: Locator;

  // Login form elements
  readonly loginEmailInput: Locator;
  readonly loginPasswordInput: Locator;
  readonly loginSubmitButton: Locator;

  // Register form elements
  readonly registerNameInput: Locator;
  readonly registerEmailInput: Locator;
  readonly registerPasswordInput: Locator;
  readonly registerSubmitButton: Locator;

  constructor(page: Page) {
    this.page = page;

    this.loginTabTrigger = page.getByRole("tab", { name: "Login" });
    this.registerTabTrigger = page.getByRole("tab", { name: "Register" });

    this.loginEmailInput = page.locator("#login-email");
    this.loginPasswordInput = page.locator("#login-password");
    this.loginSubmitButton = page.getByRole("button", { name: /sign in/i });

    this.registerNameInput = page.locator("#reg-name");
    this.registerEmailInput = page.locator("#reg-email");
    this.registerPasswordInput = page.locator("#reg-password");
    this.registerSubmitButton = page.getByRole("button", { name: /create account/i });
  }

  async goto() {
    await this.page.goto("/auth");
    await this.page.waitForLoadState("networkidle");
  }

  async switchToRegister() {
    await this.registerTabTrigger.click();
    await expect(this.registerNameInput).toBeVisible();
  }

  async login(email: string, password: string) {
    await this.loginEmailInput.fill(email);
    await this.loginPasswordInput.fill(password);

    const responsePromise = this.page.waitForResponse(
      (resp) => resp.url().includes("/api/auth/login") && resp.request().method() === "POST",
    );
    await this.loginSubmitButton.click();
    return responsePromise;
  }

  async register(name: string, email: string, password: string) {
    await this.switchToRegister();
    await this.registerNameInput.fill(name);
    await this.registerEmailInput.fill(email);
    await this.registerPasswordInput.fill(password);

    const responsePromise = this.page.waitForResponse(
      (resp) => resp.url().includes("/api/auth/register") && resp.request().method() === "POST",
    );
    await this.registerSubmitButton.click();
    return responsePromise;
  }

  async getAuthToken(): Promise<string | null> {
    return this.page.evaluate(() => localStorage.getItem("auth_token"));
  }

  async clearAuth() {
    await this.page.evaluate(() => {
      localStorage.removeItem("auth_token");
      localStorage.removeItem("auth_refresh_token");
      localStorage.removeItem("auth_user");
    });
  }
}
