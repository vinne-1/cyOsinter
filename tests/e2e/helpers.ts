import { type Page } from "@playwright/test";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import type { SharedAuthState } from "./global-setup";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SHARED_STATE_PATH = path.join(__dirname, ".auth-state.json");

/**
 * Read the auth state written by global-setup.ts.
 * Returns null if the file does not exist yet.
 */
function readSharedState(): SharedAuthState | null {
  try {
    const raw = fs.readFileSync(SHARED_STATE_PATH, "utf-8");
    return JSON.parse(raw) as SharedAuthState;
  } catch {
    return null;
  }
}

/**
 * Inject a cached auth token into localStorage from the shared state written
 * by global-setup. This avoids hitting the /api/auth/login rate limit (5/min)
 * on every test.
 *
 * Falls back to a fresh API login if no cached token is available.
 */
export async function injectCachedToken(
  page: Page,
  baseURL: string,
  email: string,
  password: string,
): Promise<void> {
  const state = readSharedState();
  const cached = state?.users[email];

  if (cached) {
    // Navigate to auth page first to establish the origin
    await page.goto(`${baseURL}/auth`);
    await page.evaluate(
      ({ t, rt, u }) => {
        localStorage.setItem("auth_token", t);
        localStorage.setItem("auth_refresh_token", rt);
        localStorage.setItem("auth_user", JSON.stringify(u));
      },
      { t: cached.token, rt: cached.refreshToken, u: { email } },
    );
    return;
  }

  // No cache — fall back to API login
  await loginViaApi(page, baseURL, email, password);
}

/**
 * Inject a valid auth token directly into localStorage, bypassing the UI login
 * form. Use injectCachedToken instead when possible to avoid rate limits.
 */
export async function loginViaApi(
  page: Page,
  baseURL: string,
  email: string,
  password: string,
): Promise<void> {
  const response = await page.request.post(`${baseURL}/api/auth/login`, {
    data: { email, password },
  });

  if (!response.ok()) {
    throw new Error(
      `loginViaApi failed: ${response.status()} — ${await response.text()}`,
    );
  }

  const body = await response.json();
  const { token, refreshToken, user } = body as {
    token: string;
    refreshToken: string;
    user: unknown;
  };

  await page.goto(`${baseURL}/auth`);
  await page.evaluate(
    ({ t, rt, u }) => {
      localStorage.setItem("auth_token", t);
      localStorage.setItem("auth_refresh_token", rt);
      localStorage.setItem("auth_user", JSON.stringify(u));
    },
    { t: token, rt: refreshToken, u: user },
  );
}

/**
 * Register a new user via the API and inject the returned token into
 * localStorage. Useful for creating isolated test users.
 */
export async function registerViaApi(
  page: Page,
  baseURL: string,
  name: string,
  email: string,
  password: string,
): Promise<void> {
  const response = await page.request.post(`${baseURL}/api/auth/register`, {
    data: { name, email, password },
  });

  if (!response.ok()) {
    if (response.status() === 409) {
      await loginViaApi(page, baseURL, email, password);
      return;
    }
    throw new Error(
      `registerViaApi failed: ${response.status()} — ${await response.text()}`,
    );
  }

  const body = await response.json();
  const { token, refreshToken, user } = body as {
    token: string;
    refreshToken: string;
    user: unknown;
  };

  await page.goto(`${baseURL}/auth`);
  await page.evaluate(
    ({ t, rt, u }) => {
      localStorage.setItem("auth_token", t);
      localStorage.setItem("auth_refresh_token", rt);
      localStorage.setItem("auth_user", JSON.stringify(u));
    },
    { t: token, rt: refreshToken, u: user },
  );
}

/**
 * Generate a reasonably-unique email address for test isolation.
 */
export function uniqueEmail(prefix = "test"): string {
  return `${prefix}+${Date.now()}@e2e.local`;
}

/**
 * Generate a reasonably-unique domain name for workspace test isolation.
 */
export function uniqueDomain(prefix = "e2e"): string {
  return `${prefix}-${Date.now()}.example.com`;
}
