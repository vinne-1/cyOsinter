import { request } from "@playwright/test";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BASE_URL = "http://localhost:5050";
const TEST_PASSWORD = "TestPassword123!";

export const SHARED_STATE_PATH = path.join(__dirname, ".auth-state.json");

export interface SharedAuthState {
  users: Record<string, { token: string; refreshToken: string }>;
}

/**
 * Global setup runs once before all test suites.
 *
 * Rate limits (per IP per minute):
 *   /api/auth/register — 3 req/min
 *   /api/auth/login    — 5 req/min
 *
 * Design principles:
 *   1. LOGIN first — only try register if login returns 401 (user does not exist).
 *   2. Cache tokens in .auth-state.json and reuse them (< 23h) to avoid ANY
 *      API calls on repeat runs.
 *   3. If we had to register any accounts, wait 62s for the rate limit window
 *      to reset before the tests start (the "register a new account" test
 *      fires one more register call).
 */
export default async function globalSetup() {
  // Fast path: reuse a recent cache file
  try {
    const raw = fs.readFileSync(SHARED_STATE_PATH, "utf-8");
    const parsed = JSON.parse(raw) as SharedAuthState & { _createdAt?: number };
    const ageMs = Date.now() - (parsed._createdAt ?? 0);
    const allPresent = [
      "auth-shared@e2e.local",
      "ws-user-a@e2e.local",
      "ws-user-b@e2e.local",
    ].every((e) => !!parsed.users[e]?.token);
    if (ageMs < 23 * 60 * 60 * 1000 && allPresent) {
      console.log("[global-setup] Reusing cached auth state (< 23h old).");
      return;
    }
  } catch {
    // No cache file or corrupt — fall through to create accounts
  }

  const ctx = await request.newContext({ baseURL: BASE_URL });

  // Warm up the DB connection pool — the first request after a server restart
  // can fail with 500 due to pg-pool initialization latency.
  // Use GET /api/workspaces with a dummy token (falls under the general 100/min limit,
  // not the login 5/min limit) to probe readiness without consuming login quota.
  console.log("[global-setup] Warming up DB connection pool...");
  for (let attempt = 0; attempt < 5; attempt++) {
    const probe = await ctx.get("/api/workspaces", {
      headers: { Authorization: "Bearer warmup-probe-dummy-token" },
    });
    // 401 = DB is ready (auth checked), 500 = DB pool not ready yet
    if (probe.status() !== 500) break;
    console.log(`[global-setup] DB pool not ready (attempt ${attempt + 1}/5), waiting 3s...`);
    await new Promise((r) => setTimeout(r, 3000));
  }

  const accounts = [
    { name: "Auth Shared", email: "auth-shared@e2e.local" },
    { name: "WS User A", email: "ws-user-a@e2e.local" },
    { name: "WS User B", email: "ws-user-b@e2e.local" },
  ];

  const state: SharedAuthState & { _createdAt: number } = {
    users: {},
    _createdAt: Date.now(),
  };

  let madeRegisterCalls = false;

  for (const account of accounts) {
    // Try LOGIN first — this does NOT use the register quota
    const loginRes = await ctx.post("/api/auth/login", {
      data: { email: account.email, password: TEST_PASSWORD },
    });

    if (loginRes.ok()) {
      const body = await loginRes.json();
      state.users[account.email] = { token: body.token, refreshToken: body.refreshToken };
      console.log(`[global-setup] Logged in: ${account.email}`);
      await new Promise((r) => setTimeout(r, 400));
      continue;
    }

    if (loginRes.status() === 401) {
      // User doesn't exist — register it
      console.log(`[global-setup] Registering: ${account.email}`);
      madeRegisterCalls = true;
      const regRes = await ctx.post("/api/auth/register", {
        data: { name: account.name, email: account.email, password: TEST_PASSWORD },
      });
      if (regRes.ok()) {
        const body = await regRes.json();
        state.users[account.email] = { token: body.token, refreshToken: body.refreshToken };
        console.log(`[global-setup] Registered: ${account.email}`);
      } else {
        console.warn(
          `[global-setup] Register failed for ${account.email}: ${regRes.status()} ${await regRes.text()}`,
        );
      }
      // Throttle between register calls to stay within 3/min
      await new Promise((r) => setTimeout(r, 1300));
    } else {
      console.warn(
        `[global-setup] Login returned unexpected status for ${account.email}: ${loginRes.status()}`,
      );
      await new Promise((r) => setTimeout(r, 500));
    }
  }

  // If we made register calls, we've used part of the 3/min register rate limit.
  // Wait for the window to reset so the "register a new account" auth test can fire
  // its own register call without getting 429.
  if (madeRegisterCalls) {
    console.log("[global-setup] Register calls made — waiting 62s for rate-limit reset...");
    await new Promise((r) => setTimeout(r, 62000));
    // Update the timestamp so the wait accounts for the new window
    state._createdAt = Date.now();
  }

  fs.writeFileSync(SHARED_STATE_PATH, JSON.stringify(state, null, 2));
  console.log(`[global-setup] Auth state saved to ${SHARED_STATE_PATH}`);
  await ctx.dispose();
}
