import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  globalSetup: "./tests/e2e/global-setup.ts",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: [
    ["list"],
    ["html", { outputFolder: "playwright-report", open: "never" }],
    ["junit", { outputFile: "playwright-results.xml" }],
  ],
  use: {
    baseURL: "http://localhost:5050",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "off",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  // Start the dev server before tests if not already running.
  // The app reads PORT from .env (default 5050 for this project).
  webServer: {
    command: "npm run dev",
    url: "http://localhost:5050",
    reuseExistingServer: true,
    timeout: 90000,
    env: {
      PORT: "5050",
    },
  },
  outputDir: "test-results",
});
