import { defineConfig, devices } from "@playwright/test";

const isCI = !!process.env.CI;
const wantHtmlReport = process.env.PW_HTML === "1";

export default defineConfig({
  testDir: "../../scripts/tests/frontend/web-admin/e2e",
  testMatch: "**/*.pw.ts",
  fullyParallel: true,
  forbidOnly: isCI,
  retries: isCI ? 2 : 0,
  workers: isCI ? 1 : undefined,
  reporter: wantHtmlReport ? [["html", { open: "never" }]] : [["list"]],
  use: {
    baseURL: "http://localhost:1430",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: "bun run dev",
    env: { E2E: "1" },
    url: "http://localhost:1430",
    reuseExistingServer: !isCI,
    timeout: 120 * 1000,
  },
});
