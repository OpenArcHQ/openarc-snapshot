import { defineConfig, devices } from "@playwright/test";

// Protected commerce-session acceptance suite.
//
// One browser worker, no retries, no server reuse and dedicated ports so no
// other worker's server is touched. Traces, videos and screenshots are OFF
// because these fixtures expose one-time handoff secrets. Every account, read,
// session capability and session read/write/status endpoint is intercepted with
// honestly labelled strict synthetic HTTP fixtures. This suite proves the UI and
// transport contract only: it is NOT proof of a live API, PostgreSQL, passkey
// freshness, TLS, the production nginx proxy or any wallet/payment behavior.
//
// The ON server (5293) enables account access, tenant reads and the API
// boundary while leaving tenant writes, machine credentials, listing and policy
// management OFF, proving commerce sessions are independent of all of them. The
// OFF server (5294) disables the session flag with the same parent flags.

const WEB_SESSION_ON = "http://localhost:5293";
const WEB_SESSION_OFF = "http://localhost:5294";
const API_ORIGIN = "http://127.0.0.1:3003";

export default defineConfig({
  testDir: "./e2e-commerce-sessions",
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  maxFailures: 3,
  reporter: "list",
  timeout: 60_000,
  use: {
    baseURL: WEB_SESSION_ON,
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  webServer: [
    {
      command: "pnpm --filter @openarc/web dev --port 5293",
      url: WEB_SESSION_ON,
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        VITE_COMMIT_SHA: "e2e-commerce-sessions",
        VITE_ACCOUNT_ACCESS_ENABLED: "true",
        VITE_API_BOUNDARY_ENABLED: "true",
        VITE_TENANT_READS_ENABLED: "true",
        VITE_TENANT_WRITES_ENABLED: "false",
        VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED: "false",
        VITE_LISTING_MANAGEMENT_ENABLED: "false",
        VITE_POLICY_MANAGEMENT_ENABLED: "false",
        VITE_COMMERCE_SESSIONS_ENABLED: "true",
        OPENARC_DEV_API_ORIGIN: API_ORIGIN,
      },
    },
    {
      command: "pnpm --filter @openarc/web dev --port 5294",
      url: WEB_SESSION_OFF,
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        VITE_COMMIT_SHA: "e2e-commerce-sessions-off",
        VITE_ACCOUNT_ACCESS_ENABLED: "true",
        VITE_API_BOUNDARY_ENABLED: "true",
        VITE_TENANT_READS_ENABLED: "true",
        VITE_TENANT_WRITES_ENABLED: "false",
        VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED: "false",
        VITE_LISTING_MANAGEMENT_ENABLED: "false",
        VITE_POLICY_MANAGEMENT_ENABLED: "false",
        VITE_COMMERCE_SESSIONS_ENABLED: "false",
        OPENARC_DEV_API_ORIGIN: API_ORIGIN,
      },
    },
  ],
  projects: [
    {
      name: "chromium-sessions",
      use: { ...devices["Desktop Chrome"] },
      testMatch: /session\.spec\.ts$/u,
    },
    {
      name: "webkit-sessions",
      use: { ...devices["Desktop Safari"] },
      testMatch: /session\.spec\.ts$/u,
    },
    {
      name: "chromium-sessions-off",
      use: { ...devices["Desktop Chrome"], baseURL: WEB_SESSION_OFF },
      testMatch: /session-off\.spec\.ts$/u,
    },
  ],
});
