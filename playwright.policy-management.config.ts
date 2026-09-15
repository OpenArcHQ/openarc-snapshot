import { defineConfig, devices } from "@playwright/test";

// Protected control-policy acceptance suite.
//
// One browser worker, no retries, no server reuse and dedicated ports so no
// other worker's server is touched. Every account, read, control capability,
// policy read and policy write/status endpoint is intercepted with honestly
// labelled strict synthetic HTTP fixtures. This suite proves the UI and
// transport contract only: it is NOT proof of a live API, PostgreSQL, passkey
// freshness, TLS, the production nginx proxy or any fund movement.
//
// The ON server (5283) enables account access, tenant reads and the API
// boundary while leaving tenant writes, machine credentials and listing
// management OFF, proving policy management is independent of all of them. The
// OFF server (5284) disables the policy flag with the same parent flags.

const WEB_POLICY_ON = "http://localhost:5283";
const WEB_POLICY_OFF = "http://localhost:5284";
const API_ORIGIN = "http://127.0.0.1:3003";

export default defineConfig({
  testDir: "./e2e-policy-management",
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  maxFailures: 3,
  reporter: "list",
  timeout: 60_000,
  use: {
    baseURL: WEB_POLICY_ON,
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  webServer: [
    {
      command: "pnpm --filter @openarc/web dev --port 5283",
      url: WEB_POLICY_ON,
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        VITE_COMMIT_SHA: "e2e-policy-management",
        VITE_ACCOUNT_ACCESS_ENABLED: "true",
        VITE_API_BOUNDARY_ENABLED: "true",
        VITE_TENANT_READS_ENABLED: "true",
        VITE_TENANT_WRITES_ENABLED: "false",
        VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED: "false",
        VITE_LISTING_MANAGEMENT_ENABLED: "false",
        VITE_POLICY_MANAGEMENT_ENABLED: "true",
        OPENARC_DEV_API_ORIGIN: API_ORIGIN,
      },
    },
    {
      command: "pnpm --filter @openarc/web dev --port 5284",
      url: WEB_POLICY_OFF,
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        VITE_COMMIT_SHA: "e2e-policy-management-off",
        VITE_ACCOUNT_ACCESS_ENABLED: "true",
        VITE_API_BOUNDARY_ENABLED: "true",
        VITE_TENANT_READS_ENABLED: "true",
        VITE_TENANT_WRITES_ENABLED: "false",
        VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED: "false",
        VITE_LISTING_MANAGEMENT_ENABLED: "false",
        VITE_POLICY_MANAGEMENT_ENABLED: "false",
        OPENARC_DEV_API_ORIGIN: API_ORIGIN,
      },
    },
  ],
  projects: [
    {
      name: "chromium-policy",
      use: { ...devices["Desktop Chrome"] },
      testMatch: /policy\.spec\.ts$/u,
    },
    {
      name: "webkit-policy",
      use: { ...devices["Desktop Safari"] },
      testMatch: /policy\.spec\.ts$/u,
    },
    {
      name: "chromium-policy-off",
      use: { ...devices["Desktop Chrome"], baseURL: WEB_POLICY_OFF },
      testMatch: /policy-off\.spec\.ts$/u,
    },
  ],
});
