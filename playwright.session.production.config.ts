import { defineConfig, devices } from "@playwright/test";

/**
 * Real production commerce-session acceptance against the lead-provisioned real
 * nginx images.
 *
 * No development/test server is launched and no webServer is reused. The
 * browser connects only to the fixed disposable origins below. Those origins
 * use the reserved test hostname `account.openarc.test`, which this fixture
 * maps to 127.0.0.1 inside Chromium via host-resolver-rules ONLY. No OS DNS
 * change, no proxy and no external host is contacted. The generated
 * self-signed TLS certificate is exempted for these fixed loopback fixture
 * origins only; the real nginx still terminates the connection and verifies its
 * upstream. Traces, screenshots, video and storageState stay off so no raw
 * handoff/session token can be captured.
 *
 * Projects:
 *  - enabled (5471) runs @session-on journeys with commerce sessions ON, plus
 *    account/tenant reads ON while policy HTTP, tenant writes, machine
 *    credentials/exchange HTTP and marketplace stay independently OFF;
 *  - off (5472) runs @session-off journeys with the session flag false and the
 *    same account/tenant reads usable.
 *
 * BOTH origins are required exactly. A wrong or absent enabled/off origin (or a
 * missing fixture opt-in) fails during config load, BEFORE any browser or
 * network activity, and the OFF project is registered unconditionally so a
 * missing exact origin can never be silently skipped.
 */

const ENABLED_ORIGIN = "https://account.openarc.test:5471";
const OFF_ORIGIN = "https://account.openarc.test:5472";

const baseURL = process.env["PLAYWRIGHT_SESSION_PRODUCTION_BASE_URL"];
if (baseURL !== ENABLED_ORIGIN) {
  throw new Error(
    `PLAYWRIGHT_SESSION_PRODUCTION_BASE_URL must be exactly ${ENABLED_ORIGIN}`,
  );
}
if (process.env["OPENARC_SESSION_PRODUCTION_FIXTURE"] !== "1") {
  throw new Error("OPENARC_SESSION_PRODUCTION_FIXTURE must be exactly 1");
}
if (process.env["OPENARC_TENANT_PRODUCTION_FIXTURE"] !== "1") {
  throw new Error("OPENARC_TENANT_PRODUCTION_FIXTURE must be exactly 1");
}

const offBaseURL = process.env["PLAYWRIGHT_SESSION_PRODUCTION_OFF_BASE_URL"];
if (offBaseURL !== OFF_ORIGIN) {
  throw new Error(
    `PLAYWRIGHT_SESSION_PRODUCTION_OFF_BASE_URL must be exactly ${OFF_ORIGIN}`,
  );
}

// Reserved test hostname resolved only inside this Chromium fixture.
const HOST_RESOLVER =
  "--host-resolver-rules=MAP account.openarc.test 127.0.0.1";

export default defineConfig({
  testDir: "./e2e-session-production",
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  maxFailures: 3,
  reporter: "list",
  timeout: 120_000,
  expect: { timeout: 5_000 },
  use: {
    trace: "off",
    screenshot: "off",
    video: "off",
    storageState: undefined,
    ignoreHTTPSErrors: true,
    // A bounded per-action timeout so a genuinely absent selector fails at its
    // real callsite instead of consuming the whole test timeout. The total test
    // timeout is unchanged and no assertion is relaxed.
    actionTimeout: 10_000,
  },
  projects: [
    {
      name: "chromium-session-production",
      grep: /@session-on/u,
      use: {
        ...devices["Desktop Chrome"],
        baseURL,
        launchOptions: { args: [HOST_RESOLVER] },
      },
    },
    {
      name: "chromium-session-production-off",
      grep: /@session-off/u,
      use: {
        ...devices["Desktop Chrome"],
        baseURL: offBaseURL,
        launchOptions: { args: [HOST_RESOLVER] },
      },
    },
  ],
});
