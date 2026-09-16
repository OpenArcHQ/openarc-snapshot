import { defineConfig } from "@playwright/test";

/**
 * PORT-04 P04-03 offline buyer-flow acceptance.
 *
 * OFFLINE BY CONSTRUCTION. There is no browser project, no webServer and no
 * external origin. The suite boots the REAL API process against a disposable
 * loopback PostgreSQL, and stands up the reference provider and the LOCAL FAKE
 * facilitator on loopback inside the worker. No live Circle, Gateway or Arc
 * endpoint is contacted, no funds move and no persistent key exists: every key
 * is generated in memory per run and dropped with it.
 *
 * Traces, screenshots and video stay OFF so no raw commerce session, grant
 * token, signature or key can be captured.
 *
 * The disposable database URL and every fixture opt-in are required EXACTLY,
 * and are checked during config load, BEFORE any test, process or connection.
 */

const FIXTURE_URL = process.env["OPENARC_TEST_DATABASE_URL"];
if (typeof FIXTURE_URL !== "string" || !/^postgres:\/\/postgres:openarc_disposable_test@127\.0\.0\.1:\d{1,5}\/openarc_auth_test$/u.test(FIXTURE_URL)) {
  throw new Error("OPENARC_TEST_DATABASE_URL must be the exact disposable loopback fixture URL");
}
for (const flag of [
  "OPENARC_COMMERCE_PAYMENT_FIXTURE",
  "OPENARC_COMMERCE_PRODUCTION_FIXTURE",
  "OPENARC_SESSION_PRODUCTION_FIXTURE",
  "OPENARC_TENANT_PRODUCTION_FIXTURE",
]) {
  if (process.env[flag] !== "1") throw new Error(`${flag} must be exactly 1`);
}

export default defineConfig({
  testDir: "./e2e-commerce-payment",
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  // Every scenario is independent evidence; a failure in one must not hide the
  // result of the others, so the run is not cut short.
  maxFailures: 0,
  reporter: "list",
  timeout: 300_000,
  expect: { timeout: 15_000 },
  use: { trace: "off", screenshot: "off", video: "off", storageState: undefined },
  projects: [{ name: "commerce-payment-offline" }],
});
