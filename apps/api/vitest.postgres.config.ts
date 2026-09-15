import { defineConfig } from "vitest/config";

/**
 * Explicit real-PostgreSQL suite for the account-only auth slice and the
 * protected tenant read slice.
 *
 * It includes ONLY the postgres test files and FAILS when the exact disposable
 * fixture URL is absent: there is no silent skip. Existing API postgres tests
 * remain included.
 */
const fixtureUrl = process.env["OPENARC_TEST_DATABASE_URL"];
if (!fixtureUrl) {
  throw new Error(
    "OPENARC_TEST_DATABASE_URL is required for the API postgres auth suite.",
  );
}

export default defineConfig({
  test: {
    environment: "node",
    include: [
      "test/auth-service.postgres.test.ts",
      "test/tenant-reads.postgres.test.ts",
      "test/tenant-writes.postgres.test.ts",
      "test/market-api.postgres.test.ts",
      "test/market-lifecycle-api.postgres.test.ts",
      "test/machine-api.postgres.test.ts",
      "test/control-policy-api.postgres.test.ts",
      "test/control-session-api.postgres.test.ts",
      "test/control-grant-adapter.postgres.test.ts",
      "test/control-payment-api.postgres.test.ts",
    ],
    fileParallelism: false,
  },
});
