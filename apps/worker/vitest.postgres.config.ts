import { defineConfig } from "vitest/config";

/**
 * Explicit real-PostgreSQL suites for the worker process: the bounded tenant
 * notification loop and the bounded settlement observation loop.
 *
 * It includes ONLY the postgres test files and FAILS when the exact disposable
 * fixture URL is absent: there is no silent skip. The suites reset only the
 * guarded disposable fixture database and never run in parallel with each
 * other.
 */
const fixtureUrl = process.env["OPENARC_TEST_DATABASE_URL"];
if (!fixtureUrl) {
  throw new Error(
    "OPENARC_TEST_DATABASE_URL is required for the worker postgres suite.",
  );
}

export default defineConfig({
  test: {
    environment: "node",
    include: [
      "test/worker.postgres.test.ts",
      "test/settlement-observation.postgres.test.ts",
    ],
    fileParallelism: false,
  },
});
