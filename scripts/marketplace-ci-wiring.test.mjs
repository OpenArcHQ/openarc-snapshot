import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

/**
 * Static wiring guards for the marketplace public/protected CI packet.
 *
 * These assertions read only the root package.json and the public source
 * workflow. They prove the three marketplace aliases exist verbatim, that the
 * public market and protected listing journeys run sequentially in the root e2e
 * gate exactly once immediately before the machine-management journey, that the
 * reference contract gate sits after build and before the browser gate, that
 * the additive deployment guards are invoked alongside every existing guard,
 * and that the workflow stays manual-only, isolated and honestly summarised.
 *
 * They do not run a browser, build an image, start PostgreSQL or execute the
 * reference contract; marketplace browser suites use synthetic HTTP fixtures
 * and the reference artifacts are contract-only.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => readFileSync(path.join(root, relativePath), "utf8");

const scripts = JSON.parse(read("package.json")).scripts;
const workflow = read(".github/workflows/source-checks.yml");

const MARKET_ALIAS = "playwright test -c playwright.market-public.config.ts";
const LISTINGS_ALIAS = "playwright test -c playwright.listing-management.config.ts";
const REFERENCE_ALIAS =
  "pnpm --filter @openarc/shared build && node --test tools/reference-provider/contract.test.mjs";
const MACHINE = "playwright test -c playwright.machine-management.config.ts";
const WRITE = "playwright test -c playwright.tenant-write.config.ts";
const SUPPLIED = "playwright test -c playwright.supplied.config.ts";

/** Every development journey the root e2e gate ran before the marketplace packet. */
const ORIGINAL_JOURNEYS = [
  "playwright test",
  "playwright test -c playwright.flag-off.config.ts",
  "playwright test -c playwright.api-boundary.config.ts",
  "playwright test -c playwright.arc-observation.config.ts",
  "playwright test -c playwright.agent-registry.config.ts",
  "playwright test -c playwright.job-evidence.config.ts",
  "playwright test -c playwright.gateway-evidence.config.ts",
  "playwright test -c playwright.local-agent-import.config.ts",
  "playwright test -c playwright.investigations.config.ts",
  "playwright test -c playwright.investigations.flag-off.config.ts",
  "playwright test -c playwright.machine-management.config.ts",
];

/** Guard filenames the deployment guard command carried before this packet. */
const EXISTING_GUARDS = [
  "scripts/account-deployment.test.mjs",
  "scripts/tenant-deployment.test.mjs",
  "scripts/tenant-write-deployment.test.mjs",
  "scripts/tenant-ci-wiring.test.mjs",
  "scripts/worker-ci-wiring.test.mjs",
  "scripts/machine-deployment.test.mjs",
  "scripts/machine-ci-wiring.test.mjs",
  "scripts/capability-deployment.test.mjs",
];

const count = (haystack, needle) => haystack.split(needle).length - 1;

test("marketplace aliases run the exact frozen Playwright configs and reference contract", () => {
  assert.equal(scripts["e2e:market"], MARKET_ALIAS);
  assert.equal(scripts["e2e:listings"], LISTINGS_ALIAS);
  assert.equal(scripts["test:reference-contract"], REFERENCE_ALIAS);
});

test("root e2e runs market then listings exactly once sequentially before machine-management", () => {
  const e2e = scripts["e2e"];
  assert.equal(typeof e2e, "string");
  assert.equal(count(e2e, MARKET_ALIAS), 1, "root e2e must run the public market suite exactly once");
  assert.equal(count(e2e, LISTINGS_ALIAS), 1, "root e2e must run the protected listing suite exactly once");
  assert.equal(count(e2e, "playwright.market-public.config.ts"), 1, "the market config must be invoked exactly once");
  assert.equal(
    count(e2e, "playwright.listing-management.config.ts"),
    1,
    "the listing config must be invoked exactly once",
  );
  assert.ok(
    e2e.includes(`${MARKET_ALIAS} && ${LISTINGS_ALIAS}`),
    "market must run sequentially immediately before listings (overlapping ports must not run in parallel)",
  );
  assert.ok(
    e2e.includes(`${LISTINGS_ALIAS} && ${MACHINE}`),
    "listings must run immediately before the machine-management journey",
  );
  assert.ok(
    e2e.indexOf(MARKET_ALIAS) < e2e.indexOf(LISTINGS_ALIAS) &&
      e2e.indexOf(LISTINGS_ALIAS) < e2e.indexOf(MACHINE),
    "market must precede listings which must precede machine-management",
  );
});

test("root e2e preserves the existing command order and final supplied journey", () => {
  const e2e = scripts["e2e"];
  const order = [MACHINE, WRITE, "pnpm e2e:tenant", SUPPLIED];
  let cursor = -1;
  for (const step of order) {
    const next = e2e.indexOf(step);
    assert.ok(next > cursor, `root e2e must keep the order and include: ${step}`);
    cursor = next;
  }
  assert.ok(e2e.includes(`${MACHINE} && ${WRITE}`), "machine must stay immediately before the tenant-write suite");
  assert.ok(e2e.includes(`${WRITE} && pnpm e2e:tenant`), "tenant-write must stay immediately before the tenant journey");
  assert.ok(
    e2e.includes(`pnpm e2e:tenant && ${SUPPLIED}`),
    "the tenant journey must stay immediately before the supplied journey",
  );
  assert.ok(e2e.endsWith(SUPPLIED), "the supplied journey must remain the final suite");
});

test("root e2e keeps every original journey and never runs a production fixture", () => {
  const e2e = scripts["e2e"];
  for (const journey of ORIGINAL_JOURNEYS) {
    assert.ok(e2e.includes(journey), `root e2e must keep the journey: ${journey}`);
  }
  assert.ok(
    !/e2e:(?:market|listings):production|market-public\.production\.config\.ts|listing-management\.production\.config\.ts/u.test(
      e2e,
    ),
    "no production browser command may run in development e2e",
  );
});

test("release gate runs the reference contract once after build and before e2e", () => {
  const releaseGate = scripts["release:gate"];
  assert.equal(typeof releaseGate, "string");
  assert.equal(
    count(releaseGate, "pnpm test:reference-contract"),
    1,
    "release gate must run the reference contract exactly once",
  );
  const build = releaseGate.indexOf("pnpm build");
  const reference = releaseGate.indexOf("pnpm test:reference-contract");
  const e2e = releaseGate.indexOf("pnpm e2e");
  assert.ok(build !== -1, "release gate must keep the recursive build");
  assert.ok(e2e !== -1, "release gate must keep the root e2e gate");
  assert.ok(build < reference && reference < e2e, "reference contract must run after build and before e2e");
  for (const step of ["release:check", "audit:prod", "licenses:check", "lint", "typecheck"]) {
    assert.ok(releaseGate.includes(`pnpm ${step}`), `release gate must keep: pnpm ${step}`);
  }
});

test("workflow deployment guard command keeps every existing guard and appends both marketplace guards", () => {
  const guardLine = workflow
    .split("\n")
    .find((line) => line.includes("node --test scripts/account-deployment.test.mjs"));
  assert.ok(guardLine, "the guard invocation must run inside the built gate image");
  for (const guard of EXISTING_GUARDS) {
    assert.ok(guardLine.includes(guard), `the gate guard invocation must keep ${guard}`);
  }
  assert.ok(
    guardLine.includes("scripts/marketplace-deployment.test.mjs"),
    "the gate guard invocation must add the marketplace deployment guard",
  );
  assert.ok(
    guardLine.includes("scripts/marketplace-ci-wiring.test.mjs"),
    "the gate guard invocation must add the marketplace CI wiring guard",
  );
});

test("workflow keeps a single manual, pinned, read-only, isolated and honestly bounded gate", () => {
  assert.match(workflow, /on:\s*\n\s*workflow_dispatch:/u);
  assert.ok(
    !/^\s{2}(?:push|pull_request|schedule|repository_dispatch):/mu.test(workflow),
    "no extra pipeline trigger may be added",
  );
  assert.match(workflow, /timeout-minutes:\s*40\b/u);
  assert.match(workflow, /actions\/checkout@[0-9a-f]{40}/u);
  assert.match(workflow, /persist-credentials:\s*false/u);
  assert.match(workflow, /permissions:\s*\n\s*contents:\s*read/u);
  assert.ok(workflow.includes("node scripts/check-public-history.mjs"), "identity history guard must remain");
  assert.ok(workflow.includes("node --test scripts/check-public-history.test.mjs"), "identity guard tests must remain");
  assert.match(workflow, /docker build -f scripts\/Dockerfile\.node22-gate/u);
  assert.equal(count(workflow, "docker build -f scripts/Dockerfile.node22-gate"), 1, "one Docker source gate only");

  assert.ok(workflow.includes("--network none"), "the PostgreSQL fixture must stay network-isolated");
  assert.match(workflow, /postgres@sha256:[0-9a-f]{64}/u);
  assert.ok(workflow.includes("cleanup()"), "the isolated fixture must keep its cleanup trap");
  const pg = workflow
    .split("\n")
    .find((line) => line.includes("pnpm --filter @openarc/db test:postgres"));
  assert.ok(pg, "the PostgreSQL step must run the DB suite");
  const pgOrder = [
    "pnpm --filter @openarc/db test:postgres",
    "pnpm --filter @openarc/api test:postgres",
    "pnpm --filter @openarc/worker test:postgres",
    "pnpm e2e:accounts",
  ];
  let cursor = -1;
  for (const step of pgOrder) {
    const next = pg.indexOf(step);
    assert.ok(next > cursor, `PostgreSQL step must run in order and include: ${step}`);
    cursor = next;
  }
  assert.ok(!/railway|paid/iu.test(pg), "the PostgreSQL step must not use paid services");
});

test("workflow summary honestly bounds marketplace, database and reference evidence", () => {
  assert.ok(
    /marketplace[^\n]*public[^\n]*protected development browser tests use synthetic HTTP fixtures/iu.test(workflow),
    "summary must state that marketplace/public/protected dev browser tests use synthetic HTTP fixtures",
  );
  assert.ok(
    /real API\/DB suites use isolated PostgreSQL/iu.test(workflow),
    "summary must state that real API/DB suites use isolated PostgreSQL",
  );
  assert.ok(
    /reference artifacts are contract-only/iu.test(workflow),
    "summary must state that reference artifacts are contract-only",
  );
  assert.ok(
    /actual production-image\/browser and mainnet validation is not proved/iu.test(workflow),
    "summary must state that actual production-image/browser and mainnet validation is not proved",
  );
  assert.ok(
    !/production-image\/browser and mainnet validation (?:was|is) (?:performed|proved|verified)/iu.test(workflow),
    "the workflow must not overclaim production or mainnet validation",
  );
});
