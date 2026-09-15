import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

/**
 * Static wiring guards for the machine-management CI packet.
 *
 * These assertions read the root package.json and the public source workflow.
 * They prove the two machine aliases exist verbatim, that the mocked machine
 * journey runs in the root e2e gate exactly once before the tenant-write suite,
 * that every legacy journey and deployment guard is preserved, that no
 * actual-production fixture leaks into development/CI, and that the workflow
 * keeps its complete Docker source gate and isolated PostgreSQL DB -> API ->
 * worker -> account order. They do not run a browser, build an image, touch a
 * database or prove an actual-production machine acceptance.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => readFileSync(path.join(root, relativePath), "utf8");

const scripts = JSON.parse(read("package.json")).scripts;
const workflow = read(".github/workflows/source-checks.yml");

const MACHINE_ALIAS = "playwright test -c playwright.machine-management.config.ts";
const MACHINE_PRODUCTION_ALIAS = "playwright test -c playwright.machine.production.config.ts";
const WRITE_ALIAS = "playwright test -c playwright.tenant-write.config.ts";
const SUPPLIED = "playwright test -c playwright.supplied.config.ts";

/** Every development journey the root e2e gate ran before the machine packet. */
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
];

const WRITE_PRODUCTION_ALIAS = "playwright test -c playwright.tenant-write.production.config.ts";

const count = (haystack, needle) => haystack.split(needle).length - 1;

test("machine aliases run the exact accepted Playwright configs", () => {
  assert.equal(scripts["e2e:machine"], MACHINE_ALIAS);
  assert.equal(scripts["e2e:machine:production"], MACHINE_PRODUCTION_ALIAS);
});

test("root e2e runs the mocked machine suite exactly once before the tenant-write suite", () => {
  const e2e = scripts["e2e"];
  assert.equal(typeof e2e, "string");
  assert.equal(count(e2e, MACHINE_ALIAS), 1, "root e2e must run the mocked machine suite exactly once");
  assert.equal(count(e2e, "playwright.machine-management.config.ts"), 1, "the machine config must be invoked exactly once");
  assert.ok(
    e2e.includes(`${MACHINE_ALIAS} && ${WRITE_ALIAS}`),
    "the mocked machine suite must run immediately before the tenant-write suite",
  );
  assert.ok(
    e2e.indexOf(MACHINE_ALIAS) < e2e.indexOf(WRITE_ALIAS),
    "the machine suite must precede the tenant-write suite",
  );
  assert.ok(
    e2e.includes(`${WRITE_ALIAS} && pnpm e2e:tenant`),
    "the tenant-write suite must stay immediately before the tenant journey",
  );
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
  assert.ok(!e2e.includes("machine.production.config.ts"), "no actual-production machine fixture in dev e2e");
  assert.ok(!e2e.includes("e2e:machine:production"), "the production machine alias must not run in dev e2e");
  assert.ok(!e2e.includes(WRITE_PRODUCTION_ALIAS), "no actual-production write fixture in dev e2e");
  const releaseGate = scripts["release:gate"];
  assert.equal(typeof releaseGate, "string");
  assert.ok(!releaseGate.includes("e2e:machine:production"), "production machine alias must stay out of the release gate");
  for (const step of ["release:check", "audit:prod", "licenses:check", "lint", "typecheck"]) {
    assert.ok(releaseGate.includes(`pnpm ${step}`), `release gate must keep: pnpm ${step}`);
  }
  assert.ok(releaseGate.includes("pnpm e2e"), "release gate must still run the root e2e gate");
});

test("workflow built gate image runs the machine deployment and CI wiring guards with the existing set", () => {
  const guardLine = workflow
    .split("\n")
    .find((line) => line.includes("node --test scripts/account-deployment.test.mjs"));
  assert.ok(guardLine, "the guard invocation must run inside the built gate image");
  for (const guard of [
    "scripts/account-deployment.test.mjs",
    "scripts/tenant-deployment.test.mjs",
    "scripts/tenant-write-deployment.test.mjs",
    "scripts/tenant-ci-wiring.test.mjs",
    "scripts/worker-ci-wiring.test.mjs",
    "scripts/machine-deployment.test.mjs",
    "scripts/machine-ci-wiring.test.mjs",
  ]) {
    assert.ok(guardLine.includes(guard), `the gate guard invocation must include ${guard}`);
  }
});

test("workflow retains the manual trigger, pinned actions/images, read-only permissions and identity guards", () => {
  assert.match(workflow, /on:\s*\n\s*workflow_dispatch:/u);
  assert.match(workflow, /actions\/checkout@[0-9a-f]{40}/u);
  assert.match(workflow, /persist-credentials:\s*false/u);
  assert.match(workflow, /timeout-minutes:\s*40\b/u);
  assert.match(workflow, /permissions:\s*\n\s*contents:\s*read/u);
  assert.ok(workflow.includes("node scripts/check-public-history.mjs"), "identity history guard must remain");
  assert.ok(workflow.includes("node --test scripts/check-public-history.test.mjs"), "identity guard tests must remain");
  assert.match(workflow, /docker build -f scripts\/Dockerfile\.node22-gate/u);
});

test("workflow PostgreSQL step runs DB, API, worker then accounts on one isolated fixture", () => {
  assert.ok(workflow.includes("--network none"), "the PostgreSQL fixture must stay network-isolated");
  assert.match(workflow, /postgres@sha256:[0-9a-f]{64}/u);
  assert.ok(workflow.includes("cleanup()"), "the isolated fixture must keep its cleanup trap");
  const pg = workflow
    .split("\n")
    .find((line) => line.includes("pnpm --filter @openarc/db test:postgres"));
  assert.ok(pg, "the PostgreSQL step must run the DB suite");
  const order = [
    "pnpm --filter @openarc/db test:postgres",
    "pnpm --filter @openarc/api test:postgres",
    "pnpm --filter @openarc/worker test:postgres",
    "pnpm e2e:accounts",
  ];
  let cursor = -1;
  for (const step of order) {
    const next = pg.indexOf(step);
    assert.ok(next > cursor, `PostgreSQL step must run in order and include: ${step}`);
    cursor = next;
  }
  assert.equal(count(pg, "pnpm --filter @openarc/worker test:postgres"), 1, "worker PostgreSQL suite must run exactly once");
  assert.ok(!/production|railway|paid/iu.test(pg), "the PostgreSQL step must not use production services");
});

test("workflow summary names the mocked machine journeys and distinguishes production-image acceptance", () => {
  assert.match(workflow, /mocked machine/iu, "summary must name the mocked machine journeys");
  assert.match(workflow, /production-image/iu, "summary must distinguish separate production-image acceptance");
  assert.ok(
    !/actual.production machine acceptance (?:was|is) (?:performed|run|verified)/iu.test(workflow),
    "the workflow must not overclaim actual-production machine acceptance",
  );
});
