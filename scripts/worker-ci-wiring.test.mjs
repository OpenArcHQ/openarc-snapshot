import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

/**
 * Static wiring guards for the tenant-write + worker CI packet.
 *
 * These assertions read the root package.json, the gate Dockerfile, the
 * production worker Dockerfile and the public workflow. They prove alias
 * exactness, root e2e ordering, frozen manifest copying, worker recursive
 * discovery, PostgreSQL step ordering, deployment guard inclusion and the
 * production worker image policy. They do not run a browser, build an image or
 * touch a live database, wallet or paid service.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => readFileSync(path.join(root, relativePath), "utf8");

const scripts = JSON.parse(read("package.json")).scripts;
const gateDockerfile = read("scripts/Dockerfile.node22-gate");
const workerDockerfile = read("apps/worker/Dockerfile");
const workflow = read(".github/workflows/source-checks.yml");

const WRITE_ALIAS = "playwright test -c playwright.tenant-write.config.ts";
const WRITE_PRODUCTION_ALIAS = "playwright test -c playwright.tenant-write.production.config.ts";
const SUPPLIED = "playwright test -c playwright.supplied.config.ts";

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

const count = (haystack, needle) => haystack.split(needle).length - 1;

test("tenant-write aliases run the exact frozen Playwright configs", () => {
  assert.equal(scripts["e2e:tenant:writes"], WRITE_ALIAS);
  assert.equal(scripts["e2e:tenant:writes:production"], WRITE_PRODUCTION_ALIAS);
});

test("root e2e runs the mocked write suite exactly once immediately before the tenant journey", () => {
  const e2e = scripts["e2e"];
  assert.equal(typeof e2e, "string");
  assert.equal(count(e2e, WRITE_ALIAS), 1, "root e2e must run the mocked write suite exactly once");
  assert.ok(
    e2e.includes(`${WRITE_ALIAS} && pnpm e2e:tenant`),
    "the mocked write suite must run immediately before the tenant journey",
  );
  assert.equal(count(e2e, "pnpm e2e:tenant"), 1, "the tenant journey must run exactly once");
  assert.ok(
    e2e.includes(`pnpm e2e:tenant && ${SUPPLIED}`),
    "the tenant journey must stay immediately before the supplied journey",
  );
  assert.ok(e2e.endsWith(SUPPLIED), "the supplied journey must remain the final suite");
});

test("root e2e keeps every legacy journey and never runs a production fixture", () => {
  const e2e = scripts["e2e"];
  for (const journey of ORIGINAL_JOURNEYS) {
    assert.ok(e2e.includes(journey), `root e2e must keep the journey: ${journey}`);
  }
  assert.ok(!e2e.includes("tenant-write.production.config.ts"), "no actual-production write fixture in dev e2e");
  assert.ok(!e2e.includes("e2e:tenant:writes:production"), "production alias must not run in dev e2e");
});

test("release gate keeps the security steps and does not duplicate the worker unit run", () => {
  const releaseGate = scripts["release:gate"];
  assert.equal(typeof releaseGate, "string");
  for (const step of ["release:check", "audit:prod", "licenses:check", "lint", "typecheck"]) {
    assert.ok(releaseGate.includes(`pnpm ${step}`), `release gate must keep: pnpm ${step}`);
  }
  assert.ok(releaseGate.includes("pnpm test"), "release gate must run the recursive test gate");
  assert.ok(releaseGate.includes("pnpm build"), "release gate must run the recursive build gate");
  assert.ok(!releaseGate.includes("@openarc/worker"), "worker units are discovered recursively, not duplicated");
  assert.ok(!releaseGate.includes("test:postgres"), "release gate must not run the PostgreSQL suites");
});

test("root recursive gates discover the worker workspace", () => {
  assert.ok(scripts["test"].includes("pnpm -r"), "root test must recurse across workspaces");
  assert.ok(scripts["typecheck"].includes("pnpm -r"), "root typecheck must recurse across workspaces");
  assert.ok(scripts["build"].includes("pnpm -r"), "root build must recurse across workspaces");
});

test("gate Dockerfile copies the worker manifest before the frozen install", () => {
  const workerManifest = gateDockerfile.indexOf("COPY apps/worker/package.json apps/worker/package.json");
  const frozenInstall = gateDockerfile.indexOf("RUN pnpm install --frozen-lockfile");
  assert.ok(workerManifest !== -1, "gate image must copy apps/worker/package.json");
  assert.ok(frozenInstall !== -1, "gate image must keep the frozen install");
  assert.ok(workerManifest < frozenInstall, "the worker manifest must be copied before the frozen install");
  for (const manifest of [
    "COPY apps/api/package.json apps/api/package.json",
    "COPY apps/web/package.json apps/web/package.json",
    "COPY packages/db/package.json packages/db/package.json",
    "COPY packages/shared/package.json packages/shared/package.json",
    "COPY packages/config/package.json packages/config/package.json",
  ]) {
    assert.ok(gateDockerfile.indexOf(manifest) < frozenInstall, `${manifest} must precede the frozen install`);
  }
  assert.ok(gateDockerfile.includes("pnpm release:gate"), "the gate image must still run the full release gate");
});

test("workflow retains the manual trigger, pinned checkout, identity guards and timeout", () => {
  assert.match(workflow, /on:\s*\n\s*workflow_dispatch:/u);
  assert.match(workflow, /actions\/checkout@[0-9a-f]{40}/u);
  assert.match(workflow, /persist-credentials:\s*false/u);
  assert.match(workflow, /timeout-minutes:\s*40\b/u);
  assert.ok(workflow.includes("node scripts/check-public-history.mjs"), "identity history guard must remain");
  assert.ok(workflow.includes("node --test scripts/check-public-history.test.mjs"), "identity guard tests must remain");
});

test("workflow built gate image runs account, tenant, tenant-write and worker guards together", () => {
  assert.ok(workflow.includes("scripts/account-deployment.test.mjs"), "account deployment guard must remain");
  assert.ok(workflow.includes("scripts/tenant-deployment.test.mjs"), "tenant deployment guard must remain");
  assert.ok(workflow.includes("scripts/tenant-write-deployment.test.mjs"), "tenant-write deployment guard must be added");
  assert.ok(workflow.includes("scripts/tenant-ci-wiring.test.mjs"), "tenant CI guard must remain");
  assert.ok(workflow.includes("scripts/worker-ci-wiring.test.mjs"), "worker CI guard must be added");
  const guardLine = workflow
    .split("\n")
    .find((line) => line.includes("node --test scripts/account-deployment.test.mjs"));
  assert.ok(guardLine, "the guard invocation must run inside the built gate image");
  for (const guard of [
    "scripts/tenant-write-deployment.test.mjs",
    "scripts/worker-ci-wiring.test.mjs",
  ]) {
    assert.ok(guardLine.includes(guard), `the gate guard invocation must include ${guard}`);
  }
});

test("workflow PostgreSQL step runs DB, API, worker then accounts on one isolated fixture", () => {
  assert.ok(workflow.includes("--network none"), "the PostgreSQL fixture must stay network-isolated");
  assert.match(workflow, /postgres@sha256:[0-9a-f]{64}/u);
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
  assert.ok(!workflow.includes("POSTGRES_PASSWORD=openarc_disposable_test") === false, "the disposable fixture password stays local");
  assert.ok(!/production|railway|paid/iu.test(pg), "the PostgreSQL step must not use production services");
});

test("workflow summary distinguishes the mocked write browser from actual production", () => {
  assert.match(workflow, /mocked tenant write browser suite/iu);
  assert.match(workflow, /actual-production browser result|actual-production fixture/iu);
  assert.ok(workflow.includes("e2e:tenant:writes:production"), "summary must name the production alias boundary");
  assert.ok(!/whole-port result that passed|economic execution (?:was|is) (?:run|verified)/iu.test(workflow), "no overclaim");
});

test("production worker Dockerfile follows the pinned Node22-alpine convention", () => {
  const build = workerDockerfile.match(/FROM node:22-alpine@sha256:[0-9a-f]{64} AS build/u);
  const runtime = workerDockerfile.match(/FROM node:22-alpine@sha256:[0-9a-f]{64} AS runtime/u);
  assert.ok(build, "build stage must pin node:22-alpine by digest");
  assert.ok(runtime, "runtime stage must pin node:22-alpine by digest");
  assert.equal(build[0], runtime[0].replace(" AS runtime", " AS build"), "builder and runtime must share the pinned image");
  assert.ok(workerDockerfile.includes("corepack prepare pnpm@11.5.1 --activate"), "pnpm must be pinned via corepack");
  assert.ok(workerDockerfile.includes("pnpm install --frozen-lockfile"), "install must stay frozen");
  for (const manifest of [
    "COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./",
    "COPY apps/worker/package.json apps/worker/package.json",
    "COPY packages/shared/package.json packages/shared/package.json",
    "COPY packages/db/package.json packages/db/package.json",
    "COPY packages/config/package.json packages/config/package.json",
  ]) {
    assert.ok(workerDockerfile.includes(manifest), `worker image must copy ${manifest}`);
  }
});

test("production worker Dockerfile builds shared then DB then worker and deploys prod", () => {
  const buildLine = workerDockerfile
    .split("\n")
    .find((line) => line.includes("pnpm --filter @openarc/shared build"));
  assert.ok(buildLine, "worker image must build shared first");
  const order = [
    "pnpm --filter @openarc/shared build",
    "pnpm --filter @openarc/db build",
    "pnpm --filter @openarc/worker build",
  ];
  let cursor = -1;
  for (const step of order) {
    const next = buildLine.indexOf(step);
    assert.ok(next > cursor, `worker build must run in order: ${step}`);
    cursor = next;
  }
  assert.ok(
    workerDockerfile.includes("pnpm --filter @openarc/worker deploy --prod"),
    "worker image must deploy production dependencies only",
  );
  assert.match(workerDockerfile, /CMD \["node", "dist\/main\.js"\]/u);
  assert.match(workerDockerfile, /USER openarc\b/u);
  assert.match(workerDockerfile, /adduser -S -G openarc openarc/u);
  assert.match(workerDockerfile, /libcrypto3=3\.5\.8-r0/u);
  assert.match(workerDockerfile, /libssl3=3\.5\.8-r0/u);
  assert.ok(workerDockerfile.includes("rm -f /usr/local/bin/npm"), "runtime must not keep npm/corepack");
});

test("production worker Dockerfile defaults OFF, takes provenance only and exposes no listener", () => {
  assert.match(workerDockerfile, /ENV NODE_ENV=production/u);
  assert.match(workerDockerfile, /WORKER_ENABLED=false/u);
  assert.match(workerDockerfile, /ARG COMMIT_SHA=local/u);
  assert.match(workerDockerfile, /COMMIT_SHA=\$\{COMMIT_SHA\}/u);
  assert.ok(!/EXPOSE\b/u.test(workerDockerfile), "worker image must not EXPOSE a public port");
  assert.ok(!/HEALTHCHECK\b/iu.test(workerDockerfile), "worker image must not invent a health endpoint");
  assert.ok(!/WORKER_DATABASE_URL|DATABASE_URL/u.test(workerDockerfile), "no database URL may be baked into the image");
  assert.ok(!/WALLET|PRIVATE_KEY|SECRET|RAILWAY/iu.test(workerDockerfile), "no wallet, key or paid-service secret may be baked in");
});

test("worker disabled default exits cleanly without keepalive or fake health", () => {
  const main = read("apps/worker/src/main.ts");
  const config = read("apps/worker/src/config.ts");
  assert.match(config, /WORKER_ENABLED/u);
  assert.match(main, /if \(!config\.enabled\) return;/u);
  assert.ok(!/setInterval|keepalive|healthz|healthcheck/iu.test(main), "disabled worker must not invent keepalive or health");
});
