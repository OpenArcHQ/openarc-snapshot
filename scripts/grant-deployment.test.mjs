import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

/**
 * Static deployment guards for the authorization-grant proxy family.
 *
 * These assertions parse the real nginx directives (never comments), the real
 * Dockerfile RUN/shell lines and the real frozen registry source at
 * packages/shared/src/commerce/control-grant-capabilities.ts. The nine-route
 * inventory, the three-audience split, every method, every audience path prefix
 * AND the credential namespace of each audience are DERIVED from that registry,
 * not restated here, so a registry edit fails this guard instead of silently
 * drifting from the edge.
 *
 * They prove: the exact nine GRANT_ROUTES and their methods; the canonical
 * typed org id ([1-8] nibble) and the version-4 grant/mutation/attempt ids; the
 * query, body and header guards; the encoded-URI-preserving no-URI proxy_pass;
 * that the registry contains no mixed-method path and the include therefore
 * declares no named-location dispatch; all THREE credential namespaces asserted
 * positively and negatively (agent `oacs_v1_`, provider `oas_pr_`, browser
 * cookie with `Authorization` rejected outright), including that the accepted
 * action and commerce-session families keep their own distinct namespaces; the
 * unconditional capability and deny installation; the full grant-flag
 * dependency chain; all flag combinations; and the OFF / no-API fail-closed
 * behaviour.
 *
 * They do not run nginx and do not prove actual nginx, TLS upstream or browser
 * acceptance; real-nginx behaviour in both flag modes is recorded separately.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => readFileSync(path.join(root, relativePath), "utf8");

const FILES = {
  registry: "packages/shared/src/commerce/control-grant-capabilities.ts",
  dockerfile: "apps/web/Dockerfile",
  apiConf: "apps/web/nginx-api.conf",
  arcConf: "apps/web/nginx-arc.conf",
  plainConf: "apps/web/nginx.conf",
  business: "apps/web/nginx-grant-locations.conf",
  capability: "apps/web/nginx-grant-capability.conf",
  deny: "apps/web/nginx-grant-deny.conf",
  agentParams: "apps/web/commerce_agent_proxy_params",
  readParams: "apps/web/tenant_proxy_params",
  writeParams: "apps/web/tenant_write_proxy_params",
  responseHeaders: "apps/web/market_response_headers",
  controlDeny: "apps/web/nginx-control-deny.conf",
  marketDeny: "apps/web/nginx-market-deny.conf",
  sessionDeny: "apps/web/nginx-session-deny.conf",
  actionDeny: "apps/web/nginx-action-deny.conf",
  sessionBusiness: "apps/web/nginx-commerce-session-locations.conf",
  actionBusiness: "apps/web/nginx-action-locations.conf",
  listingBusiness: "apps/web/nginx-listing-management-locations.conf",
  sourceChecks: ".github/workflows/source-checks.yml",
};

const registrySource = read(FILES.registry);
const businessSource = read(FILES.business);
const capabilitySource = read(FILES.capability);
const denySource = read(FILES.deny);
const agentParams = read(FILES.agentParams);
const readParams = read(FILES.readParams);
const writeParams = read(FILES.writeParams);
const responseHeaders = read(FILES.responseHeaders);
const dockerfile = read(FILES.dockerfile);

function stripNginxComments(config) {
  return config
    .split("\n")
    .map((line) => line.replace(/(^|\s)#[^\n]*$/u, ""))
    .join("\n");
}

function parseLocations(config) {
  const stripped = stripNginxComments(config);
  const locations = [];
  const header = /location\s+([=^~]*)\s*("@?[^"]*"|\S+)\s*\{/gu;
  let match;
  while ((match = header.exec(stripped)) !== null) {
    const open = match.index + match[0].length - 1;
    let depth = 0;
    let close = -1;
    for (let index = open; index < stripped.length; index += 1) {
      if (stripped[index] === "{") depth += 1;
      else if (stripped[index] === "}") {
        depth -= 1;
        if (depth === 0) {
          close = index;
          break;
        }
      }
    }
    assert.ok(close > open, `unterminated location block for ${match[2]}`);
    const rawPath = match[2];
    locations.push({
      modifier: match[1],
      path: rawPath.startsWith('"') ? rawPath.slice(1, -1) : rawPath,
      raw: rawPath,
      index: match.index,
      body: stripped.slice(open + 1, close),
    });
    header.lastIndex = close + 1;
  }
  return locations;
}

/* ------------------------------------------------------------------ *
 * The frozen registry, parsed from its own TypeScript source.
 * ------------------------------------------------------------------ */

function parseRegistry(source) {
  const capabilityPath = source.match(
    /export const GRANT_CAPABILITIES_PATH\s*=\s*\n?\s*"([^"]+)"/u,
  );
  assert.ok(capabilityPath, "GRANT_CAPABILITIES_PATH must be declared");
  const agentBase = source.match(/const GRANT_AGENT_BASE = "([^"]+)"/u);
  const providerBase = source.match(/const GRANT_PROVIDER_BASE = "([^"]+)"/u);
  const controlBase = source.match(/const GRANT_CONTROL_BASE = "([^"]+)"/u);
  assert.ok(agentBase && providerBase && controlBase, "all three frozen route bases must be declared");
  const bases = {
    GRANT_AGENT_BASE: agentBase[1],
    GRANT_PROVIDER_BASE: providerBase[1],
    GRANT_CONTROL_BASE: controlBase[1],
  };
  const entry =
    /\{\s*id:\s*"([a-z0-9_]+)",\s*family:\s*"([a-z_]+)",\s*audience:\s*"([a-z]+)",\s*method:\s*"([A-Z]+)",\s*path:\s*`([^`]+)`\s*\}/gu;
  const routes = [];
  let match;
  while ((match = entry.exec(source)) !== null) {
    const template = match[5].replace(/\$\{([A-Z_]+)\}/gu, (_all, name) => {
      assert.ok(Object.hasOwn(bases, name), `unknown base ${name}`);
      return bases[name];
    });
    routes.push({
      id: match[1],
      family: match[2],
      audience: match[3],
      method: match[4],
      path: template,
    });
  }
  // Frozen audience -> path prefix map.
  const prefixBlock = source.match(
    /GRANT_CAPABILITY_AUDIENCE_PREFIX[\s\S]*?Object\.freeze\(\{([\s\S]*?)\}\)/u,
  );
  assert.ok(prefixBlock, "GRANT_CAPABILITY_AUDIENCE_PREFIX must be declared");
  const prefixes = {};
  for (const line of prefixBlock[1].matchAll(/([a-z]+):\s*"([^"]+)"/gu)) {
    prefixes[line[1]] = line[2];
  }
  // Frozen audience -> credential-class map. The credential NAMESPACES below
  // are read out of this, never restated.
  const credentialBlock = source.match(
    /GRANT_CAPABILITY_CREDENTIAL[\s\S]*?Object\.freeze\(\{([\s\S]*?)\}\)/u,
  );
  assert.ok(credentialBlock, "GRANT_CAPABILITY_CREDENTIAL must be declared");
  const credentials = {};
  for (const line of credentialBlock[1].matchAll(/([a-z]+):\s*"([^"]+)"/gu)) {
    credentials[line[1]] = line[2];
  }
  const forbidden = source.match(/GRANT_PROVIDER_FORBIDDEN_PREFIX\s*=\s*\n?\s*"([^"]+)"/u);
  assert.ok(forbidden, "GRANT_PROVIDER_FORBIDDEN_PREFIX must be declared");
  return {
    capabilityPath: capabilityPath[1],
    routes,
    prefixes,
    credentials,
    forbiddenProviderPrefix: forbidden[1],
  };
}

const registry = parseRegistry(registrySource);
const ROUTES = registry.routes;
const CAPABILITY_PATH = registry.capabilityPath;
const PREFIX = registry.prefixes;

/**
 * The three credential namespaces, DERIVED from the frozen
 * GRANT_CAPABILITY_CREDENTIAL map rather than restated. The agent lane consumes
 * a commerce session (`oacs_v1_`); the provider lane presents a provider
 * session (`oas_pr_`) plus a body-only `oag_v1_` grant token; the browser lane
 * presents a cookie and no bearer at all.
 */
const AGENT_NAMESPACE = registry.credentials.agent.match(/^([a-z0-9]+_v1_)/u)?.[1];
const PROVIDER_NAMESPACE = registry.credentials.provider.match(/^(oas_[a-z]{2}_)/u)?.[1];
const GRANT_TOKEN_NAMESPACE = registry.credentials.provider.match(/\+([a-z0-9]+_v1_)/u)?.[1];
// The read-only machine credential that must NEVER reach a spending surface.
const MACHINE_NAMESPACE = "oas_ag_";

// Concrete canonical ids that expand each frozen `:parameter` template into the
// exact wire target nginx must select.
const IDS = Object.freeze({
  ":organizationId": "openarc:org:11111111-1111-4111-8111-111111111111",
  ":grantId": "openarc:grant:33333333-3333-4333-8333-333333333333",
  ":mutationId": "22222222-2222-4222-8222-222222222222",
  ":attemptId": "55555555-5555-4555-8555-555555555555",
});

function targetFor(routePath) {
  return routePath
    .split("/")
    .map((segment) => {
      if (!segment.startsWith(":")) return segment;
      assert.ok(Object.hasOwn(IDS, segment), `no concrete id for ${segment}`);
      return IDS[segment];
    })
    .join("/");
}

const UUID_ID = "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const UUID_V4 = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

const locations = parseLocations(businessSource);
const named = locations.filter((entry) => entry.path.startsWith("@"));
const external = locations.filter((entry) => !entry.path.startsWith("@"));
const proxying = external.filter((entry) => entry.body.includes("proxy_pass"));

function pathText(entry) {
  return entry.path.replace(/^\^/u, "");
}

function regexFor(entry) {
  return new RegExp("^(?:" + entry.path.split('"').join("") + ")$", "u");
}

function findRoute(target) {
  return proxying.filter((entry) =>
    entry.modifier === "=" ? entry.path === target : regexFor(entry).test(target),
  );
}

function methodOf(entry) {
  const match = entry.body.match(/if\s*\(\$request_method\s*!=\s*([A-Z]+)\)\s*\{\s*return\s+405;\s*\}/u);
  return match ? match[1] : null;
}

const browserLocations = proxying.filter((entry) => pathText(entry).startsWith(PREFIX.browser));
const agentLocations = proxying.filter((entry) => pathText(entry).startsWith(`${PREFIX.agent}commerce-grant`));
const providerLocations = proxying.filter((entry) => pathText(entry).startsWith(PREFIX.provider));

/** Extract the literal nginx bearer regex text from a location body. */
function bearerPattern(entry) {
  const match = entry.body.match(/if\s*\(\$http_authorization\s*!~\s*"([^"]+)"\)\s*\{\s*return\s+403;\s*\}/u);
  return match ? match[1] : null;
}

const SAMPLE = (namespace) => `Bearer ${namespace}${"A".repeat(43)}`;

/* ------------------------------------------------------------------ *
 * Registry-derived inventory
 * ------------------------------------------------------------------ */

test("the frozen registry publishes exactly nine routes across three disjoint audiences", () => {
  assert.equal(CAPABILITY_PATH, "/v2/public/grant-capabilities");
  assert.equal(ROUTES.length, 9, "the grant registry is exactly nine routes");
  assert.equal(new Set(ROUTES.map((route) => route.id)).size, 9, "route ids are unique");
  const byFamily = {
    commerce_grant_authorization: "agent",
    commerce_grant_claim: "provider",
    commerce_grant_management: "browser",
  };
  for (const [family, audience] of Object.entries(byFamily)) {
    const members = ROUTES.filter((route) => route.family === family);
    assert.equal(members.length, 3, `three ${family} routes`);
    for (const route of members) {
      assert.equal(route.audience, audience, `${route.id} must be ${audience} audience`);
      assert.ok(route.path.startsWith(PREFIX[audience]), `${route.id} must live under ${PREFIX[audience]}`);
      assert.ok(["GET", "POST"].includes(route.method), `${route.id} must be GET or POST`);
    }
  }
  // No audience prefix may be a prefix of another, so the audience of a grant
  // route is decidable from its path alone.
  const prefixValues = ["browser", "agent", "provider"].map((audience) => PREFIX[audience]);
  for (const left of prefixValues) {
    for (const right of prefixValues) {
      if (left === right) continue;
      assert.ok(!left.startsWith(right), `${left} must not sit under ${right}`);
    }
  }
  // A provider grant route may never live under the seller browser listing lane.
  for (const route of ROUTES.filter((candidate) => candidate.audience === "provider")) {
    assert.ok(
      !route.path.startsWith(registry.forbiddenProviderPrefix),
      `${route.id} must not live under ${registry.forbiddenProviderPrefix}`,
    );
  }
  assert.deepEqual(
    ROUTES.map((route) => route.id),
    [
      "grant_issue",
      "grant_replace",
      "agent_grant_mutation_status",
      "provider_grant_introspect",
      "provider_grant_claim",
      "provider_grant_attempt_status",
      "grant_detail",
      "grant_mutation_status",
      "grant_revoke",
    ],
    "the frozen id order must not drift",
  );
});

test("the business include declares exactly one location per frozen route with the exact method", () => {
  assert.equal(proxying.length, 9, "exactly nine externally addressable proxying locations");
  assert.equal(external.length, 9, "no extra non-proxying location may hide in the business include");
  const claimed = new Set();
  for (const route of ROUTES) {
    const target = targetFor(route.path);
    const matches = findRoute(target);
    assert.equal(matches.length, 1, `${route.id} (${route.method} ${target}) must select exactly one location`);
    assert.equal(methodOf(matches[0]), route.method, `${route.id} must pin ${route.method}`);
    assert.ok(!claimed.has(matches[0].raw), `${matches[0].raw} may serve only one frozen route`);
    claimed.add(matches[0].raw);
  }
  assert.equal(claimed.size, 9, "the nine routes map one-to-one onto nine locations");
  assert.equal(browserLocations.length, 3, "three browser locations");
  assert.equal(agentLocations.length, 3, "three agent locations");
  assert.equal(providerLocations.length, 3, "three provider locations");
  // No capability, manifest, health, payment or settlement descriptor is proxied here.
  assert.ok(
    !/payment|settlement|refund|healthz|capabilit/iu.test(stripNginxComments(businessSource).replace(/#[^\n]*/gu, "")),
    "no unrelated endpoint may hide in the business include",
  );
});

test("the registry has no mixed-method path, so no named-location dispatch is declared or needed", () => {
  const byPath = new Map();
  for (const route of ROUTES) {
    byPath.set(route.path, new Set([...(byPath.get(route.path) ?? []), route.method]));
  }
  for (const [routePath, methods] of byPath) {
    assert.equal(methods.size, 1, `${routePath} must carry exactly one method (a mixed-method path would need an error_page 418 dispatch)`);
  }
  assert.equal(named.length, 0, "no named location may be declared when no path is mixed-method");
  assert.ok(!/error_page\s+418/u.test(stripNginxComments(businessSource)), "no 418 dispatch may be declared");
  assert.ok(!/return\s+418;/u.test(stripNginxComments(businessSource)), "no bare return 418 may be declared");
  // The accepted mixed-method family still carries its dispatch: this guard must
  // never be read as permission to remove one.
  assert.match(read(FILES.sessionBusiness), /error_page\s+418\s*=\s*@openarc_session_issue;/u, "the accepted session dispatch must remain");
});

test("ids use the canonical typed grammars: [1-8] organization id, version-4 grant/mutation/attempt ids", () => {
  for (const entry of browserLocations) {
    assert.ok(entry.raw.includes(`openarc:org:${UUID_ID}`), `${entry.raw} must anchor a canonical typed organization id`);
  }
  for (const entry of [...browserLocations, ...agentLocations].filter((candidate) => /openarc:grant:/u.test(candidate.path))) {
    assert.ok(entry.raw.includes(`openarc:grant:${UUID_V4}`), `${entry.raw} must pin the grant id to version 4`);
  }
  const humanMutation = browserLocations.find((entry) => /grant-mutations/u.test(entry.path));
  assert.ok(humanMutation, "the human mutation route must exist");
  assert.ok(humanMutation.raw.includes(UUID_V4), "the human mutation id must pin version 4");
  const agentMutation = agentLocations.find((entry) => /commerce-grant-mutations/u.test(pathText(entry)));
  assert.ok(agentMutation, "the agent mutation route must exist");
  assert.ok(agentMutation.raw.includes(UUID_V4), "the agent mutation id must pin version 4");
  const attempt = providerLocations.find((entry) => /grant-attempts/u.test(pathText(entry)));
  assert.ok(attempt, "the provider attempt status route must exist");
  assert.ok(attempt.raw.includes(UUID_V4), "the provider attempt id must pin version 4");
  // Version drift and untyped ids must not match.
  const org = IDS[":organizationId"];
  const detail = browserLocations.find((entry) => /\/grants\/openarc:grant:[^/]*\$$/u.test(entry.path));
  assert.ok(detail, "the human grant detail route must exist");
  assert.ok(!regexFor(detail).test(`${PREFIX.browser}${org.replace("openarc:org:", "openarc:org:")}/grants/openarc:grant:33333333-3333-1333-8333-333333333333`), "the grant id must reject a non-v4 UUID");
  assert.ok(!regexFor(detail).test(`${PREFIX.browser}${org}/grants/33333333-3333-4333-8333-333333333333`), "the grant id must reject an untyped UUID");
  assert.ok(!regexFor(detail).test(`${PREFIX.browser}openarc:org:11111111-1111-9111-8111-111111111111/grants/openarc:grant:33333333-3333-4333-8333-333333333333`), "the organization id must reject a version-9 nibble");
  assert.ok(!regexFor(attempt).test(`${PREFIX.provider}-attempts/55555555-5555-1555-8555-555555555555`), "the attempt id must reject a non-v4 UUID");
});

test("every proxying grant route uses the host-only no-URI proxy_pass", () => {
  for (const entry of proxying) {
    assert.match(entry.body, /proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\};/u, `${entry.raw} must proxy with no URI part`);
    assert.ok(!/proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\}\S+;/u.test(entry.body), `${entry.raw} must not append a URI component`);
    assert.ok(!/proxy_pass\s+http:/u.test(entry.body), `${entry.raw} must use https only`);
    assert.ok(!/proxy_cache\b|proxy_store\b/u.test(entry.body), `${entry.raw} must not cache or store`);
  }
  assert.ok(!/rewrite\b/u.test(stripNginxComments(businessSource)), "must not rewrite the request target");
});

test("no grant route is a collection list, so every one of the nine rejects a literal ?", () => {
  // Every frozen GET terminates in a path parameter, so no route is a
  // collection list and none of the nine has a bounded read query to preserve.
  for (const route of ROUTES.filter((candidate) => candidate.method === "GET")) {
    const last = route.path.split("/").pop();
    assert.ok(last.startsWith(":"), `${route.id} must terminate in a path parameter, not a collection segment`);
  }
  for (const entry of proxying) {
    if (entry.modifier === "=") {
      assert.match(
        entry.body,
        new RegExp(`if\\s*\\(\\$request_uri\\s*!=\\s*"${entry.path}"\\)\\s*\\{\\s*return\\s+400;\\s*\\}`, "u"),
        `${entry.raw} exact route must reject any query including a bare ?`,
      );
      continue;
    }
    assert.match(entry.body, /if\s*\(\$request_uri\s*~\s*"\\\?"\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject a literal ?`);
  }
  assert.ok(!/\$request_uri\s*(?:!=|=)\s*\$uri\b/u.test(stripNginxComments(businessSource)), "must never compare encoded $request_uri to decoded $uri");
  assert.ok(!/\$arg_/u.test(stripNginxComments(businessSource)), "no grant route may read a query argument");
});

test("wrong verbs including HEAD, PUT, DELETE and OPTIONS are rejected with 405 on every route", () => {
  for (const entry of proxying) {
    const method = methodOf(entry);
    assert.ok(method === "GET" || method === "POST", `${entry.raw} must pin exactly one method`);
    const guards = entry.body.match(/\$request_method\s*!=\s*[A-Z]+/gu) ?? [];
    assert.equal(guards.length, 1, `${entry.raw} must declare exactly one method guard`);
    assert.ok(!/\$request_method\s*=\s*[A-Z]+/u.test(entry.body), `${entry.raw} must not branch on an extra verb`);
  }
  const expectedGet = ROUTES.filter((route) => route.method === "GET").length;
  const expectedPost = ROUTES.filter((route) => route.method === "POST").length;
  assert.equal(proxying.filter((entry) => methodOf(entry) === "GET").length, expectedGet, `${expectedGet} GET locations`);
  assert.equal(proxying.filter((entry) => methodOf(entry) === "POST").length, expectedPost, `${expectedPost} POST locations`);
});

test("browser reads are bodyless and the browser write requires JSON, CSRF, idempotency and a 16KiB bound", () => {
  const getters = browserLocations.filter((entry) => methodOf(entry) === "GET");
  const writers = browserLocations.filter((entry) => methodOf(entry) === "POST");
  assert.equal(getters.length, 2, "two browser GET locations (detail, mutation status)");
  assert.equal(writers.length, 1, "one browser POST location (revoke)");
  for (const entry of getters) {
    assert.match(entry.body, /if\s*\(\$http_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject a bearer`);
    assert.match(entry.body, /if\s*\(\$http_proxy_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject proxy authorization`);
    assert.match(entry.body, /if\s*\(\$http_x_openarc_csrf\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject a CSRF header`);
    assert.match(entry.body, /if\s*\(\$http_idempotency_key\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject an idempotency header`);
    assert.match(entry.body, /if\s*\(\$openarc_grant_body_ok\s*=\s*0\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must fail the body guard`);
    assert.match(entry.body, /client_max_body_size\s+1k;/u, `${entry.raw} must be 1KiB bounded`);
  }
  for (const entry of writers) {
    assert.match(entry.body, /if\s*\(\$http_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject a bearer`);
    assert.match(entry.body, /if\s*\(\$http_proxy_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject proxy authorization`);
    assert.match(entry.body, /if\s*\(\$http_content_type\s*!~\s*"\^application\/json/u, `${entry.raw} must require JSON`);
    assert.match(entry.body, /if\s*\(\$http_transfer_encoding\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject transfer encoding`);
    assert.match(entry.body, /if\s*\(\$http_x_openarc_csrf\s*=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must require CSRF`);
    assert.match(entry.body, /if\s*\(\$http_idempotency_key\s*=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must require idempotency`);
    assert.match(entry.body, /client_max_body_size\s+16k;/u, `${entry.raw} must be 16KiB bounded`);
  }
  for (const entry of proxying) {
    assert.ok(!/client_max_body_size\s+0;/u.test(entry.body), `${entry.raw} must never be unlimited`);
  }
});

test("no proxy directive or include is ever placed inside an if block", () => {
  for (const source of [businessSource, capabilitySource, denySource]) {
    for (const entry of parseLocations(source)) {
      const blocks = entry.body.match(/if\s*\([^)]*\)\s*\{[^}]*\}/gu) ?? [];
      for (const block of blocks) {
        assert.ok(!block.includes("proxy_pass"), "if block must not contain proxy_pass");
        assert.ok(!block.includes("proxy_set_header"), "if block must not contain proxy_set_header");
        assert.ok(!block.includes("include "), "if block must not contain include");
        assert.ok(!block.includes("client_max_body_size"), "if block must not contain a body bound");
      }
    }
  }
});

test("browser transport reuses the unchanged tenant params plus response suppression", () => {
  for (const entry of browserLocations) {
    if (methodOf(entry) === "GET") {
      assert.match(entry.body, /include\s+\/etc\/nginx\/tenant_proxy_params;/u, `${entry.raw} must reuse the read params`);
      assert.ok(!entry.body.includes("tenant_write_proxy_params"), `${entry.raw} must not use the write params`);
    } else {
      assert.match(entry.body, /include\s+\/etc\/nginx\/tenant_write_proxy_params;/u, `${entry.raw} must reuse the write params`);
    }
    assert.match(entry.body, /include\s+\/etc\/nginx\/market_response_headers;/u, `${entry.raw} must suppress Set-Cookie/CORS`);
  }
  // The reused param files gain no grant edit.
  assert.match(readParams, /proxy_pass_request_body\s+off;/u);
  assert.match(readParams, /proxy_ssl_verify\s+on;/u);
  assert.match(readParams, /proxy_next_upstream\s+off;/u);
  assert.match(writeParams, /proxy_pass_request_body\s+on;/u);
  for (const [name, source] of [[FILES.readParams, readParams], [FILES.writeParams, writeParams], [FILES.agentParams, agentParams]]) {
    assert.ok(!/openarc_grant|commerce-grant|grant-capabilities/u.test(source), `${name} must stay unchanged`);
  }
  for (const header of ["Set-Cookie", "Access-Control-Allow-Origin", "Vary"]) {
    assert.match(responseHeaders, new RegExp(`proxy_hide_header\\s+${header};`, "u"));
  }
});

test("both headless audiences forward only the allowlist and reject every browser credential", () => {
  const headless = [...agentLocations, ...providerLocations];
  assert.equal(headless.length, 6, "six headless locations (three agent, three provider)");
  for (const entry of headless) {
    for (const header of [
      "$http_cookie",
      "$http_origin",
      "$http_sec_fetch_site",
      "$http_sec_fetch_mode",
      "$http_sec_fetch_dest",
      "$http_sec_fetch_user",
      "$http_x_openarc_client",
      "$http_x_openarc_csrf",
      "$http_proxy_authorization",
      "$http_x_openarc_proxy_secret",
    ]) {
      const escaped = header.replace("$", "\\$");
      assert.match(entry.body, new RegExp(`if\\s*\\(${escaped}\\s*!=\\s*""\\)\\s*\\{\\s*return\\s+403;\\s*\\}`, "u"), `${entry.raw} must reject ${header}`);
    }
    assert.match(entry.body, /include\s+\/etc\/nginx\/commerce_agent_proxy_params;/u, `${entry.raw} must use the headless allowlist`);
    assert.match(entry.body, /include\s+\/etc\/nginx\/market_response_headers;/u, `${entry.raw} must suppress Set-Cookie/CORS`);
    assert.ok(!entry.body.includes("tenant_proxy_params"), `${entry.raw} must not use the browser read params`);
    assert.ok(!entry.body.includes("tenant_write_proxy_params"), `${entry.raw} must not use the browser write params`);
  }
  // Mutating POSTs carry the bounded JSON body and an idempotency key; reads do not.
  const mutating = headless.filter((entry) => methodOf(entry) === "POST" && !/introspect$/u.test(entry.path));
  assert.equal(mutating.length, 3, "three mutating headless POSTs (issue, replace, claim)");
  for (const entry of mutating) {
    assert.match(entry.body, /if\s*\(\$http_content_type\s*!~\s*"\^application\/json/u, `${entry.raw} must require JSON`);
    assert.match(entry.body, /if\s*\(\$http_idempotency_key\s*=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must require idempotency`);
    assert.match(entry.body, /client_max_body_size\s+16k;/u, `${entry.raw} must be 16KiB bounded`);
    assert.match(entry.body, /proxy_set_header\s+Content-Type\s+\$http_content_type;/u);
    assert.match(entry.body, /proxy_set_header\s+Content-Length\s+\$http_content_length;/u);
    assert.match(entry.body, /proxy_set_header\s+Idempotency-Key\s+\$http_idempotency_key;/u);
    assert.match(entry.body, /proxy_pass_request_body\s+on;/u);
  }
  const reads = headless.filter((entry) => methodOf(entry) === "GET");
  assert.equal(reads.length, 2, "two headless GET reads (agent mutation status, provider attempt status)");
  for (const entry of reads) {
    assert.match(entry.body, /if\s*\(\$http_content_type\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
    assert.match(entry.body, /if\s*\(\$http_content_length\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
    assert.match(entry.body, /if\s*\(\$http_idempotency_key\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
    assert.match(entry.body, /client_max_body_size\s+1k;/u);
    assert.match(entry.body, /proxy_pass_request_body\s+off;/u);
    assert.ok(!/proxy_set_header\s+Idempotency-Key/u.test(entry.body), "a headless GET must not forward an idempotency key");
    assert.ok(!/proxy_pass_request_body\s+on;/u.test(entry.body), "a headless GET must never forward a body");
  }
  assert.ok(!/proxy_pass_request_body/u.test(agentParams), "the headless params must not set body forwarding globally");
  assert.match(agentParams, /proxy_pass_request_headers\s+off;/u);
  const forwarded = agentParams.match(/proxy_set_header\s+([^\s]+)\s+(\S+)/gu) ?? [];
  const allowed = new Set(["Connection", "Host", "Authorization", "Accept"]);
  for (const directive of forwarded) {
    const name = directive.replace(/proxy_set_header\s+/u, "").split(/\s+/u)[0];
    assert.ok(allowed.has(name), `headless params must not forward unexpected header ${name}`);
  }
  assert.ok(!/proxy_set_header\s+Cookie\s+\$http_cookie/u.test(agentParams), "the headless params must never forward a browser cookie");
  assert.ok(!/SOURCE_PROXY_SECRET/u.test(agentParams), "the headless surface must not reuse the legacy proxy secret");
});

/* ------------------------------------------------------------------ *
 * The three credential namespaces, asserted BOTH ways.
 * ------------------------------------------------------------------ */

test("the agent grant routes require the exact oacs_v1_ commerce session and reject every other namespace", () => {
  assert.equal(AGENT_NAMESPACE, "oacs_v1_", "the frozen registry must name the commerce-session namespace for the agent audience");
  assert.equal(agentLocations.length, 3, "three agent locations");
  for (const entry of agentLocations) {
    const pattern = bearerPattern(entry);
    assert.ok(pattern, `${entry.raw} must declare a bearer guard`);
    assert.equal(pattern, `^Bearer ${AGENT_NAMESPACE}[A-Za-z0-9_-]{43}$`, `${entry.raw} must pin the exact ${AGENT_NAMESPACE} grammar`);
    const compiled = new RegExp(pattern, "u");
    // Positive: a valid commerce-session bearer is accepted.
    assert.ok(compiled.test(SAMPLE(AGENT_NAMESPACE)), `${entry.raw} must ACCEPT a valid ${AGENT_NAMESPACE} bearer`);
    // Negative: the read-only machine credential and the provider session are not.
    assert.ok(!compiled.test(SAMPLE(MACHINE_NAMESPACE)), `${entry.raw} must REJECT an ${MACHINE_NAMESPACE} machine credential: a read-only machine bearer can never authorize spending`);
    assert.ok(!compiled.test(SAMPLE(PROVIDER_NAMESPACE)), `${entry.raw} must REJECT a ${PROVIDER_NAMESPACE} provider session`);
    assert.ok(!compiled.test(`Bearer ${AGENT_NAMESPACE}${"A".repeat(42)}`), `${entry.raw} must REJECT a truncated commerce-session bearer`);
    assert.ok(!compiled.test(`Bearer ${AGENT_NAMESPACE}${"A".repeat(44)}`), `${entry.raw} must REJECT an over-long commerce-session bearer`);
    // The wrong namespaces must not appear anywhere in the location at all.
    assert.ok(!entry.body.includes(MACHINE_NAMESPACE), `${entry.raw} must not mention ${MACHINE_NAMESPACE}`);
    assert.ok(!entry.body.includes(PROVIDER_NAMESPACE), `${entry.raw} must not mention ${PROVIDER_NAMESPACE}`);
  }
});

test("the provider grant routes require the exact oas_pr_ provider session, never a cookie and never a grant token in the URL", () => {
  assert.equal(PROVIDER_NAMESPACE, "oas_pr_", "the frozen registry must name the provider-session namespace for the provider audience");
  assert.equal(GRANT_TOKEN_NAMESPACE, "oag_v1_", "the frozen registry must name the one-use grant-token namespace as the provider's second factor");
  assert.equal(providerLocations.length, 3, "three provider locations");
  for (const entry of providerLocations) {
    const pattern = bearerPattern(entry);
    assert.ok(pattern, `${entry.raw} must declare a bearer guard`);
    assert.equal(pattern, `^Bearer ${PROVIDER_NAMESPACE}[A-Za-z0-9_-]{43}$`, `${entry.raw} must pin the exact ${PROVIDER_NAMESPACE} grammar`);
    const compiled = new RegExp(pattern, "u");
    assert.ok(compiled.test(SAMPLE(PROVIDER_NAMESPACE)), `${entry.raw} must ACCEPT a valid ${PROVIDER_NAMESPACE} bearer`);
    assert.ok(!compiled.test(SAMPLE(AGENT_NAMESPACE)), `${entry.raw} must REJECT a ${AGENT_NAMESPACE} commerce session`);
    assert.ok(!compiled.test(SAMPLE(MACHINE_NAMESPACE)), `${entry.raw} must REJECT an ${MACHINE_NAMESPACE} agent machine credential`);
    assert.ok(!compiled.test(SAMPLE(GRANT_TOKEN_NAMESPACE)), `${entry.raw} must REJECT a raw ${GRANT_TOKEN_NAMESPACE} grant token presented as a bearer`);
    assert.ok(!entry.body.includes(AGENT_NAMESPACE), `${entry.raw} must not mention ${AGENT_NAMESPACE}`);
    assert.ok(!entry.body.includes(MACHINE_NAMESPACE), `${entry.raw} must not mention ${MACHINE_NAMESPACE}`);
    // The cookie ban is explicit, not merely implied by the bearer guard.
    assert.match(entry.body, /if\s*\(\$http_cookie\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must never accept a cookie`);
  }
  // The buyer's one-use grant token lives in the BODY only: introspection is a
  // POST precisely so the secret never reaches a path, a query or a log line.
  const introspect = ROUTES.find((route) => route.id === "provider_grant_introspect");
  const claim = ROUTES.find((route) => route.id === "provider_grant_claim");
  assert.equal(introspect.method, "POST", "introspection must be POST even though it is read-only");
  assert.equal(claim.method, "POST");
  for (const route of [introspect, claim]) {
    assert.ok(!route.path.includes(":"), `${route.id} must carry no path parameter that could hold a secret`);
  }
  const bodyCarrying = providerLocations.filter((entry) => entry.modifier === "=");
  assert.equal(bodyCarrying.length, 2, "introspect and claim are exact, parameterless, body-carrying locations");
  for (const entry of bodyCarrying) {
    assert.match(entry.body, /proxy_pass_request_body\s+on;/u, `${entry.raw} must forward the body that carries the grant token`);
  }
  // Read-only introspection carries no mutation id, so it rejects an idempotency key.
  const introspectLocation = providerLocations.find((entry) => entry.path === introspect.path);
  assert.ok(introspectLocation, "the introspect location must exist");
  assert.match(introspectLocation.body, /if\s*\(\$http_idempotency_key\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u, "read-only introspection must reject an idempotency key");
  assert.ok(!/proxy_set_header\s+Idempotency-Key/u.test(introspectLocation.body), "read-only introspection must not forward an idempotency key");
  // Nothing in this family ever names or logs a raw grant token.
  assert.ok(!new RegExp(`${GRANT_TOKEN_NAMESPACE}[A-Za-z0-9]`, "u").test(businessSource), "no literal grant token may appear in the include");
});

test("the browser grant routes present a cookie and reject every bearer namespace outright", () => {
  assert.equal(registry.credentials.browser, "browser_session_cookie", "the frozen registry must name the cookie credential for the browser audience");
  assert.equal(browserLocations.length, 3, "three browser locations");
  for (const entry of browserLocations) {
    assert.equal(bearerPattern(entry), null, `${entry.raw} must not accept any bearer namespace`);
    assert.match(entry.body, /if\s*\(\$http_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject Authorization outright`);
    assert.match(entry.body, /if\s*\(\$http_proxy_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject Proxy-Authorization outright`);
    for (const namespace of [AGENT_NAMESPACE, PROVIDER_NAMESPACE, MACHINE_NAMESPACE, GRANT_TOKEN_NAMESPACE]) {
      assert.ok(!entry.body.includes(namespace), `${entry.raw} must not mention ${namespace}`);
    }
    assert.ok(!entry.body.includes("commerce_agent_proxy_params"), `${entry.raw} must not use the headless allowlist`);
  }
  // The browser lane forwards the cookie, the browser marker, Origin and the
  // Fetch-Metadata triple through the unchanged tenant params; the API remains
  // the authority for the EXACT Origin value and the CSRF comparison.
  for (const header of ["Cookie $http_cookie", "Origin $http_origin", "X-OpenArc-Client $http_x_openarc_client", "Sec-Fetch-Site $http_sec_fetch_site"]) {
    assert.ok(readParams.includes(`proxy_set_header ${header};`), `the read params must forward ${header}`);
    assert.ok(writeParams.includes(`proxy_set_header ${header};`), `the write params must forward ${header}`);
  }
  assert.ok(writeParams.includes("proxy_set_header X-OpenArc-CSRF $http_x_openarc_csrf;"), "the write params must forward the CSRF token");
});

test("the accepted action and commerce-session families keep their own distinct namespaces", () => {
  // The commerce-SESSION agent routes are where a machine credential (oas_ag_)
  // is exchanged for a commerce session, so oas_ag_ is correct THERE.
  const sessionAgent = parseLocations(read(FILES.sessionBusiness)).filter((entry) => entry.path.includes("/v2/agent/"));
  assert.ok(sessionAgent.length > 0, "expected accepted session agent locations");
  for (const entry of sessionAgent) {
    assert.ok(/\^Bearer oas_ag_/u.test(entry.body), `${entry.raw} must keep the oas_ag_ machine-credential namespace`);
    assert.ok(!/oacs_v1_|oas_pr_/u.test(entry.body), `${entry.raw} must not accept a commerce-session or provider token at the exchange surface`);
  }
  // The commerce-ACTION agent routes consume a commerce session: oacs_v1_.
  const actionAgent = parseLocations(read(FILES.actionBusiness)).filter((entry) => entry.path.includes("/v2/agent/"));
  assert.equal(actionAgent.length, 3, "expected exactly three action agent locations");
  for (const entry of actionAgent) {
    assert.ok(/\^Bearer oacs_v1_\[A-Za-z0-9_-\]\{43\}\$/u.test(entry.body), `${entry.raw} must require the exact oacs_v1_ commerce-session bearer`);
    assert.ok(!/oas_ag_|oas_pr_/u.test(entry.body), `${entry.raw} must reject the machine and provider namespaces`);
  }
  // The accepted families gain no grant edit.
  for (const accepted of [FILES.sessionBusiness, FILES.actionBusiness, FILES.listingBusiness, FILES.sessionDeny, FILES.actionDeny]) {
    assert.ok(!/commerce-grant|grant-capabilities|grant-attempts|openarc:grant:/u.test(read(accepted)), `${accepted} must stay unchanged by this packet`);
  }
});

test("no conf in this family embeds a secret, token or credential value", () => {
  for (const [name, source] of [
    [FILES.business, businessSource],
    [FILES.capability, capabilitySource],
    [FILES.deny, denySource],
  ]) {
    assert.ok(!/SOURCE_PROXY_SECRET/u.test(source), `${name} must not reference the legacy proxy secret`);
    assert.ok(!/oacs_v1_[A-Za-z0-9]{4,}/u.test(source), `${name} must not embed a literal commerce-session bearer`);
    assert.ok(!/oas_pr_[A-Za-z0-9]{4,}/u.test(source), `${name} must not embed a literal provider session`);
    assert.ok(!/oas_ag_[A-Za-z0-9]{4,}/u.test(source), `${name} must not embed a literal machine credential`);
    assert.ok(!/oag_v1_[A-Za-z0-9]{4,}/u.test(source), `${name} must not embed a literal grant token`);
    assert.ok(!/Bearer\s+(?!oacs_v1_\[|oas_pr_\[)[A-Za-z0-9._-]{8,}/u.test(source), `${name} must not embed a literal token`);
  }
});

test("the grant-capability route is an exact credentialless GET with a fixed upstream path", () => {
  const capabilityLocations = parseLocations(capabilitySource);
  assert.equal(capabilityLocations.length, 1, "the capability file must declare exactly one location");
  const entry = capabilityLocations[0];
  assert.equal(entry.modifier, "=", "the capability route must be an exact match");
  assert.equal(entry.path, CAPABILITY_PATH, "the capability route must be the frozen GRANT_CAPABILITIES_PATH");
  assert.match(entry.body, /if\s*\(\$request_method\s*!=\s*GET\)\s*\{\s*return\s+405;\s*\}/u);
  assert.match(entry.body, new RegExp(`if\\s*\\(\\$request_uri\\s*!=\\s*"${CAPABILITY_PATH}"\\)\\s*\\{\\s*return\\s+400;\\s*\\}`, "u"));
  for (const header of ["$http_cookie", "$http_authorization", "$http_proxy_authorization", "$http_x_openarc_csrf", "$http_idempotency_key", "$http_x_openarc_proxy_secret"]) {
    const escaped = header.replace("$", "\\$");
    assert.match(entry.body, new RegExp(`if\\s*\\(${escaped}\\s*!=\\s*""\\)\\s*\\{\\s*return\\s+403;\\s*\\}`, "u"), `the capability route must reject ${header}`);
  }
  assert.match(entry.body, /proxy_pass_request_headers\s+off;/u);
  assert.match(entry.body, /proxy_pass_request_body\s+off;/u);
  assert.match(entry.body, /proxy_ssl_verify\s+on;/u);
  assert.match(entry.body, /proxy_next_upstream\s+off;/u);
  assert.match(entry.body, new RegExp(`proxy_pass\\s+https://\\$\\{API_UPSTREAM_HOST\\}${CAPABILITY_PATH};`, "u"));
  assert.ok(!/try_files|index\.html/u.test(entry.body), "the capability route must never serve SPA HTML");
});

test("the deny include uses plain prefixes, covers lookalikes and shadows no accepted family", () => {
  const denyLocations = parseLocations(denySource);
  assert.equal(denyLocations.length, 4, "exactly four plain grant denies");
  for (const required of [CAPABILITY_PATH, "/v2/agent/commerce-grants", "/v2/agent/commerce-grant-mutations", PREFIX.provider]) {
    const entry = denyLocations.find((candidate) => candidate.path === required);
    assert.ok(entry, `${required} must be a plain deny prefix`);
    assert.equal(entry.modifier, "", `${required} must not use ^~ or =`);
    assert.match(entry.body.trim(), /^return 404;$/u);
    assert.ok(!/proxy_pass|try_files/u.test(entry.body), `${required} deny must not proxy or serve SPA`);
  }
  for (const lookalike of [
    "/v2/public/grant-capabilitiesXYZ",
    "/v2/agent/commerce-grantsXYZ",
    "/v2/agent/commerce-grant-mutationsXYZ",
    "/v2/agent/commerce-grants/not-an-id/replace",
    "/v2/agent/commerce-grant-mutations/11111111-1111-1111-8111-111111111111",
    "/v2/provider/grantsXYZ",
    "/v2/provider/grants/introspectXYZ",
    "/v2/provider/grant-attemptsXYZ",
    "/v2/provider/grant-attempts/not-an-id",
  ]) {
    assert.ok(denyLocations.some((entry) => entry.modifier === "" && lookalike.startsWith(entry.path)), `${lookalike} must be covered by a plain prefix`);
  }
  // No broad prefix may shadow an accepted family.
  for (const broad of ["/v2/agent", "/v2/agent/", "/v2/provider", "/v2/provider/", "/v2/control", "/v2/control/"]) {
    assert.equal(denyLocations.filter((entry) => entry.path === broad).length, 0, `no broad ${broad} deny may be declared here`);
  }
  for (const accepted of [
    "/v2/agent/commerce-sessions/exchange",
    "/v2/agent/commerce-session-mutations/22222222-2222-4222-8222-222222222222",
    "/v2/agent/commerce-actions",
    "/v2/agent/commerce-action-mutations/22222222-2222-4222-8222-222222222222",
    "/v2/provider/organizations/openarc:org:11111111-1111-4111-8111-111111111111/listings",
    "/v2/control/organizations/openarc:org:11111111-1111-4111-8111-111111111111/actions",
  ]) {
    assert.ok(!denyLocations.some((entry) => accepted.startsWith(entry.path)), `${accepted} must not be captured by a grant deny`);
  }
  assert.ok(!denySource.includes("API_UPSTREAM_HOST"), "the deny file must not reference the upstream");
  assert.ok(!denyLocations.some((entry) => entry.modifier === "^~"), "deny fallbacks must not use ^~ (would suppress enabled regexes)");
  // The family roots owned by accepted denies are not restated (a duplicate
  // location is a configuration error).
  assert.match(read(FILES.controlDeny), /location \/v2\/control \{ return 404; \}/u, "the unconditional control deny must still cover the browser grant roots");
  assert.match(read(FILES.marketDeny), /location \/v2\/provider \{ return 404; \}/u, "the unconditional market deny must still cover /v2/provider");
  // Enabled routes still beat the deny prefixes.
  assert.ok(proxying.some((entry) => entry.modifier === "=" && entry.path === "/v2/agent/commerce-grants"), "the exact agent issue route must beat the /v2/agent/commerce-grants prefix");
  assert.ok(proxying.some((entry) => entry.modifier === "=" && entry.path === "/v2/provider/grants/introspect"), "the exact introspect route must beat the /v2/provider/grant prefix");
  assert.ok(proxying.some((entry) => entry.modifier === "~" && pathText(entry).startsWith("/v2/provider/grant-attempts/")), "the anchored attempt regex must beat the prefix");
  assert.ok(proxying.some((entry) => entry.modifier === "~" && pathText(entry).startsWith("/v2/agent/commerce-grants/")), "the anchored replace regex must beat the prefix");
});

test("both API templates install capability, business and deny includes exactly once", () => {
  for (const template of [FILES.apiConf, FILES.arcConf]) {
    const source = read(template);
    for (const include of [
      "openarc-grant-capability-locations.inc",
      "openarc-commerce-grant-locations.inc",
      "openarc-grant-deny.inc",
    ]) {
      assert.equal(source.split(include).length - 1, 1, `${template} must include ${include} exactly once`);
    }
    // The accepted families are untouched.
    for (const include of [
      "openarc-session-capability-locations.inc",
      "openarc-commerce-session-locations.inc",
      "openarc-session-deny.inc",
      "openarc-action-capability-locations.inc",
      "openarc-commerce-action-locations.inc",
      "openarc-action-deny.inc",
      "openarc-control-deny.inc",
      "openarc-market-deny.inc",
      "openarc-listing-management-locations.inc",
    ]) {
      assert.equal(source.split(include).length - 1, 1, `${template} must keep ${include} exactly once`);
    }
    // The fail-closed API namespace guards survive ahead of the SPA fallback.
    for (const guard of ["location = /v1 { return 404; }", "location = /v2 { return 404; }", "location /v1/ { return 404; }", "location /v2/ { return 404; }"]) {
      assert.ok(source.includes(guard), `${template} must keep ${guard}`);
      assert.ok(source.indexOf(guard) < source.indexOf("location / { try_files"), `${guard} must precede the SPA fallback`);
    }
    // The grant includes sit before the fail-closed namespace guards.
    assert.ok(
      source.indexOf("openarc-grant-deny.inc") < source.indexOf("location = /v1 { return 404; }"),
      `${template} must install the grant family before the fail-closed namespace guards`,
    );
  }
  // Capability, business and deny are three independent files.
  assert.ok(!businessSource.includes(CAPABILITY_PATH), "the business include must not own the capability route");
  assert.ok(!capabilitySource.includes("/commerce-grants"), "the capability file must not own a business route");
  assert.ok(!capabilitySource.includes("/grants/"), "the capability file must not own a business route");
});

test("the plain no-API template denies every grant path without SPA fallback", () => {
  const plainSource = read(FILES.plainConf);
  const plain = stripNginxComments(plainSource);
  assert.ok(!plain.includes("API_UPSTREAM_HOST"), "plain template must stay API boundary OFF");
  const plainLocations = parseLocations(plainSource);
  for (const required of [CAPABILITY_PATH, "/v2/agent/commerce-grants", "/v2/agent/commerce-grant-mutations", PREFIX.provider]) {
    const entry = plainLocations.find((candidate) => candidate.path === required);
    assert.ok(entry, `${required} must be denied in the no-API template`);
    assert.equal(entry.modifier, "", `${required} must be a plain prefix`);
    assert.match(entry.body.trim(), /^return 404;$/u);
    assert.ok(!/try_files|proxy_pass/u.test(entry.body), `${required} must not fall through to SPA or proxy`);
  }
  assert.ok(plainLocations.some((entry) => entry.path === "/v2/control" && entry.modifier === ""), "the no-API template must keep denying the browser grant roots via /v2/control");
  assert.ok(!plain.includes("openarc-commerce-grant-locations"), "the no-API template must never include the proxying business file");
  assert.ok(!plainLocations.some((entry) => entry.path === "/v2/agent" || entry.path === "/v2/agent/"), "the no-API template must not add a broad /v2/agent deny");
  // Every declared location path is unique: a duplicate is an nginx config error.
  const paths = plainLocations.map((entry) => `${entry.modifier}|${entry.path}`);
  assert.equal(new Set(paths).size, paths.length, "the no-API template must declare no duplicate location");
});

test("Dockerfile defaults the grant flag off in both stages and requires the full dependency chain", () => {
  const argOccurrences = dockerfile.match(/ARG\s+VITE_COMMERCE_GRANTS_ENABLED=false/gu) ?? [];
  assert.equal(argOccurrences.length, 2, "the flag must default to false in both stages");
  assert.ok(!/ARG\s+VITE_COMMERCE_GRANTS_ENABLED=true/u.test(dockerfile), "the flag must never default on");
  const caseOccurrences = dockerfile.match(/case\s+"\$\{VITE_COMMERCE_GRANTS_ENABLED\}"\s+in\s+true\|false\)/gu) ?? [];
  assert.equal(caseOccurrences.length, 2, "the flag must be validated true|false in both stages");
  const dependency =
    'if [ "${VITE_COMMERCE_GRANTS_ENABLED}" = "true" ] && { ' +
    '[ "${VITE_COMMERCE_ACTIONS_ENABLED}" != "true" ] || ' +
    '[ "${VITE_COMMERCE_SESSIONS_ENABLED}" != "true" ] || ' +
    '[ "${VITE_TENANT_READS_ENABLED}" != "true" ] || ' +
    '[ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || ' +
    '[ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }';
  assert.equal(dockerfile.split(dependency).length - 1, 2, "the full dependency chain must appear in both stages");
  const dependencyLines = dockerfile.split("\n").filter((line) => line.includes("VITE_COMMERCE_GRANTS_ENABLED=true requires"));
  assert.equal(dependencyLines.length, 2, "the dependency message must appear once per stage");
  for (const line of dependencyLines) {
    for (const required of [
      "VITE_COMMERCE_ACTIONS_ENABLED=true",
      "VITE_COMMERCE_SESSIONS_ENABLED=true",
      "VITE_TENANT_READS_ENABLED=true",
      "VITE_ACCOUNT_ACCESS_ENABLED=true",
      "VITE_API_BOUNDARY_ENABLED=true",
    ]) {
      assert.ok(line.includes(required), `the grant dependency message must name ${required}`);
    }
  }
  // The accepted action and session dependencies are not widened by this packet.
  assert.equal(
    dockerfile.split('if [ "${VITE_COMMERCE_ACTIONS_ENABLED}" = "true" ] && { [ "${VITE_COMMERCE_SESSIONS_ENABLED}" != "true" ] || [ "${VITE_TENANT_READS_ENABLED}" != "true" ] || [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }').length - 1,
    2,
    "the action dependency must stay exactly as accepted",
  );
  assert.equal(
    dockerfile.split('if [ "${VITE_COMMERCE_SESSIONS_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }').length - 1,
    2,
    "the session dependency must stay exactly as accepted",
  );
});

test("Dockerfile copies the grant files and installs capability/deny unconditionally, business conditionally", () => {
  for (const file of [
    "apps/web/nginx-grant-capability.conf",
    "apps/web/nginx-grant-locations.conf",
    "apps/web/nginx-grant-deny.conf",
  ]) {
    assert.equal(dockerfile.split(file).length - 1, 1, `Dockerfile must copy ${file} exactly once`);
  }
  assert.match(dockerfile, /cp \/tmp\/openarc-nginx\/nginx-grant-capability\.conf \/etc\/nginx\/templates\/openarc-grant-capability-locations\.inc\.template;/u);
  assert.match(dockerfile, /cp \/tmp\/openarc-nginx\/nginx-grant-deny\.conf \/etc\/nginx\/templates\/openarc-grant-deny\.inc\.template;/u);
  assert.match(dockerfile, /cp \/tmp\/openarc-nginx\/nginx-grant-locations\.conf \/etc\/nginx\/templates\/openarc-commerce-grant-locations\.inc\.template;/u);
  assert.match(dockerfile, /:\s*>\s*\/etc\/nginx\/templates\/openarc-commerce-grant-locations\.inc\.template;/u, "the omitted business include must be written empty");
  const capabilityCp = dockerfile.indexOf("cp /tmp/openarc-nginx/nginx-grant-capability.conf /etc/nginx/templates/openarc-grant-capability-locations.inc.template");
  const denyCp = dockerfile.indexOf("cp /tmp/openarc-nginx/nginx-grant-deny.conf /etc/nginx/templates/openarc-grant-deny.inc.template");
  const branch = dockerfile.indexOf('if [ "${VITE_COMMERCE_GRANTS_ENABLED}" = "true" ]; then');
  assert.ok(capabilityCp !== -1 && denyCp !== -1 && branch !== -1, "the grant install lines must exist");
  assert.ok(capabilityCp < branch, "capability must be installed unconditionally before the grants branch");
  assert.ok(denyCp < branch, "deny must be installed unconditionally before the grants branch");
  // Capability and deny installation is gated only by the API boundary.
  const apiBranch = dockerfile.indexOf('if [ "${VITE_API_BOUNDARY_ENABLED}" = "true" ]; then');
  assert.ok(apiBranch !== -1 && apiBranch < capabilityCp, "capability/deny install must sit inside the API-boundary branch");
});

test("every grant flag combination resolves to a byte-identical server template", () => {
  const start = dockerfile.indexOf('if [ "${VITE_COMMERCE_GRANTS_ENABLED}" = "true" ]; then');
  const end = dockerfile.indexOf("cp /tmp/openarc-nginx/nginx-market-capability.conf");
  assert.ok(start !== -1 && end > start, "the grants install branch must exist before the market capability copy");
  const branch = dockerfile.slice(start, end);
  const branches = dockerfile.match(/if \[ "\$\{VITE_COMMERCE_GRANTS_ENABLED\}" = "true" \]; then/gu) ?? [];
  assert.equal(branches.length, 1, "exactly one runtime install branch selects the grant business include");
  // Both arms write the SAME runtime include path, so the server template never
  // varies across flag combinations: ON copies the nine routes, OFF truncates.
  assert.equal(branch.split("openarc-commerce-grant-locations.inc.template").length - 1, 2, "both arms must write the same runtime include path");
  assert.match(branch, /cp \/tmp\/openarc-nginx\/tenant_proxy_params \/etc\/nginx\/tenant_proxy_params;/u);
  assert.match(branch, /cp \/tmp\/openarc-nginx\/tenant_write_proxy_params \/etc\/nginx\/tenant_write_proxy_params;/u);
  assert.match(branch, /cp \/tmp\/openarc-nginx\/commerce_agent_proxy_params \/etc\/nginx\/commerce_agent_proxy_params;/u);
  for (const forbidden of [
    "VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED",
    "VITE_POLICY_MANAGEMENT_ENABLED",
    "VITE_MARKET_CATALOG_ENABLED",
    "VITE_MARKET_MODERATION_ENABLED",
    "VITE_LISTING_MANAGEMENT_ENABLED",
    "VITE_ARC_OBSERVATION_ENABLED",
  ]) {
    assert.ok(!branch.includes(forbidden), `the grant install must not depend on ${forbidden}`);
  }
  // The business include references exactly the three param files installed here.
  assert.match(businessSource, /include\s+\/etc\/nginx\/tenant_proxy_params;/u);
  assert.match(businessSource, /include\s+\/etc\/nginx\/tenant_write_proxy_params;/u);
  assert.match(businessSource, /include\s+\/etc\/nginx\/commerce_agent_proxy_params;/u);
  // The accepted action install branch is unchanged.
  assert.equal((dockerfile.match(/if \[ "\$\{VITE_COMMERCE_ACTIONS_ENABLED\}" = "true" \]; then/gu) ?? []).length, 1, "the action install branch must stay single");
});

test("the public source gate runs the grant deployment guard alongside the existing guards", () => {
  const sourceChecks = read(FILES.sourceChecks);
  const guardLine = sourceChecks.split("\n").find((line) => line.includes("node --test scripts/account-deployment.test.mjs"));
  assert.ok(guardLine, "the source gate guard invocation must exist");
  assert.ok(guardLine.includes("scripts/grant-deployment.test.mjs"), "the source gate must run the grant deployment guard");
  for (const existing of [
    "scripts/control-deployment.test.mjs",
    "scripts/marketplace-deployment.test.mjs",
    "scripts/machine-deployment.test.mjs",
    "scripts/session-deployment.test.mjs",
    "scripts/action-deployment.test.mjs",
    "scripts/capability-deployment.test.mjs",
    "scripts/api-namespace-deployment.test.mjs",
  ]) {
    assert.ok(guardLine.includes(existing), `the gate must keep running ${existing}`);
  }
  assert.match(sourceChecks, /source-gate:\s*\n\s*runs-on:\s*ubuntu-latest\s*\n\s*timeout-minutes:\s*40\b/u, "the source-gate job must keep the deliberate 40-minute timeout");
});

test("the accepted deployment guards and denies are unchanged and never mention the grant family", () => {
  for (const legacy of [
    "scripts/control-deployment.test.mjs",
    "scripts/marketplace-deployment.test.mjs",
    "scripts/machine-deployment.test.mjs",
    "scripts/tenant-deployment.test.mjs",
    "scripts/session-deployment.test.mjs",
    "scripts/action-deployment.test.mjs",
  ]) {
    const source = read(legacy);
    assert.ok(!/commerce-grant|commerce_grant|grant-capabilities/u.test(source), `${legacy} must stay unchanged by this packet`);
  }
  const sessionDeny = parseLocations(read(FILES.sessionDeny));
  assert.deepEqual(
    sessionDeny.map((entry) => entry.path).sort(),
    ["/v2/agent/commerce-session-mutations", "/v2/agent/commerce-sessions", "/v2/public/session-capabilities"],
    "the accepted session deny must not change",
  );
  const actionDeny = parseLocations(read(FILES.actionDeny));
  assert.deepEqual(
    actionDeny.map((entry) => entry.path).sort(),
    ["/v2/agent/commerce-action-mutations", "/v2/agent/commerce-actions", "/v2/public/action-capabilities"],
    "the accepted action deny must not change",
  );
});

/* ================================================================== *
 * PORT-04 P04-02c: the migration-0015 payment-attempt proxy family.
 *
 * The grant family's successor lane. Same method: the five-route inventory,
 * both audiences, their path prefixes and credential namespaces are DERIVED
 * from packages/shared/src/commerce/control-payment-capabilities.ts, and the
 * real nginx directives and Dockerfile lines are parsed (never comments).
 * ================================================================== */

const PAYMENT_FILES = {
  registry: "packages/shared/src/commerce/control-payment-capabilities.ts",
  business: "apps/web/nginx-payment-locations.conf",
  capability: "apps/web/nginx-payment-capability.conf",
  deny: "apps/web/nginx-payment-deny.conf",
};

const PAYMENT_FILES_LIST = [PAYMENT_FILES.capability, PAYMENT_FILES.business, PAYMENT_FILES.deny];

const paymentRegistrySource = read(PAYMENT_FILES.registry);
const paymentBusinessSource = read(PAYMENT_FILES.business);
const paymentCapabilitySource = read(PAYMENT_FILES.capability);
const paymentDenySource = read(PAYMENT_FILES.deny);

function parsePaymentRegistry(source) {
  const capabilityPath = source.match(/export const PAYMENT_CAPABILITIES_PATH\s*=\s*\n?\s*"([^"]+)"/u);
  assert.ok(capabilityPath, "PAYMENT_CAPABILITIES_PATH must be declared");
  const agentBase = source.match(/const PAYMENT_AGENT_BASE = "([^"]+)"/u);
  const providerBase = source.match(/const PAYMENT_PROVIDER_BASE = "([^"]+)"/u);
  assert.ok(agentBase && providerBase, "both frozen payment route bases must be declared");
  const bases = { PAYMENT_AGENT_BASE: agentBase[1], PAYMENT_PROVIDER_BASE: providerBase[1] };
  const entry =
    /\{\s*id:\s*"([a-z0-9_]+)",\s*family:\s*"([a-z_]+)",\s*audience:\s*"([a-z]+)",\s*method:\s*"([A-Z]+)",\s*path:\s*`([^`]+)`\s*\}/gu;
  const routes = [];
  let match;
  while ((match = entry.exec(source)) !== null) {
    routes.push({
      id: match[1],
      family: match[2],
      audience: match[3],
      method: match[4],
      path: match[5].replace(/\$\{([A-Z_]+)\}/gu, (_all, name) => {
        assert.ok(Object.hasOwn(bases, name), `unknown base ${name}`);
        return bases[name];
      }),
    });
  }
  const block = (name) => {
    const found = source.match(new RegExp(`${name}[\\s\\S]*?Object\\.freeze\\(\\{([\\s\\S]*?)\\}\\)`, "u"));
    assert.ok(found, `${name} must be declared`);
    const map = {};
    for (const line of found[1].matchAll(/([a-z]+):\s*"([^"]+)"/gu)) map[line[1]] = line[2];
    return map;
  };
  return {
    capabilityPath: capabilityPath[1],
    routes,
    prefixes: block("PAYMENT_CAPABILITY_AUDIENCE_PREFIX"),
    credentials: block("PAYMENT_CAPABILITY_CREDENTIAL"),
  };
}

const paymentRegistry = parsePaymentRegistry(paymentRegistrySource);
const PAYMENT_ROUTES = paymentRegistry.routes;
const PAYMENT_PREFIX = paymentRegistry.prefixes;
const PAYMENT_AGENT_NAMESPACE = paymentRegistry.credentials.agent?.match(/^([a-z0-9]+_v1_)/u)?.[1];

const PAYMENT_IDS = Object.freeze({
  ":organizationId": "openarc:org:11111111-1111-4111-8111-111111111111",
  ":listingId": "openarc:listing:44444444-4444-4444-8444-444444444444",
  ":version": "7",
  ":attemptId": "55555555-5555-4555-8555-555555555555",
});

function paymentTargetFor(routePath) {
  return routePath
    .split("/")
    .map((segment) => {
      if (!segment.startsWith(":")) return segment;
      assert.ok(Object.hasOwn(PAYMENT_IDS, segment), `no concrete id for ${segment}`);
      return PAYMENT_IDS[segment];
    })
    .join("/");
}

const paymentLocations = parseLocations(paymentBusinessSource);
const paymentProxying = paymentLocations.filter((entry) => !entry.path.startsWith("@") && entry.body.includes("proxy_pass"));
const paymentAgentLocations = paymentProxying.filter((entry) => pathText(entry).startsWith(`${PAYMENT_PREFIX.agent}commerce-payment`));
const paymentBrowserLocations = paymentProxying.filter((entry) => pathText(entry).startsWith(PAYMENT_PREFIX.browser));

function selects(entry, target) {
  return entry.modifier === "=" ? entry.path === target : entry.modifier === "~" && regexFor(entry).test(target);
}

test("payment: the frozen registry publishes exactly five routes across two disjoint audiences", () => {
  assert.equal(paymentRegistry.capabilityPath, "/v2/public/payment-capabilities");
  assert.deepEqual(
    PAYMENT_ROUTES.map((route) => [route.id, route.family, route.audience, route.method]),
    [
      ["listing_payment_terms_record", "commerce_payment_terms", "browser", "POST"],
      ["payment_requirement_register", "commerce_payment_attempt", "agent", "POST"],
      ["payment_attempt_persist", "commerce_payment_attempt", "agent", "POST"],
      ["payment_attempt_dispatch", "commerce_payment_attempt", "agent", "POST"],
      ["payment_attempt_detail", "commerce_payment_attempt", "agent", "GET"],
    ],
    "the frozen payment inventory must not drift",
  );
  for (const route of PAYMENT_ROUTES) {
    assert.ok(route.path.startsWith(PAYMENT_PREFIX[route.audience]), `${route.id} must live under ${PAYMENT_PREFIX[route.audience]}`);
    assert.ok(!/observ|settle|release|refund/iu.test(route.path), `${route.id} must not be an observation or settlement route`);
  }
  assert.equal(paymentRegistry.credentials.browser, "browser_session_cookie");
  assert.equal(PAYMENT_AGENT_NAMESPACE, "oacs_v1_", "the agent audience must name the commerce-session namespace");
});

test("payment: the business include declares exactly one location per frozen route with the exact method", () => {
  assert.equal(paymentProxying.length, 5, "exactly five proxying locations");
  assert.equal(paymentLocations.length, 5, "no extra or named location may hide in the payment include");
  const claimed = new Set();
  for (const route of PAYMENT_ROUTES) {
    const target = paymentTargetFor(route.path);
    const matches = paymentProxying.filter((entry) => selects(entry, target));
    assert.equal(matches.length, 1, `${route.id} (${target}) must select exactly one location`);
    assert.equal(methodOf(matches[0]), route.method, `${route.id} must pin ${route.method}`);
    claimed.add(matches[0].raw);
  }
  assert.equal(claimed.size, 5);
  assert.equal(paymentBrowserLocations.length, 1, "one browser location");
  assert.equal(paymentAgentLocations.length, 4, "four agent locations");
  const directives = stripNginxComments(paymentBusinessSource).replace(/#[^\n]*/gu, "");
  assert.ok(!/observ|settle|release|refund|healthz|capabilit|grant/iu.test(directives), "no unrelated endpoint may hide in the payment include");
  assert.ok(!/error_page\s+418|return\s+418;/u.test(directives), "no mixed-method dispatch is declared");
});

test("payment: ids use the canonical typed grammars and reject drift", () => {
  const terms = paymentBrowserLocations[0];
  assert.ok(terms.raw.includes(`openarc:org:${UUID_ID}`), "typed organization id");
  assert.ok(terms.raw.includes(`openarc:listing:${UUID_ID}`), "typed listing id");
  assert.ok(terms.raw.includes("/versions/[1-9][0-9]{0,8}/payment-terms$"), "canonical listing version");
  const base = `${PAYMENT_PREFIX.browser}${PAYMENT_IDS[":organizationId"]}/listings/${PAYMENT_IDS[":listingId"]}/versions`;
  assert.ok(regexFor(terms).test(`${base}/7/payment-terms`));
  assert.ok(!regexFor(terms).test(`${base}/0/payment-terms`), "version 0 must not match");
  assert.ok(!regexFor(terms).test(`${base}/07/payment-terms`), "a leading zero must not match");
  assert.ok(!regexFor(terms).test(`${base}/7/payment-terms/extra`), "an extra segment must not match");
  for (const entry of paymentAgentLocations.filter((candidate) => candidate.modifier === "~")) {
    assert.ok(entry.raw.includes(UUID_V4), `${entry.raw} must pin the attempt id to version 4`);
    assert.ok(!regexFor(entry).test(`${PAYMENT_PREFIX.agent}commerce-payment-attempts/55555555-5555-1555-8555-555555555555`), "a non-v4 attempt id must not match");
  }
  // The terms route is disjoint from the accepted listing lifecycle regexes.
  const target = paymentTargetFor(PAYMENT_ROUTES[0].path);
  for (const entry of parseLocations(read(FILES.listingBusiness))) {
    if (entry.path.startsWith("@")) continue;
    assert.ok(!selects(entry, target), `the listing-management location ${entry.raw} must not capture the terms route`);
  }
});

test("payment: every route uses the host-only no-URI proxy_pass and rejects a literal ?", () => {
  for (const entry of paymentProxying) {
    assert.match(entry.body, /proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\};/u, `${entry.raw} must proxy with no URI part`);
    assert.ok(!/proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\}\S+;/u.test(entry.body), `${entry.raw} must not append a URI`);
    assert.ok(!/proxy_cache\b|proxy_store\b|client_max_body_size\s+0;/u.test(entry.body));
    if (entry.modifier === "=") {
      assert.match(entry.body, new RegExp(`if\\s*\\(\\$request_uri\\s*!=\\s*"${entry.path}"\\)\\s*\\{\\s*return\\s+400;\\s*\\}`, "u"), `${entry.raw} must reject any query`);
    } else {
      assert.match(entry.body, /if\s*\(\$request_uri\s*~\s*"\\\?"\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject a literal ?`);
    }
    const guards = entry.body.match(/\$request_method\s*!=\s*[A-Z]+/gu) ?? [];
    assert.equal(guards.length, 1, `${entry.raw} must declare exactly one method guard`);
  }
  assert.ok(!/rewrite\b|\$arg_/u.test(stripNginxComments(paymentBusinessSource)));
  for (const source of [paymentBusinessSource, paymentCapabilitySource, paymentDenySource]) {
    for (const entry of parseLocations(source)) {
      for (const block of entry.body.match(/if\s*\([^)]*\)\s*\{[^}]*\}/gu) ?? []) {
        assert.ok(!/proxy_pass|proxy_set_header|include |client_max_body_size/u.test(block), "no proxy directive inside an if block");
      }
    }
  }
});

test("payment: the agent routes require exactly oacs_v1_ and reject oas_ag_, oas_pr_ and every browser credential", () => {
  assert.equal(paymentAgentLocations.length, 4);
  for (const entry of paymentAgentLocations) {
    const pattern = bearerPattern(entry);
    assert.equal(pattern, `^Bearer ${PAYMENT_AGENT_NAMESPACE}[A-Za-z0-9_-]{43}$`, `${entry.raw} must pin the exact commerce-session grammar`);
    const compiled = new RegExp(pattern, "u");
    assert.ok(compiled.test(SAMPLE("oacs_v1_")), `${entry.raw} must ACCEPT oacs_v1_`);
    assert.ok(!compiled.test(SAMPLE("oas_ag_")), `${entry.raw} must REJECT the oas_ag_ machine credential`);
    assert.ok(!compiled.test(SAMPLE("oas_pr_")), `${entry.raw} must REJECT an oas_pr_ provider session`);
    assert.ok(!compiled.test(SAMPLE("oag_v1_")), `${entry.raw} must REJECT a grant token`);
    assert.ok(!compiled.test(`Bearer oacs_v1_${"A".repeat(42)}`), `${entry.raw} must REJECT a truncated bearer`);
    assert.ok(!/oas_ag_|oas_pr_|oag_v1_/u.test(entry.body), `${entry.raw} must not mention another namespace`);
    for (const header of ["$http_cookie", "$http_origin", "$http_sec_fetch_site", "$http_sec_fetch_mode", "$http_sec_fetch_dest", "$http_sec_fetch_user", "$http_x_openarc_client", "$http_x_openarc_csrf", "$http_proxy_authorization", "$http_x_openarc_proxy_secret"]) {
      assert.match(entry.body, new RegExp(`if\\s*\\(${header.replace("$", "\\$")}\\s*!=\\s*""\\)\\s*\\{\\s*return\\s+403;\\s*\\}`, "u"), `${entry.raw} must reject ${header}`);
    }
    // Agent writes are keyed by their own canonical ids: an idempotency key is rejected.
    assert.match(entry.body, /if\s*\(\$http_idempotency_key\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject an idempotency key`);
    assert.ok(!/proxy_set_header\s+Idempotency-Key/u.test(entry.body), `${entry.raw} must not forward an idempotency key`);
    assert.match(entry.body, /include\s+\/etc\/nginx\/commerce_agent_proxy_params;/u);
    assert.match(entry.body, /include\s+\/etc\/nginx\/market_response_headers;/u);
    assert.ok(!/tenant_(write_)?proxy_params/u.test(entry.body), `${entry.raw} must not use browser params`);
    if (methodOf(entry) === "POST") {
      assert.match(entry.body, /if\s*\(\$http_content_type\s*!~\s*"\^application\/json/u);
      assert.match(entry.body, /client_max_body_size\s+16k;/u);
      assert.match(entry.body, /proxy_pass_request_body\s+on;/u);
    } else {
      assert.match(entry.body, /if\s*\(\$http_content_length\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
      assert.match(entry.body, /client_max_body_size\s+1k;/u);
      assert.match(entry.body, /proxy_pass_request_body\s+off;/u);
    }
  }
});

test("payment: the seller terms route presents a cookie, requires CSRF and idempotency, and rejects every bearer", () => {
  assert.equal(paymentBrowserLocations.length, 1);
  const entry = paymentBrowserLocations[0];
  assert.equal(methodOf(entry), "POST");
  assert.equal(bearerPattern(entry), null, "no bearer namespace is accepted");
  assert.match(entry.body, /if\s*\(\$http_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u);
  assert.match(entry.body, /if\s*\(\$http_proxy_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u);
  assert.match(entry.body, /if\s*\(\$http_content_type\s*!~\s*"\^application\/json/u);
  assert.match(entry.body, /if\s*\(\$http_transfer_encoding\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
  assert.match(entry.body, /if\s*\(\$http_x_openarc_csrf\s*=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
  assert.match(entry.body, /if\s*\(\$http_idempotency_key\s*=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
  assert.match(entry.body, /client_max_body_size\s+16k;/u);
  assert.match(entry.body, /include\s+\/etc\/nginx\/tenant_write_proxy_params;/u);
  assert.match(entry.body, /include\s+\/etc\/nginx\/market_response_headers;/u);
  assert.ok(!/commerce_agent_proxy_params|oacs_v1_|oas_ag_|oas_pr_/u.test(entry.body));
  assert.ok(writeParams.includes("proxy_set_header X-OpenArc-CSRF $http_x_openarc_csrf;"));
  assert.ok(writeParams.includes("proxy_set_header Idempotency-Key $http_idempotency_key;"));
  for (const source of [writeParams, agentParams, responseHeaders]) {
    assert.ok(!/payment/u.test(source), "the reused param files gain no payment edit");
  }
});

test("payment: the capability route is an exact credentialless GET and no conf embeds a secret", () => {
  const capability = parseLocations(paymentCapabilitySource);
  assert.equal(capability.length, 1);
  const entry = capability[0];
  assert.equal(entry.modifier, "=");
  assert.equal(entry.path, paymentRegistry.capabilityPath);
  assert.match(entry.body, /if\s*\(\$request_method\s*!=\s*GET\)\s*\{\s*return\s+405;\s*\}/u);
  assert.match(entry.body, new RegExp(`if\\s*\\(\\$request_uri\\s*!=\\s*"${entry.path}"\\)\\s*\\{\\s*return\\s+400;\\s*\\}`, "u"));
  for (const header of ["$http_cookie", "$http_authorization", "$http_proxy_authorization", "$http_x_openarc_csrf", "$http_idempotency_key", "$http_x_openarc_proxy_secret"]) {
    assert.match(entry.body, new RegExp(`if\\s*\\(${header.replace("$", "\\$")}\\s*!=\\s*""\\)\\s*\\{\\s*return\\s+403;\\s*\\}`, "u"));
  }
  assert.match(entry.body, /proxy_pass_request_headers\s+off;/u);
  assert.match(entry.body, /proxy_pass_request_body\s+off;/u);
  assert.match(entry.body, new RegExp(`proxy_pass\\s+https://\\$\\{API_UPSTREAM_HOST\\}${entry.path};`, "u"));
  assert.ok(!/try_files|index\.html/u.test(entry.body));
  for (const source of [paymentBusinessSource, paymentCapabilitySource, paymentDenySource]) {
    assert.ok(!/SOURCE_PROXY_SECRET/u.test(source));
    assert.ok(!/(?:oacs_v1_|oas_pr_|oas_ag_|oag_v1_)[A-Za-z0-9]{4,}/u.test(source), "no literal token");
    assert.ok(!/Bearer\s+(?!oacs_v1_\[)[A-Za-z0-9._-]{8,}/u.test(source), "no literal bearer");
  }
});

test("payment: the deny include uses plain prefixes, covers lookalikes and shadows no accepted family", () => {
  const deny = parseLocations(paymentDenySource);
  assert.deepEqual(
    deny.map((entry) => `${entry.modifier}|${entry.path}`).sort(),
    ["|/v2/agent/commerce-payment-attempts", "|/v2/agent/commerce-payment-requirements", "|/v2/public/payment-capabilities"],
    "exactly three plain payment denies",
  );
  for (const entry of deny) {
    assert.match(entry.body.trim(), /^return 404;$/u);
  }
  for (const lookalike of [
    "/v2/public/payment-capabilitiesXYZ",
    "/v2/agent/commerce-payment-requirementsXYZ",
    "/v2/agent/commerce-payment-requirements/extra",
    "/v2/agent/commerce-payment-attemptsXYZ",
    "/v2/agent/commerce-payment-attempts/not-an-id",
    "/v2/agent/commerce-payment-attempts/55555555-5555-4555-8555-555555555555/observe",
  ]) {
    assert.ok(deny.some((entry) => lookalike.startsWith(entry.path)), `${lookalike} must be covered by a plain prefix`);
  }
  for (const accepted of [
    "/v2/agent/commerce-sessions/exchange",
    "/v2/agent/commerce-actions",
    "/v2/agent/commerce-grants",
    "/v2/provider/organizations/openarc:org:11111111-1111-4111-8111-111111111111/listings",
  ]) {
    assert.ok(!deny.some((entry) => accepted.startsWith(entry.path)), `${accepted} must not be captured by a payment deny`);
  }
  // The seller terms root is owned by the accepted market deny, not restated.
  assert.match(read(FILES.marketDeny), /location \/v2\/provider \{ return 404; \}/u);
  // Enabled exact and anchored routes still beat the deny prefixes.
  assert.ok(paymentProxying.some((entry) => entry.modifier === "=" && entry.path === "/v2/agent/commerce-payment-attempts"));
  assert.ok(paymentProxying.some((entry) => entry.modifier === "~" && pathText(entry).startsWith("/v2/agent/commerce-payment-attempts/")));
  // No accepted business include selects a payment target.
  for (const file of [FILES.sessionBusiness, FILES.actionBusiness, FILES.business]) {
    for (const entry of parseLocations(read(file)).filter((candidate) => !candidate.path.startsWith("@"))) {
      for (const route of PAYMENT_ROUTES.slice(1)) {
        assert.ok(!selects(entry, paymentTargetFor(route.path)), `${file} ${entry.raw} must not capture ${route.id}`);
      }
    }
  }
});

test("payment: both API templates install capability, business and deny once, before the namespace guards", () => {
  for (const template of [FILES.apiConf, FILES.arcConf]) {
    const source = read(template);
    for (const include of ["openarc-payment-capability-locations.inc", "openarc-commerce-payment-locations.inc", "openarc-payment-deny.inc"]) {
      assert.equal(source.split(include).length - 1, 1, `${template} must include ${include} exactly once`);
      assert.ok(source.indexOf(include) > source.indexOf("openarc-grant-deny.inc"), `${include} must follow the grant family`);
      assert.ok(source.indexOf(include) < source.indexOf("location = /v1 { return 404; }"), `${include} must precede the namespace guards`);
      assert.ok(source.indexOf(include) < source.indexOf("location / { try_files"), `${include} must precede the SPA fallback`);
    }
  }
  assert.ok(!paymentBusinessSource.includes(paymentRegistry.capabilityPath));
  assert.ok(!/commerce-payment|payment-terms/u.test(paymentCapabilitySource));
});

test("payment: the plain no-API template denies every payment path without duplicates or proxying", () => {
  const plainSource = read(FILES.plainConf);
  const plainLocations = parseLocations(plainSource);
  for (const required of ["/v2/public/payment-capabilities", "/v2/agent/commerce-payment-requirements", "/v2/agent/commerce-payment-attempts", "/v2/provider"]) {
    const entry = plainLocations.find((candidate) => candidate.path === required && candidate.modifier === "");
    assert.ok(entry, `${required} must be a plain deny in the no-API template`);
    assert.match(entry.body.trim(), /^return 404;$/u);
  }
  assert.ok(!plainSource.includes("openarc-commerce-payment-locations"));
  assert.ok(!stripNginxComments(plainSource).includes("API_UPSTREAM_HOST"));
  const paths = plainLocations.map((entry) => `${entry.modifier}|${entry.path}`);
  assert.equal(new Set(paths).size, paths.length, "no duplicate location");
});

test("payment: Dockerfile defaults the flag off in both stages and requires the grant and action chain", () => {
  assert.equal((dockerfile.match(/ARG\s+VITE_COMMERCE_PAYMENTS_ENABLED=false/gu) ?? []).length, 2, "default false in both stages");
  assert.ok(!/ARG\s+VITE_COMMERCE_PAYMENTS_ENABLED=true/u.test(dockerfile));
  assert.equal((dockerfile.match(/case\s+"\$\{VITE_COMMERCE_PAYMENTS_ENABLED\}"\s+in\s+true\|false\)/gu) ?? []).length, 2);
  const dependency =
    'if [ "${VITE_COMMERCE_PAYMENTS_ENABLED}" = "true" ] && { ' +
    '[ "${VITE_COMMERCE_GRANTS_ENABLED}" != "true" ] || ' +
    '[ "${VITE_COMMERCE_ACTIONS_ENABLED}" != "true" ] || ' +
    '[ "${VITE_COMMERCE_SESSIONS_ENABLED}" != "true" ] || ' +
    '[ "${VITE_TENANT_READS_ENABLED}" != "true" ] || ' +
    '[ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || ' +
    '[ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }';
  assert.equal(dockerfile.split(dependency).length - 1, 2, "the full dependency chain in both stages");
  assert.equal(dockerfile.split("\n").filter((line) => line.includes("VITE_COMMERCE_PAYMENTS_ENABLED=true requires VITE_COMMERCE_GRANTS_ENABLED=true, VITE_COMMERCE_ACTIONS_ENABLED=true")).length, 2);
});

test("payment: Dockerfile installs capability/deny unconditionally in the API branch and the business include conditionally", () => {
  for (const file of PAYMENT_FILES_LIST) {
    assert.equal(dockerfile.split(file).length - 1, 1, `Dockerfile must copy ${file} exactly once`);
  }
  const capabilityCp = dockerfile.indexOf("cp /tmp/openarc-nginx/nginx-payment-capability.conf /etc/nginx/templates/openarc-payment-capability-locations.inc.template;");
  const denyCp = dockerfile.indexOf("cp /tmp/openarc-nginx/nginx-payment-deny.conf /etc/nginx/templates/openarc-payment-deny.inc.template;");
  const branch = dockerfile.indexOf('if [ "${VITE_COMMERCE_PAYMENTS_ENABLED}" = "true" ]; then');
  const apiBranch = dockerfile.indexOf('if [ "${VITE_API_BOUNDARY_ENABLED}" = "true" ]; then');
  assert.ok(capabilityCp !== -1 && denyCp !== -1 && branch !== -1 && apiBranch !== -1);
  assert.ok(apiBranch < capabilityCp && capabilityCp < branch && denyCp < branch, "capability/deny are unconditional inside the API branch");
  assert.equal((dockerfile.match(/if \[ "\$\{VITE_COMMERCE_PAYMENTS_ENABLED\}" = "true" \]; then/gu) ?? []).length, 1);
  const end = dockerfile.indexOf("cp /tmp/openarc-nginx/nginx-market-capability.conf");
  assert.ok(end > branch);
  const arm = dockerfile.slice(branch, end);
  assert.equal(arm.split("openarc-commerce-payment-locations.inc.template").length - 1, 2, "both arms write the same runtime include path");
  assert.match(arm, /:\s*>\s*\/etc\/nginx\/templates\/openarc-commerce-payment-locations\.inc\.template;/u);
  assert.match(arm, /cp \/tmp\/openarc-nginx\/tenant_write_proxy_params \/etc\/nginx\/tenant_write_proxy_params;/u);
  assert.match(arm, /cp \/tmp\/openarc-nginx\/commerce_agent_proxy_params \/etc\/nginx\/commerce_agent_proxy_params;/u);
});
