import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

/**
 * Static deployment guards for the commerce-action proxy family.
 *
 * These assertions parse the real nginx directives (never comments), the real
 * Dockerfile RUN/shell lines and the real frozen registry source at
 * packages/shared/src/commerce/control-action-capabilities.ts. The twelve-route
 * inventory, the family/audience split and every method are DERIVED from that
 * registry, not restated here, so a registry edit fails this guard instead of
 * silently drifting from the edge.
 *
 * They prove: the exact twelve ACTION_ROUTES and their methods; the canonical
 * typed org/agent/policy ids ([1-8] nibble) and the version-4
 * action/approval/mutation ids; the query, body and header guards; the
 * encoded-URI-preserving no-URI proxy_pass; that the registry contains no
 * mixed-method path and the include therefore declares no named-location
 * dispatch; the strict browser/agent credential separation; the unconditional
 * capability and deny installation; the full action-flag dependency chain; all
 * flag combinations; and the OFF / no-API fail-closed behaviour.
 *
 * They do not run nginx and do not prove actual nginx, TLS upstream or browser
 * acceptance; real-nginx behaviour in both flag modes is recorded separately.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => readFileSync(path.join(root, relativePath), "utf8");

const FILES = {
  registry: "packages/shared/src/commerce/control-action-capabilities.ts",
  dockerfile: "apps/web/Dockerfile",
  apiConf: "apps/web/nginx-api.conf",
  arcConf: "apps/web/nginx-arc.conf",
  plainConf: "apps/web/nginx.conf",
  business: "apps/web/nginx-action-locations.conf",
  capability: "apps/web/nginx-action-capability.conf",
  deny: "apps/web/nginx-action-deny.conf",
  agentParams: "apps/web/commerce_agent_proxy_params",
  readParams: "apps/web/tenant_proxy_params",
  writeParams: "apps/web/tenant_write_proxy_params",
  responseHeaders: "apps/web/market_response_headers",
  controlDeny: "apps/web/nginx-control-deny.conf",
  sessionDeny: "apps/web/nginx-session-deny.conf",
  sessionBusiness: "apps/web/nginx-commerce-session-locations.conf",
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
    /export const ACTION_CAPABILITIES_PATH\s*=\s*\n?\s*"([^"]+)"/u,
  );
  assert.ok(capabilityPath, "ACTION_CAPABILITIES_PATH must be declared");
  const controlBase = source.match(/const ACTION_CONTROL_BASE = "([^"]+)"/u);
  const agentBase = source.match(/const ACTION_AGENT_BASE = "([^"]+)"/u);
  assert.ok(controlBase && agentBase, "both frozen route bases must be declared");
  const bases = {
    ACTION_CONTROL_BASE: controlBase[1],
    ACTION_AGENT_BASE: agentBase[1],
  };
  const entry =
    /\{\s*id:\s*"([a-z0-9_]+)",\s*family:\s*"([a-z_]+)",\s*audience:\s*"([a-z]+)",\s*method:\s*"([A-Z]+)",\s*path:\s*`([^`]+)`\s*\}/gu;
  const routes = [];
  let match;
  while ((match = entry.exec(source)) !== null) {
    const template = match[5].replace(
      /\$\{([A-Z_]+)\}/gu,
      (_all, name) => {
        assert.ok(Object.hasOwn(bases, name), `unknown base ${name}`);
        return bases[name];
      },
    );
    routes.push({
      id: match[1],
      family: match[2],
      audience: match[3],
      method: match[4],
      path: template,
    });
  }
  return { capabilityPath: capabilityPath[1], routes };
}

const registry = parseRegistry(registrySource);
const ROUTES = registry.routes;
const CAPABILITY_PATH = registry.capabilityPath;

// Concrete canonical ids that expand each frozen `:parameter` template into the
// exact wire target nginx must select.
const IDS = Object.freeze({
  ":organizationId": "openarc:org:11111111-1111-4111-8111-111111111111",
  ":actionId": "openarc:action:33333333-3333-4333-8333-333333333333",
  ":approvalId": "openarc:approval:44444444-4444-4444-8444-444444444444",
  ":subjectAgentId": "openarc:agent:55555555-5555-4555-8555-555555555555",
  ":policyId": "openarc:policy:66666666-6666-4666-8666-666666666666",
  ":mutationId": "22222222-2222-4222-8222-222222222222",
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

// Canonical shared grammars: identity ids carry the [1-8] version nibble, the
// new action/approval namespaces and the logical mutation id pin version 4.
const UUID_ID = "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const UUID_V4 = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const CONTROL_BASE = "/v2/control/organizations";
const AGENT_BASE = "/v2/agent";

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

const browserLocations = proxying.filter((entry) => pathText(entry).startsWith(CONTROL_BASE));
const agentLocations = proxying.filter((entry) => pathText(entry).startsWith(`${AGENT_BASE}/commerce-action`));

/* ------------------------------------------------------------------ *
 * Registry-derived inventory
 * ------------------------------------------------------------------ */

test("the frozen registry publishes exactly twelve routes across two audiences", () => {
  assert.equal(CAPABILITY_PATH, "/v2/public/action-capabilities");
  assert.equal(ROUTES.length, 12, "the action registry is exactly twelve routes");
  assert.equal(new Set(ROUTES.map((route) => route.id)).size, 12, "route ids are unique");
  const management = ROUTES.filter((route) => route.family === "commerce_action_management");
  const authorization = ROUTES.filter((route) => route.family === "commerce_action_authorization");
  assert.equal(management.length, 9, "nine commerce_action_management routes");
  assert.equal(authorization.length, 3, "three commerce_action_authorization routes");
  for (const route of management) {
    assert.equal(route.audience, "browser", `${route.id} must be browser audience`);
    assert.ok(route.path.startsWith(`${CONTROL_BASE}/:organizationId/`), `${route.id} must live under the control base`);
  }
  for (const route of authorization) {
    assert.equal(route.audience, "agent", `${route.id} must be agent audience`);
    assert.ok(route.path.startsWith(`${AGENT_BASE}/commerce-action`), `${route.id} must live under the agent base`);
  }
  for (const route of ROUTES) {
    assert.ok(["GET", "POST"].includes(route.method), `${route.id} must be GET or POST`);
  }
  assert.deepEqual(
    ROUTES.map((route) => route.id),
    [
      "action_list",
      "action_detail",
      "approval_list",
      "approval_detail",
      "action_exposure",
      "action_mutation_status",
      "action_approve",
      "action_reject",
      "action_cancel",
      "action_authorize",
      "agent_action_detail",
      "agent_action_mutation_status",
    ],
    "the frozen id order must not drift",
  );
});

test("the business include declares exactly one location per frozen route with the exact method", () => {
  assert.equal(proxying.length, 12, "exactly twelve externally addressable proxying locations");
  assert.equal(external.length, 12, "no extra non-proxying location may hide in the business include");
  const claimed = new Set();
  for (const route of ROUTES) {
    const target = targetFor(route.path);
    const matches = findRoute(target);
    assert.equal(matches.length, 1, `${route.id} (${route.method} ${target}) must select exactly one location`);
    assert.equal(methodOf(matches[0]), route.method, `${route.id} must pin ${route.method}`);
    assert.ok(!claimed.has(matches[0].raw), `${matches[0].raw} may serve only one frozen route`);
    claimed.add(matches[0].raw);
  }
  assert.equal(claimed.size, 12, "the twelve routes map one-to-one onto twelve locations");
  // No capability, manifest, health, grant or payment descriptor is proxied here.
  assert.ok(
    !/grant|payment|healthz|capabilit/iu.test(stripNginxComments(businessSource).replace(/#[^\n]*/gu, "")),
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
  // The accepted mixed-method families still carry their dispatch: this guard
  // must never be read as permission to remove one.
  const sessionBusiness = read(FILES.sessionBusiness);
  assert.match(sessionBusiness, /error_page\s+418\s*=\s*@openarc_session_issue;/u, "the accepted session dispatch must remain");
});

test("ids use the canonical typed grammars: [1-8] identity ids, version-4 action/approval/mutation ids", () => {
  assert.equal(browserLocations.length, 9, "nine browser locations");
  assert.equal(agentLocations.length, 3, "three agent locations");
  for (const entry of browserLocations) {
    assert.ok(entry.raw.includes(`openarc:org:${UUID_ID}`), `${entry.raw} must anchor a canonical typed organization id`);
  }
  for (const entry of browserLocations.filter((candidate) => /\/actions\/openarc:action:/u.test(candidate.path))) {
    assert.ok(entry.raw.includes(`openarc:action:${UUID_V4}`), `${entry.raw} must pin the action id to version 4`);
  }
  const approvalDetail = browserLocations.find((entry) => /\/approvals\/openarc:approval:/u.test(entry.path));
  assert.ok(approvalDetail, "the approval detail route must exist");
  assert.ok(approvalDetail.raw.includes(`openarc:approval:${UUID_V4}`), "the approval id must pin version 4");
  const exposure = browserLocations.find((entry) => /exposure\$/u.test(entry.path));
  assert.ok(exposure, "the exposure route must exist");
  assert.ok(exposure.raw.includes(`openarc:agent:${UUID_ID}`), "the subject agent id must be a canonical typed agent id");
  assert.ok(exposure.raw.includes(`openarc:policy:${UUID_ID}`), "the policy id must be a canonical typed policy id");
  const humanMutation = browserLocations.find((entry) => /action-mutations/u.test(entry.path));
  assert.ok(humanMutation, "the human mutation route must exist");
  assert.ok(humanMutation.raw.includes(UUID_V4), "the human mutation id must pin version 4");
  const agentMutation = agentLocations.find((entry) => /commerce-action-mutations/u.test(pathText(entry)));
  assert.ok(agentMutation, "the agent mutation route must exist");
  assert.ok(agentMutation.raw.includes(UUID_V4), "the agent mutation id must pin version 4");
  const agentDetail = agentLocations.find((entry) => entry.modifier === "~" && /commerce-actions\//u.test(pathText(entry)));
  assert.ok(agentDetail, "the agent action detail route must exist");
  assert.ok(agentDetail.raw.includes(`openarc:action:${UUID_V4}`), "the agent action id must pin version 4");
  // Version drift and untyped ids must not match.
  const detail = browserLocations.find((entry) => /\/actions\/openarc:action:[^/]*\$$/u.test(entry.path));
  assert.ok(detail, "the human action detail route must exist");
  const org = IDS[":organizationId"];
  assert.ok(!regexFor(detail).test(`${CONTROL_BASE}/${org}/actions/openarc:action:33333333-3333-1333-8333-333333333333`), "the action id must reject a non-v4 UUID");
  assert.ok(!regexFor(detail).test(`${CONTROL_BASE}/${org}/actions/33333333-3333-4333-8333-333333333333`), "the action id must reject an untyped UUID");
  assert.ok(!regexFor(detail).test(`${CONTROL_BASE}/openarc:org:11111111-1111-9111-8111-111111111111/actions/openarc:action:33333333-3333-4333-8333-333333333333`), "the organization id must reject a version-9 nibble");
});

test("every proxying action route uses the host-only no-URI proxy_pass", () => {
  for (const entry of proxying) {
    assert.match(entry.body, /proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\};/u, `${entry.raw} must proxy with no URI part`);
    assert.ok(!/proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\}\S+;/u.test(entry.body), `${entry.raw} must not append a URI component`);
    assert.ok(!/proxy_pass\s+http:/u.test(entry.body), `${entry.raw} must use https only`);
    assert.ok(!/proxy_cache\b|proxy_store\b/u.test(entry.body), `${entry.raw} must not cache or store`);
  }
  assert.ok(!/rewrite\b/u.test(stripNginxComments(businessSource)), "must not rewrite the request target");
});

test("only the two collection lists accept a raw query; every other route rejects a literal ?", () => {
  const listTargets = ROUTES.filter((route) => /\/(actions|approvals)$/u.test(route.path)).map((route) => targetFor(route.path));
  assert.equal(listTargets.length, 2, "exactly two frozen collection lists");
  const lists = listTargets.map((target) => findRoute(target)[0]);
  for (const entry of lists) {
    assert.ok(!/\$request_uri\s*~/u.test(entry.body), `${entry.raw} must keep its bounded read query`);
    assert.ok(!/\$args\s*!=\s*""/u.test(entry.body), `${entry.raw} must not reject the read query`);
  }
  const queryRejecting = proxying.filter((entry) => !lists.includes(entry));
  assert.equal(queryRejecting.length, 10, "the other ten routes reject a query");
  for (const entry of queryRejecting) {
    if (entry.modifier === "=") {
      assert.match(entry.body, /if\s*\(\$request_uri\s*!=\s*"\/v2\/agent\/commerce-actions"\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} exact route must reject any query including a bare ?`);
      continue;
    }
    assert.match(entry.body, /if\s*\(\$request_uri\s*~\s*"\\\?"\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject a literal ?`);
  }
  assert.ok(!/\$request_uri\s*(?:!=|=)\s*\$uri\b/u.test(stripNginxComments(businessSource)), "must never compare encoded $request_uri to decoded $uri");
});

test("wrong verbs including HEAD, PUT, DELETE and OPTIONS are rejected with 405 on every route", () => {
  for (const entry of proxying) {
    const method = methodOf(entry);
    assert.ok(method === "GET" || method === "POST", `${entry.raw} must pin exactly one method`);
    const guards = entry.body.match(/\$request_method\s*!=\s*[A-Z]+/gu) ?? [];
    assert.equal(guards.length, 1, `${entry.raw} must declare exactly one method guard`);
    assert.ok(!/\$request_method\s*=\s*[A-Z]+/u.test(entry.body), `${entry.raw} must not branch on an extra verb`);
  }
  assert.equal(proxying.filter((entry) => methodOf(entry) === "GET").length, 8, "eight GET locations");
  assert.equal(proxying.filter((entry) => methodOf(entry) === "POST").length, 4, "four POST locations");
});

test("browser reads are bodyless and browser writes require JSON, CSRF, idempotency and a 16KiB bound", () => {
  const getters = browserLocations.filter((entry) => methodOf(entry) === "GET");
  const writers = browserLocations.filter((entry) => methodOf(entry) === "POST");
  assert.equal(getters.length, 6, "six browser GET locations");
  assert.equal(writers.length, 3, "three browser POST locations (approve, reject, cancel)");
  for (const entry of getters) {
    assert.match(entry.body, /if\s*\(\$http_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject a bearer`);
    assert.match(entry.body, /if\s*\(\$http_proxy_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject proxy authorization`);
    assert.match(entry.body, /if\s*\(\$http_x_openarc_csrf\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject a CSRF header`);
    assert.match(entry.body, /if\s*\(\$http_idempotency_key\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject an idempotency header`);
    assert.match(entry.body, /if\s*\(\$openarc_action_body_ok\s*=\s*0\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must fail the body guard`);
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
  // The reused param files gain no action edit.
  assert.match(readParams, /proxy_pass_request_body\s+off;/u);
  assert.match(readParams, /proxy_ssl_verify\s+on;/u);
  assert.match(readParams, /proxy_next_upstream\s+off;/u);
  assert.match(writeParams, /proxy_pass_request_body\s+on;/u);
  assert.ok(!readParams.includes("openarc_action"), "the read params must stay unchanged");
  assert.ok(!writeParams.includes("openarc_action"), "the write params must stay unchanged");
  assert.ok(!agentParams.includes("openarc_action"), "the agent params must stay unchanged");
  for (const header of ["Set-Cookie", "Access-Control-Allow-Origin", "Vary"]) {
    assert.match(responseHeaders, new RegExp(`proxy_hide_header\\s+${header};`, "u"));
  }
});

test("agent routes forward only the headless allowlist and reject every browser credential", () => {
  const authorize = proxying.find((entry) => entry.modifier === "=" && entry.path === `${AGENT_BASE}/commerce-actions`);
  assert.ok(authorize, "the agent authorize route must be an exact location");
  assert.equal(methodOf(authorize), "POST");
  const reads = agentLocations.filter((entry) => entry !== authorize);
  assert.equal(reads.length, 2, "two agent GET routes (detail and mutation status)");
  for (const entry of agentLocations) {
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
    assert.match(entry.body, /if\s*\(\$http_authorization\s*!~\s*"\^Bearer oacs_v1_\[A-Za-z0-9_-\]\{43\}\$"\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must require the exact oacs_v1_ commerce-session bearer namespace`);
    assert.ok(!/oas_ag_/u.test(entry.body), `${entry.raw} must NOT accept an oas_ag_ machine credential: a read-only machine bearer can never authorize spending`);
    assert.match(entry.body, /include\s+\/etc\/nginx\/commerce_agent_proxy_params;/u, `${entry.raw} must use the agent params`);
    assert.match(entry.body, /include\s+\/etc\/nginx\/market_response_headers;/u, `${entry.raw} must suppress Set-Cookie/CORS`);
  }
  // POST authorize alone carries the bounded JSON body and idempotency key.
  assert.match(authorize.body, /if\s*\(\$http_content_type\s*!~\s*"\^application\/json/u);
  assert.match(authorize.body, /if\s*\(\$http_idempotency_key\s*=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
  assert.match(authorize.body, /client_max_body_size\s+16k;/u);
  assert.match(authorize.body, /proxy_set_header\s+Content-Type\s+\$http_content_type;/u);
  assert.match(authorize.body, /proxy_set_header\s+Content-Length\s+\$http_content_length;/u);
  assert.match(authorize.body, /proxy_set_header\s+Idempotency-Key\s+\$http_idempotency_key;/u);
  assert.match(authorize.body, /proxy_pass_request_body\s+on;/u);
  for (const entry of reads) {
    assert.equal(methodOf(entry), "GET");
    assert.match(entry.body, /if\s*\(\$http_content_type\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
    assert.match(entry.body, /if\s*\(\$http_content_length\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
    assert.match(entry.body, /if\s*\(\$http_idempotency_key\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
    assert.match(entry.body, /client_max_body_size\s+1k;/u);
    assert.match(entry.body, /proxy_pass_request_body\s+off;/u);
    assert.ok(!/proxy_set_header\s+Idempotency-Key/u.test(entry.body), "an agent GET must not forward an idempotency key");
    assert.ok(!/proxy_pass_request_body\s+on;/u.test(entry.body), "an agent GET must never forward a body");
  }
  assert.ok(!/proxy_pass_request_body/u.test(agentParams), "the agent params must not set body forwarding globally");
});

test("browser and agent credentials are strictly separated", () => {
  for (const entry of browserLocations) {
    assert.ok(!entry.body.includes("commerce_agent_proxy_params"), `${entry.raw} must not use the agent allowlist`);
    assert.ok(!/oas_ag_/u.test(entry.body), `${entry.raw} must not accept an agent bearer`);
    assert.match(entry.body, /if\s*\(\$http_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject any bearer outright`);
  }
  for (const entry of agentLocations) {
    assert.ok(!entry.body.includes("tenant_proxy_params"), `${entry.raw} must not use the browser read params`);
    assert.ok(!entry.body.includes("tenant_write_proxy_params"), `${entry.raw} must not use the browser write params`);
    assert.match(entry.body, /if\s*\(\$http_cookie\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must never accept a cookie`);
  }
  // The headless allowlist forwards nothing user-controlled beyond the bearer.
  assert.match(agentParams, /proxy_pass_request_headers\s+off;/u);
  const forwarded = agentParams.match(/proxy_set_header\s+([^\s]+)\s+(\S+)/gu) ?? [];
  const allowed = new Set(["Connection", "Host", "Authorization", "Accept"]);
  for (const directive of forwarded) {
    const name = directive.replace(/proxy_set_header\s+/u, "").split(/\s+/u)[0];
    assert.ok(allowed.has(name), `agent params must not forward unexpected header ${name}`);
  }
  for (const forbidden of ["X-Forwarded-For", "X-Real-IP", "X-OpenArc-Proxy-Secret", "X-OpenArc-Proxy-Client-IP", "Forwarded", "X-Forwarded-Proto", "X-Forwarded-Host"]) {
    assert.ok(!new RegExp(`proxy_set_header\\s+${forbidden}\\s+\\$http_`, "u").test(agentParams), `agent params must not forward ${forbidden}`);
  }
  assert.ok(!/proxy_set_header\s+Cookie\s+\$http_cookie/u.test(agentParams), "the agent params must never forward a browser cookie");
  assert.ok(!/SOURCE_PROXY_SECRET/u.test(agentParams), "the agent surface must not reuse the legacy proxy secret");
  assert.match(agentParams, /proxy_ssl_verify\s+on;/u);
  assert.match(agentParams, /proxy_next_upstream\s+off;/u);
});

test("no conf in this family embeds a secret, token or credential value", () => {
  for (const [name, source] of [
    [FILES.business, businessSource],
    [FILES.capability, capabilitySource],
    [FILES.deny, denySource],
  ]) {
    assert.ok(!/SOURCE_PROXY_SECRET/u.test(source), `${name} must not reference the legacy proxy secret`);
    assert.ok(!/oacs_v1_[A-Za-z0-9]{4,}/u.test(source), `${name} must not embed a literal bearer value`);
    assert.ok(!/oas_ag_[A-Za-z0-9]{4,}/u.test(source), `${name} must not embed a literal machine credential`);
    assert.ok(!/Bearer\s+(?!oacs_v1_\[)[A-Za-z0-9._-]{8,}/u.test(source), `${name} must not embed a literal token`);
  }
});

test("the action-capability route is an exact credentialless GET with a fixed upstream path", () => {
  const capabilityLocations = parseLocations(capabilitySource);
  assert.equal(capabilityLocations.length, 1, "the capability file must declare exactly one location");
  const entry = capabilityLocations[0];
  assert.equal(entry.modifier, "=", "the capability route must be an exact match");
  assert.equal(entry.path, CAPABILITY_PATH, "the capability route must be the frozen ACTION_CAPABILITIES_PATH");
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

test("the deny include uses plain prefixes, covers lookalikes and never shadows the session agent routes", () => {
  const denyLocations = parseLocations(denySource);
  assert.equal(denyLocations.length, 3, "exactly three plain action denies");
  for (const required of [CAPABILITY_PATH, "/v2/agent/commerce-actions", "/v2/agent/commerce-action-mutations"]) {
    const entry = denyLocations.find((candidate) => candidate.path === required);
    assert.ok(entry, `${required} must be a plain deny prefix`);
    assert.equal(entry.modifier, "", `${required} must not use ^~ or =`);
    assert.match(entry.body.trim(), /^return 404;$/u);
    assert.ok(!/proxy_pass|try_files/u.test(entry.body), `${required} deny must not proxy or serve SPA`);
  }
  for (const lookalike of [
    "/v2/public/action-capabilitiesXYZ",
    "/v2/agent/commerce-actionsXYZ",
    "/v2/agent/commerce-action-mutationsXYZ",
    "/v2/agent/commerce-actions/not-an-id",
    "/v2/agent/commerce-action-mutations/11111111-1111-1111-8111-111111111111",
  ]) {
    assert.ok(denyLocations.some((entry) => entry.modifier === "" && lookalike.startsWith(entry.path)), `${lookalike} must be covered by a plain prefix`);
  }
  assert.equal(denyLocations.filter((entry) => entry.path === "/v2/agent" || entry.path === "/v2/agent/").length, 0, "no broad /v2/agent deny may shadow the commerce-session agent routes");
  for (const sessionPath of ["/v2/agent/commerce-sessions/exchange", "/v2/agent/commerce-session-mutations/22222222-2222-4222-8222-222222222222"]) {
    assert.ok(!denyLocations.some((entry) => sessionPath.startsWith(entry.path)), `${sessionPath} must not be captured by an action deny`);
  }
  assert.ok(!denySource.includes("API_UPSTREAM_HOST"), "the deny file must not reference the upstream");
  assert.ok(!denyLocations.some((entry) => entry.modifier === "^~"), "deny fallbacks must not use ^~ (would suppress enabled regexes)");
  // The browser family root deny is owned by the existing control deny and must
  // not be restated (a duplicate location is a configuration error).
  assert.ok(!denyLocations.some((entry) => entry.path.startsWith("/v2/control")), "the action deny must not restate the control deny");
  assert.match(read(FILES.controlDeny), /location \/v2\/control \{ return 404; \}/u, "the unconditional control deny must still cover the browser action roots");
  // Enabled routes still beat the deny prefixes.
  assert.ok(proxying.some((entry) => entry.modifier === "=" && entry.path === "/v2/agent/commerce-actions"), "the exact authorize route must beat the /v2/agent/commerce-actions prefix");
  assert.ok(proxying.some((entry) => entry.modifier === "~" && pathText(entry).startsWith("/v2/agent/commerce-action-mutations/")), "the anchored agent mutation regex must beat the prefix");
});

test("both API templates install capability, business and deny includes exactly once", () => {
  for (const template of [FILES.apiConf, FILES.arcConf]) {
    const source = read(template);
    for (const include of [
      "openarc-action-capability-locations.inc",
      "openarc-commerce-action-locations.inc",
      "openarc-action-deny.inc",
    ]) {
      assert.equal(source.split(include).length - 1, 1, `${template} must include ${include} exactly once`);
    }
    // The accepted families are untouched.
    for (const include of [
      "openarc-session-capability-locations.inc",
      "openarc-commerce-session-locations.inc",
      "openarc-session-deny.inc",
      "openarc-control-deny.inc",
      "openarc-market-deny.inc",
    ]) {
      assert.equal(source.split(include).length - 1, 1, `${template} must keep ${include} exactly once`);
    }
    // The fail-closed API namespace guards survive ahead of the SPA fallback.
    for (const guard of ["location = /v1 { return 404; }", "location = /v2 { return 404; }", "location /v1/ { return 404; }", "location /v2/ { return 404; }"]) {
      assert.ok(source.includes(guard), `${template} must keep ${guard}`);
      assert.ok(source.indexOf(guard) < source.indexOf("location / { try_files"), `${guard} must precede the SPA fallback`);
    }
  }
  // Capability, business and deny are three independent files.
  assert.ok(!businessSource.includes(CAPABILITY_PATH), "the business include must not own the capability route");
  assert.ok(!capabilitySource.includes("/commerce-actions"), "the capability file must not own a business route");
  assert.ok(!capabilitySource.includes("/actions"), "the capability file must not own a business route");
});

test("the plain no-API template denies every action path without SPA fallback", () => {
  const plainSource = read(FILES.plainConf);
  const plain = stripNginxComments(plainSource);
  assert.ok(!plain.includes("API_UPSTREAM_HOST"), "plain template must stay API boundary OFF");
  const plainLocations = parseLocations(plainSource);
  for (const required of [CAPABILITY_PATH, "/v2/agent/commerce-actions", "/v2/agent/commerce-action-mutations"]) {
    const entry = plainLocations.find((candidate) => candidate.path === required);
    assert.ok(entry, `${required} must be denied in the no-API template`);
    assert.equal(entry.modifier, "", `${required} must be a plain prefix`);
    assert.match(entry.body.trim(), /^return 404;$/u);
    assert.ok(!/try_files|proxy_pass/u.test(entry.body), `${required} must not fall through to SPA or proxy`);
  }
  assert.ok(plainLocations.some((entry) => entry.path === "/v2/control" && entry.modifier === ""), "the no-API template must keep denying the browser action roots via /v2/control");
  assert.ok(!plain.includes("openarc-commerce-action-locations"), "the no-API template must never include the proxying business file");
  assert.ok(!plainLocations.some((entry) => entry.path === "/v2/agent" || entry.path === "/v2/agent/"), "the no-API template must not add a broad /v2/agent deny");
});

test("Dockerfile defaults the action flag off in both stages and requires the full dependency chain", () => {
  const argOccurrences = dockerfile.match(/ARG\s+VITE_COMMERCE_ACTIONS_ENABLED=false/gu) ?? [];
  assert.equal(argOccurrences.length, 2, "the flag must default to false in both stages");
  assert.ok(!/ARG\s+VITE_COMMERCE_ACTIONS_ENABLED=true/u.test(dockerfile), "the flag must never default on");
  const caseOccurrences = dockerfile.match(/case\s+"\$\{VITE_COMMERCE_ACTIONS_ENABLED\}"\s+in\s+true\|false\)/gu) ?? [];
  assert.equal(caseOccurrences.length, 2, "the flag must be validated true|false in both stages");
  const dependency =
    'if [ "${VITE_COMMERCE_ACTIONS_ENABLED}" = "true" ] && { ' +
    '[ "${VITE_COMMERCE_SESSIONS_ENABLED}" != "true" ] || ' +
    '[ "${VITE_TENANT_READS_ENABLED}" != "true" ] || ' +
    '[ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || ' +
    '[ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }';
  assert.equal(dockerfile.split(dependency).length - 1, 2, "the full dependency chain must appear in both stages");
  const dependencyLines = dockerfile.split("\n").filter((line) => line.includes("VITE_COMMERCE_ACTIONS_ENABLED=true requires"));
  assert.equal(dependencyLines.length, 2, "the dependency message must appear once per stage");
  for (const line of dependencyLines) {
    for (const required of [
      "VITE_COMMERCE_SESSIONS_ENABLED=true",
      "VITE_TENANT_READS_ENABLED=true",
      "VITE_ACCOUNT_ACCESS_ENABLED=true",
      "VITE_API_BOUNDARY_ENABLED=true",
    ]) {
      assert.ok(line.includes(required), `the action dependency message must name ${required}`);
    }
  }
  // The accepted session dependency is not widened by this packet.
  assert.equal(
    dockerfile.split('if [ "${VITE_COMMERCE_SESSIONS_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }').length - 1,
    2,
    "the session dependency must stay exactly as accepted",
  );
});

test("Dockerfile copies the action files and installs capability/deny unconditionally, business conditionally", () => {
  for (const file of [
    "apps/web/nginx-action-capability.conf",
    "apps/web/nginx-action-locations.conf",
    "apps/web/nginx-action-deny.conf",
  ]) {
    assert.equal(dockerfile.split(file).length - 1, 1, `Dockerfile must copy ${file} exactly once`);
  }
  assert.match(dockerfile, /cp \/tmp\/openarc-nginx\/nginx-action-capability\.conf \/etc\/nginx\/templates\/openarc-action-capability-locations\.inc\.template;/u);
  assert.match(dockerfile, /cp \/tmp\/openarc-nginx\/nginx-action-deny\.conf \/etc\/nginx\/templates\/openarc-action-deny\.inc\.template;/u);
  assert.match(dockerfile, /cp \/tmp\/openarc-nginx\/nginx-action-locations\.conf \/etc\/nginx\/templates\/openarc-commerce-action-locations\.inc\.template;/u);
  assert.match(dockerfile, /:\s*>\s*\/etc\/nginx\/templates\/openarc-commerce-action-locations\.inc\.template;/u, "the omitted business include must be written empty");
  const capabilityCp = dockerfile.indexOf("cp /tmp/openarc-nginx/nginx-action-capability.conf /etc/nginx/templates/openarc-action-capability-locations.inc.template");
  const denyCp = dockerfile.indexOf("cp /tmp/openarc-nginx/nginx-action-deny.conf /etc/nginx/templates/openarc-action-deny.inc.template");
  const branch = dockerfile.indexOf('if [ "${VITE_COMMERCE_ACTIONS_ENABLED}" = "true" ]; then');
  assert.ok(capabilityCp !== -1 && denyCp !== -1 && branch !== -1, "the action install lines must exist");
  assert.ok(capabilityCp < branch, "capability must be installed unconditionally before the actions branch");
  assert.ok(denyCp < branch, "deny must be installed unconditionally before the actions branch");
  // Capability and deny installation is gated only by the API boundary.
  const apiBranch = dockerfile.indexOf('if [ "${VITE_API_BOUNDARY_ENABLED}" = "true" ]; then');
  assert.ok(apiBranch !== -1 && apiBranch < capabilityCp, "capability/deny install must sit inside the API-boundary branch");
});

test("every action flag combination resolves to a byte-identical server template", () => {
  const start = dockerfile.indexOf('if [ "${VITE_COMMERCE_ACTIONS_ENABLED}" = "true" ]; then');
  const end = dockerfile.indexOf("cp /tmp/openarc-nginx/nginx-market-capability.conf");
  assert.ok(start !== -1 && end > start, "the actions install branch must exist before the market capability copy");
  const branch = dockerfile.slice(start, end);
  const branches = dockerfile.match(/if \[ "\$\{VITE_COMMERCE_ACTIONS_ENABLED\}" = "true" \]; then/gu) ?? [];
  assert.equal(branches.length, 1, "exactly one runtime install branch selects the action business include");
  // Both arms write the SAME runtime include path, so the server template never
  // varies across flag combinations: ON copies the twelve routes, OFF truncates.
  assert.equal(branch.split("openarc-commerce-action-locations.inc.template").length - 1, 2, "both arms must write the same runtime include path");
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
    assert.ok(!branch.includes(forbidden), `the action install must not depend on ${forbidden}`);
  }
  // The business include references exactly the three param files installed here.
  assert.match(businessSource, /include\s+\/etc\/nginx\/tenant_proxy_params;/u);
  assert.match(businessSource, /include\s+\/etc\/nginx\/tenant_write_proxy_params;/u);
  assert.match(businessSource, /include\s+\/etc\/nginx\/commerce_agent_proxy_params;/u);
});

test("the public source gate runs the action deployment guard alongside the existing guards", () => {
  const sourceChecks = read(FILES.sourceChecks);
  const guardLine = sourceChecks.split("\n").find((line) => line.includes("node --test scripts/account-deployment.test.mjs"));
  assert.ok(guardLine, "the source gate guard invocation must exist");
  assert.ok(guardLine.includes("scripts/action-deployment.test.mjs"), "the source gate must run the action deployment guard");
  for (const existing of [
    "scripts/control-deployment.test.mjs",
    "scripts/marketplace-deployment.test.mjs",
    "scripts/machine-deployment.test.mjs",
    "scripts/session-deployment.test.mjs",
    "scripts/capability-deployment.test.mjs",
    "scripts/api-namespace-deployment.test.mjs",
  ]) {
    assert.ok(guardLine.includes(existing), `the gate must keep running ${existing}`);
  }
  assert.match(sourceChecks, /source-gate:\s*\n\s*runs-on:\s*ubuntu-latest\s*\n\s*timeout-minutes:\s*40\b/u, "the source-gate job must keep the deliberate 40-minute timeout");
});

test("the accepted guards and denies are unchanged and never mention the action family", () => {
  for (const legacy of [
    "scripts/control-deployment.test.mjs",
    "scripts/marketplace-deployment.test.mjs",
    "scripts/machine-deployment.test.mjs",
    "scripts/tenant-deployment.test.mjs",
    "scripts/session-deployment.test.mjs",
  ]) {
    const source = read(legacy);
    assert.ok(!/commerce-action|commerce_action|action-capabilities/u.test(source), `${legacy} must stay unchanged by this packet`);
  }
  // The accepted session deny keeps its exact three prefixes and no broad agent deny.
  const sessionDeny = parseLocations(read(FILES.sessionDeny));
  assert.deepEqual(
    sessionDeny.map((entry) => entry.path).sort(),
    ["/v2/agent/commerce-session-mutations", "/v2/agent/commerce-sessions", "/v2/public/session-capabilities"],
    "the accepted session deny must not change",
  );
});

test("the action and session agent families use different credential namespaces", () => {
  // The commerce-SESSION agent routes are where a machine credential (oas_ag_)
  // is exchanged for a commerce session, so they correctly require oas_ag_.
  // The action agent routes consume that commerce session and therefore require
  // oacs_v1_. Copying the session family's bearer guard into the action family
  // would both reject every valid commerce-session token and let a read-only
  // machine credential reach a spending surface. Pin both directions.
  const sessionAgent = parseLocations(read("apps/web/nginx-commerce-session-locations.conf"))
    .filter((entry) => entry.path.includes("/v2/agent/"));
  assert.ok(sessionAgent.length > 0, "expected accepted session agent locations");
  for (const entry of sessionAgent) {
    assert.ok(
      /\^Bearer oas_ag_/u.test(entry.body),
      `${entry.raw} must keep the oas_ag_ machine-credential namespace`,
    );
    assert.ok(
      !/oacs_v1_/u.test(entry.body),
      `${entry.raw} must not accept a commerce-session token at the exchange surface`,
    );
  }

  const actionAgent = parseLocations(read(FILES.business))
    .filter((entry) => entry.path.includes("/v2/agent/"));
  assert.equal(actionAgent.length, 3, "expected exactly three action agent locations");
  for (const entry of actionAgent) {
    assert.ok(
      /\^Bearer oacs_v1_\[A-Za-z0-9_-\]\{43\}\$/u.test(entry.body),
      `${entry.raw} must require the exact oacs_v1_ commerce-session bearer`,
    );
    assert.ok(
      !/oas_ag_/u.test(entry.body),
      `${entry.raw} must reject the oas_ag_ machine-credential namespace`,
    );
  }
});
