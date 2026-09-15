import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

/**
 * Static deployment guards for the P03 commerce-session proxy.
 *
 * These assertions parse the real nginx directives (never comments) and the
 * real Dockerfile RUN/shell lines. They prove the exact seven-route
 * SESSION_ROUTES inventory and methods, the canonical typed org id plus
 * version-4 session/mutation ids, the query/body/header guards, the
 * encoded-URI-preserving no-URI proxy_pass, the human named POST dispatch with
 * the 16KiB combined-parent bound, the separate headless agent allowlist and
 * browser-credential rejection, the unconditional capability/deny installation,
 * the sessions-only Docker dependency, the independent tenant param install,
 * all-flag-combination include wiring, the no-API/OFF fail-closed behavior and
 * the unchanged legacy transport params. They do not run nginx and do not prove
 * actual nginx, TLS upstream or browser acceptance.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => readFileSync(path.join(root, relativePath), "utf8");

const FILES = {
  dockerfile: "apps/web/Dockerfile",
  apiConf: "apps/web/nginx-api.conf",
  arcConf: "apps/web/nginx-arc.conf",
  plainConf: "apps/web/nginx.conf",
  business: "apps/web/nginx-commerce-session-locations.conf",
  capability: "apps/web/nginx-session-capability.conf",
  deny: "apps/web/nginx-session-deny.conf",
  agentParams: "apps/web/commerce_agent_proxy_params",
  readParams: "apps/web/tenant_proxy_params",
  writeParams: "apps/web/tenant_write_proxy_params",
  responseHeaders: "apps/web/market_response_headers",
  workflow: ".github/workflows/source-checks.yml",
};

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
      body: stripped.slice(open + 1, close),
    });
    header.lastIndex = close + 1;
  }
  return locations;
}

const locations = parseLocations(businessSource);
const external = locations.filter((entry) => !entry.path.startsWith("@"));
const named = locations.filter((entry) => entry.path.startsWith("@"));
const externalProxying = external.filter((entry) => entry.body.includes("proxy_pass"));
const namedProxying = named.filter((entry) => entry.body.includes("proxy_pass"));
const allProxying = [...externalProxying, ...namedProxying];

// Canonical shared UUID grammar: identity nibble [1-8], new ids pin version 4.
const UUID_ID = "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const UUID_V4 = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const ORG = `openarc:org:${UUID_ID}`;
const CONTROL_BASE = "/v2/control/organizations";
const AGENT_BASE = "/v2/agent";

// Regex location paths carry a leading `^` anchor; strip it before comparing a
// declared location against a literal route prefix.
function pathText(entry) {
  return entry.path.replace(/^\^/u, "");
}

function regexFor(entry) {
  return new RegExp("^(?:" + entry.path.split('"').join("") + ")$", "u");
}

function findRoute(method, target) {
  return externalProxying.find((entry) => {
    if (entry.modifier === "=") return entry.path === target;
    return regexFor(entry).test(target);
  },
  );
}

function matchesMethod(entry, method) {
  if (entry.body.includes("$request_method = POST")) {
    return method === "GET" || method === "POST";
  }
  return method === (/\$request_method\s*!=\s*POST/u.test(entry.body) ? "POST" : "GET");
}

// The frozen seven SESSION_ROUTES from
// packages/shared/src/commerce/control-session-capabilities.ts (5 browser +
// 2 agent). Concrete version-4 ids produce the exact wire targets.
const org = "openarc:org:11111111-1111-4111-8111-111111111111";
const sessionId = "11111111-1111-4111-8111-111111111111";
const mutationId = "22222222-2222-4222-8222-222222222222";

const SESSION_ROUTES = Object.freeze([
  Object.freeze({ id: "commerce_session_list", method: "GET", path: `${CONTROL_BASE}/${org}/commerce-sessions`, target: `${CONTROL_BASE}/${org}/commerce-sessions` }),
  Object.freeze({ id: "commerce_session_issue", method: "POST", path: `${CONTROL_BASE}/:organizationId/commerce-sessions`, target: `${CONTROL_BASE}/${org}/commerce-sessions` }),
  Object.freeze({ id: "commerce_session_status", method: "GET", path: `${CONTROL_BASE}/:organizationId/commerce-sessions/:sessionId`, target: `${CONTROL_BASE}/${org}/commerce-sessions/${sessionId}` }),
  Object.freeze({ id: "commerce_session_revoke", method: "POST", path: `${CONTROL_BASE}/:organizationId/commerce-sessions/:sessionId/revoke`, target: `${CONTROL_BASE}/${org}/commerce-sessions/${sessionId}/revoke` }),
  Object.freeze({ id: "commerce_session_human_mutation_status", method: "GET", path: `${CONTROL_BASE}/:organizationId/commerce-session-mutations/:mutationId`, target: `${CONTROL_BASE}/${org}/commerce-session-mutations/${mutationId}` }),
  Object.freeze({ id: "commerce_session_exchange", method: "POST", path: `${AGENT_BASE}/commerce-sessions/exchange`, target: `${AGENT_BASE}/commerce-sessions/exchange` }),
  Object.freeze({ id: "commerce_session_agent_mutation_status", method: "GET", path: `${AGENT_BASE}/commerce-session-mutations/:mutationId`, target: `${AGENT_BASE}/commerce-session-mutations/${mutationId}` }),
]);

test("the frozen seven-route SESSION_ROUTES inventory is present with exact methods", () => {
  assert.equal(SESSION_ROUTES.length, 7, "the session registry is exactly seven routes");
  assert.equal(externalProxying.length, 6, "six externally addressable routes proxy (the collection parent carries GET+POST)");
  assert.equal(namedProxying.length, 1, "exactly one internal named POST dispatch target proxies");
  assert.equal(allProxying.length, 7, "the seven SESSION_ROUTES must proxy exactly once");
  for (const route of SESSION_ROUTES) {
    const entry = findRoute(route.method, route.target);
    assert.ok(entry, `missing declared route for ${route.method} ${route.target} (${route.id})`);
    assert.ok(matchesMethod(entry, route.method), `${route.id} must permit ${route.method}`);
  }
  assert.ok(named.some((entry) => entry.path === "@openarc_session_issue"), "the issue dispatch target must be a named location");
  assert.equal(businessSource.split("@openarc_session_issue").length - 1, 2, "the issue target must be declared once and referenced once");
  // No capability/manifest/health/grant or payment descriptor is proxied here.
  assert.ok(!/grant|payment|healthz|capabilit/iu.test(stripNginxComments(businessSource).replace(/#[^\n]*/gu, "")), "no unrelated endpoint may hide in the business include");
});

test("human ids are canonical typed org [1-8] UUIDs and version-4 session/mutation UUIDs", () => {
  const human = externalProxying.filter((entry) => pathText(entry).startsWith(CONTROL_BASE));
  assert.equal(human.length, 4, "four human path families proxy");
  for (const entry of human) {
    assert.ok(entry.raw.includes(ORG), `${entry.raw} must anchor a canonical typed organization id`);
  }
  // The collection parent has no id; only the id-bearing session routes pin v4.
  const sessionRoutes = human.filter((entry) => entry.path.includes("/commerce-sessions/"));
  assert.equal(sessionRoutes.length, 2, "the two id-bearing session routes (status + revoke) must exist");
  for (const entry of sessionRoutes) {
    assert.ok(entry.raw.includes(UUID_V4), `${entry.raw} must pin the session id to version 4`);
  }
  const mutationRoute = human.find((entry) => /commerce-session-mutations/u.test(entry.path));
  assert.ok(mutationRoute, "the human mutation route must exist");
  assert.ok(mutationRoute.raw.includes(UUID_V4), "the human mutation id must pin version 4");
  const agentMutation = externalProxying.find((entry) => /^\/v2\/agent\/commerce-session-mutations\//u.test(pathText(entry)));
  assert.ok(agentMutation, "the agent mutation route must exist");
  assert.ok(agentMutation.raw.includes(UUID_V4), "the agent mutation id must pin version 4");
  // Alias/version drift must not match: a version-1 session id is rejected.
  const statusEntry = human.find((entry) => entry.path.includes("/commerce-sessions/") && entry.modifier === "~" && !/revoke/u.test(entry.path));
  assert.ok(statusEntry, "the human status route must exist");
  assert.ok(!regexFor(statusEntry).test(`${CONTROL_BASE}/${org}/commerce-sessions/11111111-1111-1111-8111-111111111111`), "session id must reject a non-v4 UUID");
});

test("every proxying session route uses the host-only no-URI proxy_pass", () => {
  for (const entry of allProxying) {
    assert.match(entry.body, /proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\};/u, `${entry.raw} must proxy with no URI part`);
    assert.ok(!/proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\}\S+;/u.test(entry.body), `${entry.raw} must not append a URI component`);
  }
  assert.ok(!/rewrite\b/u.test(stripNginxComments(businessSource)), "must not rewrite the request target");
  for (const entry of allProxying) {
    assert.ok(!/proxy_pass\s+http:/u.test(entry.body), `${entry.raw} must use https only`);
    assert.ok(!/proxy_cache\b/u.test(entry.body), `${entry.raw} must not cache`);
  }
});

test("only the human list accepts a raw query; every other route rejects a literal ?", () => {
  const parent = externalProxying.find((entry) => entry.body.includes("$request_method = POST"));
  assert.ok(parent, "the combined human collection parent must exist");
  assert.ok(!/\$request_uri\s*~/u.test(parent.body), "the human list must keep its bounded read query");
  assert.ok(!/\$args\s*!=\s*""/u.test(parent.body), "the human list must not reject the read query");
  const queryRejecting = allProxying.filter((entry) => entry !== parent);
  assert.equal(queryRejecting.length, 6, "every other route including the named dispatch rejects a query");
  for (const entry of queryRejecting) {
    if (entry.modifier === "=") {
      assert.match(entry.body, /if\s*\(\$request_uri\s*!=\s*"\/v2\/agent\/commerce-sessions\/exchange"\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} exact route must reject any query`);
      continue;
    }
    assert.match(entry.body, /if\s*\(\$request_uri\s*~\s*"\\\?"\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject a literal ?`);
  }
  assert.ok(!/\$request_uri\s*(?:!=|=)\s*\$uri\b/u.test(stripNginxComments(businessSource)), "must never compare encoded $request_uri to decoded $uri");
});

test("wrong verbs including HEAD and OPTIONS are rejected with 405 on every session route", () => {
  for (const entry of externalProxying) {
    if (entry.body.includes("$request_method = POST")) {
      assert.match(entry.body, /if\s*\(\$request_method\s*=\s*POST\)\s*\{\s*return\s+418;\s*\}/u, `${entry.raw} must dispatch POST internally`);
      assert.match(entry.body, /if\s*\(\$request_method\s*!=\s*GET\)\s*\{\s*return\s+405;\s*\}/u, `${entry.raw} must pin GET on the parent`);
      continue;
    }
    const method = /\$request_method\s*!=\s*POST/u.test(entry.body) ? "POST" : "GET";
    assert.match(entry.body, new RegExp(`if\\s*\\(\\$request_method\\s*!=\\s*${method}\\)\\s*\\{\\s*return\\s+405;\\s*\\}`, "u"), `${entry.raw} must pin ${method}`);
  }
  for (const entry of namedProxying) {
    assert.match(entry.body, /if\s*\(\$request_method\s*!=\s*POST\)\s*\{\s*return\s+405;\s*\}/u);
  }
});

test("human reads are bodyless and human writes require JSON, CSRF, idempotency and a 16KiB bound", () => {
  const human = externalProxying.filter((entry) => pathText(entry).startsWith(CONTROL_BASE));
  const getters = human.filter((entry) => /\$request_method\s*!=\s*GET/u.test(entry.body));
  assert.equal(getters.length, 3, "three human GET locations");
  for (const entry of getters) {
    assert.match(entry.body, /if\s*\(\$http_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject bearer`);
    assert.match(entry.body, /if\s*\(\$http_proxy_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject proxy authorization`);
    assert.match(entry.body, /if\s*\(\$http_x_openarc_csrf\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject CSRF header`);
    assert.match(entry.body, /if\s*\(\$http_idempotency_key\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject idempotency header`);
    assert.match(entry.body, /if\s*\(\$openarc_session_body_ok\s*=\s*0\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must fail the body guard`);
  }
  const writers = [...namedProxying, ...human.filter((entry) => /\$request_method\s*!=\s*POST/u.test(entry.body))];
  assert.equal(writers.length, 2, "the two human POST routes");
  for (const entry of writers) {
    assert.match(entry.body, /if\s*\(\$http_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject bearer`);
    assert.match(entry.body, /if\s*\(\$http_proxy_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject proxy authorization`);
    assert.match(entry.body, /if\s*\(\$http_content_type\s*!~\s*"\^application\/json/u, `${entry.raw} must require JSON`);
    assert.match(entry.body, /if\s*\(\$http_transfer_encoding\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject transfer encoding`);
    assert.match(entry.body, /if\s*\(\$http_x_openarc_csrf\s*=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must require CSRF`);
    assert.match(entry.body, /if\s*\(\$http_idempotency_key\s*=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must require idempotency`);
    assert.match(entry.body, /client_max_body_size\s+16k;/u, `${entry.raw} must be 16KiB bounded`);
    assert.ok(!/client_max_body_size\s+0;/u.test(entry.body), `${entry.raw} must never be unlimited`);
  }
  // The combined parent admits the 16KiB POST before the named dispatch while
  // its GET body guard survives.
  const parent = human.find((entry) => entry.body.includes("$request_method = POST"));
  assert.match(parent.body, /client_max_body_size\s+16k;/u);
  assert.match(parent.body, /if\s*\(\$openarc_session_body_ok\s*=\s*0\)\s*\{\s*return\s+400;\s*\}/u);
});

test("no proxy directive or include is ever placed inside an if block", () => {
  for (const entry of locations) {
    const blocks = entry.body.match(/if\s*\([^)]*\)\s*\{[^}]*\}/gu) ?? [];
    for (const block of blocks) {
      assert.ok(!block.includes("proxy_pass"), "if block must not contain proxy_pass");
      assert.ok(!block.includes("proxy_set_header"), "if block must not contain proxy_set_header");
      assert.ok(!block.includes("include "), "if block must not contain include");
    }
  }
});

test("human transport reuses the unchanged tenant params plus response suppression", () => {
  const human = externalProxying.filter((entry) => pathText(entry).startsWith(CONTROL_BASE));
  const parent = human.find((entry) => entry.body.includes("$request_method = POST"));
  for (const entry of human) {
    if (entry.body.includes("$request_method = POST")) {
      assert.match(entry.body, /include\s+\/etc\/nginx\/tenant_proxy_params;/u, `${entry.raw} must reuse the read params`);
    } else if (/\$request_method\s*!=\s*GET/u.test(entry.body)) {
      assert.match(entry.body, /include\s+\/etc\/nginx\/tenant_proxy_params;/u, `${entry.raw} must reuse the read params`);
    } else {
      assert.match(entry.body, /include\s+\/etc\/nginx\/tenant_write_proxy_params;/u, `${entry.raw} must reuse the write params`);
    }
    assert.match(entry.body, /include\s+\/etc\/nginx\/market_response_headers;/u, `${entry.raw} must suppress Set-Cookie/CORS`);
  }
  assert.match(namedProxying[0].body, /include\s+\/etc\/nginx\/tenant_write_proxy_params;/u);
  // The reused param files gain no session edit.
  assert.match(readParams, /proxy_pass_request_body\s+off;/u);
  assert.match(readParams, /proxy_ssl_verify\s+on;/u);
  assert.match(readParams, /proxy_next_upstream\s+off;/u);
  assert.match(writeParams, /proxy_pass_request_body\s+on;/u);
  assert.ok(!readParams.includes("openarc_session"), "the read params must stay unchanged");
  assert.ok(!writeParams.includes("openarc_session"), "the write params must stay unchanged");
  for (const header of ["Set-Cookie", "Access-Control-Allow-Origin", "Vary"]) {
    assert.match(responseHeaders, new RegExp(`proxy_hide_header\\s+${header};`, "u"));
  }
  assert.ok(parent, "the combined human parent must exist");
});

test("agent routes forward only the headless allowlist and reject every browser credential", () => {
  const exchange = externalProxying.find((entry) => entry.modifier === "=" && entry.path === `${AGENT_BASE}/commerce-sessions/exchange`);
  const agentMutation = externalProxying.find((entry) => /^\/v2\/agent\/commerce-session-mutations\//u.test(pathText(entry)));
  assert.ok(exchange, "the agent exchange route must be an exact location");
  assert.ok(agentMutation, "the agent mutation route must exist");
  assert.match(exchange.body, /if\s*\(\$request_method\s*!=\s*POST\)\s*\{\s*return\s+405;\s*\}/u);
  assert.match(agentMutation.body, /if\s*\(\$request_method\s*!=\s*GET\)\s*\{\s*return\s+405;\s*\}/u);
  for (const entry of [exchange, agentMutation]) {
    for (const header of ["$http_cookie", "$http_origin", "$http_sec_fetch_site", "$http_sec_fetch_mode", "$http_sec_fetch_dest", "$http_sec_fetch_user", "$http_x_openarc_client", "$http_x_openarc_csrf", "$http_proxy_authorization", "$http_x_openarc_proxy_secret"]) {
      const escaped = header.replace("$", "\\$");
      assert.match(entry.body, new RegExp(`if\\s*\\(${escaped}\\s*!=\\s*""\\)\\s*\\{\\s*return\\s+403;\\s*\\}`, "u"), `${entry.raw} must reject ${header}`);
    }
    assert.match(entry.body, /if\s*\(\$http_authorization\s*!~\s*"\^Bearer oas_ag_\[A-Za-z0-9_-\]\+\$"\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must require the exact oas_ag_ bearer namespace`);
    assert.match(entry.body, /include\s+\/etc\/nginx\/commerce_agent_proxy_params;/u, `${entry.raw} must use the agent params`);
    assert.match(entry.body, /include\s+\/etc\/nginx\/market_response_headers;/u, `${entry.raw} must suppress Set-Cookie/CORS`);
  }
  // POST exchange alone carries the bounded JSON body and idempotency key.
  assert.match(exchange.body, /if\s*\(\$http_content_type\s*!~\s*"\^application\/json/u);
  assert.match(exchange.body, /if\s*\(\$http_idempotency_key\s*=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
  assert.match(exchange.body, /client_max_body_size\s+16k;/u);
  assert.match(exchange.body, /proxy_set_header\s+Content-Type\s+\$http_content_type;/u);
  assert.match(exchange.body, /proxy_set_header\s+Content-Length\s+\$http_content_length;/u);
  assert.match(exchange.body, /proxy_set_header\s+Idempotency-Key\s+\$http_idempotency_key;/u);
  // GET status is bearer-only: no query, body, idempotency or content type.
  assert.match(agentMutation.body, /if\s*\(\$http_content_type\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
  assert.match(agentMutation.body, /if\s*\(\$http_content_length\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
  assert.match(agentMutation.body, /if\s*\(\$http_idempotency_key\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
  assert.match(agentMutation.body, /client_max_body_size\s+1k;/u);
  assert.ok(!/proxy_set_header\s+Idempotency-Key/u.test(agentMutation.body), "the GET status must not forward an idempotency key");
  // The agent params never forward user-controlled forward/real-IP/proxy identity.
  assert.match(agentParams, /proxy_pass_request_headers\s+off;/u);
  const forwarded = agentParams.match(/proxy_set_header\s+([^\s]+)\s+(\S+)/gu) ?? [];
  const allowed = new Set([
    "Connection",
    "Host",
    "Authorization",
    "Accept",
  ]);
  for (const directive of forwarded) {
    const name = directive.replace(/proxy_set_header\s+/u, "").split(/\s+/u)[0];
    assert.ok(allowed.has(name), `agent params must not forward unexpected header ${name}`);
  }
  for (const forbidden of ["X-Forwarded-For", "X-Real-IP", "X-OpenArc-Proxy-Secret", "X-OpenArc-Proxy-Client-IP", "Forwarded", "X-Forwarded-Proto", "X-Forwarded-Host"]) {
    assert.ok(!new RegExp(`proxy_set_header\\s+${forbidden}\\s+\\$http_`, "u").test(agentParams), `agent params must not forward ${forbidden}`);
  }
  assert.ok(!/SOURCE_PROXY_SECRET/u.test(agentParams), "the agent surface must not reuse the legacy proxy secret");
});

test("agent transport enforces verified TLS, retries off and no disk spooling", () => {
  assert.match(agentParams, /proxy_ssl_server_name\s+on;/u);
  assert.match(agentParams, /proxy_ssl_verify\s+on;/u);
  assert.match(agentParams, /proxy_ssl_verify_depth\s+3;/u);
  assert.ok(!/proxy_ssl_verify\s+off;/u.test(agentParams));
  assert.match(agentParams, /proxy_next_upstream\s+off;/u);
  assert.match(agentParams, /proxy_(connect|send|read)_timeout\s+[1-9]\d*s;/u);
  assert.match(agentParams, /proxy_request_buffering\s+off;/u);
  assert.match(agentParams, /proxy_buffering\s+off;/u);
  assert.match(agentParams, /proxy_max_temp_file_size\s+0;/u);
  assert.ok(!/proxy_cache\b|proxy_store\b|proxy_cache_path\b/u.test(agentParams), "the agent params must not cache or store");
  assert.ok(!/proxy_set_header\s+Cookie\s+\$http_cookie/u.test(agentParams), "the agent params must never forward a browser cookie");
});

test("agent request body forwarding is explicit per route and absent from the shared params", () => {
  const exchange = externalProxying.find((entry) => entry.modifier === "=" && entry.path === `${AGENT_BASE}/commerce-sessions/exchange`);
  const agentMutation = externalProxying.find((entry) => /^\/v2\/agent\/commerce-session-mutations\//u.test(pathText(entry)));
  assert.ok(exchange, "the agent exchange route must be an exact location");
  assert.ok(agentMutation, "the agent mutation route must exist");
  // The bounded POST body must be forwarded explicitly in the location, and the
  // GET status must disable body forwarding explicitly; neither decision lives
  // in the shared params include.
  assert.match(exchange.body, /proxy_pass_request_body\s+on;/u, "the POST exchange must explicitly forward its bounded body");
  assert.match(agentMutation.body, /proxy_pass_request_body\s+off;/u, "the GET status must explicitly disable body forwarding");
  assert.ok(!/proxy_pass_request_body\s+off;/u.test(exchange.body), "the POST exchange must never discard its bounded body");
  assert.ok(!/proxy_pass_request_body\s+on;/u.test(agentMutation.body), "the GET status must never forward a body");
  assert.ok(!/proxy_pass_request_body/u.test(agentParams), "the agent params must not set request body forwarding globally");
});

test("the session-capability route is an exact credentialless GET with a fixed upstream path", () => {
  const capabilityLocations = parseLocations(capabilitySource);
  assert.equal(capabilityLocations.length, 1, "the capability file must declare exactly one location");
  const entry = capabilityLocations[0];
  assert.equal(entry.modifier, "=", "the capability route must be an exact match");
  assert.equal(entry.path, "/v2/public/session-capabilities");
  assert.match(entry.body, /if\s*\(\$request_method\s*!=\s*GET\)\s*\{\s*return\s+405;\s*\}/u);
  assert.match(entry.body, /if\s*\(\$request_uri\s*!=\s*"\/v2\/public\/session-capabilities"\)\s*\{\s*return\s+400;\s*\}/u);
  for (const header of ["$http_cookie", "$http_authorization", "$http_proxy_authorization", "$http_x_openarc_csrf", "$http_idempotency_key", "$http_x_openarc_proxy_secret"]) {
    const escaped = header.replace("$", "\\$");
    assert.match(entry.body, new RegExp(`if\\s*\\(${escaped}\\s*!=\\s*""\\)\\s*\\{\\s*return\\s+403;\\s*\\}`, "u"), `the capability route must reject ${header}`);
  }
  assert.match(entry.body, /proxy_pass_request_headers\s+off;/u);
  assert.match(entry.body, /proxy_ssl_verify\s+on;/u);
  assert.match(entry.body, /proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\}\/v2\/public\/session-capabilities;/u);
  assert.ok(!/try_files|index\.html/u.test(entry.body), "the capability route must never serve SPA HTML");
});

test("the deny include covers malformed session paths with plain prefixes and no broad agent deny", () => {
  const denyLocations = parseLocations(denySource);
  for (const required of ["/v2/public/session-capabilities", "/v2/agent/commerce-sessions", "/v2/agent/commerce-session-mutations"]) {
    const entry = denyLocations.find((candidate) => candidate.path === required);
    assert.ok(entry, `${required} must be a plain deny prefix`);
    assert.equal(entry.modifier, "", `${required} must not use ^~ or =`);
    assert.match(entry.body, /return\s+404;/u);
    assert.ok(!/proxy_pass|try_files/u.test(entry.body), `${required} deny must not proxy or serve SPA`);
  }
  for (const lookalike of ["/v2/public/session-capabilitiesXYZ", "/v2/agent/commerce-sessionsXYZ", "/v2/agent/commerce-session-mutationsXYZ"]) {
    assert.ok(denyLocations.some((entry) => entry.modifier === "" && lookalike.startsWith(entry.path)), `${lookalike} must be covered by a plain prefix`);
  }
  assert.equal(denyLocations.filter((entry) => entry.path === "/v2/agent").length, 0, "no broad /v2/agent deny may shadow unrelated legacy agents");
  assert.ok(!denyLocations.some((entry) => entry.modifier === "^~"), "deny fallbacks must not use ^~ (would suppress enabled regexes)");
  assert.ok(!denySource.includes("API_UPSTREAM_HOST"), "the deny file must not reference the upstream");
  // Enabled routes must still win over the deny prefixes.
  const exchange = externalProxying.find((entry) => entry.modifier === "=" && entry.path === `${AGENT_BASE}/commerce-sessions/exchange`);
  assert.ok(exchange, "the exact exchange route must beat the /v2/agent/commerce-sessions prefix");
  assert.ok(externalProxying.some((entry) => entry.modifier === "~" && pathText(entry).startsWith("/v2/agent/commerce-session-mutations/")), "the anchored agent mutation regex must beat the prefix");
});

test("both API templates install capability, business and deny includes exactly once", () => {
  for (const template of [FILES.apiConf, FILES.arcConf]) {
    const source = read(template);
    for (const include of [
      "openarc-session-capability-locations.inc",
      "openarc-commerce-session-locations.inc",
      "openarc-session-deny.inc",
    ]) {
      assert.equal(source.split(include).length - 1, 1, `${template} must include ${include} exactly once`);
    }
  }
  // The capability file is independent of the business file: neither embeds the
  // other, and the capability route is never declared in the business include.
  assert.ok(!businessSource.includes("/v2/public/session-capabilities"), "the business include must not own the capability route");
  assert.ok(!capabilitySource.includes("/commerce-sessions"), "the capability file must not own a business route");
});

test("the plain no-API template denies every session path without SPA fallback", () => {
  const plain = stripNginxComments(read(FILES.plainConf));
  assert.ok(!plain.includes("API_UPSTREAM_HOST"), "plain template must stay API boundary OFF");
  const plainLocations = parseLocations(read(FILES.plainConf));
  for (const required of ["/v2/public/session-capabilities", "/v2/agent/commerce-sessions", "/v2/agent/commerce-session-mutations"]) {
    const entry = plainLocations.find((candidate) => candidate.path === required);
    assert.ok(entry, `${required} must be denied in the no-API template`);
    assert.equal(entry.modifier, "", `${required} must be a plain prefix`);
    assert.match(entry.body, /return\s+404;/u);
    assert.ok(!/try_files|proxy_pass/u.test(entry.body), `${required} must not fall through to SPA or proxy`);
  }
  assert.ok(!plain.includes("openarc-commerce-session-locations"), "the no-API template must never include the proxying business file");
});

test("Dockerfile defaults the session flag off in both stages and requires only account access + API boundary", () => {
  const argOccurrences = dockerfile.match(/ARG\s+VITE_COMMERCE_SESSIONS_ENABLED=false/gu) ?? [];
  assert.equal(argOccurrences.length, 2, "the flag must default to false in both stages");
  const caseOccurrences = dockerfile.match(/case\s+"\$\{VITE_COMMERCE_SESSIONS_ENABLED\}"\s+in\s+true\|false\)/gu) ?? [];
  assert.equal(caseOccurrences.length, 2, "the flag must be validated true|false in both stages");
  const dependency = 'if [ "${VITE_COMMERCE_SESSIONS_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }';
  assert.equal(dockerfile.split(dependency).length - 1, 2, "the account+API dependency must appear in both stages");
  assert.match(dockerfile, /VITE_COMMERCE_SESSIONS_ENABLED=true requires VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true/u);
  const dependencyLines = dockerfile.split("\n").filter((line) => line.includes("VITE_COMMERCE_SESSIONS_ENABLED=true requires"));
  assert.equal(dependencyLines.length, 2, "the dependency message must appear once per stage");
  for (const line of dependencyLines) {
    for (const forbidden of ["TENANT_READS", "TENANT_WRITES", "MACHINE_", "MARKET_", "MODERATION", "ARC_OBSERVATION", "AGENT_REGISTRY", "POLICY_MANAGEMENT"]) {
      assert.ok(!line.includes(forbidden), `the session dependency must not require ${forbidden}`);
    }
  }
});

test("Dockerfile copies the session files and installs capability/deny unconditionally and business conditionally", () => {
  for (const file of [
    "apps/web/nginx-commerce-session-locations.conf",
    "apps/web/nginx-session-capability.conf",
    "apps/web/nginx-session-deny.conf",
    "apps/web/commerce_agent_proxy_params",
  ]) {
    assert.ok(dockerfile.includes(file), `Dockerfile must copy ${file}`);
  }
  assert.match(dockerfile, /cp \/tmp\/openarc-nginx\/nginx-session-capability\.conf \/etc\/nginx\/templates\/openarc-session-capability-locations\.inc\.template;/u);
  assert.match(dockerfile, /cp \/tmp\/openarc-nginx\/nginx-session-deny\.conf \/etc\/nginx\/templates\/openarc-session-deny\.inc\.template;/u);
  assert.match(dockerfile, /cp \/tmp\/openarc-nginx\/nginx-commerce-session-locations\.conf \/etc\/nginx\/templates\/openarc-commerce-session-locations\.inc\.template;/u);
  assert.match(dockerfile, /:\s*>\s*\/etc\/nginx\/templates\/openarc-commerce-session-locations\.inc\.template;/u, "the omitted business include must be written empty");
  // Capability and deny are installed unconditionally before the business
  // branch; the business include is copied only under the enabled branch.
  const capabilityCp = dockerfile.indexOf("cp /tmp/openarc-nginx/nginx-session-capability.conf /etc/nginx/templates/openarc-session-capability-locations.inc.template");
  const denyCp = dockerfile.indexOf("cp /tmp/openarc-nginx/nginx-session-deny.conf /etc/nginx/templates/openarc-session-deny.inc.template");
  const branch = dockerfile.indexOf('if [ "${VITE_COMMERCE_SESSIONS_ENABLED}" = "true" ]; then');
  assert.ok(capabilityCp !== -1 && denyCp !== -1 && branch !== -1, "the session install lines must exist");
  assert.ok(capabilityCp < branch, "capability must be installed unconditionally before the sessions branch");
  assert.ok(denyCp < branch, "deny must be installed unconditionally before the sessions branch");
});

test("sessions-only mode installs both tenant params and the agent params independently of every other flag", () => {
  const start = dockerfile.indexOf('if [ "${VITE_COMMERCE_SESSIONS_ENABLED}" = "true" ]; then');
  const end = dockerfile.indexOf("cp /tmp/openarc-nginx/nginx-market-capability.conf");
  assert.ok(start !== -1 && end > start, "the sessions install branch must exist before the market capability copy");
  const branch = dockerfile.slice(start, end);
  assert.match(branch, /cp \/tmp\/openarc-nginx\/tenant_proxy_params \/etc\/nginx\/tenant_proxy_params;/u);
  assert.match(branch, /cp \/tmp\/openarc-nginx\/tenant_write_proxy_params \/etc\/nginx\/tenant_write_proxy_params;/u);
  assert.match(branch, /cp \/tmp\/openarc-nginx\/commerce_agent_proxy_params \/etc\/nginx\/commerce_agent_proxy_params;/u);
  assert.ok(branch.includes("VITE_COMMERCE_SESSIONS_ENABLED"), "the install must be gated by the session flag alone");
  for (const forbidden of ["VITE_TENANT_READS_ENABLED", "VITE_TENANT_WRITES_ENABLED", "VITE_POLICY_MANAGEMENT_ENABLED", "VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED", "VITE_MARKET_CATALOG_ENABLED", "VITE_MARKET_MODERATION_ENABLED", "VITE_LISTING_MANAGEMENT_ENABLED"]) {
    assert.ok(!branch.includes(forbidden), `the session install must not depend on ${forbidden}`);
  }
  // The human routes reference the installed tenant params; the agent routes
  // reference the installed agent params.
  assert.match(businessSource, /include\s+\/etc\/nginx\/tenant_proxy_params;/u);
  assert.match(businessSource, /include\s+\/etc\/nginx\/tenant_write_proxy_params;/u);
  assert.match(businessSource, /include\s+\/etc\/nginx\/commerce_agent_proxy_params;/u);
});

test("the source gate keeps its deliberate 40-minute timeout and runs the new guard", () => {
  const workflow = read(FILES.workflow);
  assert.match(workflow, /source-gate:\s*\n\s*runs-on:\s*ubuntu-latest\s*\n\s*timeout-minutes:\s*40\b/u, "the source-gate job must keep the deliberate 40-minute timeout");
  assert.ok(!/timeout-minutes:\s*25\b/u.test(workflow), "the old 25-minute timeout must not return");
  const guardLine = workflow.split("\n").find((line) => line.includes("node --test scripts/account-deployment.test.mjs"));
  assert.ok(guardLine, "the guard invocation must exist");
  assert.ok(guardLine.includes("scripts/session-deployment.test.mjs"), "the gate must run the session deployment guard");
  for (const existing of ["scripts/control-deployment.test.mjs", "scripts/marketplace-deployment.test.mjs", "scripts/machine-deployment.test.mjs"]) {
    assert.ok(guardLine.includes(existing), `the gate must keep running ${existing}`);
  }
});

test("the frozen legacy guards are unchanged and never mention the session family", () => {
  for (const legacy of [
    "scripts/control-deployment.test.mjs",
    "scripts/marketplace-deployment.test.mjs",
    "scripts/machine-deployment.test.mjs",
    "scripts/tenant-deployment.test.mjs",
  ]) {
    const source = read(legacy);
    assert.ok(!/commerce-session|commerce_session|session-capabilities/u.test(source), `${legacy} must stay unchanged by this packet`);
  }
  // The legacy control deny still owns /v2/control and never broadens.
  assert.match(read("apps/web/nginx-control-deny.conf"), /location \/v2\/control \{ return 404; \}/u);
});
