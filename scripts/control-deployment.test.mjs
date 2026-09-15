import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

/**
 * Static deployment guards for the P03 policy-management proxy.
 *
 * These assertions read the real nginx directives (never comments) and the real
 * Dockerfile RUN/shell lines. They prove the exact 10-route/8-path control
 * inventory and methods, the canonical typed org/policy ids, version-4 mutation
 * ids, the bounded canonical revision, the query/body/header guards, the
 * encoded-URI-preserving no-URI proxy_pass, named POST dispatch plus the 16KiB
 * combined-parent body bound, the unconditional capability and deny includes,
 * the policy-only Docker dependency (independent of the old tenant and market
 * flags), all-off/no-API fail-closed behavior and the reused transport params.
 * They do not run nginx and do not prove actual nginx or browser acceptance.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => readFileSync(path.join(root, relativePath), "utf8");

const FILES = {
  dockerfile: "apps/web/Dockerfile",
  apiConf: "apps/web/nginx-api.conf",
  arcConf: "apps/web/nginx-arc.conf",
  plainConf: "apps/web/nginx.conf",
  policy: "apps/web/nginx-policy-management-locations.conf",
  capability: "apps/web/nginx-control-capability.conf",
  deny: "apps/web/nginx-control-deny.conf",
  readParams: "apps/web/tenant_proxy_params",
  writeParams: "apps/web/tenant_write_proxy_params",
  responseHeaders: "apps/web/market_response_headers",
};

const policySource = read(FILES.policy);
const capabilitySource = read(FILES.capability);
const denySource = read(FILES.deny);
const dockerfile = read(FILES.dockerfile);
const readParams = read(FILES.readParams);
const writeParams = read(FILES.writeParams);

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

const policyLocations = parseLocations(policySource);
const external = policyLocations.filter((entry) => !entry.path.startsWith("@"));
const named = policyLocations.filter((entry) => entry.path.startsWith("@"));
const externalProxying = external.filter((entry) => entry.body.includes("proxy_pass"));
const namedProxying = named.filter((entry) => entry.body.includes("proxy_pass"));
const allProxying = [...externalProxying, ...namedProxying];

const UUID_ID =
  "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const UUID_MUTATION =
  "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const ORG = `openarc:org:${UUID_ID}`;
const POLICY = `openarc:policy:${UUID_ID}`;
const REVISION = "[1-9][0-9]{0,8}";

function locationEndingSuffix(suffix) {
  return externalProxying.filter((entry) => entry.raw.includes(suffix));
}

test("the frozen control inventory declares exactly the ten routes over eight paths", () => {
  // Eight externally addressable proxying locations + two internal named POST
  // dispatch targets = the ten frozen CONTROL_ROUTES (5 GET + 5 POST).
  assert.equal(externalProxying.length, 8, "eight externally addressable control routes must proxy");
  assert.equal(namedProxying.length, 2, "two internal named POST dispatch targets must proxy");
  assert.equal(allProxying.length, 10, "the ten frozen control routes must proxy exactly once");

  const expected = [
    ["policies collection", "/policies$"],
    ["policy root", `/policies/${POLICY}$`],
    ["revision collection", `/policies/${POLICY}/revisions$`],
    ["revision", `/policies/${POLICY}/revisions/${REVISION}$`],
    ["pause", `/policies/${POLICY}/pause$`],
    ["resume", `/policies/${POLICY}/resume$`],
    ["revoke", `/policies/${POLICY}/revoke$`],
    ["mutation status", `/policy-mutations/${UUID_MUTATION}$`],
  ];
  for (const [label, fragment] of expected) {
    assert.ok(
      externalProxying.some((entry) => entry.raw.includes(fragment)),
      `the ${label} route must exist`,
    );
  }
  for (const name of ["@openarc_policy_policies", "@openarc_policy_revisions"]) {
    assert.ok(named.some((entry) => entry.raw === name), `${name} must be a named location`);
    assert.equal(policySource.split(name).length - 1, 2, `${name} must be declared once and referenced once`);
  }
});

test("wrong methods on every route are rejected with 405 (including HEAD and OPTIONS)", () => {
  for (const entry of externalProxying) {
    if (entry.body.includes("$request_method = POST")) {
      // Combined GET/POST collection parent.
      assert.match(entry.body, /if\s*\(\$request_method\s*=\s*POST\)\s*\{\s*return\s+418;\s*\}/u);
      assert.match(entry.body, /if\s*\(\$request_method\s*!=\s*GET\)\s*\{\s*return\s+405;\s*\}/u);
      continue;
    }
    const method = /\$request_method\s*!=\s*POST/u.test(entry.body) ? "POST" : "GET";
    assert.match(
      entry.body,
      new RegExp(`if\\s*\\(\\$request_method\\s*!=\\s*${method}\\)\\s*\\{\\s*return\\s+405;\\s*\\}`, "u"),
      `${entry.raw} must pin ${method}`,
    );
  }
  for (const entry of namedProxying) {
    assert.match(entry.body, /if\s*\(\$request_method\s*!=\s*POST\)\s*\{\s*return\s+405;\s*\}/u);
  }
});

test("typed org/policy ids, version-4 mutation ids and the canonical revision are exact", () => {
  for (const entry of externalProxying) {
    assert.ok(entry.raw.includes(ORG), `${entry.raw} must anchor a canonical organization id`);
  }
  for (const entry of locationEndingSuffix(POLICY)) {
    assert.ok(entry.raw.includes(POLICY), `${entry.raw} must anchor a canonical policy id`);
  }
  for (const entry of locationEndingSuffix("policy-mutations/")) {
    assert.ok(entry.raw.includes(UUID_MUTATION), `${entry.raw} must pin a version-4 mutation id`);
  }
  const revisionRoute = externalProxying.find((entry) => entry.raw.includes(`/revisions/${REVISION}$`));
  assert.ok(revisionRoute, "the revision route must accept the canonical 1..999999999 decimal");
  assert.ok(!/\[0-9\]\{9,10\}/u.test(revisionRoute.raw), "the revision must stay bounded to nine digits");
});

test("regex and named proxy_pass carry no URI component so encoded ids and query survive", () => {
  for (const entry of allProxying) {
    assert.match(entry.body, /proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\};/u, `${entry.raw} must proxy with no URI part`);
    assert.ok(
      !/proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\}\S+;/u.test(entry.body),
      `${entry.raw} must not append a URI component`,
    );
  }
  assert.ok(!/rewrite\b/u.test(stripNginxComments(policySource)), "must not rewrite the request target");
});

test("only the root-list and history reads accept a raw query; every other route rejects a literal ?", () => {
  const queryPermitting = externalProxying.filter(
    (entry) => entry.raw.includes("/policies$") || entry.raw.includes("/revisions$"),
  );
  assert.equal(queryPermitting.length, 2, "exactly the two collection reads may carry raw query");
  for (const entry of queryPermitting) {
    assert.ok(!/\$request_uri\s*~/u.test(entry.body), `${entry.raw} must keep the bounded read query`);
    assert.ok(!/\$args\s*!=\s*""/u.test(entry.body), `${entry.raw} must not reject the read query`);
  }
  const queryRejecting = allProxying.filter(
    (entry) => !(entry.raw.includes("/policies$") || entry.raw.includes("/revisions$")),
  );
  assert.equal(queryRejecting.length, 8, "every other route, including both named dispatch targets, must reject a query");
  for (const entry of queryRejecting) {
    assert.match(entry.body, /if\s*\(\$request_uri\s*~\s*"\\\?"\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject a literal ?`);
  }
  // Reject literal `?` via request_uri; never compare the encoded request_uri
  // to the decoded uri.
  assert.ok(!/\$request_uri\s*(?:!=|=)\s*\$uri\b/u.test(stripNginxComments(policySource)));
});

test("GET routes reject all bodies, transfer encoding, bearer, CSRF and idempotency headers", () => {
  const getters = externalProxying.filter(
    (entry) =>
      /\$request_method\s*!=\s*GET/u.test(entry.body) ||
      entry.body.includes("$request_method = POST"),
  );
  assert.ok(getters.length >= 5, "the five GET routes must be present");
  for (const entry of getters) {
    assert.match(entry.body, /if\s*\(\$http_content_length\s*!=\s*""\)\s*\{\s*set\s+\$openarc_policy_body_ok\s+0;\s*\}/u, `${entry.raw} must reject a declared body`);
    assert.match(entry.body, /if\s*\(\$http_transfer_encoding\s*!=\s*""\)\s*\{\s*set\s+\$openarc_policy_body_ok\s+0;\s*\}/u, `${entry.raw} must reject transfer encoding`);
    assert.match(entry.body, /if\s*\(\$openarc_policy_body_ok\s*=\s*0\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must fail the body guard`);
    assert.match(entry.body, /if\s*\(\$http_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject bearer auth`);
    assert.match(entry.body, /if\s*\(\$http_x_openarc_csrf\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject a GET CSRF header`);
    assert.match(entry.body, /if\s*\(\$http_idempotency_key\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject a GET idempotency header`);
  }
});

test("POST routes require JSON, CSRF and idempotency, reject bearer/transfer encoding and are 16KiB bounded", () => {
  const writers = [
    ...namedProxying,
    ...externalProxying.filter(
      (entry) =>
        entry.raw.includes("/pause$") || entry.raw.includes("/resume$") || entry.raw.includes("/revoke$"),
    ),
  ];
  assert.equal(writers.length, 5, "the five POST routes must be present");
  for (const entry of writers) {
    assert.match(entry.body, /if\s*\(\$http_authorization\s*!=\s*""\)\s*\{\s*return\s+403;\s*\}/u, `${entry.raw} must reject bearer auth`);
    assert.match(entry.body, /if\s*\(\$http_content_type\s*!~\s*"\^application\/json/u, `${entry.raw} must require JSON`);
    assert.match(entry.body, /if\s*\(\$http_transfer_encoding\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must reject transfer encoding`);
    assert.match(entry.body, /if\s*\(\$http_x_openarc_csrf\s*=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must require CSRF`);
    assert.match(entry.body, /if\s*\(\$http_idempotency_key\s*=\s*""\)\s*\{\s*return\s+400;\s*\}/u, `${entry.raw} must require idempotency`);
    assert.match(entry.body, /client_max_body_size\s+16k;/u, `${entry.raw} must be 16KiB bounded`);
    assert.ok(!/client_max_body_size\s+0;/u.test(entry.body), `${entry.raw} must never be unlimited`);
  }
});

test("combined GET/POST collections dispatch POST internally and bound the parent at 16KiB before dispatch", () => {
  const parents = externalProxying.filter((entry) => entry.body.includes("$request_method = POST"));
  assert.equal(parents.length, 2, "exactly two combined GET/POST collection parents");
  for (const entry of parents) {
    assert.match(entry.body, /error_page\s+418\s*=\s*@openarc_policy_\w+;/u, `${entry.raw} must dispatch to a named target`);
    assert.match(entry.body, /client_max_body_size\s+16k;/u, `${entry.raw} parent must admit the 16KiB POST before dispatch`);
    assert.ok(!/client_max_body_size\s+1k;/u.test(entry.body), `${entry.raw} must not keep the 1k read bound`);
    const target = entry.body.match(/error_page\s+418\s*=\s*(@[A-Za-z0-9_]+);/u);
    assert.ok(target, `${entry.raw} must name its dispatch target`);
    const dispatch = named.find((candidate) => candidate.path === target[1]);
    assert.ok(dispatch, `${target[1]} must exist`);
    assert.match(dispatch.body, /client_max_body_size\s+16k;/u, `${target[1]} must keep its 16KiB named bound`);
    // The GET body guard must survive the larger transport bound.
    assert.match(entry.body, /if\s*\(\$openarc_policy_body_ok\s*=\s*0\)\s*\{\s*return\s+400;\s*\}/u);
    assert.match(entry.body, /if\s*\(\$http_transfer_encoding\s*!=\s*""\)\s*\{\s*set\s+\$openarc_policy_body_ok\s+0;\s*\}/u);
  }
  // No broad 16KiB relaxation leaked onto the pure GET reads.
  for (const entry of externalProxying.filter(
    (candidate) =>
      /\$request_method\s*!=\s*GET/u.test(candidate.body) && !candidate.body.includes("$request_method = POST"),
  )) {
    assert.match(entry.body, /client_max_body_size\s+1k;/u, `${entry.raw} read-only location must keep the 1k no-body bound`);
  }
});

test("no proxy directive or include is ever placed inside an if block", () => {
  for (const entry of policyLocations) {
    const blocks = entry.body.match(/if\s*\([^)]*\)\s*\{[^}]*\}/gu) ?? [];
    for (const block of blocks) {
      assert.ok(!block.includes("proxy_pass"), "if block must not contain proxy_pass");
      assert.ok(!block.includes("proxy_set_header"), "if block must not contain proxy_set_header");
      assert.ok(!block.includes("include "), "if block must not contain include");
    }
  }
});

test("the policy transport reuses the read and write params with market response suppression unchanged", () => {
  for (const entry of externalProxying.filter(
    (candidate) => candidate.raw.includes("/policies$") || candidate.raw.includes("/revisions$"),
  )) {
    assert.match(entry.body, /include\s+\/etc\/nginx\/tenant_proxy_params;/u, `${entry.raw} must reuse the read params`);
  }
  for (const entry of namedProxying) {
    assert.match(entry.body, /include\s+\/etc\/nginx\/tenant_write_proxy_params;/u, `${entry.raw} must reuse the write params`);
  }
  for (const entry of allProxying) {
    assert.match(entry.body, /include\s+\/etc\/nginx\/market_response_headers;/u, `${entry.raw} must suppress Set-Cookie/CORS`);
  }
  // The reused parameter files keep their reviewed content and gain no policy edit.
  assert.match(readParams, /proxy_pass_request_body\s+off;/u);
  assert.match(readParams, /proxy_ssl_verify\s+on;/u);
  assert.match(readParams, /proxy_next_upstream\s+off;/u);
  assert.match(readParams, /proxy_buffering\s+off;/u);
  assert.match(readParams, /proxy_max_temp_file_size\s+0;/u);
  assert.match(writeParams, /proxy_pass_request_body\s+on;/u);
  assert.match(writeParams, /proxy_set_header\s+X-OpenArc-CSRF\s+\$http_x_openarc_csrf;/u);
  assert.match(writeParams, /proxy_set_header\s+Idempotency-Key\s+\$http_idempotency_key;/u);
  assert.ok(!readParams.includes("openarc_policy"), "the read params must stay unchanged");
  assert.ok(!writeParams.includes("openarc_policy"), "the write params must stay unchanged");
  for (const header of ["Set-Cookie", "Access-Control-Allow-Origin", "Vary"]) {
    assert.match(read(FILES.responseHeaders), new RegExp(`proxy_hide_header\\s+${header};`, "u"));
  }
});

test("all proxied policy routes keep verified TLS, retries off and no cache or disk spooling", () => {
  const transport = readParams + writeParams;
  assert.match(transport, /proxy_ssl_server_name\s+on;/u);
  assert.match(transport, /proxy_ssl_verify\s+on;/u);
  assert.match(transport, /proxy_ssl_verify_depth\s+3;/u);
  assert.ok(!/proxy_ssl_verify\s+off;/u.test(transport));
  for (const entry of allProxying) {
    assert.ok(!/proxy_pass\s+http:/u.test(entry.body), `${entry.raw} must use https only`);
    assert.ok(!/proxy_cache\b/u.test(entry.body), `${entry.raw} must not cache`);
  }
});

test("the control-capability route is an exact credentialless GET with a fixed upstream path", () => {
  const locations = parseLocations(capabilitySource);
  assert.equal(locations.length, 1, "the capability file must declare exactly one location");
  const entry = locations[0];
  assert.equal(entry.modifier, "=", "the capability route must be an exact match");
  assert.equal(entry.path, "/v2/public/control-capabilities");
  assert.match(entry.body, /if\s*\(\$request_method\s*!=\s*GET\)\s*\{\s*return\s+405;\s*\}/u);
  assert.match(entry.body, /if\s*\(\$request_uri\s*!=\s*"\/v2\/public\/control-capabilities"\)\s*\{\s*return\s+400;\s*\}/u);
  for (const header of ["$http_cookie", "$http_authorization", "$http_proxy_authorization", "$http_x_openarc_csrf", "$http_idempotency_key"]) {
    const escaped = header.replace("$", "\\$");
    assert.match(entry.body, new RegExp(`if\\s*\\(${escaped}\\s*!=\\s*""\\)\\s*\\{\\s*return\\s+403;\\s*\\}`, "u"));
  }
  assert.match(entry.body, /proxy_pass_request_headers\s+off;/u);
  assert.match(entry.body, /proxy_ssl_verify\s+on;/u);
  assert.match(entry.body, /proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\}\/v2\/public\/control-capabilities;/u);
  assert.ok(!/try_files|index\.html/u.test(entry.body), "the capability route must never serve SPA HTML");
});

test("the deny include covers /v2/control and the capability lookalikes with plain prefixes only", () => {
  const locations = parseLocations(denySource);
  for (const required of ["/v2/control", "/v2/public/control-capabilities"]) {
    const entry = locations.find((candidate) => candidate.path === required);
    assert.ok(entry, `${required} must be a plain deny prefix`);
    assert.equal(entry.modifier, "", `${required} must not use ^~ or =`);
    assert.match(entry.body, /return\s+404;/u);
    assert.ok(!/proxy_pass|try_files/u.test(entry.body), `${required} deny must not proxy or serve SPA`);
  }
  for (const lookalike of ["/v2/controlXYZ", "/v2/public/control-capabilitiesXYZ"]) {
    assert.ok(
      locations.some((entry) => lookalike.startsWith(entry.path)),
      `${lookalike} must be covered by a plain prefix`,
    );
  }
});

test("both API-enabled templates install capability, business and deny includes exactly once", () => {
  for (const template of [FILES.apiConf, FILES.arcConf]) {
    const source = read(template);
    for (const include of [
      "openarc-control-capability-locations.inc",
      "openarc-policy-management-locations.inc",
      "openarc-control-deny.inc",
    ]) {
      assert.equal(source.split(include).length - 1, 1, `${template} must include ${include} exactly once`);
    }
  }
});

test("the plain no-API template denies control paths and capability without SPA fallback", () => {
  const plain = stripNginxComments(read(FILES.plainConf));
  assert.ok(!plain.includes("API_UPSTREAM_HOST"), "plain template must stay API boundary OFF");
  const locations = parseLocations(read(FILES.plainConf));
  for (const required of ["/v2/control", "/v2/public/control-capabilities"]) {
    const entry = locations.find((candidate) => candidate.path === required);
    assert.ok(entry, `${required} must be denied in the no-API template`);
    assert.equal(entry.modifier, "", `${required} must be a plain prefix`);
    assert.match(entry.body, /return\s+404;/u);
    assert.ok(!/try_files|proxy_pass/u.test(entry.body), `${required} must not fall through to SPA or proxy`);
  }
});

test("Dockerfile declares the policy flag true|false in both stages and requires only account access + API boundary", () => {
  const argOccurrences = dockerfile.match(/ARG\s+VITE_POLICY_MANAGEMENT_ENABLED=false/gu) ?? [];
  assert.equal(argOccurrences.length, 2, "the flag must default to false in both stages");
  const caseOccurrences = dockerfile.match(/case\s+"\$\{VITE_POLICY_MANAGEMENT_ENABLED\}"\s+in\s+true\|false\)/gu) ?? [];
  assert.equal(caseOccurrences.length, 2, "the flag must be validated true|false in both stages");
  const dependency =
    'if [ "${VITE_POLICY_MANAGEMENT_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }';
  assert.equal(dockerfile.split(dependency).length - 1, 2, "the account+API dependency must appear in both stages");
  assert.match(dockerfile, /VITE_POLICY_MANAGEMENT_ENABLED=true requires VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true/u);
  // The dependency must NOT reach into the tenant, machine, market, moderation
  // or Arc flags: the proxy supports the direct policy API independently.
  const dependencyLines = dockerfile
    .split("\n")
    .filter((line) => line.includes("VITE_POLICY_MANAGEMENT_ENABLED=true requires"));
  assert.equal(dependencyLines.length, 2, "the dependency message must appear once per stage");
  for (const line of dependencyLines) {
    for (const forbidden of ["TENANT_READS", "TENANT_WRITES", "MACHINE_", "MARKET_", "MODERATION", "ARC_OBSERVATION", "AGENT_REGISTRY"]) {
      assert.ok(!line.includes(forbidden), `the policy dependency must not require ${forbidden}`);
    }
  }
});

test("Dockerfile copies the control files and installs capability, deny and policy includes correctly", () => {
  for (const file of [
    "apps/web/nginx-control-capability.conf",
    "apps/web/nginx-control-deny.conf",
    "apps/web/nginx-policy-management-locations.conf",
  ]) {
    assert.ok(dockerfile.includes(file), `Dockerfile must copy ${file}`);
  }
  assert.match(
    dockerfile,
    /cp \/tmp\/openarc-nginx\/nginx-control-capability\.conf \/etc\/nginx\/templates\/openarc-control-capability-locations\.inc\.template;/u,
  );
  assert.match(
    dockerfile,
    /cp \/tmp\/openarc-nginx\/nginx-control-deny\.conf \/etc\/nginx\/templates\/openarc-control-deny\.inc\.template;/u,
  );
  // Capability and deny are installed unconditionally (outside the policy
  // if/else); the business include is copied under the enabled branch and
  // written empty when off.
  const capabilityCp = dockerfile.indexOf(
    "cp /tmp/openarc-nginx/nginx-control-capability.conf /etc/nginx/templates/openarc-control-capability-locations.inc.template",
  );
  const denyCp = dockerfile.indexOf(
    "cp /tmp/openarc-nginx/nginx-control-deny.conf /etc/nginx/templates/openarc-control-deny.inc.template",
  );
  const policyBranch = dockerfile.indexOf(
    'if [ "${VITE_POLICY_MANAGEMENT_ENABLED}" = "true" ]; then',
  );
  assert.ok(capabilityCp !== -1 && denyCp !== -1 && policyBranch !== -1, "the control install lines must exist");
  assert.ok(capabilityCp < policyBranch, "capability must be installed unconditionally before the policy branch");
  assert.ok(denyCp < policyBranch, "deny must be installed unconditionally before the policy branch");
  assert.match(
    dockerfile,
    /cp \/tmp\/openarc-nginx\/nginx-policy-management-locations\.conf \/etc\/nginx\/templates\/openarc-policy-management-locations\.inc\.template;/u,
  );
  assert.match(
    dockerfile,
    /:\s*>\s*\/etc\/nginx\/templates\/openarc-policy-management-locations\.inc\.template;/u,
    "the omitted business include must be written empty",
  );
});

test("policy-only mode installs both reused params independently of the old tenant and market flags", () => {
  // The enabled branch installs BOTH shared parameter files itself, without
  // depending on the tenant read/write or marketplace flags.
  const branch = dockerfile.slice(
    dockerfile.indexOf('if [ "${VITE_POLICY_MANAGEMENT_ENABLED}" = "true" ]; then'),
    dockerfile.indexOf("cp /tmp/openarc-nginx/nginx-market-capability.conf"),
  );
  assert.match(branch, /cp \/tmp\/openarc-nginx\/tenant_proxy_params \/etc\/nginx\/tenant_proxy_params;/u);
  assert.match(branch, /cp \/tmp\/openarc-nginx\/tenant_write_proxy_params \/etc\/nginx\/tenant_write_proxy_params;/u);
  assert.ok(branch.includes("VITE_POLICY_MANAGEMENT_ENABLED"), "the install must be gated by the policy flag alone");
  for (const forbidden of ["VITE_TENANT_READS_ENABLED", "VITE_TENANT_WRITES_ENABLED", "VITE_MARKET_CATALOG_ENABLED", "VITE_MARKET_MODERATION_ENABLED", "VITE_LISTING_MANAGEMENT_ENABLED"]) {
    assert.ok(!branch.includes(forbidden), `the policy install must not depend on ${forbidden}`);
  }
  // The market response headers are installed unconditionally and reused.
  assert.match(dockerfile, /cp \/tmp\/openarc-nginx\/market_response_headers \/etc\/nginx\/market_response_headers;/u);
});

test("the source-gate job carries the deliberate 40-minute timeout and the new guard is wired", () => {
  const workflow = read(".github/workflows/source-checks.yml");
  // Match the source-gate job specifically: its job key followed by the
  // intended 40-minute bound, and never the old 25-minute value.
  assert.match(
    workflow,
    /source-gate:\s*\n\s*runs-on:\s*ubuntu-latest\s*\n\s*timeout-minutes:\s*40\b/u,
    "the source-gate job must keep the deliberate 40-minute timeout",
  );
  assert.ok(!/timeout-minutes:\s*25\b/u.test(workflow), "the old 25-minute timeout must not remain");
  const guardLine = workflow
    .split("\n")
    .find((line) => line.includes("node --test scripts/account-deployment.test.mjs"));
  assert.ok(guardLine, "the guard invocation must run inside the built gate image");
  assert.ok(
    guardLine.includes("scripts/control-deployment.test.mjs"),
    "the built gate image must run the control deployment guard",
  );
  // The workflow stays manual-only.
  assert.match(workflow, /on:\s*\n\s*workflow_dispatch:/u);
});
