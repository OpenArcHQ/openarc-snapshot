import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

/**
 * Static deployment guards for the PORT-01 public capability proxy.
 *
 * These assertions read the real nginx directives (never comments). They prove
 * the public capability manifest is reachable at exactly one method-exact,
 * query-free public route in the two API-enabled templates, that the route
 * forwards to the same exact upstream path with verified TLS and a bounded
 * read, that request/response sensitive headers are stripped, and that the
 * plain non-API template fails closed with 404. They do not run nginx or prove
 * a live upstream response.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => readFileSync(path.join(root, relativePath), "utf8");

const FILES = {
  apiConf: "apps/web/nginx-api.conf",
  arcConf: "apps/web/nginx-arc.conf",
  plainConf: "apps/web/nginx.conf",
};

const PUBLIC_PATH = "/v2/public/capabilities";

function stripNginxComments(config) {
  return config
    .split("\n")
    .map((line) => line.replace(/(^|\s)#[^\n]*$/u, ""))
    .join("\n");
}

function parseLocations(config) {
  const locations = [];
  const header = /location\s+([=^~]*)\s*("@?[^"]*"|\S+)\s*\{/gu;
  let match;
  while ((match = header.exec(config)) !== null) {
    const open = match.index + match[0].length - 1;
    let depth = 0;
    let close = -1;
    for (let index = open; index < config.length; index += 1) {
      if (config[index] === "{") depth += 1;
      else if (config[index] === "}") {
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
      body: config.slice(open + 1, close),
    });
    header.lastIndex = close + 1;
  }
  return locations;
}

const apiStripped = stripNginxComments(read(FILES.apiConf));
const arcStripped = stripNginxComments(read(FILES.arcConf));
const plainStripped = stripNginxComments(read(FILES.plainConf));
const apiLocations = parseLocations(apiStripped);
const arcLocations = parseLocations(arcStripped);
const plainLocations = parseLocations(plainStripped);

const credentialHeaders = [
  "$http_cookie",
  "$http_authorization",
  "$http_x_openarc_csrf",
  "$http_idempotency_key",
];

const strippedRequestHeaders = [
  "Cookie",
  "Authorization",
  "X-OpenArc-Proxy-Secret",
  "X-OpenArc-Proxy-Client-IP",
  "X-Real-IP",
  "X-Forwarded-For",
  "X-Forwarded-Proto",
  "X-Forwarded-Host",
  "Forwarded",
  "Idempotency-Key",
  "X-OpenArc-Csrf",
];

const individuallyStrippedForwarded = [
  "$http_x_forwarded_for",
  "$http_x_forwarded_proto",
  "$http_forwarded",
];

const passedHeaders = [
  "Origin",
  "X-OpenArc-Client",
  "Sec-Fetch-Site",
  "Sec-Fetch-Mode",
  "Sec-Fetch-Dest",
];

const responseStrippedHeaders = [
  "Set-Cookie",
  "Strict-Transport-Security",
  "Access-Control-Allow-Origin",
  "Access-Control-Allow-Credentials",
  "Access-Control-Allow-Headers",
  "Access-Control-Allow-Methods",
  "Access-Control-Expose-Headers",
  "Access-Control-Max-Age",
];

function publicLocation(locations, template) {
  const matches = locations.filter(
    (entry) => entry.path === PUBLIC_PATH && entry.modifier === "=",
  );
  assert.equal(matches.length, 1, `${template} must declare exactly one exact ${PUBLIC_PATH} location`);
  return matches[0];
}

test("both API-enabled templates declare exactly one exact public capability location", () => {
  for (const [template, locations] of [
    [FILES.apiConf, apiLocations],
    [FILES.arcConf, arcLocations],
  ]) {
    const entry = publicLocation(locations, template);
    assert.match(entry.body, /proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\}\/v2\/public\/capabilities;/u);
  }
});

test("the public capability route is never a wildcard or prefix", () => {
  for (const [template, locations, source] of [
    [FILES.apiConf, apiLocations, apiStripped],
    [FILES.arcConf, arcLocations, arcStripped],
  ]) {
    for (const entry of locations) {
      if (!entry.path.includes("/v2")) continue;
      // A non-proxying fail-closed deny is allowed and required: the API
      // namespace guards keep unrouted /v2 paths off the SPA fallback. They
      // carry no upstream, so they cannot widen what is forwarded.
      if (!entry.body.includes("proxy_pass")) {
        assert.match(
          entry.body.trim(),
          /^return 404;$/u,
          `${template} ${entry.raw} must either proxy the exact capability route or deny`,
        );
        assert.ok(
          !entry.modifier.includes("^~"),
          `${template} ${entry.raw} must not suppress the exact capability route`,
        );
        continue;
      }
      assert.equal(entry.modifier, "=", `${template} ${entry.raw} must be an exact match`);
      assert.equal(entry.path, PUBLIC_PATH, `${template} must not widen /v2`);
    }
    assert.ok(!/location[^\n]*\/v2\/[^\n]*\*/u.test(source), `${template} must not wildcard /v2`);
  }
});

test("forwarding targets the same exact upstream path and keeps verified TLS/SNI/trust", () => {
  for (const [template, locations, source] of [
    [FILES.apiConf, apiLocations, apiStripped],
    [FILES.arcConf, arcLocations, arcStripped],
  ]) {
    const entry = publicLocation(locations, template);
    assert.match(entry.body, /proxy_pass\s+https:\/\/\$\{API_UPSTREAM_HOST\}\/v2\/public\/capabilities;/u);
    assert.ok(!/proxy_pass[^\n]*\/v1\//u.test(entry.body), `${template} public route must not reuse a private path`);
    assert.match(source, /proxy_ssl_name\s+\$\{API_UPSTREAM_SNI\};/u);
    assert.match(source, /proxy_ssl_trusted_certificate\s+\$\{API_TRUST_BUNDLE\};/u);
  }
});

test("the public route is method-exact GET and rejects non-GET with 405", () => {
  for (const [template, locations] of [
    [FILES.apiConf, apiLocations],
    [FILES.arcConf, arcLocations],
  ]) {
    const entry = publicLocation(locations, template);
    assert.match(entry.body, /if\s*\(\$request_method\s*!=\s*GET\)\s*\{\s*return\s+405;\s*\}/u);
  }
});

test("the public route rejects any query, exact request-uri only, body and transfer encoding with 400", () => {
  for (const [template, locations] of [
    [FILES.apiConf, apiLocations],
    [FILES.arcConf, arcLocations],
  ]) {
    const entry = publicLocation(locations, template);
    assert.match(
      entry.body,
      /if\s*\(\$request_uri\s*!=\s*"\/v2\/public\/capabilities"\)\s*\{\s*return\s+400;\s*\}/u,
    );
    assert.ok(!/\$args\b/u.test(entry.body), `${template} must use exact request-uri, not $args`);
    assert.match(entry.body, /if\s*\(\$http_transfer_encoding\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
    assert.match(entry.body, /if\s*\(\$http_content_length\s*!=\s*""\s*\)\s*\{\s*return\s+400;\s*\}/u);
    assert.match(entry.body, /if\s*\(\$http_content_type\s*!=\s*""\)\s*\{\s*return\s+400;\s*\}/u);
  }
});

test("nonempty credential headers are rejected locally with 403", () => {
  for (const [template, locations] of [
    [FILES.apiConf, apiLocations],
    [FILES.arcConf, arcLocations],
  ]) {
    const entry = publicLocation(locations, template);
    for (const header of credentialHeaders) {
      const escaped = header.replace("$", "\\$");
      assert.match(
        entry.body,
        new RegExp(`if\\s*\\(${escaped}\\s*!=\\s*""\\)\\s*\\{\\s*return\\s+403;\\s*\\}`, "u"),
        `${template} must reject nonempty ${header} locally`,
      );
    }
  }
});

test("only explicit needed request headers are forwarded upstream", () => {
  for (const [template, locations] of [
    [FILES.apiConf, apiLocations],
    [FILES.arcConf, arcLocations],
  ]) {
    const entry = publicLocation(locations, template);
    assert.match(
      entry.body,
      /proxy_pass_request_headers\s+off;/u,
      `${template} must disable blanket request-header passthrough`,
    );
    assert.match(
      entry.body,
      /proxy_set_header\s+Connection\s+"";/u,
      `${template} must clear the hop-by-hop Connection header`,
    );
    for (const header of passedHeaders) {
      assert.match(
        entry.body,
        new RegExp(`proxy_set_header\\s+${header}\\s+\\$http_`, "u"),
        `${template} must forward ${header}`,
      );
    }
    const forwarded = entry.body.match(/proxy_set_header\s+([^\s]+)\s+\$http_/gu) ?? [];
    const allowed = new Set([...passedHeaders, "Accept"]);
    for (const directive of forwarded) {
      const name = directive.replace(/proxy_set_header\s+/u, "").replace(/\s+\$http_$/u, "");
      assert.ok(allowed.has(name), `${template} must not forward an unexpected header: ${name}`);
    }
  }
});

test("sensitive request headers are cleared before reaching the upstream", () => {
  for (const [template, locations] of [
    [FILES.apiConf, apiLocations],
    [FILES.arcConf, arcLocations],
  ]) {
    const entry = publicLocation(locations, template);
    for (const header of strippedRequestHeaders) {
      assert.match(
        entry.body,
        new RegExp(`proxy_set_header\\s+${header}\\s+"";`, "u"),
        `${template} must clear ${header}`,
      );
    }
    for (const header of individuallyStrippedForwarded) {
      const escaped = header.replace("$", "\\$");
      assert.ok(
        !new RegExp(`if\\s*\\(${escaped}\\s*!=\\s*""\\)`, "u").test(entry.body),
        `${template} must strip ${header} rather than reject it (Railway proxy metadata is legitimate)`,
      );
    }
    assert.ok(
      !/if\s*\(\$http_x_forwarded_for/u.test(entry.body) &&
        !/if\s*\(\$http_x_forwarded_proto/u.test(entry.body) &&
        !/if\s*\(\$http_forwarded\b/u.test(entry.body),
      `${template} must never turn forwarded proxy metadata into a client error`,
    );
    assert.ok(!/proxy_set_header\s+Cookie\s+\$http_cookie/u.test(entry.body), "must never forward Cookie");
    assert.ok(!/proxy_set_header\s+Authorization\s+\$http_authorization/u.test(entry.body), "must never forward Authorization");
    assert.ok(!/proxy_set_header\s+Origin\s+\$\{/u.test(entry.body), "Origin must be the explicit client value");
  }
});

test("response Set-Cookie and CORS headers are hidden", () => {
  for (const [template, locations] of [
    [FILES.apiConf, apiLocations],
    [FILES.arcConf, arcLocations],
  ]) {
    const entry = publicLocation(locations, template);
    for (const header of responseStrippedHeaders) {
      assert.match(
        entry.body,
        new RegExp(`proxy_hide_header\\s+${header};`, "u"),
        `${template} must hide response ${header}`,
      );
    }
  }
});

test("the public route has a short bounded upstream read and no retry or spooling", () => {
  for (const [template, locations] of [
    [FILES.apiConf, apiLocations],
    [FILES.arcConf, arcLocations],
  ]) {
    const entry = publicLocation(locations, template);
    for (const directive of [
      /proxy_read_timeout\s+[1-9]\d*s;/u,
      /proxy_connect_timeout\s+[1-9]\d*s;/u,
      /proxy_send_timeout\s+[1-9]\d*s;/u,
    ]) {
      assert.match(entry.body, directive, `${template} must bound its upstream read`);
    }
    assert.match(entry.body, /proxy_next_upstream\s+off;/u, `${template} must explicitly disable retries`);
    assert.ok(!/proxy_cache/u.test(entry.body), `${template} must not spool or cache`);
    assert.match(entry.body, /proxy_buffering\s+off;/u);
    assert.match(entry.body, /proxy_request_buffering\s+off;/u);
    assert.match(entry.body, /proxy_max_temp_file_size\s+0;/u, `${template} must never spool responses to a temp file`);
  }
});

test("the public route declares the standalone directive set once without a generic include", () => {
  for (const [template, locations] of [
    [FILES.apiConf, apiLocations],
    [FILES.arcConf, arcLocations],
  ]) {
    const entry = publicLocation(locations, template);
    assert.ok(
      !/include\s+\/etc\/nginx\/[A-Za-z_]+_?proxy_params;/u.test(entry.body),
      `${template} must not include a generic proxy_params file`,
    );
    for (const singleton of [
      "proxy_http_version",
      "proxy_connect_timeout",
      "proxy_send_timeout",
      "proxy_read_timeout",
      "proxy_request_buffering",
      "proxy_buffering",
      "proxy_next_upstream",
      "proxy_max_temp_file_size",
    ]) {
      const occurrences = entry.body.match(new RegExp(`(^|\\s)${singleton}\\s`, "gu")) ?? [];
      assert.equal(occurrences.length, 1, `${template} must declare ${singleton} exactly once`);
    }
    assert.match(entry.body, /proxy_http_version\s+1\.1;/u);
    assert.match(entry.body, /proxy_ssl_server_name\s+on;/u);
    assert.match(entry.body, /proxy_ssl_verify\s+on;/u);
    assert.match(entry.body, /proxy_ssl_verify_depth\s+3;/u);
    assert.ok(!/proxy_ssl_verify\s+off;/u.test(entry.body), `${template} must keep upstream verification on`);
  }
});

test("the plain non-API template returns 404 for the exact public path and never SPA HTML", () => {
  const matches = plainLocations.filter((entry) => entry.path === PUBLIC_PATH);
  assert.equal(matches.length, 1, "plain template must declare exactly one public path location");
  assert.equal(matches[0].modifier, "=", "the plain deny must be an exact match");
  assert.match(matches[0].body, /return\s+404;/u);
  assert.ok(!matches[0].body.includes("proxy_pass"), "the plain deny must not proxy");
  assert.ok(!matches[0].body.includes("try_files"), "the plain deny must not fall back to the SPA shell");
  assert.ok(!plainStripped.includes("API_UPSTREAM_HOST"), "the plain template must stay API boundary OFF");
});

test("existing private routes and machine/auth/tenant includes are preserved", () => {
  for (const [template, source] of [
    [FILES.apiConf, apiStripped],
    [FILES.arcConf, arcStripped],
  ]) {
    assert.match(source, /location\s+=\s+\/v1\/private\/capabilities\b/u);
    assert.match(source, /location\s+=\s+\/metrics\b/u);
    for (const include of [
      "openarc-auth-locations.inc",
      "openarc-tenant-locations.inc",
      "openarc-machine-locations.inc",
    ]) {
      const references = source.split(include).length - 1;
      assert.equal(references, 1, `${template} must include ${include} exactly once`);
    }
    assert.match(source, /location\s+\/\s*\{\s*try_files\s+\$uri\s+\$uri\/\s+\/index\.html;\s*\}/u);
    assert.ok(
      !/proxy_pass[^\n]*\/v1\/agent\b/u.test(source) && !/proxy_pass[^\n]*\/v1\/provider\b/u.test(source),
      `${template} must not proxy machine session endpoints`,
    );
  }
});
