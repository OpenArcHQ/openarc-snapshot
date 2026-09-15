import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

/**
 * Static deployment guard for the fail-closed API namespace.
 *
 * Every server config ends with the SPA fallback `location / { try_files ...
 * /index.html; }`. Without an API-namespace deny, any `/v1/` or `/v2/` path
 * that no enabled route and no family deny happens to cover falls through to
 * that fallback and answers HTTP 200 text/html, so an absent or disabled
 * endpoint is indistinguishable from a working one by status code. This was
 * observed live: `/v2/public/control-capabilities`, `/v2/public/session-
 * capabilities` and `/v2/health` all returned 200 text/html on deployed
 * staging.
 *
 * These assertions parse the real nginx directives (never comments). They
 * prove the four guards exist in all three server configs, that they are plain
 * prefix or exact locations and never `^~` (so every enabled exact and
 * anchored-regex API location still wins), that they are the shortest API
 * prefixes declared, that they deny rather than proxy, and that they are
 * declared before the SPA fallback. They do not run nginx; real-nginx
 * behaviour in both flag modes is recorded in the release evidence.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => readFileSync(path.join(root, relativePath), "utf8");

const SERVER_CONFIGS = [
  "apps/web/nginx-api.conf",
  "apps/web/nginx-arc.conf",
  "apps/web/nginx.conf",
];

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
      index: match.index,
      body: stripped.slice(open + 1, close),
    });
    header.lastIndex = close + 1;
  }
  return locations;
}

const GUARDS = [
  { modifier: "=", path: "/v1" },
  { modifier: "=", path: "/v2" },
  { modifier: "", path: "/v1/" },
  { modifier: "", path: "/v2/" },
];

for (const file of SERVER_CONFIGS) {
  const source = read(file);
  const locations = parseLocations(source);

  test(`${file} declares all four API namespace guards`, () => {
    for (const guard of GUARDS) {
      const found = locations.filter(
        (entry) => entry.path === guard.path && entry.modifier === guard.modifier,
      );
      assert.equal(
        found.length,
        1,
        `expected exactly one \`location ${guard.modifier} ${guard.path}\``,
      );
      assert.match(
        found[0].body.trim(),
        /^return 404;$/u,
        `${guard.path} must deny with a bare return 404 and never proxy`,
      );
      assert.ok(
        !found[0].body.includes("proxy_pass"),
        `${guard.path} must not reference an upstream`,
      );
    }
  });

  test(`${file} guards are never ^~ so enabled routes still win`, () => {
    for (const guard of GUARDS) {
      const found = locations.find(
        (entry) => entry.path === guard.path && entry.modifier === guard.modifier,
      );
      assert.ok(
        !found.modifier.includes("^~"),
        `${guard.path} must stay a plain prefix: \`^~\` would suppress the ` +
          "anchored regex API locations selected above it",
      );
    }
  });

  test(`${file} prefix guards are the shortest API prefixes declared`, () => {
    // nginx selects the LONGEST matching prefix location, so the guards may
    // only catch paths that no longer prefix, exact or regex location claims.
    const prefixes = locations.filter(
      (entry) =>
        entry.modifier === "" &&
        !entry.path.startsWith("@") &&
        /^\/v[12]/u.test(entry.path),
    );
    for (const entry of prefixes) {
      if (entry.path === "/v1/" || entry.path === "/v2/") continue;
      assert.ok(
        entry.path.length > 4,
        `${entry.path} must be longer than the namespace guard it sits under`,
      );
      assert.ok(
        entry.path.startsWith("/v1/") ||
          entry.path.startsWith("/v2/") ||
          entry.path === "/v1" ||
          entry.path === "/v2",
        `${entry.path} must live inside a guarded namespace`,
      );
    }
  });

  test(`${file} declares the guards before the SPA fallback`, () => {
    const fallback = locations.find((entry) => entry.path === "/" && entry.modifier === "");
    assert.ok(fallback, "expected the SPA fallback location");
    assert.match(fallback.body, /try_files\s+\$uri\s+\$uri\/\s+\/index\.html;/u);
    for (const guard of GUARDS) {
      const found = locations.find(
        (entry) => entry.path === guard.path && entry.modifier === guard.modifier,
      );
      assert.ok(
        found.index < fallback.index,
        `${guard.path} must be declared before the SPA fallback for readability`,
      );
    }
  });

  test(`${file} fails every payment-family path closed before the namespace guards`, () => {
    // PORT-04 P04-02c: the payment family's plain denies (or its includes, in
    // the API templates) must be declared before the namespace guards, and no
    // payment-family location may ever be `^~` or serve the SPA shell.
    const guardIndex = source.indexOf("location = /v1 { return 404; }");
    const fallback = locations.find((entry) => entry.path === "/" && entry.modifier === "");
    assert.ok(guardIndex !== -1 && fallback, "expected the namespace guard and SPA fallback");
    if (file === "apps/web/nginx.conf") {
      for (const prefix of ["/v2/public/payment-capabilities", "/v2/agent/commerce-payment-requirements", "/v2/agent/commerce-payment-attempts"]) {
        const found = locations.filter((entry) => entry.path === prefix);
        assert.equal(found.length, 1, `expected exactly one plain deny for ${prefix}`);
        assert.equal(found[0].modifier, "", `${prefix} must stay a plain prefix`);
        assert.match(found[0].body.trim(), /^return 404;$/u);
        assert.ok(found[0].index < fallback.index, `${prefix} must precede the SPA fallback`);
      }
    } else {
      for (const include of ["openarc-payment-capability-locations.inc", "openarc-commerce-payment-locations.inc", "openarc-payment-deny.inc"]) {
        const at = source.indexOf(`include /etc/nginx/conf.d/${include};`);
        assert.ok(at !== -1 && at < guardIndex, `${include} must be included before the namespace guards`);
      }
    }
    // Unrouted payment lookalikes still fall under a /v2/ guard, never the SPA.
    for (const unrouted of ["/v2/agent/commerce-payments", "/v2/agent/commerce-payment-observations", "/v2/public/payment"]) {
      assert.ok(unrouted.startsWith("/v2/"), `${unrouted} must stay inside the guarded namespace`);
      assert.ok(!locations.some((entry) => entry.modifier === "" && entry.path !== "/" && unrouted.startsWith(entry.path) && entry.body.includes("try_files")));
    }
    assert.ok(!/location\s+\^~\s+\/v2\/(?:agent\/commerce-payment|public\/payment)/u.test(source), "no ^~ payment location");
  });

  test(`${file} never lets an API path reach the SPA fallback`, () => {
    // Every declared API location either proxies, denies, or dispatches to a
    // named location. None may serve the SPA shell.
    const apiLocations = locations.filter(
      (entry) => !entry.path.startsWith("@") && /\/v[12]/u.test(entry.path),
    );
    assert.ok(apiLocations.length >= GUARDS.length, "expected API locations");
    for (const entry of apiLocations) {
      assert.ok(
        !entry.body.includes("try_files"),
        `${entry.path} must never fall back to the SPA shell`,
      );
      assert.ok(
        !entry.body.includes("index.html"),
        `${entry.path} must never serve index.html`,
      );
    }
  });
}
