# Fail-closed API namespace at the web edge

Accepted 2026-09-15 UTC, based on `4f08e15`. Closes a real defect found while
verifying deployed staging: unrouted `/v1/` and `/v2/` paths fell through to the
SPA fallback and answered **HTTP 200 `text/html`**.

## The defect, observed live

Against `https://web-staging-1275.up.railway.app` on 2026-09-15:

| Path | Status | Content type |
| --- | --- | --- |
| `/v2/public/capabilities` | 200 | `application/json` |
| `/v2/public/marketplace-capabilities` | 200 | `application/json` |
| `/v2/public/control-capabilities` | 200 | **`text/html`** |
| `/v2/public/session-capabilities` | 200 | **`text/html`** |
| `/v2/public/action-capabilities` | 200 | **`text/html`** |
| `/v2/health` | 200 | **`text/html`** |
| `/v2/ready` | 200 | **`text/html`** |

An absent or disabled endpoint was therefore indistinguishable from a working
one by status code, and a deployment check reading only the status would take
the SPA shell for API success. `/v2/public/control-capabilities` and
`/v2/public/session-capabilities` are accepted built families, so this also hid
which capability surfaces the deployed artifact actually carries.

Every server config ended with `location / { try_files $uri $uri/ /index.html; }`
and no general API-namespace deny, so only paths covered by a specific family
deny failed closed.

## The fix

`apps/web/nginx-api.conf`, `nginx-arc.conf` and `nginx.conf` each gain four
fail-closed locations before the SPA fallback:

```
location = /v1 { return 404; }
location = /v2 { return 404; }
location /v1/ { return 404; }
location /v2/ { return 404; }
```

They are plain prefix and exact locations, never `^~`, and they are the
shortest API prefixes in the server. nginx selects the longest matching prefix
first, and a matching exact `=` or anchored regex location still overrides a
plain prefix, so every enabled route keeps winning and only genuinely unrouted
API paths reach the deny. This is the same precedence contract the twelve
existing family deny files already rely on.

## Real-nginx verification

Both flag modes were assembled exactly as the Dockerfile does and served by real
`nginx:1.29-alpine` against a dead upstream, so `502` proves a route was
selected and proxied, `404` proves a deny, and `200 text/html` would prove a
SPA leak. Observed:

| Path | Flags ON | Flags OFF |
| --- | --- | --- |
| `/v2/public/capabilities` | 502 | 502 |
| `/v2/public/marketplace-capabilities` | 502 | 502 |
| `/v2/public/control-capabilities` | 502 | 502 |
| `/v2/public/session-capabilities` | 502 | 502 |
| `/v2/public/market/listings` | 502 | 404 |
| `/v2/control/organizations/:org/policies` | 502 | 404 |
| `/v2/control/organizations/:org/commerce-sessions` | 502 | 404 |
| `/v2/agent/commerce-sessions/exchange` | 405 | 404 |
| `/healthz` | 502 | 502 |
| `/v2/public/action-capabilities` | 404 | 404 |
| `/v2/health`, `/v2/anything`, `/v1/anything`, `/v2`, `/v1` | 404 | 404 |
| `/market`, `/` | 200 HTML | 200 HTML |

No enabled route was suppressed, every previously leaking path now fails closed,
and the SPA still serves its own routes. `/v2/agent/commerce-sessions/exchange`
answering 405 to a GET is the existing method guard, not the new deny.

## Static guard

`scripts/api-namespace-deployment.test.mjs` adds 15 assertions across the three
server configs: all four guards present exactly once, each a bare `return 404;`
with no upstream, never `^~`, the shortest API prefixes declared, ordered before
the SPA fallback, and no API location anywhere may reference `try_files` or
`index.html`. The test was negative-checked against three regression shapes —
guard deleted (3 failures), guard marked `^~` (3 failures), guard proxying
instead of denying (1 failure) — and passes 15/15 on the restored source.

Registered in `source-checks.yml` alongside the other deployment guards and in
`release-gates.yml` as its own step.

`scripts/capability-deployment.test.mjs` asserted that *every* location whose
path contains `/v2` is an exact match equal to `/v2/public/capabilities`, which
the new denies violated. Its real hazard is a **proxying** wildcard or prefix
that could forward arbitrary paths upstream, so the assertion was tightened
rather than relaxed: a `/v2` location must now either proxy the exact capability
route, or be a bare `return 404;` with no upstream and no `^~`. Negative-checked
by turning the guard into a proxying prefix, which the tightened assertion still
rejects. All 154 deployment-guard assertions across the nine proxy test files
pass on the final source.

## Boundary

This is a web-edge correctness fix. It enables no feature, changes no API
behaviour, and adds no capability. `/v2/public/action-capabilities` deliberately
stays 404 until the action family ships. The deployed staging artifact is
unchanged and still exhibits the defect; redeployment is a separate step.
