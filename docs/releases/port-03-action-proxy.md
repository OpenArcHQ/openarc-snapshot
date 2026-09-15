# PORT-03 commerce-action web-edge proxy

Accepted 2026-09-15 UTC, integrated onto `d20bcd5`. Adds the commerce-action
nginx family: the exact capability manifest location, the twelve business
routes, and the unconditional fail-closed denies.

**Ships DEFAULT OFF** behind `VITE_COMMERCE_ACTIONS_ENABLED`, which the
Dockerfile validates in both stages and which requires account access, tenant
reads, the API boundary and commerce sessions.

## Structure

`nginx-action-capability.conf` installs the exact `= /v2/public/action-capabilities`
location unconditionally whenever the API boundary is on, matching how the
session and market manifests behave regardless of their business flag.
`nginx-action-locations.conf` carries the twelve routes and is installed only
when the action flag is true; an empty template is installed otherwise.
`nginx-action-deny.conf` is unconditional and plain-prefix.

Route grammars are reused verbatim from the shared schemas: `openarc:org:`,
`openarc:agent:` and `openarc:policy:` carry the `[1-8]` identity nibble, while
`openarc:action:`, `openarc:approval:` and the bare mutation id pin UUID v4.
Every `proxy_pass` carries no URI part, so the encoded request URI is preserved.

The nine browser routes sit under the existing unconditional `/v2/control` deny,
which the anchored regexes override when enabled; the deny is deliberately not
restated, since a duplicate `location /v2/control` is an nginx configuration
error.

## Lead review: a real defect found and fixed

The submitted family required `^Bearer oas_ag_[A-Za-z0-9_-]+$` on all three
agent routes, copied from the accepted commerce-session family. **That is the
wrong credential namespace.**

The session agent routes are where a machine credential (`oas_ag_`) is exchanged
for a commerce session, so `oas_ag_` is correct *there*. The action agent routes
**consume** that commerce session and require `oacs_v1_`, exactly as
`apps/api/src/control/action-routes.ts` enforces and as the frozen grant contract
states: "an old read-only machine bearer can never authorize spending."

The consequences were twofold. Every valid `oacs_v1_` commerce-session token
would have been rejected with 403 at the edge, leaving the agent action lane
entirely non-functional whenever the flag was enabled. And an `oas_ag_` machine
credential — precisely the credential that must never reach a spending surface —
would have been forwarded to the API. The API rejects it, so defence in depth
held, but the edge policy was inverted in both directions.

The three guards now read `^Bearer oacs_v1_[A-Za-z0-9_-]{43}$`, pinning the same
43-character base64url length the API enforces.

**Why the submitted verification missed it:** the real-nginx matrix tested the
agent routes only with a *missing* bearer and with a cookie, both of which
correctly return 403. It never sent a valid bearer, so the wrong namespace
produced the expected status for the wrong reason.

## Static guard

`scripts/action-deployment.test.mjs`, 23 assertions. Added during review: the
agent locations must require the exact `oacs_v1_` bearer **and** must not mention
`oas_ag_` at all, plus a cross-family test pinning both directions — the session
agent routes must keep `oas_ag_` and must not accept `oacs_v1_`, and the action
agent routes the reverse. Negative-checked by reinjecting the original defect: 2
failures with it, 0 without.

Registered in `source-checks.yml` and as its own step in `release-gates.yml`.
All deployment guards pass: **177 assertions across ten files** (was 154 across
nine). `release-check.mjs` exits 0.

## Real-nginx verification

Assembled exactly as the Dockerfile does and served by `nginx:1.29-alpine` on
port 8080 against a dead upstream, so 502 proves a route was selected and
proxied, 404 proves a deny, and 200 `text/html` would prove a SPA leak.

| Probe | Result |
| --- | --- |
| nine browser routes | 502 |
| browser route presented a bearer | 403 |
| agent authorize + valid `oacs_v1_` | **502** |
| agent authorize + `oas_ag_` machine credential | **403** |
| agent authorize + no bearer | 403 |
| agent detail + valid `oacs_v1_` / + `oas_ag_` | 502 / 403 |
| agent mutation status + valid `oacs_v1_` | 502 |
| session exchange + `oas_ag_` / + `oacs_v1_` | 502 / 403 |
| `/v2/public/action-capabilities` | 502 |
| `…-capabilitiesXYZ`, `/v2/agent/commerce-actionsXYZ`, `/v2/anything` | 404 |
| `/market`, `/` | 200 HTML |

No API path returns 200 `text/html`. The session family is unregressed: the
unconditional action denies never shadow the accepted commerce-session agent
routes. All throwaway containers were removed.

## Deliberate deviation

The frozen registry contains **no mixed-method path**, so this family declares no
`error_page 418 = @name` dispatch and no named location; adding one would be dead
configuration. The guard proves this positively by deriving per-path method sets
from the registry and asserting each is a singleton, and separately asserts the
accepted session dispatch is still present so this cannot be read as licence to
remove one. A future registry revision adding a mixed-method action path trips
that assertion.

## Not covered

No full `docker build` of the web image was run; the Dockerfile's assembly was
reproduced file-for-file into the template tree and served by real nginx, and the
shell dependency expression was executed directly across seven flag combinations.
Reproduce with `docker build -f apps/web/Dockerfile --build-arg VITE_COMMERCE_ACTIONS_ENABLED=true … .`

## Boundary

Edge routing only. Default OFF, and enabling it enables no payment lane.
