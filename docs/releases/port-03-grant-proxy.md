# PORT-03 authorization-grant web-edge proxy

Accepted 2026-09-15 UTC, integrated onto `0781c98`. Adds the grant capability
manifest location, the nine business routes and the unconditional fail-closed
denies. **Ships DEFAULT OFF** behind `VITE_COMMERCE_GRANTS_ENABLED`, validated
in both Dockerfile stages and requiring commerce actions, commerce sessions,
tenant reads, account access and the API boundary.

## The three credential namespaces, taken from the contract not a sibling

The action proxy shipped a real defect by copying `^Bearer oas_ag_` from the
commerce-session family onto routes that need `oacs_v1_`. This family derived
each namespace from the frozen `GRANT_CAPABILITY_CREDENTIAL` map instead:

| Family | Routes | Edge credential |
| --- | --- | --- |
| agent | 3 | `Bearer oacs_v1_<43 base64url>` — the commerce session |
| provider | 3 | `Bearer oas_pr_<43 base64url>` — the provider session |
| browser | 3 | cookie + CSRF on writes; `Authorization` rejected outright |

`oas_ag_` appears in this family only inside comments explaining why it is
**rejected**: it is a read-only machine credential and can never authorize
spending. The accepted session family keeps `oas_ag_` because that is exactly
where a machine credential is exchanged *for* a commerce session.

The buyer's one-use `oag_v1_` grant token travels in the **body only**, never a
path or query — which is why provider introspection is POST despite being
read-only, and why no provider path carries a token parameter.

## Deny scope

Four plain prefixes: `/v2/public/grant-capabilities`,
`/v2/agent/commerce-grants`, `/v2/agent/commerce-grant-mutations` and
`/v2/provider/grant`. Deliberately **not** bare `/v2/agent` or `/v2/provider`,
which would shadow the accepted commerce-session agent routes and the seller
browser lane at `/v2/provider/organizations/.../listings`. `/v2/control` and
`/v2/provider` remain owned by the accepted control and market denies and are
not restated, since a duplicate location is an nginx configuration error.

## Real-nginx verification

Assembled file-for-file as the Dockerfile does and served by
`nginx:1.29-alpine` on port 8080 against a dead upstream, so 502 proves a route
was selected and proxied, 404 proves a deny and 200 `text/html` would prove a
SPA leak. **80 probes with flags ON**, and crucially each family was probed with
its *correct* credential, not only a missing one — the omission that let the
action defect through:

| Presented | agent routes | provider routes | browser routes |
| --- | --- | --- | --- |
| correct credential | **502** | **502** | **502** (cookie) |
| `oacs_v1_` | — | 403 | 403 |
| `oas_pr_` | 403 | — | 403 |
| `oas_ag_` | **403** | 403 | 403 |
| cookie | 403 | 403 | — |
| none | 403 | 403 | — |

Also verified: wrong verb 405, query string 400, wrong content-type 415, revoke
without CSRF 400, introspect *rejecting* an idempotency key as a read, untyped
or non-v4 ids 404, capability manifest 502 with `…XYZ` 404 and `?x=1` 400, and
five lookalike paths 404.

Accepted families unregressed: session exchange 502 with `oas_ag_` and 403 with
`oacs_v1_`; action authorize 502 with `oacs_v1_` and 403 with `oas_ag_`; and
**`/v2/provider/organizations/:org/listings` still 502**, proving the grant deny
does not shadow the seller browser lane.

With flags OFF all nine routes and every variant return 404 while the capability
manifest still proxies. A third container verified the no-API template: `nginx
-t` OK, all grant paths 404, SPA only at `/`. All `openarc-grantproxy-*`
containers were removed.

## Static guard

`scripts/grant-deployment.test.mjs`, 25 assertions, registered in both CI
workflows. Negative-checked by reinjecting three defects: the shipped
action-proxy defect (`oas_ag_` on agent routes) → 1 failure; `oacs_v1_` on
provider routes → 1 failure; browser revoke accepting a bearer → 2 failures.

All deployment guards on the integrated source: **202 assertions across eleven
files**, up from 177 across ten. `release-check.mjs` exits 0.

## Notes

The packet could not run `release-check.mjs` in its container (its overlay
excludes the `e2e*/` and `playwright.*` tree, and the container has Node 26 while
the project contract is Node 22). It was run here on the full integration
checkout with Node 22 and exits 0; nothing in this change is gated by it.

No full `docker build` of the web image was run in the packet; the Dockerfile
assembly was reproduced file-for-file and the shell dependency expression
executed directly for both flag values. Separately, the web image **was** built
end to end for the staging deploy recorded in
`docs/operations/staging-deploy-2026-09-15.md`.

**Deliberate deviation on exact Origin:** no accepted family enforces a literal
Origin value at the edge, because there is no configured origin variable there.
The browser routes reject `Authorization` outright, require CSRF on the write,
and forward Cookie, the browser client marker, Origin and the Fetch-Metadata
triple through the unchanged tenant params, leaving the API as the authority for
the exact Origin comparison — matching every accepted family.

The API has no grant routes yet, so the edge is ahead of the handlers; nothing
here asserts API acceptance.

## Boundary

Edge routing only, default OFF. Enabling it enables no payment lane.
