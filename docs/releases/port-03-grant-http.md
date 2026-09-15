# PORT-03 authorization-grant HTTP service, runtime and capability endpoint

Accepted 2026-09-15 UTC, integrated onto `f115c36`. Implements the nine frozen
grant routes across three audiences, the public capability endpoint, the runtime
and the store binding. **DEFAULT OFF** behind `COMMERCE_GRANTS_ENABLED`.

`grantRouteTemplates()` asserts each template is identical to `GRANT_ROUTES[i]`
and throws `COMMERCE_GRANT_ROUTE_REGISTRY_DRIFT` in either direction at
registration, so the inventory cannot silently diverge from the contract.

With the gate off all nine templates still register and answer `503
FEATURE_DISABLED` from `onRequest` before any service, store, limiter or cookie
work — proven with zero service calls and with a hostile not-found handler
returning HTML 200, which no frozen target reaches.

## Store-error mapping

| DB12 code | HTTP | wire code |
| --- | --- | --- |
| `INPUT_INVALID` | 400 | `INVALID_REQUEST` |
| `SESSION_INVALID` | 401 | `UNAUTHENTICATED` |
| `FORBIDDEN` / `NOT_FOUND` | 403 | `FORBIDDEN` |
| `CONFLICT` / `GRANT_CONFLICT` | 409 | `POLICY_DENIED` |
| `GRANT_EXPIRED` | 409 | `GRANT_EXPIRED` |
| `POTENTIAL_EXPOSURE` | 409 | `BUDGET_RESERVATION_CONFLICT` |
| `IDEMPOTENCY_CONFLICT` | 409 | `IDEMPOTENCY_CONFLICT` |
| `REQUIREMENT_UNAVAILABLE` / `UNAVAILABLE` / unrecognized | 503 | `INTERNAL_ERROR` |
| `OUTCOME_UNKNOWN` | **500** | `INTERNAL_ERROR` |

`NOT_FOUND` collapses into the same denial as `FORBIDDEN` so there is no
existence oracle. `GRANT_CONFLICT` maps to the neutral `POLICY_DENIED` rather
than an "already used" code, because the store collapses claimed, revoked and
superseded into one code and "already used" would assert a **consumed** grant —
and therefore a possible payment — for a merely revoked one. `GRANT_EXPIRED` is
terminal: deliberately not 401, which invites re-authentication and repeat, and
not 503, which invites retry. `OUTCOME_UNKNOWN` keeps its own definitive 500,
distinct from the 503 that `UNAVAILABLE` and the fallback share, because
repeating an unknown-outcome grant mutation is the double-spend risk.

The map is `as const satisfies Record<ControlGrantStoreErrorCode, true>` against
a type-only `@openarc/db` import, so an upstream rename or addition is a build
error. The commerce-session path uses a separate raw, vocabulary-free extractor,
so a session outage still answers 503 rather than being downgraded.

## Verification

| Gate | Result |
| --- | --- |
| `@openarc/api` test:unit | 68 files / **1,225** (was 62 / 1,124) |
| `@openarc/api` test:postgres | 9 files / **134** (was 8 / 129) |
| typecheck, build, ESLint `--max-warnings=0` | exit 0 |

A real PostgreSQL adapter proof migrates the schema, builds the store over the
restricted `openarc_tenant_app` role, and shows all nine `openarc_durable`
helpers exist, that each bound operation is refused by the database with a code
from DB12's real vocabulary and **never** `INPUT_INVALID` (which is what a
swapped or mis-shaped argument produces), and that five are refused on
**authority**, proving the SQL genuinely ran.

The runtime reaches `enabled` with the full seam set, initializes exactly once
before serving, and reports `built_disabled` for ten misconfigurations and for
each of the nine store methods removed individually, with zero lifecycle calls
while disabled.

## Genuine blocker, carried honestly

**The two grant mutation-status routes have no DB12 backing.**
`ControlGrantStore` exposes seven operations and `0012_authorization_grants.sql`
declares no grant mutation-status helper — verified here independently. The
frozen registry nevertheless publishes `agent_grant_mutation_status` and
`grant_mutation_status`, and **the grant console's lost-response recovery
depends on the browser one**.

Both routes are implemented end to end — transport, audience separation, service
projection, audience-restricted receipt binding — and the adapter reports the
missing dependency as `CONTROL_GRANT_STORE_UNAVAILABLE`, yielding a fixed 503.

That is the correct choice and worth stating: a `not_found` was **deliberately
not faked**, no receipt was reconstructed from another table, and the
commerce-action status helpers were not borrowed, because they answer only for
action operations and would return a **false negative on a money-adjacent
recovery read** — telling a caller their mutation does not exist when it may
have committed.

Closing it needs `read_agent_grant_mutation_status` and
`read_human_grant_mutation_status` SECURITY DEFINER helpers in a new migration
plus store methods; the port method and service projection are already in place
and tested. Until then the grant family must not be enabled, since its recovery
path answers 503.

## Review note: two hash domains for one secret

The service digests the raw `oag_v1_` with the API-side
`hashCommerceGrantToken` (domain `openarc.control.authorization-grant.v1`) and
passes only the digest across the store seam, mirroring how `action-service.ts`
avoids a runtime `@openarc/db` import. The store also exports
`digestCommerceGrantToken` under a **different** domain,
`openarc.control.grant.token.v1`, which is currently consumed only by the DB
package's own tests.

Behaviour is correct today because the store treats the hash as opaque and the
API is the only producer in production, so a token can only match itself. It is
recorded here because two domains for one secret is a latent footgun: if any
future live path digests with the store's domain, tokens would silently stop
matching. Converging on one canonical domain is a cheap follow-up.

## Other deliberate decisions

No provider-session read port: the provider's current-authorization check runs
inside the store transaction against the very row being read or written, which
is stronger than a separate pre-read. Introspection rejects an
`Idempotency-Key`, since accepting one on a read-only POST would imply a
replayable write. No query string is accepted on any grant route, verified over
a raw socket, because the store exposes no list or page method.

## Not covered

No end-to-end PostgreSQL test of a real issue → introspect → claim → revoke flow
through HTTP; `control-grant-store.postgres.test.ts` owns that semantics.
Raw-token zeroing in memory is not asserted — JS strings cannot be wiped, and
the guarantee is structural. API-layer concurrency is not re-tested; the single
compare-and-set is database-owned.

## Boundary

Default OFF at the database, API, proxy and console. An enabled grant surface
enables no payment lane.
