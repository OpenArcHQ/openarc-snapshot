# PORT-03 action HTTP service, runtime and capability endpoint

Accepted 2026-09-15 UTC, integrated onto `f9d7838`. Adds the commerce-action
service, routes, runtime and the public capability endpoint in `apps/api`,
implementing exactly the twelve routes of the accepted frozen manifest.

**The family ships DEFAULT OFF.** `COMMERCE_ACTIONS_ENABLED` defaults to false
and is false in every default config.

## Route inventory and audience separation

Route templates are asserted equal to the shared `ACTION_ROUTES` registry at
registration time and a mismatch throws `COMMERCE_ACTION_ROUTE_REGISTRY_DRIFT`,
so the inventory cannot silently diverge from the accepted manifest.

The nine `commerce_action_management` routes are **browser** audience: cookie
session, the exact browser client marker, exact configured Origin, and CSRF on
every write. `Authorization` and `Proxy-Authorization` are rejected outright.
The three `commerce_action_authorization` routes are **agent** audience:
exactly one `Authorization: Bearer oacs_v1_<43 base64url>` commerce-session
token with an absolute-end anchor, and cookie, Origin, CSRF, Fetch-metadata and
proxy credentials all rejected. Separation is tested in both directions: a
browser cookie is inert on an agent route and a bearer is inert on a browser
route.

Transport guards additionally cover duplicate critical headers, request URL
size, exact method, query rejection on routes that take none, body limits and
`transfer-encoding`.

## Disabled-lane behaviour

This layer deliberately diverges from the session layer, which registers nothing
when disabled. With the gate off, all twelve exact templates are still
registered and each returns the strict `503 FEATURE_DISABLED` envelope from
`onRequest`, before any service, store, limiter or cookie parsing runs. A test
registers a hostile catch-all returning `200 text/html` after the family and
proves no frozen target can reach it. This is the API-side counterpart of the
web-edge fail-closed namespace guard: a disabled endpoint can never be mistaken
for API success.

## Store error mapping

| DB10 code | HTTP | wire code |
| --- | --- | --- |
| `INPUT_INVALID` | 400 | `INVALID_REQUEST` |
| `SESSION_INVALID` | 401 | `UNAUTHENTICATED` |
| `FORBIDDEN` | 403 | `FORBIDDEN` |
| `NOT_FOUND` | 403 | `FORBIDDEN` |
| `CONFLICT` | 409 | `POLICY_DENIED` |
| `IDEMPOTENCY_CONFLICT` | 409 | `IDEMPOTENCY_CONFLICT` |
| `BUDGET_DENIED` | 409 | `BUDGET_LIMIT_EXCEEDED` |
| `POTENTIAL_EXPOSURE` | 409 | `BUDGET_RESERVATION_CONFLICT` |
| `STALE_TERMS` | 409 | `POLICY_DENIED` |
| `REQUIREMENT_UNAVAILABLE` | 503 | `INTERNAL_ERROR` |
| `OUTCOME_UNKNOWN` | **500** | `INTERNAL_ERROR` |
| `UNAVAILABLE` | 503 | `INTERNAL_ERROR` |
| unrecognized | 503 | `INTERNAL_ERROR` |

`NOT_FOUND` maps to 403 to avoid an existence oracle. `STALE_TERMS` carries
SQLSTATE `40001`, but is deliberately **not** treated as a transient
serialization failure: a 5xx there would invite an automatic retry of a
money-adjacent write, so the caller must re-read current terms and submit a new
logical mutation. `REQUIREMENT_UNAVAILABLE` (`P0D10`) is raised only for
`internal_fixture` provenance refused in production mode — verified at both
`RAISE` sites in `0010_control_actions.sql` — so it is an operator-side
admission failure, not a caller-correctable request, and a 4xx would also make
it a provenance oracle.

`OUTCOME_UNKNOWN` gets its own definitive **500** rather than sharing the 503
that `UNAVAILABLE` and the unrecognized fallback use. A 503 reads as a transient
outage that a client, agent or proxy may safely repeat, and repeating an
unknown-outcome authorization is exactly the double-charge risk. The wire code
stays the fixed non-echoing `INTERNAL_ERROR`, so the distinction discloses
nothing and claims no payment or settlement lane. Recovery is only ever the
explicit bounded mutation-status read; the service issues none on the caller's
behalf, never retries and never re-dispatches.

**Approval-required is a success, not an error.** DB10 routes always-approve and
above-threshold policies to `pending_approval` with a zero reservation, and the
service returns that normally. Proven by "returns a pending_approval
authorization as a normal success with a zero reservation".

## Lead hardening: compile-time coupling to DB10

The service matched store errors structurally on `error.code`, with no
compile-time link to DB10's vocabulary — a rename upstream would have silently
fallen through to the 503 fallback and, worse, an `OUTCOME_UNKNOWN` would have
lost its distinct non-retryable mapping. The code table is now declared as
`satisfies Record<ControlActionStoreErrorCode, true>` against a **type-only**
import from `@openarc/db`, so the import is erased and the service stays
testable with injected fakes while DB10 adding a code (missing key) or renaming
one (unknown key) becomes a build error. Negative-checked both directions.

Narrowing immediately surfaced a real latent defect: `mapCommerceSessionError`
shared the same extractor while matching the commerce-**session** vocabulary, so
narrowing to DB10 codes would have discarded the session outage codes and
downgraded a genuine 503 outage to a 401. The extractors are now split, with the
session path keeping a raw, vocabulary-free read.

## Verification on the integrated revision

| Gate | Result |
| --- | --- |
| `@openarc/api` build, typecheck, ESLint `--max-warnings=0` | exit 0 |
| `pnpm --filter @openarc/api test:unit` | 61 files / **1,110** tests (baseline 55 / 1,013) |
| `pnpm --filter @openarc/api test:postgres` | 8 files / **129** tests, against 0010+0011 applied |

Also covered: exact per-route rate-limit bucket order (global → peer → subject)
with short-circuit behaviour and HMAC keys containing no raw bearer or IP;
`/readyz` reporting `commerceActionDatabase` only while enabled; and a guard
test that every stale code, including the three removed invented ones, falls to
the unrecognized 503 so the old vocabulary cannot reappear.

## Known gaps, deliberately open

`server.ts` wiring is verified by typecheck, build and the runtime's own
`built_disabled` tests, not by a running server: the action runtime's `store`
and `commerceSessions` seams have no concrete binding yet, so with the flag on
the runtime reports `built_disabled` and `createApp` throws
`"Commerce action dependencies are unavailable"` — fail-closed startup rather
than a silently missing surface, until an integrator binds the DB10/DB11 stores.
No PostgreSQL test drives the store-error mapping end to end; the codes are now
compile-time coupled, which closes the silent-drift risk but is not the same as
an executed round trip. The proxy layer and the DB11 store adapter are separate
follow-up packets.

## Boundary

An enabled action surface is a control surface only. It does not enable a
payment, settlement or delivery lane; the listing payment lane remains
unavailable and production authorization still rejects unverified requirement
provenance. Whole PORT-03 acceptance and publication remain pending.
