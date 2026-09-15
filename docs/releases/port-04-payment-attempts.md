# PORT-04 — Verified requirement provenance and durable payment attempts

Accepted 2026-09-15 UTC. Commit `2484eb3`, `feat(control): add verified requirement provenance and
durable payment attempts`.

Migration `0015_payment_attempts.sql` (schema15) is additive over schema14 and leaves
migrations 0001–0014 untouched. It is owned by `openarc_migrator`, and the runtime role is
`openarc_tenant_app`. The migration never creates roles or schemas, never calls a
provider, Circle, Gateway or an Arc endpoint, and never signs, moves funds, settles or
delivers.

The persistence behind it is `packages/db/src/control-payment-attempt-store.ts`, exported
from `@openarc/db`.

## What shipped

1. **Verified requirement provenance.** A new requirement source kind,
   `verified_listing`, whose terms are all derived on the server.
2. **Seller payment terms.** `listing_version_payment_terms` stores one immutable pay-to
   address for each listing version.
3. **Durable payment attempts.** `payment_attempts` mirrors the accepted `packages/x402`
   lane exposure states.
4. **Exposure guards.** Additive triggers on the schema10 and schema12 reservation,
   action and grant tables.
5. **Runtime registrar.** `register_verified_commerce_requirement` lets the tenant
   runtime register a verified requirement using only a commerce token and ids.

## Verified requirement provenance

A `verified_listing` requirement row is admissible in production only because an insert
trigger re-proves every term. The terms come from two places:

- the seller's currently published (active), origin-approved listing version
- the pinned Arc-testnet x402 lane manifest: network `eip155:5042002`, scheme `exact`,
  `x402Version` 2, EIP-712 domain `GatewayWalletBatched` version `1`, verifying contract
  `0x0077777d7eba4688bdef3e311b846f25870a19b9`, USDC
  `0x3600000000000000000000000000000000000000`, 6 decimals, `erc20`

How each term is set:

- `amount_atomic` is the listing's recorded fixed-price `atomicAmount`, stored as exact
  text and never a float.
- `fee_atomic` is `'0'`. The recorded price has no fee component, and an x402 `exact`
  authorization transfers exactly `value`.
- No caller can supply an origin, price, network, asset, verifying contract, pay-to
  address or calldata.

The registration paths take only a requirement id and a listing id. The migrator core
also takes the buyer organization. The runtime registrar takes the exact commerce token
instead.

The trigger refuses any row whose terms differ from the server derivation. That includes
ordinary migrator DML.

`internal_fixture` is still refused on every production path, as schema10 and schema12
already did. There is no GUC, flag, callback or bypass.

### Frozen verified-requirement digest

The digest is not generic JSON. It is `sha256:` followed by the hex SHA-256 of the exact
newline-joined string below, with no trailing newline, so the API and tests can
reproduce it byte for byte. This is copied from the migration header:

```
openarc.control.requirement.verified_listing.v1 \n sellerOrgId \n providerId
\n listingId \n version \n eip155:5042002 \n exact \n 2 \n
GatewayWalletBatched \n 1 \n 0x0077777d7eba4688bdef3e311b846f25870a19b9 \n
USDC \n 0x3600000000000000000000000000000000000000 \n 6 \n erc20 \n
payToAddress (lowercase 0x + 40 hex) \n amountAtomic \n feeAtomic
```

It is implemented by `openarc_durable.verified_requirement_digest` and stays
migrator-private.

## Seller payment terms

`listing_version_payment_terms` holds one pay-to address for each
`(organization, listing, version)`.

**Where rows come from.** Only `commit_listing_payment_terms` can create a row. It needs
a fresh `owner` or `provider_admin` seller session. Each row carries a deferred foreign
key to its exact idempotency receipt, `market.listing.payment_terms.record` on a
`listing_version` resource.

**Immutability.** An append-only trigger rejects every update and delete with
`listing_payment_terms_immutable`. Changing the pay-to address needs a new listing
version.

**Address checks.** The address must be lowercase `0x` plus 40 hex characters. It cannot
be the zero address, the GatewayWallet contract or the USDC address. The same check
applies to the new `pay_to_address` column on `commerce_requirement_references`, and a
`verified_listing` row must have one.

A published, approved version without terms cannot back a verified requirement.

No outbox event type is added, so the outbox claim projection and the worker handlers are
unaffected.

## Durable payment attempts

`payment_attempts` mirrors `LaneExposure`, with one extra pre-dispatch state:

| State | Meaning |
| --- | --- |
| `persisted` | durable binding written, before any dispatch |
| `unknown` | dispatched; possibly exposed; held |
| `pending` | Gateway received, batched or confirmed; held |
| `committed` | one fully matching completed transfer; consumes exposure |

The only edges are:

- `persisted → unknown` (dispatch, exactly once)
- `unknown → pending`
- `unknown → committed`
- `pending → pending` (forward status only)
- `pending → committed`

**There is no release, failed, expired or cancelled state.** The only ways out of
`unknown` are `pending` and `committed`.

The stored `binding_digest` must equal
`payment_attempt_binding_digest(...)` of the row's own fields, which reproduces the
`packages/x402` `digestLaneBinding` output exactly. A row whose digest does not describe
its own binding cannot be represented.

No raw signature, raw authorization payload or key material can be represented. The row
holds only the lane binding digest and its non-secret fields.

## Exposure guards

These are separate additive triggers. No trigger, constraint or function body from
0010–0014 is loosened.

- A reservation with any durable attempt can never be released.
- A non-fixture reservation cannot advance past `held` (to `claimed`, `unknown` or
  `committed`) unless its attempt was durably dispatched first.
- A granted action with any durable attempt can never move to `cancelled`, `expired` or
  `rejected`.
- A non-fixture grant can be claimed only by the attempt id its buyer durably dispatched.

`revoke_authorization_grant` is redefined to keep exposure held when an attempt exists.
The body is the accepted schema12 body verbatim, except for one attempt row lock (after
the grant, in the frozen lock order) and one added release condition. A revoke still
retires the token and marks the grant revoked, so buyer cleanup is never blocked.

`internal_fixture` rows keep their exact accepted behaviour.

## Least privilege

`PUBLIC` receives nothing.

The tenant runtime can execute exactly these functions:

- `persist_payment_attempt`
- `record_payment_attempt_dispatch`
- `read_agent_payment_attempt`
- `commit_listing_payment_terms`
- `register_verified_commerce_requirement`

These stay migrator-private:

- the registration core
- `record_payment_attempt_observation`
- the digest helpers
- every trigger function

The runtime has no direct access to `payment_attempts`. The redefined revoke keeps its
accepted schema12 grants.

**How the entry points check authority.** The buyer persist, dispatch and read run under
the full commerce chain. `read_agent_payment_attempt` is scoped to the DB-derived buyer
organization and to the presenting subject agent. An attempt belonging to another
organization or another agent returns no row, exactly like a missing one. Authority is
asserted before and after the read, including on the not-found path.

The runtime registrar derives the buyer organization from the exact consumed commerce
token and asserts that authority before and after delegating.

## Fail-closed rules and their proofs

`packages/db/test/control-payment-attempt-store.postgres.test.ts`:

- **schema15 manifest, ownership, ACLs and readiness**
  - *records schema15 and keeps the runtime off the attempt table and every private
    helper*
  - *readiness passes, then fails for EVERY new helper that is missing, mis-signed,
    widened or bypassed*
- **verified requirement provenance**
  - *derives every term server-side from the published origin-approved listing version
    and the pinned manifest*
  - *refuses supplied or overridden price, fee, network, asset, verifying contract,
    window and version even as migrator DML*
  - *refuses a paused, retired, unreviewed or superseded listing version, and production
    authorize refuses a superseded one with zero mutations*
- **production path against verified provenance**
  - *production authorize, issue, persist, dispatch and claim succeed for a verified
    requirement; internal_fixture is still refused with zero mutations*
  - *a verified grant cannot be claimed or advance past held before its attempt is
    durably dispatched, nor by another attempt id*
- **durable attempt persistence**
  - *persists before exposure, echoes the recomputed digest, binds every DB-derived term
    and never takes a second attempt*
  - *rolls back everything when a failure is injected after the attempt write*
  - *a cross-organization or other-agent caller cannot persist against, dispatch or read
    another buyer's attempt; missing and foreign are indistinguishable*
- **attempt state machine**
  - *dispatch only from persisted; a second dispatch is refused in every later state;
    unknown moves only to pending or committed*
  - *the action exposure guard names exactly cancelled, expired and rejected and nothing
    else*
  - *no path releases exposure once an attempt exists: repeated revoke, cancel, authority
    expiry and direct cleanup keep it held*
- **secret material**
  - *stores and returns no raw signature, authorization payload or key material
    anywhere*
- **seller payment terms**
  - *records immutable pay-to terms exactly once per non-retired version with idempotency
    and audit receipts*
  - *refuses non-owner roles, cross-organization sellers and stale proofs with zero
    mutations*
  - *a published, approved version WITHOUT terms cannot back a verified requirement
    through any path*
- **runtime verified requirement registrar**
  - *derives the buyer organization from the exact commerce token and every term
    server-side; production authorize then succeeds*
  - *cross-organization tokens can only ever register for their own organization and
    cannot reuse or overwrite another buyer's requirement*
  - *refuses revoked and expired commerce sessions with zero mutations; fixture
    provenance stays refused in production*

`packages/db/test/control-payment-attempt-store.test.ts` (unit):

- *mirrors LaneExposure with a pre-dispatch persisted state and no release state at the
  type level*
- *reproduces the lane canonical digest and is independent of key order*
- *refuses every malformed or overriding persist input before taking a connection*
- *refuses malformed payment-terms and registrar inputs before taking a connection*
- *maps database codes to fixed non-echoing store codes and rolls back*
- *reports a lost COMMIT as OUTCOME_UNKNOWN and destroys the connection*
- *accepts a well-formed persisted row and refuses rows that disagree with the binding or
  the state model*

The existing PostgreSQL suites, including durability, tenant, market, credential and the
other control stores, were updated to run against schema15.

## Verification

| Gate | Result |
| --- | --- |
| `packages/db` unit tests | 17 files / **356** |
| `packages/db` PostgreSQL tests (combined verification) | 17 files / **556** |
| `0015_payment_attempts.sql` sha256 | `1145065fd56186d362e165853eb92f2d4db4afe9097f997ced3451f8ad6efdfd` |

Typecheck, lint and the remaining workspace gates: see CI.

## Deferred and kept fail-closed

- **Observation recorder principal.** `record_payment_attempt_observation` records only a
  positive observation (`pending` or `committed`). An `unknown` classification is not
  written, because `unknown` is already the held state. The accepted contracts do not
  settle which principal may record late observations after the buyer chain has expired,
  so the function is granted to no runtime role. Until that is decided, no runtime path
  can move an attempt out of `unknown`, and exposure stays held.
- **Requirement reader scoping.** This migration adds no new requirement reader. The
  schema10 `resolve_commerce_requirement` reader remains executable by the tenant runtime
  by requirement id (requirement ids are random UUIDv4 values) and does not return the new
  `pay_to_address` column. Scoping verified requirements to their buyer and seller is not
  done in this commit.
- **Pre-dispatch release: none, by design.** Even a `persisted` attempt, which was never
  dispatched, keeps its reservation held and forbids cancelling its action. A crash
  between persist and dispatch therefore strands exposure rather than risking a false
  release. This follows the lane's rule that anything after persist is treated as
  possibly sent.
- **Fee.** `fee_atomic` is fixed at `'0'`, derived from the recorded price and the
  `exact` scheme. It must be confirmed at live testnet acceptance.
- **Reservation commitment on observation.** Recording a `committed` observation on an
  attempt does not yet carry the reservation to its committed state. That wiring is
  deferred, and the reservation stays held in the meantime.

## HTTP wiring, default off (commit `60dff53`)

`feat(control): wire payment terms and buyer payment attempts over HTTP, default off`.

| Family (audience) | Method | Path | Credential |
| --- | --- | --- | --- |
| `commerce_payment_terms` (browser) | POST | `/v2/provider/organizations/:organizationId/listings/:listingId/versions/:version/payment-terms` | session cookie, Origin, client marker, CSRF and `Idempotency-Key`; any `Authorization` header is rejected |
| `commerce_payment_attempt` (agent) | POST | `/v2/agent/commerce-payment-requirements` | exactly one `Bearer oacs_v1_…` commerce session |
| same | POST | `/v2/agent/commerce-payment-attempts` | same |
| same | POST | `/v2/agent/commerce-payment-attempts/:attemptId/dispatch` | same |
| same | GET | `/v2/agent/commerce-payment-attempts/:attemptId` | same |

- Agent routes reject machine credentials (`oas_ag_`), provider credentials, grant tokens,
  cookies, Origin, CSRF and client markers. The requirement id and attempt id are the
  replay keys, so an `Idempotency-Key` header on an agent write is rejected.
- **There is no route for the observation recorder.**
- The persist body carries only the lane-chosen fields. The server rebuilds the binding
  from the pinned constants and the buyer's own authorized action, and the store
  recomputes the digest, so a lane that signed a different amount or pay-to cannot match.
- The store error vocabulary is coupled to the HTTP mapping at compile time. Nothing is
  retryable: a second dispatch is a `409` conflict, and a lost outcome is a `500`.
- `GET /v2/public/payment-capabilities` (`openarc.capabilities.commerce-payments.v1`)
  reports both families `built_disabled` while `COMMERCE_PAYMENTS_ENABLED` and
  `VITE_COMMERCE_PAYMENTS_ENABLED` are false, which is the default. Enabling payments
  refuses to start unless authentication, commerce sessions, actions, grants and a
  dedicated restricted database are also enabled.
- The web edge installs the payment locations only when the flag is on; otherwise the
  payment paths are denied with `404`.

Proofs include `apps/api/test/control-payment-routes.test.ts`,
`control-payment-service.test.ts`, `control-payment-config.test.ts`,
`control-payment-integration.test.ts`, `payment-capabilities.test.ts` and the real
PostgreSQL `control-payment-api.postgres.test.ts`: the seller records terms (with replay
and conflict), the agent registers a requirement, authorize and issue run through the
production stores, a wrong pay-to and an inflated amount are refused, persist replays,
one dispatch succeeds and a second is refused as a non-retryable conflict, the attempt
reads back, a fixture-backed grant is refused with zero attempts, and no credential
appears in any response.

## Combined verification

On the integration head with both commits and the other landed packets:

| Gate | Result |
| --- | --- |
| `packages/db` unit / PostgreSQL | 17 / 356 · 17 / 556 |
| `apps/api` unit (real Redis) / PostgreSQL | 73 / 1,285 · 10 / 137 |
| `apps/worker` unit / PostgreSQL | 1 / 51 · 1 / 17 |
| deployment and CI-wiring guards | 251 |
| `release-check.mjs`, typecheck, lint | pass |

A staging-shaped pre-flight of the exact API and web images booted in production mode
with every commerce family off: every capability manifest served JSON, both payment
families reported `built_disabled`, the payment agent routes failed closed as
`503 FEATURE_DISABLED` at the API and `404` at the edge, and enabling payments with grants
off refused to start. Migration 0015 applied to a disposable database gives schema
version 15, and a second run is a no-op.

## Boundary

No worker changes, no calls to Gateway, Circle or Arc, no signing, no funds and no live
endpoint. The payment family ships disabled. The attempt table records what the lane
reports; OpenArc does not dispatch payments itself.
