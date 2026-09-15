# PORT-05 — Evidence foundations

Accepted 2026-09-15 UTC. Four commits:

| Commit | Subject |
| --- | --- |
| `c0629ec` | `fix(outbox): project and consume authorization grant events` |
| `9653a97` | `feat(evidence): add evidence v2 contracts with audience views and payment certainty` |
| `9e152d7` | `feat(evidence): project commerce control facts into evidence v2` |
| `ff79deb` | `refactor(shared): use one SHA-256 implementation for Vault and evidence digests` |

All four are pure contracts, a pure projection, or a fix to the outbox store and worker.
Nothing here calls Gateway, Circle or Arc, and nothing moves funds.

## Payment certainty vocabulary

This is the most important contract in the set, so it comes first. Rule version
`openarc.evidence.v2.payment-certainty.v1` has exactly four certainties:

| Lane state | Certainty | Exposure |
| --- | --- | --- |
| `unknown`, for any reason | `unknown` | held |
| `pending` | `pending` | held, even with a finalized matching chain observation |
| `committed` | **`submitted_pending_chain`** | committed |
| `committed`, with a finalized, matching, successful Arc receipt on Arc testnet | `onchain_confirmed` | committed |

- **A lane `committed` is `submitted_pending_chain`.** It means Gateway reports a
  completed transfer. It does not mean the chain has confirmed it. An observation that
  is unfinalized, names a different transaction or comes from the wrong network keeps
  `submitted_pending_chain`, and records the reason in `chainCheck`.
- **`onchain_confirmed` requires a finalized Arc observation that matches** the Gateway
  batch transaction. A lane state on its own can never produce it.
- **A finalized receipt that reverted** contradicts Gateway, so it is held as `unknown`.
- **There is no settled, paid, released, refunded or failed state.** This is proved at
  the type level, not left to convention.

The exposure summary has exactly four buckets: `held`, `claimed`, `unknown` and
`committed`. **`unknown` stays in its own bucket** and is never folded into another. The
summary has no merged total, and a merged total, a missing bucket, a `released` status or
a non-integer amount is rejected.

## c0629ec — grant outbox events (defect 8)

**The defect.** Schema12 emits four events: `control.grant.issued`,
`control.grant.replaced`, `control.grant.revoked` and `control.grant.claimed`. Neither the
outbox store nor the worker had a case for them. The first grant mutation would have
failed every claim batch and stalled all notifications.

**The fix.** It adds the four cases, using the canonical grant id grammar, to
`packages/db/src/outbox-store.ts` and `apps/worker/src/handlers.ts`.

**The guard.** A new test catalog (`packages/db/test/outbox-event-catalog.ts`) derives the
set of permitted events from the migrated outbox `CHECK` constraints. Any future event
type the database permits will fail the tests until both the store and the worker handle
it.

Proofs:

- *keeps the exact closed event inventory: 21 legacy tuples plus the 3 commerce-session,
  4 commerce-action and 4 grant tuples*
- *accepts each of the four grant tuples and rejects a malformed grant id*
- *projects all four grant events with a canonical grant id* and *rejects a malformed
  grant resource or a mismatched resource type* (OutboxStore authorization_grant claim
  boundary)
- *claims and completes a row for each pair the outbox CHECK constraints permit*
  (PostgreSQL)
- *matches the worker registry exactly to the pairs the outbox CHECK constraints permit*
  (worker, PostgreSQL)
- A PostgreSQL test in *worker consumes a real authorization-grant event without jamming
  the queue*

## 9653a97 — evidence v2 contracts

`packages/shared/src/commerce/evidence-v2.ts` defines `openarc.evidence.v2`. It is pure:
no clock, no I/O and no persistence. Every schema is strict, with no passthrough, no
stripping and no defaults.

**Source classes.** There are exactly nine, and each fact kind is bound to the source
classes permitted to assert it. Every fact carries a source class, origin, adapter version
and `observedAt`. Chain facts also carry block number, block hash and finality, and no
other fact may carry a chain anchor. A fact whose `occurredAt` is after its `observedAt`
is rejected.

**Actors.** There are exactly five actor kinds, all identified by canonical server ids.
Token and session hashes are rejected as actor identifiers. A provider actor or provider
attestation must match the provider scope.

**Audience views.** There are three views — public, provider and operator — each with an
exact key set:

- The public view carries no amount, no address and no internal id. It refuses
  organization-protected facts.
- The provider view carries only the viewer's own listing and grant facts.
- The operator view carries the full fact.

**No secret material.** No signature, authorization payload, token, session, nonce or key
field can be represented. A compile-time proof fails the build if a secret-named key is
added. Canary secret keys are rejected at every nesting level, canary secret values in
every string slot, and projections throw on a smuggled key rather than passing it through.

**Conflicts.** Conflicting observations resolve to an explicit conflict, never
last-write-wins. The same source reporting a different status, a changed block anchor for
the same transaction, and a reused evidence id with different content are all conflicts.
Finality and `lastObservedAt` never regress when observations arrive out of order, and the
result is the same for every input order.

**ERC-8183 refunds.** A job refund fact is created only for a paired mirror refund (see
PORT-07).

**Versioning.** The legacy investigation rule-version allowlist is unchanged.

Proofs in `packages/shared/test/commerce-evidence-v2.test.ts`:

- *defines exactly the nine source classes of the source of truth*
- *enforces the kind by source-class authority matrix for all nine classes*
- *rejects token and session hashes as actor identifiers or extra actor fields*
- *public view has the exact key set and no amount, address or internal ID*
- *proves at the type level that no secret-named key is representable*
- *rejects canary secret keys at every nesting level of every fact and view*
- *proves at the type level that no settled, paid, refunded, failed or released state
  exists*
- *maps every lane unknown reason to unknown and held, with or without a matching chain
  observation*
- *keeps pending as pending even with a finalized matching chain observation*
- *maps committed without a chain observation to submitted_pending_chain*
- *keeps committed at submitted_pending_chain for an unfinalized, mismatched-transaction
  or wrong-network observation*
- *yields onchain_confirmed only for a finalized, matching, successful Arc receipt*
- *holds a finalized reverted receipt that contradicts Gateway as unknown*
- *confirms exactly one combination across the exhaustive lane by chain table*
- *has exactly the held, claimed, unknown and committed buckets and no merged total*
- *keeps unknown in its own bucket and never folds it into another*
- *flags the same source reporting a different status as a conflict, never
  last-write-wins*
- *versions the module and leaves the legacy investigation rule-version allowlist
  unchanged*

## 9e152d7 — control evidence projection, conflict rule v2, lane type sync

### Projection

`packages/shared/src/commerce/control-evidence-projection.ts` is a pure function,
`projectControlEvidence`, with rule version `openarc.control-evidence-projection.v1`.

**Inputs:** actions, approvals, reservations, grants and payment attempts.

**Outputs:**

- evidence v2 facts
- a four-bucket exposure summary
- per-attempt payment certainty
- commerce state dimensions

**Fail-closed behaviour:**

- **Expiry** is derived only against an explicit `evaluatedAt` instant, at the earliest
  expired authority. A record newer than the evaluation instant is refused.
- **No payment attempt** means payment stays `not_requested`, whatever the reservation
  says.
- **A `persisted` attempt** is required and held, and has no observation.
- **An `unknown` attempt** is unknown exposure in its own bucket, never folded into
  `claimed`.
- **A `committed` attempt** maps to `submitted_pending_chain` with committed exposure. It
  is never "paid".
- **Inconsistencies are listed, not repaired.** An out-of-order snapshot or a missing
  record appears as one of `approval_record_missing`, `approval_status_disagrees`,
  `grant_record_missing`, `grant_status_disagrees`, `reservation_record_missing` or
  `reservation_released_with_payment_attempt`. An attempt against a released reservation
  keeps its attempt exposure.
- **Input errors** are closed: `invalid_input`, `identity_mismatch`,
  `record_after_evaluation`, `payment_attempt_without_grant` and
  `payment_source_required`.

### Conflict rule v2

`openarc.evidence.v2.conflict.v2`: agreeing facts from different sources now resolve as
`corroborated` and list every source. Under v1 they were a `multiple_sources` conflict.
`multiple_sources` stays in the vocabulary for compatibility, but v2 never emits it. A
real disagreement between sources is still a conflict.

### Lane type sync

The payment lane package carries a compile-time and runtime test that keeps shared's copy
of the lane exposure types identical to the lane's own. That package is not part of this
public snapshot, so the test is not included here; shared's copy is self-contained and its
own tests pin every state, disposition and unknown reason.

Proofs:

- *corroborates agreeing facts from different sources, listing every source, for every
  input order*
- *corroborates agreeing chain observations from two sources without regressing finality
  or lastObservedAt*
- *keeps a real disagreement between different sources a conflict and never reports
  multiple_sources*
- *derives expiry only against evaluatedAt, at the earliest expired authority*
- *refuses any record newer than the evaluation instant*
- *keeps payment not_requested without an attempt, whatever the reservation says*
- *surfaces an unknown attempt as unknown exposure in its own bucket, never folded into
  claimed*
- *maps a committed attempt to submitted_pending_chain, committed exposure and never
  paid*
- *covers every attempt state against every unresolved reservation status*
- *flags an attempt against a released reservation while keeping the attempt exposure*
- *does not depend on payment attempt order* and *gives out-of-order snapshots the same
  IDs for the facts they share*
- *has the same state, disposition and unknown-reason unions* and *has mutually
  assignable per-state shapes with identical keys* (lane sync)

## ff79deb — single SHA-256

**The problem.** The Vault ROOT-kind reader and the evidence projection each carried
their own pure SHA-256. The evidence copy encoded lone surrogates differently from
`TextEncoder`.

**The fix.** Both now use `packages/shared/src/sha256.ts`, which follows `TextEncoder`
semantics.

Proofs in `packages/shared/test/sha256.test.ts`:

- *matches the FIPS 180-4 vectors*
- *encodes lone surrogates exactly as TextEncoder (U+FFFD) at every padding boundary*
- *is the single implementation behind the Vault and evidence helpers*

## Verification

Test counts for these commits: see CI.

## Unverified and kept fail-closed

- **`onchain_confirmed` needs a real Arc observation adapter.** The rule exists, but no
  runtime in these commits produces a matching finalized Arc observation. Every committed
  attempt therefore projects to `submitted_pending_chain`.
- **Gateway's word.** `committed` still rests on Gateway reporting one fully matching
  completed transfer, as in PORT-04.
- **Persistence and API.** These commits add no storage for the projection and no route
  that serves it or the audience views.

## Boundary

Shared contracts, a pure projection and a fix to the outbox store and worker. There is no
new migration, no API route, no network call, no signing and no funds.
