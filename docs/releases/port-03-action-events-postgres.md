# PORT-03 worker consumption from real action lifecycle transactions

Accepted 2026-09-15 UTC, integrated onto `939c3c6`. Closes the evidence gap the
notification-handler release deferred: proving the worker consumes
commerce-action events produced by **real lifecycle transactions**, not by
direct outbox inserts.

## How "real lifecycle transaction" was proven

Not by row existence. Two independent, discriminating methods:

- **`xmin` transaction identity.** The `authorized` outbox row carries the same
  PostgreSQL transaction id as the `commerce_actions` and `audit_events` rows
  the same call inserted; `approved` shares `xmin` with the inserted
  `budget_reservations` row; `rejected` with the updated `commerce_approvals`
  row; `cancelled` with both the updated action row and the `budget_events`
  release row. Each decide `xmin` is asserted **different** from its own
  authorize `xmin`, and the two authorize `xmin`s differ from each other and
  from the chain-seeding session row, so the equality discriminates rather than
  holding trivially.
- **In-flight visibility.** An authorize run on an explicitly opened transaction
  sees its own action, reservation and event inside that transaction while an
  outside connection sees none, and `ROLLBACK` removes all of it.

The assertion was falsification-checked: re-pointing one `xmin` comparison at an
admin-seeded row made the case fail, then it was reverted.

No new case inserts an outbox row. Cancel additionally runs through the real
restricted-runtime `ControlActionStore.cancelCommerceAction` on the tenant pool.

## Proofs closed

All seven: same-commit emission for all four events; the real claim loop
claiming and acknowledging each exactly once with the handler selected by the
exact `resourceType|eventType` key; canonical `openarc:action:<uuidv4>` resource
ids matching the actions actually created; no financial effect from consumption,
compared as whole-row `jsonb` snapshots of actions, reservations, approvals,
budget events and exposure locks with exact integer money strings; no secret
leakage across four serialized surfaces, including a blanket
`not.toMatch(/[0-9a-f]{64}/)`; a rolled-back lifecycle transaction leaving
nothing to claim; and lease-expiry redelivery reclaimed with an incremented
generation, acknowledged exactly once overall, with the stale generation refused
and the financial snapshot byte-identical.

## Two real defects found and fixed

### 1. The outbox store could not project four events the worker registers

`market.listing.origin_review.recorded`, `market.listing.version.published`,
`…paused` and `…retired` are genuinely emitted by `0007_market_lifecycle.sql`
and are registered in the worker's closed handler registry, but
`OutboxStore#projectClaim` had no case for them and fell through to
`default: fail('OUTBOX_STORE_UNAVAILABLE')`.

Because one unprojectable row fails the **whole claim batch**, a single
published listing version would have permanently stalled every notification of
every type. This was a live queue-blocking defect, not a test artifact.

Fixed by adding the four cases. The subtlety is the resource validator: these
four legitimately target a listing's **first** version, whereas
`market.listing.version.created` deliberately excludes `@1` because creating
version 1 is already reported by `market.listing.created`. Reusing the stricter
pattern would have reintroduced the jam, so a separate
`isListingVersionLifecycleResource` accepts version >= 1 while keeping the same
length bound, canonical listing grammar and absolute-end anchor.

Three unit regressions cover all four events at versions 1, 2 and 999999999;
malformed resources (`@0`, `@01`, `@`, bare listing, trailing newline, trailing
space, non-numeric suffix) still rejected; and `version.created` still excluding
a first version. Negative-checked twice: removing the four cases fails, and
swapping in the strict `@1`-rejecting validator fails.

### 2. The worker loop retried claim failures forever

`WorkerLoop.run()` logged `claim_error`, backed off to `idleMaxMs` and retried
without bound. With defect 1 present this spun indefinitely and stalled the
queue silently. A claim failure is not always transient.

`maxConsecutiveClaimErrors` (integer 1..1000, default 10) now stops the loop and
logs `stopping` with the count, so a supervisor restart makes the condition
visible instead of invisible. A single successful claim resets the counter.
Three unit regressions: the bound trips at exactly the configured count, a
successful claim resets it, and an out-of-range bound is rejected rather than
accepted.

## Verification on the integrated revision

| Gate | Result |
| --- | --- |
| `@openarc/db` test | 15 files / **308** tests (was 305) |
| `@openarc/worker` test | 1 file / **50** tests (was 47) |
| `@openarc/worker` test:postgres | 1 file / **15** tests (was 12) |
| `@openarc/api` test:unit | 61 files / 1,110 tests |
| typecheck, build, ESLint `--max-warnings=0` | exit 0 |

## Scope note recorded, not worked around

Production-provenance authorize and decide are structurally impossible in
schema 10 today: `is_canonical_source_kind` accepts only `internal_fixture`,
while `mode = 'production'` in both cores explicitly refuses that provenance. So
those paths cannot succeed against any requirement that can currently exist, and
the proof uses the DB10 privileged fixture seam for authorize/approve/reject.
`cancel_commerce_action_core` has no provenance gate, which is why cancel is
exercised through the restricted runtime store.

## Not covered

Dead-lettering a commerce-action event after exhausted attempts; concurrent
worker claim splitting across action events specifically; the DB11 read store;
and idempotent re-authorize producing no second event.
