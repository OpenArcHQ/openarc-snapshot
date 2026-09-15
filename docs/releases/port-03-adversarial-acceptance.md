# PORT-03 P03-06 adversarial race suite

Accepted 2026-09-15 UTC, integrated onto `aa7f846`. The whole-phase financial
safety gate: `packages/db/test/control-adversarial.postgres.test.ts`, 22 tests,
registered in the `test:postgres` script.

This suite exists to try to break the financial invariants, not to re-prove the
happy paths the per-packet suites already cover.

## The eight races

| Race | Status |
| --- | --- |
| Parallel authorization against one cap | CLOSED |
| Cross-principal replay | CLOSED |
| Response loss after a real commit | CLOSED |
| Post-claim expiry and revocation | CLOSED |
| Lowered limit mid-flight | CLOSED |
| Organization bypass | CLOSED |
| Token rotation | CLOSED |
| Concurrent claim | CLOSED |

## Non-vacuity is the point

A race test that silently never contends is worse than none, so every race
carries a probe that **throws** rather than passes if contention did not happen:
`observeBlockedBy` waits until `pg_blocking_pids()` names the blocker *and*
`pg_stat_activity.wait_event_type = 'Lock'`; `observeBlockedBackends` confirms
the waiter is parked **inside** the named SECURITY DEFINER core; and a `track()`
wrapper asserts the loser's promise provably had not settled while blocked.

For the non-lock attacks the equivalent is a **paired positive control**: the
rightful principal's identical call still succeeds immediately after each
cross-principal attempt is refused, so a refusal cannot be an accident of
fixture setup. In race 6 the rightful provider passes every authority check and
is stopped only by the production provenance seam, proving the foreign-provider
refusals were genuine authorization refusals.

Response loss asserts `commits === 1`, zero rollbacks, the client released for
destruction, and the backend polled until actually gone from
`pg_stat_activity` — so the uncertainty followed a **real applied commit**,
observed from an independent connection before any retry. Expiry is proven by
the database's own clock on a deliberately short-lived grant, never a forged
timestamp.

Money is asserted on committed state as exact SQL numerics compared with
`BigInt`, and rollback proofs compare full durable snapshots across actions,
reservations, approvals, budget events, grants, tokens, claims, idempotency,
audit and outbox.

## A real defect found — and fixed

`ControlActionStore.normalizeError` mapped SQLSTATE `23514` into
`CONTROL_ACTION_STORE_INPUT_INVALID` alongside the genuine operand codes
`22023 / 22P02 / 22001 / 22003`. But `0010_control_actions.sql` raises `23514`
for three materially different families, verified independently here:

| Literal | Sites | Meaning |
| --- | --- | --- |
| `commerce_expired` | 11 | authority lapsed |
| `commerce_cancel_conflict`, `commerce_decision_conflict` | 3 | target state conflict |
| immutability and clock trigger invariants | 4 | genuine invariant violation |

A caller therefore could not distinguish "your body is malformed — fix it and
retry" from "this action is already cancelled or expired — do **not** retry,
read the status." That is precisely the wrong signal on the response-loss
recovery path: a caller that lost a reply was told to fix its input.

It always failed **closed** financially — nothing released twice, no row moved —
so it was an error-contract defect, not a money defect. It was still worth
fixing, because the error contract *is* the recovery contract.

**Fix:** `normalizeError` now classifies `23514` by the exact RAISE literal,
yielding a new `CONTROL_ACTION_STORE_EXPIRED` for `commerce_expired` and the
existing `CONTROL_ACTION_STORE_CONFLICT` for the two conflict literals. Any
other `23514` — an unrecognised CHECK or trigger invariant — still returns
`INPUT_INVALID` exactly as before, so there is no regression and the change
fails safe. Matching is on the **full message, never a substring**, and those
literals are internal and never caller-controlled.

`ControlGrantStore` never had this problem: it carries dedicated `P0D14` and
`P0D15` codes for the same families, and the suite asserts the contrast side by
side.

The compile-time coupling added when the action HTTP layer was integrated did
its job: adding the new store code **broke the API build** at
`satisfies Record<ControlActionStoreErrorCode, true>`, forcing an explicit
decision rather than a silent fall-through to 503. `CONTROL_ACTION_STORE_EXPIRED`
maps to 409, deliberately not 401 (which invites re-authenticating and
repeating) and not 5xx (which invites a proxy or agent to retry a money-adjacent
write).

Two tests that had pinned the defective behaviour were updated to pin the
separation instead — including, fittingly, the response-loss recovery test
itself, which now asserts the caller is told the target is in a conflicting
state rather than being told to fix its input.

## Verification

| Gate | Result |
| --- | --- |
| adversarial suite alone | 1 file / 22 tests |
| `@openarc/db` test | 16 files / **339** (unchanged) |
| `@openarc/db` test:postgres | 16 files / **527** (was 15 / 505) |
| `@openarc/api` test:unit | 68 files / **1,225** (unchanged) |
| typecheck, build, ESLint `--max-warnings=0` | exit 0 |

## Deliberately not covered

**Redis restart**, named in the backlog line, is out of scope for this file and
was not faked: `packages/db` has no Redis dependency and no financial authority
lives there. Every invariant here is enforced by PostgreSQL row locks, SECURITY
DEFINER cores and durable idempotency records. Redis remains disposable
signalling and cannot restore spending capacity — that property belongs to a
runtime-level test, not a database one.

Production-lane success paths remain unreachable by construction, since
production wrappers reject `internal_fixture` provenance. Nothing here is
production purchase, grant, payment or settlement evidence.

## Boundary

Test-only. No source, migration or existing test was modified by the suite
itself; the defect fix above is a separate, deliberate source change.
