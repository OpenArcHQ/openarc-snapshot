# PORT-03 DB10 action, reservation and approval engine

Accepted 2026-09-15 UTC, integrated onto `6a3b87d`. Migration `0010_control_actions.sql`
plus `control-action-store.ts` and `control-action-mutations.ts` land the
financial core: authorization, reservation, approval decisions, cancellation,
exposure accounting and safe receipt recovery.

Migrations `0001`-`0009` are byte-unchanged, verified by digest against the
integration checkout before and after the merge.

## Recovered state

An earlier worker record reported a focused PostgreSQL result of 35/36 with revoked-commerce
authorization returning an idempotency conflict before the required
current-authority denial. That failure was **already closed** by later edits
that postdate the packet's own logs; it was reproduced as 36/36 before any new
work, so it was not re-fixed. REVIEW-SQL-01, REVIEW-SQL-02, REVIEW-TS-01,
REVIEW-OUTBOX-01, REVIEW-READERS-01 and AMENDMENT-SELLER-01 were likewise
already closed in code with regressions, as were both REVIEW-FINAL-INVARIANTS-01
SQL findings: commerce state is locked after policy/listing/requirement, and
exact replay is resolved before target actionability, on the authorize and the
decide path.

## The eight original financial proofs, now closed

1. **Shared exposure across policy roots and sessions.** Same buyer and agent,
   two policy roots and two commerce sessions share exactly one exposure row;
   the second authorization cannot evade the first reservation. The exposure
   primary key is asserted to be exactly the six accepted fields.
2. **Cap lowered by a real policy revision.** A genuine new immutable version
   advances `current_revision` through the SQL8 trigger. Exposure 2000000 and
   deficit 1000000 are retained, available is 0, new excess is denied, and a
   brand-new session under the revised policy is denied identically.
3. **Fee-inclusive rolling window.** `assess_action_budget` and
   `read_commerce_exposure` expose no `asOf` parameter, so a bounded real
   DB-time fixture was used rather than a fake clock. Committed rows inside and
   outside the window, plus aged claimed and unknown reservations, produce an
   exact fee-inclusive total; the aged rows never disappear from exposure.
4. **4,096 accepted / 4,097 rejected, independently per source.** Proven
   separately for the committed and the unresolved source with bulk privileged
   synthetic rows and no relaxed constraint or grant. At 4,097 the store fails
   closed with `CONTROL_ACTION_STORE_UNAVAILABLE`, exposing no partial value,
   and business, idempotency, audit and outbox counts are asserted equal before
   and after.
5. **Listing and requirement binding matrix.** Superseded active listing
   version, rejected origin review, and tampered price or requirement identity
   are each denied. Provider pause was already covered and is not duplicated.
6. **Durability failure injection for approve, reject and cancel.** Each
   compares a full JSONB snapshot of actions, reservations, approvals, budget
   events, idempotency, audit and outbox rows for deep equality — not merely a
   caught error.
7. **Real post-COMMIT transport uncertainty.** A pool wrapper awaits the real
   `COMMIT` against actual PostgreSQL and then raises a bounded fault, labelled
   explicitly as an injected post-commit transport fault. Asserted:
   `OUTCOME_UNKNOWN`, exactly one COMMIT, zero ROLLBACKs, the backend pid gone
   from `pg_stat_activity`, no 64-hex token in any recorded statement, and an
   independent connection observing exactly one committed change.
8. **Replay after target invalidation with a different live decider.** After the
   original parent human logs out, and separately after the policy revision
   changes, a distinct still-live operator recovers the identical original
   receipt while a new decision is denied. Suspending that decider's membership
   then denies even the replay, proving the fresh caller's own check stays
   mandatory.

## Real defect found and fixed

`getHumanMutationStatus` passed the **agent** projection, which admits only
`control.commerce_action.authorize` — an operation the human SQL reader can
never return. Every committed human approve, reject and cancel receipt was
therefore converted into a fixed `CONTROL_ACTION_STORE_UNAVAILABLE`. The
transposable `agent: boolean` parameter was replaced with an explicit
`reader: 'human' | 'agent'` union so the two call sites cannot be swapped again.
Covered by one PostgreSQL and two unit regressions.

## Verification on the integrated revision

`@openarc/db` build, typecheck and ESLint (`--max-warnings=0`) exit 0. Focused
DB10 checks pass 20/20 unit and 51/51 PostgreSQL. Whole-package gates are
recorded in `port-03-action-reads.md`, which integrates alongside this one.

## Known gaps, deliberately open

The `v_review <> 'approved'` branch of `lock_action_listing` is not driven in
isolation: the append-only review table and the `active ⇒ approved` CHECK make
an active-but-unapproved version unreachable without relaxing a constraint,
which was not done. No listing-version pause/retire case. No overflow proof on
the decide path, and no case with both exposure sources simultaneously at the
bound. Post-commit uncertainty is injected for `cancel` only; the handling is
shared `#withTransaction` code.

## Boundary

This is persistence and financial accounting only. No HTTP, no transport, no
grant, no payment, no settlement and no delivery. The listing payment lane
remains unavailable and production authorization still rejects unverified
requirement provenance. Whole PORT-03 acceptance and publication remain pending.
