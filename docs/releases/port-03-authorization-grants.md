# PORT-03 DB12 one-use authorization grants

Accepted 2026-09-15 UTC, integrated onto `ac694f1`. `0012_authorization_grants.sql`
plus `control-grant-store.ts` complete the last persistence packet of PORT-03:
buyer-issued one-use grants, provider two-token claim, introspection, revocation
and provider attempt recovery.

Migrations `0001`-`0011` are byte-unchanged, verified by digest.

## Authority model, as frozen

**Two-token claim.** A provider claim requires BOTH a currently authenticated
matching provider session (`oas_pr_`) under its existing `provider:self.read`
scope AND the buyer's exact one-use grant token (`oag_v1_`). Neither alone
suffices, and no existing credential scope or endpoint was widened. Agent
issue and replace authenticate the exact `oacs_v1_` commerce session and its
bound action, so a read-only machine bearer can never authorize spending.

**One grant per action, no second reservation.** Tokens are stored hash-only;
no raw `oag_v1_` and no reconstructable material exists in any row or output.

**Replacement only before any claim or exposure.** It retires the old
generation and cannot extend the original expiry. Validity is capped at 300
seconds and further bounded by the current chain of authority.

**Revocation after claim retains the claim fact and the held exposure.**
Repeated revoke releases nothing, and provider recovery keeps the claim plus a
`grantRevoked` flag. Retirement alone is never evidence of nonpayment.

## Surface

Three forced-RLS migrator-owned tables (`authorization_grants`,
`authorization_grant_tokens`, `authorization_grant_claims`); seven
tenant-executable production functions; seven migrator-private helpers plus
three trigger functions. New SQLSTATEs `P0D14` (grant conflict) and `P0D15`
(grant expired); `P0D01`, `P0D10` and `P0D13` reused.

Lead review confirmed: exactly **seven** `GRANT EXECUTE`, all to
`openarc_tenant_app`; **nothing** granted to `PUBLIC`; no table-level grant; no
new role; no policy outside the three new tables; and no raw-token column.

## Proofs closed

All fourteen required proofs, including: the exact
`reserved_not_granted -> grant_issued` transition; refusal to issue twice or
create a second reservation; replacement retiring the old generation with
`expires_at`, `issued_at` and `reservation_id` identical and the retired hash
denied; refusal to replace after a claim or any exposure; the 300-second ceiling
and a shorter chain bound winning; **both** single-token claim attempts denied
(session-only `42501`, token-only `28000`, wrong provider `42501`, zero claims);
an atomic two-token claim binding grant, action, listing, version, requirement,
provider and attempt; **real concurrent claims on separate connections electing
exactly one winner**, with the loser asserted still-pending for 300 ms while the
winner holds the row lock; introspection never consuming; provider recovery for
a new session of the same provider with missing and foreign indistinguishable;
revoke-after-claim retaining claim, exposure and `grantRevoked` with repeated
revoke releasing nothing; safe never-claimed cleanup reaching `cancelled`; the
production wrapper rejecting `internal_fixture` with zero mutations; and an
eight-table canary proving no raw token, secret body or hash is recoverable.

Also covered: schema-12 manifest and ACL denial, readiness failing when a core
gains `PUBLIC EXECUTE`, explicit transition control (orphan `grant_issued`,
DB10 cancel failing closed on `grant_issued`, all other edges closed, grant and
token immutability), and claim replay semantics.

## Deliberate deviations, both recorded

`replace` is provenance-gated in production even though the spec named only
issue, introspect and claim — a replace on a fixture grant would otherwise mint
runtime-valid authority. Conversely `revoke`, `readGrant` and
`readProviderAttemptStatus` take no mode: buyer cleanup and honest history must
never be blocked by provenance.

## Verification on the integrated revision

| Gate | Result |
| --- | --- |
| `@openarc/db` build, typecheck, ESLint `--max-warnings=0` | exit 0 |
| focused grant unit / PostgreSQL | 24 / 19 |
| `pnpm --filter @openarc/db test` | 16 files / **332** tests (was 15 / 308) |
| `pnpm --filter @openarc/db test:postgres` | 15 files / **498** tests (was 14 / 479) |
| `release-check.mjs` | exit 0 |

## Infrastructure note: a false failure worth recording

The first full PostgreSQL run after integration reported nine failed files and
292 skipped. The cause was **not** code: the fixture reported
`OOMKilled=true`, and the log showed "the database system is not yet accepting
connections" and "in recovery mode" — PostgreSQL crashed and restarted mid-run.
The combined schema is now much larger (0010 at 185 KB plus 0012 at 139 KB) and
sixteen PostgreSQL fixtures were running concurrently on a host with roughly
260 MB free.

Thirteen fixtures belonging to completed packets were **stopped, not removed**
(the list is preserved so `docker start` restores them). The re-run then passed
498/498. No timeout was extended and no assertion was relaxed. Treat a mass
failure with `not yet accepting connections` as fixture exhaustion and re-run
before investigating code.

## Not implemented, deliberately

No grant mutation-status-by-mutation-id reader: a lost COMMIT yields
`OUTCOME_UNKNOWN`, and the designated recovery is `readProviderAttemptStatus`
for the provider and `readGrant` for the buyer. No agent-side grant status
reader and no organization-wide grant listing or paging. Generation exhaustion
at 2147483647 is enforced by constraint and the increment-only trigger but is
unreachable by test. Lock-wait and expiry-during-wait drills for grants are not
included.

## Boundary

Persistence only. No HTTP, transport, payment, settlement or delivery. The
listing payment lane remains unavailable and production authorization still
rejects unverified requirement provenance. Grant transport, runtime, proxy, UI
and event handling remain to be built, and whole PORT-03 acceptance and
publication remain pending.
