# PORT-03 commerce-session bearer read and action runtime binding

Accepted 2026-09-15 UTC, integrated onto `6b81c7f`. Adds
`0013_commerce_session_reads.sql` and completes the `server.ts` binding, so the
commerce-action runtime now reaches `enabled` instead of failing closed.

Migrations `0001`-`0012` are byte-unchanged, verified by digest.

## The gap this closes

The action runtime requires a `CommerceSessionReadPort` exposing
`getCommerceSessionByHash(tokenHash)`. No such read existed:
`CommerceSessionStore.getCommerceSessionStatus` requires a *human* session hash,
organization and session id, so it cannot resolve a bearer, and no helper in
`0009` resolved a commerce-session bearer hash into session metadata. Until now
the runtime reported `built_disabled` and startup failed with the flag on.

## The read

```sql
openarc_durable.read_commerce_session_by_token(commerce_token_hash text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog
```

`REVOKE ALL ... FROM PUBLIC` then `GRANT EXECUTE` to `openarc_tenant_app` only.
No table, no policy, no `ALTER`, no broad grant. Resolution mirrors
`lock_action_commerce` (consumed handoff `token_hash` with
`token_hash_version = 1` into `commerce_sessions`) but takes **no** `FOR UPDATE`
and is declared `STABLE`, so PostgreSQL itself forbids it writing. Its eleven
output columns are exactly the existing `SESSION_ROW_KEYS`, so the store reuses
its strict keyset and projection unchanged.

`CommerceSessionStore.getCommerceSessionByHash(tokenHash) => CommerceControlSessionMetadata | null`.

**The store reports the truth; the service enforces policy.** A revoked,
expired or shortened session still resolves, carrying its real `revokedAt` and
`expiresAt`, so the service can reject it explicitly rather than having it
silently vanish.

## Proofs closed

An exchanged live session resolves byte-exact; a revoked session resolves with
its real `revokedAt`; an expired session resolves with its real `expiresAt`; an
issued-but-unexchanged handoff never resolves as live, and the same bearer does
resolve after a real exchange; unknown and foreign are indistinguishable — nine
non-bearer digests, including both organizations' handoff, human-session and
machine-session hashes, all return identical `null`; no 64-hex value survives in
any output; the read mutates nothing, proven by md5 over every column of both
tables plus counts and `provolatile === 's'`; and the restricted runtime role
executes while `PUBLIC` cannot, with `public_grants = 0`, worker and auth roles
false, and an empirical `42501` from both pools.

Note on scope: the read is bearer-only and takes no organization argument, so
another organization's *bearer* legitimately resolves that organization's own
session — which is exactly what the agent lane needs, since it derives its
organization from the bearer. What is proven indistinguishable is every
**non-bearer** digest.

## Lead addition: readiness now covers the new helper

As delivered, `read_commerce_session_by_token` was absent from
`#assertHelpers`' expected list and its `IN (...)` filter, so runtime readiness
did not verify the helper's owner, `search_path`, `SECURITY DEFINER` or grants —
those were asserted only in the PostgreSQL suite. Both lists now include it, so
readiness fails closed if the helper is missing or misconfigured.
Negative-checked: an intentionally wrong expected signature turns the session
PostgreSQL suite from 62 passed to 1 failed / 61 passed, and reverting restores
62/62.

## The runtime now reaches `enabled`

`apps/api/test/control-action-server-startup.test.ts` wraps the **real**
`startCommerceActionRuntime` rather than stubbing it, and captures the state it
actually returns. Verified: `state === "enabled"`, one pool over
`TENANT_DATABASE_URL`, three stores constructed and initialized exactly once
before `createApp`, service and readiness callback handed over, and the bound
`getCommerceSessionByHash` genuinely reaching the store method. The pool closes
exactly once on shutdown (a double signal still closes once), on init failure,
on `createApp` failure, on listen failure and on a throwing pool. With the flag
off nothing is constructed. Removing any one seam from the object `server.ts`
actually builds yields `built_disabled` with no service, no readiness callback
and zero store side effects.

## Verification on the integrated revision

| Gate | Result |
| --- | --- |
| `@openarc/db` test | 16 files / **339** (was 16 / 332) |
| `@openarc/db` test:postgres | 15 files / **505** (was 15 / 498) |
| `@openarc/api` test:unit | 62 files / **1,124** (was 61 / 1,110) |
| `@openarc/api` test:postgres | 8 files / 129 |
| typecheck, build, ESLint `--max-warnings=0` | exit 0 |

## Integration reconciliation

The packet predated DB12, so its manifest lists ran `0011` then `0013`.
`0012_authorization_grants` was inserted ahead of `0013` in all twelve lists —
including DB12's own `control-grant-store.postgres.test.ts`, which the packet
never saw and which failed the first combined run.
`control-action-read-store.postgres.test.ts` is a tail slice and moved to
`.slice(-4)`; `postgres.test.ts` moved to schema version 13 with synthetic ids
`0014_*`; and `durability.postgres.test.ts` gained the new helper in its
alphabetical inventory.

The packet used a temporary `0012_local_placeholder.sql` while DB12 was still in
flight, because `validateMigrations` enforces contiguous numbering. It was
removed before delivery and its absence was verified by grep and directory
listing.

## Boundary

The action family still ships **DEFAULT OFF** at the API, the web console and
the proxy. Reaching `enabled` means the control surface can serve when
explicitly switched on; it enables no payment, settlement or delivery lane, and
the listing payment lane remains unavailable.
