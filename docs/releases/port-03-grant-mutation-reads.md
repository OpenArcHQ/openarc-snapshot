# PORT-03 DB14 grant mutation-status reads

Accepted 2026-09-15 UTC, integrated onto `be0d745`. `0014_grant_mutation_reads.sql`
adds the two readers that were the last blocker preventing the authorization-grant
family from being enabled.

Migrations `0001`-`0013` verified byte-identical by SHA-256.

## Why this existed

The frozen registry publishes `agent_grant_mutation_status` and
`grant_mutation_status`, the API implemented both end to end, but DB12 declared
no grant mutation-status helper, so the adapter returned a fixed 503. **The
grant console's lost-response recovery depends on the browser one** — it is how
a buyer learns whether a revoke that lost its response actually committed.

## The readers

```sql
read_human_grant_mutation_status(human_session_hash text, organization_id text, mutation_id uuid)
read_agent_grant_mutation_status(commerce_token_hash text, mutation_id uuid)
```

Both `STABLE SECURITY DEFINER`, `SET search_path = pg_catalog`, `REVOKE ALL ...
FROM PUBLIC` then `GRANT EXECUTE` to `openarc_tenant_app` only. No table, policy,
`ALTER`, role or broad grant. The agent reader derives its organization from the
presented commerce session and returns it, never taking it as an argument.

Store methods mirror DB10's, discriminated by an explicit
`CommerceGrantStatusAudience = 'human' | 'agent'`. **DB10's transposable
`agent: boolean` shape — which caused a real defect where every committed human
receipt became a fixed `UNAVAILABLE` — is deliberately not reintroduced.**

## Audience split, and why the obvious barrier was not enough

`0012` records exactly four operations. Agent recovers **issue** and **replace**
(both authenticate the `oacs_v1_` commerce bearer); human recovers **revoke**
(the browser lane). **Claim belongs to neither** — it is seller-side and already
has its own keyed recovery read, `read_provider_grant_attempt_status`. This
matches the accepted wire schemas exactly.

The important finding: **the operation filter alone is insufficient.** The issue
and replace cores record the buyer's *parent human account* as
`actor_account_id`, so a buyer cookie genuinely matches the actor column on
agent-lane rows. Separation therefore rests on two independent barriers, both
applied: the closed operation filter **and** the per-operation
`session_context_digest` binding the exact presented hash. A PostgreSQL test
asserts all three receipts really do carry the buyer's account, so the second
barrier is proven **necessary rather than assumed**.

## Proofs

All closed: committed human revoke and committed agent issue/replace recover
their exact receipts, compared against what the mutation itself returned;
unknown ids return a bare `{status:'not_found'}` with `Object.keys` exactly
`['status']`; neither audience can recover the other's; wrong organization,
co-owner, a second live session of the same buyer, and foreign commerce tokens
are all refused or indistinguishable while the original still recovers; revoked
and expired sessions are denied on both lanes; authority is revalidated on the
not-found path, proven by a real lock-wait harness plus a structural
`pg_get_functiondef` assertion that each reader invokes its preamble twice with
the last invocation before `RETURN NEXT`; no 64-hex value survives any answer;
the read mutates nothing, compared by counts **and** an `md5` digest over eleven
durable tables; and `PUBLIC` holds no EXECUTE while a live `openarc_worker_app`
connection is refused `42501` on both functions.

## Lead addition: readiness now covers both readers

As delivered, the two readers were absent from `#assertHelpers`' production
inventory, so `initialize()`/`readiness()` did not assert their existence,
owner, `search_path`, `SECURITY DEFINER` or grants — a missing function would
have surfaced late as a `42883` mapped to `UNAVAILABLE` rather than failing at
readiness. Both are now listed. Negative-checked: an intentionally wrong
expected signature turns the grant PostgreSQL suite from 27 passed to 1 failed /
26 passed, and reverting restores 27/27.

This is the second time a packet delivered a new definer helper without
extending its store's readiness inventory. Worth building into the next
migration brief.

## The API now serves real receipts

`grant-store-adapter.ts` binds both ports to the real store and the
`GrantMutationStatusUnavailableError` stub class is **deleted** — verified
absent. Against real PostgreSQL both calls now produce a genuine authority
refusal, explicitly not `UNAVAILABLE`, not `INPUT_INVALID` and not
`OUTCOME_UNKNOWN`, which a stub short-circuiting before SQL could not produce.

## Verification

| Gate | Result |
| --- | --- |
| `@openarc/db` test | 16 files / **346** (was 339) |
| `@openarc/db` test:postgres | 16 files / **535** (was 527) |
| `@openarc/api` test:unit | 68 files / 1,225 |
| `@openarc/api` test:postgres | 9 files / 134 |
| typecheck, build, ESLint `--max-warnings=0` | exit 0 |

API counts are flat because the two stub tests were replaced one-for-one with
strictly stronger assertions rather than added.

## Not covered

No single end-to-end test runs adapter → real PostgreSQL → *committed* receipt;
the chain is proven in two links, because the API PostgreSQL adapter suite
deliberately runs against an unseeded tenant. The post-read recheck has no test
that deterministically fails the second preamble while the first succeeds, since
the two are identical with no interleaving point — the same limitation the
existing DB3 and DB10 revalidation tests carry.

## Boundary

The grant family still ships **default OFF** at the database, API, proxy and
console. Its recovery path now answers truthfully instead of 503, which was the
condition for enabling it at all.
