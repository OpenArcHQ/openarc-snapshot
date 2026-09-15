# PORT-03 DB11 action and approval read queues

Accepted 2026-09-15 UTC, integrated onto `6a3b87d` alongside DB10. Migration
`0011_control_action_reads.sql` plus `control-action-read-store.ts` add bounded
action and approval pages and approval-by-approvalId detail over accepted DB10.

DB11 is **reads only**: no authority, no mutation, no grant, no payment. Grants
are DB12 (`0012_authorization_grants.sql`), a separate later packet. Migrations
`0001`-`0010` are byte-unchanged, verified by digest.

## Public API

`ControlActionReadStore` exposes `listActions`, `listApprovals` and
`readApprovalById`, returning the frozen shared `CommerceActionPage`,
`CommerceApprovalPage` and `CommerceApprovalDetail` shapes from
`control-action-wire.ts`, strict-parsed before return. DB10's existing
`readApproval` remains keyed by **actionId** and is unchanged; DB11 supplies the
approval-ID lookup the wire contract requires.

## Contract conformance

Canonical string `limit` 1-50 with the default of 25 applied in the store and
the bound enforced again in SQL (SQLSTATE 22023). Lexical keyset cursors over
the existing primary key with a `limit + 1` fetch. Every page item is bound to
the wrapper organization with unique ascending ids, and the cursor is non-null
only for the last returned id when another page genuinely exists. **No status
predicate exists anywhere**, so no status can be silently filtered.

## Lead review

`0011` creates no table, no policy and no `ALTER TABLE`. It adds three
`SECURITY DEFINER` functions granted only to `openarc_tenant_app`, plus
`resolve_action_reader_org`, which is revoked from PUBLIC and deliberately given
**no** runtime grant. No table privilege and no broad grant was added anywhere.

Money columns are declared `text` and passed through as canonical strings;
`Number.parseInt` appears only for the page limit and timestamp components,
never for an amount. `seller_organization_id`, `source_kind` and
`request_digest` are never selected. Current authority is revalidated after the
projection, including the empty and the not-found path.

## Verification on the integrated revision

Focused DB11 checks pass 25/25 unit and 17/17 PostgreSQL. Whole-package gates on
the integrated source, in an isolated container against a dedicated synthetic
PostgreSQL fixture:

| Gate | Result |
| --- | --- |
| `@openarc/db` build, typecheck, ESLint `--max-warnings=0` | exit 0 |
| `pnpm --filter @openarc/db test` | 15 files / **305** tests |
| `pnpm --filter @openarc/db test:postgres` | 14 files / **479** tests |
| `pnpm --filter @openarc/shared test` | 40 files / **1,253** tests |

PostgreSQL assertions cover exact paging in all four cursor cases and a full
traversal returning every row once in ascending order; the default of 25 proven
against 26 seeded rows; rejection of limit 0, 51, `'05'`, `' 1'`, `'1\n'`, `''`
and malformed cursors; cross-organization isolation both ways; denial for
expired, deleted and recovery-method sessions and for viewer, demoted and
suspended members, including on zero-row and not-found paths; all five action
and four approval statuses returned in one page; exact key-set assertions plus a
negative check that the stored digest, provenance, seller organization, commerce
token hash and session hash appear nowhere in the output; and unchanged row
counts **and** `md5` digests across a batch of reads.

## Integration reconciliation

Adding `0011` required appending it to the nine hardcoded migration-manifest
lists and to DB10's applied-migration assertion, and adding DB11's four new
definer helpers to the exact helper inventory in `durability.postgres.test.ts`.
`postgres.test.ts` moves to schema version 11 with synthetic ids `0012_*`. Both
new DB11 test files are registered in `packages/db/package.json` so the repo
gate actually runs them — the package `test` script now lists 15 files and
`test:postgres` lists 14.

One transient failure was observed and investigated rather than suppressed: a
`beforeEach` hook timeout in `market-lifecycle-store.postgres.test.ts` during a
loaded sequential run. Run alone the file passes 48/48 in 13 seconds, and a
clean full run passes 479/479, so it is fixture contention under concurrent
workers, not a schema regression. No timeout was extended and no assertion was
relaxed.

## Deliberately not covered

Read behaviour under a competing concurrent writer is not exercised; these reads
take no lock beyond the `organizations`/`memberships` lock DB10's
`lock_action_reader` already takes. Nothing grant-shaped is implemented here.

## Boundary

Persistence reads only. No HTTP, transport, grant, payment, settlement or
delivery. The listing payment lane remains unavailable. Whole PORT-03 acceptance
and publication remain pending, and worker consumption from real action
lifecycle transactions in PostgreSQL is still outstanding.
