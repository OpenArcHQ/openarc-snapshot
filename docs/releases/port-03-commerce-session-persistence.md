# PORT-03 commerce-session persistence acceptance

September12, 2026. Local component acceptance, authored using exact OpenCode
`opencode-go/deepseek-v4.1-flash`. Lead store/integration review and independent
SQL/race review completed; no live route, deployment or payment claim.

Migration9 adds hash-only human-to-agent handoffs and short-lived commerce-session
bindings. Issuance requires fresh authorized human proof; exchange binds the exact
agent session and credential, checks both current parent chains and only shortens
expiry. Revoke/history remain possible when an original sponsor session is gone.
Logout/recovery can delete auth sessions without deleting durable commerce history.

The accepted base passed 257 database unit tests and all 408 real PostgreSQL
tests. Final narrow output-nullness closure and integration of the previously
accepted policy regression then passed 38 focused session units, 53 real session
PostgreSQL cases, 31 policy PostgreSQL cases, build, type checking and lint.
All commands exited0. The 408/257 full suites were not rerun after the two
nullness checks; their unchanged-path evidence is supplemented by the final
focused runs. A later combined phase gate remains required.

Review closure covers canonical cross-parent lock order, current requester checks
before replay, DB-derived expired/invalidated status, immutable metadata and
exact output bindings, final temporal checks, RLS/ACL and exact readiness objects.
Real PostgreSQL races include opposing sponsor/issuer accounts, blocked expiry,
same-action replay and durability rollback. Unknown commit stays unknown.

Testing found default PostgreSQL-to-JavaScript Date conversion truncating
microseconds. Store SELECT projections now preserve timestamp text; the genuine
one-microsecond regression remains intact. No global driver or schema weakening
was used. Explicit database nulls are distinct from malformed undefined outputs.

The public HTTP/runtime, session console, notification handlers and the financial
reservation/approval/grant engine remain separate pending tasks. Existing machine
credentials keep their read-only scopes; these tables do not execute payments.
