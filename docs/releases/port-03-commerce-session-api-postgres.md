# PORT-03 real session API / PostgreSQL acceptance

September 12, 2026. Actual accepted HTTP/runtime source `096f697` and schema9,
plus the narrow unpublished schema9 correction described below. Implementation
and tests: OpenCode CLI `opencode-go/deepseek-v4.1-flash`. Lead review and a
separate read-only API/security review accepted all concrete closure items.

The suite uses real AuthService/cookie/CSRF, session runtime, durable rate
limiter, CredentialStore, ControlPolicyStore and CommerceSessionStore over
restricted PostgreSQL roles. Human setup seeds synthetic sessions with a mocked
proof adapter: this is NOT real WebAuthn/browser acceptance. All commerce
sessions, handoffs, receipts, audit and outbox records originate through HTTP,
not direct fixture insertion. Machine session tokens use production hashing.

Covered: owner/operator lifecycle; exact replay without second secret; current
parent/credential/session authority; viewer/provider/stale/recovery denial;
cross-tenant/agent isolation; concurrent single-use exchange; real outbox failure
rollback; postcommit response loss with original-status recovery and no resend;
post-read revocation for committed and missing results; pagination and safe
projections; session-only runtime independence and disabled registration.

Review found a real receipt confidentiality gap: SQL9's human status reader
previously bound the account but not the exact presenting human session, and
included agent exchange receipts. The unpublished function now requires the
exact operation-domain/session SHA-256 context for issue/revoke only. SQL1–8
are byte-unchanged. Both API and database tests prove that a second live session
of the same account receives `not_found`, the original retrieves its receipt,
and human readers never retrieve machine exchange receipts. Agent reader
authority is unchanged. Fresh delivered secrets match their exact production
hashes and version1 in PostgreSQL.

Final checks, all exit 0:

- 26 focused real API/PostgreSQL tests.
- 55 focused DB9/PostgreSQL tests (two added regressions).
- Complete API PostgreSQL suite: 129 tests across eight files.
- API build, typecheck and targeted ESLint.

An initial DB-focused runner referenced a nonexistent config. Correcting the
lead-owned bridge to use the existing default config resolved that harness
failure; no application/config workaround or assertion weakening was made.

Combined production-image/browser and whole-phase gates remain pending.
No payment authority, production enrollment, hosting resource or remote flag
was enabled by this component.
