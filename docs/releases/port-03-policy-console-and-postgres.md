# PORT-03 policy console and real PostgreSQL acceptance

September 12, 2026. These are local component results, not whole-port or live
payment acceptance. Source authored through OpenCode
`opencode-go/deepseek-v4.1-flash`; lead integration and focused independent review.

## Policy console

The protected budgets routes now manage immutable policy revisions and
pause/resume/revoke, with exact USDC inputs and explicit policy-only wording.
There are no fabricated spent/reserved balances or transaction execution claims.
The default-off UI retains supplied styling and existing workspace navigation.

The accepted candidate passed 72 focused client/controller tests, 528 web unit
tests and 38 synthetic browser contract tests (Chromium and WebKit enabled,
Chromium disabled), plus build, type checking and lint, all exit 0. These browser
fixtures do not establish real API or production authentication acceptance.

Review closure enforces response/request organization and mutation bindings,
original-ID-only recovery after uncertain writes, and synchronous form remount
across account/organization/role/privacy-generation changes. Independent review
accepted the form-state fix. Existing suppression also clears tested contexts;
the new key provides direct same-render remount rather than relying on it alone.

## Real policy API and database

The final real PostgreSQL candidate passed 21 policy API cases and all 103 API
PostgreSQL cases, plus API build/type checking/lint. A focused database run then
passed 31 policy persistence cases, including the new exact-session regression.
All exited 0. The authentication proof adapter is a test adapter; the API,
stores, SQL, RLS, locks and durable records are real.

Testing exposed mutation-status lookup binding only to the account, not its
exact presenting session. A narrow correction to the unpublished migration 8
now matches the existing per-operation session digest. A second live session of
the same account cannot retrieve or replay the original session's receipt;
the original session still can. Cross-organization agent rejection is also
exercised with matching request path/body and a genuinely foreign subject.

One disposable PostgreSQL fixture exhausted its 1 GiB tmpfs. It was preserved
and replaced with a fresh disk-backed synthetic database; no application checks
were weakened and no real database, hosted service or funds were used.

Actual combined-image passkey-to-policy browser journeys, commerce-session
persistence and the rest of PORT-03 remain separate pending acceptance work.
