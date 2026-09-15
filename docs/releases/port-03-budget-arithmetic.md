# PORT-03 exact budget arithmetic component

September 12, 2026; source based on private `096f697`. Implemented through
OpenCode CLI `opencode-go/deepseek-v4.1-flash` and reviewed by the lead.

This is a pure arithmetic kernel, not a financial authorization engine. It
cannot reserve funds, approve an action, verify a requirement or issue a grant.
Current listings remain payment-unavailable. Future database transactions must
load complete authoritative inputs under locks and revalidate scope and state.

The stable exposure key excludes policy roots/revisions. Exact BigInt arithmetic
counts committed amounts in `(now - window, now]` and all unresolved reservations
regardless of age. Assessment includes explicit fees, zero/null cap semantics,
existing deficits and approval thresholds; no refund silently replenishes a cap.
Inputs are strict, bounded and non-echoing; timestamps retain nanosecond precision.

Review corrections: action IDs now enforce UUIDv4 rather than versions 1–8;
computed aggregates exceeding the 128-digit DTO bound fail closed rather than
wrap or clamp. No legacy primitives or prior test assertions changed.

Final checks on the accepted candidate, all exit 0:

- 86 focused arithmetic tests.
- 1,065 shared tests across 35 files.
- Shared build, typecheck and ESLint.

Database action/reservation/approval/grant persistence and real concurrency
acceptance remain separate, unfinished PORT-03 work. No deployment claimed.
