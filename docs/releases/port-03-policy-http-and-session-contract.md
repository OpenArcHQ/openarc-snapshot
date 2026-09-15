# PORT-03 policy HTTP and commerce-session contract acceptance

September 12, 2026. Local foundations only; not a completed control phase or
deployed financial authorization system. Existing staging flags remain off.

## Policy HTTP

Exact OpenCode `opencode-go/deepseek-v4.1-flash` authored the three protected
policy modules and two test files. The accepted closure passed 48 focused tests,
761 API unit tests, type checking, build and focused lint (all exit 0). Existing
API test auto-discovery remains unchanged. Runtime registration, actual API
PostgreSQL and production browser verification are separate upcoming gates.

Lead service review and independent route review covered strict result binding,
cookie/CSRF transport, raw duplicate headers, one-write unknown-outcome handling
and read completion checks. Closure adds cross-organization body rejection,
successful encoded canonical IDs, unsupported-method coverage and a single
explicit authentication-context source. No retry or financial enforcement added.

## Commerce-session pure contract

The same exact CLI model authored strict session metadata, one-time delivery,
status, list, receipt and mutation schemas. Accepted closure passed 95 focused
tests, 955 shared tests, type checking, build and focused lint (all exit 0).
Independent review's outer status organization binding finding is closed with
a regression. Contracts alone grant no authority and do not change existing
read-only machine credential scopes.

One-time human-approved handoffs and separately namespaced session tokens are
specified without storing raw tokens in persistence. Actual persistence,
exchange, reservation, approval, grant and payment execution remain unbuilt at
this checkpoint; do not describe these schema tests as integration evidence.

## Session token primitives

The isolated, unregistered token module has now passed lead review and 30 focused
tests, type checking and lint (all exit 0). Exact OpenCode DeepSeek authored it.
It uses 32-byte Node CSPRNG secrets, accepted distinct handoff/session namespaces
and purpose-separated SHA-256 hashes including the full token. No pepper, new
operational key, logging, persistence or authorization is added by this module.
The combined API gate will cover it before phase acceptance.
