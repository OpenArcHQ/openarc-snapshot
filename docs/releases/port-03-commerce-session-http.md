# PORT-03 commerce-session HTTP component

Accepted 2026-09-12, authored through OpenCode CLI
`opencode-go/deepseek-v4.1-flash`. Base includes DB9 and the separate seven-route
session registry. This commit exports the HTTP registration but does not yet
wire it into the server.

The five human routes use the existing cookie/Origin/CSRF account boundary.
The two agent routes accept only an existing agent-session bearer. Exchange
passes hashes into one DB9 transaction, with no credential preflight that would
change its lock order. Durable purpose-separated rate limits precede token
creation. Fresh issue/exchange returns one-time material; replay and uncertain
outcomes never manufacture replacement secrets.

Human reads revalidate the original session before returning data, including
null results. Agent status binds the current machine identity before and after
the read. Whole database-result validation includes organization, exact keys,
receipt and resource bindings, current machine versions and original handoff
expiry even on historical replay.

Verification:

- Initial implementation: 49 focused tests, 903 API units, build/typecheck/lint
  passed. This full-unit run predates the bounded review closure below.
- Final review closure: 67 focused tests (37 service, 23 route, 7 limiter),
  build/typecheck/lint passed, all exit 0. The closure covers wrong/null-result
  organization, whole machine projection and version/issuer drift, replay
  expiry, default list bound, raw duplicate credential headers, wrong methods,
  size limits and no-store/no-cookie/no-CORS responses.
- Bounded route review found no material route-code defect; lead reviewed
  service ordering/projection and the final targeted fixes.

These are honestly mocked service/store boundary tests. Real PostgreSQL API,
runtime, proxy and production-browser acceptance follow on the combined source.
No payment, signing, wallet or financial-reservation behavior is enabled here.
