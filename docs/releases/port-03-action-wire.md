# PORT-03 action and approval wire contracts

Accepted 2026-09-13 UTC, based on `5b43815`. Three shared files add strict
action/approval requests, safe mutation receipts/status, bounded pages/detail
responses and exact budget-exposure projections with v2 envelopes.

Verification: 55 focused tests and all 1,193 shared unit tests passed on the
stable candidate; shared build, typecheck and ESLint exited 0. Lead review
closed an unrequested mutation-status wrapper mismatch before final tests.
Status now matches the DB contract exactly: committed receipt or not-found.

Tests cover cross-organization/ID binding, canonical cursors and ordering,
strict unknown-field rejection, explicit undefined optionals, exact large
integer sums, malformed values, deficit/null-cap semantics and private fields.
Rolling-window bounds reuse the accepted 2,592,000-second maximum. No transport,
authorization, SQL, payment, deployment or capability activation is introduced.

All fields remain organization-protected. Parsing a response is not proof of
current authority or an available payment lane. Whole PORT-03 acceptance and
publication remain pending.
