# PORT-03 commerce-session production acceptance

Accepted 2026-09-13 UTC. Application source:
`8cfc3efa150692eb0e1fea6bd590fbcb1fd2e90c` (SQL migrations through 0009).
The tests in this commit ran against real production API and ON/OFF nginx
images built from that source, isolated PostgreSQL, and verified upstream TLS.
They did not run against Railway or change its configuration.

## Evidence

- Four ON browser journeys and one OFF journey passed on the stable test
  candidate; Playwright registration lists exactly five tests.
- Focused owner, role, lost-response and proxy runs passed. ESLint and test
  TypeScript checks exited 0.
- Real passkey signup via a virtual authenticator; no cookie injection or
  successful HTTP mocks. Synthetic organization/agent/membership preconditions
  and real policy/credential/machine-session store calls are explicitly fixture
  setup, not user-facing onboarding evidence.
- The owner creates a session through the UI, receives a one-time handoff,
  exchanges it through nginx using a real machine bearer, verifies exact stored
  hash/binding via boolean observations, reads the original agent mutation,
  tests replay without secret re-delivery and revokes through the UI.
- A real same-organization wrong-agent bearer cannot consume the handoff. Nine
  independent browser-metadata header variations and a wrong token namespace
  are denied on otherwise-valid requests with zero committed durability. The
  rightful bearer then exchanges the same unconsumed handoff successfully.
- Operator lifecycle succeeds; a viewer receives an actual API denial on a
  known same-organization session, not a missing-resource false positive.
- The lost-response test independently observes the real issue commit before
  applying a CDP response-stage failure. Explicit recovery uses the original
  mutation GET, with exactly one total session POST and no recovered secret.
- OFF preserves real account signup, reports `built_disabled`, makes no
  automatic session business calls and denies session paths without SPA fallback.

Raw synthetic tokens remain transient test memory; only bounded, non-secret
observations leave fixtures. Node requests enforce the two fixed loopback ports
at runtime and verify the fixture CA/SNI. No personal wallet, real funds, new
hosted service or deployment was used.

Lead browser review and a separate read-only fixture/TLS review were completed;
the identified lost-response counting, valid-negative counterproof and fixed-port
guard gaps were closed before the final passing runs. These are bounded agent
reviews, not an independent professional security audit.

This accepts the session production slice only. The whole PORT-03 gate,
publication/deployment, action budgets/grants and later port phases remain
separate work. No payment or mainnet readiness is implied.
