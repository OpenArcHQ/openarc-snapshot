# PORT-03 commerce-session notifications

Accepted 2026-09-12. Application and test author: OpenCode CLI,
`opencode-go/deepseek-v4.1-flash`. Source base includes accepted DB9 (`3b7de99`).

The worker recognizes exactly three additional notification-only tuples for
commerce-session issuance, exchange and revocation. These validate a canonical
UUIDv4 resource and the existing closed outbox envelope, then use the existing
fenced consume path. They do not initiate payments or any other external action.

Verification from the isolated worker packet:

- Worker units: 41 passed, exit 0.
- Real PostgreSQL worker suite: 12 passed, exit 0. The new case obtains events
  through actual DB9 issue/exchange/revoke transactions, not direct outbox inserts,
  and verifies their distinct mutations, common session resource and single
  completion through the real worker loop.
- Build, typecheck and lint: exit 0.
- Bounded independent diff review: passed. Canonical IDs, closed tuple inventory,
  private-field rejection, abort behavior and secret-free projections checked.

This is component acceptance, not whole-phase or deployment verification.
The public deployment remains the previously accepted PORT-02 revision.
