# PORT-03 policy persistence foundation

Accepted bounded database packet, September12, 2026. Implementation and tests
were written by DeepSeek V4.1 Flash through OpenCode CLI, with independent SQL
review and lead repository/projection review. This is policy management, not a
financial reservation or payment engine.

Schema8 adds immutable policy revisions and stable policy roots, scoped to a
payer organization and agent. Only one root can be active for that subject.
Owner/operator mutations require current fresh, non-recovery human authority.
Reads allow owner/operator/viewer. External provider/listing allowlists do not
require ownership by the payer organization. Fixed Arc Testnet USDC units and
canonical exact amounts are independently validated in SQL.

Each create, revision, pause, resume and revoke is atomic with its idempotency,
audit and outbox records. Existing-root changes compare both revision and
microsecond-precision update time. Safe committed receipts remain recoverable
after later policy changes. Unknown commit results never automatically retry.
Revision history exposes bounded summaries; explicit revision reads expose the
full rule content. Runtime roles have no direct table access.

Final focused verification:40 unit tests and30 real PostgreSQL tests passed,
plus build, typecheck and lint. Coverage includes role/isolation boundaries,
lock-wait expiry, rollback, immutable history, one-winner create/append/lifecycle
races and no loser durability residue. Healthy readiness and tampered required
constraints/triggers/helpers/indexes are tested. Strict input, receipt tuple,
revision boundary, history subject and lookahead-page projections are covered.

The prior reviewed candidate passed215 complete DB unit tests and354 complete
DB PostgreSQL tests. Subsequent changes were the focused projection and
concurrency-evidence closures above; they did not edit SQL or old migrations.
The final combined PORT-03 gate remains pending consumer integration. Do not
present the prior full-suite run as verification of that later combined revision.

No scoped commerce token, reservation, grant, provider call, signing or broadcast
was added. Earlier migrations remain byte-identical.

Notification-worker integration is accepted on the DB8 foundation:35 worker
unit tests and11 real PostgreSQL tests, plus build/typecheck/lint, passed. The
new fixture creates the policy and revision and performs pause/resume/revoke
through the real store, then consumes and acknowledges exactly five durable
events without replay duplication. No direct outbox insertion or mocked success
is used. Closed event/resource validation and private-canary rejection passed
independent review. Consuming a notification does not execute a business action,
send a message or dispatch a payment.
