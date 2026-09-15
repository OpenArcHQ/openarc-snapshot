# PORT-03 commerce-session runtime acceptance

Accepted 2026-09-12, exact OpenCode CLI `opencode-go/deepseek-v4.1-flash` author.
Combined source includes accepted HTTP714ace8 and DB9, not the earlier runtime
packet's pre-closure HTTP copy.

COMMERCE_SESSIONS_ENABLED defaults off. Enabled runtime requires account auth
and a dedicated restricted tenant database, but does not require tenant,
machine, policy or marketplace HTTP features to be enabled. One restricted
pool backs DB9 and current-agent-session reads. Startup failures close it;
readiness uses retained single-flight probes with a two-second deadline and
cannot become ready after closure. Startup does not migrate the database.

The separate credentialless session-capability endpoint is always registered.
It reports both frozen families disabled without probing when off, or shares
the actual auth/DB9 readiness when on. Seven protected routes retain their
human/agent boundaries and v2 errors, privacy headers and coarse metrics.

Verification, all exit 0:

- 59 focused runtime/config/capability/app/startup tests.
- 126 combined runtime plus HTTP tests after the accepted HTTP overlay.
- Full API unit suite on final combined source: 54 files, 980 tests passed.
- Build, typecheck and lint passed.
- Independent app/config/server review and lead runtime/capability review.
  The capability classification omission found during review was fixed and
  covered by actual-app metric and forced unexpected-error regressions.

Tests here use honestly mocked DB runtime seams; the separate real API/PG
packet is still required. No deployment or financial execution is claimed.
