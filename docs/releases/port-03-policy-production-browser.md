# PORT-03 policy production-browser acceptance

September12, 2026. Exact application/image source:
`23ed02de1356c5c411ac57db5111c0f94700a32a` (schema8). Separate ON/OFF production
API and nginx images use real passkey authentication, guarded disposable
PostgreSQL and verified upstream TLS. No real account, wallet, funds or provider.

Exact OpenCode `opencode-go/deepseek-v4.1-flash` authored four fixture/config
files. Independent evidence review and lead closure review accepted:

- Real owner passkey signup, policy creation, immutable revision append/read,
  pause/resume/revoke and independent durable receipts.
- Real operator write; viewer reads a known policy created through the owner UI,
  has no write controls, and a valid-session/CSRF write is denied403 without rows.
- Independent database commit established before deliberately losing its HTTP
  response. Explicit original-mutation status recovers the receipt. An
  unconditional request observer counts every policy POST, including requests
  that never receive a response: exactly one across submission and recovery.
- Feature OFF preserves real account/tenant reads, makes no automatic control
  requests, reports strict built_disabled capability, and denies business paths
  at nginx without serving the app shell.

The stable base passed three ON journeys (14.8s) and one OFF journey (2.3s), plus
fixture type checking, lint and four-test discovery. A final one-predicate
counter correction then passed the focused lost-response journey (4.3s), types
and lint. All exited0. The other unchanged journeys were not redundantly rerun.
No successful HTTP mocks, authentication-cookie injection or fabricated policy
receipts were used. Virtual passkeys are fixture devices, not user devices.

The original OFF test incorrectly expected an API JSON404. Accepted OFF nginx
uses a local HTML404 deny response; the fixture now checks the exact denial,
expected404 title, no app root/scripts/assets and no success payload. No app or
proxy change was required. A transient runner timeout during a build step was
followed by a successful complete run; it was not an application assertion failure.

This establishes policy journeys at the stated source, not later schema9/session
HTTP or whole-control/payment acceptance. Combined phase gate and deployment
remain pending; existing staging enrollment/payment flags stay off.
