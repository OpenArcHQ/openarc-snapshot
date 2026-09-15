# PORT-03 commerce-session proxy component

Accepted against private integration `096f697`, September 12, 2026. This is
component evidence, not whole-phase acceptance, image acceptance or deployment.

Exact implementation worker: OpenCode CLI `opencode-go/deepseek-v4.1-flash`,
isolated session-proxy packet. Lead and read-only backend reviewer checked the
result. The review correction makes POST exchange body forwarding explicitly
`on`, GET status explicitly `off`; shared parameters do not override either.

The default-off build flag installs the five protected human routes and two
headless agent routes independently of policy/machine/market HTTP flags. The
credentialless capability route remains available. Disabled/malformed routes
cannot fall through to the SPA. Agent requests reject browser credentials and
metadata, preserve only the exact required headers, verify upstream TLS and
disable retry/cache/disk buffering. API authorization remains authoritative.

Evidence from final worker candidate:

- 20 session deployment guards passed; ESLint passed.
- Complete deployment/CI guard selector: 173 passed, zero failed, exit 0.
  This run included the separately owned UI candidate's root package script
  ordering correction: policy/session suites precede the preserved contiguous
  market → listings → machine sequence, with supplied-design suite last.
  The initial proxy bridge omitted CI wiring tests; its earlier 138-test result
  is not represented as the complete guard run.
- Actual session production-image and upstream/browser acceptance is pending
  the combined UI/API candidate. Earlier policy image results do not substitute.

No flags enabled remotely, no hosted resources added, no payments initiated.
