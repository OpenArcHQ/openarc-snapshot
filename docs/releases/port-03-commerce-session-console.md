# PORT-03 protected session console component

September 12, 2026. Implemented with OpenCode CLI
`opencode-go/deepseek-v4.1-flash`; lead and a separate read-only frontend reviewer
checked the protected client/controller and concrete review closures.

Protected session list/new/detail routes now support explicit issue confirmation,
one-time handoff display, detail revocation, safe receipt recovery after an
unknown response, and no automatic mutation resend. Browser code does not carry
agent bearer credentials or sign transactions. Session capability is independent;
an optional policy picker requires its own enabled capability, otherwise the
canonical policy-ID input remains usable without policy requests.

Review corrections preserve fresh handoff visibility until explicit navigation,
render revocation/status on detail, clear both in-memory raw copies at expiry,
remount drafts synchronously on privacy/context changes, bound and abort policy
pages, filter active policies to the selected agent/organization, and highlight
Sessions for detail routes. Expiry callback uses exact source timestamp
comparison; a millisecond scheduling estimate cannot prematurely erase a
sub-millisecond expiry. Access/copy checks remain separately guarded.

Evidence:

- Final focused client/controller suite: 55 passed, exit 0.
- Web build, typecheck and targeted ESLint: exit 0 on the final timer candidate.
- Before the final isolated timer correction: 582 web unit tests and 34
  synthetic Chromium/WebKit/enabled/disabled browser cases passed. Those are
  supporting prior-candidate results, not a full final-candidate gate.
- Corrected synthetic fixtures use internally consistent future timestamps;
  active detail retains exchangedAt metadata. An expired January fixture was
  rightly rejected by the new UI expiry guard; no application guard was relaxed.
- Same-task pagehide checks inspect actual draft DOM, and disabled routes make
  zero session requests. Synthetic ON fixture tests the manual policy fallback;
  live policy-picker integration is not claimed by that test.
- Root e2e script includes new policy/session suites before the preserved
  market → listings → machine sequence; every prior suite remains once and
  supplied-design remains last. Matches the proxy's 173-guard candidate.

These browser tests use synthetic transport fixtures, not real passkeys,
PostgreSQL or production TLS/nginx. Actual combined production acceptance and
the whole PORT-03 gate remain pending. No remote deployment or flag activation.
