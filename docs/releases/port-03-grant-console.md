# PORT-03 authorization-grant console

Accepted 2026-09-15 UTC, integrated onto `5b89508`. Adds the buyer-facing grant
surface under `/app/grants`, **DEFAULT OFF** behind
`VITE_COMMERCE_GRANTS_ENABLED`, which additionally requires account access,
tenant reads, the API boundary, commerce sessions and commerce actions.

## Routes

`/app/grants` looks a grant up by exact canonical id; `/app/grants/:grantId`
shows detail and the revoke flow.

**There is deliberately no list or queue route.** `ControlGrantStore` exposes no
list method and the frozen registry publishes no browser list endpoint, so a
queue would mean inventing data. The lookup issues zero requests until an
operator submits a canonical id.

The client calls exactly the three `commerce_grant_management` browser routes
and exports `GRANT_BROWSER_ROUTE_IDS`, `GRANT_AGENT_ROUTE_IDS` and
`GRANT_PROVIDER_ROUTE_IDS` so the exclusion is testable; `routeTemplate` refuses
any non-browser id before a request object exists. A test asserts the nine
frozen routes partition exactly 3/3/3 and that the client's prototype surface is
exactly `constructor/readGrant/readMutationStatus/revoke`.

## The copy that matters most

A claimed grant that is later revoked must never read as a refund. Verbatim:

> "This grant was claimed before it was revoked. Revoking it did not undo the
> claim: the claim fact is retained, the held exposure is retained, and this
> grant may still have been paid. Revocation is not a refund, not a release and
> not a cancellation of payment. This console is not told whether payment,
> settlement or delivery happened, so it does not say."

Proven by "renders the claim-retained, may-have-been-paid state and never a
refund", which asserts each required phrase, that `claimedAt` and `revokedAt`
survive as rendered fields, and that seven refund/reversal patterns never match.
The never-claimed case is worded as a cap adjustment, not a refund: "Releasing a
hold is a cap adjustment, not a refund: no money moved and none was owed."

## No implied payment, proven non-vacuously

A detector splits every exported copy string into sentences and flags any
money or fulfilment word (`pay|paid|settle*|deliver*|refund*|releas*|purchas*`)
in a sentence lacking a hedge or negator, running over roughly ninety strings —
labels, explanations, all seventeen display fields across five record shapes and
two clocks, all ten rejection messages and every outcome label.

Critically, a **self-check test proves the detector fires** on strings like
"This grant was paid.", and asserts that more than eight corpus strings genuinely
contain money words. The guard therefore cannot pass vacuously.

## Lost-response recovery

A failed or 5xx revoke becomes `outcome-unknown` holding the frozen original
mutation id, organization and grant. The only exit is a user-clicked
`checkRevokeStatus()` GET against the mutation-status route with that same id.
No resend, no new key, no polling, no backoff. A recovered committed receipt
carries no release flag, so `released` and `actionStatus` are stored as null and
render as unknown rather than an implied release.

Proven by "offers only an explicit status re-check after a lost response and
issues no automatic retry" (drains sixty microtasks plus real macrotasks) and
"issues no request at all after a lost response even once every timer has fired"
(fake timers advanced 600 seconds plus fifty microtask turns, call count
identical). Verified at integration: the controller contains no `setTimeout`,
`setInterval`, retry or resubmit path — the only textual matches are comments
and one user-facing "Do not resubmit." string.

## Expiry, roles and money

Expiry state takes the clock as an explicit parameter; a lagging server record
past `expiresAt` renders as no longer claimable, and an unparseable clock **fails
closed to expired**. The exact `expiresAt` is always shown beside the instant it
was compared against. No countdown, no timer.

A viewer reads but cannot begin a revoke, with zero requests; a server 403 sets
`serverDeniedRevoke` and flips `canRevoke` false, so the local role guess never
stands against the server.

The browser wire carries **no money field at all** — grant metadata has no
amount, fee or debit — so there is nothing to format. Verified at integration:
no `Number`, `parseFloat` or rounding call exists in the controller; the only
textual match is a comment asserting their absence.

## Verification

| Gate | Result |
| --- | --- |
| `@openarc/web` test | 46 files / **764** (was 43 / 668) |
| typecheck, build, ESLint `--max-warnings=0` | exit 0 |

No existing test or assertion was modified.

## Stated plainly — not covered

The "no secret in the view" requirement is covered at the **model boundary
only**. The web package has no jsdom or happy-dom environment and no existing
test renders React, so there is **no DOM-level assertion**. What is asserted: the
client refuses any payload containing `oag_v1_` material or a
`grantToken`/`token`/`secret` key; no display field key or value contains
`oag_v1_`, `sha256:` or matches `token|secret|hash|digest|cookie|csrf`; the field
list is an exact positive allowlist of seventeen keys; and the serialized
controller state contains no idempotency key, CSRF value, digest or cookie.

For the same reason the flag-off wiring in `TenantApp` is not render-tested. The
gate's default-false behaviour and the controller's zero-request behaviour are
tested; "the component never constructs the controller" is verified by reading
the code, not by a test.

## Boundary

Default OFF at the console, the API and the proxy. No payment, settlement or
delivery is displayed or implied anywhere.
