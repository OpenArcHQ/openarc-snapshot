# PORT-03 commerce action and approval console

Accepted 2026-09-15 UTC, integrated onto `e496d22`. Adds the protected action
and approval console under `/app/actions`, implementing backlog item P03-05.

**The console ships DEFAULT OFF** behind `VITE_COMMERCE_ACTIONS_ENABLED`.

## Routes

`/app/actions` (action queue), `/app/actions/approvals` (approval queue),
`/app/actions/exposure`, `/app/actions/:actionId`, and
`/app/actions/approvals/:approvalId`. The literal `approvals` and `exposure`
segments are matched before the dynamic branch, and ids are decoded once and
must round-trip their own canonical encoding.

`App.tsx` needed no change: it already routes `/app/*` to the lazily loaded
`TenantApp`, so public routes still mount no private client.

## Availability gate

`commerceActionsEnabled` requires the action flag to be exactly true **and**
account access, tenant reads and the API boundary all enabled. Every input
defaults to false. It deliberately does not depend on the writes, machine,
listing, policy, session, vault, wallet or market flags.

With the flag off, no controller, no client and no stylesheet is constructed and
**zero** requests are made, including the capability probe. With the flag on but
the public `commerce_action_management` capability not `enabled`, or the probe
itself failing, the console renders an explicit unavailable state that states no
empty queue is implied, and still issues no action request.

## Money and status discipline

The client calls exactly the nine browser routes, built from the frozen
`ACTION_ROUTES` registry; the three agent-audience routes are refused before a
request object exists and are exported as `ACTION_AGENT_ROUTE_IDS` so the
exclusion is testable. Every response passes the accepted shared envelope and
schema, and anything that fails to parse becomes `invalid-response`.

Amounts are handled as exact atomic strings with no `Number`, no `parseFloat`
and no rounding anywhere in the controller.

## Lost-response recovery

A decision whose transport or 5xx response is lost maps to `outcome-unknown`,
retaining the original mutation id, idempotency key, operation and action id.
The UI states plainly that the outcome "is not a success, not a failure, not a
refund and not a release", and offers a single explicit **Check status once**
button that issues one GET against the mutation-status route with the
**original** mutation id. A `not_found` stays unknown; only a receipt bound to
that exact mutation, operation and action becomes committed. Nothing is ever
resent and no new key is minted.

Proven by "offers only an explicit status re-check after a lost response and
issues no automatic retry", which asserts exactly one POST and an unchanged
total call count both immediately and after draining timers and microtasks.
There is no `setTimeout`, `setInterval`, retry or resubmit path in the
controller.

## Deliberate design decisions

Exposure labels follow the accepted schema rather than the requested wording.
`CommerceExposureViewSchema` has **no expired-amount field**, so none was
invented: the five rows are Available, Reserved-not-resolved, Committed, Total
exposure and Over-the-cap-by, each showing the exact atomic string alongside its
decimal placement. Expiry is reported per action through its `expired` status
and `expiresAt` rather than as a fabricated balance. A null `availableAtomic`
renders "No rolling cap", never `0`.

Viewers may read actions but decision controls are hidden for them, and
`canDecide` is additionally forced false once the server returns `FORBIDDEN`,
with a message stating that the server, not the local role guess, decides.

## Verification on the integrated revision

| Gate | Result |
| --- | --- |
| `@openarc/web` typecheck, build, ESLint `--max-warnings=0` | exit 0 |
| `pnpm --filter @openarc/web test` | 43 files / **668** tests (baseline 40 / 583) |

No existing test or assertion was modified.

## Known gaps, deliberately open

There are **no DOM-rendering tests**: the web package has no jsdom or
happy-dom environment and none of the 40 baseline files render React, so none
was introduced. The "no secret reaches the DOM" requirement is therefore covered
at the model boundary instead — `actionDisplayFields` provably omits
`requirementDigest` (asserted present on the record and absent from every
rendered field), and after a full approve the serialized controller state
contains no CSRF token, idempotency key or authorization value. The panels
render only from those field lists. This is weaker than an actual DOM scrape and
is recorded as such. `requirementDigest` does remain in the controller's
in-memory parsed record, since it is part of the accepted metadata; only the
display layer omits it.

The exposure agent/policy selector is a manual canonical-id form rather than a
bounded picker, and there are no Playwright end-to-end specs for the new routes.

## Boundary

No payment, settlement or delivery is displayed or implied anywhere. An approval
is not a payment and a reservation is not a settlement. The console is gated off
by default, the API family is gated off by default, and the listing payment lane
remains unavailable. Whole PORT-03 acceptance and publication remain pending.
