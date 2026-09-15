# PORT-03 grant wire and capability contracts

Accepted 2026-09-15 UTC, integrated onto `96d5e4d`. Adds the strict grant
request, receipt, status and detail shapes plus the frozen nine-route capability
manifest. These are the contracts the grant API, proxy and UI will be held to.

## Frozen route table

| id | method | path | audience | family |
| --- | --- | --- | --- | --- |
| `grant_issue` | POST | `/v2/agent/commerce-grants` | agent | `commerce_grant_authorization` |
| `grant_replace` | POST | `/v2/agent/commerce-grants/:grantId/replace` | agent | `commerce_grant_authorization` |
| `agent_grant_mutation_status` | GET | `/v2/agent/commerce-grant-mutations/:mutationId` | agent | `commerce_grant_authorization` |
| `provider_grant_introspect` | POST | `/v2/provider/grants/introspect` | provider | `commerce_grant_claim` |
| `provider_grant_claim` | POST | `/v2/provider/grants/claim` | provider | `commerce_grant_claim` |
| `provider_grant_attempt_status` | GET | `/v2/provider/grant-attempts/:attemptId` | provider | `commerce_grant_claim` |
| `grant_detail` | GET | `/v2/control/organizations/:organizationId/grants/:grantId` | browser | `commerce_grant_management` |
| `grant_mutation_status` | GET | `/v2/control/organizations/:organizationId/grant-mutations/:mutationId` | browser | `commerce_grant_management` |
| `grant_revoke` | POST | `/v2/control/organizations/:organizationId/grants/:grantId/revoke` | browser | `commerce_grant_management` |

Manifest path `/v2/public/grant-capabilities`, version
`openarc.capabilities.commerce-grants.v1`. Three audiences with one pinned
prefix each, proven pairwise non-prefixing, plus a published per-audience
credential map: browser session cookie, `oacs_v1_` commerce session, and
`oas_pr_` provider session **plus** `oag_v1_` grant token together.

**Both provider token-bearing routes are POST, including introspection.**
Introspection is read-only, but a raw `oag_v1_` must never appear in a path,
query string, access log or referrer. This is a deliberate deviation from
"reads are GET" and the right one.

Provider routes sit under `/v2/provider/grant…` rather than the existing
`/v2/provider/organizations/…`, because that prefix is **browser** audience;
the manifest rejects outright any provider route under it.

## The authority model is structural, not documentary

- **One-shot token.** The issue and replace data shapes are a
  `discriminatedUnion("replayed")`: the `false` arm requires `grantToken`, and
  the `true` arm is a closed object with **no `grantToken` key at all**. A test
  enumerates the actual zod `.shape` keys of both arms, so a replay is
  structurally incapable of carrying the secret.
- **Token-free reads.** A key-inventory test walks every status, detail, receipt
  and outcome shape — union arms included — asserting none declares
  `grantToken`, `token`, `rawToken`, `secret`, `grantTokenHash`, `tokenHash`,
  `salt`, `pepper` or `credential`.
- **Revoke retains the claim.** `claimedAt !== null` implies `released === false`;
  a release implies the action is cancelled and was never claimed.
- **Unknown outcome** is a distinct third arm carrying only the mutation id — no
  receipt, no `released`, `refunded`, `settled`, `status`, `committedAt`,
  `resourceId` or token on any arm.
- **Provider recovery** `not_found` carries exactly one key, asserted by
  `Object.keys`, so missing is indistinguishable from foreign.

## Verification

| Gate | Result |
| --- | --- |
| `@openarc/shared` test | 42 files / **1,466** (was 40 / 1,253) |
| focused grant wire + capabilities | 2 files / 213 |
| typecheck, build, ESLint `--max-warnings=0` | exit 0 |

Mutation-checked for non-vacuity: disabling the claimed-cannot-be-released rule,
adding an optional `grantToken` to the replay arm, and renaming the introspect
path each failed exactly the right tests (5 total), then sources were restored
and re-verified.

## Deliberately not covered, with reasons

No grant list, page, cursor or limit shape: `ControlGrantStore` has no list
method, so a page route would be unimplementable. No new money field — money
reaches the wire only through the reused provider view, tested for BigInt
discipline including a case a float implementation would wrongly accept. No
`reservationStatus` on revoke data, because no accepted shared reservation-status
enum exists and inventing one was declined; `actionStatus` and `released` are
surfaced instead.

Replacement-cannot-extend-expiry is enforced by the reused 300-second ceiling
against the immutable first-issue `issuedAt`, plus a two-snapshot continuity
predicate. A single replace response cannot self-prove it, since it carries no
prior expiry and adding one would invent a field the store does not return.

## Boundary

Pure parsers. No SQL, transport, authority, crypto, clock, network or runtime
registration. An enabled grant surface does not mean a payment lane is usable.
