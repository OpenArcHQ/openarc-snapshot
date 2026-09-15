# PORT-03 action capability manifest and grant metadata model

Accepted 2026-09-15 UTC, based on `a5ef5ce`. Integrates the combined shared
candidate: a frozen two-family commerce-action capability manifest with the
exact twelve action routes, pure grant metadata and provider projections, and
the additive `grant_issued` action status.

Owned files: `control-action-capabilities.ts`, `control-grant-model.ts`,
`control-action.ts` and their three tests, plus two additive `index.ts` exports.

## Test-collection reconciliation

The candidate report stated 1,189 full shared tests, which is lower than the
accepted 1,193 at `44637be` and was recorded as an unresolved discrepancy. It
was reproduced and resolved with clean-workspace runs; the earlier figure was
simply wrong, and a first local re-run was itself invalidated by stale packet
files left in a reused container.

| Source | Test files | Tests |
| --- | --- | --- |
| Integration `a5ef5ce`, clean workspace | 38 | 1,193 |
| Integrated candidate, clean workspace | 40 | 1,253 |

Per-file comparison accounts for the delta exactly: `control-action-capabilities`
+27, `control-grant-model` +29, `control-action` 39 -> 43. Every pre-existing
file keeps its exact count. No test file or test case was removed.

## Verification

Run in an isolated container against this revision: `@openarc/shared` build and
typecheck exited 0; ESLint over the seven owned files exited 0 with
`--max-warnings=0`; the full shared suite passed 1,253/1,253 across 40 files;
the three focused files passed 99/99.

## Lead review

Reviewed the two new contracts for financial and privacy correctness. Amounts
use absolute-end canonical patterns and BigInt comparisons with no floating
point; `debitAtomic` must equal `amountAtomic + feeAtomic`; grant lifetime is
capped at 300 seconds with sub-second fractions carried verbatim rather than
rounded through a JS millisecond; revoked grants retain the claim fact. The two
provider projections are positive allowlists and carry no buyer organization,
policy, session, reservation or account fields, and `not_found` carries only its
status. No raw token, hash or payment material is representable.

Two comments claiming DB11 would enforce the reservation-to-grant transition
were corrected to DB12; the accepted ordering is DB11 reads, DB12 grants.

## Boundary

These are pure parsers. No SQL, transport, authorization, crypto, token
issuance or claim, clock, network or capability activation is introduced.
Parsing any of these objects proves no live grant, current authority, payment,
settlement or delivery. An enabled action surface does not make a listing
payment lane usable. DB10 still emits only its five older action states; the
listing payment lane remains unavailable. Whole PORT-03 acceptance, DB10
integration and publication all remain pending.
