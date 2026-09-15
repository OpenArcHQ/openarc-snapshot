# PORT-07 — ERC-8183 deployment manifest and job mirror

Accepted 2026-09-15 UTC. Commit `b155212`, `feat(erc8183): pin the Arc testnet job deployment and add a
pure job mirror`. It covers packets P07-01 (manifest) and P07-03 (mirror).

It adds `packages/shared/src/commerce/erc8183-manifest.ts` and
`packages/shared/src/commerce/erc8183-job-mirror.ts`. Both are pure, and neither is wired
into any runtime.

## P07-01 — pinned deployment manifest

There is a single, deeply frozen Arc-testnet entry, `arc-testnet-erc8183-reference`
(`eip155:5042002`, chain id 5042002), for the verified ERC-8183 reference deployment:

- proxy `0x0747eef0706327138c69792bf28cd525089e4583` (ERC-1967/UUPS), deployed at block
  33908011
- implementation `0xa316fd02827242d537f84730f8a37d0ba5fd351a`, contract
  `AgenticCommerce`
  - verified source SHA-256
    `a16ae3290855910a4c06a59fa691d1d2b56b534e744f15b6f73a6a06ccb1bec4`
  - compiler `v0.8.28+commit.7893614a`, optimization off, EVM `cancun`
  - runtime code 21,560 bytes
- payment token USDC `0x3600000000000000000000000000000000000000`, 6 decimals. Its native
  18-decimal mirror emitter is recorded so its `Transfer` logs are never counted.
- reviewed parameters at block 62293116: `platformFeeBP` 0, `evaluatorFeeBP` 0, and the
  zero hook whitelisted. These are admin-mutable without an event.
- the deployed six-state `JobStatus` machine: `Open`, `Funded`, `Submitted`, `Completed`,
  `Rejected`, `Expired`

**Pinned values are recomputed by the tests.** Every event topic, every function selector,
the EIP-1967 implementation slot and the AccessControl role ids are literals in the
module, and the tests recompute each one with keccak-256. The runtime module has no
hashing dependency.

The manifest pins the deployed six-argument `JobCreated` (with `hook`). The ERC text's
five-argument topic is recorded as non-deployed and is never indexed.

**No mainnet entry and no fallback.** `resolveErc8183Deployment` accepts only the exact
string `eip155:5042002` or the exact number 5042002. Anything else, including missing
input, throws. At load, the manifest also cross-checks the shared `ARC_TESTNET` and
`ARC_ERC8183` constants and throws `invalid_config` if any of them has drifted.

**Deployed deviations from the ERC text** are recorded as C1–C11. Examples:

- `fund` has no `expectedBudget` front-running guard.
- The provider may call `setBudget` repeatedly while the job is `Open`.
- There is no on-chain dispute function, state or event.
- There is no provider-acceptance call, and settlement is atomic inside `complete`.

**Unsupported actions:** dispute, provider acceptance, deadline extension, partial refund,
client cancel after funding, budget change after funding, hooks and admin calls.

**Drift assessment.** `assessDeploymentDrift` compares observed facts with the manifest.
The verdict is:

- `verified` only when every field is observed at a `finalized` anchor and matches
- `drifted` on any mismatch or malformed value
- `incomplete` when any field is unobserved

Drift outranks incompleteness. Any verdict other than `verified` sets
`freezePreparation`.

### Pinned vs held unverified

**Pinned (verified):** everything listed above, and deviations C7 (fees apply on
completion only), C8 (no on-chain dispute) and C9 (`createJob` requires
`expiredAt > block.timestamp + 5 minutes`).

**Held unverified** (`ERC8183_UNVERIFIED_FACTS`; nothing in the module builds on them):

| Id | Fact |
| --- | --- |
| D12 | Full role and `HookWhitelistUpdated` history (explorer index only). |
| F2/Q1 | Whether a `latest` block can differ from `finalized`; the mirror anchors on `finalized` until resolved. |
| Q2 | No live `claimRefund` / `JobExpired` path has been observed on this deployment. |
| Q3 | Whether any non-zero hook is whitelisted. |
| Q4 | Whether any address other than the pinned admin holds a role. |
| Q7 | Sign-off that a Draft-ERC reference deployment under one admin EOA is acceptable. |
| D13-hash | The parameter review block hash is recorded only in truncated form; only its number is pinned. |

## P07-03 — pure job mirror

`projectErc8183JobMirror` is a pure, deterministic projection of decoded logs into job
state, anchored on a finalized block.

**Finalized anchor.** Facts above the anchor are unfinalized and never terminal. A
non-finalized anchor throws.

**Holds instead of empty.** Each of these holds the affected jobs instead of reading as
empty:

- a page gap, after which nothing is applied
- a failed or rate-limited page
- unscanned finalized blocks
- an out-of-order page
- a page wider than the 10,000-block RPC limit
- a removed log
- a block-hash conflict
- a conflicting overlapping page
- a proxy log with an unknown topic
- a job created before the mirror start

At an `Upgraded` event to a different implementation, application freezes.

**Refund pairing rule.** A `Refunded` event counts as money returned only when it is
paired in the same transaction with a `JobRejected` (evaluator rejection of a funded job)
or a `JobExpired` (`claimRefund` after expiry).

- An unpaired `Refunded` is held as unknown and never counted.
- A funded rejection without `Refunded` is held, not assumed refunded.
- A client rejecting an `Open` job, or an evaluator rejecting a zero-budget job, records
  no refund.
- A passing deadline changes nothing without a `JobExpired` event.

**Money.** The double USDC `Transfer` (ERC-20 plus the native 18-decimal mirror) is counted
once. A native `Transfer` without an ERC-20 twin is flagged, not counted. A completion
without `PaymentReleased` is held as unknown money.

**Budget.** A budget change after client approval, and a funded amount that differs from
the agreement, are flagged. An unchanged budget is not flagged. Non-zero hooks are flagged
as unsupported.

**Unrepresentable states.** `accepted`, `settled` and `disputed` are rejected at both the
type level and runtime. No status, refund or flag outside the deployed vocabulary is
emitted in any scenario.

## Fail-closed rules and their proofs

`packages/shared/test/erc8183-manifest.test.ts`:

- *pins exactly one Arc Testnet entry with the reviewed proxy, implementation and
  provenance*
- *recomputes the EIP-1967 implementation slot and the AccessControl role ids*
- *recomputes every event topic from its signature string and pins the deployed indexed
  layout*
- *uses the deployed six-argument JobCreated topic, not the ERC text's five-argument form
  (C5)*
- *recomputes every function selector from its signature string*
- *records deviations C1–C11, unsupported actions and unverified facts, and nothing named
  dispute/accept/settle*
- *is deeply frozen*
- *has no mainnet entry and no default: every other network throws*
- *verifies only a fully observed, finalized, matching deployment*
- *reports drift and never verifies: %s* (parameterised)
- *treats malformed observations as drift*
- *is incomplete, never verified, when any field is unobserved*
- *drift outranks incompleteness*

`packages/shared/test/erc8183-job-mirror.test.ts`:

- *projects a full lifecycle and counts the double USDC Transfer once*
- *flags a native 18-decimal Transfer without an ERC-20 twin instead of counting it*
- *evaluator may reject after the deadline; the refund counts only when paired in the same
  tx*
- *an unpaired Refunded is held as unknown and never counted as returned*
- *a funded rejection without Refunded is held, not assumed refunded*
- *claimRefund: Refunded paired with JobExpired moves Funded/Submitted to Expired*
- *a passing deadline changes nothing without a JobExpired event*
- *surfaces a budget change after client approval and a funded amount that differs from
  the agreement*
- *anchors on finalized: facts above it are unfinalized and never terminal*
- *holds a page gap and applies nothing after it*
- *holds a failed (rate-limited) page as a gap, never as empty*
- *holds a page range wider than the 10,000-block RPC limit, a removed log, and a
  block-hash conflict*
- *freezes application at an Upgraded event to a different implementation*
- *holds a completion without PaymentReleased as unknown money*
- *is pure and deterministic: identical output for repeated and page-reordered input,
  deeply frozen*
- *rejects provider acceptance, settled and disputed at the type and runtime level*
- *never emits a status, refund or flag outside the deployed vocabulary across every
  scenario*

## Verification

Test counts for this commit: see CI.

## Owner decisions still needed

- **Budget front-running ADR.** The deployed `fund` has no `expectedBudget` guard (C1),
  and the provider can call `setBudget` repeatedly while the job is `Open` (C2). The
  mirror flags budget changes after approval. Whether that is an acceptable control
  needs a recorded decision.
- **Dispute scope.** There is no on-chain dispute (C8, C11). Whether OpenArc offers any
  off-chain dispute, and how it would be presented, is undecided. Until then `disputed`
  stays unrepresentable.
- **Deployment sign-off (Q7).** Relying on a Draft-ERC reference deployment controlled
  by a single admin EOA needs explicit owner acceptance.
- **Live expiry proof (Q2).** No live `claimRefund` / `JobExpired` path has been observed.
  The expiry and refund handling is proven only against synthetic logs.

## Boundary

Pure shared modules. There is no RPC client, no log fetching, no persistence, no API
route, no job creation or funding, no signing and no funds. Nothing reads the chain in
this commit.
