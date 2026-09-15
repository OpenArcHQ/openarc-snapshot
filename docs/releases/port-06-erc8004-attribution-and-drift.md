# PORT-06 — ERC-8004 validation attribution and registry drift

Accepted 2026-09-15 UTC. Commit `acb7c22`, `fix(erc8004): stop attributing pending validations and
detect registry upgrades`.

This commit changes the M05 agent-registry evidence adapter (`apps/api`), its shared
contract (`packages/shared/src/agent-registry-evidence.ts`), the Vault record schema and
the Vault workspace panel.

## What shipped

### 1. Pending validations are no longer attributed

The Validation registry getter returns `0` in two different cases: when a request has not
been answered, and when the validator answered with a response of `0`. The adapter
previously read that `0` as a validator response.

`attributeValidationStatus` now attributes a response only from a matching
`ValidationResponse` log. The log must:

- be emitted by the pinned Validation registry
- carry the reviewed topic
- not be removed
- be for the exact request hash
- be at or before the anchor

Without such a log, the state is explicitly `pending_or_unobserved`, with the relationship
`request_names_validator_without_observed_response`. It never carries a response value.
If a matching log names a different validator or agent id, that is `SOURCE_CONFLICT`.

The evidence adapter version is now `openarc.agent-registry-evidence.m05.v2`, and new
responses use schema `openarc.agent-registry-evidence.v2`.

### 2. Registry implementation and owner drift

The three ERC-8004 registries are owner-upgradeable ERC-1967/UUPS proxies, and one EOA
can upgrade them. Every observation re-reads, at its anchor, the implementation slot and
`owner()` of all three proxies. It compares them with the reviewed pins in
`ARC_ERC8004_DEPLOYMENT` (reviewed 2026-09-15):

- implementation slot
  `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`
- proxy owner `0x547289319c3e6aedb179c0b8e8af0b5acd062603`
- identity implementation `0x7274e874ca62410a93bd8bf61c69d8045e399c02`
- reputation implementation `0x16e0fa7f7c56b9a767e34b192b51f921be31da34`
- validation implementation `0xdb31f5d9167f8ebc8b30fbbf814c4d297c2d7f99`

Deployment status is `verified` only when every comparison matches.

- Any mismatch is `drift`, reported with its reason.
- An RPC error or a malformed slot is `unknown`.
- Drift wins over unknown.

The Vault panel shows drift and unknown as "EVIDENCE NOT VERIFIED" and lists the reasons.

Two limitations are added to every v2 record:

- A validation request without an observed `ValidationResponse` event is pending or
  unobserved, never a validator response of 0.
- The registries are owner-upgradeable proxies. Implementation and owner were compared
  with reviewed pins at this block only.

### 3. `SOURCE_MAX_SUBCALLS` raised to 16

The drift reads need more bounded source subcalls. The configuration check for the agent
registry now requires `SOURCE_MAX_SUBCALLS >= 16` (previously 10). The CI production image
run, `.env.example` and the release-check tokens were updated from 11 to 16.

### 4. Legacy v1 records stay readable

`StoredAgentRegistryEvidenceSchema` accepts both v2 and the original M05 v1 shape
(`LegacyAgentRegistryEvidenceV1Schema`). The Vault's `agent_registry_observation` record
now parses through it.

A v1 record is shown as "LEGACY RECORD · DEPLOYMENT NOT CHECKED". Any validation value in
it is shown as "NOT ATTRIBUTED", because the getter value may be a pending request. The
API never returns the v1 shape as a new response.

## Fail-closed rules and their proofs

`apps/api/test/agent-registry.test.ts`:

- *returns identity, an exact observer claim, and an explicit unobserved validation state
  at one final block*
- *reports a getter response of 0 without an event as pending, never as a validator
  response*
- **ERC-8004 deployment pins**
  - *verifies matching implementation slots and proxy owners*
  - *reports a different implementation slot as drift and not verified, with the reason*
  - *reports a changed proxy owner as drift*
  - *reports an RPC error or malformed slot as unknown, not verified*
  - *lets drift win over unknown*
- **ValidationResponse attribution**
  - *uses the reviewed ValidationResponse topic*
  - *treats getter 0 with no event as pending*
  - *attributes getter 0 with a matching event as a validator response of 0*
  - *fails closed when a matching event conflicts with the stored validator or latest
    response*

`apps/api/test/agent-registry-routes.test.ts`:

- *accepts an explicit pending validation but rejects a legacy getter-only response from
  the API*

`packages/shared/test/agent-registry-evidence.test.ts`:

- *keeps pending validation explicit and never carries a response value*
- *derives deployment status from every pin comparison*
- *reads original v1 records only as stored legacy data, never as a new API response*

`e2e-agent-registry/agent-registry.spec.ts`:

- *shows registry implementation drift as not verified with its reason*

`apps/web/test/vault.test.ts` now builds its v1 observation with
`LegacyAgentRegistryEvidenceV1Schema`, which proves that original M05 evidence still
decrypts after the change.

## Verification

Test counts for this commit: see CI. The release-gates workflow and `release-check.mjs`
were updated to the new subcall minimum.

## Vault forward-compatibility consequence

This change is additive for readers going forward, but not backwards.

- A build that includes this commit reads both v1 and v2 observations.
- **A Vault that holds a v2 observation cannot be unlocked by an older build.** An older
  build knows only the v1 schema, and a record that fails the closed union fails the
  whole unlock.

Anyone who saves a new ERC-8004 observation should keep using a build at or after this
commit. Older builds predate `VAULT_INCOMPATIBLE` (PORT-08), so they report this as a
generic unlock failure, not as an incompatible Vault.

## Deferred

- **`ValidationResponse` log wiring.** The attribution rule is implemented and tested
  against supplied logs. The live adapter still reads no event logs: it passes an empty
  log set (`NO_OBSERVED_VALIDATION_LOGS`). Every live validation is therefore reported as
  `pending_or_unobserved`, which fails closed. Reading `ValidationResponse` logs in the
  live adapter is not implemented in this commit.
- **Operator-aware self-feedback.** The self-feedback check still compares the feedback
  author only with the agent's owner and agent wallet at the observed block; approved
  operators and ownership history are not considered. Feedback remains presented as one
  observer's claim.

## Boundary

Read-only public RPC observation on Arc testnet. There are no writes, no signing, no
funds, and no fetching or rendering of agent metadata. Registry facts remain claims
defined by a draft standard, not proof of safety, quality or control.
