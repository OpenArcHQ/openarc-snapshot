<div align="center">
  <img src="assets/openarc-logo.jpeg" alt="OpenArc" width="180" />
  <h1>OpenArc</h1>
  <p><strong>Understand the evidence behind agent activity.</strong></p>
  <p>A local-first investigation workspace for autonomous finance on Arc Testnet.</p>
  <p>
    <a href="#capabilities">Capabilities</a> ·
    <a href="#run-locally">Quick start</a> ·
    <a href="#architecture">Architecture</a> ·
    <a href="#documentation">Documentation</a>
  </p>
</div>

---

OpenArc brings agent reports, owner-supplied policies, payment metadata and
onchain observations into an inspectable evidence trail. Distinguish what was
reported, what was observed and what remains unresolved—without treating a
successful transfer as proof of authorization or service delivery.

**Current status:** OpenArc runs on Arc Testnet as a local-first evidence
workspace. Available today: Arc account and transaction observation, ERC-8004
identity and reputation evidence, ERC-8183 job evidence, Circle Gateway transfer
evidence, the encrypted browser workspace, investigations and bounded exports.
Hosted accounts, the marketplace and agent purchases are built behind their own
switches and are not enabled in this deployment, so purchases are unavailable.
OpenArc does not support mainnet. See the [roadmap](docs/roadmap.md) for what
ships next and the rules the purchase path will follow.

## Capabilities

| Capability | Purpose |
| --- | --- |
| Encrypted workspace | Keep records in a passphrase-protected browser vault, with explicit backup, recovery and deletion. |
| Agent reports and policies | Import structured reports and compare supplied activity against local monitoring rules. |
| Testnet observations | Request bounded Arc account, transaction, ERC-8004 registry and fixed-reference ERC-8183 job observations with explicit consent. |
| Payment evidence | Compare imported x402 metadata with separately requested Gateway status and Arc batch evidence. |
| Investigations | Search records, review exceptions and inspect explicitly linked evidence in graph and list views. |
| Redacted exports | Preview bounded investigation reports with private fields omitted by default. |
| Minimal-record account access | Optional passkeys or wallet login, server-side session revocation and recovery codes; no required name or email. Sign-in is authentication only and is not permission to pay. |
| Marketplace source preview | Public allowlisted catalog, provider profiles, search and pagination, plus draft/version management and independent origin review. Purchases remain unavailable and flags are required. |
| Tenant and agent scope | Separate public, organization and provider-minimal tenant scopes; role-based read/write and scoped machine sessions for agent/provider credentials. |
| Supplied public design | Preview the supplied visual system, local video, technical docs and FAQ at `/design`, without replacing the existing evidence workspace. |

Features default off. Local imports and investigations need no live source;
connector-enabled builds require explicit approval before each source lookup.
See the [feature and authority matrix](docs/operations/public-testnet-runbook.md#feature-flags-and-authority-matrix)
for prerequisites and limits.

## A typical investigation

1. **Collect:** import a report or add evidence to an unlocked local workspace.
2. **Observe:** optionally approve a specific Testnet lookup; saved observations
   retain their source and time context.
3. **Compare:** inspect explicit relationships, policy findings, conflicts and
   missing evidence. Incomplete records remain incomplete.
4. **Share deliberately:** review a redacted export before downloading it.

## Trust boundaries

- **No financial execution yet.** No wallet-key custody, transaction signing,
  payment broadcasting or enforcement of another agent's policy. Optional wallet
  login requests an authentication signature only; it cannot authorize payment.
- **Evidence is not endorsement.** Imported reports are unauthenticated claims.
  Registry entries do not establish trust; matching batch inclusion does not
  establish individual settlement or resource fulfillment.
- **Local storage has limits.** Records are encrypted in browser-local storage.
  Losing the passphrase, clearing storage or changing origin can prevent access.
  Retain an encrypted backup and its passphrase separately.
- **Lookups cross a privacy boundary.** Approved inputs leave the browser through
  the API. The API does not persist workspace or evidence bodies; this is not a
  promise that hosting infrastructure retains no metadata.
- **Minimal records are not zero retention.** Account access retains credential
  public keys/IDs, pseudonymous bindings and necessary security records. Passkey
  use keeps minimal records and is not a zero-retention path. Guest access
  remains separate; no email or personal-name field is required.
- **Metadata review is not authority.** Listing review by an independent
  moderator is independent origin-metadata moderation, not a security
  endorsement or execution authority; provider self-review is not permitted.
  Purchases are unavailable; reference-sum artifacts are contract or synthetic
  fixtures, not a working service, payment or retrieval path.
- **Testnet only.** No mainnet compatibility, independent security certification,
  or Circle/Arc endorsement is claimed. External network and protocol costs are
  not represented as free.

## Architecture

| Component | Responsibility |
| --- | --- |
| `apps/web` | React/TypeScript UI, WebCrypto vault, IndexedDB, consent and investigations. |
| `apps/api` | Fastify/TypeScript API, fixed Testnet destinations, validation and bounded reads. |
| `packages/shared` | Versioned schemas, reconciliation, policy evaluation and fail-closed network configuration. |
| `packages/db` | PostgreSQL migrations, restricted runtime roles and durable account/session/recovery state. |
| Redis | Shared abuse and source-budget counters; not a server-side workspace vault. |
| Release tooling | Chromium/WebKit journeys, production-image tests, dependency/license checks, image scans and SBOMs. |

Graph views project the same supplied evidence as the accessible lists. They do
not infer relationships from matching wallet addresses or transaction hashes.

## Run locally

Prerequisites: **Node.js 22** and **pnpm 11.5.1**. From the repository root:

```bash
pnpm install --frozen-lockfile
pnpm --filter @openarc/shared build
VITE_ENCRYPTED_WORKSPACE_ENABLED=true VITE_GENERIC_AGENT_IMPORT_ENABLED=true VITE_INVESTIGATIONS_ENABLED=true pnpm --filter @openarc/web dev
```

Open `http://127.0.0.1:5173`. This enables local workspace, report imports and
investigations without live API sources. Use synthetic data for testing.
The inline environment syntax above is for POSIX shells.

Source-enabled deployments need additional API, Redis, origin and proxy
configuration. Follow the [operations runbook](docs/operations/public-testnet-runbook.md);
never place real secrets in source control or `VITE_*` variables.

## Verification

The M10 application candidate passed **528 unit/integration tests**, **112
development browser checks**, **44 production browser checks** and **ten image
scans**, without retries or flaky passes. Historical-reader and recovery drills
also passed. These are candidate-specific results, not a security audit or
public-launch approval.

With Docker available, the isolated Node 22 gate provisions its own test Redis
and browser dependencies:

```bash
docker build -f scripts/Dockerfile.node22-gate -t openarc-local-gate .
```

This runs `pnpm release:gate`, also used by the manual **Public source checks**
workflow. The pre-publication production-image, SBOM and historical-reader gates
are separate: see the [public verification boundary](docs/public-source-publication.md).
Exact earlier candidates and limitations are recorded in the
[M09 release ledger](docs/releases/09-investigation-operations.md) and
[M10 hardening ledger](docs/releases/10-public-testnet-hardening.md).

## Documentation

| Start here | Contents |
| --- | --- |
| [Engineering source of truth](docs/engineering/openarc-engineering-source-of-truth.md) | Scope, implementation order, contracts and release criteria. |
| [Backend architecture](docs/engineering/openarc-backend-architecture.md) | API boundaries, adapters, budgets, privacy and observability. |
| [Frontend architecture](docs/engineering/openarc-frontend-architecture.md) | Vault lifecycle, consent, UI states, accessibility and visualization. |
| [Technical specification](docs/openarc-technical-spec.md) | Testnet parameters, evidence models, source limitations and migration gates. |
| [Operations runbook](docs/operations/public-testnet-runbook.md) | Flags, source shutdown, recovery, origin migration and incidents. |
| [Product blueprint](docs/openarc-product-blueprint.md) | Product rationale and investigation workflows. |
| [Roadmap](docs/openarc-roadmap.md) | Planned capabilities; not a claim that future features are implemented. |

## Project status and contact

The project-facing organization name is **OpenArc**. There is no permanent domain
yet; the existing Railway address remains a temporary controlled staging origin.
Public support and security contacts have not been designated. Do not submit
private records, credentials or vulnerability details in public issues.

The repository is currently marked **UNLICENSED**; no open-source license has been
granted. Public source availability is separate from licensing and
product-launch readiness.
