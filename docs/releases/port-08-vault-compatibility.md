# PORT-08 — Private Vault compatibility

Accepted 2026-09-15 UTC. Five commits:

| Commit | Subject |
| --- | --- |
| `2cd3e8e` | `test(vault): freeze Vault compatibility with golden fixtures` |
| `ed0b86d` | `feat(vault): lock the Vault in every tab on logout, account change and expiry` |
| `4ee29eb` | `chore(vault): cite compatibility rules without private note paths` |
| `b1230fb` | `feat(vault): open Vaults written by the ROOT build and report incompatible Vaults` |
| `217a695` | `feat(vault): guard every receipt-gated egress and lazy-load the workspace` |

**Compatibility rule.** Vault data written by integration build `0f5caa9` must stay
unlockable, importable, recoverable and rescuable by every later build. Records written by
the ROOT build must open here as well. A failing test means the reader gets fixed. A frozen
fixture is never edited or regenerated to make a test pass.

## 2cd3e8e — golden fixtures and identifier freeze (P08-00)

### Golden fixtures

Frozen, test-only synthetic fixtures under `apps/web/test/fixtures/vault-compat/`, each
pinned by byte length and SHA-256 in `manifest.json`:

- an encrypted IndexedDB snapshot, with its expected plaintext records
- an `OPENARC-ENCRYPTED-BACKUP` v1 file, and its logical backup
- an `OPENARC-OPAQUE-RESCUE` v1 file

Together they cover all 14 record kinds, permission receipts v1–v5, and every permitted
relationship. The tests open them record by record:

- unlock
- wrong-passphrase handling
- import into an empty browser and over an existing Vault
- export
- recovery with secret rotation
- passphrase change
- linked deletion
- Vault destruction
- opaque rescue export and restore

### Identifier freeze

`apps/web/test/vault-compat-identifiers.test.ts` checks eleven groups of identifiers
against an independent reference decoder:

1. database name, version, store names, key paths and meta row key
2. format and version literals
3. the exact key sets of metadata, envelope, KDF, wrapped key, backup, logical archive and
   rescue
4. KDF ids: PBKDF2-HMAC-SHA-256 with exactly 600000 iterations, plus salt, IV and wrap
   sizes
5. the record AAD template, backup AAD, canonical JSON, and AES-GCM-256 with a 128-bit tag
6. the sentinel marker, manifest digest rule, manifest maximum and total record cap
7. backup, logical and rescue magics, versions, the warning literal, and the 2/32/64 MiB
   caps
8. recovery secret format and passphrase normalization rules
9. the `recordSchema` literal of every stored kind
10. the BroadcastChannel name and coordination message shape
11. lock rotates only `coordinationRevision`, and deletion sets the `deletionPending`
    marker

`packages/shared/test/vault-compat-literals.test.ts` freezes the shared parser's side:

- every `recordSchema` literal
- permission receipt disclosure text, destinations and released field tuples for v1–v5
- embedded payload schema, rule and adapter literals
- the sentinel marker and the 6,601-entry manifest maximum

Any change fails with a message starting `COMPAT RULE`.

### Known gap, pinned

`apps/web/test/vault-compat-root-kinds.test.ts` pinned a known gap. Records of the
ROOT-only kinds `task_draft`, `task_report` and `research_run` made unlock, recovery and
import fail. `b1230fb` closes this gap.

## ed0b86d — lock on logout, account change and expiry (P08-02)

**When it locks.** The Vault now locks on logout, on an account switch, and on a detected
session expiry (account to guest). It does not lock on first observation, login, a
same-account refresh or unmount.

**What locking does.** Session end drops decrypted state in the current tab, writes the
existing lock signal, and broadcasts the existing lock message. It does this through a
lazily loaded bridge (`session-bridge.ts`) that never creates a Vault and never blocks
logout. Receiving tabs reuse the unchanged coordination handler, which is now extracted to
`coordination.ts`.

**Egress revision re-read.** Before any egress, the permission flow and the Arc permission
flow re-read the stored Vault revision and lock signal (`revision-guard.ts`). Egress is
refused if another tab silently changed the Vault, or if the Vault disappeared or was
replaced. When egress is refused, the committed approval stays as the audit trail.

**Freeze update.** The identifier freeze now follows the frozen channel name, message
shape and predicate into `coordination.ts`, and requires every Vault channel to use the
frozen constant.

Proofs in `apps/web/test/vault-session-lock.test.ts`:

- *logout reads metadata, writes the manual-lock signal and broadcasts the existing lock
  message*
- *a logout whose request was sent but not confirmed still locks*
- *an account switch locks*
- *a detected session expiry (account to guest) locks*
- *first observation, login, same-account refresh and unmount never lock*
- *does nothing and creates nothing when no Vault exists*
- *IndexedDB unavailable: logout still resolves, this tab drops plaintext, status is
  non-secret*
- *a throwing lock write still broadcasts lock and reports the failure*
- *storage that never answers cannot block logout*
- *without BroadcastChannel the durable lock signal is still written for polling tabs*
- *another open tab clears decrypted plaintext exactly as for a manual lock from another
  tab*
- *account and tenant shells reach Vault code only through a dynamic import*

Proofs in `apps/web/test/vault-egress-revision.test.ts`:

- *capability flow sends nothing after a silent %s* (parameterised over peer changes)
- *Arc observation flow sends nothing after a silent %s*
- *keeps the committed approval as the audit trail when egress is refused*
- *an unchanged stored revision proceeds to exactly one request*
- *refuses when the Vault disappeared or was replaced*

## 4ee29eb — citation cleanup

Compatibility test messages and comments now cite "PORT-08 Vault compatibility rules"
by section, instead of an internal file path. There is no behaviour change: three test
files, five lines.

## b1230fb — ROOT-build record kinds and VAULT_INCOMPATIBLE (P08-01)

### Dual reader

The ROOT build's `task_draft`, `task_report` and `research_run` kinds are appended to the
shared record union as additive members. Their stored literals are:

- `openarc.task-draft-record.v1`
- `openarc.task-report-record.v1`
- `openarc.research-run.v1`

The union now has 17 members, with the existing 14 unchanged and in order. Each new member
has the ROOT build's exact schema, caps, relationship rules and digest checks, and the ROOT
build's write-side immutability rules. It is neither looser nor stricter than the ROOT
build.

Digests are reproduced exactly as the ROOT build computes them with viem, including
non-ASCII input, and use the single shared SHA-256.

This build has no editor for these kinds, so they are read-only. They are preserved
byte-identically through save, export, import, recovery and passphrase change. They can be
deleted only through linked deletion or whole-Vault deletion.

Per-kind caps are enforced additively. The frozen caps and the 6,602 total are unchanged.

### Honest incompatible-Vault state

A record that decrypts but matches no known kind and schema now raises
`VAULT_INCOMPATIBLE`. The reason is either `unknown_record_identity` or
`unsupported_record_content`. The error:

- is raised only after key unwrap and AES-GCM authentication succeed, so it is never
  reported as a wrong passphrase
- carries no record contents, identifiers or field values
- tells the user their passphrase was accepted, nothing was changed, and they should
  download an opaque rescue and open the Vault with the build that wrote it

Key unwrap failure still reports a wrong passphrase. Ciphertext damage still reports
damage, and damage wins over incompatibility.

No existing identifier, format, KDF, AAD or golden fixture changed.

Proofs in `apps/web/test/vault-compat-root-kinds.test.ts`:

- *accepts ROOT-build records with their ROOT literals, without transforming them*
- *unlocks, recovers and rescues a ROOT-build Vault holding %s, byte-faithfully, writing
  nothing on unlock*
- *imports a ROOT-build backup holding %s and re-exports records the ROOT build's
  contracts still accept*
- *keeps ROOT-build records byte-identical and read-only across passphrase change,
  unrelated saves and refused writes*
- *deletes ROOT-build records only through linked deletion or whole-Vault deletion*
- *enforces the ROOT build's per-kind caps additively, leaving the frozen caps and the
  6,602 total unchanged*
- *still reports a wrong passphrase on a Vault holding ROOT-build records as a wrong
  passphrase, writing nothing*
- parameterised over "a future version of a ROOT kind" and "a kind no build knows"
  (incompatible state)
- *never presents a tampered ROOT-build digest as verified*
- *reports a tampered ROOT-build ciphertext as damage, and damage wins over
  incompatibility*

Proofs in `packages/shared/test/vault-root-kinds.test.ts`:

- *computes SHA-256 exactly like node:crypto for boundary lengths, multi-block, non-ASCII
  and lone-surrogate input*
- *reproduces the ROOT build's viem digests for task drafts and report requests,
  including non-ASCII intent*
- *accepts or rejects exactly as the ROOT build: %s*, over a corpus of accepted and
  rejected records
- *agrees with the ROOT build's own pinned WorkspaceRecordSchema on every corpus entry*
  (skipped when the ROOT build source is unavailable)
- *appends the three members after the existing fourteen and keeps the identity table in
  lock-step with the union*
- *classifies only the identity pair of an untrusted value*

## Verification

Test counts for these commits: see CI.

## Unverified and kept fail-closed

- **ROOT parity against the ROOT build's own schema** runs only where that source is
  available. Otherwise parity rests on the frozen corpus.
- **Forward compatibility.** An older build given a Vault with records it does not know
  still fails. Since `b1230fb` that failure is reported as `VAULT_INCOMPATIBLE`, not as
  corruption, but nothing makes the older build able to open it. See PORT-06 for the v2
  ERC-8004 observation case.
- **ROOT-kind editing** is not offered. The records are read-only here.

## 217a695 — egress guards on every receipt flow and a lazy workspace

`feat(vault): guard every receipt-gated egress and lazy-load the workspace`.

**Every receipt-gated flow is guarded.** The ERC-8004 agent registry, ERC-8183 job and
Circle Gateway permission flows now run the same pre-egress sequence as the capability and
Arc observation flows: commit the approval receipt, check the active session, re-read the
stored Vault revision and lock signal, check the session again, then make the single
request. Each of these flows makes exactly one request with no polling, and the failed or
completed receipt is saved only after the response, so no other egress follows a receipt
commit. A search of the web client found no other request that follows a Vault receipt.

Proofs in `apps/web/test/vault-egress-revision.test.ts`: for each of the three flows, a
silent peer lock, peer save or deletion marker produces zero requests and keeps the
committed approval; an unchanged Vault produces exactly one request.

**The Vault workspace is lazy-loaded.** `App.tsx` loads the workspace with
`React.lazy` and `Suspense`, the same pattern the design, account, tenant and market routes
use. The entry chunk shrank from 762 kB to 562 kB and no longer contains Vault workspace,
IndexedDB or crypto code; that code now loads only on `/workspace`. The session-end lock
bridge is still reached only through a dynamic import.
`apps/web/test/app-vault-lazy.test.ts` enforces the import graph: `App.tsx` has no static
import from the Vault folder, its static imports reach no Vault file, and the bridge never
statically reaches the workspace.

## Combined verification

On the integration head including all five commits: web 52 files / 846 tests (one test
skipped unless the ROOT build source is available), shared 51 files / 1,694 (one such
skip), web build, typecheck and lint pass, the Playwright workspace suite passes (42) and
the Playwright agent-registry suite passes (6). The golden fixtures are unchanged.

## Boundary

Browser-local Vault only. There is no server-side storage of Vault contents, and no change
to the database, format, KDF, AAD or any frozen fixture. All fixture secrets are synthetic
and test-only.
