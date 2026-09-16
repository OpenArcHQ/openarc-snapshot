# OpenArc roadmap

OpenArc exists to answer one question honestly: **what actually happened, and
how do we know?**

Agent activity produces claims from several directions at once — an agent says
it did something, a provider says it delivered, a payment network says a
transfer moved, a chain says a block was written. Those are four different kinds
of evidence with four different levels of certainty, and collapsing them into a
single green checkmark is how people end up believing things that are not true.
Everything below follows from refusing to do that.

## Available today

A local-first evidence workspace. Nothing is stored on our servers, and no
account is required.

| Capability | What it gives you |
| --- | --- |
| Arc observation | Read public account and transaction facts from Arc Testnet, recorded with their source, adapter version and observation time |
| Agent identity and reputation | Read ERC-8004 registry facts — who owns an agent, what feedback exists, what a validator actually answered |
| Job lifecycle | Read ERC-8183 job state from the deployed contract, anchored on finalized blocks |
| Payment observation | Read Circle Gateway transfer facts as reported, without inferring settlement |
| Encrypted workspace | An encrypted, browser-local vault for your evidence, with passphrase and recovery-secret unlock, backup, import and opaque rescue export |
| Investigations | Build a bounded graph and list of related records, with conflicts surfaced rather than merged |
| Bounded export | Share a capped, redacted report where identifiers, amounts and timestamps are each off by default |

**How it behaves, by design**

- **Read-only.** OpenArc observes public data. It signs nothing and moves nothing.
- **Nothing leaves your browser silently.** Every outbound request that follows a
  disclosure decision writes an encrypted receipt in your vault first, re-reads
  the stored vault state, and only then sends — once. If the vault changed
  underneath, the request does not go out.
- **Uncertainty stays visible.** An unanswered validation request reads as
  pending, never as a score of zero. A registry whose deployed code no longer
  matches its reviewed pin is reported as drifted, not verified. A gap in a log
  scan is a gap, not an empty result.
- **Your vault stays readable.** Formats, key derivation and record schemas are
  frozen and covered by golden fixtures. New record types are added additively,
  and a vault written by a newer build says so plainly instead of claiming a
  wrong passphrase.

## What we are building next

The sequence below is the order we intend to ship in. Each stage is built behind
its own switch and stays off until it earns its acceptance run.

**1. Hosted accounts and organizations.** Passwordless sign-in, organizations,
roles and memberships, and durable server-side storage for teams who want their
evidence to outlive one browser profile.

**2. Marketplace.** A reviewed catalog: providers publish listings, listings
carry a recorded price and an origin-approved endpoint, and every version change
is reviewable.

**3. Agent commerce on Arc Testnet.** The part that matters most and ships last
on purpose. Owner-set budgets and policies, scoped commerce sessions for agents,
explicit human approval of a purchase, one-use authorization grants, x402
payment through Circle Gateway, settlement observation and entitlements.

Its money rules are already fixed, because they are the whole point:

- Exposure that cannot be resolved stays held. No path marks a payment
  released, failed or refunded on a guess.
- A payment the network reports as complete reads as *submitted, awaiting
  on-chain confirmation* — never as paid or settled. Only a finalized,
  matching chain observation can say confirmed.
- Money that is unresolved is shown on its own line, never folded into a total.
- Every term of a purchase — price, network, asset, contract and payee — is
  derived on the server from the seller's published listing. A buying agent
  cannot choose where the money goes.
- Amounts are exact integers end to end. There is no floating-point arithmetic
  anywhere in the money path.

**4. Operator control room.** An organization-wide view of what is held,
claimed, unresolved and committed, a queue of anything stuck or unknown, and
the evidence behind every entry.

**5. Identity, reputation and disputes.** Per-source attribution rebuilt from
registry logs, ownership proofs, and an explicit OpenArc dispute record — kept
clearly distinct from the standards, which define no dispute mechanism.

**6. Job lifecycle.** Job state mirrored from the deployed contract with its
real terminal states, including the ones the standard's text and the deployed
code disagree about.

## Mainnet

OpenArc supports Arc Testnet only, and says so everywhere it matters.

Mainnet is not a decision we can make alone: it requires a published Circle
Gateway deployment on Arc mainnet and a mainnet USDC address in Circle's own
registry. Neither exists yet. Our network configuration is data-driven and
pinned per chain, so adding mainnet is configuration plus an acceptance run
rather than a rewrite — but we will not ship it, or claim readiness for it,
before those exist and we have run the full acceptance against them.

## How we decide something is ready

A stage ships when it has: a real database acceptance run rather than mocks,
adversarial tests that try to break its guarantees, proof that it fails closed
when its inputs are missing or hostile, and a production-image run with the
feature enabled and then disabled again. Anything we have not verified is
labelled unverified in the release notes rather than left to inference.
