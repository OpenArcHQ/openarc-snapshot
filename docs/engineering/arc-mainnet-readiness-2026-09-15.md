# Arc mainnet readiness assessment — verified 2026-09-15

Read-only research against official Circle and Arc sources. No funds moved, no
transaction sent, no new dependency added, no service created.

Arc public mainnet is scheduled for **September 16, 2026** — tomorrow.

## Headline: the mainnet payment lane is externally blocked

OpenArc's chosen purchase lane is Circle Gateway x402 batching. **Circle has not
published an Arc mainnet Gateway deployment.** This is an external dependency we
cannot satisfy by writing code, and it cannot be "completed behind a flag".

## What the official sources actually say today

### 1. Arc documents testnet only

`docs.arc.io/arc/references/rpc-endpoints` documents exactly one network:

| Field | Value |
| --- | --- |
| Network | Arc Testnet |
| Chain ID | `5042002` (`0x4D1152`) |
| RPC | `https://rpc.testnet.arc.io` |
| Explorer | `https://testnet.arcscan.app` |
| Native gas token | USDC |

The page states verbatim that its values "apply to the Arc Testnet. Mainnet
endpoints and parameters are published separately when available."

**There is no officially published Arc mainnet RPC, explorer or chain ID.**

### 2. Circle Gateway does not list Arc mainnet

`developers.circle.com/gateway/references/contract-addresses`:

- **Arc Testnet is present**, domain `26`, GatewayWallet
  `0x0077777d7EBA4688BDeF3E311b846F25870A19B9`, GatewayMinter
  `0x0022222ABE238Cc2C7Bb1f21003F0a260052475B`.
- The **mainnet** table lists roughly ten chains — Arbitrum, Avalanche, Base,
  Ethereum, HyperEVM, OP, Polygon PoS, Sei, Sonic, Unichain, World Chain — with
  GatewayWallet `0x77777777Dcc4d5A8B6E418Fd04D8997ef11000eE` and GatewayMinter
  `0x2222222d7164433c4C09B0b0D809a9b52C04C205`.
- **Arc does not appear in the mainnet table.**

This also confirms an earlier project caution: `0x0077777d7EBA...` is the
**GatewayWallet contract**, not the USDC token contract.

### 3. Circle's USDC address registry does not list Arc mainnet

`developers.circle.com/stablecoins/usdc-contract-addresses` lists Arc Testnet
USDC at `0x3600000000000000000000000000000000000000` and ~41 mainnet chains.
**Arc mainnet is not among them.**

### 4. Third-party chain ID claims are unverified

Aggregators (QuickNode, Sequence, metaschool, The Graph) publish an Arc mainnet
chain ID of **1243 / `0x4db`**. **No official Circle or Arc source confirms
this.** Project boundaries explicitly forbid guessing a mainnet chain ID, RPC, token or
verifier address, or swapping the testnet URL. Do not pin 1243 until an official
Arc or Circle manifest publishes it.

## Resolved: the payment-authorization validity contradiction

Earlier project notes recorded an unresolved discrepancy in signature validity. It is
**still live in Circle's own documentation today**, and the two pages directly
contradict each other:

| Source | Requirement |
| --- | --- |
| Gateway **seller quickstart** | "`validBefore` ... must be at least **7 days** in the future, or Gateway will reject it." |
| Gateway **EIP-3009 signing howto** | "`validBefore` must be at least **3 days** in the future", with a worked example using **5 days**. |

**Resolution: pin the stricter requirement — at least 7 days plus a buffer.** A
5-day authorization built by following the signing example would be rejected by
Gateway according to the seller page, so the signing doc's example is unsafe to
copy. Treat 7 days + buffer as the contract and re-verify at integration.

This does not change OpenArc's 300-second grant bound: the grant is an internal
one-use delegation and was never a substitute for the protocol signature
lifetime. A 7-day signature lifetime alongside a 300-second grant is exactly the
intended asymmetry.

## Still unpinned: SDK versions

`@circle-fin/x402-batching`, `@x402/core`, `@x402/evm` and `viem` are installed
**without pinned versions** in Circle's quickstart. Exact compatible versions are
still not frozen. Pin them explicitly before any lane work; do not inherit a
floating range.

## EIP-712 signing domain

Name `GatewayWalletBatched`, version `1`, verified against the GatewayWallet
contract for the target chain. Unchanged from the earlier project record, and the Arc
testnet address is confirmed above.

## What this means for launch

**Mainnet swap-over cannot be completed today, and not because of OpenArc.** The
blocking facts are all external:

1. No official Arc mainnet chain ID, RPC or explorer is published.
2. No Circle Gateway deployment exists on Arc mainnet.
3. No Arc mainnet USDC contract address is published by Circle.

Any of (1)-(3) alone blocks a real mainnet purchase. Guessing an address or
reusing a testnet value would risk sending value to an address we have not
verified, which is exactly the class of action the standing boundaries forbid.

**What we can do without any of the above**, and what the work should target:

- Finish PORT-03 and the testnet purchase lane (PORT-04) against Arc **testnet**,
  which is fully documented and Gateway-supported today.
- Keep network configuration data-driven so a mainnet entry is added, not coded:
  chain ID, RPC, explorer, USDC address, GatewayWallet, GatewayMinter and domain
  all belong in one pinned manifest with no testnet default fallback.
- Pin the SDK versions and the 7-day-plus-buffer authorization contract now.
- Re-check the three official pages above at and after Arc mainnet launch.
  Read-only mainnet exploration needs no funds and is permitted; transactions,
  wallet funding, contract deployment and new billed services remain separately
  bounded, and S-M11 remains a distinct acceptance gate.

## Sources

- https://docs.arc.io/arc/references/rpc-endpoints
- https://developers.circle.com/gateway/references/contract-addresses
- https://developers.circle.com/stablecoins/usdc-contract-addresses
- https://developers.circle.com/gateway/nanopayments/quickstarts/seller
- https://developers.circle.com/gateway/nanopayments/howtos/eip-3009-signing
- https://www.arc.io/blog/arc-mainnet-goes-live-on-september-16-2026
