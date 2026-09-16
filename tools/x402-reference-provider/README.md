# Reference x402 provider (PORT-04 P04-03)

TESTNET REFERENCE, OFFLINE ONLY. This package is a local reference seller and a
LOCAL FAKE facilitator. It is not Circle, not Gateway, not a deployment and not
a payment implementation. It settles nothing and proves no settlement.

## What it does

`startReferenceProvider` serves one paid resource — the deterministic integer
sum already declared by `tools/reference-provider` — over loopback:

1. an unpaid request gets a **402** whose single requirement is built from the
   pinned Arc-testnet lane manifest (`eip155:5042002`, `exact`, `x402Version` 2,
   `GatewayWalletBatched` v1, the pinned GatewayWallet and USDC) and whose
   `payTo` is the **seller's recorded payment terms**, passed in by the operator.
   The envelope is re-parsed with the lane's own `parseLanePaymentRequired`
   before it is served, so an envelope this lane would reject is never emitted;
2. a paid request is **claimed through the real OpenArc provider claim API**
   (`POST /v2/provider/grants/claim`, live `oas_pr_` session plus the buyer's
   one-use `oag_v1_` token in the body) **before anything is delivered**;
3. the presented `PAYMENT-SIGNATURE` is verified offline by `packages/x402`
   against the exact issued requirement and the claimed grant;
4. the payment is persisted provider-side, then settled **exactly once** through
   the injected facilitator transport.

**The resource is released only on `accepted`.** A timeout, a settle error
reason, a 500 and every unreadable answer are `unknown` and HELD: no resource is
served, and the lane never re-signs or re-sends. A repeated paid request for the
same attempt is refused before any facilitator call.

## How the fakes inject

`packages/x402` has no default `fetch`: `createLaneFacilitatorClient` requires
one. `createFakeFacilitatorFetch` is that injection. The client still builds
every request against the pinned Circle testnet origin, and the adapter refuses
any URL whose origin is not exactly that pinned origin before re-targeting the
path at a loopback fake. The pinned host is never resolved and never contacted,
and no other host is reachable.

`startFakeFacilitator` implements `/v1/x402/settle`, `/v1/x402/transfers` and
`/v1/x402/supported` on loopback. It verifies the presented EIP-712 signature,
so an accepted settle really does prove the buyer signed. Its behaviour —
acceptance, `nonce_already_used`, a 500, or a hang that makes the lane's own
timeout fire — is chosen by the caller. Received payloads stay in memory, are
never written to disk and are never returned: only counts and the non-secret
transfer projection leave the module.

## Boundaries

- Loopback only. A non-loopback API or facilitator base URL is refused before
  the server listens.
- No real or persistent key. This package never signs a buyer payment.
- No signature, grant token or provider session is logged, echoed or persisted.
- A claim is not a payment, a settlement or a delivery, and `accepted` means
  accepted-and-locked, never settled.
