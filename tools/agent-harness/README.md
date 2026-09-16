# Headless buyer-agent harness (PORT-04 P04-03)

OFFLINE ONLY. This harness drives the whole x402 buyer flow against a LOCAL
OpenArc stack with local fakes. It never contacts Circle, Gateway or Arc, never
holds a persistent key, and never sends a live payment.

## The pass it performs

With an `oacs_v1_` commerce session:

1. fetch the provider's **402** and parse it with the lane's own strict parser;
2. register the verified requirement (`POST /v2/agent/commerce-payment-requirements`);
3. check that the 402 describes the **seller's server-derived terms** — the
   pay-to, amount and network the database returned. A mismatch is refused here,
   before any key, signature or attempt exists;
4. authorize the action and issue the grant through the existing agent routes;
5. prepare and sign with `packages/x402` using an **ephemeral in-memory key**;
6. persist the attempt (`POST /v2/agent/commerce-payment-attempts`);
7. record the one dispatch (`.../:attemptId/dispatch`);
8. send **exactly once** — the paid retry of the resource, carrying
   `PAYMENT-SIGNATURE`;
9. classify the exposure through the facilitator (a read-only transfer lookup);
10. read the durable attempt back.

## Lane rules it follows

- **Persist before dispatch.** The signature cannot leave the process until the
  API has durably recorded the attempt, and the dispatch is recorded before the
  send.
- **Dispatch exactly once.** The lane refuses a second dispatch of the same
  handle; this harness never re-signs, re-sends or retries anything.
- **Any unclear outcome is unknown and held.** A timeout, a transport failure,
  an unreadable answer or a refused dispatch record never reads as a failure and
  never releases exposure. A refused dispatch record means *do not send*.
- **One release only.** A payment refused before persistence provably never
  reached a transport, and only that path releases.

## Output

A structured, secret-free JSON run report
(`openarc.agent-harness.run-report.v1`). No credential, private key, signature
or nonce is representable in it, and the report is re-checked against the exact
secrets the run held plus every credential namespace before it is returned.

The durable attempt reads `unknown` after a dispatch: `unknown` is the held
state, and no runtime route can move an attempt out of it (the observation
recorder is migrator-private and has no route). The lane's own classification of
what the facilitator reported is carried separately, in `exposure`.

## Refusals and the live stub

Every endpoint — API, provider, facilitator and the optional RPC URL — must be
loopback. Nothing defaults to a live URL, and a non-loopback URL is refused
before any request.

`--live-testnet` is a **refusing stub**: it prints the P04-07 prerequisites (a
user-created, faucet-funded disposable wallet whose approve and deposit the user
sends themselves) and exits non-zero. No sending path exists in this packet.

## Usage

```sh
OPENARC_COMMERCE_SESSION_TOKEN=... node tools/agent-harness/dist/cli.js \
  --api http://127.0.0.1:5491 \
  --provider http://127.0.0.1:5492/v1/sum \
  --facilitator http://127.0.0.1:5493 \
  --listing openarc:listing:... --a 2 --b 3
```

The commerce session is read from the environment, never from argv, so it cannot
appear in a process listing. Exit codes: `0` delivered, `3` held, `4` refused,
`64` configuration refused, `2` the live-testnet stub.
