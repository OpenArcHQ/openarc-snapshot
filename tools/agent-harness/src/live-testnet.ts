/**
 * `--live-testnet` is a REFUSING STUB. It is not implemented and it never
 * sends.
 *
 * A live Arc-testnet run is P04-07 work and needs things only the USER can do:
 * create a disposable wallet, fund it from a faucet, and send its own approve
 * and deposit transactions. This tool does not create wallets, hold keys, move
 * funds or broadcast anything, so the flag prints those prerequisites and exits
 * non-zero. There is no environment variable, argument or build that turns this
 * into a sending path.
 */

export const LIVE_TESTNET_EXIT_CODE = 2;

export const LIVE_TESTNET_PREREQUISITES: readonly string[] = Object.freeze([
  "A live testnet run is NOT implemented here and this harness will not send one.",
  "P04-07 prerequisites, all of which the user performs themselves:",
  "  1. Create a DISPOSABLE buyer wallet. This tool never creates, holds, imports or writes a key.",
  "  2. Fund it from the Arc testnet faucet. No funds are ever moved by this tool.",
  "  3. Send the wallet's own USDC approve and Gateway deposit transactions from the user's own wallet software.",
  "  4. Re-check the live facilitator advertisement (/v1/x402/supported) against the pinned lane manifest,",
  "     including minValiditySeconds (604800) and whether a validity buffer above the SDK's 100 s is accepted.",
  "  5. Record the seller's real recorded pay-to terms for the listing version under test.",
  "Until a reviewed P04-07 packet lands, only the offline loopback mode exists:",
  "every facilitator and Gateway endpoint is a local fake and no non-loopback URL is accepted.",
]);

export function liveTestnetStub(): { readonly exitCode: number; readonly text: string } {
  return {
    exitCode: LIVE_TESTNET_EXIT_CODE,
    text: `${LIVE_TESTNET_PREREQUISITES.join("\n")}\n`,
  };
}
