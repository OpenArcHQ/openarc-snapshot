import { COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION } from "@openarc/shared";
import type { Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import {
  acceptReceivedLanePayment,
  dispatchLanePayment,
  parseLanePaymentRequired,
  persistLanePayment,
  prepareLanePayment,
  type LaneFetch,
  type LaneFetchInit,
  type LaneFetchResponse,
  type LanePersist,
  type PersistedLanePayment,
  type PrepareLanePaymentInput,
} from "../src/index.js";

/** Fixed test clock (2026-09-09T20:26:40Z). No real time source participates. */
export const NOW = 1_789_000_000;
export const GATEWAY_WALLET = "0x0077777d7EBA4688BDeF3E311b846F25870A19B9";
export const USDC = "0x3600000000000000000000000000000000000000";
/** Circle's mainnet GatewayWallet (other chains). Used only as a must-reject value. */
export const MAINNET_GATEWAY_WALLET = "0x77777777Dcc4d5A8B6E418Fd04D8997ef11000eE";
export const ATTEMPT_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
export const GRANT_ID = "openarc:grant:12345678-1234-4234-8123-123456789abc";
export const ACTION_ID = "openarc:action:11111111-1111-4111-8111-111111111111";

/**
 * Throwaway in-memory key generated per call. Never written anywhere, never
 * funded, never used to broadcast anything.
 */
export function throwawayAccount() {
  const key = generatePrivateKey();
  return { key, account: privateKeyToAccount(key) };
}

export function freshNonce(): Hex {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

export function rawRequirement(payTo: string, overrides: Record<string, unknown> = {}) {
  return {
    scheme: "exact",
    network: "eip155:5042002",
    asset: USDC,
    amount: "10000",
    payTo,
    maxTimeoutSeconds: 604900,
    extra: {
      name: "GatewayWalletBatched",
      version: "1",
      verifyingContract: GATEWAY_WALLET,
    },
    ...overrides,
  };
}

export function paymentRequiredEnvelope(payTo: string, requirementOverrides: Record<string, unknown> = {}) {
  return {
    x402Version: 2,
    resource: {
      url: "https://provider.example/resource",
      description: "fixture resource",
      mimeType: "application/json",
    },
    accepts: [rawRequirement(payTo, requirementOverrides)],
  };
}

export function grantView(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION,
    grantId: GRANT_ID,
    actionId: ACTION_ID,
    providerId: "openarc:provider:77777777-7777-4777-8777-777777777777",
    listingId: "openarc:listing:88888888-8888-4888-8888-888888888888",
    listingVersion: "1",
    requirementId: "openarc:requirement:44444444-4444-4444-8444-444444444444",
    requirementDigest: `sha256:${"a".repeat(64)}`,
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    amountAtomic: "10000",
    feeAtomic: "0",
    debitAtomic: "10000",
    expiresAt: new Date((NOW + 200) * 1000).toISOString(),
    status: "issued",
    claimedAttemptId: null,
    ...overrides,
  };
}

export const claimedGrantView = () => grantView({ status: "claimed", claimedAttemptId: ATTEMPT_ID });

export const persistOk: LanePersist = async (record) => ({ bindingDigest: record.bindingDigest });

export async function preparedBuyerPayment(overrides: Partial<PrepareLanePaymentInput> = {}) {
  const buyer = throwawayAccount();
  const payee = throwawayAccount();
  const paymentRequired = parseLanePaymentRequired(paymentRequiredEnvelope(payee.account.address));
  const nonce = freshNonce();
  const unpersisted = await prepareLanePayment({
    paymentRequired,
    grant: grantView(),
    attemptId: ATTEMPT_ID,
    signer: buyer.account,
    nonce,
    nowUnixSeconds: NOW,
    ...overrides,
  });
  return { buyer, payee, paymentRequired, nonce, unpersisted };
}

/** Full buyer flow into an in-memory transport that captures the header. */
export async function capturedBuyerHeader() {
  const prepared = await preparedBuyerPayment();
  const persisted = await persistLanePayment(prepared.unpersisted, persistOk);
  let header = "";
  const dispatched = await dispatchLanePayment(
    persisted,
    async (request) => {
      header = request.headerValue;
      return { status: 200 };
    },
    NOW + 5,
  );
  return { ...prepared, persisted, dispatched, header };
}

export async function persistedProviderPayment(): Promise<{
  persisted: PersistedLanePayment;
  header: string;
  buyerKey: Hex;
  signature: string;
}> {
  const buyerSide = await capturedBuyerHeader();
  const unpersisted = await acceptReceivedLanePayment({
    header: buyerSide.header,
    paymentRequired: buyerSide.paymentRequired,
    grant: claimedGrantView(),
    attemptId: ATTEMPT_ID,
    nowUnixSeconds: NOW + 10,
  });
  const persisted = await persistLanePayment(unpersisted, persistOk);
  const decoded = JSON.parse(Buffer.from(buyerSide.header, "base64").toString("utf8")) as {
    payload: { signature: string };
  };
  return { persisted, header: buyerSide.header, buyerKey: buyerSide.buyer.key, signature: decoded.payload.signature };
}

export function mockFetch(handler: (url: string, init: LaneFetchInit) => Promise<LaneFetchResponse>) {
  const calls: { url: string; init: LaneFetchInit }[] = [];
  const fetch: LaneFetch = async (url, init) => {
    calls.push({ url, init });
    return handler(url, init);
  };
  return { fetch, calls };
}

export function jsonResponse(status: number, body: unknown): LaneFetchResponse {
  return { status, text: async () => JSON.stringify(body) };
}
