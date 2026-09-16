import {
  COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION,
  type CommerceGrantProviderView,
} from "@openarc/shared";
import {
  LANE_PAYMENT_HEADER,
  dispatchLanePayment,
  parseLanePaymentRequired,
  persistLanePayment,
  prepareLanePayment,
} from "@openarc/x402";
import { randomUUID } from "node:crypto";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it } from "vitest";

import {
  ReferenceProviderError,
  assertLoopbackBaseUrl,
  createFakeFacilitatorFetch,
  startFakeFacilitator,
  startReferenceProvider,
  type FakeFacilitator,
  type FakeFacilitatorBehaviour,
  type GrantClaim,
  type ReferenceProvider,
} from "../src/index.js";

/**
 * Offline unit proofs for the reference provider and the local fakes.
 *
 * No OpenArc API, no database and no network egress: the grant claim is the
 * injected seam, the facilitator is the loopback fake, and every key is a
 * throwaway generated in memory for one assertion.
 */

const PAY_TO = "0xabcdefabcdefabcdefabcdefabcdefabcdef2222";
const AMOUNT = "1000000";
const ACTION_ID = "openarc:action:11111111-1111-4111-8111-111111111111";
const GRANT_ID = "openarc:grant:22222222-2222-4222-8222-222222222222";
const GRANT_TOKEN = `oag_v1_${"F".repeat(42)}Y`;
const API = "http://127.0.0.1:1";

const open: { provider: ReferenceProvider | undefined; facilitator: FakeFacilitator | undefined } = {
  provider: undefined,
  facilitator: undefined,
};

afterEach(async () => {
  await open.provider?.close();
  await open.facilitator?.close();
  open.provider = undefined;
  open.facilitator = undefined;
});

function grantView(attemptId: string, status: "issued" | "claimed"): CommerceGrantProviderView {
  return {
    schemaVersion: COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION,
    grantId: GRANT_ID,
    actionId: ACTION_ID,
    providerId: "openarc:provider:33333333-3333-4333-8333-333333333333",
    listingId: "openarc:listing:44444444-4444-4444-8444-444444444444",
    listingVersion: "1",
    requirementId: "openarc:requirement:55555555-5555-4555-8555-555555555555",
    requirementDigest: `sha256:${"a".repeat(64)}`,
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    amountAtomic: AMOUNT,
    feeAtomic: "0",
    debitAtomic: AMOUNT,
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    status,
    claimedAttemptId: status === "claimed" ? attemptId : null,
  } as CommerceGrantProviderView;
}

function claimStub(attemptId: string): GrantClaim {
  return async () => ({ outcome: "claimed", grant: grantView(attemptId, "claimed") });
}

async function stack(
  behaviour: FakeFacilitatorBehaviour,
  overrides: { claim?: GrantClaim; payTo?: string; attemptId?: string } = {},
): Promise<{ provider: ReferenceProvider; facilitator: FakeFacilitator; attemptId: string }> {
  const attemptId = overrides.attemptId ?? randomUUID();
  const facilitator = await startFakeFacilitator(behaviour);
  const provider = await startReferenceProvider({
    apiBaseUrl: API,
    providerSessionToken: `oas_pr_${"D".repeat(42)}Q`,
    payToAddress: overrides.payTo ?? PAY_TO,
    amountAtomic: AMOUNT,
    facilitator: createFakeFacilitatorFetch(facilitator.url),
    facilitatorTimeoutMs: 400,
    claim: overrides.claim ?? claimStub(attemptId),
  });
  open.provider = provider;
  open.facilitator = facilitator;
  return { provider, facilitator, attemptId };
}

/** One full buyer pass: 402, sign with a throwaway key, send exactly once. */
async function buyOnce(
  provider: ReferenceProvider,
  attemptId: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const required = await fetch(provider.resourceUrl);
  expect(required.status).toBe(402);
  const paymentRequired = parseLanePaymentRequired(await required.json());
  const account = privateKeyToAccount(generatePrivateKey());
  const nonce = `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`;
  const unpersisted = await prepareLanePayment({
    paymentRequired,
    grant: grantView(attemptId, "issued"),
    attemptId,
    signer: account,
    nonce,
    nowUnixSeconds: Math.floor(Date.now() / 1000),
  });
  const persisted = await persistLanePayment(unpersisted, async (record) => ({
    bindingDigest: record.bindingDigest,
  }));
  let captured: { status: number; body: Record<string, unknown> } = { status: 0, body: {} };
  await dispatchLanePayment(
    persisted,
    async (request) => {
      const response = await fetch(provider.resourceUrl, {
        method: "POST",
        headers: { "content-type": "application/json", [request.headerName]: request.headerValue },
        body: JSON.stringify({
          grantToken: GRANT_TOKEN,
          actionId: ACTION_ID,
          attemptId,
          input: { a: 2, b: 3 },
        }),
      });
      captured = { status: response.status, body: (await response.json()) as Record<string, unknown> };
      return captured;
    },
    Math.floor(Date.now() / 1000),
  );
  return captured;
}

describe("loopback admission", () => {
  it("refuses every non-loopback, credentialed or non-http base URL", () => {
    for (const value of [
      "https://gateway-api-testnet.circle.com",
      "http://example.com",
      "http://user:pw@127.0.0.1:8080",
      "ftp://127.0.0.1",
      "http://127.0.0.1:8080/?x=1",
      "not a url",
    ]) {
      expect(() => assertLoopbackBaseUrl(value, "field")).toThrow(ReferenceProviderError);
    }
    expect(assertLoopbackBaseUrl("http://127.0.0.1:8080", "field")).toBe("http://127.0.0.1:8080");
  });

  it("refuses to start against a non-loopback API", async () => {
    const facilitator = await startFakeFacilitator({ settle: "accept", lookup: "completed" });
    open.facilitator = facilitator;
    await expect(
      startReferenceProvider({
        apiBaseUrl: "https://api.example.com",
        providerSessionToken: `oas_pr_${"D".repeat(42)}Q`,
        payToAddress: PAY_TO,
        amountAtomic: AMOUNT,
        facilitator: createFakeFacilitatorFetch(facilitator.url),
      }),
    ).rejects.toBeInstanceOf(ReferenceProviderError);
  });

  it("refuses a facilitator transport pointed at a public origin", () => {
    expect(() => createFakeFacilitatorFetch("https://gateway-api-testnet.circle.com")).toThrow(
      ReferenceProviderError,
    );
  });
});

describe("the 402 requirement", () => {
  it("matches the pinned lane manifest and carries the configured pay-to", async () => {
    const { provider } = await stack({ settle: "accept", lookup: "completed" });
    const response = await fetch(provider.resourceUrl);
    expect(response.status).toBe(402);
    const body = (await response.json()) as Record<string, unknown>;
    const parsed = parseLanePaymentRequired(body);
    expect(parsed.requirement.payTo.toLowerCase()).toBe(PAY_TO);
    expect(parsed.requirement.amount).toBe(AMOUNT);
    expect(parsed.requirement.network).toBe("eip155:5042002");
    // The header carries the same envelope, base64 of the same JSON.
    const header = response.headers.get("payment-required");
    expect(header).not.toBeNull();
    expect(JSON.parse(Buffer.from(header as string, "base64").toString("utf8"))).toEqual(body);
  });
});

describe("release only on accepted settlement", () => {
  it("delivers the resource when the fake accepts, after exactly one settle", async () => {
    const { provider, facilitator, attemptId } = await stack({ settle: "accept", lookup: "completed" });
    const result = await buyOnce(provider, attemptId);
    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({
      status: "delivered",
      result: { schemaVersion: "openarc.reference-output.v1", sum: 5 },
      settlement: { outcome: "accepted" },
    });
    expect(facilitator.counts().settle).toBe(1);
    expect(provider.counts().delivered).toBe(1);
  });

  it.each([
    ["nonce_already_used", { settle: "nonce_already_used", lookup: "empty" }],
    ["a 500", { settle: "http_500", lookup: "empty" }],
    ["a hung facilitator", { settle: "timeout", lookup: "empty" }],
  ] as const)("holds and never delivers on %s, with one settle and no retry", async (_label, behaviour) => {
    const { provider, facilitator, attemptId } = await stack(behaviour as FakeFacilitatorBehaviour);
    const result = await buyOnce(provider, attemptId);
    expect(result.status).toBe(202);
    expect(result.body).toMatchObject({ status: "held", settlement: { outcome: "unknown" } });
    expect(JSON.stringify(result.body)).not.toContain("sum");
    expect(facilitator.counts().settle).toBe(1);
    expect(provider.counts().delivered).toBe(0);
    expect(provider.counts().held).toBe(1);
  });

  it("refuses a repeated paid request for the same attempt before any settle", async () => {
    const { provider, facilitator, attemptId } = await stack({ settle: "accept", lookup: "completed" });
    const first = await buyOnce(provider, attemptId);
    expect(first.status).toBe(200);
    // A replayed header for an attempt already settled never reaches the fake.
    const replay = await fetch(provider.resourceUrl, {
      method: "POST",
      headers: { "content-type": "application/json", [LANE_PAYMENT_HEADER]: "irrelevant" },
      body: JSON.stringify({ grantToken: GRANT_TOKEN, actionId: ACTION_ID, attemptId, input: { a: 2, b: 3 } }),
    });
    expect(replay.status).toBe(409);
    expect(await replay.json()).toMatchObject({ status: "refused", code: "attempt_already_settled" });
    expect(facilitator.counts().settle).toBe(1);
  });

  it("never settles when the grant claim is refused", async () => {
    const { provider, facilitator, attemptId } = await stack(
      { settle: "accept", lookup: "completed" },
      { claim: async () => ({ outcome: "refused", httpStatus: 409, code: "POLICY_DENIED" }) },
    );
    const result = await buyOnce(provider, attemptId);
    expect(result.status).toBe(409);
    expect(result.body).toMatchObject({ status: "refused", code: "grant_claim_refused" });
    expect(facilitator.counts().settle).toBe(0);
    expect(provider.counts().delivered).toBe(0);
  });
});

describe("the fake facilitator", () => {
  it("refuses a payload whose signature does not verify, and never accepts it", async () => {
    const facilitator = await startFakeFacilitator({ settle: "accept", lookup: "completed" });
    open.facilitator = facilitator;
    const response = await fetch(`${facilitator.url}/v1/x402/settle`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        paymentPayload: {
          payload: {
            authorization: {
              from: "0x1111111111111111111111111111111111111111",
              to: PAY_TO,
              value: AMOUNT,
              validAfter: "1",
              validBefore: "2",
              nonce: `0x${"7".repeat(64)}`,
            },
            signature: `0x${"1".repeat(130)}`,
          },
        },
      }),
    });
    expect(await response.json()).toMatchObject({ success: false, errorReason: "invalid_signature" });
    expect(facilitator.counts().acceptedSettles).toBe(0);
  });

  it("advertises exactly the pinned manifest values", async () => {
    const facilitator = await startFakeFacilitator({ settle: "accept", lookup: "completed" });
    open.facilitator = facilitator;
    const response = await fetch(`${facilitator.url}/v1/x402/supported`);
    const body = (await response.json()) as { kinds: { network: string; extra: { minValiditySeconds: number } }[] };
    expect(body.kinds).toHaveLength(1);
    expect(body.kinds[0]?.network).toBe("eip155:5042002");
    expect(body.kinds[0]?.extra.minValiditySeconds).toBe(604800);
  });
});
