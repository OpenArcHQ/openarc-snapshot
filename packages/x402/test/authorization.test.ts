import { BatchEvmScheme } from "@circle-fin/x402-batching/client";
import { recoverTypedDataAddress, type Hex } from "viem";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  LANE_DEFAULT_VALIDITY_BUFFER_SECONDS,
  LANE_BINDING_SCHEMA_VERSION,
  X402LaneError,
  acceptReceivedLanePayment,
  buildLaneTypedData,
  dispatchLanePayment,
  parseLanePaymentBinding,
  parseLanePaymentRequired,
  persistLanePayment,
  prepareLanePayment,
  releaseUnsentLanePayment,
  type DispatchedLaneAttempt,
  type LanePaymentBinding,
  type PersistedLanePayment,
  type UnpersistedLanePayment,
} from "../src/index.js";
import {
  ATTEMPT_ID,
  NOW,
  capturedBuyerHeader,
  claimedGrantView,
  freshNonce,
  grantView,
  paymentRequiredEnvelope,
  persistOk,
  preparedBuyerPayment,
  throwawayAccount,
} from "./fixtures.js";

async function codeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (error) {
    return error instanceof X402LaneError ? error.code : `non_lane_error:${String(error)}`;
  }
  return "no_throw";
}

function decodeHeader(header: string) {
  return JSON.parse(Buffer.from(header, "base64").toString("utf8")) as {
    x402Version: number;
    accepted: Record<string, unknown>;
    resource: Record<string, unknown>;
    payload: { authorization: Record<string, string>; signature: Hex };
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("authorization builder", () => {
  it("builds GatewayWalletBatched typed data with ≥ 7 days + buffer validity and a caller nonce", async () => {
    const { unpersisted, nonce, buyer, payee } = await preparedBuyerPayment();
    const binding = unpersisted.binding;
    expect(unpersisted.phase).toBe("unpersisted");
    expect(binding.nonce).toBe(nonce.toLowerCase());
    expect(binding.from).toBe(buyer.account.address);
    expect(binding.to).toBe(payee.account.address);
    expect(binding.value).toBe("10000");
    expect(BigInt(binding.validAfter)).toBe(BigInt(NOW - 600));
    expect(BigInt(binding.validBefore)).toBe(BigInt(NOW + 604800 + LANE_DEFAULT_VALIDITY_BUFFER_SECONDS));
    expect(BigInt(binding.validBefore) - BigInt(NOW)).toBeGreaterThan(604800n + 100n);

    const typed = buildLaneTypedData(binding);
    expect(typed.domain).toEqual({
      name: "GatewayWalletBatched",
      version: "1",
      chainId: 5042002,
      verifyingContract: "0x0077777d7EBA4688BDeF3E311b846F25870A19B9",
    });
    expect(typed.primaryType).toBe("TransferWithAuthorization");
    expect(parseLanePaymentBinding(JSON.parse(JSON.stringify(binding)))).toEqual(binding);
  });

  it("uses a larger seller maxTimeoutSeconds but never shortens below the floor", async () => {
    const payee = throwawayAccount().account.address;
    const buyer = throwawayAccount().account;
    const long = await prepareLanePayment({
      paymentRequired: parseLanePaymentRequired(paymentRequiredEnvelope(payee, { maxTimeoutSeconds: 608400 })),
      grant: grantView(),
      attemptId: ATTEMPT_ID,
      signer: buyer,
      nonce: freshNonce(),
      nowUnixSeconds: NOW,
    });
    expect(BigInt(long.binding.validBefore)).toBe(BigInt(NOW + 608400));
    const short = await prepareLanePayment({
      paymentRequired: parseLanePaymentRequired(paymentRequiredEnvelope(payee, { maxTimeoutSeconds: 3600 })),
      grant: grantView(),
      attemptId: ATTEMPT_ID,
      signer: buyer,
      nonce: freshNonce(),
      nowUnixSeconds: NOW,
      validityBufferSeconds: 400,
    });
    expect(BigInt(short.binding.validBefore)).toBe(BigInt(NOW + 604800 + 400));
  });

  it("refuses validity buffers outside 400..3600 s (including the SDK's 100 s)", async () => {
    for (const validityBufferSeconds of [0, 100, 399, 3601, 400.5, Number.NaN]) {
      expect(await codeOf(() => preparedBuyerPayment({ validityBufferSeconds }))).toBe("validity_rejected");
    }
  });

  it("refuses bad nonces, clocks, grants and self-transfer before signing", async () => {
    const zero = `0x${"0".repeat(64)}`;
    for (const nonce of [zero, "0x1234", `0x${"g".repeat(64)}`, ""]) {
      expect(await codeOf(() => preparedBuyerPayment({ nonce }))).toBe("invalid_nonce");
    }
    for (const nowUnixSeconds of [NOW + 0.5, -1, Number.NaN]) {
      expect(await codeOf(() => preparedBuyerPayment({ nowUnixSeconds }))).toBe("invalid_clock");
    }
    expect(await codeOf(() => preparedBuyerPayment({ grant: grantView({ amountAtomic: "9999", debitAtomic: "9999" }) }))).toBe(
      "grant_mismatch",
    );
    expect(await codeOf(() => preparedBuyerPayment({ grant: grantView({ status: "revoked" }) }))).toBe("grant_mismatch");
    expect(await codeOf(() => preparedBuyerPayment({ nowUnixSeconds: NOW + 200 }))).toBe("grant_mismatch");
    expect(await codeOf(() => preparedBuyerPayment({ grant: grantView({ networkId: "eip155:1" }) }))).toBe("grant_mismatch");
    expect(await codeOf(() => preparedBuyerPayment({ attemptId: "not-a-uuid" }))).toBe("invalid_binding");

    const self = throwawayAccount().account;
    expect(
      await codeOf(() =>
        prepareLanePayment({
          paymentRequired: parseLanePaymentRequired(paymentRequiredEnvelope(self.address)),
          grant: grantView(),
          attemptId: ATTEMPT_ID,
          signer: self,
          nonce: freshNonce(),
          nowUnixSeconds: NOW,
        }),
      ),
    ).toBe("invalid_address");
  });

  it("refuses a signer that signs anything other than the lane typed data", async () => {
    const real = throwawayAccount().account;
    const other = throwawayAccount().account;
    const forged = await other.signTypedData(buildLaneTypedData((await preparedBuyerPayment()).unpersisted.binding));
    expect(
      await codeOf(() =>
        preparedBuyerPayment({ signer: { address: real.address, signTypedData: async () => forged } }),
      ),
    ).toBe("signature_mismatch");
    expect(
      await codeOf(() => preparedBuyerPayment({ signer: { address: real.address, signTypedData: async () => "0x1234" } })),
    ).toBe("signature_mismatch");
  });

  it("performs no network I/O while preparing or persisting", async () => {
    const fetchSpy = vi.fn(async () => {
      throw new Error("network forbidden");
    });
    vi.stubGlobal("fetch", fetchSpy);
    const { unpersisted } = await preparedBuyerPayment();
    await persistLanePayment(unpersisted, persistOk);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("produces the same signature as the pinned SDK for identical authorization fields", async () => {
    const { account } = throwawayAccount();
    const payee = throwawayAccount().account.address;
    const paymentRequired = parseLanePaymentRequired(paymentRequiredEnvelope(payee));
    const scheme = new BatchEvmScheme(account);
    const created = await scheme.createPaymentPayload(2, {
      ...paymentRequired.requirement.accepted,
      extra: { ...paymentRequired.requirement.accepted.extra },
    });
    const payload = created.payload as { authorization: Record<string, string>; signature: Hex };
    const auth = payload.authorization;
    // The SDK's own window is 604800 + 100, which this lane refuses as too tight.
    expect(BigInt(auth.validBefore!) - BigInt(auth.validAfter!)).toBe(604900n + 600n);

    const binding: LanePaymentBinding = {
      schemaVersion: LANE_BINDING_SCHEMA_VERSION,
      role: "buyer",
      network: "eip155:5042002",
      grantId: grantView().grantId,
      actionId: grantView().actionId,
      attemptId: ATTEMPT_ID,
      grantRequirementDigest: `sha256:${"a".repeat(64)}`,
      laneRequirementDigest: paymentRequired.requirement.digest,
      verifyingContract: paymentRequired.requirement.verifyingContract,
      asset: paymentRequired.requirement.asset,
      from: account.address,
      to: payee,
      value: auth.value!,
      validAfter: auth.validAfter!,
      validBefore: auth.validBefore!,
      nonce: auth.nonce! as Hex,
    };
    const ours = await account.signTypedData(buildLaneTypedData(binding));
    expect(ours).toBe(payload.signature);
  });
});

describe("two-phase prepare → persist → send", () => {
  it("cannot send an unpersisted, forged or cast payload", async () => {
    const { unpersisted } = await preparedBuyerPayment();
    const transport = vi.fn(async () => ({}));
    expect(
      await codeOf(() => dispatchLanePayment(unpersisted as unknown as PersistedLanePayment, transport, NOW)),
    ).toBe("not_persisted");
    const forged = { phase: "persisted", binding: unpersisted.binding, bindingDigest: unpersisted.bindingDigest };
    expect(await codeOf(() => dispatchLanePayment(forged as unknown as PersistedLanePayment, transport, NOW))).toBe(
      "not_persisted",
    );
    expect(transport).not.toHaveBeenCalled();

    // @ts-expect-error an unpersisted handle is not a PersistedLanePayment at the type level
    const typeProof: PersistedLanePayment = unpersisted;
    expect(typeProof).toBe(unpersisted);
  });

  it("stays unsendable when the durable write throws or does not echo the digest", async () => {
    const { unpersisted } = await preparedBuyerPayment();
    const transport = vi.fn(async () => ({}));
    expect(
      await codeOf(() =>
        persistLanePayment(unpersisted, async () => {
          throw new Error("db down");
        }),
      ),
    ).toBe("persistence_failed");
    expect(await codeOf(() => persistLanePayment(unpersisted, async () => ({ bindingDigest: `sha256:${"0".repeat(64)}` })))).toBe(
      "persistence_mismatch",
    );
    expect(await codeOf(() => persistLanePayment(unpersisted, async () => undefined as never))).toBe("persistence_mismatch");
    expect(await codeOf(() => dispatchLanePayment(unpersisted as unknown as PersistedLanePayment, transport, NOW))).toBe(
      "not_persisted",
    );
    expect(transport).not.toHaveBeenCalled();

    // A later successful write makes it sendable.
    const persisted = await persistLanePayment(unpersisted, persistOk);
    expect(await codeOf(() => persistLanePayment(unpersisted, persistOk))).toBe("already_persisted");
    await dispatchLanePayment(persisted, transport, NOW);
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it("hands the persist callback the binding only, never the signature", async () => {
    const { unpersisted } = await preparedBuyerPayment();
    let stored = "";
    const persisted = await persistLanePayment(unpersisted, async (record) => {
      stored = JSON.stringify(record);
      return { bindingDigest: record.bindingDigest };
    });
    let header = "";
    await dispatchLanePayment(persisted, async (request) => {
      header = request.headerValue;
    }, NOW);
    const signature = decodeHeader(header).payload.signature;
    expect(signature).toMatch(/^0x[0-9a-f]{130}$/u);
    expect(stored).not.toContain(signature.slice(2));
    expect(stored).toContain(unpersisted.binding.nonce);
  });

  it("sends exactly once, never resends, and never releases after dispatch", async () => {
    const { unpersisted, buyer } = await preparedBuyerPayment();
    const persisted = await persistLanePayment(unpersisted, persistOk);
    const transport = vi.fn(async () => {
      throw new Error("socket hang up");
    });
    const dispatched = await dispatchLanePayment(persisted, transport, NOW + 1);
    expect(dispatched.exposure).toBe("possibly_exposed");
    expect(dispatched.transport.outcome).toBe("threw");
    expect(transport).toHaveBeenCalledTimes(1);

    const header = (transport.mock.calls as unknown as [{ headerName: string; headerValue: string }][])[0]![0];
    expect(header.headerName).toBe("PAYMENT-SIGNATURE");
    const decoded = decodeHeader(header.headerValue);
    expect(decoded.x402Version).toBe(2);
    expect(
      await recoverTypedDataAddress({ ...buildLaneTypedData(unpersisted.binding), signature: decoded.payload.signature }),
    ).toBe(buyer.account.address);

    expect(await codeOf(() => dispatchLanePayment(persisted, transport, NOW + 2))).toBe("already_dispatched");
    expect(transport).toHaveBeenCalledTimes(1);
    expect(await codeOf(async () => releaseUnsentLanePayment(persisted))).toBe("already_dispatched");
    expect(await codeOf(async () => releaseUnsentLanePayment(unpersisted))).toBe("already_dispatched");

    // @ts-expect-error a dispatched attempt can never be passed to the release function
    const releaseTypeProof: Parameters<typeof releaseUnsentLanePayment>[0] = dispatched as DispatchedLaneAttempt;
    expect(releaseTypeProof).toBe(dispatched);
  });

  it("allows release only before dispatch, after which sending is refused", async () => {
    const { unpersisted } = await preparedBuyerPayment();
    const persisted = await persistLanePayment(unpersisted, persistOk);
    expect(releaseUnsentLanePayment(persisted).phase).toBe("released_unsent");
    const transport = vi.fn(async () => ({}));
    expect(await codeOf(() => dispatchLanePayment(persisted, transport, NOW))).toBe("already_released");
    expect(await codeOf(async () => releaseUnsentLanePayment(persisted))).toBe("already_released");
    expect(transport).not.toHaveBeenCalled();

    const second = await preparedBuyerPayment();
    releaseUnsentLanePayment(second.unpersisted as UnpersistedLanePayment);
    expect(await codeOf(() => persistLanePayment(second.unpersisted, persistOk))).toBe("already_released");
  });

  it("refuses to send once remaining validity is under 7 days, leaving it releasable", async () => {
    const { unpersisted } = await preparedBuyerPayment();
    const persisted = await persistLanePayment(unpersisted, persistOk);
    const transport = vi.fn(async () => ({}));
    const late = Number(BigInt(unpersisted.binding.validBefore) - 604800n + 1n);
    expect(await codeOf(() => dispatchLanePayment(persisted, transport, late))).toBe("validity_rejected");
    expect(transport).not.toHaveBeenCalled();
    expect(releaseUnsentLanePayment(persisted).phase).toBe("released_unsent");
  });
});

describe("provider acceptance of a received payment", () => {
  it("accepts the buyer header against the issued requirement and claimed grant", async () => {
    const buyerSide = await capturedBuyerHeader();
    const received = await acceptReceivedLanePayment({
      header: buyerSide.header,
      paymentRequired: buyerSide.paymentRequired,
      grant: claimedGrantView(),
      attemptId: ATTEMPT_ID,
      nowUnixSeconds: NOW + 10,
    });
    expect(received.binding.role).toBe("provider");
    expect(received.binding.nonce).toBe(buyerSide.dispatched.binding.nonce);
    expect(received.binding.validBefore).toBe(buyerSide.dispatched.binding.validBefore);
  });

  it("rejects tampering, short validity, wrong requirement, unclaimed grants and foreign signatures", async () => {
    const buyerSide = await capturedBuyerHeader();
    const base = decodeHeader(buyerSide.header);
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value), "utf8").toString("base64");
    const accept = (header: string, overrides: Record<string, unknown> = {}) =>
      codeOf(() =>
        acceptReceivedLanePayment({
          header,
          paymentRequired: buyerSide.paymentRequired,
          grant: claimedGrantView(),
          attemptId: ATTEMPT_ID,
          nowUnixSeconds: NOW + 10,
          ...overrides,
        }),
      );
    const withAuth = (changes: Record<string, string>) =>
      encode({ ...base, payload: { ...base.payload, authorization: { ...base.payload.authorization, ...changes } } });

    expect(await accept(withAuth({ value: "10001" }))).toBe("invalid_payment_payload");
    expect(await accept(withAuth({ to: throwawayAccount().account.address }))).toBe("invalid_payment_payload");
    expect(await accept(withAuth({ nonce: freshNonce() }))).toBe("signature_mismatch");
    const threeDays = (BigInt(NOW + 10) + 3n * 86400n).toString();
    expect(await accept(withAuth({ validBefore: threeDays }))).toBe("validity_rejected");
    expect(await accept(withAuth({ validAfter: String(NOW + 1000) }))).toBe("validity_rejected");
    expect(await accept(withAuth({ validBefore: String(NOW + 365 * 86400) }))).toBe("validity_rejected");
    expect(await accept(encode({ ...base, accepted: { ...base.accepted, amount: "1" } }))).toBe("invalid_payment_payload");
    expect(await accept(encode({ ...base, x402Version: 1 }))).toBe("invalid_payment_payload");
    expect(await accept(encode({ ...base, extensions: { foo: 1 } }))).toBe("invalid_payment_payload");
    expect(await accept(encode({ ...base, facilitatorUrl: "https://gateway-api.circle.com" }))).toBe("invalid_payment_payload");
    expect(await accept("%%%")).toBe("invalid_payment_payload");
    expect(await accept(buyerSide.header, { grant: grantView() })).toBe("grant_mismatch");
    expect(await accept(buyerSide.header, { grant: grantView({ status: "claimed", claimedAttemptId: "aaaaaaaa-cccc-4ddd-8eee-ffffffffffff" }) })).toBe(
      "grant_mismatch",
    );

    const foreign = throwawayAccount().account;
    const foreignSig = await foreign.signTypedData(buildLaneTypedData(buyerSide.dispatched.binding));
    expect(await accept(encode({ ...base, payload: { ...base.payload, signature: foreignSig } }))).toBe("signature_mismatch");
  });

  it("provider payments cannot be sent through the buyer transport nor released", async () => {
    const buyerSide = await capturedBuyerHeader();
    const received = await acceptReceivedLanePayment({
      header: buyerSide.header,
      paymentRequired: buyerSide.paymentRequired,
      grant: claimedGrantView(),
      attemptId: ATTEMPT_ID,
      nowUnixSeconds: NOW + 10,
    });
    const persisted = await persistLanePayment(received, persistOk);
    const transport = vi.fn(async () => ({}));
    expect(await codeOf(() => dispatchLanePayment(persisted, transport, NOW + 10))).toBe("wrong_role");
    expect(await codeOf(async () => releaseUnsentLanePayment(persisted))).toBe("wrong_role");
    expect(transport).not.toHaveBeenCalled();
  });
});
