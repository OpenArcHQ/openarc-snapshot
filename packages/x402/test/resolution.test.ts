import { describe, expect, expectTypeOf, it } from "vitest";

import {
  LANE_EXPOSURE_ADMITS_NO_RELEASE,
  LANE_SETTLE_ADMITS_NO_RELEASE,
  classifyLaneAttempt,
  createLaneFacilitatorClient,
  type LaneExposure,
  type LaneExposureAdmitsNoRelease,
  type LaneLookupObservation,
  type LanePaymentBinding,
  type LaneSettleAdmitsNoRelease,
  type LaneSettleObservation,
  type LaneTransferRecord,
} from "../src/index.js";
import { NOW, jsonResponse, mockFetch, persistedProviderPayment } from "./fixtures.js";

const TX_HASH = `0x${"ab".repeat(32)}`;
const TRANSFER_ID = "3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b";

async function binding(): Promise<LanePaymentBinding> {
  return (await persistedProviderPayment()).persisted.binding;
}

function record(b: LanePaymentBinding, overrides: Partial<LaneTransferRecord> = {}): LaneTransferRecord {
  return {
    id: TRANSFER_ID,
    status: "completed",
    fromAddress: b.from.toLowerCase(),
    toAddress: b.to,
    amount: b.value,
    nonce: b.nonce,
    sendingNetwork: "eip155:5042002",
    recipientNetwork: "eip155:5042002",
    txHash: TX_HASH,
    ...overrides,
  };
}

const records = (transfers: LaneTransferRecord[], hasMorePages = false): LaneLookupObservation => ({
  kind: "records",
  transfers,
  hasMorePages,
});

const nonceAlreadyUsed: LaneSettleObservation = {
  outcome: "unknown",
  reason: "settle_error_reason",
  httpStatus: 200,
  errorReason: "nonce_already_used",
};

describe("lost-settle resolution", () => {
  it("commits only a single matching completed transfer with a batch hash", async () => {
    const b = await binding();
    expect(classifyLaneAttempt({ binding: b, nowUnixSeconds: NOW, lookup: records([record(b)]) })).toEqual({
      state: "committed",
      disposition: "committed",
      transferId: TRANSFER_ID,
      gatewayStatus: "completed",
      batchTxHash: TX_HASH,
      onchainReceiptVerified: false,
    });
  });

  it("never commits or releases for timeout, silence, failed, nonce_already_used, not-found or expiry", async () => {
    const b = await binding();
    const afterExpiry = Number(BigInt(b.validBefore) + 1n);
    const cases: [string, Parameters<typeof classifyLaneAttempt>[0], string][] = [
      ["timeout", { binding: b, nowUnixSeconds: NOW, lookup: { kind: "timeout" } }, "timeout"],
      ["silence/transport", { binding: b, nowUnixSeconds: NOW, lookup: { kind: "transport_error" } }, "transport_error"],
      ["http 404", { binding: b, nowUnixSeconds: NOW, lookup: { kind: "http_error", status: 404 } }, "http_error"],
      ["malformed", { binding: b, nowUnixSeconds: NOW, lookup: { kind: "malformed" } }, "malformed_response"],
      ["not found", { binding: b, nowUnixSeconds: NOW, lookup: records([]) }, "not_found"],
      ["not found after validBefore", { binding: b, nowUnixSeconds: afterExpiry, lookup: records([]) }, "not_found_after_expiry"],
      ["failed", { binding: b, nowUnixSeconds: NOW, lookup: records([record(b, { status: "failed", txHash: null })]) }, "gateway_failed_not_terminal"],
      ["failed with hash", { binding: b, nowUnixSeconds: NOW, lookup: records([record(b, { status: "failed" })]) }, "gateway_failed_not_terminal"],
      ["failed after expiry", { binding: b, nowUnixSeconds: afterExpiry, lookup: records([record(b, { status: "failed" })]) }, "gateway_failed_not_terminal"],
      ["nonce_already_used + not found", { binding: b, nowUnixSeconds: NOW, lookup: records([]), settle: nonceAlreadyUsed }, "nonce_already_used"],
      ["nonce_already_used + expiry", { binding: b, nowUnixSeconds: afterExpiry, lookup: records([]), settle: nonceAlreadyUsed }, "nonce_already_used"],
      ["timeout after nonce_already_used", { binding: b, nowUnixSeconds: afterExpiry, lookup: { kind: "timeout" }, settle: nonceAlreadyUsed }, "timeout"],
      ["completed without hash", { binding: b, nowUnixSeconds: NOW, lookup: records([record(b, { txHash: null })]) }, "completed_without_batch_hash"],
      ["completed but wrong payee", { binding: b, nowUnixSeconds: NOW, lookup: records([record(b, { toAddress: b.from })]) }, "record_mismatch"],
      ["completed but wrong amount", { binding: b, nowUnixSeconds: NOW, lookup: records([record(b, { amount: "1" })]) }, "record_mismatch"],
      ["completed on other network", { binding: b, nowUnixSeconds: NOW, lookup: records([record(b, { sendingNetwork: "eip155:8453" })]) }, "record_mismatch"],
      ["record for another nonce", { binding: b, nowUnixSeconds: NOW, lookup: records([record(b, { nonce: `0x${"1".repeat(64)}` })]) }, "record_mismatch"],
      ["two records", { binding: b, nowUnixSeconds: NOW, lookup: records([record(b), record(b, { id: "11111111-2222-4333-8444-555555555555" })]) }, "ambiguous_records"],
      ["more pages", { binding: b, nowUnixSeconds: NOW, lookup: records([record(b)], true) }, "ambiguous_records"],
      ["transfer id disagrees with settle", { binding: b, nowUnixSeconds: NOW, lookup: records([record(b)]), settle: { outcome: "accepted", transferId: "11111111-2222-4333-8444-555555555555", network: "eip155:5042002", payer: b.from } }, "record_mismatch"],
      ["malformed tx hash", { binding: b, nowUnixSeconds: NOW, lookup: records([record(b, { txHash: "0x1234" })]) }, "malformed_response"],
      ["unrecognized status", { binding: b, nowUnixSeconds: NOW, lookup: records([record(b, { status: "refunded" })]) }, "unrecognized_status"],
    ];
    for (const [label, input, reason] of cases) {
      expect({ label, exposure: classifyLaneAttempt(input) }).toEqual({
        label,
        exposure: { state: "unknown", disposition: "held", reason },
      });
    }
  });

  it("keeps received, batched and confirmed transfers pending and held, even after expiry", async () => {
    const b = await binding();
    for (const status of ["received", "batched", "confirmed"] as const) {
      const exposure = classifyLaneAttempt({
        binding: b,
        nowUnixSeconds: Number(BigInt(b.validBefore) + 10n),
        lookup: records([record(b, { status, txHash: status === "confirmed" ? TX_HASH : null })]),
      });
      expect(exposure).toMatchObject({ state: "pending", disposition: "held", gatewayStatus: status });
    }
  });

  it("encodes 'no release' at the type level", () => {
    expectTypeOf<LaneExposureAdmitsNoRelease>().toEqualTypeOf<true>();
    expectTypeOf<LaneSettleAdmitsNoRelease>().toEqualTypeOf<true>();
    expectTypeOf<LaneExposure["state"]>().toEqualTypeOf<"committed" | "pending" | "unknown">();
    expectTypeOf<LaneExposure["disposition"]>().toEqualTypeOf<"committed" | "held">();
    expectTypeOf<LaneSettleObservation["outcome"]>().toEqualTypeOf<"accepted" | "unknown">();
    expect(LANE_EXPOSURE_ADMITS_NO_RELEASE).toBe(true);
    expect(LANE_SETTLE_ADMITS_NO_RELEASE).toBe(true);

    // @ts-expect-error a released exposure is not representable
    const released: LaneExposure = { state: "released", disposition: "released", reason: "not_found" };
    // @ts-expect-error an unknown exposure cannot be marked anything but held
    const unheld: LaneExposure = { state: "unknown", disposition: "committed", reason: "not_found" };
    // @ts-expect-error a failed settle outcome is not representable
    const failed: LaneSettleObservation = { outcome: "failed", reason: "settle_error_reason", httpStatus: 200, errorReason: null };
    expect([released, unheld, failed]).toHaveLength(3);
  });

  it("resolveAttempt performs exactly one lookup request", async () => {
    const b = await binding();
    const { fetch, calls } = mockFetch(async () => jsonResponse(200, { transfers: [record(b, { status: "failed" })] }));
    const facilitator = createLaneFacilitatorClient({
      network: "eip155:5042002",
      facilitatorOrigin: "https://gateway-api-testnet.circle.com",
      fetch,
      timeoutMs: 1000,
    });
    expect(await facilitator.resolveAttempt(b, { nowUnixSeconds: NOW, settle: nonceAlreadyUsed })).toEqual({
      state: "unknown",
      disposition: "held",
      reason: "gateway_failed_not_terminal",
    });
    expect(calls).toHaveLength(1);

    const silent = mockFetch(() => new Promise(() => undefined));
    const slow = createLaneFacilitatorClient({
      network: "eip155:5042002",
      facilitatorOrigin: "https://gateway-api-testnet.circle.com",
      fetch: silent.fetch,
      timeoutMs: 20,
    });
    expect(await slow.resolveAttempt(b, { nowUnixSeconds: NOW })).toEqual({ state: "unknown", disposition: "held", reason: "timeout" });
    expect(silent.calls).toHaveLength(1);
  });
});
