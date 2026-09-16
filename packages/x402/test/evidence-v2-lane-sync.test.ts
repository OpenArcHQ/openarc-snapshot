import { describe, expect, expectTypeOf, it } from "vitest";

import {
  EvidenceV2LaneExposureSchema,
  derivePaymentCertainty,
  type EvidenceV2LaneExposure,
  type EvidenceV2LaneState,
  type EvidenceV2LaneUnknownReason,
} from "@openarc/shared";

import type { LaneExposure, LaneUnknownReason } from "../src/index.js";

/**
 * Compile-time sync guard. `@openarc/shared` keeps a copy of the x402
 * `LaneExposure` shape because shared cannot depend on x402. These assertions
 * run under `tsc -p tsconfig.test.json` (the second half of this package's
 * `typecheck` script), so a state, field or reason added on either side fails
 * the typecheck. Vitest itself does not evaluate type assertions.
 */

type Mutable<T> = { -readonly [K in keyof T]: T[K] };
/** x402 brands hashes as viem `Hex`; the shared zod copy carries validated plain strings. */
type UnbrandHex<T> = {
  [K in keyof T]: T[K] extends `0x${string}` ? string : T[K] extends `0x${string}` | null ? string | null : T[K];
};
type Comparable<T> = Mutable<UnbrandHex<T>>;
type MutuallyAssignable<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
type X402State<S extends LaneExposure["state"]> = Comparable<Extract<LaneExposure, { state: S }>>;
type SharedState<S extends EvidenceV2LaneState> = Extract<EvidenceV2LaneExposure, { state: S }>;

const TX_HASH = `0x${"ab".repeat(32)}` as const;
const TRANSFER_ID = "3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b";

describe("evidence v2 lane exposure copy stays in sync with packages/x402", () => {
  it("has the same state, disposition and unknown-reason unions", () => {
    expectTypeOf<LaneExposure["state"]>().toEqualTypeOf<EvidenceV2LaneState>();
    expectTypeOf<MutuallyAssignable<LaneExposure["state"], EvidenceV2LaneState>>().toEqualTypeOf<true>();
    expectTypeOf<LaneExposure["disposition"]>().toEqualTypeOf<EvidenceV2LaneExposure["disposition"]>();
    expectTypeOf<LaneUnknownReason>().toEqualTypeOf<EvidenceV2LaneUnknownReason>();
  });

  it("has mutually assignable per-state shapes with identical keys", () => {
    expectTypeOf<MutuallyAssignable<X402State<"unknown">, SharedState<"unknown">>>().toEqualTypeOf<true>();
    expectTypeOf<MutuallyAssignable<X402State<"pending">, SharedState<"pending">>>().toEqualTypeOf<true>();
    expectTypeOf<MutuallyAssignable<X402State<"committed">, SharedState<"committed">>>().toEqualTypeOf<true>();
    expectTypeOf<keyof X402State<"unknown">>().toEqualTypeOf<keyof SharedState<"unknown">>();
    expectTypeOf<keyof X402State<"pending">>().toEqualTypeOf<keyof SharedState<"pending">>();
    expectTypeOf<keyof X402State<"committed">>().toEqualTypeOf<keyof SharedState<"committed">>();
    expectTypeOf<MutuallyAssignable<Comparable<LaneExposure>, EvidenceV2LaneExposure>>().toEqualTypeOf<true>();
    // A lane result passes to shared directly, without any widening.
    expectTypeOf<[LaneExposure] extends [EvidenceV2LaneExposure] ? true : false>().toEqualTypeOf<true>();
  });

  it("accepts every x402 lane state at runtime through the shared schema and certainty rule", () => {
    const lanes: LaneExposure[] = [
      { state: "unknown", disposition: "held", reason: "timeout" },
      { state: "pending", disposition: "held", transferId: TRANSFER_ID, gatewayStatus: "batched", batchTxHash: null },
      { state: "committed", disposition: "committed", transferId: TRANSFER_ID, gatewayStatus: "completed", batchTxHash: TX_HASH,
        onchainReceiptVerified: false },
    ];
    for (const lane of lanes) {
      expect(EvidenceV2LaneExposureSchema.parse(lane)).toEqual(lane);
      expect(derivePaymentCertainty(lane).certainty).not.toBe("onchain_confirmed");
    }
  });
});
