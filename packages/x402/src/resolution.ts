import type { Hex } from "viem";

import type { LanePaymentBinding } from "./binding.js";
import { isBytes32, parseUnixSeconds, sameAddress } from "./primitives.js";

/** Settle `errorReason` enum (contract §5.1, OpenAPI S4) plus the 500 reason. */
export const GATEWAY_SETTLE_ERROR_REASONS = Object.freeze([
  "unsupported_scheme",
  "unsupported_network",
  "unsupported_asset",
  "invalid_payload",
  "address_mismatch",
  "amount_mismatch",
  "invalid_signature",
  "authorization_not_yet_valid",
  "authorization_expired",
  "authorization_validity_too_short",
  "self_transfer",
  "insufficient_balance",
  "nonce_already_used",
  "unsupported_domain",
  "wallet_not_found",
  "unexpected_error",
] as const);

export type GatewaySettleErrorReason = (typeof GATEWAY_SETTLE_ERROR_REASONS)[number];

/**
 * What one settle call observed. There is intentionally no `rejected`,
 * `failed` or `released` outcome: a settle error proves nothing about other
 * copies of the signed payload (contract §6, §7), so every non-acceptance is
 * `unknown`. `accepted` means accepted-and-locked, NOT settled.
 */
export type LaneSettleObservation =
  | {
      readonly outcome: "accepted";
      readonly transferId: string;
      readonly network: LanePaymentBinding["network"];
      readonly payer: LanePaymentBinding["from"];
    }
  | {
      readonly outcome: "unknown";
      readonly reason:
        | "timeout"
        | "transport_error"
        | "unexpected_response"
        | "settle_error_reason"
        | "incomplete_acceptance"
        | "acceptance_mismatch";
      readonly httpStatus: number | null;
      readonly errorReason: GatewaySettleErrorReason | "unrecognized" | null;
    };

export interface LaneTransferRecord {
  readonly id: string;
  readonly status: string;
  readonly fromAddress: string;
  readonly toAddress: string;
  readonly amount: string;
  readonly nonce: string;
  readonly sendingNetwork: string;
  readonly recipientNetwork: string;
  readonly txHash: string | null;
}

export type LaneLookupObservation =
  | { readonly kind: "records"; readonly transfers: readonly LaneTransferRecord[]; readonly hasMorePages: boolean }
  | { readonly kind: "timeout" }
  | { readonly kind: "transport_error" }
  | { readonly kind: "http_error"; readonly status: number }
  | { readonly kind: "malformed" };

export type LaneUnknownReason =
  | "timeout"
  | "transport_error"
  | "http_error"
  | "malformed_response"
  | "not_found"
  | "not_found_after_expiry"
  | "nonce_already_used"
  | "gateway_failed_not_terminal"
  | "ambiguous_records"
  | "record_mismatch"
  | "completed_without_batch_hash"
  | "unrecognized_status";

/**
 * Post-send exposure. `committed` consumes the exposure (it is never a
 * release); `pending` and `unknown` keep it held. No member releases.
 */
export type LaneExposure =
  | {
      readonly state: "committed";
      readonly disposition: "committed";
      readonly transferId: string;
      readonly gatewayStatus: "completed";
      readonly batchTxHash: Hex;
      /** Gateway-asserted only. The finalized Arc receipt / BatchProcessed log check is later work. */
      readonly onchainReceiptVerified: false;
    }
  | {
      readonly state: "pending";
      readonly disposition: "held";
      readonly transferId: string;
      readonly gatewayStatus: "received" | "batched" | "confirmed";
      readonly batchTxHash: Hex | null;
    }
  | {
      readonly state: "unknown";
      readonly disposition: "held";
      readonly reason: LaneUnknownReason;
    };

/** States that would release held exposure. None may appear in the post-send types. */
export type LaneForbiddenReleaseState =
  | "released"
  | "released_unsent"
  | "failed"
  | "rejected"
  | "expired"
  | "cancelled"
  | "refunded"
  | "not_paid"
  | "nonpayment";

type IsNever<T> = [T] extends [never] ? true : false;

/** Type-level rule: resolves to `true` only while no release state is representable. */
export type LaneExposureAdmitsNoRelease = IsNever<
  Extract<LaneExposure["state"] | LaneExposure["disposition"], LaneForbiddenReleaseState | "released">
>;
export type LaneSettleAdmitsNoRelease = IsNever<Extract<LaneSettleObservation["outcome"], LaneForbiddenReleaseState>>;

/** Compile-time proofs: adding a release state to either union breaks the build here. */
export const LANE_EXPOSURE_ADMITS_NO_RELEASE: LaneExposureAdmitsNoRelease = true;
export const LANE_SETTLE_ADMITS_NO_RELEASE: LaneSettleAdmitsNoRelease = true;

function unknown(reason: LaneUnknownReason): LaneExposure {
  return Object.freeze({ state: "unknown", disposition: "held", reason });
}

export interface ClassifyLaneAttemptInput {
  readonly binding: LanePaymentBinding;
  readonly nowUnixSeconds: bigint | number;
  readonly lookup: LaneLookupObservation;
  readonly settle?: LaneSettleObservation;
}

/**
 * Pure lost-settle classification. Timeout, silence, `failed`,
 * `nonce_already_used`, not-found and `validBefore` expiry all stay `unknown`
 * (held). Only one Gateway record matching the full binding, in status
 * `completed` with a batch tx hash, is `committed`.
 */
export function classifyLaneAttempt(input: ClassifyLaneAttemptInput): LaneExposure {
  const { binding, lookup, settle } = input;
  const now = parseUnixSeconds(input.nowUnixSeconds, "nowUnixSeconds");

  switch (lookup.kind) {
    case "timeout":
      return unknown("timeout");
    case "transport_error":
      return unknown("transport_error");
    case "http_error":
      return unknown("http_error");
    case "malformed":
      return unknown("malformed_response");
    case "records":
      break;
  }

  const matching = lookup.transfers.filter(
    (record) => sameAddress(record.fromAddress, binding.from) && record.nonce.toLowerCase() === binding.nonce,
  );
  if (matching.length !== lookup.transfers.length) return unknown("record_mismatch");
  if (matching.length > 1 || lookup.hasMorePages) return unknown("ambiguous_records");

  const record = matching[0];
  if (record === undefined) {
    if (settle?.outcome === "unknown" && settle.errorReason === "nonce_already_used") {
      return unknown("nonce_already_used");
    }
    return now >= BigInt(binding.validBefore) ? unknown("not_found_after_expiry") : unknown("not_found");
  }

  if (
    !sameAddress(record.toAddress, binding.to) ||
    record.amount !== binding.value ||
    record.sendingNetwork !== binding.network ||
    record.recipientNetwork !== binding.network
  ) {
    return unknown("record_mismatch");
  }
  if (settle?.outcome === "accepted" && settle.transferId.toLowerCase() !== record.id.toLowerCase()) {
    return unknown("record_mismatch");
  }
  if (record.txHash !== null && !isBytes32(record.txHash)) {
    return unknown("malformed_response");
  }
  const batchTxHash = record.txHash === null ? null : (record.txHash.toLowerCase() as Hex);

  switch (record.status) {
    case "completed":
      return batchTxHash === null
        ? unknown("completed_without_batch_hash")
        : Object.freeze({
            state: "committed",
            disposition: "committed",
            transferId: record.id,
            gatewayStatus: "completed",
            batchTxHash,
            onchainReceiptVerified: false,
          });
    case "received":
    case "batched":
    case "confirmed":
      return Object.freeze({
        state: "pending",
        disposition: "held",
        transferId: record.id,
        gatewayStatus: record.status,
        batchTxHash,
      });
    case "failed":
      return unknown("gateway_failed_not_terminal");
    default:
      return unknown("unrecognized_status");
  }
}
