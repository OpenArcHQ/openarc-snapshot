/**
 * Internal, NOT exported from the package index. Holds the signed wire payload
 * outside every public handle so a handle can be logged, serialised or
 * inspected without revealing the signature, and so a forged or cast object
 * can never be sent: only handles minted here are recognised.
 */
import type { Hex } from "viem";

import { X402LaneError } from "./errors.js";
import type { LaneDigest } from "./primitives.js";
import type { LaneResource, RawLaneRequirement } from "./requirement.js";
import type { LanePaymentBinding, LaneRole } from "./binding.js";

export interface LaneWireAuthorization {
  readonly from: string;
  readonly to: string;
  readonly value: string;
  readonly validAfter: string;
  readonly validBefore: string;
  readonly nonce: string;
}

export interface LaneWirePayload {
  readonly x402Version: 2;
  readonly resource?: LaneResource;
  readonly accepted: Readonly<RawLaneRequirement>;
  readonly payload: {
    readonly authorization: LaneWireAuthorization;
    readonly signature: Hex;
  };
}

export type LaneStage = "unpersisted" | "persisting" | "persisted" | "dispatched" | "released";

export interface LaneRecord {
  stage: LaneStage;
  readonly role: LaneRole;
  readonly binding: LanePaymentBinding;
  readonly bindingDigest: LaneDigest;
  wire: LaneWirePayload | null;
  readonly unpersistedHandle: object;
  persistedHandle: object | null;
}

const records = new WeakMap<object, LaneRecord>();

export function registerHandle(handle: object, record: LaneRecord): void {
  records.set(handle, record);
}

export function recordFor(handle: unknown): LaneRecord {
  const record = typeof handle === "object" && handle !== null ? records.get(handle) : undefined;
  if (record === undefined) {
    throw new X402LaneError("not_persisted", ["handle:unrecognised"]);
  }
  return record;
}

/**
 * The single gate every send path passes through. It requires the exact
 * persisted handle minted by `persistLanePayment`, the expected role, and a
 * record still in `persisted`; it flips the stage to `dispatched` BEFORE the
 * caller performs I/O so a thrown transport still counts as possibly exposed,
 * and a second send is refused without any I/O.
 */
export function takeForDispatch(handle: unknown, role: LaneRole): { record: LaneRecord; wire: LaneWirePayload } {
  const record = recordFor(handle);
  if (record.persistedHandle !== handle) {
    throw new X402LaneError("not_persisted", ["handle:not_persisted_handle"]);
  }
  if (record.role !== role) {
    throw new X402LaneError("wrong_role", [`role:expected_${role}`]);
  }
  if (record.stage === "dispatched") {
    throw new X402LaneError("already_dispatched");
  }
  if (record.stage === "released") {
    throw new X402LaneError("already_released");
  }
  if (record.stage !== "persisted" || record.wire === null) {
    throw new X402LaneError("not_persisted", [`stage:${record.stage}`]);
  }
  const wire = record.wire;
  record.stage = "dispatched";
  return { record, wire };
}
