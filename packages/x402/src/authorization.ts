import {
  CommerceGrantAttemptIdSchema,
  CommerceGrantProviderViewSchema,
  type CommerceGrantProviderView,
} from "@openarc/shared";
import { recoverTypedDataAddress, type Hex, type LocalAccount } from "viem";
import { z } from "zod";

import {
  LANE_BINDING_SCHEMA_VERSION,
  buildLaneTypedData,
  digestLaneBinding,
  type LanePaymentBinding,
  type LaneRole,
} from "./binding.js";
import { X402LaneError, issuePaths } from "./errors.js";
import { resolveLaneNetwork } from "./manifest.js";
import { recordFor, registerHandle, takeForDispatch, type LaneRecord, type LaneWirePayload } from "./payment-state.js";
import {
  canonicalJson,
  decodeBase64Json,
  encodeBase64Json,
  isPlainObject,
  isSignatureHex,
  parseAddress,
  parseAtomicAmount,
  parseNonce,
  parseUnixSeconds,
  sameAddress,
  type LaneDigest,
} from "./primitives.js";
import {
  LANE_MAX_REQUIREMENT_TIMEOUT_SECONDS,
  parseLaneRequirement,
  parseLaneResource,
  type LanePaymentRequired,
  type LaneRequirement,
} from "./requirement.js";

/** SDK-matching back-date for `validAfter` (contract §4.3: `now − 600`). */
export const LANE_VALID_AFTER_BACKDATE_SECONDS = 600;
/**
 * Buffer above the 7-day floor. The lane persists, sends, and the provider
 * claims a grant of up to 300 s before settle, so the SDK's 100 s buffer would
 * let a normal claim push the signature under the floor. Minimum 400 s
 * (300 s grant + SDK 100 s), default 900 s, maximum 3600 s because the
 * facilitator's upper bound is UNVERIFIED.
 */
export const LANE_MIN_VALIDITY_BUFFER_SECONDS = 400;
export const LANE_DEFAULT_VALIDITY_BUFFER_SECONDS = 900;
export const LANE_MAX_VALIDITY_BUFFER_SECONDS = 3600;
/** Provider-side tolerance for buyer/provider clock skew when checking validity. */
export const LANE_CLOCK_SKEW_SECONDS = 600;
export const LANE_PAYMENT_HEADER = "PAYMENT-SIGNATURE" as const;

declare const unpersistedBrand: unique symbol;
declare const persistedBrand: unique symbol;
declare const dispatchedBrand: unique symbol;

/** Signed but NOT durable. Cannot be sent. Carries no signature. */
export interface UnpersistedLanePayment {
  readonly [unpersistedBrand]: true;
  readonly phase: "unpersisted";
  readonly binding: LanePaymentBinding;
  readonly bindingDigest: LaneDigest;
}

/** Durable binding confirmed by the caller's store. The only sendable handle. */
export interface PersistedLanePayment {
  readonly [persistedBrand]: true;
  readonly phase: "persisted";
  readonly binding: LanePaymentBinding;
  readonly bindingDigest: LaneDigest;
}

/** The signature may have left. Exposure is held until resolution commits it. */
export interface DispatchedLaneAttempt {
  readonly [dispatchedBrand]: true;
  readonly phase: "dispatched";
  readonly binding: LanePaymentBinding;
  readonly bindingDigest: LaneDigest;
  readonly exposure: "possibly_exposed";
  readonly transport:
    | { readonly outcome: "returned"; readonly response: unknown }
    | { readonly outcome: "threw"; readonly error: unknown };
}

export interface ReleasedUnsentLanePayment {
  readonly phase: "released_unsent";
  readonly binding: LanePaymentBinding;
  readonly bindingDigest: LaneDigest;
}

export type LaneSigner = Pick<LocalAccount, "address" | "signTypedData">;

export interface PrepareLanePaymentInput {
  readonly paymentRequired: LanePaymentRequired;
  /** Provider-minimal grant view in status `issued`, bound to this requirement. */
  readonly grant: unknown;
  readonly attemptId: string;
  readonly signer: LaneSigner;
  /** Fresh caller-generated 32-byte nonce. The lane never generates one internally. */
  readonly nonce: string;
  readonly nowUnixSeconds: bigint | number;
  readonly validityBufferSeconds?: number;
}

function grantCoversRequirement(
  grantInput: unknown,
  requirement: LaneRequirement,
  expected: "issued" | "claimed",
  attemptId: string,
  now: bigint,
): CommerceGrantProviderView {
  const parsed = CommerceGrantProviderViewSchema.safeParse(grantInput);
  if (!parsed.success) {
    throw new X402LaneError("grant_mismatch", issuePaths(parsed.error.issues));
  }
  const grant = parsed.data;
  const manifest = resolveLaneNetwork(requirement.network);
  const issues: string[] = [];
  if (grant.networkId !== manifest.caip2) issues.push("networkId:mismatch");
  if (grant.decimals !== manifest.asset.decimals) issues.push("decimals:mismatch");
  if (grant.asset !== manifest.asset.symbol || grant.representation !== "erc20") {
    issues.push("asset:mismatch");
  }
  if (grant.amountAtomic !== requirement.amount) issues.push("amountAtomic:mismatch");
  if (grant.status !== expected) issues.push(`status:expected_${expected}`);
  if (expected === "issued") {
    const expiresSeconds = BigInt(Math.floor(Date.parse(`${grant.expiresAt.slice(0, 19)}Z`) / 1000));
    if (expiresSeconds <= now) issues.push("expiresAt:expired");
  } else if (grant.claimedAttemptId !== attemptId) {
    issues.push("claimedAttemptId:mismatch");
  }
  if (issues.length > 0) {
    throw new X402LaneError("grant_mismatch", issues);
  }
  return grant;
}

function parseAttemptId(value: unknown): string {
  const parsed = CommerceGrantAttemptIdSchema.safeParse(value);
  if (!parsed.success) {
    throw new X402LaneError("invalid_binding", ["attemptId:invalid"]);
  }
  return parsed.data;
}

function parseBuffer(value: unknown): bigint {
  if (value === undefined) return BigInt(LANE_DEFAULT_VALIDITY_BUFFER_SECONDS);
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < LANE_MIN_VALIDITY_BUFFER_SECONDS ||
    value > LANE_MAX_VALIDITY_BUFFER_SECONDS
  ) {
    throw new X402LaneError("validity_rejected", ["validityBufferSeconds:out_of_range"]);
  }
  return BigInt(value);
}

function mintUnpersisted(record: Omit<LaneRecord, "unpersistedHandle" | "persistedHandle">): UnpersistedLanePayment {
  const handle = Object.freeze({
    phase: "unpersisted",
    binding: record.binding,
    bindingDigest: record.bindingDigest,
  }) as UnpersistedLanePayment;
  registerHandle(handle, { ...record, unpersistedHandle: handle, persistedHandle: null });
  return handle;
}

async function assertSignatureFrom(binding: LanePaymentBinding, signature: unknown): Promise<Hex> {
  if (!isSignatureHex(signature)) {
    throw new X402LaneError("signature_mismatch", ["signature:not_65_bytes"]);
  }
  let recovered: string;
  try {
    recovered = await recoverTypedDataAddress({ ...buildLaneTypedData(binding), signature });
  } catch {
    throw new X402LaneError("signature_mismatch", ["signature:unrecoverable"]);
  }
  if (!sameAddress(recovered, binding.from)) {
    throw new X402LaneError("signature_mismatch", ["signature:not_from_payer"]);
  }
  return signature;
}

/**
 * Buyer phase 1. Builds and signs the authorization locally and returns an
 * UNPERSISTED handle. It performs no network I/O and cannot send: the signed
 * payload is only reachable through `persistLanePayment` → `dispatchLanePayment`.
 * `GatewayClient.pay()` and `BatchEvmScheme` are deliberately not used because
 * they generate the nonce internally and (for `pay()`) send in the same step.
 */
export async function prepareLanePayment(input: PrepareLanePaymentInput): Promise<UnpersistedLanePayment> {
  const requirement = input.paymentRequired.requirement;
  const manifest = resolveLaneNetwork(requirement.network);
  const now = parseUnixSeconds(input.nowUnixSeconds, "nowUnixSeconds");
  const attemptId = parseAttemptId(input.attemptId);
  const grant = grantCoversRequirement(input.grant, requirement, "issued", attemptId, now);
  const from = parseAddress(input.signer.address, "signer.address");
  if (sameAddress(from, requirement.payTo)) {
    throw new X402LaneError("invalid_address", ["payTo:self_transfer"]);
  }
  const nonce = parseNonce(input.nonce);
  const buffer = parseBuffer(input.validityBufferSeconds);
  if (now < BigInt(LANE_VALID_AFTER_BACKDATE_SECONDS)) {
    throw new X402LaneError("invalid_clock", ["nowUnixSeconds:too_small"]);
  }
  const floor = BigInt(manifest.minValiditySeconds) + buffer;
  const window = BigInt(requirement.maxTimeoutSeconds) > floor ? BigInt(requirement.maxTimeoutSeconds) : floor;
  const validBefore = now + window;

  const binding: LanePaymentBinding = Object.freeze({
    schemaVersion: LANE_BINDING_SCHEMA_VERSION,
    role: "buyer",
    network: manifest.caip2,
    grantId: grant.grantId,
    actionId: grant.actionId,
    attemptId,
    grantRequirementDigest: grant.requirementDigest as LaneDigest,
    laneRequirementDigest: requirement.digest,
    verifyingContract: manifest.eip712.verifyingContract,
    asset: manifest.asset.address,
    from,
    to: requirement.payTo,
    value: requirement.amount,
    validAfter: (now - BigInt(LANE_VALID_AFTER_BACKDATE_SECONDS)).toString(),
    validBefore: validBefore.toString(),
    nonce,
  });

  const signature = await assertSignatureFrom(binding, await input.signer.signTypedData(buildLaneTypedData(binding)));
  const wire: LaneWirePayload = Object.freeze({
    x402Version: 2,
    resource: input.paymentRequired.resource,
    accepted: requirement.accepted,
    payload: Object.freeze({
      authorization: Object.freeze({
        from: binding.from,
        to: binding.to,
        value: binding.value,
        validAfter: binding.validAfter,
        validBefore: binding.validBefore,
        nonce: binding.nonce,
      }),
      signature,
    }),
  });
  return mintUnpersisted({
    stage: "unpersisted",
    role: "buyer",
    binding,
    bindingDigest: digestLaneBinding(binding),
    wire,
  });
}

const WireAuthorizationSchema = z.strictObject({
  from: z.string(),
  to: z.string(),
  value: z.string(),
  validAfter: z.string(),
  validBefore: z.string(),
  nonce: z.string(),
});

const WirePayloadSchema = z.strictObject({
  x402Version: z.literal(2),
  resource: z.unknown().optional(),
  accepted: z.unknown(),
  payload: z.strictObject({
    authorization: WireAuthorizationSchema,
    signature: z.string(),
  }),
  extensions: z.record(z.string(), z.unknown()).optional(),
});

export interface AcceptReceivedLanePaymentInput {
  /** Raw `PAYMENT-SIGNATURE` header value received from the buyer. */
  readonly header: string;
  /** The exact envelope this provider issued. */
  readonly paymentRequired: LanePaymentRequired;
  /** Provider-minimal grant view in status `claimed` by `attemptId`. */
  readonly grant: unknown;
  readonly attemptId: string;
  readonly nowUnixSeconds: bigint | number;
}

/**
 * Provider phase 1. Strictly validates a received payment against the issued
 * requirement and claimed grant, verifies the EIP-712 signature offline, and
 * returns an UNPERSISTED handle. Settlement requires persisting it first.
 */
export async function acceptReceivedLanePayment(input: AcceptReceivedLanePaymentInput): Promise<UnpersistedLanePayment> {
  const decoded = decodeBase64Json(input.header);
  if (!isPlainObject(decoded)) {
    throw new X402LaneError("invalid_payment_payload", ["header:not_base64_json_object"]);
  }
  const parsed = WirePayloadSchema.safeParse(decoded);
  if (!parsed.success) {
    throw new X402LaneError("invalid_payment_payload", issuePaths(parsed.error.issues));
  }
  const wireIn = parsed.data;
  if (wireIn.extensions !== undefined && Object.keys(wireIn.extensions).length > 0) {
    throw new X402LaneError("invalid_payment_payload", ["extensions:not_empty"]);
  }
  const issued = input.paymentRequired.requirement;
  const accepted = parseLaneRequirement(wireIn.accepted);
  if (accepted.digest !== issued.digest) {
    throw new X402LaneError("invalid_payment_payload", ["accepted:not_issued_requirement"]);
  }
  if (wireIn.resource !== undefined) {
    const resource = parseLaneResource(wireIn.resource);
    if (canonicalJson(resource) !== canonicalJson(input.paymentRequired.resource)) {
      throw new X402LaneError("invalid_payment_payload", ["resource:not_issued_resource"]);
    }
  }
  const manifest = resolveLaneNetwork(issued.network);
  const now = parseUnixSeconds(input.nowUnixSeconds, "nowUnixSeconds");
  const attemptId = parseAttemptId(input.attemptId);
  const grant = grantCoversRequirement(input.grant, issued, "claimed", attemptId, now);

  const auth = wireIn.payload.authorization;
  const from = parseAddress(auth.from, "authorization.from");
  const to = parseAddress(auth.to, "authorization.to");
  const issues: string[] = [];
  if (!sameAddress(to, issued.payTo)) issues.push("authorization.to:not_payTo");
  if (sameAddress(from, to)) issues.push("authorization.from:self_transfer");
  if (auth.value !== issued.amount) issues.push("authorization.value:not_amount");
  if (issues.length > 0) {
    throw new X402LaneError("invalid_payment_payload", issues);
  }
  const validAfter = BigInt(parseAtomicAmount(auth.validAfter, "authorization.validAfter", false));
  const validBefore = BigInt(parseAtomicAmount(auth.validBefore, "authorization.validBefore", true));
  const nonce = parseNonce(auth.nonce);
  if (validAfter > now) {
    throw new X402LaneError("validity_rejected", ["authorization.validAfter:in_future"]);
  }
  if (validBefore - now < BigInt(manifest.minValiditySeconds)) {
    throw new X402LaneError("validity_rejected", ["authorization.validBefore:under_7_days"]);
  }
  const ceiling = BigInt(LANE_MAX_REQUIREMENT_TIMEOUT_SECONDS + LANE_CLOCK_SKEW_SECONDS);
  if (validBefore - now > ceiling) {
    throw new X402LaneError("validity_rejected", ["authorization.validBefore:over_ceiling"]);
  }

  const binding: LanePaymentBinding = Object.freeze({
    schemaVersion: LANE_BINDING_SCHEMA_VERSION,
    role: "provider",
    network: manifest.caip2,
    grantId: grant.grantId,
    actionId: grant.actionId,
    attemptId,
    grantRequirementDigest: grant.requirementDigest as LaneDigest,
    laneRequirementDigest: issued.digest,
    verifyingContract: manifest.eip712.verifyingContract,
    asset: manifest.asset.address,
    from,
    to,
    value: issued.amount,
    validAfter: validAfter.toString(),
    validBefore: validBefore.toString(),
    nonce,
  });
  const signature = await assertSignatureFrom(binding, wireIn.payload.signature);

  const wire: LaneWirePayload = Object.freeze({
    x402Version: 2,
    resource: input.paymentRequired.resource,
    accepted: issued.accepted,
    payload: Object.freeze({
      authorization: Object.freeze({ ...auth }),
      signature,
    }),
  });
  return mintUnpersisted({
    stage: "unpersisted",
    role: "provider",
    binding,
    bindingDigest: digestLaneBinding(binding),
    wire,
  });
}

export interface LanePersistRecord {
  readonly binding: LanePaymentBinding;
  readonly bindingDigest: LaneDigest;
}

/**
 * The caller's durable write. It must resolve only after the record is durable
 * and must echo the stored `bindingDigest` read back from storage. Any throw,
 * rejection or mismatch leaves the payment unsendable.
 */
export type LanePersist = (record: LanePersistRecord) => Promise<{ readonly bindingDigest: string }>;

/** Phase 2 (both roles): durable binding before any send. */
export async function persistLanePayment(
  handle: UnpersistedLanePayment,
  persist: LanePersist,
): Promise<PersistedLanePayment> {
  const record = recordFor(handle);
  if (record.unpersistedHandle !== handle) {
    throw new X402LaneError("not_persisted", ["handle:not_unpersisted_handle"]);
  }
  if (record.stage === "released") throw new X402LaneError("already_released");
  if (record.stage === "dispatched") throw new X402LaneError("already_dispatched");
  if (record.stage !== "unpersisted") throw new X402LaneError("already_persisted");

  record.stage = "persisting";
  let echoed: unknown;
  try {
    const result = await persist(Object.freeze({ binding: record.binding, bindingDigest: record.bindingDigest }));
    echoed = isPlainObject(result) ? result.bindingDigest : undefined;
  } catch (cause) {
    if (record.stage === "persisting") record.stage = "unpersisted";
    throw Object.assign(new X402LaneError("persistence_failed"), { cause });
  }
  if (record.stage !== "persisting") {
    throw new X402LaneError("already_released");
  }
  if (echoed !== record.bindingDigest) {
    record.stage = "unpersisted";
    throw new X402LaneError("persistence_mismatch", ["bindingDigest:not_echoed"]);
  }
  record.stage = "persisted";
  const persisted = Object.freeze({
    phase: "persisted",
    binding: record.binding,
    bindingDigest: record.bindingDigest,
  }) as PersistedLanePayment;
  record.persistedHandle = persisted;
  registerHandle(persisted, record);
  return persisted;
}

export interface LaneTransportRequest {
  readonly headerName: typeof LANE_PAYMENT_HEADER;
  readonly headerValue: string;
}

export type LaneTransport = (request: LaneTransportRequest) => Promise<unknown>;

/**
 * Buyer phase 3. Sends the persisted payment exactly once. Refuses (without
 * I/O, leaving the payment releasable) if the remaining signature validity is
 * below the 7-day floor. After this call the attempt is `possibly_exposed`
 * whatever the transport did; the lane never re-signs or resends.
 */
export async function dispatchLanePayment(
  handle: PersistedLanePayment,
  transport: LaneTransport,
  nowUnixSeconds: bigint | number,
): Promise<DispatchedLaneAttempt> {
  const now = parseUnixSeconds(nowUnixSeconds, "nowUnixSeconds");
  const pre = recordFor(handle);
  const manifest = resolveLaneNetwork(pre.binding.network);
  if (pre.persistedHandle === handle && pre.stage === "persisted" && pre.role === "buyer") {
    if (BigInt(pre.binding.validBefore) - now < BigInt(manifest.minValiditySeconds)) {
      throw new X402LaneError("validity_rejected", ["validBefore:under_7_days_at_send"]);
    }
  }
  const { record, wire } = takeForDispatch(handle, "buyer");
  const headerValue = encodeBase64Json(wire);
  let transportResult: DispatchedLaneAttempt["transport"];
  try {
    transportResult = { outcome: "returned", response: await transport(Object.freeze({ headerName: LANE_PAYMENT_HEADER, headerValue })) };
  } catch (error) {
    transportResult = { outcome: "threw", error };
  }
  record.wire = null;
  return Object.freeze({
    phase: "dispatched",
    binding: record.binding,
    bindingDigest: record.bindingDigest,
    exposure: "possibly_exposed",
    transport: Object.freeze(transportResult),
  }) as DispatchedLaneAttempt;
}

/**
 * The ONLY release in the lane (contract §6): a buyer payment that provably
 * never reached any transport. Refuses dispatched attempts at the type level
 * (the parameter excludes `DispatchedLaneAttempt`) and at runtime.
 */
export function releaseUnsentLanePayment(
  handle: UnpersistedLanePayment | PersistedLanePayment,
): ReleasedUnsentLanePayment {
  const record = recordFor(handle);
  if (record.unpersistedHandle !== handle && record.persistedHandle !== handle) {
    throw new X402LaneError("not_persisted", ["handle:unrecognised"]);
  }
  if (record.role !== ("buyer" satisfies LaneRole)) {
    throw new X402LaneError("wrong_role", ["role:expected_buyer"]);
  }
  if (record.stage === "dispatched") throw new X402LaneError("already_dispatched");
  if (record.stage === "released") throw new X402LaneError("already_released");
  record.stage = "released";
  record.wire = null;
  return Object.freeze({
    phase: "released_unsent",
    binding: record.binding,
    bindingDigest: record.bindingDigest,
  });
}
