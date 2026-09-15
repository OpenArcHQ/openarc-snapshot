import { z } from "zod";

import { createCommerceSuccessEnvelopeSchema } from "./api.js";
import { CommerceRequirementIdSchema } from "./control-action.js";
import { CommerceActionIdSchema } from "./control-budget.js";
import { CommerceGrantIdSchema } from "./control-grant.js";
import { CommerceGrantAttemptIdSchema } from "./control-grant-wire.js";
import {
  CommerceOrganizationIdSchema,
  CommerceProviderIdSchema,
} from "./identity.js";
import {
  CommerceListingIdSchema,
  CommerceListingVersionSchema,
} from "./listing.js";
import { CommerceTenantMutationIdSchema } from "./tenant-writes.js";

/**
 * Pure strict payment-attempt wire contracts for the migration-0015 surfaces.
 *
 * Bodies, read requests and response data shapes only. There is no transport,
 * route parsing, clock, storage, authority, signing, sending, settlement or
 * capability activation here. Parsing a record never proves a principal, a
 * payment or a settlement.
 *
 * TERMS ARE SERVER-DERIVED. No body in this module can carry an amount, a
 * value, a fee, a network, an asset, a verifying contract, a decimals count, a
 * representation or a source kind: every object is closed, so any such key is
 * rejected. The lane binding the store persists is rebuilt by the SERVER from
 * the fixed constants below and from the buyer's own authorized action; the
 * caller supplies only the fields the lane itself chose (its attempt id, the
 * payer and pay-to addresses, the validity window, the nonce, its own lane
 * requirement digest and the binding digest it computed).
 *
 * NO SECRET IS REPRESENTABLE. There is no signature, authorization payload,
 * private key, token or token-hash field anywhere in these shapes, inbound or
 * outbound.
 *
 * STATES ADMIT NO RELEASE. An attempt is `persisted`, `unknown`, `pending` or
 * `committed`; nothing here can describe a released, failed, refunded or
 * cancelled payment, and a dispatched attempt is `unknown`, never success.
 */

/** The exact packages/x402 lane binding schema version the store persists. */
export const COMMERCE_PAYMENT_BINDING_SCHEMA_VERSION =
  "openarc.x402.lane-binding.v1" as const;
/** The only binding role the buyer lane persists. */
export const COMMERCE_PAYMENT_BINDING_ROLE = "buyer" as const;
/** Arc testnet. There is no mainnet entry and no fallback. */
export const COMMERCE_PAYMENT_NETWORK = "eip155:5042002" as const;
/** EIP-55 forms exactly as the lane's `getAddress` emits them. */
export const COMMERCE_PAYMENT_ASSET_ADDRESS =
  "0x3600000000000000000000000000000000000000" as const;
export const COMMERCE_PAYMENT_VERIFYING_CONTRACT =
  "0x0077777d7EBA4688BDeF3E311b846F25870A19B9" as const;

/** Seller payment-terms operation and resource type, exactly as the store. */
export const COMMERCE_PAYMENT_TERMS_OPERATION =
  "market.listing.payment_terms.record" as const;
export const COMMERCE_PAYMENT_TERMS_RESOURCE_TYPE = "listing_version" as const;

export const CommercePaymentAttemptStateSchema = z.enum([
  "persisted",
  "unknown",
  "pending",
  "committed",
]);

export type CommercePaymentAttemptState = z.infer<
  typeof CommercePaymentAttemptStateSchema
>;

export const CommercePaymentGatewayStatusSchema = z.enum([
  "received",
  "batched",
  "confirmed",
  "completed",
]);

// ── Local leaf grammars (absolute end everywhere) ───────────────────────────

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

const AddressSchema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{40}(?![\s\S])/u, { message: "Expected an address" })
  .refine((value) => value.toLowerCase() !== ZERO_ADDRESS, {
    message: "The zero address is not allowed",
  });

const LowerAddressSchema = z
  .string()
  .regex(/^0x[0-9a-f]{40}(?![\s\S])/u, {
    message: "Expected a lowercase address",
  });

const Sha256DigestSchema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}(?![\s\S])/u, {
    message: "Expected a lowercase SHA-256 digest",
  });

const UINT256_MAX = (1n << 256n) - 1n;

const Uint256Schema = z
  .string()
  .regex(/^(?:0|[1-9][0-9]{0,77})(?![\s\S])/u, {
    message: "Expected a canonical uint256 string",
  })
  .refine((value) => BigInt(value) <= UINT256_MAX, {
    message: "Expected a canonical uint256 string",
  });

const Bytes32Schema = z
  .string()
  .regex(/^0x[0-9a-f]{64}(?![\s\S])/u, {
    message: "Expected a lowercase bytes32",
  });

const NonceSchema = Bytes32Schema.refine((value) => BigInt(value) !== 0n, {
  message: "The zero nonce is not allowed",
});

const TransferIdSchema = z
  .string()
  .regex(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![\s\S])/u,
    { message: "Expected a canonical UUID" },
  );

/** The store's canonical microsecond UTC timestamp. */
const StoreTimestampSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])/u, {
    message: "Expected a canonical UTC timestamp",
  });

const TERMS_RESOURCE_ID =
  /^openarc:listing:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@[1-9][0-9]{0,8}(?![\s\S])/u;

function rejectExplicitUndefinedKeys(
  value: unknown,
  ctx: z.RefinementCtx,
): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return;
  }
  for (const key of Object.keys(value)) {
    if ((value as Record<string, unknown>)[key] === undefined) {
      ctx.addIssue({
        code: "custom",
        path: [key],
        message: "Explicit undefined request fields are not allowed",
      });
    }
  }
}

function strictRequestSchema<T extends z.ZodRawShape>(shape: T) {
  return z
    .unknown()
    .superRefine(rejectExplicitUndefinedKeys)
    .pipe(z.strictObject(shape));
}

// ── Write bodies ────────────────────────────────────────────────────────────

/**
 * Seller human records the immutable pay-to of ONE listing version.
 * Organization, listing and version are path derived. No amount, network or
 * asset exists: the price stays the listing version's own immutable content.
 */
export const CommercePaymentTermsBodySchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
  payToAddress: AddressSchema,
});

/**
 * Buyer agent registers a verified requirement. The buyer organization comes
 * from the `oacs_v1_` commerce session; every term comes from the database.
 */
export const CommercePaymentRequirementBodySchema = z.strictObject({
  requirementId: CommerceRequirementIdSchema,
  listingId: CommerceListingIdSchema,
});

/**
 * Buyer agent persists a lane attempt BEFORE any signature may leave its
 * process. Only the lane-chosen fields are accepted. `value`, `network`,
 * `asset`, `verifyingContract`, `schemaVersion`, `role` and the grant
 * requirement digest are rebuilt by the server; they are not representable.
 */
export const CommercePaymentAttemptPersistBodySchema = z
  .strictObject({
    grantId: CommerceGrantIdSchema,
    actionId: CommerceActionIdSchema,
    attemptId: CommerceGrantAttemptIdSchema,
    laneRequirementDigest: Sha256DigestSchema,
    from: AddressSchema,
    to: AddressSchema,
    validAfter: Uint256Schema,
    validBefore: Uint256Schema,
    nonce: NonceSchema,
    bindingDigest: Sha256DigestSchema,
  })
  .superRefine((value, ctx) => {
    if (
      typeof value.from === "string" &&
      typeof value.to === "string" &&
      value.from.toLowerCase() === value.to.toLowerCase()
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["to"],
        message: "The pay-to must differ from the payer",
      });
    }
    if (
      /^(?:0|[1-9][0-9]*)$/u.test(value.validAfter) &&
      /^(?:0|[1-9][0-9]*)$/u.test(value.validBefore) &&
      BigInt(value.validBefore) <= BigInt(value.validAfter)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["validBefore"],
        message: "validBefore must be after validAfter",
      });
    }
  });

/** Record the one dispatch of a persisted attempt. The id is path derived. */
export const CommercePaymentAttemptDispatchBodySchema = z.strictObject({
  bindingDigest: Sha256DigestSchema,
});

export type CommercePaymentTermsBody = z.infer<
  typeof CommercePaymentTermsBodySchema
>;
export type CommercePaymentRequirementBody = z.infer<
  typeof CommercePaymentRequirementBodySchema
>;
export type CommercePaymentAttemptPersistBody = z.infer<
  typeof CommercePaymentAttemptPersistBodySchema
>;
export type CommercePaymentAttemptDispatchBody = z.infer<
  typeof CommercePaymentAttemptDispatchBodySchema
>;

// ── Read requests ───────────────────────────────────────────────────────────

/** Agent attempt recovery, keyed only by the lane's own attempt id. */
export const CommercePaymentAttemptReadRequestSchema = strictRequestSchema({
  attemptId: CommerceGrantAttemptIdSchema,
});

export type CommercePaymentAttemptReadRequest = z.infer<
  typeof CommercePaymentAttemptReadRequestSchema
>;

// ── Response data ───────────────────────────────────────────────────────────

export const CommercePaymentTermsReceiptSchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
  operation: z.literal(COMMERCE_PAYMENT_TERMS_OPERATION),
  resourceType: z.literal(COMMERCE_PAYMENT_TERMS_RESOURCE_TYPE),
  resourceId: z.string().regex(TERMS_RESOURCE_ID),
  committedAt: StoreTimestampSchema,
});

export const CommercePaymentTermsSchema = z.strictObject({
  organizationId: CommerceOrganizationIdSchema,
  listingId: CommerceListingIdSchema,
  version: CommerceListingVersionSchema,
  payToAddress: LowerAddressSchema,
  recordedAt: StoreTimestampSchema,
});

export const CommercePaymentTermsDataSchema = z
  .strictObject({
    replayed: z.boolean(),
    terms: CommercePaymentTermsSchema,
    receipt: CommercePaymentTermsReceiptSchema,
  })
  .superRefine((value, ctx) => {
    if (
      value.receipt.resourceId !==
      `${value.terms.listingId}@${value.terms.version}`
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["receipt", "resourceId"],
        message: "The receipt must name the recorded listing version",
      });
    }
  });

export const CommercePaymentVerifiedRequirementSchema = z.strictObject({
  organizationId: CommerceOrganizationIdSchema,
  requirementId: CommerceRequirementIdSchema,
  sellerOrganizationId: CommerceOrganizationIdSchema,
  providerId: CommerceProviderIdSchema,
  listingId: CommerceListingIdSchema,
  listingVersion: CommerceListingVersionSchema,
  networkId: z.literal(COMMERCE_PAYMENT_NETWORK),
  asset: z.literal("USDC"),
  representation: z.literal("erc20"),
  decimals: z.literal(6),
  amountAtomic: Uint256Schema,
  feeAtomic: z.literal("0"),
  payToAddress: LowerAddressSchema,
  requirementDigest: Sha256DigestSchema,
  sourceKind: z.literal("verified_listing"),
  createdAt: StoreTimestampSchema,
  validUntil: StoreTimestampSchema,
});

export const CommercePaymentAttemptSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    attemptId: CommerceGrantAttemptIdSchema,
    grantId: CommerceGrantIdSchema,
    actionId: CommerceActionIdSchema,
    providerId: CommerceProviderIdSchema,
    listingId: CommerceListingIdSchema,
    listingVersion: CommerceListingVersionSchema,
    requirementId: CommerceRequirementIdSchema,
    requirementDigest: Sha256DigestSchema,
    networkId: z.literal(COMMERCE_PAYMENT_NETWORK),
    assetAddress: z.literal(COMMERCE_PAYMENT_ASSET_ADDRESS),
    verifyingContract: z.literal(COMMERCE_PAYMENT_VERIFYING_CONTRACT),
    payerAddress: AddressSchema,
    payToAddress: AddressSchema,
    valueAtomic: Uint256Schema,
    validAfter: Uint256Schema,
    validBefore: Uint256Schema,
    nonce: NonceSchema,
    laneRequirementDigest: Sha256DigestSchema,
    bindingDigest: Sha256DigestSchema,
    state: CommercePaymentAttemptStateSchema,
    persistedAt: StoreTimestampSchema,
    dispatchedAt: StoreTimestampSchema.nullable(),
    observedAt: StoreTimestampSchema.nullable(),
    transferId: TransferIdSchema.nullable(),
    gatewayStatus: CommercePaymentGatewayStatusSchema.nullable(),
    batchTxHash: Bytes32Schema.nullable(),
  })
  .superRefine((value, ctx) => {
    // The closed state shape, exactly as the store re-asserts it.
    const ok =
      (value.state === "persisted" &&
        value.dispatchedAt === null &&
        value.transferId === null) ||
      (value.state === "unknown" &&
        value.dispatchedAt !== null &&
        value.transferId === null &&
        value.gatewayStatus === null) ||
      (value.state === "pending" &&
        value.dispatchedAt !== null &&
        value.transferId !== null &&
        value.gatewayStatus !== null &&
        value.gatewayStatus !== "completed") ||
      (value.state === "committed" &&
        value.dispatchedAt !== null &&
        value.transferId !== null &&
        value.gatewayStatus === "completed" &&
        value.batchTxHash !== null);
    if (!ok) {
      ctx.addIssue({
        code: "custom",
        path: ["state"],
        message: "The attempt state shape is not closed",
      });
    }
  });

export const CommercePaymentAttemptPersistDataSchema = z
  .strictObject({
    replayed: z.boolean(),
    attempt: CommercePaymentAttemptSchema,
  })
  .superRefine((value, ctx) => {
    if (!value.replayed && value.attempt.state !== "persisted") {
      ctx.addIssue({
        code: "custom",
        path: ["attempt", "state"],
        message: "A first persist must be in the persisted state",
      });
    }
  });

/**
 * A recorded dispatch is `unknown`: the lane may now send, and nothing here
 * says the payment happened, settled or failed.
 */
export const CommercePaymentAttemptDispatchDataSchema = z
  .strictObject({
    attempt: CommercePaymentAttemptSchema,
  })
  .superRefine((value, ctx) => {
    if (value.attempt.state !== "unknown") {
      ctx.addIssue({
        code: "custom",
        path: ["attempt", "state"],
        message: "A recorded dispatch must be in the unknown state",
      });
    }
  });

/** Missing and foreign attempts are the same safe `item: null`. */
export const CommercePaymentAttemptReadDataSchema = z
  .strictObject({
    attemptId: CommerceGrantAttemptIdSchema,
    item: CommercePaymentAttemptSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    if (value.item !== null && value.item.attemptId !== value.attemptId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "attemptId"],
        message: "The item must be the requested attempt",
      });
    }
  });

export type CommercePaymentTermsData = z.infer<
  typeof CommercePaymentTermsDataSchema
>;
export type CommercePaymentVerifiedRequirement = z.infer<
  typeof CommercePaymentVerifiedRequirementSchema
>;
export type CommercePaymentAttempt = z.infer<
  typeof CommercePaymentAttemptSchema
>;
export type CommercePaymentAttemptPersistData = z.infer<
  typeof CommercePaymentAttemptPersistDataSchema
>;
export type CommercePaymentAttemptDispatchData = z.infer<
  typeof CommercePaymentAttemptDispatchDataSchema
>;
export type CommercePaymentAttemptReadData = z.infer<
  typeof CommercePaymentAttemptReadDataSchema
>;

// ── Success envelopes ───────────────────────────────────────────────────────

export const CommercePaymentTermsDataResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommercePaymentTermsDataSchema);
export const CommercePaymentRequirementResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommercePaymentVerifiedRequirementSchema);
export const CommercePaymentAttemptPersistDataResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommercePaymentAttemptPersistDataSchema);
export const CommercePaymentAttemptDispatchDataResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommercePaymentAttemptDispatchDataSchema);
export const CommercePaymentAttemptReadDataResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommercePaymentAttemptReadDataSchema);
