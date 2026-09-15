import { z } from "zod";

import { compareIsoTimestamps, IsoTimestampSchema } from "../primitives.js";
import { createCommerceSuccessEnvelopeSchema } from "./api.js";
import { CommerceActionStatusSchema } from "./control-action.js";
import { CommerceActionIdSchema } from "./control-budget.js";
import {
  CommerceGrantIdSchema,
  CommerceGrantTokenSchema,
} from "./control-grant.js";
import {
  CommerceGrantMetadataSchema,
  CommerceGrantProviderAttemptStatusSchema,
  CommerceGrantProviderViewSchema,
} from "./control-grant-model.js";
import { CommerceOrganizationIdSchema } from "./identity.js";
import { CommerceTenantMutationIdSchema } from "./tenant-writes.js";

/**
 * Pure strict authorization-grant management wire contracts.
 *
 * Bodies, read requests, safe receipts and response data shapes only. There is
 * no transport, URL/route parsing, server clock, storage, authority, crypto,
 * token issuance/retirement, hashing, reservation, payment, settlement or
 * capability activation here. Operation names and grant/action/attempt
 * identity are endpoint/path derived; this module never accepts an operation
 * as a body override. Parsing a record never proves a principal, a live grant,
 * a claim, a payment or spend authority: the future server must rebind the
 * current principal/session and reject cross-tenant receipts. All quantities
 * on the wire remain canonical integer strings, compared only as BigInt.
 *
 * Authority expressed by these shapes, unchanged from the frozen P03 review
 * resolution:
 *   * agent issue/replace authenticate the EXACT `oacs_v1_` commerce session
 *     and its bound action, so no organization/agent/policy id is accepted in
 *     an agent body;
 *   * a provider claim needs BOTH a current matching `oas_pr_` provider
 *     session AND the buyer's exact one-use `oag_v1_` grant token - neither
 *     alone, which is why the raw token is an INBOUND body field on exactly
 *     two provider requests;
 *   * human revoke and grant read use the browser/cookie audience inside the
 *     buyer organization and are organization-scoped in the path.
 *
 * Raw-token discipline is STRUCTURAL, not conventional. `CommerceGrantToken`
 * appears in exactly three places in this module: the provider introspect
 * body, the provider claim body, and the single `replayed: false` arm of the
 * agent issue/replace response data. Every status, detail, page, receipt,
 * outcome and provider projection here is a closed strict object whose key set
 * contains no field able to carry a raw token, a token hash, a salt, a pepper
 * or any secret material, so a replay or a status read cannot reconstruct a
 * retired secret even if a future service tried to put one there.
 *
 * Scope note: the accepted grant store exposes no list/page method, so this
 * module deliberately declares NO grant page, cursor or limit shape. Adding
 * one would freeze a route the store cannot serve. The action-wire page and
 * cursor discipline is therefore referenced, not duplicated.
 */

const ORGANIZATION_PROTECTED = "organization_protected" as const;
const ORGANIZATION_AUDIENCE = "organization" as const;
const PROVIDER_MINIMAL_AUDIENCE = "provider_minimal" as const;

type GrantWireAudience =
  | typeof ORGANIZATION_AUDIENCE
  | typeof PROVIDER_MINIMAL_AUDIENCE;

function protectedFields<K extends string>(
  keys: readonly K[],
): Readonly<Record<K, typeof ORGANIZATION_PROTECTED>> {
  const map = {} as Record<K, typeof ORGANIZATION_PROTECTED>;
  for (const key of keys) {
    map[key] = ORGANIZATION_PROTECTED;
  }
  return Object.freeze(map);
}

function grantWireFieldClass<K extends string>(
  audience: GrantWireAudience,
  keys: readonly K[],
) {
  return Object.freeze({
    dataClass: ORGANIZATION_PROTECTED,
    audience,
    fields: protectedFields(keys),
  });
}

/**
 * Rejects an object that explicitly carries a key whose value is `undefined`
 * so a present-but-undefined optional is not silently treated as absent. Runs
 * on raw input before the strict object parses it, mirroring the accepted
 * action/policy/session wire convention.
 */
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

/** Strict read-request builder: unknown keys rejected, no defaults/coercions. */
function strictRequestSchema<T extends z.ZodRawShape>(shape: T) {
  return z
    .unknown()
    .superRefine(rejectExplicitUndefinedKeys)
    .pipe(z.strictObject(shape));
}

// ── Local leaf grammars ─────────────────────────────────────────────────────

/**
 * Exact lower-case canonical UUIDv4 provider attempt id, absolute end. The
 * accepted grant model validates the same grammar for its provider
 * projections but does not export the leaf, so the identical pattern is
 * restated here rather than loosened. `(?![\s\S])` pins the absolute end of
 * input so a trailing LF cannot satisfy `$`.
 */
const ATTEMPT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/u;

export const CommerceGrantAttemptIdSchema = z
  .string()
  .regex(ATTEMPT_ID_PATTERN, { message: "Expected a canonical UUIDv4" });

export type CommerceGrantAttemptId = z.infer<
  typeof CommerceGrantAttemptIdSchema
>;

/**
 * `sha256:<64 lower-case hex>` with an absolute end. This is the opaque claim
 * correlation digest the store already computes from provider-side inputs. It
 * is NOT payment evidence, a nonce, a signature or a delivery proof, and it
 * never carries buyer material.
 */
const CLAIM_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}(?![\s\S])/u;

export const CommerceGrantClaimDigestSchema = z
  .string()
  .regex(CLAIM_DIGEST_PATTERN, {
    message: "Expected a lowercase SHA-256 digest",
  });

export type CommerceGrantClaimDigest = z.infer<
  typeof CommerceGrantClaimDigestSchema
>;

/**
 * Canonical generation 1..2147483647, absolute end. Compared only as BigInt;
 * no JS number, float or coercion participates.
 */
const GENERATION_PATTERN = /^[1-9][0-9]{0,9}(?![\s\S])/u;
const MAX_GENERATION = 2147483647n;

function canonicalGenerationToBigInt(value: string): bigint | null {
  if (!GENERATION_PATTERN.test(value)) return null;
  const parsed = BigInt(value);
  return parsed <= MAX_GENERATION ? parsed : null;
}

/** The frozen resource type for every grant receipt. Exactly one exists. */
export const COMMERCE_GRANT_RESOURCE_TYPE = "authorization_grant" as const;

/**
 * The fixed maximum grant lifetime, restated from the accepted grant model so
 * transport callers can name the bound. The bound itself is ENFORCED by
 * `CommerceGrantMetadataSchema`, which every grant-bearing shape below reuses;
 * this constant adds no second implementation of it.
 */
export const COMMERCE_GRANT_MAX_LIFETIME_SECONDS = 300 as const;

// ── Write bodies ────────────────────────────────────────────────────────────

/**
 * Agent grant issue. The `oacs_v1_` commerce session supplies organization,
 * agent, policy and buyer session identity, so none of those is representable
 * here. No expiry, amount, provider, listing or token field exists: the grant
 * secret is minted by the server and the economics come from the immutable
 * action/requirement, never from the caller.
 */
export const CommerceGrantIssueBodySchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
  actionId: CommerceActionIdSchema,
});

/**
 * Agent grant replace. The grant id is path derived, so the body carries only
 * the mutation correlation id. No expiry field exists, which is the structural
 * half of "a replacement can never extend the original expiry"; the arithmetic
 * half is enforced by the reused grant metadata bound and by
 * `CommerceGrantReplacementContinuitySchema`.
 */
export const CommerceGrantReplaceBodySchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
});

/**
 * Human grant revoke. Organization and grant id are path derived. There is no
 * reason, note, force, release or cascade field: revocation is a flag, never
 * an erasure, and it cannot be told to release a claimed exposure.
 */
export const CommerceGrantRevokeBodySchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
});

/**
 * Provider introspect. The SECOND factor - the buyer's exact one-use
 * `oag_v1_` token - is supplied here, in a body, never in a path or query, so
 * it cannot reach a URL, a log line or a referrer. The first factor is the
 * live `oas_pr_` provider session, which is transport state and is not
 * representable on the wire. Introspection is read-only: it consumes nothing.
 */
export const CommerceGrantProviderIntrospectBodySchema = z.strictObject({
  grantToken: CommerceGrantTokenSchema,
});

/**
 * Provider claim. Both factors again: the live provider session (transport)
 * and the exact one-use grant token (body). `expectedActionId` makes the
 * provider state the action it believes it is claiming, and `attemptId` is the
 * provider's OWN correlation id, which is later the only recovery key. No
 * buyer organization, policy, agent, session, account, balance or amount
 * override is representable.
 */
export const CommerceGrantProviderClaimBodySchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
  grantToken: CommerceGrantTokenSchema,
  expectedActionId: CommerceActionIdSchema,
  attemptId: CommerceGrantAttemptIdSchema,
});

export type CommerceGrantIssueBody = z.infer<
  typeof CommerceGrantIssueBodySchema
>;
export type CommerceGrantReplaceBody = z.infer<
  typeof CommerceGrantReplaceBodySchema
>;
export type CommerceGrantRevokeBody = z.infer<
  typeof CommerceGrantRevokeBodySchema
>;
export type CommerceGrantProviderIntrospectBody = z.infer<
  typeof CommerceGrantProviderIntrospectBodySchema
>;
export type CommerceGrantProviderClaimBody = z.infer<
  typeof CommerceGrantProviderClaimBodySchema
>;

// ── Read requests ───────────────────────────────────────────────────────────

/** Human grant detail read, organization scoped. */
export const CommerceGrantDetailRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  grantId: CommerceGrantIdSchema,
});

/** Human mutation-status read, organization scoped. */
export const CommerceGrantHumanMutationRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  mutationId: CommerceTenantMutationIdSchema,
});

/**
 * Agent mutation-status read. Organization and session identity come from the
 * `oacs_v1_` token, so only the mutation correlation id is carried.
 */
export const CommerceGrantAgentMutationRequestSchema = strictRequestSchema({
  mutationId: CommerceTenantMutationIdSchema,
});

/**
 * Provider attempt-status recovery. Keyed ONLY by the provider's own attempt
 * id: no grant id, no token, no action id and no organization. A missing
 * attempt and a foreign attempt must be indistinguishable, which is why this
 * request cannot name anything the provider does not already own.
 */
export const CommerceGrantProviderAttemptStatusRequestSchema =
  strictRequestSchema({
    attemptId: CommerceGrantAttemptIdSchema,
  });

export type CommerceGrantDetailRequest = z.infer<
  typeof CommerceGrantDetailRequestSchema
>;
export type CommerceGrantHumanMutationRequest = z.infer<
  typeof CommerceGrantHumanMutationRequestSchema
>;
export type CommerceGrantAgentMutationRequest = z.infer<
  typeof CommerceGrantAgentMutationRequestSchema
>;
export type CommerceGrantProviderAttemptStatusRequest = z.infer<
  typeof CommerceGrantProviderAttemptStatusRequestSchema
>;

// ── Receipts ────────────────────────────────────────────────────────────────

function grantReceiptSchema<T extends string>(operation: T) {
  return z.strictObject({
    mutationId: CommerceTenantMutationIdSchema,
    operation: z.literal(operation),
    resourceType: z.literal(COMMERCE_GRANT_RESOURCE_TYPE),
    resourceId: CommerceGrantIdSchema,
    committedAt: IsoTimestampSchema,
  });
}

/**
 * Operation-discriminated safe receipts. Each variant fixes the operation and
 * the literal `authorization_grant` resource type with a canonical grant id.
 * No actor, hash, session context, idempotency material, token, generation or
 * raw payload is representable, so a receipt can never deliver a secret.
 */
export const CommerceGrantIssueReceiptSchema = grantReceiptSchema(
  "control.grant.issue",
);
export const CommerceGrantReplaceReceiptSchema = grantReceiptSchema(
  "control.grant.replace",
);
export const CommerceGrantClaimReceiptSchema = grantReceiptSchema(
  "control.grant.claim",
);
export const CommerceGrantRevokeReceiptSchema = grantReceiptSchema(
  "control.grant.revoke",
);

/** Agent audience receipts: issue and replace only. */
export const CommerceGrantAgentReceiptSchema = z.discriminatedUnion(
  "operation",
  [CommerceGrantIssueReceiptSchema, CommerceGrantReplaceReceiptSchema],
);

/** Full four-operation receipt union. */
export const CommerceGrantMutationReceiptSchema = z.discriminatedUnion(
  "operation",
  [
    CommerceGrantIssueReceiptSchema,
    CommerceGrantReplaceReceiptSchema,
    CommerceGrantClaimReceiptSchema,
    CommerceGrantRevokeReceiptSchema,
  ],
);

export type CommerceGrantIssueReceipt = z.infer<
  typeof CommerceGrantIssueReceiptSchema
>;
export type CommerceGrantReplaceReceipt = z.infer<
  typeof CommerceGrantReplaceReceiptSchema
>;
export type CommerceGrantClaimReceipt = z.infer<
  typeof CommerceGrantClaimReceiptSchema
>;
export type CommerceGrantRevokeReceipt = z.infer<
  typeof CommerceGrantRevokeReceiptSchema
>;
export type CommerceGrantAgentReceipt = z.infer<
  typeof CommerceGrantAgentReceiptSchema
>;
export type CommerceGrantMutationReceipt = z.infer<
  typeof CommerceGrantMutationReceiptSchema
>;

// ── Agent issue / replace delivery data ─────────────────────────────────────

/**
 * Agent issue data. The raw one-use `oag_v1_` token is delivered EXACTLY ONCE,
 * by the API, after commit, and that is expressed by the discriminator rather
 * than by a convention: the `replayed: true` arm is a closed strict object
 * with no `grantToken` key at all, so a replay is structurally incapable of
 * reconstructing the secret. A fresh commit is the first generation of a grant
 * in status `issued`; the reused grant metadata already pins the 300-second
 * ceiling, the strictly-future expiry and the claim/revoke nullability rules.
 */
export const CommerceGrantIssueDataSchema = z
  .discriminatedUnion("replayed", [
    z.strictObject({
      replayed: z.literal(false),
      metadata: CommerceGrantMetadataSchema,
      receipt: CommerceGrantIssueReceiptSchema,
      grantToken: CommerceGrantTokenSchema,
    }),
    z.strictObject({
      replayed: z.literal(true),
      metadata: CommerceGrantMetadataSchema,
      receipt: CommerceGrantIssueReceiptSchema,
    }),
  ])
  .superRefine((value, ctx) => {
    if (value.receipt.resourceId !== value.metadata.grantId) {
      ctx.addIssue({
        code: "custom",
        path: ["receipt", "resourceId"],
        message: "receipt resourceId must equal metadata.grantId",
      });
    }
    if (value.replayed) return;
    if (value.metadata.status !== "issued") {
      ctx.addIssue({
        code: "custom",
        path: ["metadata", "status"],
        message: "a first-delivery issue requires status 'issued'",
      });
    }
    const generation = canonicalGenerationToBigInt(value.metadata.generation);
    if (generation !== null && generation !== 1n) {
      ctx.addIssue({
        code: "custom",
        path: ["metadata", "generation"],
        message: "a first-delivery issue requires generation '1'",
      });
    }
  });

/**
 * Agent replace data. Same one-shot delivery discipline. A first delivery is
 * always a LATER generation of the SAME grant, still unclaimed and unrevoked,
 * because replacement is permitted only before any claim or exposure. The
 * original expiry is immutable, so `metadata.expiresAt` is still measured
 * against the immutable first-issue `issuedAt` and its 300-second ceiling.
 */
export const CommerceGrantReplaceDataSchema = z
  .discriminatedUnion("replayed", [
    z.strictObject({
      replayed: z.literal(false),
      metadata: CommerceGrantMetadataSchema,
      receipt: CommerceGrantReplaceReceiptSchema,
      grantToken: CommerceGrantTokenSchema,
    }),
    z.strictObject({
      replayed: z.literal(true),
      metadata: CommerceGrantMetadataSchema,
      receipt: CommerceGrantReplaceReceiptSchema,
    }),
  ])
  .superRefine((value, ctx) => {
    if (value.receipt.resourceId !== value.metadata.grantId) {
      ctx.addIssue({
        code: "custom",
        path: ["receipt", "resourceId"],
        message: "receipt resourceId must equal metadata.grantId",
      });
    }
    if (value.replayed) return;
    if (value.metadata.status !== "issued") {
      ctx.addIssue({
        code: "custom",
        path: ["metadata", "status"],
        message: "a first-delivery replacement requires status 'issued'",
      });
    }
    if (value.metadata.claimedAt !== null) {
      ctx.addIssue({
        code: "custom",
        path: ["metadata", "claimedAt"],
        message: "a replacement is only permitted before any claim",
      });
    }
    const generation = canonicalGenerationToBigInt(value.metadata.generation);
    if (generation !== null && generation < 2n) {
      ctx.addIssue({
        code: "custom",
        path: ["metadata", "generation"],
        message: "a first-delivery replacement requires generation 2 or later",
      });
    }
  });

export type CommerceGrantIssueData = z.infer<
  typeof CommerceGrantIssueDataSchema
>;
export type CommerceGrantReplaceData = z.infer<
  typeof CommerceGrantReplaceDataSchema
>;

/**
 * Local replacement-continuity check over two grant metadata snapshots of the
 * SAME grant. This is not a response shape and no route returns it; it is the
 * pure predicate a service or test uses to prove a replacement kept its
 * identity, advanced exactly one grant's generation, and did NOT extend the
 * original expiry. Timestamps are compared with the accepted exact fractional
 * comparator, never through a JS Date millisecond, and generations are
 * compared as BigInt.
 */
export const CommerceGrantReplacementContinuitySchema = z
  .strictObject({
    previous: CommerceGrantMetadataSchema,
    next: CommerceGrantMetadataSchema,
  })
  .superRefine((value, ctx) => {
    const { previous, next } = value;
    const identity = [
      ["grantId", previous.grantId, next.grantId],
      ["organizationId", previous.organizationId, next.organizationId],
      ["subjectAgentId", previous.subjectAgentId, next.subjectAgentId],
      ["actionId", previous.actionId, next.actionId],
      ["reservationId", previous.reservationId, next.reservationId],
      [
        "commerceSessionId",
        previous.commerceSessionId,
        next.commerceSessionId,
      ],
      ["providerId", previous.providerId, next.providerId],
      ["listingId", previous.listingId, next.listingId],
      ["listingVersion", previous.listingVersion, next.listingVersion],
      ["issuedAt", previous.issuedAt, next.issuedAt],
    ] as const;
    for (const [field, before, after] of identity) {
      if (before !== after) {
        ctx.addIssue({
          code: "custom",
          path: ["next", field],
          message: `a replacement must not change ${field}`,
        });
      }
    }

    const before = canonicalGenerationToBigInt(previous.generation);
    const after = canonicalGenerationToBigInt(next.generation);
    if (before !== null && after !== null && after <= before) {
      ctx.addIssue({
        code: "custom",
        path: ["next", "generation"],
        message: "a replacement must advance the generation",
      });
    }

    if (previous.status !== "issued") {
      ctx.addIssue({
        code: "custom",
        path: ["previous", "status"],
        message: "only an 'issued' grant may be replaced",
      });
    }
    if (previous.claimedAt !== null) {
      ctx.addIssue({
        code: "custom",
        path: ["previous", "claimedAt"],
        message: "a claimed grant may not be replaced",
      });
    }
    if (next.status !== "issued") {
      ctx.addIssue({
        code: "custom",
        path: ["next", "status"],
        message: "a replacement must produce an 'issued' grant",
      });
    }

    const previousExpiryValid = IsoTimestampSchema.safeParse(
      previous.expiresAt,
    ).success;
    const nextExpiryValid = IsoTimestampSchema.safeParse(
      next.expiresAt,
    ).success;
    if (
      previousExpiryValid &&
      nextExpiryValid &&
      compareIsoTimestamps(next.expiresAt, previous.expiresAt) > 0
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["next", "expiresAt"],
        message: "a replacement must not extend the original expiry",
      });
    }
  });

export type CommerceGrantReplacementContinuity = z.infer<
  typeof CommerceGrantReplacementContinuitySchema
>;

// ── Human revoke data ───────────────────────────────────────────────────────

/**
 * Human revoke data. `released` is true ONLY when the grant was never claimed
 * and its held reservation was actually released, in which case the bound
 * action is `cancelled`. A claimed grant keeps its claim fact AND its held
 * exposure: `claimedAt` stays non-null and `released` must be false. Revoked
 * is a flag, never an erasure, so this shape has no field able to clear a
 * claim and no refund, settlement, payment or delivery field of any kind.
 *
 * The store's raw reservation status is deliberately NOT surfaced: no accepted
 * shared reservation-status vocabulary exists and the transport must not
 * invent one.
 */
export const CommerceGrantRevokeDataSchema = z
  .strictObject({
    replayed: z.boolean(),
    metadata: CommerceGrantMetadataSchema,
    receipt: CommerceGrantRevokeReceiptSchema,
    released: z.boolean(),
    actionStatus: CommerceActionStatusSchema,
  })
  .superRefine((value, ctx) => {
    if (value.receipt.resourceId !== value.metadata.grantId) {
      ctx.addIssue({
        code: "custom",
        path: ["receipt", "resourceId"],
        message: "receipt resourceId must equal metadata.grantId",
      });
    }
    if (value.metadata.status !== "revoked") {
      ctx.addIssue({
        code: "custom",
        path: ["metadata", "status"],
        message: "revoke data requires metadata.status 'revoked'",
      });
    }
    if (value.metadata.claimedAt !== null && value.released) {
      ctx.addIssue({
        code: "custom",
        path: ["released"],
        message: "a claimed grant retains its exposure and cannot be released",
      });
    }
    if (value.released) {
      if (value.metadata.claimedAt !== null) {
        ctx.addIssue({
          code: "custom",
          path: ["metadata", "claimedAt"],
          message: "a released revoke requires a never-claimed grant",
        });
      }
      if (value.actionStatus !== "cancelled") {
        ctx.addIssue({
          code: "custom",
          path: ["actionStatus"],
          message: "a released revoke requires a cancelled action",
        });
      }
    }
  });

export type CommerceGrantRevokeData = z.infer<
  typeof CommerceGrantRevokeDataSchema
>;

// ── Provider data ───────────────────────────────────────────────────────────

/**
 * Provider introspection data. Exactly the accepted provider projection, which
 * is a positive allowlist: no buyer organization, agent, policy, session,
 * account, balance or approval field exists in it. A missing or foreign grant
 * is a fixed error at the service boundary, never a distinguishable null here.
 */
export const CommerceGrantProviderIntrospectionSchema = z.strictObject({
  item: CommerceGrantProviderViewSchema,
});

export type CommerceGrantProviderIntrospection = z.infer<
  typeof CommerceGrantProviderIntrospectionSchema
>;

/**
 * Provider claim data. The projection is the same positive allowlist, so this
 * response can carry no buyer-private field. `claimDigest` is opaque internal
 * correlation derived from provider-side inputs; it is NOT a payment nonce,
 * signature, settlement or delivery proof. The claimed attempt must be exactly
 * the attempt the provider named, the grant must actually record a claim, and
 * the claim instant must fall strictly before the grant expiry, compared with
 * the exact fractional comparator.
 */
export const CommerceGrantProviderClaimDataSchema = z
  .strictObject({
    replayed: z.boolean(),
    item: CommerceGrantProviderViewSchema,
    attemptId: CommerceGrantAttemptIdSchema,
    claimedAt: IsoTimestampSchema,
    claimDigest: CommerceGrantClaimDigestSchema,
    receipt: CommerceGrantClaimReceiptSchema,
  })
  .superRefine((value, ctx) => {
    if (value.receipt.resourceId !== value.item.grantId) {
      ctx.addIssue({
        code: "custom",
        path: ["receipt", "resourceId"],
        message: "receipt resourceId must equal item.grantId",
      });
    }
    if (value.item.status !== "claimed" && value.item.status !== "revoked") {
      ctx.addIssue({
        code: "custom",
        path: ["item", "status"],
        message: "claim data requires a claimed or revoked grant projection",
      });
    }
    if (value.item.claimedAttemptId === null) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "claimedAttemptId"],
        message: "claim data requires a non-null claimedAttemptId",
      });
    } else if (value.item.claimedAttemptId !== value.attemptId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "claimedAttemptId"],
        message: "item claimedAttemptId must equal the claimed attemptId",
      });
    }
    const claimedValid = IsoTimestampSchema.safeParse(
      value.claimedAt,
    ).success;
    const expiresValid = IsoTimestampSchema.safeParse(
      value.item.expiresAt,
    ).success;
    if (
      claimedValid &&
      expiresValid &&
      compareIsoTimestamps(value.claimedAt, value.item.expiresAt) >= 0
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["claimedAt"],
        message: "claimedAt must be strictly before the grant expiresAt",
      });
    }
  });

export type CommerceGrantProviderClaimData = z.infer<
  typeof CommerceGrantProviderClaimDataSchema
>;

/**
 * Provider attempt-status recovery data. The wrapper echoes only the attempt
 * id the provider already owns and the accepted recovery projection, whose
 * `not_found` arm carries ONLY its status - which is exactly what makes a
 * missing attempt indistinguishable from a foreign one. A `claimed` arm
 * retains the claim fact plus the `grantRevoked` flag after revocation or
 * expiry, because retirement alone is not evidence of nonpayment.
 */
export const CommerceGrantProviderAttemptStatusDataSchema = z
  .strictObject({
    attemptId: CommerceGrantAttemptIdSchema,
    item: CommerceGrantProviderAttemptStatusSchema,
  })
  .superRefine((value, ctx) => {
    if (value.item.status !== "claimed") return;
    if (value.item.attemptId !== value.attemptId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "attemptId"],
        message: "item attemptId must match the requested attemptId",
      });
    }
  });

export type CommerceGrantProviderAttemptStatusData = z.infer<
  typeof CommerceGrantProviderAttemptStatusDataSchema
>;

// ── Human detail read ───────────────────────────────────────────────────────

/**
 * Human grant detail: wrapper identity plus nullable accepted grant metadata.
 * When non-null the item grantId and organizationId must match the wrapper,
 * enforcing cross-ID and cross-tenant binding. A missing grant and a foreign
 * grant are the same safe `null`. The metadata carries no token, no token
 * hash and no secret material, so this read can never expose a grant secret.
 */
export const CommerceGrantDetailSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    grantId: CommerceGrantIdSchema,
    item: CommerceGrantMetadataSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    if (value.item === null) return;
    if (value.item.grantId !== value.grantId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "grantId"],
        message: "item grantId must match grantId",
      });
    }
    if (value.item.organizationId !== value.organizationId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "organizationId"],
        message: "item organizationId must match organizationId",
      });
    }
  });

export type CommerceGrantDetail = z.infer<typeof CommerceGrantDetailSchema>;

// ── Mutation status ─────────────────────────────────────────────────────────

/**
 * Agent mutation status. Closed discriminated union, exactly
 * `{status:'committed',receipt}` or `{status:'not_found'}`; `not_found`
 * carries no field besides `status`. The committed receipt is restricted to
 * the two agent operations, so a browser or provider receipt can never be
 * served on the agent lane. No `grantToken` key exists on either arm: a status
 * read NEVER reconstructs the one-use secret.
 */
export const CommerceGrantAgentMutationStatusSchema = z.discriminatedUnion(
  "status",
  [
    z.strictObject({
      status: z.literal("not_found"),
    }),
    z.strictObject({
      status: z.literal("committed"),
      receipt: CommerceGrantAgentReceiptSchema,
    }),
  ],
);

/**
 * Human mutation status. Same committed-or-not-found discipline, with the
 * committed receipt restricted to `control.grant.revoke`, so a browser cookie
 * can never be handed an agent issue/replace or a provider claim receipt.
 */
export const CommerceGrantHumanMutationStatusSchema = z.discriminatedUnion(
  "status",
  [
    z.strictObject({
      status: z.literal("not_found"),
    }),
    z.strictObject({
      status: z.literal("committed"),
      receipt: CommerceGrantRevokeReceiptSchema,
    }),
  ],
);

export type CommerceGrantAgentMutationStatus = z.infer<
  typeof CommerceGrantAgentMutationStatusSchema
>;
export type CommerceGrantHumanMutationStatus = z.infer<
  typeof CommerceGrantHumanMutationStatusSchema
>;

/**
 * Unknown-outcome representation for a grant mutation whose COMMIT could not
 * be confirmed. It is deliberately a THIRD arm that can never be mistaken for
 * any of the others:
 *
 *   * it is not success - it carries no receipt, no committedAt and no
 *     resource id, so nothing downstream can treat it as committed;
 *   * it is not failure - `not_committed` is a separate literal, so an unknown
 *     outcome can never be reported as a clean rollback;
 *   * it is not a refund and not a release - there is no `released`,
 *     `refunded`, `settled`, `reservation`, `amount` or `status` field on any
 *     arm, so an unknown outcome cannot assert that money or exposure moved
 *     back.
 *
 * The only safe recovery is to re-read the mutation status by `mutationId`,
 * or, for a provider claim, the attempt status by `attemptId`. Every arm
 * carries the mutation id so the caller can do exactly that, and a committed
 * arm must carry a receipt bound to that same mutation id.
 */
export const CommerceGrantMutationOutcomeSchema = z
  .discriminatedUnion("outcome", [
    z.strictObject({
      outcome: z.literal("committed"),
      mutationId: CommerceTenantMutationIdSchema,
      receipt: CommerceGrantMutationReceiptSchema,
    }),
    z.strictObject({
      outcome: z.literal("not_committed"),
      mutationId: CommerceTenantMutationIdSchema,
    }),
    z.strictObject({
      outcome: z.literal("unknown"),
      mutationId: CommerceTenantMutationIdSchema,
    }),
  ])
  .superRefine((value, ctx) => {
    if (value.outcome !== "committed") return;
    if (value.receipt.mutationId !== value.mutationId) {
      ctx.addIssue({
        code: "custom",
        path: ["receipt", "mutationId"],
        message: "receipt mutationId must equal the outcome mutationId",
      });
    }
  });

export type CommerceGrantMutationOutcome = z.infer<
  typeof CommerceGrantMutationOutcomeSchema
>;

// ── Envelopes ───────────────────────────────────────────────────────────────

/**
 * Typed strict v2 success envelopes over the eight response data shapes. These
 * reuse the accepted factory and add no envelope version or error behavior.
 */
export const CommerceGrantIssueDataResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceGrantIssueDataSchema);
export const CommerceGrantReplaceDataResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceGrantReplaceDataSchema);
export const CommerceGrantRevokeDataResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceGrantRevokeDataSchema);
export const CommerceGrantProviderIntrospectionResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceGrantProviderIntrospectionSchema);
export const CommerceGrantProviderClaimDataResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceGrantProviderClaimDataSchema);
export const CommerceGrantProviderAttemptStatusDataResponseSchema =
  createCommerceSuccessEnvelopeSchema(
    CommerceGrantProviderAttemptStatusDataSchema,
  );
export const CommerceGrantDetailResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceGrantDetailSchema);
export const CommerceGrantAgentMutationStatusResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceGrantAgentMutationStatusSchema);
export const CommerceGrantHumanMutationStatusResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceGrantHumanMutationStatusSchema);

export type CommerceGrantIssueDataResponse = z.infer<
  typeof CommerceGrantIssueDataResponseSchema
>;
export type CommerceGrantReplaceDataResponse = z.infer<
  typeof CommerceGrantReplaceDataResponseSchema
>;
export type CommerceGrantRevokeDataResponse = z.infer<
  typeof CommerceGrantRevokeDataResponseSchema
>;
export type CommerceGrantProviderIntrospectionResponse = z.infer<
  typeof CommerceGrantProviderIntrospectionResponseSchema
>;
export type CommerceGrantProviderClaimDataResponse = z.infer<
  typeof CommerceGrantProviderClaimDataResponseSchema
>;
export type CommerceGrantProviderAttemptStatusDataResponse = z.infer<
  typeof CommerceGrantProviderAttemptStatusDataResponseSchema
>;
export type CommerceGrantDetailResponse = z.infer<
  typeof CommerceGrantDetailResponseSchema
>;
export type CommerceGrantAgentMutationStatusResponse = z.infer<
  typeof CommerceGrantAgentMutationStatusResponseSchema
>;
export type CommerceGrantHumanMutationStatusResponse = z.infer<
  typeof CommerceGrantHumanMutationStatusResponseSchema
>;

// ── Field classes ───────────────────────────────────────────────────────────

/**
 * Conservative field-class registry for the new grant wire fields. Every field
 * is `organization_protected`; buyer/agent shapes carry the `organization`
 * audience and the three provider shapes carry `provider_minimal`. This is
 * descriptive metadata only, not authorization, redaction or a persistence
 * assertion, and it deliberately reuses the existing privacy vocabulary.
 *
 * The `provider_minimal` entries are positive allowlists: none of them names a
 * buyer organization, agent, policy, policy revision, commerce session,
 * account, approval, reservation or balance field.
 */
export const COMMERCE_GRANT_WIRE_FIELD_CLASSES = Object.freeze({
  issueBody: grantWireFieldClass(ORGANIZATION_AUDIENCE, [
    "mutationId",
    "actionId",
  ] as const),
  replaceBody: grantWireFieldClass(ORGANIZATION_AUDIENCE, [
    "mutationId",
  ] as const),
  revokeBody: grantWireFieldClass(ORGANIZATION_AUDIENCE, [
    "mutationId",
  ] as const),
  providerIntrospectBody: grantWireFieldClass(PROVIDER_MINIMAL_AUDIENCE, [
    "grantToken",
  ] as const),
  providerClaimBody: grantWireFieldClass(PROVIDER_MINIMAL_AUDIENCE, [
    "mutationId",
    "grantToken",
    "expectedActionId",
    "attemptId",
  ] as const),
  detailRequest: grantWireFieldClass(ORGANIZATION_AUDIENCE, [
    "organizationId",
    "grantId",
  ] as const),
  humanMutationRequest: grantWireFieldClass(ORGANIZATION_AUDIENCE, [
    "organizationId",
    "mutationId",
  ] as const),
  agentMutationRequest: grantWireFieldClass(ORGANIZATION_AUDIENCE, [
    "mutationId",
  ] as const),
  providerAttemptStatusRequest: grantWireFieldClass(
    PROVIDER_MINIMAL_AUDIENCE,
    ["attemptId"] as const,
  ),
  receipt: grantWireFieldClass(ORGANIZATION_AUDIENCE, [
    "mutationId",
    "operation",
    "resourceType",
    "resourceId",
    "committedAt",
  ] as const),
  issueData: grantWireFieldClass(ORGANIZATION_AUDIENCE, [
    "replayed",
    "metadata",
    "receipt",
    "grantToken",
  ] as const),
  replaceData: grantWireFieldClass(ORGANIZATION_AUDIENCE, [
    "replayed",
    "metadata",
    "receipt",
    "grantToken",
  ] as const),
  revokeData: grantWireFieldClass(ORGANIZATION_AUDIENCE, [
    "replayed",
    "metadata",
    "receipt",
    "released",
    "actionStatus",
  ] as const),
  providerIntrospection: grantWireFieldClass(PROVIDER_MINIMAL_AUDIENCE, [
    "item",
  ] as const),
  providerClaimData: grantWireFieldClass(PROVIDER_MINIMAL_AUDIENCE, [
    "replayed",
    "item",
    "attemptId",
    "claimedAt",
    "claimDigest",
    "receipt",
  ] as const),
  providerAttemptStatusData: grantWireFieldClass(PROVIDER_MINIMAL_AUDIENCE, [
    "attemptId",
    "item",
  ] as const),
  detail: grantWireFieldClass(ORGANIZATION_AUDIENCE, [
    "organizationId",
    "grantId",
    "item",
  ] as const),
  mutationStatus: grantWireFieldClass(ORGANIZATION_AUDIENCE, [
    "status",
    "receipt",
  ] as const),
  mutationOutcome: grantWireFieldClass(ORGANIZATION_AUDIENCE, [
    "outcome",
    "mutationId",
    "receipt",
  ] as const),
});
