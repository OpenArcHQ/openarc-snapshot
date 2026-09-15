import { z } from "zod";

import {
  IsoTimestampSchema,
  compareIsoTimestamps,
} from "../primitives.js";
import { createCommerceSuccessEnvelopeSchema } from "./api.js";
import { CommercePolicyIdSchema } from "./control-policy.js";
import {
  CommerceAgentIdSchema,
  CommerceOrganizationIdSchema,
} from "./identity.js";
import { CommerceTenantMutationIdSchema } from "./tenant-writes.js";

/**
 * Pure commerce-session wire contracts.
 *
 * Browser-safe, strict Zod DTOs for the human-issued commerce session, the
 * one-time handoff exchange, revocation, status/pages and their v2 envelopes.
 * There is no transport, URL parsing, route registry, server clock, storage,
 * crypto, hashing or authorization here. Parsing one of these shapes never
 * proves a principal is authenticated, that an exchange happened, or that any
 * spending/payment authority exists: the future server must rebind the current
 * principal and reject cross-tenant receipts.
 *
 * Raw handoff/session secrets appear ONLY in the exchange request body and the
 * one-time `available_once` delivery. They are never representable in a
 * status, receipt, replay delivery, page, metadata or error shape.
 */

export const COMMERCE_CONTROL_SESSION_SCHEMA_VERSION =
  "openarc.control.commerce-session.v1" as const;

export const COMMERCE_CONTROL_SESSION_NETWORK_ID = "eip155:5042002" as const;
export const COMMERCE_CONTROL_SESSION_ASSET = "USDC" as const;
export const COMMERCE_CONTROL_SESSION_REPRESENTATION = "erc20" as const;
export const COMMERCE_CONTROL_SESSION_DECIMALS = 6 as const;
export const COMMERCE_CONTROL_SESSION_SCOPE = "commerce.authorize" as const;

/** New session identity is a canonical lower-case UUIDv4 correlation id. */
export const CommerceControlSessionIdSchema = CommerceTenantMutationIdSchema;

export type CommerceControlSessionId = z.infer<
  typeof CommerceControlSessionIdSchema
>;

/**
 * Exactly one scope: `commerce.authorize`. A tuple rejects empty, duplicate,
 * widened and old-machine-scope variants.
 */
export const CommerceControlSessionScopesSchema = z.tuple([
  z.literal(COMMERCE_CONTROL_SESSION_SCOPE),
]);

export type CommerceControlSessionScopes = z.infer<
  typeof CommerceControlSessionScopesSchema
>;

/**
 * Canonical unpadded base64url encoding of exactly 32 bytes: 43 characters
 * whose final character carries zero padding bits. Reused verbatim from the
 * accepted machine 43-character grammar; no decode dependency is required.
 */
const BASE64URL_FINAL_ALPHABET = "AEIMQUYcgkosw048";
const SECRET_MATERIAL_PATTERN = `[A-Za-z0-9_-]{42}[${BASE64URL_FINAL_ALPHABET}](?![\\s\\S])`;

/**
 * Raw one-time handoff token `oach_v1_<43base64url>`. Its distinct namespace
 * cannot accept machine `oas_ag_`/`oas_pr_`/`oac_*` tokens, and the commerce
 * namespace cannot satisfy it.
 */
export const CommerceControlHandoffTokenSchema = z
  .string()
  .regex(
    new RegExp(`^oach_v1_${SECRET_MATERIAL_PATTERN}`),
    "Expected a canonical oach_v1_ handoff token",
  );

export type CommerceControlHandoffToken = z.infer<
  typeof CommerceControlHandoffTokenSchema
>;

/**
 * Raw one-time commerce session token `oacs_v1_<43base64url>`. Distinct from
 * every machine token namespace and from the handoff namespace.
 */
export const CommerceControlSessionTokenSchema = z
  .string()
  .regex(
    new RegExp(`^oacs_v1_${SECRET_MATERIAL_PATTERN}`),
    "Expected a canonical oacs_v1_ session token",
  );

export type CommerceControlSessionToken = z.infer<
  typeof CommerceControlSessionTokenSchema
>;

/**
 * Exact whole seconds shifted onto an accepted ISO leaf, preserving the
 * original fractional digits so the comparison stays exact (Date.parse on the
 * whole timestamp would truncate the fraction).
 */
function shiftIsoSeconds(iso: string, seconds: number): string | null {
  const match =
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$/u.exec(iso);
  if (!match) return null;
  const baseMs = Date.parse(`${match[1]}Z`);
  if (!Number.isFinite(baseMs)) return null;
  const shifted = new Date(baseMs + seconds * 1000).toISOString();
  const secondPart = shifted.slice(0, 19);
  return match[2] === undefined
    ? `${secondPart}Z`
    : `${secondPart}.${match[2]}Z`;
}

const MAX_ISSUE_LIFETIME_SECONDS = 900;
const MAX_HANDOFF_LIFETIME_SECONDS = 300;

/**
 * Strict safe session metadata. `expiresAt` must strictly follow `issuedAt`
 * and stay within the 900-second database maximum, compared with exact
 * fractional precision. `exchangedAt`, when present, sits at or after
 * `issuedAt` and strictly before `expiresAt`. `revokedAt`, when present, sits
 * at or after `issuedAt` and (if exchanged) at or after `exchangedAt`;
 * revocation may occur after expiry. No current-clock inference exists here.
 */
export const CommerceControlSessionMetadataSchema = z
  .strictObject({
    schemaVersion: z.literal(COMMERCE_CONTROL_SESSION_SCHEMA_VERSION),
    sessionId: CommerceControlSessionIdSchema,
    organizationId: CommerceOrganizationIdSchema,
    subjectAgentId: CommerceAgentIdSchema,
    policyId: CommercePolicyIdSchema,
    scopes: CommerceControlSessionScopesSchema,
    networkId: z.literal(COMMERCE_CONTROL_SESSION_NETWORK_ID),
    asset: z.literal(COMMERCE_CONTROL_SESSION_ASSET),
    representation: z.literal(COMMERCE_CONTROL_SESSION_REPRESENTATION),
    decimals: z.literal(COMMERCE_CONTROL_SESSION_DECIMALS),
    issuedAt: IsoTimestampSchema,
    expiresAt: IsoTimestampSchema,
    exchangedAt: IsoTimestampSchema.nullable(),
    revokedAt: IsoTimestampSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    const issuedAtValid = IsoTimestampSchema.safeParse(value.issuedAt).success;
    const expiresAtValid = IsoTimestampSchema.safeParse(value.expiresAt).success;
    if (!issuedAtValid || !expiresAtValid) return;
    if (compareIsoTimestamps(value.expiresAt, value.issuedAt) <= 0) {
      ctx.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "expiresAt must strictly follow issuedAt",
      });
    } else {
      const maxExpiry = shiftIsoSeconds(
        value.issuedAt,
        MAX_ISSUE_LIFETIME_SECONDS,
      );
      if (
        maxExpiry !== null &&
        compareIsoTimestamps(value.expiresAt, maxExpiry) > 0
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["expiresAt"],
          message: "expiresAt must be at most 900 seconds after issuedAt",
        });
      }
    }
    if (value.exchangedAt !== null) {
      if (
        IsoTimestampSchema.safeParse(value.exchangedAt).success &&
        (compareIsoTimestamps(value.exchangedAt, value.issuedAt) < 0 ||
          compareIsoTimestamps(value.exchangedAt, value.expiresAt) >= 0)
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["exchangedAt"],
          message:
            "exchangedAt must be at or after issuedAt and strictly before expiresAt",
        });
      }
    }
    if (value.revokedAt !== null) {
      if (!IsoTimestampSchema.safeParse(value.revokedAt).success) return;
      if (compareIsoTimestamps(value.revokedAt, value.issuedAt) < 0) {
        ctx.addIssue({
          code: "custom",
          path: ["revokedAt"],
          message: "revokedAt must be at or after issuedAt",
        });
      }
      if (
        value.exchangedAt !== null &&
        IsoTimestampSchema.safeParse(value.exchangedAt).success &&
        compareIsoTimestamps(value.revokedAt, value.exchangedAt) < 0
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["revokedAt"],
          message: "revokedAt must be at or after exchangedAt",
        });
      }
    }
  });

export type CommerceControlSessionMetadata = z.infer<
  typeof CommerceControlSessionMetadataSchema
>;

export const CommerceControlSessionStatusValueSchema = z.enum([
  "handoff_pending",
  "active",
  "revoked",
  "expired",
  "invalidated",
]);

export type CommerceControlSessionStatusValue = z.infer<
  typeof CommerceControlSessionStatusValueSchema
>;

/**
 * DB-derived status view. `revoked` holds iff `revokedAt` is present;
 * `handoff_pending` requires a null `exchangedAt`; `active` requires a
 * non-null `exchangedAt`; `expired`/`invalidated` require a null `revokedAt`
 * and may carry either exchange state. This declares server state only; the
 * parser never proves the clock or a principal.
 */
export const CommerceControlSessionStatusItemSchema = z
  .strictObject({
    metadata: CommerceControlSessionMetadataSchema,
    status: CommerceControlSessionStatusValueSchema,
  })
  .superRefine((value, ctx) => {
    const revokedPresent = value.metadata.revokedAt !== null;
    if ((value.status === "revoked") !== revokedPresent) {
      ctx.addIssue({
        code: "custom",
        path: ["status"],
        message: "status revoked must hold if and only if revokedAt is present",
      });
    }
    if (
      value.status === "handoff_pending" &&
      value.metadata.exchangedAt !== null
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["metadata", "exchangedAt"],
        message: "handoff_pending requires a null exchangedAt",
      });
    }
    if (value.status === "active" && value.metadata.exchangedAt === null) {
      ctx.addIssue({
        code: "custom",
        path: ["metadata", "exchangedAt"],
        message: "active requires a non-null exchangedAt",
      });
    }
    if (
      (value.status === "expired" || value.status === "invalidated") &&
      revokedPresent
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["status"],
        message: "expired/invalidated require a null revokedAt",
      });
    }
  });

export type CommerceControlSessionStatusItem = z.infer<
  typeof CommerceControlSessionStatusItemSchema
>;

/** Canonical whole-second duration 1..900. No default is inserted. */
const DURATION_PATTERN = /^[1-9][0-9]{0,2}(?![\s\S])/u;

export const CommerceControlSessionDurationSecondsSchema = z
  .string()
  .regex(DURATION_PATTERN, {
    message: "Expected a canonical duration 1..900",
  })
  .refine((value) => DURATION_PATTERN.test(value) && BigInt(value) <= 900n, {
    message: "Expected a canonical duration 1..900",
  });

export type CommerceControlSessionDurationSeconds = z.infer<
  typeof CommerceControlSessionDurationSecondsSchema
>;

/** Canonical page limit 1..50 as an optional string. Two digits max. */
const LIST_LIMIT_PATTERN = /^(?:[1-9]|[1-4][0-9]|50)(?![\s\S])/u;

export const CommerceControlSessionListLimitSchema = z.string().regex(
  LIST_LIMIT_PATTERN,
  { message: "Expected a canonical limit 1..50" },
);

export type CommerceControlSessionListLimit = z.infer<
  typeof CommerceControlSessionListLimitSchema
>;

/**
 * Rejects an object that explicitly carries a key whose value is `undefined`,
 * so a present-but-undefined optional is not silently treated as absent.
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

/** Strict builder: unknown keys rejected, explicit undefined rejected. */
function strictRequestSchema<T extends z.ZodRawShape>(shape: T) {
  return z
    .unknown()
    .superRefine(rejectExplicitUndefinedKeys)
    .pipe(z.strictObject(shape));
}

/**
 * Human issue body. Duration is optional and absence means the server will
 * choose 300s later; parsing never inserts a default. No actor, organization,
 * role, token hash or proof travels in the body.
 */
export const CommerceControlSessionIssueBodySchema = strictRequestSchema({
  mutationId: CommerceTenantMutationIdSchema,
  subjectAgentId: CommerceAgentIdSchema,
  policyId: CommercePolicyIdSchema,
  durationSeconds: CommerceControlSessionDurationSecondsSchema.optional(),
});

export const CommerceControlSessionRevokeBodySchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
});

/** Agent exchange body: the raw handoff token appears here only. */
export const CommerceControlSessionExchangeBodySchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
  handoffToken: CommerceControlHandoffTokenSchema,
});

export type CommerceControlSessionIssueBody = z.infer<
  typeof CommerceControlSessionIssueBodySchema
>;
export type CommerceControlSessionRevokeBody = z.infer<
  typeof CommerceControlSessionRevokeBodySchema
>;
export type CommerceControlSessionExchangeBody = z.infer<
  typeof CommerceControlSessionExchangeBodySchema
>;

const RESOURCE_TYPE = "commerce_session" as const;

/**
 * Safe durable receipt. Exactly the three commerce-session operations, each
 * bound to `commerce_session` and an exact session UUIDv4. No raw token, key,
 * signature, payload or actor is representable.
 */
export const CommerceControlSessionReceiptSchema = z.discriminatedUnion(
  "operation",
  [
    z.strictObject({
      mutationId: CommerceTenantMutationIdSchema,
      operation: z.literal("control.commerce_session.issue"),
      resourceType: z.literal(RESOURCE_TYPE),
      resourceId: CommerceControlSessionIdSchema,
      committedAt: IsoTimestampSchema,
    }),
    z.strictObject({
      mutationId: CommerceTenantMutationIdSchema,
      operation: z.literal("control.commerce_session.exchange"),
      resourceType: z.literal(RESOURCE_TYPE),
      resourceId: CommerceControlSessionIdSchema,
      committedAt: IsoTimestampSchema,
    }),
    z.strictObject({
      mutationId: CommerceTenantMutationIdSchema,
      operation: z.literal("control.commerce_session.revoke"),
      resourceType: z.literal(RESOURCE_TYPE),
      resourceId: CommerceControlSessionIdSchema,
      committedAt: IsoTimestampSchema,
    }),
  ],
);

export type CommerceControlSessionReceipt = z.infer<
  typeof CommerceControlSessionReceiptSchema
>;

const NotReplayableDeliverySchema = z.strictObject({
  state: z.literal("not_replayable"),
});

const HandoffAvailableOnceDeliverySchema = z.strictObject({
  state: z.literal("available_once"),
  handoffToken: CommerceControlHandoffTokenSchema,
  handoffExpiresAt: IsoTimestampSchema,
});

const SessionAvailableOnceDeliverySchema = z.strictObject({
  state: z.literal("available_once"),
  sessionToken: CommerceControlSessionTokenSchema,
});

/**
 * Binds a result to its receipt, organization and metadata session id. A
 * malformed nested leaf already produced a failure, so guards keep
 * `safeParse` total.
 */
function bindResult(
  value: {
    organizationId: string;
    metadata: { organizationId: string; sessionId: string };
    receipt: { operation: string; resourceId: string };
  },
  operation: string,
  ctx: z.RefinementCtx,
): void {
  if (value.receipt.operation !== operation) {
    ctx.addIssue({
      code: "custom",
      path: ["receipt", "operation"],
      message: `receipt operation must be ${operation}`,
    });
  }
  if (value.receipt.resourceId !== value.metadata.sessionId) {
    ctx.addIssue({
      code: "custom",
      path: ["receipt", "resourceId"],
      message: "receipt resourceId must equal metadata.sessionId",
    });
  }
  if (value.metadata.organizationId !== value.organizationId) {
    ctx.addIssue({
      code: "custom",
      path: ["metadata", "organizationId"],
      message: "metadata organizationId must equal organizationId",
    });
  }
}

/**
 * Issue result. A fresh issue carries the handoff token exactly once; the
 * issuance metadata is pending (no exchanged/revoked) and `handoffExpiresAt`
 * sits strictly after `issuedAt`, at or before `expiresAt`, and at or before
 * `issuedAt + 300s` with exact fractional precision. A replayed issue carries
 * no second secret ever.
 */
export const CommerceControlSessionIssueResultSchema = z
  .discriminatedUnion("replayed", [
    z.strictObject({
      organizationId: CommerceOrganizationIdSchema,
      replayed: z.literal(false),
      metadata: CommerceControlSessionMetadataSchema,
      receipt: CommerceControlSessionReceiptSchema,
      delivery: HandoffAvailableOnceDeliverySchema,
    }),
    z.strictObject({
      organizationId: CommerceOrganizationIdSchema,
      replayed: z.literal(true),
      metadata: CommerceControlSessionMetadataSchema,
      receipt: CommerceControlSessionReceiptSchema,
      delivery: NotReplayableDeliverySchema,
    }),
  ])
  .superRefine((value, ctx) => {
    bindResult(value, "control.commerce_session.issue", ctx);
    const issuedAtValid = IsoTimestampSchema.safeParse(
      value.metadata.issuedAt,
    ).success;
    const expiresAtValid = IsoTimestampSchema.safeParse(
      value.metadata.expiresAt,
    ).success;
    if (value.replayed === false) {
      if (
        value.metadata.exchangedAt !== null ||
        value.metadata.revokedAt !== null
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["metadata"],
          message: "fresh issuance metadata must be pending",
        });
      }
      if (!issuedAtValid || !expiresAtValid) return;
      const handoffExpiresAt = value.delivery.handoffExpiresAt;
      if (!IsoTimestampSchema.safeParse(handoffExpiresAt).success) return;
      if (compareIsoTimestamps(handoffExpiresAt, value.metadata.issuedAt) <= 0) {
        ctx.addIssue({
          code: "custom",
          path: ["delivery", "handoffExpiresAt"],
          message: "handoffExpiresAt must strictly follow issuedAt",
        });
      }
      if (compareIsoTimestamps(handoffExpiresAt, value.metadata.expiresAt) > 0) {
        ctx.addIssue({
          code: "custom",
          path: ["delivery", "handoffExpiresAt"],
          message: "handoffExpiresAt must be at or before expiresAt",
        });
      }
      const maxHandoff = shiftIsoSeconds(
        value.metadata.issuedAt,
        MAX_HANDOFF_LIFETIME_SECONDS,
      );
      if (
        maxHandoff !== null &&
        compareIsoTimestamps(handoffExpiresAt, maxHandoff) > 0
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["delivery", "handoffExpiresAt"],
          message: "handoffExpiresAt must be at most 300 seconds after issuedAt",
        });
      }
    }
  });

export type CommerceControlSessionIssueResult = z.infer<
  typeof CommerceControlSessionIssueResultSchema
>;

/**
 * Exchange result, same shape as the issue result. A fresh exchange delivers
 * the commerce session token exactly once and requires exchangedAt non-null
 * with revokedAt null; a replay carries no secret.
 */
export const CommerceControlSessionExchangeResultSchema = z
  .discriminatedUnion("replayed", [
    z.strictObject({
      organizationId: CommerceOrganizationIdSchema,
      replayed: z.literal(false),
      metadata: CommerceControlSessionMetadataSchema,
      receipt: CommerceControlSessionReceiptSchema,
      delivery: SessionAvailableOnceDeliverySchema,
    }),
    z.strictObject({
      organizationId: CommerceOrganizationIdSchema,
      replayed: z.literal(true),
      metadata: CommerceControlSessionMetadataSchema,
      receipt: CommerceControlSessionReceiptSchema,
      delivery: NotReplayableDeliverySchema,
    }),
  ])
  .superRefine((value, ctx) => {
    bindResult(value, "control.commerce_session.exchange", ctx);
    if (
      value.replayed === false &&
      (value.metadata.exchangedAt === null || value.metadata.revokedAt !== null)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["metadata"],
        message:
          "fresh exchange metadata requires a non-null exchangedAt and null revokedAt",
      });
    }
  });

export type CommerceControlSessionExchangeResult = z.infer<
  typeof CommerceControlSessionExchangeResultSchema
>;

/** Revoke result: operation revoke and a non-null revokedAt. No delivery. */
export const CommerceControlSessionRevokeResultSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    replayed: z.boolean(),
    metadata: CommerceControlSessionMetadataSchema,
    receipt: CommerceControlSessionReceiptSchema,
  })
  .superRefine((value, ctx) => {
    bindResult(value, "control.commerce_session.revoke", ctx);
    if (value.metadata.revokedAt === null) {
      ctx.addIssue({
        code: "custom",
        path: ["metadata", "revokedAt"],
        message: "revoke result requires a non-null revokedAt",
      });
    }
  });

export type CommerceControlSessionRevokeResult = z.infer<
  typeof CommerceControlSessionRevokeResultSchema
>;

/**
 * Status response: one null or DB-derived status item. When the item is
 * present its metadata organizationId must equal the outer organizationId,
 * the same strict equality binding used by the list page.
 */
export const CommerceControlSessionStatusSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    item: CommerceControlSessionStatusItemSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    if (
      value.item !== null &&
      value.item.metadata.organizationId !== value.organizationId
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "metadata", "organizationId"],
        message: "item organizationId must match the outer organizationId",
      });
    }
  });

export type CommerceControlSessionStatus = z.infer<
  typeof CommerceControlSessionStatusSchema
>;

/**
 * Closed mutation status. `committed` carries the safe receipt whose
 * mutationId must equal the outer mutationId; `not_found` carries no receipt.
 */
export const CommerceControlSessionMutationStatusSchema = z
  .discriminatedUnion("status", [
    z.strictObject({
      organizationId: CommerceOrganizationIdSchema,
      mutationId: CommerceTenantMutationIdSchema,
      status: z.literal("not_found"),
    }),
    z.strictObject({
      organizationId: CommerceOrganizationIdSchema,
      mutationId: CommerceTenantMutationIdSchema,
      status: z.literal("committed"),
      receipt: CommerceControlSessionReceiptSchema,
    }),
  ])
  .superRefine((value, ctx) => {
    if (
      value.status === "committed" &&
      value.receipt.mutationId !== value.mutationId
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["receipt", "mutationId"],
        message: "receipt mutationId must equal the outer mutationId",
      });
    }
  });

export type CommerceControlSessionMutationStatus = z.infer<
  typeof CommerceControlSessionMutationStatusSchema
>;

function isStrictlyAscending(values: readonly string[]): boolean {
  for (let index = 1; index < values.length; index += 1) {
    if (!(values[index - 1]! < values[index]!)) return false;
  }
  return true;
}

/**
 * Org-bound page of status items. At most 50, same organization, strictly
 * ascending unique session ids, and a non-null cursor must be exactly the last
 * item id. An empty page requires a null cursor.
 */
export const CommerceControlSessionListSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    items: z.array(CommerceControlSessionStatusItemSchema).max(50),
    nextCursor: CommerceControlSessionIdSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    const sessionIds: string[] = [];
    value.items.forEach((item, index) => {
      sessionIds.push(item.metadata.sessionId);
      if (item.metadata.organizationId !== value.organizationId) {
        ctx.addIssue({
          code: "custom",
          path: ["items", index, "metadata", "organizationId"],
          message: "item organizationId must match the page organizationId",
        });
      }
    });
    if (!isStrictlyAscending(sessionIds)) {
      ctx.addIssue({
        code: "custom",
        path: ["items"],
        message: "item sessionIds must be strictly ascending and unique",
      });
    }
    if (
      value.nextCursor !== null &&
      (sessionIds.length === 0 ||
        value.nextCursor !== sessionIds[sessionIds.length - 1])
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["nextCursor"],
        message:
          "nextCursor must be null or exactly the last item sessionId, and non-null only for a non-empty page",
      });
    }
  });

export type CommerceControlSessionList = z.infer<
  typeof CommerceControlSessionListSchema
>;

/** Pure read requests; all strict, no URL parsing. */
export const CommerceControlSessionRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  sessionId: CommerceControlSessionIdSchema,
});

export const CommerceControlSessionMutationRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  mutationId: CommerceTenantMutationIdSchema,
});

export const CommerceControlSessionListRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  afterSessionId: CommerceControlSessionIdSchema.optional(),
  limit: CommerceControlSessionListLimitSchema.optional(),
});

export type CommerceControlSessionRequest = z.infer<
  typeof CommerceControlSessionRequestSchema
>;
export type CommerceControlSessionMutationRequest = z.infer<
  typeof CommerceControlSessionMutationRequestSchema
>;
export type CommerceControlSessionListRequest = z.infer<
  typeof CommerceControlSessionListRequestSchema
>;

/**
 * Typed strict v2 success envelopes over each data variant. These reuse the
 * accepted factory and add no envelope version or error behavior.
 */
export const CommerceControlSessionIssueResultResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceControlSessionIssueResultSchema);
export const CommerceControlSessionExchangeResultResponseSchema =
  createCommerceSuccessEnvelopeSchema(
    CommerceControlSessionExchangeResultSchema,
  );
export const CommerceControlSessionRevokeResultResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceControlSessionRevokeResultSchema);
export const CommerceControlSessionStatusResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceControlSessionStatusSchema);
export const CommerceControlSessionMutationStatusResponseSchema =
  createCommerceSuccessEnvelopeSchema(
    CommerceControlSessionMutationStatusSchema,
  );
export const CommerceControlSessionListResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceControlSessionListSchema);

export type CommerceControlSessionIssueResultResponse = z.infer<
  typeof CommerceControlSessionIssueResultResponseSchema
>;
export type CommerceControlSessionExchangeResultResponse = z.infer<
  typeof CommerceControlSessionExchangeResultResponseSchema
>;
export type CommerceControlSessionRevokeResultResponse = z.infer<
  typeof CommerceControlSessionRevokeResultResponseSchema
>;
export type CommerceControlSessionStatusResponse = z.infer<
  typeof CommerceControlSessionStatusResponseSchema
>;
export type CommerceControlSessionMutationStatusResponse = z.infer<
  typeof CommerceControlSessionMutationStatusResponseSchema
>;
export type CommerceControlSessionListResponse = z.infer<
  typeof CommerceControlSessionListResponseSchema
>;
