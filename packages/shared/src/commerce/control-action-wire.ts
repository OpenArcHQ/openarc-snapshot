import { z } from "zod";

import { IsoTimestampSchema } from "../primitives.js";
import { createCommerceSuccessEnvelopeSchema } from "./api.js";
import {
  CommerceApprovalIdSchema,
  CommerceApprovalMetadataSchema,
  CommerceActionMetadataSchema,
  CommerceRequirementIdSchema,
} from "./control-action.js";
import { CommerceActionIdSchema } from "./control-budget.js";
import { CommercePolicyIdSchema } from "./control-policy.js";
import {
  CommerceAgentIdSchema,
  CommerceOrganizationIdSchema,
} from "./identity.js";
import { CommerceTenantMutationIdSchema } from "./tenant-writes.js";

/**
 * Pure strict action/approval management wire contracts.
 *
 * Bodies, read requests, safe receipts and response data shapes only. There is
 * no transport, URL/route parsing, server clock, storage, authorization,
 * reservation, approval decision, signature or capability activation here.
 * Operation names and action/approval identity are endpoint/path derived; this
 * module never accepts them as body overrides. Parsing a record never proves a
 * principal, an approval decision or spend authority: the future server must
 * rebind the current principal/session and reject cross-tenant receipts. All
 * quantities on the wire remain canonical strings.
 */

const ORGANIZATION_PROTECTED = "organization_protected" as const;

function protectedFields<K extends string>(
  keys: readonly K[],
): Readonly<Record<K, typeof ORGANIZATION_PROTECTED>> {
  const map = {} as Record<K, typeof ORGANIZATION_PROTECTED>;
  for (const key of keys) {
    map[key] = ORGANIZATION_PROTECTED;
  }
  return Object.freeze(map);
}

/**
 * Rejects an object that explicitly carries a key whose value is `undefined`
 * so a present-but-undefined optional is not silently treated as absent. Runs
 * on raw input before the strict object parses it, mirroring the accepted
 * policy/session wire convention.
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

/**
 * Bounded 1..50 wire limit as an OPTIONAL canonical decimal string with
 * absolute-end matching. No number, default, coercion or leading zero.
 */
const CommerceActionListLimitSchema = z.string().regex(
  /^(?:[1-9]|[1-4][0-9]|50)(?![\s\S])/u,
  { message: "Expected a canonical limit 1..50" },
);

export type CommerceActionListLimit = z.infer<
  typeof CommerceActionListLimitSchema
>;

/** Write/decision bodies. Operation is never carried in the body. */
export const CommerceActionAuthorizeBodySchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
  actionId: CommerceActionIdSchema,
  requirementId: CommerceRequirementIdSchema,
});

export const CommerceActionDecisionBodySchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
});

export const CommerceActionCancelBodySchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
});

export type CommerceActionAuthorizeBody = z.infer<
  typeof CommerceActionAuthorizeBodySchema
>;
export type CommerceActionDecisionBody = z.infer<
  typeof CommerceActionDecisionBodySchema
>;
export type CommerceActionCancelBody = z.infer<
  typeof CommerceActionCancelBodySchema
>;

/** Pure read requests; all strict, no URL parsing. */
export const CommerceActionDetailRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  actionId: CommerceActionIdSchema,
});

export const CommerceActionAgentDetailRequestSchema = strictRequestSchema({
  actionId: CommerceActionIdSchema,
});

export const CommerceApprovalDetailRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  approvalId: CommerceApprovalIdSchema,
});

export const CommerceActionListRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  afterActionId: CommerceActionIdSchema.optional(),
  limit: CommerceActionListLimitSchema.optional(),
});

export const CommerceApprovalListRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  afterApprovalId: CommerceApprovalIdSchema.optional(),
  limit: CommerceActionListLimitSchema.optional(),
});

export const CommerceExposureRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  subjectAgentId: CommerceAgentIdSchema,
  policyId: CommercePolicyIdSchema,
});

/**
 * Human/agent mutation requests. The organization-scoped variant carries
 * organizationId; the agent variant derives org/session from the token and
 * carries only the mutation correlation id.
 */
export const CommerceActionHumanMutationRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  mutationId: CommerceTenantMutationIdSchema,
});

export const CommerceActionAgentMutationRequestSchema = strictRequestSchema({
  mutationId: CommerceTenantMutationIdSchema,
});

export type CommerceActionDetailRequest = z.infer<
  typeof CommerceActionDetailRequestSchema
>;
export type CommerceActionAgentDetailRequest = z.infer<
  typeof CommerceActionAgentDetailRequestSchema
>;
export type CommerceApprovalDetailRequest = z.infer<
  typeof CommerceApprovalDetailRequestSchema
>;
export type CommerceActionListRequest = z.infer<
  typeof CommerceActionListRequestSchema
>;
export type CommerceApprovalListRequest = z.infer<
  typeof CommerceApprovalListRequestSchema
>;
export type CommerceExposureRequest = z.infer<
  typeof CommerceExposureRequestSchema
>;
export type CommerceActionHumanMutationRequest = z.infer<
  typeof CommerceActionHumanMutationRequestSchema
>;
export type CommerceActionAgentMutationRequest = z.infer<
  typeof CommerceActionAgentMutationRequestSchema
>;

/**
 * Operation-discriminated safe receipt. Each variant fixes the operation and
 * the literal `commerce_action` resource type with a canonical action id. No
 * actor, hash, session context, idempotency material, token or raw payload is
 * representable.
 */
export const CommerceActionMutationReceiptSchema = z.discriminatedUnion(
  "operation",
  [
    z.strictObject({
      mutationId: CommerceTenantMutationIdSchema,
      operation: z.literal("control.commerce_action.authorize"),
      resourceType: z.literal("commerce_action"),
      resourceId: CommerceActionIdSchema,
      committedAt: IsoTimestampSchema,
    }),
    z.strictObject({
      mutationId: CommerceTenantMutationIdSchema,
      operation: z.literal("control.commerce_action.approve"),
      resourceType: z.literal("commerce_action"),
      resourceId: CommerceActionIdSchema,
      committedAt: IsoTimestampSchema,
    }),
    z.strictObject({
      mutationId: CommerceTenantMutationIdSchema,
      operation: z.literal("control.commerce_action.reject"),
      resourceType: z.literal("commerce_action"),
      resourceId: CommerceActionIdSchema,
      committedAt: IsoTimestampSchema,
    }),
    z.strictObject({
      mutationId: CommerceTenantMutationIdSchema,
      operation: z.literal("control.commerce_action.cancel"),
      resourceType: z.literal("commerce_action"),
      resourceId: CommerceActionIdSchema,
      committedAt: IsoTimestampSchema,
    }),
  ],
);

export type CommerceActionMutationReceipt = z.infer<
  typeof CommerceActionMutationReceiptSchema
>;

/**
 * Mutation data. `metadata` is the accepted current action metadata; the
 * receipt is historical. Only the receipt resourceId == metadata.actionId
 * binding is enforced. The receipt timestamp is a historical commit and the
 * metadata may be current, so no timestamp/status match is required on replay.
 * No token delivery is representable.
 */
export const CommerceActionMutationDataSchema = z
  .strictObject({
    replayed: z.boolean(),
    metadata: CommerceActionMetadataSchema,
    receipt: CommerceActionMutationReceiptSchema,
  })
  .superRefine((value, ctx) => {
    if (value.receipt.resourceId !== value.metadata.actionId) {
      ctx.addIssue({
        code: "custom",
        path: ["receipt", "resourceId"],
        message: "receipt resourceId must equal metadata.actionId",
      });
    }
  });

export type CommerceActionMutationData = z.infer<
  typeof CommerceActionMutationDataSchema
>;

/**
 * Closed status discriminated union, exactly `{status:'committed',receipt}`
 * or `{status:'not_found'}`. `not_found` carries no field besides `status`.
 * The request already carries the mutation id; the future service binds the
 * returned receipt to it and the current auth context. This pure union does
 * not prove identity.
 */
export const CommerceActionMutationStatusSchema = z.discriminatedUnion(
  "status",
  [
    z.strictObject({
      status: z.literal("not_found"),
    }),
    z.strictObject({
      status: z.literal("committed"),
      receipt: CommerceActionMutationReceiptSchema,
    }),
  ],
);

export type CommerceActionMutationStatus = z.infer<
  typeof CommerceActionMutationStatusSchema
>;

/**
 * Action detail: wrapper identity plus nullable accepted action metadata.
 * When non-null the item actionId and exposureKey.organizationId must match
 * the wrapper, enforcing cross-ID and cross-tenant binding.
 */
export const CommerceActionDetailSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    actionId: CommerceActionIdSchema,
    item: CommerceActionMetadataSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    if (value.item === null) return;
    if (value.item.actionId !== value.actionId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "actionId"],
        message: "item actionId must match actionId",
      });
    }
    if (value.item.exposureKey.organizationId !== value.organizationId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "exposureKey", "organizationId"],
        message: "item exposureKey.organizationId must match organizationId",
      });
    }
  });

export type CommerceActionDetail = z.infer<typeof CommerceActionDetailSchema>;

/**
 * Approval detail: wrapper identity plus nullable accepted approval metadata.
 * When non-null the item organizationId and approvalId must match the wrapper.
 */
export const CommerceApprovalDetailSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    approvalId: CommerceApprovalIdSchema,
    item: CommerceApprovalMetadataSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    if (value.item === null) return;
    if (value.item.organizationId !== value.organizationId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "organizationId"],
        message: "item organizationId must match organizationId",
      });
    }
    if (value.item.approvalId !== value.approvalId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "approvalId"],
        message: "item approvalId must match approvalId",
      });
    }
  });

export type CommerceApprovalDetail = z.infer<
  typeof CommerceApprovalDetailSchema
>;

function isStrictlyAscending(values: readonly string[]): boolean {
  for (let index = 1; index < values.length; index += 1) {
    if (!(values[index - 1]! < values[index]!)) return false;
  }
  return true;
}

/**
 * Org-bound action page. At most 50 items sharing the wrapper organization,
 * unique strictly lexically ascending action ids, and a non-null cursor that
 * equals the last id of a non-empty page. An empty page requires a null cursor.
 */
export const CommerceActionPageSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    items: z.array(CommerceActionMetadataSchema).max(50),
    nextCursor: CommerceActionIdSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    const actionIds: string[] = [];
    value.items.forEach((item, index) => {
      actionIds.push(item.actionId);
      if (item.exposureKey.organizationId !== value.organizationId) {
        ctx.addIssue({
          code: "custom",
          path: ["items", index, "exposureKey", "organizationId"],
          message: "item organizationId must match the page organizationId",
        });
      }
    });
    if (!isStrictlyAscending(actionIds)) {
      ctx.addIssue({
        code: "custom",
        path: ["items"],
        message: "item actionIds must be strictly ascending and unique",
      });
    }
    if (
      value.nextCursor !== null &&
      (actionIds.length === 0 ||
        value.nextCursor !== actionIds[actionIds.length - 1])
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["nextCursor"],
        message:
          "nextCursor must be null or exactly the last item actionId, and non-null only for a non-empty page",
      });
    }
  });

export type CommerceActionPage = z.infer<typeof CommerceActionPageSchema>;

/**
 * Org-bound approval page. At most 50 items sharing the wrapper organization,
 * unique strictly lexically ascending approval ids, and a non-null cursor that
 * equals the last id of a non-empty page. An empty page requires a null cursor.
 */
export const CommerceApprovalPageSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    items: z.array(CommerceApprovalMetadataSchema).max(50),
    nextCursor: CommerceApprovalIdSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    const approvalIds: string[] = [];
    value.items.forEach((item, index) => {
      approvalIds.push(item.approvalId);
      if (item.organizationId !== value.organizationId) {
        ctx.addIssue({
          code: "custom",
          path: ["items", index, "organizationId"],
          message: "item organizationId must match the page organizationId",
        });
      }
    });
    if (!isStrictlyAscending(approvalIds)) {
      ctx.addIssue({
        code: "custom",
        path: ["items"],
        message: "item approvalIds must be strictly ascending and unique",
      });
    }
    if (
      value.nextCursor !== null &&
      (approvalIds.length === 0 ||
        value.nextCursor !== approvalIds[approvalIds.length - 1])
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["nextCursor"],
        message:
          "nextCursor must be null or exactly the last item approvalId, and non-null only for a non-empty page",
      });
    }
  });

export type CommerceApprovalPage = z.infer<typeof CommerceApprovalPageSchema>;

// ── Exposure view ───────────────────────────────────────────────────────────

// Canonical nonnegative decimal of at most 128 digits, absolute end.
const EXPOSURE_AMOUNT_PATTERN = /^(0|[1-9][0-9]{0,127})(?![\s\S])/u;

const ExposureAmountSchema = z
  .string()
  .regex(EXPOSURE_AMOUNT_PATTERN, {
    message: "Expected a canonical nonnegative decimal of at most 128 digits",
  });

// Canonical revision 1..999999999, absolute end.
const REVISION_PATTERN = /^[1-9][0-9]{0,8}(?![\s\S])/u;

const ExposurePolicyRevisionSchema = z
  .string()
  .regex(REVISION_PATTERN, {
    message: "Expected a canonical revision 1..999999999",
  })
  .refine((value) => REVISION_PATTERN.test(value) && BigInt(value) <= 999999999n, {
    message: "Expected a canonical revision 1..999999999",
  });

// Accepted policy rolling-window bound is 1..2592000 (30 days), matching the
// frozen control-policy/control-budget window grammar. The task contract line
// mentioned 1..31536000 but instructed to use the actual accepted bound; the
// actual bound is 2592000 and is recorded in the handoff.
const WINDOW_PATTERN = /^[1-9][0-9]{0,6}(?![\s\S])/u;

const ExposureWindowSecondsSchema = z
  .string()
  .regex(WINDOW_PATTERN, {
    message: "Expected canonical window seconds 1..2592000",
  })
  .refine((value) => WINDOW_PATTERN.test(value) && BigInt(value) <= 2592000n, {
    message: "Expected canonical window seconds 1..2592000",
  });

function canonicalAmountToBigInt(value: string): bigint | null {
  if (!EXPOSURE_AMOUNT_PATTERN.test(value)) return null;
  return BigInt(value);
}

/**
 * EXACT current DB10 exposure view shape (all fields required). This is a
 * declaration of server state only: it does not infer a cap, a new permission
 * or current liveness, and its values are DB `asOf`, not wallet balances.
 *
 * Arithmetic is exact BigInt: committed + unresolved must equal total.
 * A positive deficit implies available is exactly "0"; a null available means
 * no rolling cap, so deficit must be "0". Malformed leaves never throw: every
 * leaf is re-validated before any BigInt conversion inside the refinement.
 */
export const CommerceExposureViewSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    subjectAgentId: CommerceAgentIdSchema,
    policyId: CommercePolicyIdSchema,
    policyRevision: ExposurePolicyRevisionSchema,
    networkId: z.literal("eip155:5042002"),
    asset: z.literal("USDC"),
    representation: z.literal("erc20"),
    decimals: z.literal(6),
    windowSeconds: ExposureWindowSecondsSchema.nullable(),
    committedAtomic: ExposureAmountSchema,
    unresolvedAtomic: ExposureAmountSchema,
    totalExposureAtomic: ExposureAmountSchema,
    availableAtomic: ExposureAmountSchema.nullable(),
    deficitAtomic: ExposureAmountSchema,
    asOf: IsoTimestampSchema,
  })
  .superRefine((value, ctx) => {
    const committed = canonicalAmountToBigInt(value.committedAtomic);
    const unresolved = canonicalAmountToBigInt(value.unresolvedAtomic);
    const total = canonicalAmountToBigInt(value.totalExposureAtomic);
    const available =
      value.availableAtomic === null
        ? null
        : canonicalAmountToBigInt(value.availableAtomic);
    const deficit = canonicalAmountToBigInt(value.deficitAtomic);
    if (
      committed === null ||
      unresolved === null ||
      total === null ||
      deficit === null ||
      (value.availableAtomic !== null && available === null)
    ) {
      return;
    }
    if (committed + unresolved !== total) {
      ctx.addIssue({
        code: "custom",
        path: ["totalExposureAtomic"],
        message: "totalExposureAtomic must equal committedAtomic + unresolvedAtomic",
      });
    }
    if (deficit > 0n && available !== null && available !== 0n) {
      ctx.addIssue({
        code: "custom",
        path: ["availableAtomic"],
        message: "a positive deficit requires availableAtomic to be exactly 0",
      });
    }
    if (available === null && deficit !== 0n) {
      ctx.addIssue({
        code: "custom",
        path: ["deficitAtomic"],
        message: "a null availableAtomic requires deficitAtomic to be 0",
      });
    }
  });

export type CommerceExposureView = z.infer<typeof CommerceExposureViewSchema>;

/**
 * Exposure response data: wrapper identity plus nullable exact view. A non-null
 * item must be bound to all three wrapper ids (organizationId, subjectAgentId,
 * policyId).
 */
export const CommerceExposureDataSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    subjectAgentId: CommerceAgentIdSchema,
    policyId: CommercePolicyIdSchema,
    item: CommerceExposureViewSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    if (value.item === null) return;
    if (value.item.organizationId !== value.organizationId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "organizationId"],
        message: "item organizationId must match the wrapper organizationId",
      });
    }
    if (value.item.subjectAgentId !== value.subjectAgentId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "subjectAgentId"],
        message: "item subjectAgentId must match the wrapper subjectAgentId",
      });
    }
    if (value.item.policyId !== value.policyId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "policyId"],
        message: "item policyId must match the wrapper policyId",
      });
    }
  });

export type CommerceExposureData = z.infer<typeof CommerceExposureDataSchema>;

/**
 * Typed strict v2 success envelopes over the seven response data shapes. These
 * reuse the accepted factory and add no envelope version or error behavior.
 */
export const CommerceActionMutationDataResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceActionMutationDataSchema);
export const CommerceActionMutationStatusResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceActionMutationStatusSchema);
export const CommerceActionDetailResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceActionDetailSchema);
export const CommerceApprovalDetailResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceApprovalDetailSchema);
export const CommerceActionPageResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceActionPageSchema);
export const CommerceApprovalPageResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceApprovalPageSchema);
export const CommerceExposureDataResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommerceExposureDataSchema);

export type CommerceActionMutationDataResponse = z.infer<
  typeof CommerceActionMutationDataResponseSchema
>;
export type CommerceActionMutationStatusResponse = z.infer<
  typeof CommerceActionMutationStatusResponseSchema
>;
export type CommerceActionDetailResponse = z.infer<
  typeof CommerceActionDetailResponseSchema
>;
export type CommerceApprovalDetailResponse = z.infer<
  typeof CommerceApprovalDetailResponseSchema
>;
export type CommerceActionPageResponse = z.infer<
  typeof CommerceActionPageResponseSchema
>;
export type CommerceApprovalPageResponse = z.infer<
  typeof CommerceApprovalPageResponseSchema
>;
export type CommerceExposureDataResponse = z.infer<
  typeof CommerceExposureDataResponseSchema
>;

/**
 * Conservative field-class registry for the new wire fields. All of these
 * fields are `organization_protected`; no public/provider projection is
 * implied.
 */
export const COMMERCE_ACTION_WIRE_FIELD_CLASSES = Object.freeze({
  authorizeBody: protectedFields([
    "mutationId",
    "actionId",
    "requirementId",
  ] as const),
  decisionBody: protectedFields(["mutationId"] as const),
  cancelBody: protectedFields(["mutationId"] as const),
  actionDetailRequest: protectedFields([
    "organizationId",
    "actionId",
  ] as const),
  agentDetailRequest: protectedFields(["actionId"] as const),
  approvalDetailRequest: protectedFields([
    "organizationId",
    "approvalId",
  ] as const),
  actionListRequest: protectedFields([
    "organizationId",
    "afterActionId",
    "limit",
  ] as const),
  approvalListRequest: protectedFields([
    "organizationId",
    "afterApprovalId",
    "limit",
  ] as const),
  exposureRequest: protectedFields([
    "organizationId",
    "subjectAgentId",
    "policyId",
  ] as const),
  humanMutationRequest: protectedFields([
    "organizationId",
    "mutationId",
  ] as const),
  agentMutationRequest: protectedFields(["mutationId"] as const),
  receipt: protectedFields([
    "mutationId",
    "operation",
    "resourceType",
    "resourceId",
    "committedAt",
  ] as const),
  mutationData: protectedFields([
    "replayed",
    "metadata",
    "receipt",
  ] as const),
  mutationStatus: protectedFields(["status", "receipt"] as const),
  actionDetail: protectedFields([
    "organizationId",
    "actionId",
    "item",
  ] as const),
  approvalDetail: protectedFields([
    "organizationId",
    "approvalId",
    "item",
  ] as const),
  actionPage: protectedFields([
    "organizationId",
    "items",
    "nextCursor",
  ] as const),
  approvalPage: protectedFields([
    "organizationId",
    "items",
    "nextCursor",
  ] as const),
  exposureView: protectedFields([
    "organizationId",
    "subjectAgentId",
    "policyId",
    "policyRevision",
    "networkId",
    "asset",
    "representation",
    "decimals",
    "windowSeconds",
    "committedAtomic",
    "unresolvedAtomic",
    "totalExposureAtomic",
    "availableAtomic",
    "deficitAtomic",
    "asOf",
  ] as const),
  exposureData: protectedFields([
    "organizationId",
    "subjectAgentId",
    "policyId",
    "item",
  ] as const),
});
