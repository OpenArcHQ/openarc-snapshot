import { z } from "zod";

import {
  IsoTimestampSchema,
  Sha256DigestSchema,
  compareIsoTimestamps,
} from "../primitives.js";
import { createCommerceSuccessEnvelopeSchema } from "./api.js";
import {
  CommercePolicyContentSchema,
  CommercePolicyIdSchema,
  CommercePolicyRevisionNumberSchema,
  CommercePolicyRevisionSchema,
  CommercePolicyRootSchema,
} from "./control-policy.js";
import {
  CommerceAgentIdSchema,
  CommerceOrganizationIdSchema,
} from "./identity.js";
import { CommerceTenantMutationIdSchema } from "./tenant-writes.js";

/**
 * Pure strict policy management wire contracts.
 *
 * Bodies, read requests, safe receipts and response data shapes only. There is
 * no transport, URL parsing, route string, server clock, storage,
 * authorization, reservation, approval decision or signature verification
 * here. Parsing a record never proves a digest was verified, that a caller is a
 * principal, or that an operation is permitted: the server must rebind the
 * current principal and reject cross-tenant receipts. All quantities on the
 * wire remain canonical strings.
 */

const UUID_PATTERN =
  "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

/**
 * Bounded 1..50 wire limit as an OPTIONAL canonical decimal string with
 * absolute-end matching. No number, default, coercion or leading zero.
 */
const PolicyListLimitSchema = z.string().regex(
  /^(?:[1-9]|[1-4][0-9]|50)(?![\s\S])/u,
  { message: "Expected a canonical limit 1..50" },
);

// Append room: the append request may only reference revisions that still have
// a successor, so the top accepted revision is one below the global maximum.
const APPEND_REVISION_PATTERN = /^[1-9][0-9]{0,8}(?![\s\S])/u;

const PolicyAppendRevisionSchema = z
  .string()
  .regex(APPEND_REVISION_PATTERN, {
    message: "Expected a canonical revision 1..999999998",
  })
  .refine(
    (value) =>
      APPEND_REVISION_PATTERN.test(value) && BigInt(value) <= 999999998n,
    { message: "Expected a canonical revision 1..999999998" },
  );

// `policyId@revision` with revision 2..999999999. The fixed prefix plus a
// bounded canonical digit run keeps the expression finite and absolute-end
// pinned; the separate `>= 2n` refinement lowers the accepted revision range
// without the digit-class trick that wrongly rejected 10, 11, 100, ...
const POLICY_REVISION_RESOURCE_ID_PATTERN = new RegExp(
  `^openarc:policy:${UUID_PATTERN}@[1-9][0-9]{0,8}(?![\\s\\S])`,
);

const CommercePolicyRevisionResourceIdSchema = z
  .string()
  .regex(POLICY_REVISION_RESOURCE_ID_PATTERN, {
    message: "Expected a canonical policyId@revision resource id",
  })
  .refine(
    (value) =>
      POLICY_REVISION_RESOURCE_ID_PATTERN.test(value) &&
      BigInt(value.slice(value.lastIndexOf("@") + 1)) >= 2n,
    { message: "Expected a canonical policyId@revision resource id" },
  );

/**
 * Rejects an object that explicitly carries a key whose value is `undefined`
 * so a present-but-undefined optional is not silently treated as absent. Runs
 * on raw input before the strict object parses it, mirroring the accepted
 * tenant/market wire convention.
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

/** Write bodies. Operation is never carried in the transition body. */
export const CommercePolicyCreateBodySchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
  content: CommercePolicyContentSchema,
});

export const CommercePolicyAppendBodySchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
  expectedRevision: PolicyAppendRevisionSchema,
  expectedUpdatedAt: IsoTimestampSchema,
  content: CommercePolicyContentSchema,
});

export const CommercePolicyTransitionBodySchema = z.strictObject({
  mutationId: CommerceTenantMutationIdSchema,
  // Only APPEND reserves room for a successor revision. A transition must
  // accept the full existing revision range so a maximum-revision policy can
  // still be paused/resumed/revoked.
  expectedRevision: CommercePolicyRevisionNumberSchema,
  expectedUpdatedAt: IsoTimestampSchema,
});

export type CommercePolicyCreateBody = z.infer<
  typeof CommercePolicyCreateBodySchema
>;
export type CommercePolicyAppendBody = z.infer<
  typeof CommercePolicyAppendBodySchema
>;
export type CommercePolicyTransitionBody = z.infer<
  typeof CommercePolicyTransitionBodySchema
>;

/**
 * History summary. A DECLARED `digest` leaf only; no full policy, allowlist,
 * approval, cap, actor, key or raw payload is representable. `expiresAt` is
 * null or strictly after `createdAt`.
 */
export const CommercePolicyRevisionSummarySchema = z
  .strictObject({
    policyId: CommercePolicyIdSchema,
    organizationId: CommerceOrganizationIdSchema,
    subjectAgentId: CommerceAgentIdSchema,
    revision: CommercePolicyRevisionNumberSchema,
    digest: Sha256DigestSchema,
    createdAt: IsoTimestampSchema,
    expiresAt: IsoTimestampSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    if (value.expiresAt === null) return;
    // A malformed child leaf can still reach this refinement, so re-validate
    // both timestamp strings before the comparison to keep safeParse total.
    if (
      !IsoTimestampSchema.safeParse(value.createdAt).success ||
      !IsoTimestampSchema.safeParse(value.expiresAt).success
    ) {
      return;
    }
    if (compareIsoTimestamps(value.expiresAt, value.createdAt) <= 0) {
      ctx.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "expiresAt must strictly follow createdAt",
      });
    }
  });

export type CommercePolicyRevisionSummary = z.infer<
  typeof CommercePolicyRevisionSummarySchema
>;

/** Pure read requests; all strict, no URL parsing. */
export const CommercePolicyListRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  afterPolicyId: CommercePolicyIdSchema.optional(),
  limit: PolicyListLimitSchema.optional(),
});

export const CommercePolicyRootRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  policyId: CommercePolicyIdSchema,
});

export const CommercePolicyHistoryRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  policyId: CommercePolicyIdSchema,
  afterRevision: CommercePolicyRevisionNumberSchema.optional(),
  limit: PolicyListLimitSchema.optional(),
});

export const CommercePolicyRevisionRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  policyId: CommercePolicyIdSchema,
  revision: CommercePolicyRevisionNumberSchema,
});

export const CommercePolicyMutationRequestSchema = strictRequestSchema({
  organizationId: CommerceOrganizationIdSchema,
  mutationId: CommerceTenantMutationIdSchema,
});

export type CommercePolicyListRequest = z.infer<
  typeof CommercePolicyListRequestSchema
>;
export type CommercePolicyRootRequest = z.infer<
  typeof CommercePolicyRootRequestSchema
>;
export type CommercePolicyHistoryRequest = z.infer<
  typeof CommercePolicyHistoryRequestSchema
>;
export type CommercePolicyRevisionRequest = z.infer<
  typeof CommercePolicyRevisionRequestSchema
>;
export type CommercePolicyMutationRequest = z.infer<
  typeof CommercePolicyMutationRequestSchema
>;

/**
 * Operation-discriminated safe receipt. Each variant fixes the exact
 * operation/resourceType pair and the matching resourceId grammar, so a
 * mismatched tuple is rejected even when each leaf parses alone. No payload,
 * key, session, actor, role or raw response is representable.
 */
export const CommercePolicyMutationReceiptSchema = z.discriminatedUnion(
  "operation",
  [
    z.strictObject({
      mutationId: CommerceTenantMutationIdSchema,
      operation: z.literal("control.policy.create"),
      resourceType: z.literal("budget_policy"),
      resourceId: CommercePolicyIdSchema,
      committedAt: IsoTimestampSchema,
    }),
    z.strictObject({
      mutationId: CommerceTenantMutationIdSchema,
      operation: z.literal("control.policy.revision.create"),
      resourceType: z.literal("budget_policy_revision"),
      resourceId: CommercePolicyRevisionResourceIdSchema,
      committedAt: IsoTimestampSchema,
    }),
    z.strictObject({
      mutationId: CommerceTenantMutationIdSchema,
      operation: z.literal("control.policy.pause"),
      resourceType: z.literal("budget_policy"),
      resourceId: CommercePolicyIdSchema,
      committedAt: IsoTimestampSchema,
    }),
    z.strictObject({
      mutationId: CommerceTenantMutationIdSchema,
      operation: z.literal("control.policy.resume"),
      resourceType: z.literal("budget_policy"),
      resourceId: CommercePolicyIdSchema,
      committedAt: IsoTimestampSchema,
    }),
    z.strictObject({
      mutationId: CommerceTenantMutationIdSchema,
      operation: z.literal("control.policy.revoke"),
      resourceType: z.literal("budget_policy"),
      resourceId: CommercePolicyIdSchema,
      committedAt: IsoTimestampSchema,
    }),
  ],
);

export type CommercePolicyMutationReceipt = z.infer<
  typeof CommercePolicyMutationReceiptSchema
>;

function isStrictlyAscending(values: readonly string[]): boolean {
  for (let index = 1; index < values.length; index += 1) {
    if (!(values[index - 1]! < values[index]!)) return false;
  }
  return true;
}

/**
 * Numeric ascending unique revisions. Only compare revisions accepted by the
 * canonical revision schema so a malformed leaf (which already produced a
 * failure) can never throw inside BigInt.
 */
function isNumericAscendingUnique(revisions: readonly string[]): boolean {
  let previous: bigint | undefined;
  for (const revision of revisions) {
    if (!CommercePolicyRevisionNumberSchema.safeParse(revision).success) {
      previous = undefined;
      continue;
    }
    const current = BigInt(revision);
    if (previous !== undefined && !(previous < current)) return false;
    previous = current;
  }
  return true;
}

export const CommercePolicyRootPageSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    items: z.array(CommercePolicyRootSchema).max(50),
    nextCursor: CommercePolicyIdSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    const ids: string[] = [];
    value.items.forEach((item, index) => {
      ids.push(item.policyId);
      if (item.organizationId !== value.organizationId) {
        ctx.addIssue({
          code: "custom",
          path: ["items", index, "organizationId"],
          message: "item organizationId must match the page organizationId",
        });
      }
    });
    if (!isStrictlyAscending(ids)) {
      ctx.addIssue({
        code: "custom",
        path: ["items"],
        message: "item policyIds must be strictly ascending and unique",
      });
    }
    if (
      value.nextCursor !== null &&
      (ids.length === 0 || value.nextCursor !== ids[ids.length - 1])
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["nextCursor"],
        message:
          "nextCursor must be null or exactly the last item policyId, and non-null only for a non-empty page",
      });
    }
  });

export const CommercePolicyRootDetailSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    policyId: CommercePolicyIdSchema,
    item: CommercePolicyRootSchema.nullable(),
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
    if (value.item.policyId !== value.policyId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "policyId"],
        message: "item policyId must match policyId",
      });
    }
  });

export const CommercePolicyHistoryPageSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    policyId: CommercePolicyIdSchema,
    items: z.array(CommercePolicyRevisionSummarySchema).max(50),
    nextCursor: CommercePolicyRevisionNumberSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    const revisions: string[] = [];
    let subjectAgentId: string | undefined;
    value.items.forEach((item, index) => {
      revisions.push(item.revision);
      if (item.organizationId !== value.organizationId) {
        ctx.addIssue({
          code: "custom",
          path: ["items", index, "organizationId"],
          message: "item organizationId must match the page organizationId",
        });
      }
      if (item.policyId !== value.policyId) {
        ctx.addIssue({
          code: "custom",
          path: ["items", index, "policyId"],
          message: "item policyId must match the page policyId",
        });
      }
      if (subjectAgentId === undefined) {
        subjectAgentId = item.subjectAgentId;
      } else if (item.subjectAgentId !== subjectAgentId) {
        ctx.addIssue({
          code: "custom",
          path: ["items", index, "subjectAgentId"],
          message: "all page summaries must share one subjectAgentId",
        });
      }
    });
    if (!isNumericAscendingUnique(revisions)) {
      ctx.addIssue({
        code: "custom",
        path: ["items"],
        message: "item revisions must be numerically ascending and unique",
      });
    }
    if (
      value.nextCursor !== null &&
      (revisions.length === 0 ||
        value.nextCursor !== revisions[revisions.length - 1])
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["nextCursor"],
        message:
          "nextCursor must be null or exactly the last item revision, and non-null only for a non-empty page",
      });
    }
  });

export const CommercePolicyRevisionDetailSchema = z
  .strictObject({
    organizationId: CommerceOrganizationIdSchema,
    policyId: CommercePolicyIdSchema,
    revision: CommercePolicyRevisionNumberSchema,
    item: CommercePolicyRevisionSchema.nullable(),
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
    if (value.item.policyId !== value.policyId) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "policyId"],
        message: "item policyId must match policyId",
      });
    }
    if (value.item.revision !== value.revision) {
      ctx.addIssue({
        code: "custom",
        path: ["item", "revision"],
        message: "item revision must match revision",
      });
    }
  });

export const CommercePolicyMutationResultSchema = z.strictObject({
  organizationId: CommerceOrganizationIdSchema,
  replayed: z.boolean(),
  receipt: CommercePolicyMutationReceiptSchema,
});

export type CommercePolicyRootPage = z.infer<
  typeof CommercePolicyRootPageSchema
>;
export type CommercePolicyRootDetail = z.infer<
  typeof CommercePolicyRootDetailSchema
>;
export type CommercePolicyHistoryPage = z.infer<
  typeof CommercePolicyHistoryPageSchema
>;
export type CommercePolicyRevisionDetail = z.infer<
  typeof CommercePolicyRevisionDetailSchema
>;
export type CommercePolicyMutationResult = z.infer<
  typeof CommercePolicyMutationResultSchema
>;

/**
 * Closed status discriminated union. `committed` carries the safe receipt and
 * its mutationId must equal the outer mutationId. There is no raw stored
 * response, secret replay or pending successor state.
 */
export const CommercePolicyMutationStatusSchema = z
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
      receipt: CommercePolicyMutationReceiptSchema,
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

export type CommercePolicyMutationStatus = z.infer<
  typeof CommercePolicyMutationStatusSchema
>;

/**
 * Typed success envelopes over the six response data shapes. These reuse the
 * accepted v2 factory and add no envelope version or error behavior.
 */
export const CommercePolicyRootPageResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommercePolicyRootPageSchema);
export const CommercePolicyRootDetailResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommercePolicyRootDetailSchema);
export const CommercePolicyHistoryPageResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommercePolicyHistoryPageSchema);
export const CommercePolicyRevisionDetailResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommercePolicyRevisionDetailSchema);
export const CommercePolicyMutationResultResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommercePolicyMutationResultSchema);
export const CommercePolicyMutationStatusResponseSchema =
  createCommerceSuccessEnvelopeSchema(CommercePolicyMutationStatusSchema);

export type CommercePolicyRootPageResponse = z.infer<
  typeof CommercePolicyRootPageResponseSchema
>;
export type CommercePolicyRootDetailResponse = z.infer<
  typeof CommercePolicyRootDetailResponseSchema
>;
export type CommercePolicyHistoryPageResponse = z.infer<
  typeof CommercePolicyHistoryPageResponseSchema
>;
export type CommercePolicyRevisionDetailResponse = z.infer<
  typeof CommercePolicyRevisionDetailResponseSchema
>;
export type CommercePolicyMutationResultResponse = z.infer<
  typeof CommercePolicyMutationResultResponseSchema
>;
export type CommercePolicyMutationStatusResponse = z.infer<
  typeof CommercePolicyMutationStatusResponseSchema
>;
