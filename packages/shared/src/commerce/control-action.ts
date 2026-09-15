import { z } from "zod";

import { compareIsoTimestamps, IsoTimestampSchema } from "../primitives.js";
import {
  CommerceActionIdSchema,
  CommerceExposureKeySchema,
} from "./control-budget.js";
import { CommercePolicyIdSchema } from "./control-policy.js";
import { CommerceControlSessionIdSchema } from "./control-session.js";
import {
  CommerceAccountIdSchema,
  CommerceAgentIdSchema,
  CommerceOrganizationIdSchema,
  CommerceProviderIdSchema,
} from "./identity.js";
import { CommerceListingIdSchema } from "./listing.js";

/**
 * P03 action/approval core shared DTO freeze.
 *
 * Pure strict shapes only: no SQL, transport, server clock, hashing,
 * signatures, grants, provider requests, budgets or execution. Parsing one of
 * these records never proves a principal, a reservation, an approval decision,
 * a digest, current policy status or spend authority. The current listing
 * paymentLane stays unavailable; durable financial transitions belong to DB10.
 */

export const COMMERCE_ACTION_SCHEMA_VERSION =
  "openarc.control.action.v1" as const;
export const COMMERCE_APPROVAL_SCHEMA_VERSION =
  "openarc.control.approval.v1" as const;

// Version nibble pinned to 4 (canonical lower-case UUIDv4); variant [89ab].
const UUID_PATTERN =
  "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

// `(?![\s\S])` pins the absolute end of input so a trailing LF cannot satisfy
// `$`. Each new namespace is distinct from every accepted identity prefix.
function canonicalUuidIdSchema(prefix: string, label: string) {
  return z.string().regex(new RegExp(`^${prefix}${UUID_PATTERN}(?![\\s\\S])`), {
    message: `Expected a canonical lower-case ${label} UUID`,
  });
}

export const CommerceReservationIdSchema = canonicalUuidIdSchema(
  "openarc:reservation:",
  "openarc:reservation:",
);

export const CommerceApprovalIdSchema = canonicalUuidIdSchema(
  "openarc:approval:",
  "openarc:approval:",
);

export const CommerceRequirementIdSchema = canonicalUuidIdSchema(
  "openarc:requirement:",
  "openarc:requirement:",
);

export type CommerceReservationId = z.infer<
  typeof CommerceReservationIdSchema
>;
export type CommerceApprovalId = z.infer<typeof CommerceApprovalIdSchema>;
export type CommerceRequirementId = z.infer<
  typeof CommerceRequirementIdSchema
>;

// The exported id leaves are deliberately NOT nullable: only the declared
// metadata relationship fields (`reservationId`, `approvalId`, `decidedBy`)
// carry `.nullable()` at their use site.
export const CommerceActionStatusSchema = z.enum([
  "pending_approval",
  "reserved_not_granted",
  "grant_issued",
  "rejected",
  "cancelled",
  "expired",
]);

export type CommerceActionStatus = z.infer<typeof CommerceActionStatusSchema>;

export const CommerceApprovalStatusSchema = z.enum([
  "pending",
  "approved",
  "rejected",
  "expired",
]);

export type CommerceApprovalStatus = z.infer<
  typeof CommerceApprovalStatusSchema
>;

// Canonical positive uint256, absolute end. Stricter than the legacy primitive
// whose `$` would accept a trailing LF.
const POSITIVE_UINT256_PATTERN = /^[1-9][0-9]{0,77}(?![\s\S])/u;
const MAX_UINT256 = (1n << 256n) - 1n;

const CommerceActionPositiveUint256Schema = z
  .string()
  .regex(POSITIVE_UINT256_PATTERN, {
    message: "Expected a canonical positive uint256",
  })
  .refine(
    (value) =>
      POSITIVE_UINT256_PATTERN.test(value) && BigInt(value) <= MAX_UINT256,
    { message: "Expected a canonical positive uint256" },
  );

// Canonical nonnegative uint256, absolute end (fee may be zero).
const UINT256_PATTERN = /^(0|[1-9][0-9]{0,77})(?![\s\S])/u;

const CommerceActionNonnegativeUint256Schema = z
  .string()
  .regex(UINT256_PATTERN, { message: "Expected a canonical uint256" })
  .refine(
    (value) => UINT256_PATTERN.test(value) && BigInt(value) <= MAX_UINT256,
    { message: "Expected a canonical uint256" },
  );

// Canonical positive decimal of at most 128 digits (compared as BigInt, so an
// all-nines 128-digit value is accepted and 129 digits are not). This does not
// inherit the old global 128-digit primary pattern that pinned `^[1-9]`, so
// debit must be positive; it is only used for the amount+fee crosssum.
const DEBIT_PATTERN = /^[1-9][0-9]{0,127}(?![\s\S])/u;

const CommerceActionDebitSchema = z
  .string()
  .regex(DEBIT_PATTERN, {
    message: "Expected a canonical positive decimal of at most 128 digits",
  })
  .refine(
    (value) => DEBIT_PATTERN.test(value) && BigInt(value) < 10n ** 128n,
    {
      message: "Expected a canonical positive decimal of at most 128 digits",
    },
  );

// Canonical version 1..999999999, absolute end.
const VERSION_PATTERN = /^[1-9][0-9]{0,8}(?![\s\S])/u;

const CommerceActionVersionSchema = z
  .string()
  .regex(VERSION_PATTERN, {
    message: "Expected a canonical version 1..999999999",
  })
  .refine(
    (value) => VERSION_PATTERN.test(value) && BigInt(value) <= 999999999n,
    { message: "Expected a canonical version 1..999999999" },
  );

// sha256:<64 lowercase hex> with an absolute end.
const CommerceActionDigestSchema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}(?![\s\S])/u, {
    message: "Expected a lowercase SHA-256 digest",
  });

export const CommerceActionMetadataSchema = z
  .strictObject({
    schemaVersion: z.literal(COMMERCE_ACTION_SCHEMA_VERSION),
    actionId: CommerceActionIdSchema,
    exposureKey: CommerceExposureKeySchema,
    commerceSessionId: CommerceControlSessionIdSchema,
    policyId: CommercePolicyIdSchema,
    policyRevision: CommerceActionVersionSchema,
    providerId: CommerceProviderIdSchema,
    listingId: CommerceListingIdSchema,
    listingVersion: CommerceActionVersionSchema,
    requirementId: CommerceRequirementIdSchema,
    requirementDigest: CommerceActionDigestSchema,
    amountAtomic: CommerceActionPositiveUint256Schema,
    feeAtomic: CommerceActionNonnegativeUint256Schema,
    debitAtomic: CommerceActionDebitSchema,
    status: CommerceActionStatusSchema,
    reservationId: CommerceReservationIdSchema.nullable(),
    approvalId: CommerceApprovalIdSchema.nullable(),
    createdAt: IsoTimestampSchema,
    updatedAt: IsoTimestampSchema,
    expiresAt: IsoTimestampSchema,
  })
  .superRefine((value, ctx) => {
    const amountValid = CommerceActionPositiveUint256Schema.safeParse(
      value.amountAtomic,
    ).success;
    const feeValid = CommerceActionNonnegativeUint256Schema.safeParse(
      value.feeAtomic,
    ).success;
    const debitValid = CommerceActionDebitSchema.safeParse(
      value.debitAtomic,
    ).success;
    if (amountValid && feeValid && debitValid) {
      const expected = BigInt(value.amountAtomic) + BigInt(value.feeAtomic);
      if (BigInt(value.debitAtomic) !== expected) {
        ctx.addIssue({
          code: "custom",
          path: ["debitAtomic"],
          message: "debitAtomic must equal amountAtomic + feeAtomic",
        });
      }
    }

    const createdAtValid = IsoTimestampSchema.safeParse(value.createdAt).success;
    const updatedAtValid = IsoTimestampSchema.safeParse(value.updatedAt).success;
    const expiresAtValid = IsoTimestampSchema.safeParse(value.expiresAt).success;
    if (createdAtValid && updatedAtValid) {
      if (compareIsoTimestamps(value.updatedAt, value.createdAt) < 0) {
        ctx.addIssue({
          code: "custom",
          path: ["updatedAt"],
          message: "updatedAt must be at or after createdAt",
        });
      }
    }
    if (createdAtValid && expiresAtValid) {
      if (compareIsoTimestamps(value.expiresAt, value.createdAt) <= 0) {
        ctx.addIssue({
          code: "custom",
          path: ["expiresAt"],
          message: "expiresAt must strictly follow createdAt",
        });
      }
    }

    switch (value.status) {
      case "pending_approval": {
        if (value.approvalId === null) {
          ctx.addIssue({
            code: "custom",
            path: ["approvalId"],
            message: "pending_approval requires a non-null approvalId",
          });
        }
        if (value.reservationId !== null) {
          ctx.addIssue({
            code: "custom",
            path: ["reservationId"],
            message: "pending_approval requires a null reservationId",
          });
        }
        break;
      }
      case "reserved_not_granted": {
        if (value.reservationId === null) {
          ctx.addIssue({
            code: "custom",
            path: ["reservationId"],
            message: "reserved_not_granted requires a non-null reservationId",
          });
        }
        break;
      }
      // Pure metadata vocabulary amendment: DB12 will later enforce the atomic
      // reservation-to-grant transition. Like reserved_not_granted, grant_issued
      // requires a non-null reservationId; approvalId may be null or valid.
      case "grant_issued": {
        if (value.reservationId === null) {
          ctx.addIssue({
            code: "custom",
            path: ["reservationId"],
            message: "grant_issued requires a non-null reservationId",
          });
        }
        break;
      }
      case "rejected": {
        if (value.approvalId === null) {
          ctx.addIssue({
            code: "custom",
            path: ["approvalId"],
            message: "rejected requires a non-null approvalId",
          });
        }
        if (value.reservationId !== null) {
          ctx.addIssue({
            code: "custom",
            path: ["reservationId"],
            message: "rejected requires a null reservationId",
          });
        }
        break;
      }
      case "cancelled":
      case "expired": {
        if (value.approvalId === null && value.reservationId === null) {
          ctx.addIssue({
            code: "custom",
            path: ["approvalId"],
            message: `${value.status} requires approvalId or reservationId`,
          });
        }
        break;
      }
    }
  });

export type CommerceActionMetadata = z.infer<
  typeof CommerceActionMetadataSchema
>;

export const CommerceApprovalMetadataSchema = z
  .strictObject({
    schemaVersion: z.literal(COMMERCE_APPROVAL_SCHEMA_VERSION),
    approvalId: CommerceApprovalIdSchema,
    actionId: CommerceActionIdSchema,
    organizationId: CommerceOrganizationIdSchema,
    subjectAgentId: CommerceAgentIdSchema,
    commerceSessionId: CommerceControlSessionIdSchema,
    policyId: CommercePolicyIdSchema,
    policyRevision: CommerceActionVersionSchema,
    requestedBy: CommerceAccountIdSchema,
    separateApprover: z.boolean(),
    status: CommerceApprovalStatusSchema,
    decidedBy: CommerceAccountIdSchema.nullable(),
    createdAt: IsoTimestampSchema,
    expiresAt: IsoTimestampSchema,
    decidedAt: IsoTimestampSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    const createdAtValid = IsoTimestampSchema.safeParse(value.createdAt).success;
    const expiresAtValid = IsoTimestampSchema.safeParse(value.expiresAt).success;
    const decidedAtValid =
      value.decidedAt === null ||
      IsoTimestampSchema.safeParse(value.decidedAt).success;

    if (createdAtValid && expiresAtValid) {
      if (compareIsoTimestamps(value.expiresAt, value.createdAt) <= 0) {
        ctx.addIssue({
          code: "custom",
          path: ["expiresAt"],
          message: "expiresAt must strictly follow createdAt",
        });
      }
    }

    const decisionPresent = value.decidedBy !== null && value.decidedAt !== null;
    const decisionAbsent = value.decidedBy === null && value.decidedAt === null;

    switch (value.status) {
      case "pending": {
        if (!decisionAbsent) {
          ctx.addIssue({
            code: "custom",
            path: ["decidedBy"],
            message: "pending requires null decidedBy and decidedAt",
          });
        }
        break;
      }
      case "approved":
      case "rejected": {
        if (!decisionPresent) {
          ctx.addIssue({
            code: "custom",
            path: ["decidedBy"],
            message: `${value.status} requires non-null decidedBy and decidedAt`,
          });
        } else if (createdAtValid && expiresAtValid && decidedAtValid) {
          if (compareIsoTimestamps(value.decidedAt!, value.createdAt) < 0) {
            ctx.addIssue({
              code: "custom",
              path: ["decidedAt"],
              message: "decidedAt must be at or after createdAt",
            });
          }
          if (compareIsoTimestamps(value.decidedAt!, value.expiresAt) >= 0) {
            ctx.addIssue({
              code: "custom",
              path: ["decidedAt"],
              message: "decidedAt must be strictly before expiresAt",
            });
          }
        }
        if (value.separateApprover && value.decidedBy === value.requestedBy) {
          ctx.addIssue({
            code: "custom",
            path: ["decidedBy"],
            message:
              "separateApprover requires decidedBy to differ from requestedBy",
          });
        }
        break;
      }
      case "expired": {
        if (!decisionAbsent) {
          ctx.addIssue({
            code: "custom",
            path: ["decidedBy"],
            message: "expired requires null decidedBy and decidedAt",
          });
        }
        break;
      }
    }
  });

export type CommerceApprovalMetadata = z.infer<
  typeof CommerceApprovalMetadataSchema
>;

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

export const COMMERCE_ACTION_FIELD_CLASSES = Object.freeze({
  action: protectedFields([
    "schemaVersion",
    "actionId",
    "exposureKey",
    "commerceSessionId",
    "policyId",
    "policyRevision",
    "providerId",
    "listingId",
    "listingVersion",
    "requirementId",
    "requirementDigest",
    "amountAtomic",
    "feeAtomic",
    "debitAtomic",
    "status",
    "reservationId",
    "approvalId",
    "createdAt",
    "updatedAt",
    "expiresAt",
  ] as const),
  approval: protectedFields([
    "schemaVersion",
    "approvalId",
    "actionId",
    "organizationId",
    "subjectAgentId",
    "commerceSessionId",
    "policyId",
    "policyRevision",
    "requestedBy",
    "separateApprover",
    "status",
    "decidedBy",
    "createdAt",
    "expiresAt",
    "decidedAt",
  ] as const),
});
