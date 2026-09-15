import { z } from "zod";

import { compareIsoTimestamps, IsoTimestampSchema } from "../primitives.js";
import {
  CommerceRequirementIdSchema,
  CommerceReservationIdSchema,
} from "./control-action.js";
import { CommerceActionIdSchema } from "./control-budget.js";
import { CommerceControlSessionIdSchema } from "./control-session.js";
import { CommerceGrantIdSchema } from "./control-grant.js";
import {
  CommerceAgentIdSchema,
  CommerceOrganizationIdSchema,
  CommerceProviderIdSchema,
} from "./identity.js";
import {
  CommerceListingIdSchema,
  CommerceListingVersionSchema,
} from "./listing.js";

/**
 * P03 pure grant metadata contracts.
 *
 * Browser-safe, strict, additive DTOs describing a grant's declared metadata
 * shape and its two provider-facing projections only. This module performs no
 * SQL, authority, crypto, token issuance/claim, network, transport, receipt or
 * execution work. Parsing one of these objects never proves a live grant, a
 * current clock, an authorization, a payment, a settlement or a delivery. The
 * DB12 grant-store atomic transition is future work (DB11 is reads); DB10
 * currently emits only its five older action states.
 *
 * The existing grant-token primitive in control-grant.ts stays unchanged and
 * secret; no raw token, hash or payment material is representable here.
 */

export const COMMERCE_GRANT_METADATA_SCHEMA_VERSION =
  "openarc.control.grant.v1" as const;
export const COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION =
  "openarc.control.grant-provider.v1" as const;

// Canonical positive uint256, absolute end. A trailing LF/space cannot satisfy
// `(?![\s\S])`. This is deliberately stricter than the legacy primitive `$`.
const POSITIVE_UINT256_PATTERN = /^[1-9][0-9]{0,77}(?![\s\S])/u;
const MAX_UINT256 = (1n << 256n) - 1n;

const CommerceGrantPositiveUint256Schema = z
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

const CommerceGrantNonnegativeUint256Schema = z
  .string()
  .regex(UINT256_PATTERN, { message: "Expected a canonical uint256" })
  .refine(
    (value) => UINT256_PATTERN.test(value) && BigInt(value) <= MAX_UINT256,
    { message: "Expected a canonical uint256" },
  );

// Canonical positive decimal of at most 128 digits. Compared as BigInt so an
// all-nines 128-digit value is accepted and 129 digits are not. Only used for
// the amount+fee crosssum.
const DEBIT_PATTERN = /^[1-9][0-9]{0,127}(?![\s\S])/u;

const CommerceGrantDebitSchema = z
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

// Canonical generation 1..2147483647, absolute end.
const GENERATION_PATTERN = /^[1-9][0-9]{0,9}(?![\s\S])/u;

const CommerceGrantGenerationSchema = z
  .string()
  .regex(GENERATION_PATTERN, {
    message: "Expected a canonical generation 1..2147483647",
  })
  .refine(
    (value) =>
      GENERATION_PATTERN.test(value) && BigInt(value) <= 2147483647n,
    { message: "Expected a canonical generation 1..2147483647" },
  );

// sha256:<64 lower-case hex> with an absolute end.
const CommerceGrantDigestSchema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}(?![\s\S])/u, {
    message: "Expected a lowercase SHA-256 digest",
  });

// Exact lower-case canonical UUIDv4 (no namespace prefix), absolute end.
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/u;

const CommerceGrantAttemptIdSchema = z
  .string()
  .regex(UUID_V4_PATTERN, { message: "Expected a canonical UUIDv4" });

export const CommerceGrantStatusSchema = z.enum([
  "issued",
  "claimed",
  "revoked",
  "expired",
]);

export type CommerceGrantStatus = z.infer<typeof CommerceGrantStatusSchema>;

// Fixed lifetime ceiling: a grant may live at most 300 seconds beyond issuance.
const GRANT_MAX_LIFETIME_SECONDS = 300;

/**
 * Exact, fraction-preserving shift of `iso` by `seconds`. The sub-second
 * fraction is carried verbatim so an expiry at exactly the 300s boundary with
 * equal or smaller fractions is accepted, and nanosecond fractions are never
 * rounded through a JS Date millisecond. Callers must have validated `iso`
 * with IsoTimestampSchema first.
 */
function shiftIsoSeconds(iso: string, seconds: number): string {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$/u.exec(
    iso,
  );
  if (!match) throw new Error("Expected a valid ISO 8601 UTC timestamp");
  const baseMs = Date.parse(`${match[1]}Z`);
  const shifted = new Date(baseMs + seconds * 1000)
    .toISOString()
    .slice(0, 19);
  return `${shifted}${match[2] ? `.${match[2]}` : ""}Z`;
}

export const CommerceGrantMetadataSchema = z
  .strictObject({
    schemaVersion: z.literal(COMMERCE_GRANT_METADATA_SCHEMA_VERSION),
    grantId: CommerceGrantIdSchema,
    organizationId: CommerceOrganizationIdSchema,
    subjectAgentId: CommerceAgentIdSchema,
    actionId: CommerceActionIdSchema,
    reservationId: CommerceReservationIdSchema,
    commerceSessionId: CommerceControlSessionIdSchema,
    providerId: CommerceProviderIdSchema,
    listingId: CommerceListingIdSchema,
    listingVersion: CommerceListingVersionSchema,
    generation: CommerceGrantGenerationSchema,
    status: CommerceGrantStatusSchema,
    issuedAt: IsoTimestampSchema,
    updatedAt: IsoTimestampSchema,
    expiresAt: IsoTimestampSchema,
    claimedAt: IsoTimestampSchema.nullable(),
    revokedAt: IsoTimestampSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    // Guard invalid leaves before the exact fractional timestamp compares so a
    // malformed timestamp never makes compareIsoTimestamps throw.
    const issuedValid = IsoTimestampSchema.safeParse(value.issuedAt).success;
    const updatedValid = IsoTimestampSchema.safeParse(value.updatedAt).success;
    const expiresValid = IsoTimestampSchema.safeParse(value.expiresAt).success;
    const claimedValid =
      value.claimedAt !== null &&
      IsoTimestampSchema.safeParse(value.claimedAt).success;
    const revokedValid =
      value.revokedAt !== null &&
      IsoTimestampSchema.safeParse(value.revokedAt).success;

    if (issuedValid && updatedValid) {
      if (compareIsoTimestamps(value.updatedAt, value.issuedAt) < 0) {
        ctx.addIssue({
          code: "custom",
          path: ["updatedAt"],
          message: "updatedAt must be at or after issuedAt",
        });
      }
    }

    if (issuedValid && expiresValid) {
      if (compareIsoTimestamps(value.expiresAt, value.issuedAt) <= 0) {
        ctx.addIssue({
          code: "custom",
          path: ["expiresAt"],
          message: "expiresAt must strictly follow issuedAt",
        });
      }
      const ceiling = shiftIsoSeconds(
        value.issuedAt,
        GRANT_MAX_LIFETIME_SECONDS,
      );
      if (compareIsoTimestamps(value.expiresAt, ceiling) > 0) {
        ctx.addIssue({
          code: "custom",
          path: ["expiresAt"],
          message: "expiresAt must be at most 300 seconds after issuedAt",
        });
      }
    }

    if (issuedValid && expiresValid && claimedValid) {
      if (compareIsoTimestamps(value.claimedAt!, value.issuedAt) < 0) {
        ctx.addIssue({
          code: "custom",
          path: ["claimedAt"],
          message: "claimedAt must be at or after issuedAt",
        });
      }
      if (compareIsoTimestamps(value.claimedAt!, value.expiresAt) >= 0) {
        ctx.addIssue({
          code: "custom",
          path: ["claimedAt"],
          message: "claimedAt must be strictly before expiresAt",
        });
      }
    }
    if (updatedValid && claimedValid) {
      if (compareIsoTimestamps(value.claimedAt!, value.updatedAt) > 0) {
        ctx.addIssue({
          code: "custom",
          path: ["claimedAt"],
          message: "claimedAt must be at or before updatedAt",
        });
      }
    }

    if (issuedValid && revokedValid) {
      if (compareIsoTimestamps(value.revokedAt!, value.issuedAt) < 0) {
        ctx.addIssue({
          code: "custom",
          path: ["revokedAt"],
          message: "revokedAt must be at or after issuedAt",
        });
      }
    }
    if (claimedValid && revokedValid) {
      if (compareIsoTimestamps(value.revokedAt!, value.claimedAt!) < 0) {
        ctx.addIssue({
          code: "custom",
          path: ["revokedAt"],
          message: "revokedAt must be at or after claimedAt",
        });
      }
    }
    if (updatedValid && revokedValid) {
      if (compareIsoTimestamps(value.revokedAt!, value.updatedAt) > 0) {
        ctx.addIssue({
          code: "custom",
          path: ["revokedAt"],
          message: "revokedAt must be at or before updatedAt",
        });
      }
    }

    switch (value.status) {
      case "issued":
      case "expired": {
        if (value.claimedAt !== null) {
          ctx.addIssue({
            code: "custom",
            path: ["claimedAt"],
            message: `${value.status} requires a null claimedAt`,
          });
        }
        if (value.revokedAt !== null) {
          ctx.addIssue({
            code: "custom",
            path: ["revokedAt"],
            message: `${value.status} requires a null revokedAt`,
          });
        }
        break;
      }
      case "claimed": {
        if (value.claimedAt === null) {
          ctx.addIssue({
            code: "custom",
            path: ["claimedAt"],
            message: "claimed requires a non-null claimedAt",
          });
        }
        if (value.revokedAt !== null) {
          ctx.addIssue({
            code: "custom",
            path: ["revokedAt"],
            message: "claimed requires a null revokedAt",
          });
        }
        break;
      }
      case "revoked": {
        if (value.revokedAt === null) {
          ctx.addIssue({
            code: "custom",
            path: ["revokedAt"],
            message: "revoked requires a non-null revokedAt",
          });
        }
        // claimedAt stays nullable so a prior claim remains visible.
        break;
      }
    }
  });

export type CommerceGrantMetadata = z.infer<
  typeof CommerceGrantMetadataSchema
>;

export const CommerceGrantProviderViewSchema = z
  .strictObject({
    schemaVersion: z.literal(COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION),
    grantId: CommerceGrantIdSchema,
    actionId: CommerceActionIdSchema,
    providerId: CommerceProviderIdSchema,
    listingId: CommerceListingIdSchema,
    listingVersion: CommerceListingVersionSchema,
    requirementId: CommerceRequirementIdSchema,
    requirementDigest: CommerceGrantDigestSchema,
    networkId: z.literal("eip155:5042002"),
    asset: z.literal("USDC"),
    representation: z.literal("erc20"),
    decimals: z.literal(6),
    amountAtomic: CommerceGrantPositiveUint256Schema,
    feeAtomic: CommerceGrantNonnegativeUint256Schema,
    debitAtomic: CommerceGrantDebitSchema,
    expiresAt: IsoTimestampSchema,
    status: CommerceGrantStatusSchema,
    claimedAttemptId: CommerceGrantAttemptIdSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    const amountValid = CommerceGrantPositiveUint256Schema.safeParse(
      value.amountAtomic,
    ).success;
    const feeValid = CommerceGrantNonnegativeUint256Schema.safeParse(
      value.feeAtomic,
    ).success;
    const debitValid = CommerceGrantDebitSchema.safeParse(
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

    switch (value.status) {
      case "issued":
      case "expired": {
        if (value.claimedAttemptId !== null) {
          ctx.addIssue({
            code: "custom",
            path: ["claimedAttemptId"],
            message: `${value.status} requires a null claimedAttemptId`,
          });
        }
        break;
      }
      case "claimed": {
        if (value.claimedAttemptId === null) {
          ctx.addIssue({
            code: "custom",
            path: ["claimedAttemptId"],
            message: "claimed requires a non-null claimedAttemptId",
          });
        }
        break;
      }
      case "revoked": {
        // Revoked may preserve a non-null claimedAttemptId as history.
        break;
      }
    }
  });

export type CommerceGrantProviderView = z.infer<
  typeof CommerceGrantProviderViewSchema
>;

/**
 * Safe recovery projection. `not_found` carries ONLY its status; `claimed`
 * retains the original claim attempt after buyer/grant expiry or revocation.
 * This proves no settlement, delivery or nonpayment and carries no signature,
 * token or permission to retransmit payment. Future servers derive provider
 * identity from the current credential/session, never from this shape.
 */
export const CommerceGrantProviderAttemptStatusSchema = z.discriminatedUnion(
  "status",
  [
    z.strictObject({
      status: z.literal("not_found"),
    }),
    z.strictObject({
      status: z.literal("claimed"),
      attemptId: CommerceGrantAttemptIdSchema,
      grantId: CommerceGrantIdSchema,
      actionId: CommerceActionIdSchema,
      providerId: CommerceProviderIdSchema,
      listingId: CommerceListingIdSchema,
      listingVersion: CommerceListingVersionSchema,
      claimedAt: IsoTimestampSchema,
      grantRevoked: z.boolean(),
    }),
  ],
);

export type CommerceGrantProviderAttemptStatus = z.infer<
  typeof CommerceGrantProviderAttemptStatusSchema
>;

const ORGANIZATION_PROTECTED = "organization_protected" as const;
const ORGANIZATION_AUDIENCE = "organization" as const;
const PROVIDER_MINIMAL_AUDIENCE = "provider_minimal" as const;

type GrantAudience =
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

function grantFieldClass<K extends string>(
  audience: GrantAudience,
  keys: readonly K[],
) {
  return Object.freeze({
    dataClass: ORGANIZATION_PROTECTED,
    audience,
    fields: protectedFields(keys),
  });
}

/**
 * Deeply frozen field-class mapping for exactly the declared grant-model
 * fields. Every field is `organization_protected`; the buyer grant is
 * `organization` audience and the two provider projections are
 * `provider_minimal`. This is descriptive metadata only, not authorization,
 * redaction or a persistence assertion, and it deliberately reuses the
 * existing privacy vocabulary rather than a new dataClass.
 */
export const COMMERCE_GRANT_MODEL_FIELD_CLASSES = Object.freeze({
  grantMetadata: grantFieldClass(ORGANIZATION_AUDIENCE, [
    "schemaVersion",
    "grantId",
    "organizationId",
    "subjectAgentId",
    "actionId",
    "reservationId",
    "commerceSessionId",
    "providerId",
    "listingId",
    "listingVersion",
    "generation",
    "status",
    "issuedAt",
    "updatedAt",
    "expiresAt",
    "claimedAt",
    "revokedAt",
  ] as const),
  providerView: grantFieldClass(PROVIDER_MINIMAL_AUDIENCE, [
    "schemaVersion",
    "grantId",
    "actionId",
    "providerId",
    "listingId",
    "listingVersion",
    "requirementId",
    "requirementDigest",
    "networkId",
    "asset",
    "representation",
    "decimals",
    "amountAtomic",
    "feeAtomic",
    "debitAtomic",
    "expiresAt",
    "status",
    "claimedAttemptId",
  ] as const),
  providerAttemptStatus: grantFieldClass(PROVIDER_MINIMAL_AUDIENCE, [
    "status",
    "attemptId",
    "grantId",
    "actionId",
    "providerId",
    "listingId",
    "listingVersion",
    "claimedAt",
    "grantRevoked",
  ] as const),
});
