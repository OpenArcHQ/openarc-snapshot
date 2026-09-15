import type {
  CommercePaymentAttemptDispatchData,
  CommercePaymentAttemptPersistData,
  CommercePaymentAttemptReadData,
  CommercePaymentTermsData,
  CommercePaymentVerifiedRequirement,
} from "@openarc/shared";

import type { TenantWriteAuthPort } from "../tenant/write-ports.js";

/**
 * Structural dependency seams for the migration-0015 payment HTTP slice.
 *
 * The store port exposes EXACTLY the five runtime payment operations the frozen
 * route registry needs. It deliberately has NO observation method: the
 * post-dispatch observation recorder is migrator-private, so no runtime seam,
 * route or service may reach it. There is no pool, client, SQL string, generic
 * callback or migration here, and the concrete `ControlPaymentAttemptStore` is
 * not imported: unit tests inject honest fakes.
 *
 * Every store payload crosses this seam as `unknown` and is re-validated by the
 * service against the accepted shared payment wire schemas.
 *
 * SECRET DISCIPLINE. No raw secret is representable on this seam. Agent
 * operations carry only the one-way digest of the `oacs_v1_` commerce bearer;
 * the seller write carries only the internal browser session hash. No
 * signature, authorization payload or key material crosses it in either
 * direction.
 */

export interface CommercePaymentMutationMetadata {
  readonly idempotencyKey: string;
  readonly mutationId: string;
}

/** Seller terms input. Organization, listing and version are path derived. */
export interface CommercePaymentTermsInput {
  readonly payToAddress: string;
}

/** Agent requirement registration: a fresh requirement id and a listing id. */
export interface CommercePaymentRequirementInput {
  readonly requirementId: string;
  readonly listingId: string;
}

/**
 * The full lane binding the store persists. The SERVICE builds it: the fixed
 * network/asset/contract/schema/role come from the frozen wire constants and
 * the value and grant requirement digest come from the buyer's own authorized
 * action. Only the lane-chosen fields originate from the caller.
 */
export interface CommercePaymentBindingInput {
  readonly schemaVersion: string;
  readonly role: string;
  readonly network: string;
  readonly grantId: string;
  readonly actionId: string;
  readonly attemptId: string;
  readonly grantRequirementDigest: string;
  readonly laneRequirementDigest: string;
  readonly verifyingContract: string;
  readonly asset: string;
  readonly from: string;
  readonly to: string;
  readonly value: string;
  readonly validAfter: string;
  readonly validBefore: string;
  readonly nonce: string;
}

export interface CommercePaymentPersistInput {
  readonly binding: CommercePaymentBindingInput;
  readonly bindingDigest: string;
}

export interface CommercePaymentDispatchInput {
  readonly attemptId: string;
  readonly bindingDigest: string;
}

export interface CommercePaymentTermsDbResult {
  readonly replayed: unknown;
  readonly terms: unknown;
  readonly receipt: unknown;
}

export interface CommercePaymentPersistDbResult {
  readonly replayed: unknown;
  readonly attempt: unknown;
}

export interface CommercePaymentAttemptReadDbResult {
  readonly attemptId: unknown;
  readonly item: unknown;
}

/** The exact five runtime payment store operations, one per frozen route. */
export interface CommercePaymentStorePort {
  recordListingPaymentTerms(
    humanSessionHash: unknown,
    organizationId: unknown,
    listingId: unknown,
    version: unknown,
    input: CommercePaymentTermsInput,
    metadata: CommercePaymentMutationMetadata,
  ): Promise<CommercePaymentTermsDbResult>;
  registerVerifiedRequirement(
    commerceSessionHash: unknown,
    input: CommercePaymentRequirementInput,
  ): Promise<unknown>;
  persistBuyerAttempt(
    commerceSessionHash: unknown,
    input: CommercePaymentPersistInput,
  ): Promise<CommercePaymentPersistDbResult>;
  recordAttemptDispatch(
    commerceSessionHash: unknown,
    input: CommercePaymentDispatchInput,
  ): Promise<unknown>;
  readAgentAttempt(
    commerceSessionHash: unknown,
    attemptId: unknown,
  ): Promise<CommercePaymentAttemptReadDbResult>;
}

/**
 * Narrow agent action read. The service derives the attempt value and the grant
 * requirement digest from the buyer's own authorized action, never the wire.
 */
export interface CommercePaymentActionReadPort {
  getAgentCommerceAction(
    commerceSessionHash: unknown,
    actionId: unknown,
  ): Promise<{ readonly organizationId: unknown; readonly item: unknown }>;
}

/** Resolves the CURRENT commerce session behind a presented `oacs_v1_` bearer. */
export interface CommercePaymentSessionReadPort {
  getCommerceSessionByHash(tokenHash: unknown): Promise<unknown>;
}

/** EXACTLY the accepted tenant write auth port; no new auth method. */
export type CommercePaymentAuthPort = TenantWriteAuthPort;

export interface CommercePaymentRateLimitStorePort {
  consume(input: {
    keyHash: string;
    limit: number;
    windowSeconds: number;
  }): Promise<{ allowed: boolean }>;
}

export type {
  CommercePaymentAttemptDispatchData,
  CommercePaymentAttemptPersistData,
  CommercePaymentAttemptReadData,
  CommercePaymentTermsData,
  CommercePaymentVerifiedRequirement,
};
