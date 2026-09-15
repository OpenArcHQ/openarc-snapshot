import type {
  COMMERCE_PAYMENT_ASSET_ADDRESS,
  COMMERCE_PAYMENT_BINDING_SCHEMA_VERSION,
  COMMERCE_PAYMENT_NETWORK,
  COMMERCE_PAYMENT_TERMS_OPERATION,
  COMMERCE_PAYMENT_VERIFYING_CONTRACT,
} from "@openarc/shared";
import type {
  CommerceSessionStore,
  ControlActionStore,
  ControlPaymentAttemptStore,
  LISTING_PAYMENT_TERMS_OPERATION,
  PAYMENT_ATTEMPT_ASSET_ADDRESS,
  PAYMENT_ATTEMPT_BINDING_SCHEMA_VERSION,
  PAYMENT_ATTEMPT_NETWORK,
  PAYMENT_ATTEMPT_VERIFYING_CONTRACT,
} from "@openarc/db";

import type {
  CommercePaymentActionReadPort,
  CommercePaymentAttemptReadDbResult,
  CommercePaymentDispatchInput,
  CommercePaymentMutationMetadata,
  CommercePaymentPersistDbResult,
  CommercePaymentPersistInput,
  CommercePaymentRequirementInput,
  CommercePaymentSessionReadPort,
  CommercePaymentStorePort,
  CommercePaymentTermsDbResult,
  CommercePaymentTermsInput,
} from "./payment-ports.js";

/**
 * Binds the payment service ports to the real schema15
 * `ControlPaymentAttemptStore`, the DB10 action store's agent read and the
 * commerce-session read.
 *
 * Deliberately thin: it renames methods and wraps the attempt read with the
 * requested id. It performs NO authority, financial, transport or validation
 * work, never retries, never swallows or relabels an error, never logs and
 * never inspects a digest. It binds NO observation method: the post-dispatch
 * recorder is migrator-private and has no runtime seam.
 *
 * All store imports are type-only and therefore erased.
 */

type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

/**
 * Compile-time proof that the frozen shared wire constants the service uses to
 * rebuild the binding are EXACTLY the store's own constants. A drift on either
 * side breaks the build here instead of producing a digest the store refuses.
 */
export const PAYMENT_WIRE_CONSTANTS_MATCH_STORE: Same<
  typeof COMMERCE_PAYMENT_NETWORK,
  typeof PAYMENT_ATTEMPT_NETWORK
> &
  Same<typeof COMMERCE_PAYMENT_ASSET_ADDRESS, typeof PAYMENT_ATTEMPT_ASSET_ADDRESS> &
  Same<
    typeof COMMERCE_PAYMENT_VERIFYING_CONTRACT,
    typeof PAYMENT_ATTEMPT_VERIFYING_CONTRACT
  > &
  Same<
    typeof COMMERCE_PAYMENT_BINDING_SCHEMA_VERSION,
    typeof PAYMENT_ATTEMPT_BINDING_SCHEMA_VERSION
  > &
  Same<typeof COMMERCE_PAYMENT_TERMS_OPERATION, typeof LISTING_PAYMENT_TERMS_OPERATION> =
  true;

export function createCommercePaymentStoreAdapter(
  payments: ControlPaymentAttemptStore,
): CommercePaymentStorePort {
  return {
    recordListingPaymentTerms(
      humanSessionHash: unknown,
      organizationId: unknown,
      listingId: unknown,
      version: unknown,
      input: CommercePaymentTermsInput,
      metadata: CommercePaymentMutationMetadata,
    ): Promise<CommercePaymentTermsDbResult> {
      return payments.recordListingPaymentTerms(
        humanSessionHash,
        organizationId,
        listingId,
        version,
        input,
        metadata,
      );
    },
    registerVerifiedRequirement(
      commerceSessionHash: unknown,
      input: CommercePaymentRequirementInput,
    ): Promise<unknown> {
      return payments.registerVerifiedRequirement(commerceSessionHash, input);
    },
    persistBuyerAttempt(
      commerceSessionHash: unknown,
      input: CommercePaymentPersistInput,
    ): Promise<CommercePaymentPersistDbResult> {
      return payments.persistBuyerAttempt(commerceSessionHash, input);
    },
    recordAttemptDispatch(
      commerceSessionHash: unknown,
      input: CommercePaymentDispatchInput,
    ): Promise<unknown> {
      return payments.recordDispatch(commerceSessionHash, input);
    },
    /**
     * The store answers a missing OR foreign attempt with the same null, so
     * echoing the requested id alongside it discloses nothing new.
     */
    async readAgentAttempt(
      commerceSessionHash: unknown,
      attemptId: unknown,
    ): Promise<CommercePaymentAttemptReadDbResult> {
      const item = await payments.readAgentAttempt(commerceSessionHash, attemptId);
      return { attemptId, item };
    },
  };
}

/** Pure rename onto the DB10 agent action read. */
export function createCommercePaymentActionReadAdapter(
  actions: ControlActionStore,
): CommercePaymentActionReadPort {
  return {
    async getAgentCommerceAction(
      commerceSessionHash: unknown,
      actionId: unknown,
    ): Promise<{ organizationId: unknown; item: unknown }> {
      const read = await actions.readAgentAction(commerceSessionHash, actionId);
      return { organizationId: read.organizationId, item: read.item };
    },
  };
}

/** Pure rename onto the DB9/DB13 commerce-session read. */
export function createCommercePaymentSessionReadAdapter(
  sessions: CommerceSessionStore,
): CommercePaymentSessionReadPort {
  return {
    getCommerceSessionByHash(tokenHash: unknown): Promise<unknown> {
      return sessions.getCommerceSessionByHash(tokenHash);
    },
  };
}
