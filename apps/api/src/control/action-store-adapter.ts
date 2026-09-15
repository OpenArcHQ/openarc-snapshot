import type {
  CommerceSessionStore,
  ControlActionReadStore,
  ControlActionStore,
} from "@openarc/db";

import type {
  CommerceActionAuthorizeInput,
  CommerceActionDetailDbResult,
  CommerceActionListOptions,
  CommerceActionMutationDbResult,
  CommerceActionMutationDbStatus,
  CommerceActionMutationMetadata,
  CommerceActionPageDbResult,
  CommerceActionStorePort,
  CommerceApprovalDetailDbResult,
  CommerceApprovalListOptions,
  CommerceApprovalPageDbResult,
  CommerceExposureDbResult,
  CommerceSessionReadPort,
} from "./action-ports.js";

/**
 * Binds the commerce-action service ports to the real DB10 mutation store and
 * the DB11 read store.
 *
 * This adapter is deliberately thin and does exactly three things: it renames
 * methods, it reshapes two results into the wrapper shape the port declares,
 * and it converts the port's integer page limit back into the canonical string
 * the read store accepts. It performs NO authority, financial, transport or
 * validation work of its own — every authority decision stays in PostgreSQL and
 * every output is re-validated by the service against the accepted shared wire
 * schemas. It never widens a scope, never retries, never swallows an error and
 * never inspects a token beyond passing it straight through.
 *
 * Both store imports are type-only and therefore erased; the concrete stores
 * are injected, so the service remains testable with fakes.
 */
export function createCommerceActionStoreAdapter(
  mutations: ControlActionStore,
  reads: ControlActionReadStore,
): CommerceActionStorePort {
  return {
    /* -- DB10 mutations, names already aligned ------------------------- */

    authorizeCommerceAction(
      commerceSessionHash: unknown,
      input: CommerceActionAuthorizeInput,
      metadata: CommerceActionMutationMetadata,
    ): Promise<CommerceActionMutationDbResult> {
      return mutations.authorizeCommerceAction(commerceSessionHash, input, metadata);
    },
    approveCommerceAction(
      humanSessionHash: unknown,
      organizationId: unknown,
      actionId: unknown,
      metadata: CommerceActionMutationMetadata,
    ): Promise<CommerceActionMutationDbResult> {
      return mutations.approveCommerceAction(humanSessionHash, organizationId, actionId, metadata);
    },
    rejectCommerceAction(
      humanSessionHash: unknown,
      organizationId: unknown,
      actionId: unknown,
      metadata: CommerceActionMutationMetadata,
    ): Promise<CommerceActionMutationDbResult> {
      return mutations.rejectCommerceAction(humanSessionHash, organizationId, actionId, metadata);
    },
    cancelCommerceAction(
      humanSessionHash: unknown,
      organizationId: unknown,
      actionId: unknown,
      metadata: CommerceActionMutationMetadata,
    ): Promise<CommerceActionMutationDbResult> {
      return mutations.cancelCommerceAction(humanSessionHash, organizationId, actionId, metadata);
    },

    /* -- DB10 status and detail reads ---------------------------------- */

    getHumanCommerceActionMutationStatus(
      humanSessionHash: unknown,
      organizationId: unknown,
      mutationId: unknown,
    ): Promise<CommerceActionMutationDbStatus> {
      return mutations.getHumanMutationStatus(humanSessionHash, organizationId, mutationId);
    },
    getAgentCommerceActionMutationStatus(
      commerceSessionHash: unknown,
      mutationId: unknown,
    ): Promise<CommerceActionMutationDbStatus> {
      return mutations.getAgentMutationStatus(commerceSessionHash, mutationId);
    },

    /**
     * DB10's `readAction` returns bare metadata or null, while the port carries
     * the organization alongside it. Echoing the requested organization is safe
     * here and ONLY here because the store validates the caller's current
     * authority against that exact organization and throws otherwise — the
     * not-found path included — so a value is only ever echoed after authority
     * has already passed for it. The service still re-validates the assembled
     * shape against the accepted detail schema.
     */
    async getCommerceAction(
      humanSessionHash: unknown,
      organizationId: unknown,
      actionId: unknown,
    ): Promise<CommerceActionDetailDbResult> {
      const item = await mutations.readAction(humanSessionHash, organizationId, actionId);
      return { organizationId, item };
    },

    /**
     * The agent read derives its own organization from the presented commerce
     * session, so nothing is echoed: the store's value is used verbatim.
     */
    async getAgentCommerceAction(
      commerceSessionHash: unknown,
      actionId: unknown,
    ): Promise<CommerceActionDetailDbResult> {
      const read = await mutations.readAgentAction(commerceSessionHash, actionId);
      return { organizationId: read.organizationId, item: read.item };
    },

    /** Same echo reasoning as `getCommerceAction`; authority is checked first. */
    async getCommerceExposure(
      humanSessionHash: unknown,
      organizationId: unknown,
      subjectAgentId: unknown,
      policyId: unknown,
    ): Promise<CommerceExposureDbResult> {
      const item = await mutations.readExposure(
        humanSessionHash,
        organizationId,
        subjectAgentId,
        policyId,
      );
      return { organizationId, subjectAgentId, policyId, item };
    },

    /* -- DB11 list and detail reads ------------------------------------ */

    async listCommerceActions(
      humanSessionHash: unknown,
      organizationId: unknown,
      options?: CommerceActionListOptions,
    ): Promise<CommerceActionPageDbResult> {
      const page = await reads.listActions(
        humanSessionHash,
        organizationId,
        buildListQuery("afterActionId", options?.afterActionId, options?.limit),
      );
      return { items: page.items, nextCursor: page.nextCursor };
    },
    async listCommerceApprovals(
      humanSessionHash: unknown,
      organizationId: unknown,
      options?: CommerceApprovalListOptions,
    ): Promise<CommerceApprovalPageDbResult> {
      const page = await reads.listApprovals(
        humanSessionHash,
        organizationId,
        buildListQuery("afterApprovalId", options?.afterApprovalId, options?.limit),
      );
      return { items: page.items, nextCursor: page.nextCursor };
    },
    async getCommerceApproval(
      humanSessionHash: unknown,
      organizationId: unknown,
      approvalId: unknown,
    ): Promise<CommerceApprovalDetailDbResult> {
      const detail = await reads.readApprovalById(humanSessionHash, organizationId, approvalId);
      return { organizationId: detail.organizationId, item: detail.item };
    },
  };
}

/**
 * Binds the commerce-session read port to the real DB9/DB13 session store.
 *
 * The agent lane authenticates a commerce-session BEARER, so the service needs
 * exactly one read: presented token hash -> safe session metadata. This adapter
 * is a pure rename onto `CommerceSessionStore.getCommerceSessionByHash` and
 * nothing else. It performs NO authority, financial, transport or validation
 * work: it does not inspect, normalize, log or store the presented hash, does
 * not widen the port beyond that single method, never swallows or relabels a
 * store error (the service's own commerce-session error vocabulary depends on
 * the raw code reaching it), and never substitutes a null for a failure. The
 * service re-parses whatever comes back against the accepted shared metadata
 * schema and is the only place that judges revocation or expiry.
 *
 * The store import is type-only and therefore erased; the concrete store is
 * injected, so the binding stays testable with a fake.
 */
export function createCommerceSessionReadAdapter(
  sessions: CommerceSessionStore,
): CommerceSessionReadPort {
  return {
    getCommerceSessionByHash(tokenHash: unknown): Promise<unknown> {
      return sessions.getCommerceSessionByHash(tokenHash);
    },
  };
}

/**
 * The service hands this port an integer limit, while the read store accepts
 * the canonical wire string. Convert exactly: only an integer in 1..50 is
 * rendered, and anything else is passed through as-is so the store's own
 * validation rejects it with its fixed error rather than this adapter
 * inventing one or silently clamping a caller's page size.
 */
function buildListQuery(
  cursorKey: "afterActionId" | "afterApprovalId",
  cursor: string | undefined,
  limit: number | undefined,
): Record<string, unknown> | undefined {
  const query: Record<string, unknown> = {};
  if (cursor !== undefined) query[cursorKey] = cursor;
  if (limit !== undefined) {
    query["limit"] =
      Number.isInteger(limit) && limit >= 1 && limit <= 50 ? String(limit) : limit;
  }
  return Object.keys(query).length === 0 ? undefined : query;
}
