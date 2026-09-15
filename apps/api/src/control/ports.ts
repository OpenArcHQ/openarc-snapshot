import type {
  CommercePolicyRevision,
  CommercePolicyRoot,
} from "@openarc/shared";
import type {
  AppendPolicyRevisionInput,
  ControlPolicyMutationResult,
  ControlPolicyMutationStatus,
  ListPolicyRevisionsInput,
  ListPolicyRevisionsResult,
  ListPolicyRootsInput,
  ListPolicyRootsResult,
  PolicyRevisionSummary,
  TransitionPolicyInput,
} from "@openarc/db";

import type { TenantWriteAuthPort } from "../tenant/write-ports.js";

/**
 * Structural seam over the accepted `@openarc/db` ControlPolicyStore.
 *
 * The service depends ONLY on the eight frozen control-policy methods with
 * their exact accepted signatures. It cannot reach a raw pool, client, SQL
 * string, generic callback or non-policy operation. The concrete runtime
 * implementation is the reviewed `ControlPolicyStore`; unit tests inject an
 * honest fake. There is deliberately no `initialize`/`readiness` seam here:
 * startup readiness is the runtime packet's responsibility, not this HTTP
 * packet's.
 *
 * Metadata is the canonical `{mutationId, idempotencyKey}` pair. The raw
 * idempotency key is never logged, stored or echoed by this module.
 */

export interface ControlPolicyMutationMetadata {
  readonly idempotencyKey: string;
  readonly mutationId: string;
}

export interface ControlPolicyStorePort {
  createPolicy(
    sessionHash: string,
    organizationId: string,
    content: unknown,
    metadata: ControlPolicyMutationMetadata,
  ): Promise<ControlPolicyMutationResult>;
  appendPolicyRevision(
    sessionHash: string,
    organizationId: string,
    policyId: string,
    input: AppendPolicyRevisionInput,
    metadata: ControlPolicyMutationMetadata,
  ): Promise<ControlPolicyMutationResult>;
  transitionPolicy(
    sessionHash: string,
    organizationId: string,
    policyId: string,
    input: TransitionPolicyInput,
    metadata: ControlPolicyMutationMetadata,
  ): Promise<ControlPolicyMutationResult>;
  getPolicyRoot(
    sessionHash: string,
    organizationId: string,
    policyId: string,
  ): Promise<CommercePolicyRoot | null>;
  listPolicyRoots(
    sessionHash: string,
    organizationId: string,
    options?: ListPolicyRootsInput,
  ): Promise<ListPolicyRootsResult>;
  getPolicyRevision(
    sessionHash: string,
    organizationId: string,
    policyId: string,
    revision: string,
  ): Promise<CommercePolicyRevision | null>;
  listPolicyRevisions(
    sessionHash: string,
    organizationId: string,
    policyId: string,
    options?: ListPolicyRevisionsInput,
  ): Promise<ListPolicyRevisionsResult>;
  getPolicyMutationStatus(
    sessionHash: string,
    organizationId: string,
    mutationId: string,
  ): Promise<ControlPolicyMutationStatus>;
}

/**
 * Auth seam for the protected control family. This is EXACTLY the accepted
 * tenant write auth port: CSRF verification for writes plus the internal
 * read-session begin/finish guards. The control service introduces no new auth
 * method and never mints, rotates or clears a cookie.
 */
export type ControlPolicyAuthPort = TenantWriteAuthPort;

/** Validated response data shapes returned by the control store methods. */
export type {
  ControlPolicyMutationResult,
  ControlPolicyMutationStatus,
  PolicyRevisionSummary,
};
