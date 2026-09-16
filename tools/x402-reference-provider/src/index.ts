/**
 * `@openarc/x402-reference-provider` — a loopback reference x402 provider plus
 * the LOCAL FAKE facilitator the offline suites inject into the transport seam
 * of `packages/x402`.
 *
 * Nothing here contacts Circle, Gateway or Arc, signs a buyer payment or moves
 * funds. The fakes are test doubles and prove no settlement.
 */
export {
  REFERENCE_INPUT_SCHEMA,
  REFERENCE_OUTPUT_SCHEMA,
  startReferenceProvider,
  type ReferenceProvider,
  type ReferenceProviderCounts,
  type ReferenceProviderOptions,
} from "./provider.js";
export {
  createProviderClaimClient,
  type GrantClaim,
  type GrantClaimInput,
  type GrantClaimResult,
  type ProviderClaimClientOptions,
} from "./claim-client.js";
export { createIdempotencyKey } from "./idempotency.js";
export {
  ReferenceProviderError,
  assertLoopbackBaseUrl,
  type ProviderRefusalCode,
} from "./loopback.js";
export {
  startFakeFacilitator,
  type FakeFacilitator,
  type FakeFacilitatorBehaviour,
  type FakeFacilitatorCounts,
  type FakeLookupBehaviour,
  type FakeSettleBehaviour,
} from "./fakes/facilitator.js";
export { createFakeFacilitatorFetch } from "./fakes/facilitator-fetch.js";
