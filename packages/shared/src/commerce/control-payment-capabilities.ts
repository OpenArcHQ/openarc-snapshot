import { z } from "zod";

import {
  COMMERCE_CAPABILITY_ENVIRONMENT,
  COMMERCE_CAPABILITY_NETWORK,
} from "./capabilities.js";
import { createCommerceSuccessEnvelopeSchema } from "./api.js";

/**
 * Strict, bounded, pure payment-attempt route/capability contract and the fixed
 * five-entry payment-route registry for the migration-0015 surfaces.
 *
 * Pure data only: a frozen two-family capability manifest and the exact five
 * route descriptors. No handler, transport, authorization, clock, crypto,
 * signing, sending, settlement or env read lives here, and it does not import
 * or mutate any other capability registry.
 *
 * The manifest describes route PREREQUISITES ONLY. An `enabled` payment surface
 * does NOT mean a payment was made, settled or can settle: it states only that
 * the seller terms write and the buyer attempt persistence routes exist. The
 * post-dispatch observation recorder is migrator-private and has NO route.
 *
 * Two strictly disjoint audiences, each pinned to its own prefix and credential:
 *
 *   * `browser` - `/v2/provider/organizations/` - the seller's browser session
 *     cookie with CSRF, inside the seller organization;
 *   * `agent`   - `/v2/agent/` - the exact `oacs_v1_` commerce session. The
 *     read-only `oas_ag_` machine credential is never accepted.
 */

export const PAYMENT_CAPABILITIES_PATH =
  "/v2/public/payment-capabilities" as const;

export const PAYMENT_CAPABILITY_VERSION =
  "openarc.capabilities.commerce-payments.v1" as const;

/** Closed family inventory, in authority order: seller terms, buyer attempt. */
export const PaymentCapabilityFamilySchema = z.enum([
  "commerce_payment_terms",
  "commerce_payment_attempt",
]);

export type PaymentCapabilityFamily = z.infer<
  typeof PaymentCapabilityFamilySchema
>;

export const PaymentCapabilityAudienceSchema = z.enum(["browser", "agent"]);

export type PaymentCapabilityAudience = z.infer<
  typeof PaymentCapabilityAudienceSchema
>;

/** State enum. `planned` and every unknown state are deliberately absent. */
export const PaymentCapabilityStateSchema = z.enum([
  "enabled",
  "built_disabled",
  "unavailable",
]);

export type PaymentCapabilityState = z.infer<
  typeof PaymentCapabilityStateSchema
>;

export const PaymentCapabilityDependencySchema = z.enum([
  "auth",
  "tenantDatabase",
  "machineDatabase",
  "policyDatabase",
  "commerceSessionDatabase",
  "commerceActionDatabase",
  "commerceGrantDatabase",
  "commercePaymentDatabase",
]);

export type PaymentCapabilityDependency = z.infer<
  typeof PaymentCapabilityDependencySchema
>;

export const PAYMENT_CAPABILITY_AUDIENCE: Readonly<
  Record<PaymentCapabilityFamily, PaymentCapabilityAudience>
> = Object.freeze({
  commerce_payment_terms: "browser",
  commerce_payment_attempt: "agent",
});

export const PAYMENT_CAPABILITY_AUDIENCE_PREFIX: Readonly<
  Record<PaymentCapabilityAudience, string>
> = Object.freeze({
  browser: "/v2/provider/organizations/",
  agent: "/v2/agent/",
});

export const PAYMENT_CAPABILITY_CREDENTIAL: Readonly<
  Record<PaymentCapabilityAudience, string>
> = Object.freeze({
  browser: "browser_session_cookie",
  agent: "oacs_v1_commerce_session",
});

export const PAYMENT_CAPABILITY_DEPENDENCY_ORDER: readonly PaymentCapabilityDependency[] =
  Object.freeze([
    "auth",
    "tenantDatabase",
    "machineDatabase",
    "policyDatabase",
    "commerceSessionDatabase",
    "commerceActionDatabase",
    "commerceGrantDatabase",
    "commercePaymentDatabase",
  ] as const);

export const PAYMENT_CAPABILITY_DEPENDENCY_LENGTH =
  PAYMENT_CAPABILITY_DEPENDENCY_ORDER.length;

/**
 * Both families share the full dependency list: the whole payment surface is
 * one flag and one runtime whose prerequisites are the grant and action chain.
 */
export const PAYMENT_CAPABILITY_DEPENDENCIES: Readonly<
  Record<PaymentCapabilityFamily, readonly PaymentCapabilityDependency[]>
> = Object.freeze({
  commerce_payment_terms: PAYMENT_CAPABILITY_DEPENDENCY_ORDER,
  commerce_payment_attempt: PAYMENT_CAPABILITY_DEPENDENCY_ORDER,
});

export const PAYMENT_CAPABILITY_FAMILY_ORDER: readonly PaymentCapabilityFamily[] =
  Object.freeze(["commerce_payment_terms", "commerce_payment_attempt"] as const);

const PaymentDependenciesSchema = z
  .array(PaymentCapabilityDependencySchema)
  .length(PAYMENT_CAPABILITY_DEPENDENCY_LENGTH);

export const PaymentCapabilityEntrySchema = z
  .strictObject({
    family: PaymentCapabilityFamilySchema,
    audience: PaymentCapabilityAudienceSchema,
    state: PaymentCapabilityStateSchema,
    dependencies: PaymentDependenciesSchema,
  })
  .superRefine((value, ctx) => {
    if (value.audience !== PAYMENT_CAPABILITY_AUDIENCE[value.family]) {
      ctx.addIssue({
        code: "custom",
        path: ["audience"],
        message: "Audience does not match the frozen family descriptor.",
      });
    }
    const expected = PAYMENT_CAPABILITY_DEPENDENCIES[value.family];
    if (
      value.dependencies.length !== expected.length ||
      value.dependencies.some(
        (dependency, index) => dependency !== expected[index],
      )
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["dependencies"],
        message: "Dependencies do not match the frozen family descriptor.",
      });
    }
  });

export type PaymentCapabilityEntry = z.infer<
  typeof PaymentCapabilityEntrySchema
>;

interface FrozenPaymentRoute {
  readonly id: string;
  readonly family: PaymentCapabilityFamily;
  readonly audience: PaymentCapabilityAudience;
  readonly method: "GET" | "POST";
  readonly path: string;
}

export const PaymentRouteDescriptorSchema = z
  .strictObject({
    id: z.string().regex(/^[a-z][a-z0-9_]*(?![\s\S])/u),
    family: PaymentCapabilityFamilySchema,
    audience: PaymentCapabilityAudienceSchema,
    method: z.enum(["GET", "POST"]),
    path: z.string().min(1).max(512),
  })
  .superRefine((value, ctx) => {
    if (value.audience !== PAYMENT_CAPABILITY_AUDIENCE[value.family]) {
      ctx.addIssue({
        code: "custom",
        path: ["audience"],
        message: "Route audience does not match the frozen family descriptor.",
      });
    }
    if (
      !value.path.startsWith(PAYMENT_CAPABILITY_AUDIENCE_PREFIX[value.audience])
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["path"],
        message: "Route path does not start with its frozen audience prefix.",
      });
    }
    if (!Object.hasOwn(PAYMENT_ROUTE_INDEX, value.id)) {
      ctx.addIssue({
        code: "custom",
        path: ["id"],
        message: "Route id is not part of the frozen registry.",
      });
      return;
    }
    const expected = PAYMENT_ROUTE_INDEX[value.id];
    if (
      expected === undefined ||
      value.family !== expected.family ||
      value.audience !== expected.audience ||
      value.method !== expected.method ||
      value.path !== expected.path
    ) {
      ctx.addIssue({
        code: "custom",
        message:
          "Route descriptor does not match the frozen id/family/audience/method/path entry.",
      });
    }
  });

export type PaymentRouteDescriptor = z.infer<
  typeof PaymentRouteDescriptorSchema
>;

const PAYMENT_AGENT_BASE = "/v2/agent";
const PAYMENT_PROVIDER_BASE = "/v2/provider/organizations";

/**
 * The frozen payment-route inventory: 1 commerce_payment_terms (browser) + 4
 * commerce_payment_attempt (agent) = 5 entries. No path is mixed-method. No
 * observation, settlement, release or refund route exists.
 */
export const PAYMENT_ROUTES: readonly PaymentRouteDescriptor[] = Object.freeze(
  (
    [
      { id: "listing_payment_terms_record", family: "commerce_payment_terms", audience: "browser", method: "POST", path: `${PAYMENT_PROVIDER_BASE}/:organizationId/listings/:listingId/versions/:version/payment-terms` },
      { id: "payment_requirement_register", family: "commerce_payment_attempt", audience: "agent", method: "POST", path: `${PAYMENT_AGENT_BASE}/commerce-payment-requirements` },
      { id: "payment_attempt_persist", family: "commerce_payment_attempt", audience: "agent", method: "POST", path: `${PAYMENT_AGENT_BASE}/commerce-payment-attempts` },
      { id: "payment_attempt_dispatch", family: "commerce_payment_attempt", audience: "agent", method: "POST", path: `${PAYMENT_AGENT_BASE}/commerce-payment-attempts/:attemptId/dispatch` },
      { id: "payment_attempt_detail", family: "commerce_payment_attempt", audience: "agent", method: "GET", path: `${PAYMENT_AGENT_BASE}/commerce-payment-attempts/:attemptId` },
    ] satisfies readonly FrozenPaymentRoute[]
  ).map((route) => Object.freeze(route)),
);

export const PAYMENT_ROUTE_INDEX: Readonly<Record<string, FrozenPaymentRoute>> =
  Object.freeze(
    PAYMENT_ROUTES.reduce<Record<string, FrozenPaymentRoute>>(
      (accumulator, route) => {
        accumulator[route.id] = route;
        return accumulator;
      },
      {},
    ),
  );

export const PAYMENT_ROUTE_IDS: readonly string[] = Object.freeze(
  PAYMENT_ROUTES.map((route) => route.id),
);

export const PaymentCapabilityManifestSchema = z
  .strictObject({
    capabilityVersion: z.literal(PAYMENT_CAPABILITY_VERSION),
    environment: z.literal(COMMERCE_CAPABILITY_ENVIRONMENT),
    network: z.literal(COMMERCE_CAPABILITY_NETWORK),
    capabilities: z.array(PaymentCapabilityEntrySchema).length(2),
    routes: z.array(PaymentRouteDescriptorSchema).length(5),
  })
  .superRefine((value, ctx) => {
    for (const [index, family] of PAYMENT_CAPABILITY_FAMILY_ORDER.entries()) {
      if (value.capabilities[index]?.family !== family) {
        ctx.addIssue({
          code: "custom",
          path: ["capabilities", index, "family"],
          message: `Family at index ${index} must be ${family}.`,
        });
      }
    }
    const firstState = value.capabilities[0]?.state;
    for (const [index, entry] of value.capabilities.entries()) {
      if (entry.state !== firstState) {
        ctx.addIssue({
          code: "custom",
          path: ["capabilities", index, "state"],
          message:
            "All payment entries must share one state from a single flag/runtime.",
        });
      }
    }
    for (const [index, id] of PAYMENT_ROUTE_IDS.entries()) {
      if (value.routes[index]?.id !== id) {
        ctx.addIssue({
          code: "custom",
          path: ["routes", index, "id"],
          message: `Route at index ${index} must be ${id}.`,
        });
      }
    }
  });

export type PaymentCapabilityManifest = z.infer<
  typeof PaymentCapabilityManifestSchema
>;

export const PaymentCapabilitiesSuccessEnvelopeSchema =
  createCommerceSuccessEnvelopeSchema(PaymentCapabilityManifestSchema);

export type PaymentCapabilitiesSuccessEnvelope = z.infer<
  typeof PaymentCapabilitiesSuccessEnvelopeSchema
>;
