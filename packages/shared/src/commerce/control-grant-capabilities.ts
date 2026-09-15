import { z } from "zod";

import {
  COMMERCE_CAPABILITY_ENVIRONMENT,
  COMMERCE_CAPABILITY_NETWORK,
} from "./capabilities.js";
import { createCommerceSuccessEnvelopeSchema } from "./api.js";

/**
 * Strict, bounded, pure authorization-grant route/capability contract and
 * fixed nine-entry grant-route registry.
 *
 * This module publishes a pure data contract only: a frozen three-family
 * capability manifest and the exact nine authorization-grant route
 * descriptors. It contains no route handlers, no transport, no authorization,
 * no request dispatch, no database/network access, no clock, no crypto, no
 * token handling, no runtime registration/reflection and no builder, env read
 * or runtime decision of any kind. It does not import or mutate the legacy
 * commerce capability registry (5 families / 41 routes), the marketplace
 * capability registry (3 families / 18 routes), the control capability
 * registry (1 family / 10 routes), the commerce-session capability registry
 * (2 families / 7 routes) or the commerce-action capability registry
 * (2 families / 12 routes); its constants are separate.
 *
 * The manifest describes route PREREQUISITES ONLY, never a permission and
 * never a verified requirement. An enabled GRANT surface does NOT mean a
 * listing payment lane is usable, that a grant can actually be issued, that a
 * claim will be accepted or that any payment, settlement or delivery can
 * occur; the listing paymentLane remains unavailable and production grant
 * issuance/introspection/claim still reject unverified requirements and
 * internal fixture provenance. This frozen registry makes no runtime
 * availability or wallet-wide control claim.
 *
 * Audience separation is part of the contract, not a deployment detail. The
 * three audiences are strictly disjoint and each is pinned to its own
 * non-overlapping path prefix and its own credential class:
 *
 *   * `browser`  - `/v2/control/organizations/` - browser session cookie
 *     inside the buyer organization;
 *   * `agent`    - `/v2/agent/` - the exact `oacs_v1_` commerce session;
 *   * `provider` - `/v2/provider/grant` - BOTH a live `oas_pr_` provider
 *     session AND the buyer's exact one-use `oag_v1_` grant token.
 *
 * A browser cookie therefore cannot authorize a provider or an agent route,
 * and the two-token provider requirement cannot be satisfied by a session
 * alone. The provider grant prefix is deliberately `/v2/provider/grant`, which
 * is disjoint from the existing browser-audience listing-management prefix
 * `/v2/provider/organizations/`, so no provider grant route can ever be served
 * by the seller browser lane.
 */

export const GRANT_CAPABILITIES_PATH =
  "/v2/public/grant-capabilities" as const;

export const GRANT_CAPABILITY_VERSION =
  "openarc.capabilities.commerce-grants.v1" as const;

/**
 * Closed family inventory: exactly three ordered grant families, in the order
 * authority actually flows - an agent issues, a provider claims, a human
 * revokes and reads.
 */
export const GrantCapabilityFamilySchema = z.enum([
  "commerce_grant_authorization",
  "commerce_grant_claim",
  "commerce_grant_management",
]);

export type GrantCapabilityFamily = z.infer<typeof GrantCapabilityFamilySchema>;

/**
 * Grant audiences: authorization is agent, claim is provider, management is
 * browser. These three are mutually exclusive; no route is served to more than
 * one of them.
 */
export const GrantCapabilityAudienceSchema = z.enum([
  "browser",
  "agent",
  "provider",
]);

export type GrantCapabilityAudience = z.infer<
  typeof GrantCapabilityAudienceSchema
>;

/** State enum. `planned` and every unknown state are deliberately absent. */
export const GrantCapabilityStateSchema = z.enum([
  "enabled",
  "built_disabled",
  "unavailable",
]);

export type GrantCapabilityState = z.infer<typeof GrantCapabilityStateSchema>;

export const GrantCapabilityDependencySchema = z.enum([
  "auth",
  "tenantDatabase",
  "machineDatabase",
  "policyDatabase",
  "commerceSessionDatabase",
  "commerceActionDatabase",
  "commerceGrantDatabase",
]);

export type GrantCapabilityDependency = z.infer<
  typeof GrantCapabilityDependencySchema
>;

/** Exact frozen audience per family. */
export const GRANT_CAPABILITY_AUDIENCE: Readonly<
  Record<GrantCapabilityFamily, GrantCapabilityAudience>
> = Object.freeze({
  commerce_grant_authorization: "agent",
  commerce_grant_claim: "provider",
  commerce_grant_management: "browser",
});

/**
 * Exact frozen path prefix per audience. Every frozen route path below starts
 * with the prefix of its own audience, and no prefix is a prefix of another,
 * so the audience of a grant route is decidable from its path alone.
 */
export const GRANT_CAPABILITY_AUDIENCE_PREFIX: Readonly<
  Record<GrantCapabilityAudience, string>
> = Object.freeze({
  browser: "/v2/control/organizations/",
  agent: "/v2/agent/",
  provider: "/v2/provider/grant",
});

/**
 * The existing browser-audience listing-management prefix. No provider grant
 * route may live under it; the manifest enforces that explicitly so a seller
 * browser cookie can never reach a headless provider grant endpoint.
 */
export const GRANT_PROVIDER_FORBIDDEN_PREFIX =
  "/v2/provider/organizations/" as const;

/**
 * Exact frozen credential class per audience, stated so the manifest names the
 * two-token provider requirement rather than implying it. These are labels for
 * a reader and a reviewer; this module authenticates nothing.
 */
export const GRANT_CAPABILITY_CREDENTIAL: Readonly<
  Record<GrantCapabilityAudience, string>
> = Object.freeze({
  browser: "browser_session_cookie",
  agent: "oacs_v1_commerce_session",
  provider: "oas_pr_provider_session+oag_v1_grant_token",
});

/** Exactly the seven frozen dependency tokens, in the frozen order. */
export const GRANT_CAPABILITY_DEPENDENCY_ORDER: readonly GrantCapabilityDependency[] =
  Object.freeze([
    "auth",
    "tenantDatabase",
    "machineDatabase",
    "policyDatabase",
    "commerceSessionDatabase",
    "commerceActionDatabase",
    "commerceGrantDatabase",
  ] as const);

export const GRANT_CAPABILITY_DEPENDENCY_LENGTH =
  GRANT_CAPABILITY_DEPENDENCY_ORDER.length;

/**
 * Exact closed dependency arrays, in the frozen order, for all three families.
 * Every grant operation - including a provider claim - runs the one combined
 * lock order over the buyer action, reservation, policy and commerce session
 * as well as the seller/provider rows, so no family has a shorter list.
 */
export const GRANT_CAPABILITY_DEPENDENCIES: Readonly<
  Record<GrantCapabilityFamily, readonly GrantCapabilityDependency[]>
> = Object.freeze({
  commerce_grant_authorization: GRANT_CAPABILITY_DEPENDENCY_ORDER,
  commerce_grant_claim: GRANT_CAPABILITY_DEPENDENCY_ORDER,
  commerce_grant_management: GRANT_CAPABILITY_DEPENDENCY_ORDER,
});

/** Fixed deterministic family order for the manifest array. */
export const GRANT_CAPABILITY_FAMILY_ORDER: readonly GrantCapabilityFamily[] =
  Object.freeze([
    "commerce_grant_authorization",
    "commerce_grant_claim",
    "commerce_grant_management",
  ] as const);

const GrantDependenciesSchema = z
  .array(GrantCapabilityDependencySchema)
  .length(GRANT_CAPABILITY_DEPENDENCY_LENGTH);

export const GrantCapabilityEntrySchema = z
  .strictObject({
    family: GrantCapabilityFamilySchema,
    audience: GrantCapabilityAudienceSchema,
    state: GrantCapabilityStateSchema,
    dependencies: GrantDependenciesSchema,
  })
  .superRefine((value, ctx) => {
    if (value.audience !== GRANT_CAPABILITY_AUDIENCE[value.family]) {
      ctx.addIssue({
        code: "custom",
        path: ["audience"],
        message: "Audience does not match the frozen family descriptor.",
      });
    }
    const expected = GRANT_CAPABILITY_DEPENDENCIES[value.family];
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

export type GrantCapabilityEntry = z.infer<typeof GrantCapabilityEntrySchema>;

/**
 * One frozen grant route descriptor. The entire tuple is validated against the
 * canonical registry below, not merely the `id` shape. The registry lookup is
 * own-property only, so inherited names (`toString`, `constructor`,
 * `__proto__`, `hasOwnProperty`, ...) are rejected as unknown ids. The path is
 * additionally checked against the frozen audience prefix, and a provider
 * route under the browser listing-management prefix is rejected outright.
 */
export const GrantRouteDescriptorSchema = z
  .strictObject({
    id: z.string().regex(/^[a-z][a-z0-9_]*(?![\s\S])/u),
    family: GrantCapabilityFamilySchema,
    audience: GrantCapabilityAudienceSchema,
    method: z.enum(["GET", "POST"]),
    path: z.string().min(1).max(512),
  })
  .superRefine((value, ctx) => {
    if (value.audience !== GRANT_CAPABILITY_AUDIENCE[value.family]) {
      ctx.addIssue({
        code: "custom",
        path: ["audience"],
        message: "Route audience does not match the frozen family descriptor.",
      });
    }
    if (!value.path.startsWith(GRANT_CAPABILITY_AUDIENCE_PREFIX[value.audience])) {
      ctx.addIssue({
        code: "custom",
        path: ["path"],
        message: "Route path does not start with its frozen audience prefix.",
      });
    }
    if (
      value.audience === "provider" &&
      value.path.startsWith(GRANT_PROVIDER_FORBIDDEN_PREFIX)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["path"],
        message:
          "A provider grant route may not live under the browser listing-management prefix.",
      });
    }
    if (!Object.hasOwn(GRANT_ROUTE_INDEX, value.id)) {
      ctx.addIssue({
        code: "custom",
        path: ["id"],
        message: "Route id is not part of the frozen registry.",
      });
      return;
    }
    const expected = GRANT_ROUTE_INDEX[value.id];
    if (expected === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["id"],
        message: "Route id is not part of the frozen registry.",
      });
      return;
    }
    if (
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

export type GrantRouteDescriptor = z.infer<typeof GrantRouteDescriptorSchema>;

interface FrozenGrantRoute {
  readonly id: string;
  readonly family: GrantCapabilityFamily;
  readonly audience: GrantCapabilityAudience;
  readonly method: "GET" | "POST";
  readonly path: string;
}

const GRANT_AGENT_BASE = "/v2/agent";
const GRANT_PROVIDER_BASE = "/v2/provider";
const GRANT_CONTROL_BASE = "/v2/control/organizations";

/**
 * The frozen grant-route inventory: exactly 3 commerce_grant_authorization
 * (agent) + 3 commerce_grant_claim (provider) + 3 commerce_grant_management
 * (browser) = 9 entries. Paths use exact camelCase `:parameter` templates. GET
 * and POST are the only methods.
 *
 * Both provider grant routes that consume the buyer's one-use `oag_v1_` token
 * are POST even though introspection is read-only: a raw grant secret must
 * never appear in a path, a query string, a log line or a referrer.
 *
 * Provider attempt-status recovery is keyed ONLY by the provider's own attempt
 * id, so a missing attempt and a foreign attempt are indistinguishable.
 *
 * No capability/manifest/health/fallback descriptor exists here, no grant list
 * or page route exists (the accepted store exposes no list method), and no
 * payment, settlement, delivery or refund route is added.
 */
export const GRANT_ROUTES: readonly GrantRouteDescriptor[] = Object.freeze(
  (
    [
      { id: "grant_issue", family: "commerce_grant_authorization", audience: "agent", method: "POST", path: `${GRANT_AGENT_BASE}/commerce-grants` },
      { id: "grant_replace", family: "commerce_grant_authorization", audience: "agent", method: "POST", path: `${GRANT_AGENT_BASE}/commerce-grants/:grantId/replace` },
      { id: "agent_grant_mutation_status", family: "commerce_grant_authorization", audience: "agent", method: "GET", path: `${GRANT_AGENT_BASE}/commerce-grant-mutations/:mutationId` },
      { id: "provider_grant_introspect", family: "commerce_grant_claim", audience: "provider", method: "POST", path: `${GRANT_PROVIDER_BASE}/grants/introspect` },
      { id: "provider_grant_claim", family: "commerce_grant_claim", audience: "provider", method: "POST", path: `${GRANT_PROVIDER_BASE}/grants/claim` },
      { id: "provider_grant_attempt_status", family: "commerce_grant_claim", audience: "provider", method: "GET", path: `${GRANT_PROVIDER_BASE}/grant-attempts/:attemptId` },
      { id: "grant_detail", family: "commerce_grant_management", audience: "browser", method: "GET", path: `${GRANT_CONTROL_BASE}/:organizationId/grants/:grantId` },
      { id: "grant_mutation_status", family: "commerce_grant_management", audience: "browser", method: "GET", path: `${GRANT_CONTROL_BASE}/:organizationId/grant-mutations/:mutationId` },
      { id: "grant_revoke", family: "commerce_grant_management", audience: "browser", method: "POST", path: `${GRANT_CONTROL_BASE}/:organizationId/grants/:grantId/revoke` },
    ] satisfies readonly FrozenGrantRoute[]
  ).map((route) => Object.freeze(route)),
);

/** Exact-id index used by the strict own-property lookup (not a mutable map). */
export const GRANT_ROUTE_INDEX: Readonly<Record<string, FrozenGrantRoute>> =
  Object.freeze(
    GRANT_ROUTES.reduce<Record<string, FrozenGrantRoute>>(
      (accumulator, route) => {
        accumulator[route.id] = route;
        return accumulator;
      },
      {},
    ),
  );

export const GRANT_ROUTE_IDS: readonly string[] = Object.freeze(
  GRANT_ROUTES.map((route) => route.id),
);

export const GrantCapabilityManifestSchema = z
  .strictObject({
    capabilityVersion: z.literal(GRANT_CAPABILITY_VERSION),
    environment: z.literal(COMMERCE_CAPABILITY_ENVIRONMENT),
    network: z.literal(COMMERCE_CAPABILITY_NETWORK),
    capabilities: z.array(GrantCapabilityEntrySchema).length(3),
    routes: z.array(GrantRouteDescriptorSchema).length(9),
  })
  .superRefine((value, ctx) => {
    // Exact family inventory: each frozen family once, no extra/omitted.
    const seen = new Set<GrantCapabilityFamily>();
    for (const [index, entry] of value.capabilities.entries()) {
      if (seen.has(entry.family)) {
        ctx.addIssue({
          code: "custom",
          path: ["capabilities", index, "family"],
          message: "Family may appear only once.",
        });
      }
      seen.add(entry.family);
    }
    for (const family of GRANT_CAPABILITY_FAMILY_ORDER) {
      if (!seen.has(family)) {
        ctx.addIssue({
          code: "custom",
          path: ["capabilities"],
          message: `Missing family ${family}.`,
        });
      }
    }
    // Exact positional order: a reordered family array is rejected even when
    // every family is present exactly once.
    for (const [index, family] of GRANT_CAPABILITY_FAMILY_ORDER.entries()) {
      if (value.capabilities[index]?.family !== family) {
        ctx.addIssue({
          code: "custom",
          path: ["capabilities", index, "family"],
          message: `Family at index ${index} must be ${family}.`,
        });
      }
    }
    // The three audiences stay strictly separate: no audience may be claimed
    // by two families, so a browser cookie can never cover an agent or a
    // provider family.
    const audienceSeen = new Set<GrantCapabilityAudience>();
    for (const [index, entry] of value.capabilities.entries()) {
      if (audienceSeen.has(entry.audience)) {
        ctx.addIssue({
          code: "custom",
          path: ["capabilities", index, "audience"],
          message: "Audience may be claimed by only one family.",
        });
      }
      audienceSeen.add(entry.audience);
    }
    // Every grant entry shares its state (one future flag/runtime): a
    // mismatched state is rejected outright.
    const firstState = value.capabilities[0]?.state;
    if (firstState !== undefined) {
      for (const [index, entry] of value.capabilities.entries()) {
        if (entry.state !== firstState) {
          ctx.addIssue({
            code: "custom",
            path: ["capabilities", index, "state"],
            message:
              "All grant entries must share one state from a single flag/runtime.",
          });
        }
      }
    }
    // Exact route inventory: each frozen id once, no extra/omitted.
    const routeSeen = new Set<string>();
    for (const [index, route] of value.routes.entries()) {
      if (routeSeen.has(route.id)) {
        ctx.addIssue({
          code: "custom",
          path: ["routes", index, "id"],
          message: "Route id may appear only once.",
        });
      }
      routeSeen.add(route.id);
    }
    for (const id of GRANT_ROUTE_IDS) {
      if (!routeSeen.has(id)) {
        ctx.addIssue({
          code: "custom",
          path: ["routes"],
          message: `Missing route ${id}.`,
        });
      }
    }
    // Exact positional order: a reordered route array is rejected even when
    // every frozen id is present exactly once.
    for (const [index, id] of GRANT_ROUTE_IDS.entries()) {
      if (value.routes[index]?.id !== id) {
        ctx.addIssue({
          code: "custom",
          path: ["routes", index, "id"],
          message: `Route at index ${index} must be ${id}.`,
        });
      }
    }
    // Every declared route belongs to a declared family, so no route can be
    // published on an audience the manifest never declared.
    const declaredFamilies = new Set(
      value.capabilities.map((entry) => entry.family),
    );
    for (const [index, route] of value.routes.entries()) {
      if (!declaredFamilies.has(route.family)) {
        ctx.addIssue({
          code: "custom",
          path: ["routes", index, "family"],
          message: "Route family is not declared in this manifest.",
        });
      }
    }
  });

export type GrantCapabilityManifest = z.infer<
  typeof GrantCapabilityManifestSchema
>;

export const GrantCapabilitiesSuccessEnvelopeSchema =
  createCommerceSuccessEnvelopeSchema(GrantCapabilityManifestSchema);

export type GrantCapabilitiesSuccessEnvelope = z.infer<
  typeof GrantCapabilitiesSuccessEnvelopeSchema
>;

/** One shared published state for all entries (single future flag/runtime). */
export const GRANT_CAPABILITY_STATE: GrantCapabilityState = "enabled";

const GRANT_ENTRY_DEPENDENCIES: GrantCapabilityDependency[] = [
  "auth",
  "tenantDatabase",
  "machineDatabase",
  "policyDatabase",
  "commerceSessionDatabase",
  "commerceActionDatabase",
  "commerceGrantDatabase",
];
Object.freeze(GRANT_ENTRY_DEPENDENCIES);

/** The three frozen grant entries, at their fixed shared published state. */
export const GRANT_CAPABILITY_ENTRIES: readonly GrantCapabilityEntry[] =
  Object.freeze([
    Object.freeze({
      family: "commerce_grant_authorization",
      audience: "agent",
      state: GRANT_CAPABILITY_STATE,
      dependencies: GRANT_ENTRY_DEPENDENCIES,
    }),
    Object.freeze({
      family: "commerce_grant_claim",
      audience: "provider",
      state: GRANT_CAPABILITY_STATE,
      dependencies: GRANT_ENTRY_DEPENDENCIES,
    }),
    Object.freeze({
      family: "commerce_grant_management",
      audience: "browser",
      state: GRANT_CAPABILITY_STATE,
      dependencies: GRANT_ENTRY_DEPENDENCIES,
    }),
  ]);

/**
 * Parsed manifest backstop. Zod clones its input, so the structured values
 * below are distinct objects; every layer is frozen explicitly (arrays,
 * entries, dependency arrays, route descriptors) before publication. The
 * exported constant is therefore deeply immutable at runtime.
 */
const PARSED_GRANT_CAPABILITY_MANIFEST = GrantCapabilityManifestSchema.parse({
  capabilityVersion: GRANT_CAPABILITY_VERSION,
  environment: COMMERCE_CAPABILITY_ENVIRONMENT,
  network: COMMERCE_CAPABILITY_NETWORK,
  capabilities: GRANT_CAPABILITY_ENTRIES,
  routes: GRANT_ROUTES,
});

for (const entry of PARSED_GRANT_CAPABILITY_MANIFEST.capabilities) {
  Object.freeze(entry.dependencies);
  Object.freeze(entry);
}
Object.freeze(PARSED_GRANT_CAPABILITY_MANIFEST.capabilities);
for (const route of PARSED_GRANT_CAPABILITY_MANIFEST.routes) {
  Object.freeze(route);
}
Object.freeze(PARSED_GRANT_CAPABILITY_MANIFEST.routes);

/**
 * Frozen full grant capability manifest. This is pure constant data: no
 * builder, no runtime decision, no process.env/network/DB access and no caller
 * extension. The structured parse above fails closed if the module constants
 * ever drift, and every nested layer is frozen before this export is visible.
 *
 * Publishing this manifest enables no payment lane. An `enabled` grant family
 * states only that the route prerequisites exist.
 */
export const GRANT_CAPABILITY_MANIFEST: GrantCapabilityManifest = Object.freeze(
  PARSED_GRANT_CAPABILITY_MANIFEST,
);
