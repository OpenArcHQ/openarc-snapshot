import { z } from "zod";

import {
  COMMERCE_CAPABILITY_ENVIRONMENT,
  COMMERCE_CAPABILITY_NETWORK,
} from "./capabilities.js";
import { createCommerceSuccessEnvelopeSchema } from "./api.js";

/**
 * Strict, bounded, pure commerce-session route/capability contract and fixed
 * seven-entry session-route registry.
 *
 * This module publishes a pure data contract only: a frozen two-family
 * capability manifest and the exact seven commerce-session route descriptors.
 * It contains no route handlers, no transport, no authorization, no request
 * dispatch, no database/network access, no clock and no runtime
 * registration/reflection (there is deliberately no builder, no env read and
 * no runtime decision of any kind). It does not import or mutate the legacy
 * commerce capability registry (5 families / 41 routes), the marketplace
 * capability registry (3 families / 18 routes) or the control capability
 * registry (1 family / 10 routes); its constants are separate.
 *
 * The contract is frozen for the current session release. The entries describe
 * PREREQUISITES ONLY. Availability here does NOT grant a role, expose a live
 * API route, claim mainnet support, or confer payment/execution authority of
 * any kind.
 */

export const SESSION_CAPABILITIES_PATH =
  "/v2/public/session-capabilities" as const;

export const SESSION_CAPABILITY_VERSION =
  "openarc.capabilities.commerce-sessions.v1" as const;

/** Closed family inventory: exactly two ordered session families. */
export const SessionCapabilityFamilySchema = z.enum([
  "commerce_session_management",
  "commerce_session_exchange",
]);

export type SessionCapabilityFamily = z.infer<
  typeof SessionCapabilityFamilySchema
>;

/** Session audiences: management is browser, exchange is agent. */
export const SessionCapabilityAudienceSchema = z.enum(["browser", "agent"]);

export type SessionCapabilityAudience = z.infer<
  typeof SessionCapabilityAudienceSchema
>;

/** State enum. `planned` and every unknown state are deliberately absent. */
export const SessionCapabilityStateSchema = z.enum([
  "enabled",
  "built_disabled",
  "unavailable",
]);

export type SessionCapabilityState = z.infer<
  typeof SessionCapabilityStateSchema
>;

export const SessionCapabilityDependencySchema = z.enum([
  "auth",
  "tenantDatabase",
  "machineDatabase",
  "policyDatabase",
  "commerceSessionDatabase",
]);

export type SessionCapabilityDependency = z.infer<
  typeof SessionCapabilityDependencySchema
>;

/** Exact frozen audience per family. */
export const SESSION_CAPABILITY_AUDIENCE: Readonly<
  Record<SessionCapabilityFamily, SessionCapabilityAudience>
> = Object.freeze({
  commerce_session_management: "browser",
  commerce_session_exchange: "agent",
});

/** Exact closed dependency arrays, in the frozen order, for both families. */
export const SESSION_CAPABILITY_DEPENDENCIES: Readonly<
  Record<SessionCapabilityFamily, readonly SessionCapabilityDependency[]>
> = Object.freeze({
  commerce_session_management: Object.freeze([
    "auth",
    "tenantDatabase",
    "machineDatabase",
    "policyDatabase",
    "commerceSessionDatabase",
  ] as const),
  commerce_session_exchange: Object.freeze([
    "auth",
    "tenantDatabase",
    "machineDatabase",
    "policyDatabase",
    "commerceSessionDatabase",
  ] as const),
});

/** Fixed deterministic family order for the manifest array. */
export const SESSION_CAPABILITY_FAMILY_ORDER: readonly SessionCapabilityFamily[] =
  Object.freeze([
    "commerce_session_management",
    "commerce_session_exchange",
  ] as const);

/** Exactly the five frozen dependency tokens, in the frozen order. */
export const SESSION_CAPABILITY_DEPENDENCY_ORDER: readonly SessionCapabilityDependency[] =
  Object.freeze([
    "auth",
    "tenantDatabase",
    "machineDatabase",
    "policyDatabase",
    "commerceSessionDatabase",
  ] as const);

export const SESSION_CAPABILITY_DEPENDENCY_LENGTH =
  SESSION_CAPABILITY_DEPENDENCY_ORDER.length;

const SessionDependenciesSchema = z
  .array(SessionCapabilityDependencySchema)
  .length(SESSION_CAPABILITY_DEPENDENCY_LENGTH);

export const SessionCapabilityEntrySchema = z
  .strictObject({
    family: SessionCapabilityFamilySchema,
    audience: SessionCapabilityAudienceSchema,
    state: SessionCapabilityStateSchema,
    dependencies: SessionDependenciesSchema,
  })
  .superRefine((value, ctx) => {
    if (value.audience !== SESSION_CAPABILITY_AUDIENCE[value.family]) {
      ctx.addIssue({
        code: "custom",
        path: ["audience"],
        message: "Audience does not match the frozen family descriptor.",
      });
    }
    const expected = SESSION_CAPABILITY_DEPENDENCIES[value.family];
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

export type SessionCapabilityEntry = z.infer<
  typeof SessionCapabilityEntrySchema
>;

/**
 * One frozen session route descriptor. The entire tuple is validated against
 * the canonical registry below, not merely the `id` shape. The registry
 * lookup is own-property only, so inherited names (`toString`, `constructor`,
 * `__proto__`, ...) are rejected as unknown ids.
 */
export const SessionRouteDescriptorSchema = z
  .strictObject({
    id: z.string().regex(/^[a-z][a-z0-9_]*$/u),
    family: SessionCapabilityFamilySchema,
    audience: SessionCapabilityAudienceSchema,
    method: z.enum(["GET", "POST"]),
    path: z.string().min(1).max(512),
  })
  .superRefine((value, ctx) => {
    if (value.audience !== SESSION_CAPABILITY_AUDIENCE[value.family]) {
      ctx.addIssue({
        code: "custom",
        path: ["audience"],
        message: "Route audience does not match the frozen family descriptor.",
      });
    }
    if (!Object.hasOwn(SESSION_ROUTE_INDEX, value.id)) {
      ctx.addIssue({
        code: "custom",
        path: ["id"],
        message: "Route id is not part of the frozen registry.",
      });
      return;
    }
    const expected = SESSION_ROUTE_INDEX[value.id];
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

export type SessionRouteDescriptor = z.infer<
  typeof SessionRouteDescriptorSchema
>;

interface FrozenSessionRoute {
  readonly id: string;
  readonly family: SessionCapabilityFamily;
  readonly audience: SessionCapabilityAudience;
  readonly method: "GET" | "POST";
  readonly path: string;
}

const SESSION_CONTROL_BASE = "/v2/control/organizations";
const SESSION_AGENT_BASE = "/v2/agent";

/**
 * The frozen session-route inventory: exactly 5 commerce_session_management
 * (browser) + 2 commerce_session_exchange (agent) = 7 entries. Paths use exact
 * camelCase `:parameter` templates. GET and POST are the only methods. No
 * capability/manifest/health/fallback, grant or payment descriptor exists
 * here.
 */
export const SESSION_ROUTES: readonly SessionRouteDescriptor[] = Object.freeze(
  (
    [
      { id: "commerce_session_list", family: "commerce_session_management", audience: "browser", method: "GET", path: `${SESSION_CONTROL_BASE}/:organizationId/commerce-sessions` },
      { id: "commerce_session_issue", family: "commerce_session_management", audience: "browser", method: "POST", path: `${SESSION_CONTROL_BASE}/:organizationId/commerce-sessions` },
      { id: "commerce_session_status", family: "commerce_session_management", audience: "browser", method: "GET", path: `${SESSION_CONTROL_BASE}/:organizationId/commerce-sessions/:sessionId` },
      { id: "commerce_session_revoke", family: "commerce_session_management", audience: "browser", method: "POST", path: `${SESSION_CONTROL_BASE}/:organizationId/commerce-sessions/:sessionId/revoke` },
      { id: "commerce_session_human_mutation_status", family: "commerce_session_management", audience: "browser", method: "GET", path: `${SESSION_CONTROL_BASE}/:organizationId/commerce-session-mutations/:mutationId` },
      { id: "commerce_session_exchange", family: "commerce_session_exchange", audience: "agent", method: "POST", path: `${SESSION_AGENT_BASE}/commerce-sessions/exchange` },
      { id: "commerce_session_agent_mutation_status", family: "commerce_session_exchange", audience: "agent", method: "GET", path: `${SESSION_AGENT_BASE}/commerce-session-mutations/:mutationId` },
    ] satisfies readonly FrozenSessionRoute[]
  ).map((route) => Object.freeze(route)),
);

/** Exact-id index used by the strict own-property lookup (not a mutable map). */
export const SESSION_ROUTE_INDEX: Readonly<
  Record<string, FrozenSessionRoute>
> = Object.freeze(
  SESSION_ROUTES.reduce<Record<string, FrozenSessionRoute>>(
    (accumulator, route) => {
      accumulator[route.id] = route;
      return accumulator;
    },
    {},
  ),
);

export const SESSION_ROUTE_IDS: readonly string[] = Object.freeze(
  SESSION_ROUTES.map((route) => route.id),
);

export const SessionCapabilityManifestSchema = z
  .strictObject({
    capabilityVersion: z.literal(SESSION_CAPABILITY_VERSION),
    environment: z.literal(COMMERCE_CAPABILITY_ENVIRONMENT),
    network: z.literal(COMMERCE_CAPABILITY_NETWORK),
    capabilities: z.array(SessionCapabilityEntrySchema).length(2),
    routes: z.array(SessionRouteDescriptorSchema).length(7),
  })
  .superRefine((value, ctx) => {
    // Exact family inventory: each frozen family once, no extra/omitted.
    const seen = new Set<SessionCapabilityFamily>();
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
    for (const family of SESSION_CAPABILITY_FAMILY_ORDER) {
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
    for (const [index, family] of SESSION_CAPABILITY_FAMILY_ORDER.entries()) {
      if (value.capabilities[index]?.family !== family) {
        ctx.addIssue({
          code: "custom",
          path: ["capabilities", index, "family"],
          message: `Family at index ${index} must be ${family}.`,
        });
      }
    }
    // Both entries share their state (one future flag/runtime): a mismatched
    // state is rejected outright.
    const firstState = value.capabilities[0]?.state;
    if (firstState !== undefined) {
      for (const [index, entry] of value.capabilities.entries()) {
        if (entry.state !== firstState) {
          ctx.addIssue({
            code: "custom",
            path: ["capabilities", index, "state"],
            message:
              "Both session entries must share one state from a single flag/runtime.",
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
    for (const id of SESSION_ROUTE_IDS) {
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
    for (const [index, id] of SESSION_ROUTE_IDS.entries()) {
      if (value.routes[index]?.id !== id) {
        ctx.addIssue({
          code: "custom",
          path: ["routes", index, "id"],
          message: `Route at index ${index} must be ${id}.`,
        });
      }
    }
  });

export type SessionCapabilityManifest = z.infer<
  typeof SessionCapabilityManifestSchema
>;

export const SessionCapabilitiesSuccessEnvelopeSchema =
  createCommerceSuccessEnvelopeSchema(SessionCapabilityManifestSchema);

export type SessionCapabilitiesSuccessEnvelope = z.infer<
  typeof SessionCapabilitiesSuccessEnvelopeSchema
>;

const SESSION_ENTRY_DEPENDENCIES: SessionCapabilityDependency[] = [
  "auth",
  "tenantDatabase",
  "machineDatabase",
  "policyDatabase",
  "commerceSessionDatabase",
];
Object.freeze(SESSION_ENTRY_DEPENDENCIES);

/** One shared published state for both entries (single future flag/runtime). */
export const SESSION_CAPABILITY_STATE: SessionCapabilityState = "enabled";

/** The two frozen session entries, at their fixed shared published state. */
export const SESSION_CAPABILITY_ENTRIES: readonly SessionCapabilityEntry[] =
  Object.freeze([
    Object.freeze({
      family: "commerce_session_management",
      audience: "browser",
      state: SESSION_CAPABILITY_STATE,
      dependencies: SESSION_ENTRY_DEPENDENCIES,
    }),
    Object.freeze({
      family: "commerce_session_exchange",
      audience: "agent",
      state: SESSION_CAPABILITY_STATE,
      dependencies: SESSION_ENTRY_DEPENDENCIES,
    }),
  ]);

/**
 * Parsed manifest backstop. Zod clones its input, so the structured values
 * below are distinct objects; every layer is frozen explicitly (arrays,
 * entries, dependency arrays, route descriptors) before publication. The
 * exported constant is therefore deeply immutable at runtime.
 */
const PARSED_SESSION_CAPABILITY_MANIFEST =
  SessionCapabilityManifestSchema.parse({
    capabilityVersion: SESSION_CAPABILITY_VERSION,
    environment: COMMERCE_CAPABILITY_ENVIRONMENT,
    network: COMMERCE_CAPABILITY_NETWORK,
    capabilities: SESSION_CAPABILITY_ENTRIES,
    routes: SESSION_ROUTES,
  });

for (const entry of PARSED_SESSION_CAPABILITY_MANIFEST.capabilities) {
  Object.freeze(entry.dependencies);
  Object.freeze(entry);
}
Object.freeze(PARSED_SESSION_CAPABILITY_MANIFEST.capabilities);
for (const route of PARSED_SESSION_CAPABILITY_MANIFEST.routes) {
  Object.freeze(route);
}
Object.freeze(PARSED_SESSION_CAPABILITY_MANIFEST.routes);

/**
 * Frozen full session capability manifest. This is pure constant data: no
 * builder, no runtime decision, no process.env/network/DB access and no caller
 * extension. The structured parse above fails closed if the module constants
 * ever drift, and every nested layer is frozen before this export is visible.
 */
export const SESSION_CAPABILITY_MANIFEST: SessionCapabilityManifest =
  Object.freeze(PARSED_SESSION_CAPABILITY_MANIFEST);
