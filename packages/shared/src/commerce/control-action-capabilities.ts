import { z } from "zod";

import {
  COMMERCE_CAPABILITY_ENVIRONMENT,
  COMMERCE_CAPABILITY_NETWORK,
} from "./capabilities.js";
import { createCommerceSuccessEnvelopeSchema } from "./api.js";

/**
 * Strict, bounded, pure commerce-action route/capability contract and fixed
 * twelve-entry action-route registry.
 *
 * This module publishes a pure data contract only: a frozen two-family
 * capability manifest and the exact twelve commerce-action route descriptors.
 * It contains no route handlers, no transport, no authorization, no request
 * dispatch, no database/network access, no clock, no runtime
 * registration/reflection and no builder, env read or runtime decision of any
 * kind. It does not import or mutate the legacy commerce capability registry
 * (5 families / 41 routes), the marketplace capability registry (3 families /
 * 18 routes), the control capability registry (1 family / 10 routes) or the
 * commerce-session capability registry (2 families / 7 routes); its constants
 * are separate.
 *
 * The manifest describes route PREREQUISITES ONLY, never a permission or a
 * verified requirement. An enabled action surface does NOT mean a listing
 * payment lane is usable or that a grant/payment can occur; the listing
 * paymentLane remains unavailable and production action authorization still
 * rejects unverified requirements. This frozen registry makes no runtime
 * availability or wallet-wide control claim.
 */

export const ACTION_CAPABILITIES_PATH =
  "/v2/public/action-capabilities" as const;

export const ACTION_CAPABILITY_VERSION =
  "openarc.capabilities.commerce-actions.v1" as const;

/** Closed family inventory: exactly two ordered action families. */
export const ActionCapabilityFamilySchema = z.enum([
  "commerce_action_management",
  "commerce_action_authorization",
]);

export type ActionCapabilityFamily = z.infer<
  typeof ActionCapabilityFamilySchema
>;

/** Action audiences: management is browser, authorization is agent. */
export const ActionCapabilityAudienceSchema = z.enum(["browser", "agent"]);

export type ActionCapabilityAudience = z.infer<
  typeof ActionCapabilityAudienceSchema
>;

/** State enum. `planned` and every unknown state are deliberately absent. */
export const ActionCapabilityStateSchema = z.enum([
  "enabled",
  "built_disabled",
  "unavailable",
]);

export type ActionCapabilityState = z.infer<
  typeof ActionCapabilityStateSchema
>;

export const ActionCapabilityDependencySchema = z.enum([
  "auth",
  "tenantDatabase",
  "machineDatabase",
  "policyDatabase",
  "commerceSessionDatabase",
  "commerceActionDatabase",
]);

export type ActionCapabilityDependency = z.infer<
  typeof ActionCapabilityDependencySchema
>;

/** Exact frozen audience per family. */
export const ACTION_CAPABILITY_AUDIENCE: Readonly<
  Record<ActionCapabilityFamily, ActionCapabilityAudience>
> = Object.freeze({
  commerce_action_management: "browser",
  commerce_action_authorization: "agent",
});

/** Exactly the six frozen dependency tokens, in the frozen order. */
export const ACTION_CAPABILITY_DEPENDENCY_ORDER: readonly ActionCapabilityDependency[] =
  Object.freeze([
    "auth",
    "tenantDatabase",
    "machineDatabase",
    "policyDatabase",
    "commerceSessionDatabase",
    "commerceActionDatabase",
  ] as const);

export const ACTION_CAPABILITY_DEPENDENCY_LENGTH =
  ACTION_CAPABILITY_DEPENDENCY_ORDER.length;

/** Exact closed dependency arrays, in the frozen order, for both families. */
export const ACTION_CAPABILITY_DEPENDENCIES: Readonly<
  Record<ActionCapabilityFamily, readonly ActionCapabilityDependency[]>
> = Object.freeze({
  commerce_action_management: ACTION_CAPABILITY_DEPENDENCY_ORDER,
  commerce_action_authorization: ACTION_CAPABILITY_DEPENDENCY_ORDER,
});

/** Fixed deterministic family order for the manifest array. */
export const ACTION_CAPABILITY_FAMILY_ORDER: readonly ActionCapabilityFamily[] =
  Object.freeze([
    "commerce_action_management",
    "commerce_action_authorization",
  ] as const);

const ActionDependenciesSchema = z
  .array(ActionCapabilityDependencySchema)
  .length(ACTION_CAPABILITY_DEPENDENCY_LENGTH);

export const ActionCapabilityEntrySchema = z
  .strictObject({
    family: ActionCapabilityFamilySchema,
    audience: ActionCapabilityAudienceSchema,
    state: ActionCapabilityStateSchema,
    dependencies: ActionDependenciesSchema,
  })
  .superRefine((value, ctx) => {
    if (value.audience !== ACTION_CAPABILITY_AUDIENCE[value.family]) {
      ctx.addIssue({
        code: "custom",
        path: ["audience"],
        message: "Audience does not match the frozen family descriptor.",
      });
    }
    const expected = ACTION_CAPABILITY_DEPENDENCIES[value.family];
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

export type ActionCapabilityEntry = z.infer<
  typeof ActionCapabilityEntrySchema
>;

/**
 * One frozen action route descriptor. The entire tuple is validated against
 * the canonical registry below, not merely the `id` shape. The registry
 * lookup is own-property only, so inherited names (`toString`, `constructor`,
 * `__proto__`, `hasOwnProperty`, ...) are rejected as unknown ids.
 */
export const ActionRouteDescriptorSchema = z
  .strictObject({
    id: z.string().regex(/^[a-z][a-z0-9_]*$/u),
    family: ActionCapabilityFamilySchema,
    audience: ActionCapabilityAudienceSchema,
    method: z.enum(["GET", "POST"]),
    path: z.string().min(1).max(512),
  })
  .superRefine((value, ctx) => {
    if (value.audience !== ACTION_CAPABILITY_AUDIENCE[value.family]) {
      ctx.addIssue({
        code: "custom",
        path: ["audience"],
        message: "Route audience does not match the frozen family descriptor.",
      });
    }
    if (!Object.hasOwn(ACTION_ROUTE_INDEX, value.id)) {
      ctx.addIssue({
        code: "custom",
        path: ["id"],
        message: "Route id is not part of the frozen registry.",
      });
      return;
    }
    const expected = ACTION_ROUTE_INDEX[value.id];
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

export type ActionRouteDescriptor = z.infer<
  typeof ActionRouteDescriptorSchema
>;

interface FrozenActionRoute {
  readonly id: string;
  readonly family: ActionCapabilityFamily;
  readonly audience: ActionCapabilityAudience;
  readonly method: "GET" | "POST";
  readonly path: string;
}

const ACTION_CONTROL_BASE = "/v2/control/organizations";
const ACTION_AGENT_BASE = "/v2/agent";

/**
 * The frozen action-route inventory: exactly 9 commerce_action_management
 * (browser) + 3 commerce_action_authorization (agent) = 12 entries. Paths use
 * exact camelCase `:parameter` templates. GET and POST are the only methods.
 * No capability/manifest/health/fallback descriptor exists here, and no
 * provider/payment/grant route is added.
 */
export const ACTION_ROUTES: readonly ActionRouteDescriptor[] = Object.freeze(
  (
    [
      { id: "action_list", family: "commerce_action_management", audience: "browser", method: "GET", path: `${ACTION_CONTROL_BASE}/:organizationId/actions` },
      { id: "action_detail", family: "commerce_action_management", audience: "browser", method: "GET", path: `${ACTION_CONTROL_BASE}/:organizationId/actions/:actionId` },
      { id: "approval_list", family: "commerce_action_management", audience: "browser", method: "GET", path: `${ACTION_CONTROL_BASE}/:organizationId/approvals` },
      { id: "approval_detail", family: "commerce_action_management", audience: "browser", method: "GET", path: `${ACTION_CONTROL_BASE}/:organizationId/approvals/:approvalId` },
      { id: "action_exposure", family: "commerce_action_management", audience: "browser", method: "GET", path: `${ACTION_CONTROL_BASE}/:organizationId/agents/:subjectAgentId/policies/:policyId/exposure` },
      { id: "action_mutation_status", family: "commerce_action_management", audience: "browser", method: "GET", path: `${ACTION_CONTROL_BASE}/:organizationId/action-mutations/:mutationId` },
      { id: "action_approve", family: "commerce_action_management", audience: "browser", method: "POST", path: `${ACTION_CONTROL_BASE}/:organizationId/actions/:actionId/approve` },
      { id: "action_reject", family: "commerce_action_management", audience: "browser", method: "POST", path: `${ACTION_CONTROL_BASE}/:organizationId/actions/:actionId/reject` },
      { id: "action_cancel", family: "commerce_action_management", audience: "browser", method: "POST", path: `${ACTION_CONTROL_BASE}/:organizationId/actions/:actionId/cancel` },
      { id: "action_authorize", family: "commerce_action_authorization", audience: "agent", method: "POST", path: `${ACTION_AGENT_BASE}/commerce-actions` },
      { id: "agent_action_detail", family: "commerce_action_authorization", audience: "agent", method: "GET", path: `${ACTION_AGENT_BASE}/commerce-actions/:actionId` },
      { id: "agent_action_mutation_status", family: "commerce_action_authorization", audience: "agent", method: "GET", path: `${ACTION_AGENT_BASE}/commerce-action-mutations/:mutationId` },
    ] satisfies readonly FrozenActionRoute[]
  ).map((route) => Object.freeze(route)),
);

/** Exact-id index used by the strict own-property lookup (not a mutable map). */
export const ACTION_ROUTE_INDEX: Readonly<
  Record<string, FrozenActionRoute>
> = Object.freeze(
  ACTION_ROUTES.reduce<Record<string, FrozenActionRoute>>(
    (accumulator, route) => {
      accumulator[route.id] = route;
      return accumulator;
    },
    {},
  ),
);

export const ACTION_ROUTE_IDS: readonly string[] = Object.freeze(
  ACTION_ROUTES.map((route) => route.id),
);

export const ActionCapabilityManifestSchema = z
  .strictObject({
    capabilityVersion: z.literal(ACTION_CAPABILITY_VERSION),
    environment: z.literal(COMMERCE_CAPABILITY_ENVIRONMENT),
    network: z.literal(COMMERCE_CAPABILITY_NETWORK),
    capabilities: z.array(ActionCapabilityEntrySchema).length(2),
    routes: z.array(ActionRouteDescriptorSchema).length(12),
  })
  .superRefine((value, ctx) => {
    // Exact family inventory: each frozen family once, no extra/omitted.
    const seen = new Set<ActionCapabilityFamily>();
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
    for (const family of ACTION_CAPABILITY_FAMILY_ORDER) {
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
    for (const [index, family] of ACTION_CAPABILITY_FAMILY_ORDER.entries()) {
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
              "Both action entries must share one state from a single flag/runtime.",
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
    for (const id of ACTION_ROUTE_IDS) {
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
    for (const [index, id] of ACTION_ROUTE_IDS.entries()) {
      if (value.routes[index]?.id !== id) {
        ctx.addIssue({
          code: "custom",
          path: ["routes", index, "id"],
          message: `Route at index ${index} must be ${id}.`,
        });
      }
    }
  });

export type ActionCapabilityManifest = z.infer<
  typeof ActionCapabilityManifestSchema
>;

export const ActionCapabilitiesSuccessEnvelopeSchema =
  createCommerceSuccessEnvelopeSchema(ActionCapabilityManifestSchema);

export type ActionCapabilitiesSuccessEnvelope = z.infer<
  typeof ActionCapabilitiesSuccessEnvelopeSchema
>;

/** One shared published state for both entries (single future flag/runtime). */
export const ACTION_CAPABILITY_STATE: ActionCapabilityState = "enabled";

const ACTION_ENTRY_DEPENDENCIES: ActionCapabilityDependency[] = [
  "auth",
  "tenantDatabase",
  "machineDatabase",
  "policyDatabase",
  "commerceSessionDatabase",
  "commerceActionDatabase",
];
Object.freeze(ACTION_ENTRY_DEPENDENCIES);

/** The two frozen action entries, at their fixed shared published state. */
export const ACTION_CAPABILITY_ENTRIES: readonly ActionCapabilityEntry[] =
  Object.freeze([
    Object.freeze({
      family: "commerce_action_management",
      audience: "browser",
      state: ACTION_CAPABILITY_STATE,
      dependencies: ACTION_ENTRY_DEPENDENCIES,
    }),
    Object.freeze({
      family: "commerce_action_authorization",
      audience: "agent",
      state: ACTION_CAPABILITY_STATE,
      dependencies: ACTION_ENTRY_DEPENDENCIES,
    }),
  ]);

/**
 * Parsed manifest backstop. Zod clones its input, so the structured values
 * below are distinct objects; every layer is frozen explicitly (arrays,
 * entries, dependency arrays, route descriptors) before publication. The
 * exported constant is therefore deeply immutable at runtime.
 */
const PARSED_ACTION_CAPABILITY_MANIFEST =
  ActionCapabilityManifestSchema.parse({
    capabilityVersion: ACTION_CAPABILITY_VERSION,
    environment: COMMERCE_CAPABILITY_ENVIRONMENT,
    network: COMMERCE_CAPABILITY_NETWORK,
    capabilities: ACTION_CAPABILITY_ENTRIES,
    routes: ACTION_ROUTES,
  });

for (const entry of PARSED_ACTION_CAPABILITY_MANIFEST.capabilities) {
  Object.freeze(entry.dependencies);
  Object.freeze(entry);
}
Object.freeze(PARSED_ACTION_CAPABILITY_MANIFEST.capabilities);
for (const route of PARSED_ACTION_CAPABILITY_MANIFEST.routes) {
  Object.freeze(route);
}
Object.freeze(PARSED_ACTION_CAPABILITY_MANIFEST.routes);

/**
 * Frozen full action capability manifest. This is pure constant data: no
 * builder, no runtime decision, no process.env/network/DB access and no caller
 * extension. The structured parse above fails closed if the module constants
 * ever drift, and every nested layer is frozen before this export is visible.
 */
export const ACTION_CAPABILITY_MANIFEST: ActionCapabilityManifest =
  Object.freeze(PARSED_ACTION_CAPABILITY_MANIFEST);
