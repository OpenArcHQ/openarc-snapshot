import { z } from "zod";

import {
  COMMERCE_CAPABILITY_ENVIRONMENT,
  COMMERCE_CAPABILITY_NETWORK,
} from "./capabilities.js";
import { createCommerceSuccessEnvelopeSchema } from "./api.js";

/**
 * Strict, bounded, browser-safe control capability manifest and fixed
 * 10-entry policy-management route registry.
 *
 * This module publishes a pure data contract only: a frozen one-family
 * capability manifest and the exact 10 control route descriptors. It contains
 * no route handlers, no transport, no authorization, no request dispatch, no
 * database/network access and no runtime registration or reflection. It does
 * not import or mutate the legacy commerce capability registry (5 families /
 * 41 routes) or the marketplace capability registry (3 families / 18 routes);
 * its constants are separate.
 *
 * The contract is frozen for the current control release. Availability in this
 * manifest does NOT grant a role, expose a live API route, claim mainnet
 * support, or confer payment/execution authority of any kind.
 */

export const CONTROL_CAPABILITIES_PATH =
  "/v2/public/control-capabilities" as const;

export const CONTROL_CAPABILITY_VERSION =
  "openarc.capabilities.control.v1" as const;

/** Closed family inventory: exactly one policy-management family. */
export const ControlCapabilityFamilySchema = z.enum(["policy_management"]);

export type ControlCapabilityFamily = z.infer<
  typeof ControlCapabilityFamilySchema
>;

/** Control audience is always the browser. */
export const ControlCapabilityAudienceSchema = z.enum(["browser"]);

export type ControlCapabilityAudience = z.infer<
  typeof ControlCapabilityAudienceSchema
>;

/** State enum. `planned` is deliberately absent from this frozen contract. */
export const ControlCapabilityStateSchema = z.enum([
  "enabled",
  "built_disabled",
  "unavailable",
]);

export type ControlCapabilityState = z.infer<
  typeof ControlCapabilityStateSchema
>;

export const ControlCapabilityDependencySchema = z.enum([
  "auth",
  "tenantDatabase",
  "policyDatabase",
]);

export type ControlCapabilityDependency = z.infer<
  typeof ControlCapabilityDependencySchema
>;

/** Exact frozen audience per family. */
export const CONTROL_CAPABILITY_AUDIENCE: Readonly<
  Record<ControlCapabilityFamily, ControlCapabilityAudience>
> = Object.freeze({
  policy_management: "browser",
});

/** Exact closed dependency arrays, in the frozen order. */
export const CONTROL_CAPABILITY_DEPENDENCIES: Readonly<
  Record<ControlCapabilityFamily, readonly ControlCapabilityDependency[]>
> = Object.freeze({
  policy_management: Object.freeze([
    "auth",
    "tenantDatabase",
    "policyDatabase",
  ] as const),
});

/** Fixed deterministic family order for the manifest array. */
export const CONTROL_CAPABILITY_FAMILY_ORDER: readonly ControlCapabilityFamily[] =
  Object.freeze(["policy_management"] as const);

/** Exactly the three frozen dependency tokens, in the frozen order. */
export const CONTROL_CAPABILITY_DEPENDENCY_ORDER: readonly ControlCapabilityDependency[] =
  Object.freeze(["auth", "tenantDatabase", "policyDatabase"] as const);

export const CONTROL_CAPABILITY_DEPENDENCY_LENGTH =
  CONTROL_CAPABILITY_DEPENDENCY_ORDER.length;

const ControlDependenciesSchema = z
  .array(ControlCapabilityDependencySchema)
  .length(CONTROL_CAPABILITY_DEPENDENCY_LENGTH);

export const ControlCapabilityEntrySchema = z
  .strictObject({
    family: ControlCapabilityFamilySchema,
    audience: ControlCapabilityAudienceSchema,
    state: ControlCapabilityStateSchema,
    dependencies: ControlDependenciesSchema,
  })
  .superRefine((value, ctx) => {
    if (value.audience !== CONTROL_CAPABILITY_AUDIENCE[value.family]) {
      ctx.addIssue({
        code: "custom",
        path: ["audience"],
        message: "Audience does not match the frozen family descriptor.",
      });
    }
    const expected = CONTROL_CAPABILITY_DEPENDENCIES[value.family];
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

export type ControlCapabilityEntry = z.infer<
  typeof ControlCapabilityEntrySchema
>;

/**
 * One frozen control route descriptor. The entire tuple is validated against
 * the canonical registry below, not merely the `id` shape.
 */
export const ControlRouteDescriptorSchema = z
  .strictObject({
    id: z.string().regex(/^[a-z][a-z0-9_]*$/u),
    family: ControlCapabilityFamilySchema,
    audience: ControlCapabilityAudienceSchema,
    method: z.enum(["GET", "POST"]),
    path: z.string().min(1).max(512),
  })
  .superRefine((value, ctx) => {
    if (value.audience !== CONTROL_CAPABILITY_AUDIENCE[value.family]) {
      ctx.addIssue({
        code: "custom",
        path: ["audience"],
        message: "Route audience does not match the frozen family descriptor.",
      });
    }
    const expected = CONTROL_ROUTE_INDEX[value.id];
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

export type ControlRouteDescriptor = z.infer<
  typeof ControlRouteDescriptorSchema
>;

interface FrozenControlRoute {
  readonly id: string;
  readonly family: ControlCapabilityFamily;
  readonly audience: ControlCapabilityAudience;
  readonly method: "GET" | "POST";
  readonly path: string;
}

const CONTROL_BASE = "/v2/control/organizations";

/**
 * The frozen control-route inventory: exactly 10 policy-management entries.
 * Paths use exact camelCase `:parameter` templates. GET and POST are the only
 * methods. No manifest, health, fallback, session, payment or execution
 * descriptors exist here.
 */
export const CONTROL_ROUTES: readonly ControlRouteDescriptor[] = Object.freeze(
  (
    [
      { id: "policy_roots", family: "policy_management", audience: "browser", method: "GET", path: `${CONTROL_BASE}/:organizationId/policies` },
      { id: "policy_create", family: "policy_management", audience: "browser", method: "POST", path: `${CONTROL_BASE}/:organizationId/policies` },
      { id: "policy_root", family: "policy_management", audience: "browser", method: "GET", path: `${CONTROL_BASE}/:organizationId/policies/:policyId` },
      { id: "policy_revisions", family: "policy_management", audience: "browser", method: "GET", path: `${CONTROL_BASE}/:organizationId/policies/:policyId/revisions` },
      { id: "policy_revision_create", family: "policy_management", audience: "browser", method: "POST", path: `${CONTROL_BASE}/:organizationId/policies/:policyId/revisions` },
      { id: "policy_revision", family: "policy_management", audience: "browser", method: "GET", path: `${CONTROL_BASE}/:organizationId/policies/:policyId/revisions/:revision` },
      { id: "policy_pause", family: "policy_management", audience: "browser", method: "POST", path: `${CONTROL_BASE}/:organizationId/policies/:policyId/pause` },
      { id: "policy_resume", family: "policy_management", audience: "browser", method: "POST", path: `${CONTROL_BASE}/:organizationId/policies/:policyId/resume` },
      { id: "policy_revoke", family: "policy_management", audience: "browser", method: "POST", path: `${CONTROL_BASE}/:organizationId/policies/:policyId/revoke` },
      { id: "policy_mutation_status", family: "policy_management", audience: "browser", method: "GET", path: `${CONTROL_BASE}/:organizationId/policy-mutations/:mutationId` },
    ] satisfies readonly FrozenControlRoute[]
  ).map((route) => Object.freeze(route)),
);

/** Exact-id index used by the strict lookup refinement (not a mutable map). */
export const CONTROL_ROUTE_INDEX: Readonly<
  Record<string, FrozenControlRoute>
> = Object.freeze(
  CONTROL_ROUTES.reduce<Record<string, FrozenControlRoute>>(
    (accumulator, route) => {
      accumulator[route.id] = route;
      return accumulator;
    },
    {},
  ),
);

export const CONTROL_ROUTE_IDS: readonly string[] = Object.freeze(
  CONTROL_ROUTES.map((route) => route.id),
);

export const ControlCapabilityManifestSchema = z
  .strictObject({
    capabilityVersion: z.literal(CONTROL_CAPABILITY_VERSION),
    environment: z.literal(COMMERCE_CAPABILITY_ENVIRONMENT),
    network: z.literal(COMMERCE_CAPABILITY_NETWORK),
    capabilities: z.array(ControlCapabilityEntrySchema).length(1),
    routes: z.array(ControlRouteDescriptorSchema).length(10),
  })
  .superRefine((value, ctx) => {
    // Exact family inventory: each frozen family once, no extra/omitted.
    const seen = new Set<ControlCapabilityFamily>();
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
    for (const family of CONTROL_CAPABILITY_FAMILY_ORDER) {
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
    for (const [index, family] of CONTROL_CAPABILITY_FAMILY_ORDER.entries()) {
      if (value.capabilities[index]?.family !== family) {
        ctx.addIssue({
          code: "custom",
          path: ["capabilities", index, "family"],
          message: `Family at index ${index} must be ${family}.`,
        });
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
    for (const id of CONTROL_ROUTE_IDS) {
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
    for (const [index, id] of CONTROL_ROUTE_IDS.entries()) {
      if (value.routes[index]?.id !== id) {
        ctx.addIssue({
          code: "custom",
          path: ["routes", index, "id"],
          message: `Route at index ${index} must be ${id}.`,
        });
      }
    }
  });

export type ControlCapabilityManifest = z.infer<
  typeof ControlCapabilityManifestSchema
>;

export const ControlCapabilitiesSuccessEnvelopeSchema =
  createCommerceSuccessEnvelopeSchema(ControlCapabilityManifestSchema);

export type ControlCapabilitiesSuccessEnvelope = z.infer<
  typeof ControlCapabilitiesSuccessEnvelopeSchema
>;

const CONTROL_ENTRY_DEPENDENCIES: ControlCapabilityDependency[] = [
  "auth",
  "tenantDatabase",
  "policyDatabase",
];
Object.freeze(CONTROL_ENTRY_DEPENDENCIES);

/** The one frozen policy-management entry, at its fixed published state. */
export const CONTROL_CAPABILITY_ENTRY: ControlCapabilityEntry = Object.freeze({
  family: "policy_management",
  audience: "browser",
  state: "enabled",
  dependencies: CONTROL_ENTRY_DEPENDENCIES,
});

/**
 * Parsed manifest backstop. Zod clones its input, so the structured values
 * below are distinct objects; every layer is frozen explicitly (arrays,
 * entries, dependency arrays, route descriptors) before publication. The
 * exported constant is therefore deeply immutable at runtime.
 */
const PARSED_CONTROL_CAPABILITY_MANIFEST =
  ControlCapabilityManifestSchema.parse({
    capabilityVersion: CONTROL_CAPABILITY_VERSION,
    environment: COMMERCE_CAPABILITY_ENVIRONMENT,
    network: COMMERCE_CAPABILITY_NETWORK,
    capabilities: [CONTROL_CAPABILITY_ENTRY],
    routes: CONTROL_ROUTES,
  });

for (const entry of PARSED_CONTROL_CAPABILITY_MANIFEST.capabilities) {
  Object.freeze(entry.dependencies);
  Object.freeze(entry);
}
Object.freeze(PARSED_CONTROL_CAPABILITY_MANIFEST.capabilities);
for (const route of PARSED_CONTROL_CAPABILITY_MANIFEST.routes) {
  Object.freeze(route);
}
Object.freeze(PARSED_CONTROL_CAPABILITY_MANIFEST.routes);

/**
 * Frozen full control capability manifest. This is pure constant data: no
 * builder, no runtime decision, no process.env/network/DB access and no caller
 * extension. The structured parse above fails closed if the module constants
 * ever drift, and every nested layer is frozen before this export is visible.
 */
export const CONTROL_CAPABILITY_MANIFEST: ControlCapabilityManifest =
  Object.freeze(PARSED_CONTROL_CAPABILITY_MANIFEST);
