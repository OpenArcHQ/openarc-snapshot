import { CommerceGrantRateLimiter } from "./grant-rate-limiter.js";
import { CommerceGrantService } from "./grant-service.js";
import type {
  CommerceGrantAuthPort,
  CommerceGrantRateLimitStorePort,
  CommerceGrantSessionReadPort,
  CommerceGrantStorePort,
} from "./grant-ports.js";

/**
 * Dedicated runtime wiring for the protected authorization-grant slice.
 *
 * The server NEVER runs migrations. This runtime owns no pool and constructs no
 * concrete repository: the DB12 grant store is authored independently and is
 * injected through the narrow `CommerceGrantStorePort` seam, together with the
 * commerce-session read, the accepted auth seam, the purpose-separated rate
 * secret and the accepted durable rate-limit store. That keeps this module free
 * of any database import and lets the integrator bind the real store without
 * touching the HTTP slice.
 *
 * The gate is DEFAULT OFF and fails closed. When the family is not enabled, or
 * when any required dependency is missing or malformed, the runtime reports
 * `built_disabled`, exposes NO service and performs ZERO side effects: no
 * initialize, no readiness probe, no limiter construction, no store call and no
 * close on a caller-supplied dependency. An enabled grant surface is a control
 * surface only: it never implies that a payment, settlement or delivery lane
 * exists.
 *
 * `ready()` is a bounded read-only readiness re-check that never migrates. It
 * is single-flight: concurrent and repeated calls while a probe is still in
 * flight share that ONE batch, so an uncancellable old probe can never be
 * multiplied. A fixed 2000ms deadline fails the await closed without clearing
 * the underlying batch; a late completion after close can never promote
 * readiness. `close()` runs the injected lifecycle close at most once.
 */

const READINESS_DEADLINE_MS = 2000;

/**
 * Optional lifecycle seam for the injected store. `initialize` runs exactly
 * once BEFORE any route may serve; `readiness` is a read-only probe and
 * `close` releases whatever the integrator owns. All three are optional so a
 * pure in-memory or already-initialized store needs none of them.
 */
export interface CommerceGrantStoreLifecyclePort {
  initialize?(): Promise<void>;
  readiness?(): Promise<void>;
  close?(): Promise<void>;
}

export interface CommerceGrantRuntimeDependencies {
  /** Default OFF. A false/absent gate installs no service at all. */
  readonly enabled?: boolean;
  readonly authSecret?: string;
  readonly auth?: CommerceGrantAuthPort;
  readonly rateLimitStore?: CommerceGrantRateLimitStorePort;
  readonly store?: CommerceGrantStorePort;
  readonly commerceSessions?: CommerceGrantSessionReadPort;
  readonly lifecycle?: CommerceGrantStoreLifecyclePort;
}

export type CommerceGrantRuntimeState = "enabled" | "built_disabled";

export interface StartedCommerceGrantRuntime {
  readonly state: CommerceGrantRuntimeState;
  /** Present ONLY in the `enabled` state. */
  readonly service: CommerceGrantService | undefined;
  ready(): Promise<boolean>;
  close(): Promise<void>;
}

function unavailable(): never {
  throw new Error("COMMERCE_GRANT_RUNTIME_UNAVAILABLE");
}

function isAuthPort(value: unknown): value is CommerceGrantAuthPort {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { verifyCsrf?: unknown }).verifyCsrf === "function" &&
    typeof (value as { beginTenantRead?: unknown }).beginTenantRead ===
      "function" &&
    typeof (value as { finishTenantRead?: unknown }).finishTenantRead ===
      "function"
  );
}

function isRateLimitStorePort(
  value: unknown,
): value is CommerceGrantRateLimitStorePort {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { consume?: unknown }).consume === "function"
  );
}

/** The exact nine operations the service depends on, one per frozen route. */
const REQUIRED_STORE_METHODS: readonly string[] = [
  "issueCommerceGrant",
  "replaceCommerceGrant",
  "getAgentCommerceGrantMutationStatus",
  "introspectCommerceGrant",
  "claimCommerceGrant",
  "getProviderCommerceGrantAttemptStatus",
  "getCommerceGrant",
  "getHumanCommerceGrantMutationStatus",
  "revokeCommerceGrant",
];

function isStorePort(value: unknown): value is CommerceGrantStorePort {
  if (typeof value !== "object" || value === null) return false;
  for (const name of REQUIRED_STORE_METHODS) {
    if (typeof (value as Record<string, unknown>)[name] !== "function") {
      return false;
    }
  }
  return true;
}

function isCommerceSessionReadPort(
  value: unknown,
): value is CommerceGrantSessionReadPort {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { getCommerceSessionByHash?: unknown })
      .getCommerceSessionByHash === "function"
  );
}

/**
 * True only when the gate is explicitly on AND every dependency the enabled
 * family requires is present and structurally valid. Anything else is
 * `built_disabled`, evaluated BEFORE any dependency is touched.
 */
export function grantDependenciesConfigured(
  dependencies: CommerceGrantRuntimeDependencies,
): boolean {
  if (dependencies === null || typeof dependencies !== "object") return false;
  if (dependencies.enabled !== true) return false;
  if (
    typeof dependencies.authSecret !== "string" ||
    dependencies.authSecret.length === 0
  ) {
    return false;
  }
  return (
    isAuthPort(dependencies.auth) &&
    isRateLimitStorePort(dependencies.rateLimitStore) &&
    isStorePort(dependencies.store) &&
    isCommerceSessionReadPort(dependencies.commerceSessions)
  );
}

function disabledRuntime(): StartedCommerceGrantRuntime {
  return {
    state: "built_disabled",
    service: undefined,
    ready: async () => false,
    close: async () => undefined,
  };
}

export async function startCommerceGrantRuntime(
  dependencies: CommerceGrantRuntimeDependencies,
): Promise<StartedCommerceGrantRuntime> {
  // Fail closed BEFORE touching any dependency: a disabled or incompletely
  // configured family performs zero side effects.
  if (!grantDependenciesConfigured(dependencies)) return disabledRuntime();

  const lifecycle = dependencies.lifecycle;
  let service: CommerceGrantService;
  try {
    if (lifecycle !== undefined && typeof lifecycle.initialize === "function") {
      await lifecycle.initialize();
    }
    const limits = new CommerceGrantRateLimiter({
      secret: dependencies.authSecret as string,
      store: dependencies.rateLimitStore as CommerceGrantRateLimitStorePort,
    });
    // Service construction is INSIDE the same cleanup boundary: a throw here
    // must still release whatever the lifecycle owns, exactly once.
    service = new CommerceGrantService({
      auth: dependencies.auth as CommerceGrantAuthPort,
      store: dependencies.store as CommerceGrantStorePort,
      commerceSessions:
        dependencies.commerceSessions as CommerceGrantSessionReadPort,
      limits,
    });
  } catch {
    if (lifecycle !== undefined && typeof lifecycle.close === "function") {
      await lifecycle.close().catch(() => undefined);
    }
    unavailable();
  }

  let closed = false;
  let inFlight: Promise<boolean> | undefined;

  async function probeReadiness(): Promise<boolean> {
    if (lifecycle === undefined || typeof lifecycle.readiness !== "function") {
      return !closed;
    }
    try {
      await lifecycle.readiness();
      // A probe that only finishes after close must never report ready.
      return !closed;
    } catch {
      return false;
    }
  }

  function runSingleFlight(): Promise<boolean> {
    if (inFlight === undefined) {
      // Retain the promise until it ACTUALLY settles: repeated probes after a
      // deadline timeout keep attaching to the same uncancelled batch.
      inFlight = probeReadiness().finally(() => {
        inFlight = undefined;
      });
    }
    return inFlight;
  }

  return {
    state: "enabled",
    service,
    async ready(): Promise<boolean> {
      if (closed) return false;
      const probe = runSingleFlight();
      let timer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<boolean>((resolve) => {
        timer = setTimeout(() => resolve(false), READINESS_DEADLINE_MS);
      });
      try {
        const result = await Promise.race([probe, deadline]);
        // Late settlement after close can never promote readiness.
        if (closed) return false;
        return result;
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
    },
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      if (lifecycle !== undefined && typeof lifecycle.close === "function") {
        await lifecycle.close().catch(() => undefined);
      }
    },
  };
}
