import { CommercePaymentRateLimiter } from "./payment-rate-limiter.js";
import { CommercePaymentService } from "./payment-service.js";
import type {
  CommercePaymentActionReadPort,
  CommercePaymentAuthPort,
  CommercePaymentRateLimitStorePort,
  CommercePaymentSessionReadPort,
  CommercePaymentStorePort,
} from "./payment-ports.js";

/**
 * Dedicated runtime wiring for the migration-0015 payment slice, with the same
 * discipline as the grant runtime: it never migrates, owns no pool and
 * constructs no repository. The gate is DEFAULT OFF and fails closed: a
 * disabled or incompletely configured family is `built_disabled`, exposes no
 * service and performs zero side effects. `ready()` is a bounded single-flight
 * read-only re-check; `close()` runs the injected close at most once.
 */

const READINESS_DEADLINE_MS = 2000;

export interface CommercePaymentStoreLifecyclePort {
  initialize?(): Promise<void>;
  readiness?(): Promise<void>;
  close?(): Promise<void>;
}

export interface CommercePaymentRuntimeDependencies {
  readonly enabled?: boolean;
  readonly authSecret?: string;
  readonly auth?: CommercePaymentAuthPort;
  readonly rateLimitStore?: CommercePaymentRateLimitStorePort;
  readonly store?: CommercePaymentStorePort;
  readonly commerceSessions?: CommercePaymentSessionReadPort;
  readonly actions?: CommercePaymentActionReadPort;
  readonly lifecycle?: CommercePaymentStoreLifecyclePort;
}

export type CommercePaymentRuntimeState = "enabled" | "built_disabled";

export interface StartedCommercePaymentRuntime {
  readonly state: CommercePaymentRuntimeState;
  readonly service: CommercePaymentService | undefined;
  ready(): Promise<boolean>;
  close(): Promise<void>;
}

function hasMethods(value: unknown, names: readonly string[]): boolean {
  if (typeof value !== "object" || value === null) return false;
  return names.every(
    (name) => typeof (value as Record<string, unknown>)[name] === "function",
  );
}

/** The exact five runtime operations; no observation method is required. */
const REQUIRED_STORE_METHODS: readonly string[] = [
  "recordListingPaymentTerms",
  "registerVerifiedRequirement",
  "persistBuyerAttempt",
  "recordAttemptDispatch",
  "readAgentAttempt",
];

export function paymentDependenciesConfigured(
  dependencies: CommercePaymentRuntimeDependencies,
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
    hasMethods(dependencies.auth, ["verifyCsrf", "beginTenantRead", "finishTenantRead"]) &&
    hasMethods(dependencies.rateLimitStore, ["consume"]) &&
    hasMethods(dependencies.store, REQUIRED_STORE_METHODS) &&
    hasMethods(dependencies.commerceSessions, ["getCommerceSessionByHash"]) &&
    hasMethods(dependencies.actions, ["getAgentCommerceAction"])
  );
}

function disabledRuntime(): StartedCommercePaymentRuntime {
  return {
    state: "built_disabled",
    service: undefined,
    ready: async () => false,
    close: async () => undefined,
  };
}

export async function startCommercePaymentRuntime(
  dependencies: CommercePaymentRuntimeDependencies,
): Promise<StartedCommercePaymentRuntime> {
  if (!paymentDependenciesConfigured(dependencies)) return disabledRuntime();

  const lifecycle = dependencies.lifecycle;
  let service: CommercePaymentService;
  try {
    if (lifecycle !== undefined && typeof lifecycle.initialize === "function") {
      await lifecycle.initialize();
    }
    const limits = new CommercePaymentRateLimiter({
      secret: dependencies.authSecret as string,
      store: dependencies.rateLimitStore as CommercePaymentRateLimitStorePort,
    });
    service = new CommercePaymentService({
      auth: dependencies.auth as CommercePaymentAuthPort,
      store: dependencies.store as CommercePaymentStorePort,
      commerceSessions: dependencies.commerceSessions as CommercePaymentSessionReadPort,
      actions: dependencies.actions as CommercePaymentActionReadPort,
      limits,
    });
  } catch {
    if (lifecycle !== undefined && typeof lifecycle.close === "function") {
      await lifecycle.close().catch(() => undefined);
    }
    throw new Error("COMMERCE_PAYMENT_RUNTIME_UNAVAILABLE");
  }

  let closed = false;
  let inFlight: Promise<boolean> | undefined;

  async function probeReadiness(): Promise<boolean> {
    if (lifecycle === undefined || typeof lifecycle.readiness !== "function") {
      return !closed;
    }
    try {
      await lifecycle.readiness();
      return !closed;
    } catch {
      return false;
    }
  }

  function runSingleFlight(): Promise<boolean> {
    if (inFlight === undefined) {
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
