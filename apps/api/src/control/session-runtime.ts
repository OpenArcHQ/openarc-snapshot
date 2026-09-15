import {
  asCommerceSessionPool,
  asCredentialPool,
  CommerceSessionStore,
  createDatabasePool,
  CredentialStore,
} from "@openarc/db";

import { CommerceSessionRateLimiter } from "./session-rate-limiter.js";
import { CommerceSessionService } from "./session-service.js";
import type {
  AgentSessionReadPort,
  CommerceSessionAuthPort,
  CommerceSessionRateLimitStorePort,
  CommerceSessionStorePort,
} from "./session-ports.js";

/**
 * Dedicated runtime wiring for the protected commerce-session slice.
 *
 * The server NEVER runs migrations. When (and only when) the session family is
 * enabled this runtime opens EXACTLY ONE owned restricted pool, constructs the
 * accepted `CommerceSessionStore` over `asCommerceSessionPool`, initializes it
 * exactly once BEFORE any route may serve, and binds the accepted
 * `CredentialStore.getAgentSession` current-agent read to the SAME pool through
 * `asCredentialPool`. The single pool is shared with the session service and
 * the purpose-separated durable rate limiter (which consumes the accepted auth
 * durable `consume` seam). No per-store pool, no global/auth pool, no SQL
 * migration, no raw pool surface and no unrelated feature activation occurs.
 *
 * Input is explicit: the dedicated restricted database URL, the purpose-separated
 * rate secret, the accepted auth seam and the accepted durable rate-limit store
 * seam. Missing/invalid input fails closed BEFORE any pool is constructed.
 * ALL post-pool construction (store adapter, store/credential construction,
 * single initialization and service construction) is protected by the same
 * cleanup boundary: any failure owns the one pool, closes it exactly once and
 * throws a fixed non-echoing error so the caller fails startup closed.
 *
 * `ready()` is a bounded read-only readiness re-check that never migrates. It
 * is single-flight: concurrent and repeated calls while a probe is still in
 * flight share that ONE batch, so an uncancellable old probe can never be
 * multiplied. A fixed 2000ms deadline fails the await closed without clearing
 * the underlying batch; a late completion after close can never promote
 * readiness. `close()` ends the owned pool exactly once.
 */

const READINESS_DEADLINE_MS = 2000;

export interface CommerceSessionRuntimeDependencies {
  readonly tenantDatabaseUrl: string;
  readonly authSecret: string;
  readonly auth: CommerceSessionAuthPort;
  readonly rateLimitStore: CommerceSessionRateLimitStorePort;
}

export interface StartedCommerceSessionRuntime {
  readonly service: CommerceSessionService;
  ready(): Promise<boolean>;
  close(): Promise<void>;
}

/** Fixed input rejection raised BEFORE any pool or store is constructed. */
function invalidInput(): never {
  throw new Error("COMMERCE_SESSION_RUNTIME_INVALID_INPUT");
}

function unavailable(): never {
  throw new Error("COMMERCE_SESSION_RUNTIME_UNAVAILABLE");
}

function isAuthPort(value: unknown): value is CommerceSessionAuthPort {
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
): value is CommerceSessionRateLimitStorePort {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { consume?: unknown }).consume === "function"
  );
}

export async function startCommerceSessionRuntime(
  dependencies: CommerceSessionRuntimeDependencies,
): Promise<StartedCommerceSessionRuntime> {
  const databaseUrl = dependencies.tenantDatabaseUrl;
  if (typeof databaseUrl !== "string" || databaseUrl.length === 0) {
    invalidInput();
  }
  if (
    typeof dependencies.authSecret !== "string" ||
    dependencies.authSecret.length === 0
  ) {
    invalidInput();
  }
  if (!isAuthPort(dependencies.auth)) invalidInput();
  if (!isRateLimitStorePort(dependencies.rateLimitStore)) invalidInput();

  let pool: ReturnType<typeof createDatabasePool>;
  try {
    pool = createDatabasePool(databaseUrl);
  } catch {
    unavailable();
  }

  let store: CommerceSessionStore;
  let service: CommerceSessionService;
  try {
    // One pool, one accepted store and the accepted credential read bound to
    // the SAME restricted pool. The single initialization composes the declared
    // tenant/machine(policy credential)/policy/commerceSession schema readiness.
    store = new CommerceSessionStore(asCommerceSessionPool(pool));
    await store.initialize();
    const credentials = new CredentialStore(asCredentialPool(pool));
    const agentSessions: AgentSessionReadPort = {
      getAgentSession: (tokenHash: unknown) =>
        credentials.getAgentSession(tokenHash),
    };
    const limits = new CommerceSessionRateLimiter({
      secret: dependencies.authSecret,
      store: dependencies.rateLimitStore,
    });
    // Service construction is INSIDE the same cleanup boundary: a throw here
    // must still close the one owned pool exactly once.
    service = new CommerceSessionService({
      auth: dependencies.auth,
      store: store as CommerceSessionStorePort,
      agentSessions,
      limits,
    });
  } catch {
    await pool.end().catch(() => undefined);
    unavailable();
  }

  let closed = false;
  let inFlight: Promise<boolean> | undefined;

  async function probeReadiness(): Promise<boolean> {
    try {
      await store.readiness();
      // A batch that only finishes after close must never report ready.
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
      await pool.end().catch(() => undefined);
    },
  };
}
