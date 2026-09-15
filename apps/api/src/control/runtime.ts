import {
  asControlPolicyPool,
  createDatabasePool,
  ControlPolicyStore,
} from "@openarc/db";

import type { ControlPolicyAuthPort } from "./ports.js";
import { PolicyService } from "./service.js";

/**
 * Dedicated runtime wiring for the protected control policy management family.
 *
 * The server NEVER runs migrations. When (and only when) policy management is
 * enabled this runtime opens EXACTLY ONE owned pool bound to the dedicated
 * restricted `openarc_tenant_app` role, constructs the accepted
 * `ControlPolicyStore`, initializes it exactly once before any route may serve,
 * and shares that one store with the `PolicyService`. No per-store pool, no
 * global/auth pool and no SQL migration is ever created.
 *
 * Input is explicit: the dedicated restricted database URL plus the accepted
 * auth seam. A missing/invalid URL or auth port fails closed BEFORE any pool is
 * constructed. ALL post-pool construction (store adapter, store construction,
 * store initialization and `PolicyService` construction) is protected by the
 * same cleanup boundary: any failure owns the one pool, closes it exactly once
 * and throws a fixed non-echoing error so the caller fails startup closed.
 *
 * `ready()` is a bounded read-only readiness re-check that never migrates and
 * never probes while disabled (the runtime is not constructed when disabled).
 * It is single-flight: concurrent and repeated calls while a probe is still in
 * flight share that ONE batch, so an uncancellable old probe can never be
 * multiplied. A fixed 2000ms deadline fails the await closed without clearing
 * the underlying batch; a late completion after close can never promote
 * readiness. `close()` ends the owned pool exactly once.
 */

const READINESS_DEADLINE_MS = 2000;

export interface ControlRuntimeDependencies {
  readonly policyDatabaseUrl: string;
  readonly auth: ControlPolicyAuthPort;
}

export interface StartedControlRuntime {
  readonly service: PolicyService;
  ready(): Promise<boolean>;
  close(): Promise<void>;
}

/** Fixed input rejection raised BEFORE any pool or store is constructed. */
function invalidInput(): never {
  throw new Error("CONTROL_RUNTIME_INVALID_INPUT");
}

function unavailable(): never {
  throw new Error("CONTROL_RUNTIME_UNAVAILABLE");
}

function isAuthPort(value: unknown): value is ControlPolicyAuthPort {
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

export async function startControlRuntime(
  dependencies: ControlRuntimeDependencies,
): Promise<StartedControlRuntime> {
  const databaseUrl = dependencies.policyDatabaseUrl;
  if (typeof databaseUrl !== "string" || databaseUrl.length === 0) {
    invalidInput();
  }
  if (!isAuthPort(dependencies.auth)) invalidInput();

  let pool: ReturnType<typeof createDatabasePool>;
  try {
    pool = createDatabasePool(databaseUrl);
  } catch {
    unavailable();
  }

  let store: ControlPolicyStore;
  let service: PolicyService;
  try {
    store = new ControlPolicyStore(asControlPolicyPool(pool));
    await store.initialize();
    // Service construction is INSIDE the same cleanup boundary: a throw here
    // must still close the one owned pool exactly once.
    service = new PolicyService({ auth: dependencies.auth, store });
  } catch {
    // Any post-pool construction/initialization failure owns the one pool:
    // close it once, then fail with a fixed non-echoing error.
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
