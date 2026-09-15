import { createApp } from "./app.js";
import { authCookieNames } from "./auth/cookies.js";
import { startAuthRuntime, type StartedAuthRuntime } from "./auth/runtime.js";
import { startTenantRuntime, type StartedTenantRuntime } from "./tenant/runtime.js";
import { startMarketRuntime, type StartedMarketRuntime } from "./market/runtime.js";
import { startMachineRuntime, type StartedMachineRuntime } from "./machine/runtime.js";
import { startControlRuntime, type StartedControlRuntime } from "./control/runtime.js";
import { startCommerceSessionRuntime, type StartedCommerceSessionRuntime } from "./control/session-runtime.js";
import { startCommerceActionRuntime, type StartedCommerceActionRuntime } from "./control/action-runtime.js";
import {
  createCommerceActionStoreAdapter,
  createCommerceSessionReadAdapter,
} from "./control/action-store-adapter.js";
import { startCommerceGrantRuntime, type StartedCommerceGrantRuntime } from "./control/grant-runtime.js";
import {
  createCommerceGrantSessionReadAdapter,
  createCommerceGrantStoreAdapter,
} from "./control/grant-store-adapter.js";
import { ArcAccountService } from "./arc/account-service.js";
import { AgentRegistryService } from "./arc/agent-registry-service.js";
import { JobService } from "./arc/job-service.js";
import { ArcRpcClient } from "./arc/rpc-client.js";
import { ArcTransactionService } from "./arc/transaction-service.js";
import { loadConfig } from "./config.js";
import {
  asCommerceSessionPool,
  asControlActionPool,
  asControlActionReadPool,
  asControlGrantPool,
  CommerceSessionStore,
  ControlActionReadStore,
  ControlActionStore,
  ControlGrantStore,
  createDatabasePool,
} from "@openarc/db";
import { connectBudgetRedis, SourceBudget } from "./limits/budget.js";
import { AggregateMetrics } from "./ops/metrics.js";
import { BoundedProviderClient } from "./providers/http.js";
import { BoundedGatewayClient } from "./gateway/client.js";
import { GatewayTransferService } from "./gateway/transfer-service.js";

/**
 * Opens the commerce-action family's ONE owned restricted pool and binds every
 * seam the action runtime requires.
 *
 * The runtime deliberately owns no pool and constructs no repository, so the
 * concrete DB10 mutation store, the DB11 read store and the DB9/DB13
 * commerce-session read are all built here over that single pool, exactly as
 * the commerce-session runtime builds its own. The `lifecycle` seam hands the
 * runtime the initialize/readiness/close of what THIS function owns: the three
 * stores are initialized once before any route may serve, readiness re-probes
 * all three read-only, and `closePool` ends the one pool exactly once no matter
 * how often it is reached (the runtime's construction-failure catch, the
 * handle's `close()`, shutdown and the startup catch all funnel into it).
 *
 * The gate stays DEFAULT OFF: this is only reached when the flag is explicitly
 * on. If the runtime still reports `built_disabled` — a seam missing or
 * malformed — nothing is left open and no service is handed to `createApp`, so
 * startup fails closed rather than serving a family the manifest advertises.
 */
async function startBoundCommerceActionRuntime(
  tenantDatabaseUrl: string,
  authSecret: string,
  auth: NonNullable<StartedAuthRuntime>["service"],
  rateLimitStore: NonNullable<StartedAuthRuntime>["rateLimitStore"],
): Promise<StartedCommerceActionRuntime> {
  const pool = createDatabasePool(tenantDatabaseUrl);
  let poolClosed = false;
  const closePool = async (): Promise<void> => {
    if (poolClosed) return;
    poolClosed = true;
    await pool.end().catch(() => undefined);
  };
  try {
    const mutations = new ControlActionStore(asControlActionPool(pool));
    const reads = new ControlActionReadStore(asControlActionReadPool(pool));
    const sessions = new CommerceSessionStore(asCommerceSessionPool(pool));
    const started = await startCommerceActionRuntime({
      enabled: true,
      authSecret,
      auth,
      rateLimitStore,
      store: createCommerceActionStoreAdapter(mutations, reads),
      commerceSessions: createCommerceSessionReadAdapter(sessions),
      lifecycle: {
        initialize: async (): Promise<void> => {
          await mutations.initialize();
          await reads.initialize();
          await sessions.initialize();
        },
        readiness: async (): Promise<void> => {
          await mutations.readiness();
          await reads.readiness();
          await sessions.readiness();
        },
        close: closePool,
      },
    });
    // A `built_disabled` outcome never runs the lifecycle, so the pool this
    // function opened would otherwise leak. Release it here instead.
    if (started.service === undefined) await closePool();
    return started;
  } catch (error) {
    await closePool();
    throw error;
  }
}

/**
 * Opens the authorization-grant family's ONE owned restricted pool and binds
 * every seam the grant runtime requires.
 *
 * The runtime deliberately owns no pool and constructs no repository, so the
 * concrete DB12 grant store and the DB9/DB13 commerce-session read are both
 * built here over that single pool, exactly as the commerce-action runtime
 * builds its own. The `lifecycle` seam hands the runtime the
 * initialize/readiness/close of what THIS function owns: both stores are
 * initialized once before any route may serve, readiness re-probes both
 * read-only, and `closePool` ends the one pool exactly once no matter how often
 * it is reached (the runtime's construction-failure catch, the handle's
 * `close()`, shutdown and the startup catch all funnel into it).
 *
 * The gate stays DEFAULT OFF: this is only reached when the flag is explicitly
 * on. If the runtime still reports `built_disabled` — a seam missing or
 * malformed — nothing is left open and no service is handed to `createApp`, so
 * startup fails closed rather than serving a family the manifest advertises.
 */
async function startBoundCommerceGrantRuntime(
  tenantDatabaseUrl: string,
  authSecret: string,
  auth: NonNullable<StartedAuthRuntime>["service"],
  rateLimitStore: NonNullable<StartedAuthRuntime>["rateLimitStore"],
): Promise<StartedCommerceGrantRuntime> {
  const pool = createDatabasePool(tenantDatabaseUrl);
  let poolClosed = false;
  const closePool = async (): Promise<void> => {
    if (poolClosed) return;
    poolClosed = true;
    await pool.end().catch(() => undefined);
  };
  try {
    const grants = new ControlGrantStore(asControlGrantPool(pool));
    const sessions = new CommerceSessionStore(asCommerceSessionPool(pool));
    const started = await startCommerceGrantRuntime({
      enabled: true,
      authSecret,
      auth,
      rateLimitStore,
      store: createCommerceGrantStoreAdapter(grants),
      commerceSessions: createCommerceGrantSessionReadAdapter(sessions),
      lifecycle: {
        initialize: async (): Promise<void> => {
          await grants.initialize();
          await sessions.initialize();
        },
        readiness: async (): Promise<void> => {
          await grants.readiness();
          await sessions.readiness();
        },
        close: closePool,
      },
    });
    // A `built_disabled` outcome never runs the lifecycle, so the pool this
    // function opened would otherwise leak. Release it here instead.
    if (started.service === undefined) await closePool();
    return started;
  } catch (error) {
    await closePool();
    throw error;
  }
}

async function start(): Promise<void> {
  const config = loadConfig();
  const metrics = new AggregateMetrics();
  let authRuntimeHandle: StartedAuthRuntime | undefined;
  let tenantRuntimeHandle: StartedTenantRuntime | undefined;
  let marketRuntimeHandle: StartedMarketRuntime | undefined;
  let machineRuntimeHandle: StartedMachineRuntime | undefined;
  let controlRuntimeHandle: StartedControlRuntime | undefined;
  let commerceSessionRuntimeHandle: StartedCommerceSessionRuntime | undefined;
  let commerceActionRuntimeHandle: StartedCommerceActionRuntime | undefined;
  let commerceGrantRuntimeHandle: StartedCommerceGrantRuntime | undefined;
  let redis: Awaited<ReturnType<typeof connectBudgetRedis>> | undefined;
  let sourceBudget: SourceBudget | undefined;
  let rpc: ArcRpcClient | undefined;
  let app: ReturnType<typeof createApp> | undefined;
  try {
    authRuntimeHandle = config.AUTH_ENABLED
      ? await startAuthRuntime({
          authDatabaseUrl: config.AUTH_DATABASE_URL as string,
          authSecret: config.AUTH_SECRET as string,
          appOrigin: config.APP_ORIGIN,
          rpId: config.AUTH_RP_ID as string,
          environment: config.NODE_ENV === "production" ? "production" : "development",
          secureCookies: config.APP_ORIGIN.startsWith("https://"),
          cookieNames: authCookieNames(config.APP_ORIGIN.startsWith("https://")),
          rateLimits: {
            globalLimit: config.AUTH_RATE_GLOBAL_PER_MINUTE,
            globalWindowSeconds: 60,
            peerLimit: config.AUTH_RATE_PEER_PER_HOUR,
            peerWindowSeconds: 3600,
            bindingLimit: config.AUTH_RATE_BINDING_PER_HOUR,
            bindingWindowSeconds: 3600,
            recoveryLimit: config.AUTH_RATE_RECOVERY_PER_15MIN,
            recoveryWindowSeconds: 900,
          },
      })
      : undefined;
    tenantRuntimeHandle = config.TENANT_READS_ENABLED
      ? await startTenantRuntime({
          tenantDatabaseUrl: config.TENANT_DATABASE_URL as string,
          auth: authRuntimeHandle!.service,
          writesEnabled: config.TENANT_WRITES_ENABLED,
          writeAuth: authRuntimeHandle!.service,
        })
      : undefined;
    const marketEnabled =
      config.MARKET_CATALOG_ENABLED ||
      config.LISTING_MANAGEMENT_ENABLED ||
      config.MARKET_MODERATION_ENABLED;
    marketRuntimeHandle = marketEnabled
      ? await startMarketRuntime({
          marketDatabaseUrl: config.TENANT_DATABASE_URL as string,
          catalogEnabled: config.MARKET_CATALOG_ENABLED,
          listingManagementEnabled: config.LISTING_MANAGEMENT_ENABLED,
          moderationEnabled: config.MARKET_MODERATION_ENABLED,
          // The protected browser families need the auth seam; a catalog-only
          // runtime gets none and never dereferences one.
          ...(config.LISTING_MANAGEMENT_ENABLED ||
          config.MARKET_MODERATION_ENABLED
            ? { auth: authRuntimeHandle!.service }
            : {}),
        })
      : undefined;
    const machineEnabled =
      config.MACHINE_CREDENTIAL_MANAGEMENT_ENABLED ||
      config.MACHINE_SESSION_EXCHANGE_ENABLED;
    machineRuntimeHandle = machineEnabled
      ? await startMachineRuntime({
          tenantDatabaseUrl: config.TENANT_DATABASE_URL as string,
          currentPepperVersion: config.MACHINE_CREDENTIAL_PEPPER_VERSION as number,
          currentPepper: config.MACHINE_CREDENTIAL_PEPPER as string,
          ...(config.MACHINE_CREDENTIAL_PREVIOUS_VERSION !== undefined
            ? { previousPepperVersion: config.MACHINE_CREDENTIAL_PREVIOUS_VERSION }
            : {}),
          ...(config.MACHINE_CREDENTIAL_PREVIOUS_PEPPER !== undefined
            ? { previousPepper: config.MACHINE_CREDENTIAL_PREVIOUS_PEPPER }
            : {}),
          rateSecret: config.MACHINE_RATE_SECRET as string,
          rateLimitStore: authRuntimeHandle!.rateLimitStore,
          managementAuth: authRuntimeHandle!.service,
        })
      : undefined;
    controlRuntimeHandle = config.POLICY_MANAGEMENT_ENABLED
      ? await startControlRuntime({
          policyDatabaseUrl: config.TENANT_DATABASE_URL as string,
          auth: authRuntimeHandle!.service,
        })
      : undefined;
    commerceSessionRuntimeHandle = config.COMMERCE_SESSIONS_ENABLED
      ? await startCommerceSessionRuntime({
          tenantDatabaseUrl: config.TENANT_DATABASE_URL as string,
          authSecret: config.AUTH_SECRET as string,
          auth: authRuntimeHandle!.service,
          rateLimitStore: authRuntimeHandle!.rateLimitStore,
        })
      : undefined;
    // The commerce-action family is DEFAULT OFF and fails closed. The runtime
    // owns no pool and constructs no repository, so every seam — the DB10
    // mutation store, the DB11 read store and the DB9/DB13 commerce-session
    // read — is built over one owned restricted pool by the helper below and
    // injected. With any seam missing or malformed the runtime still reports
    // `built_disabled`, exposes NO service and performs zero side effects, and
    // `createApp` then fails startup rather than serving a family the
    // capability manifest advertises. This runtime is opened, handed to
    // `createApp` and closed exactly like the commerce-session runtime above.
    commerceActionRuntimeHandle = config.COMMERCE_ACTIONS_ENABLED
      ? await startBoundCommerceActionRuntime(
          config.TENANT_DATABASE_URL as string,
          config.AUTH_SECRET as string,
          authRuntimeHandle!.service,
          authRuntimeHandle!.rateLimitStore,
        )
      : undefined;
    // The authorization-grant family is DEFAULT OFF and fails closed, with the
    // same discipline as the commerce-action family above: the runtime owns no
    // pool and constructs no repository, every seam is built over one owned
    // restricted pool by the helper above and injected, and a `built_disabled`
    // outcome hands `createApp` no service so startup fails closed rather than
    // serving a family the capability manifest advertises.
    commerceGrantRuntimeHandle = config.COMMERCE_GRANTS_ENABLED
      ? await startBoundCommerceGrantRuntime(
          config.TENANT_DATABASE_URL as string,
          config.AUTH_SECRET as string,
          authRuntimeHandle!.service,
          authRuntimeHandle!.rateLimitStore,
        )
      : undefined;
    redis = config.ARC_OBSERVATION_ENABLED && config.REDIS_URL ? await connectBudgetRedis(config.REDIS_URL) : undefined;
    sourceBudget = redis && config.ABUSE_LIMIT_SECRET ? new SourceBudget(redis, {
      secret: config.ABUSE_LIMIT_SECRET,
      requestsPerPeerHour: config.REQUESTS_PER_IP_HOUR,
      globalUnitsPerDay: config.GLOBAL_SOURCE_UNITS_PER_DAY,
      maxSubcalls: config.SOURCE_MAX_SUBCALLS,
      observe: (source, event) => metrics.recordBudget(source, event),
    }) : undefined;
    rpc = config.ARC_OBSERVATION_ENABLED ? new ArcRpcClient(new BoundedProviderClient({
      timeoutMs: config.SOURCE_TIMEOUT_MS,
      maxResponseBytes: config.SOURCE_MAX_RESPONSE_BYTES,
    })) : undefined;
    app = createApp({ config, metrics,
      ...(authRuntimeHandle
        ? { authService: authRuntimeHandle.service, authReady: () => authRuntimeHandle!.ready() }
        : {}),
      ...(tenantRuntimeHandle
        ? { tenantReadService: tenantRuntimeHandle.service, tenantReady: () => tenantRuntimeHandle!.ready(),
            ...(tenantRuntimeHandle.writeService !== undefined
              ? { tenantWriteService: tenantRuntimeHandle.writeService }
              : {}) }
        : {}),
      ...(marketRuntimeHandle
        ? {
            ...(marketRuntimeHandle.service !== undefined
              ? { marketService: marketRuntimeHandle.service }
              : {}),
            ...(marketRuntimeHandle.lifecycleService !== undefined
              ? { marketLifecycleService: marketRuntimeHandle.lifecycleService }
              : {}),
            ...(marketRuntimeHandle.catalogService !== undefined
              ? { marketCatalogService: marketRuntimeHandle.catalogService }
              : {}),
            marketReady: () => marketRuntimeHandle!.ready(),
          }
        : {}),
      ...(machineRuntimeHandle
        ? {
            machineManagementService: machineRuntimeHandle.managementService,
            machineSessionService: machineRuntimeHandle.sessionService,
            machineReady: () => machineRuntimeHandle!.ready(),
          }
        : {}),
      ...(controlRuntimeHandle
        ? {
            policyManagementService: controlRuntimeHandle.service,
            policyReady: () => controlRuntimeHandle!.ready(),
          }
        : {}),
      ...(commerceSessionRuntimeHandle
        ? {
            commerceSessionService: commerceSessionRuntimeHandle.service,
            commerceSessionReady: () => commerceSessionRuntimeHandle!.ready(),
          }
        : {}),
      // A `built_disabled` action runtime exposes no service, so nothing is
      // handed over and `createApp` fails startup closed rather than serving an
      // enabled family with no store behind it.
      ...(commerceActionRuntimeHandle?.service !== undefined
        ? {
            commerceActionService: commerceActionRuntimeHandle.service,
            commerceActionReady: () => commerceActionRuntimeHandle!.ready(),
          }
        : {}),
      // A `built_disabled` grant runtime exposes no service, so nothing is
      // handed over and `createApp` fails startup closed rather than serving an
      // enabled family with no store behind it.
      ...(commerceGrantRuntimeHandle?.service !== undefined
        ? {
            commerceGrantService: commerceGrantRuntimeHandle.service,
            commerceGrantReady: () => commerceGrantRuntimeHandle!.ready(),
          }
        : {}),
      ...(config.GATEWAY_EVIDENCE_ENABLED ? { gatewayTransferService: new GatewayTransferService(new BoundedGatewayClient({
        timeoutMs: config.SOURCE_TIMEOUT_MS, maxResponseBytes: config.SOURCE_MAX_RESPONSE_BYTES,
      })) } : {}),
      ...(sourceBudget ? { sourceBudget } : {}),
      ...(rpc ? { arcAccountService: new ArcAccountService(rpc), arcTransactionService: new ArcTransactionService(rpc),
        ...(config.AGENT_REGISTRY_ENABLED ? { agentRegistryService: new AgentRegistryService(rpc) } : {}),
        ...(config.AGENT_JOBS_ENABLED ? { jobService: new JobService(rpc) } : {}) } : {}) });
    const running = app;
    const shutdown = async (): Promise<void> => {
      await running.close();
      await authRuntimeHandle?.close();
      await tenantRuntimeHandle?.close();
      await marketRuntimeHandle?.close();
      await machineRuntimeHandle?.close();
      await controlRuntimeHandle?.close();
      await commerceSessionRuntimeHandle?.close();
      await commerceActionRuntimeHandle?.close();
      await commerceGrantRuntimeHandle?.close();
      if (redis?.isOpen) redis.destroy();
      process.exit(0);
    };
    process.once("SIGINT", () => void shutdown());
    process.once("SIGTERM", () => void shutdown());
    await running.listen({ host: config.HOST, port: config.PORT });
  } catch (error) {
    // Server construction/listen failure owns every already-opened runtime:
    // close each exactly once (idempotent) so no pool is leaked, then rethrow.
    await app?.close().catch(() => undefined);
    await authRuntimeHandle?.close().catch(() => undefined);
    await tenantRuntimeHandle?.close().catch(() => undefined);
    await marketRuntimeHandle?.close().catch(() => undefined);
    await machineRuntimeHandle?.close().catch(() => undefined);
    await controlRuntimeHandle?.close().catch(() => undefined);
    await commerceSessionRuntimeHandle?.close().catch(() => undefined);
    await commerceActionRuntimeHandle?.close().catch(() => undefined);
    await commerceGrantRuntimeHandle?.close().catch(() => undefined);
    if (redis?.isOpen) redis.destroy();
    throw error;
  }
}

void start().catch(() => {
  // Never serialize environment validation, transport errors, identifiers, or stacks.
  process.stderr.write('{"event":"startup_failed","code":"CONFIGURATION_OR_LISTEN_FAILED"}\n');
  process.exit(1);
});
