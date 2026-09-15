import {
  API_ERRORS, API_MAX_REQUEST_BYTES, API_MAX_RESPONSE_BYTES, API_SCHEMA_VERSION,
  AGENT_REGISTRY_EVIDENCE_PATH, ARC_ERC8004,
  COMMERCE_CAPABILITIES_PATH,
  CONTROL_CAPABILITIES_PATH,
  ARC_ACCOUNT_SNAPSHOT_PATH, ARC_TESTNET, ARC_TRANSACTION_EVIDENCE_PATH,
  ArcAccountSnapshotEnvelopeSchema, ArcAccountSnapshotRequestSchema,
  ArcTransactionEvidenceEnvelopeSchema, ArcTransactionEvidenceRequestSchema,
  AgentRegistryEvidenceEnvelopeSchema, AgentRegistryEvidenceRequestSchema,
  CAPABILITIES_PATH, CapabilitiesEnvelopeSchema, type ApiErrorCode,
  type ArcAccountSnapshotEnvelope, type ArcAccountSnapshotRequest,
  type ArcTransactionEvidenceEnvelope, type ArcTransactionEvidenceRequest,
  type AgentRegistryEvidenceEnvelope, type AgentRegistryEvidenceRequest,
  ARC_ERC8183, JOB_EVIDENCE_PATH, JobEvidenceRequestSchema, JobEvidenceEnvelopeSchema,
  type JobEvidenceRequest,
  GATEWAY_TRANSFER_PATH, GatewayTransferRequestSchema, GatewayTransferEnvelopeSchema, type GatewayTransferRequest,
  MARKETPLACE_CAPABILITIES_PATH,
  SESSION_CAPABILITIES_PATH,
  ACTION_CAPABILITIES_PATH,
  GRANT_CAPABILITIES_PATH,
  PAYMENT_CAPABILITIES_PATH,
} from "@openarc/shared";
import { randomUUID } from "node:crypto";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";

import type { ApiConfig } from "./config.js";
import type { ArcAccountService } from "./arc/account-service.js";
import type { AgentRegistryService } from "./arc/agent-registry-service.js";
import type { JobService } from "./arc/job-service.js";
import type { GatewayTransferService } from "./gateway/transfer-service.js";
import type { ArcTransactionService } from "./arc/transaction-service.js";
import { authCookieNames } from "./auth/cookies.js";
import { AUTH_ERRORS, AuthApiError, authErrorEnvelope } from "./auth/errors.js";
import { AUTH_ROUTE_PATHS, registerAuthRoutes } from "./auth/routes.js";
import type { AuthService } from "./auth/service.js";
import { registerTenantRoutes, TENANT_ROUTE_PREFIX } from "./tenant/routes.js";
import type { TenantReadService } from "./tenant/service.js";
import { registerTenantWriteRoutes } from "./tenant/write-routes.js";
import type { TenantWriteService } from "./tenant/write-service.js";
import { registerMarketRoutes, MARKET_ROUTE_PREFIX } from "./market/routes.js";
import type { MarketService } from "./market/service.js";
import { registerMarketLifecycleRoutes } from "./market/lifecycle-routes.js";
import type { MarketLifecycleService } from "./market/lifecycle-service.js";
import { registerMarketCatalogRoutes } from "./market/catalog-routes.js";
import type { MarketCatalogService } from "./market/catalog-service.js";
import { registerMachineManagementRoutes } from "./machine/management-routes.js";
import { registerMachineSessionRoutes, isMachineSessionFamilyPath } from "./machine/session-routes.js";
import type { MachineManagementService } from "./machine/management-service.js";
import type { MachineSessionService } from "./machine/session-service.js";
import { registerCommerceCapabilities } from "./commerce/capabilities.js";
import { registerMarketplaceCapabilities } from "./commerce/marketplace-capabilities.js";
import { registerControlCapabilities } from "./commerce/control-capabilities.js";
import { registerSessionCapabilities } from "./commerce/session-capabilities.js";
import { registerActionCapabilities } from "./commerce/action-capabilities.js";
import { registerGrantCapabilities } from "./commerce/grant-capabilities.js";
import { registerPaymentCapabilities } from "./commerce/payment-capabilities.js";
import { registerPolicyRoutes, CONTROL_ROUTE_PREFIX } from "./control/routes.js";
import type { PolicyService } from "./control/service.js";
import { registerCommerceSessionRoutes } from "./control/session-routes.js";
import type { CommerceSessionService } from "./control/session-service.js";
import { registerCommerceActionRoutes } from "./control/action-routes.js";
import type { CommerceActionService } from "./control/action-service.js";
import { registerCommerceGrantRoutes } from "./control/grant-routes.js";
import type { CommerceGrantService } from "./control/grant-service.js";
import { registerCommercePaymentRoutes } from "./control/payment-routes.js";
import type { CommercePaymentService } from "./control/payment-service.js";
import { ApiBoundaryError, apiErrorEnvelope, normalizeApiError } from "./http/errors.js";
import { verifyBrowserOrigin, verifyPreflight } from "./http/origin.js";
import { registerSourceRoute } from "./http/source-route.js";
import type { SourceBudget } from "./limits/budget.js";
import { AggregateMetrics, durationBucket, metricsAuthorized, safeMethod,
  type DurationBucket, type RouteClass, type SafeMethod } from "./ops/metrics.js";

export interface CompletionLog {
  requestId: string;
  route: RouteClass;
  method: SafeMethod;
  status: number;
  duration: DurationBucket;
  failureCode: ApiErrorCode | null;
  buildSha: string;
}

export interface CreateAppOptions {
  config: ApiConfig;
  logger?: boolean;
  logSink?: (entry: Readonly<CompletionLog>) => void;
  metrics?: AggregateMetrics;
  sourceBudget?: SourceBudget;
  arcAccountService?: ArcAccountService;
  arcTransactionService?: ArcTransactionService;
  agentRegistryService?: AgentRegistryService;
  jobService?: JobService;
  gatewayTransferService?: GatewayTransferService;
  authService?: AuthService;
  authReady?: () => Promise<boolean>;
  tenantReadService?: TenantReadService;
  tenantWriteService?: TenantWriteService;
  tenantReady?: () => Promise<boolean>;
  tenantMaxResponseBytes?: number;
  marketService?: MarketService;
  marketLifecycleService?: MarketLifecycleService;
  marketCatalogService?: MarketCatalogService;
  marketReady?: () => Promise<boolean>;
  marketMaxResponseBytes?: number;
  machineManagementService?: MachineManagementService;
  machineSessionService?: MachineSessionService;
  machineReady?: () => Promise<boolean>;
  policyManagementService?: PolicyService;
  policyReady?: () => Promise<boolean>;
  commerceSessionService?: CommerceSessionService;
  commerceSessionReady?: () => Promise<boolean>;
  commerceActionService?: CommerceActionService;
  commerceActionReady?: () => Promise<boolean>;
  commerceGrantService?: CommerceGrantService;
  commerceGrantReady?: () => Promise<boolean>;
  commercePaymentService?: CommercePaymentService;
  commercePaymentReady?: () => Promise<boolean>;
}

const disabledPaths = [
  "/v1/private/gateway/transfer-evidence",
] as const;

/**
 * The exact bounded protected tenant family is the route root or the root plus
 * a slash. A bare `startsWith` would capture lookalike paths such as
 * `/v1/operator/organizationsXYZ`, so those keep their legacy behavior.
 */
function isTenantFamilyPath(path: string): boolean {
  return (
    path === TENANT_ROUTE_PREFIX || path.startsWith(`${TENANT_ROUTE_PREFIX}/`)
  );
}

/**
 * The exact bounded protected market family is the route root or the root plus
 * a slash. A bare `startsWith` would capture lookalike paths such as
 * `/v2/provider/organizationsXYZ`, so those keep their legacy behavior.
 */
function isMarketFamilyPath(path: string): boolean {
  return (
    path === MARKET_ROUTE_PREFIX || path.startsWith(`${MARKET_ROUTE_PREFIX}/`)
  );
}

/**
 * Exact roots of the two NEW protected marketplace families and the public
 * catalog family. Only the root itself or the root plus a slash carries
 * authority: lookalike prefixes such as `/v2/public/marketXYZ` keep the
 * ordinary legacy 404 and are never treated as this family.
 */
function isModeratorFamilyPath(path: string): boolean {
  return (
    path === "/v2/moderator/organizations" ||
    path.startsWith("/v2/moderator/organizations/")
  );
}

function isPublicMarketFamilyPath(path: string): boolean {
  return (
    path === "/v2/public/market" || path.startsWith("/v2/public/market/")
  );
}

/** Any exact new marketplace family root (threaded through v2 error mapping). */
function isMarketplaceFamilyPath(path: string): boolean {
  return (
    isMarketFamilyPath(path) ||
    isModeratorFamilyPath(path) ||
    isPublicMarketFamilyPath(path)
  );
}

/**
 * The exact machine management family shares the tenant prefix and is matched
 * BEFORE the broader tenant family so its routes are classified and mapped as
 * machine, not tenant. Session routes live under `/v1/agent` and `/v1/provider`.
 */
function isMachineManagementPath(path: string): boolean {
  if (!path.startsWith(`${TENANT_ROUTE_PREFIX}/`)) return false;
  return (
    path.includes("/agent-credentials/") ||
    path.includes("/provider-credentials/") ||
    path.includes("/agent-credential-mutations/") ||
    path.includes("/provider-credential-mutations/") ||
    /\/agents\/[^/]+\/credentials(?:\/|$)/u.test(path) ||
    /\/providers\/[^/]+\/credentials(?:\/|$)/u.test(path)
  );
}

function isMachinePath(path: string): boolean {
  return isMachineManagementPath(path) || isMachineSessionFamilyPath(path);
}

/**
 * The exact bounded protected control policy family is the route root or the
 * root plus a slash. A bare `startsWith` would capture lookalike paths such as
 * `/v2/control/organizationsXYZ`, so those keep the ordinary legacy 404.
 */
function isControlFamilyPath(path: string): boolean {
  return (
    path === CONTROL_ROUTE_PREFIX ||
    path.startsWith(`${CONTROL_ROUTE_PREFIX}/`)
  );
}

/**
 * Exact bounded agent-family roots of the protected commerce-session surface.
 * The browser routes share the control policy root and are already classified
 * as control; only the two agent targets need their own exact match so that
 * lookalike prefixes keep the ordinary legacy behavior and never capture
 * authority. `/v2/agent/commerce-sessions` and
 * `/v2/agent/commerce-session-mutations` are distinct from the old `/v1/agent`
 * machine routes.
 */
function isCommerceSessionAgentPath(path: string): boolean {
  return (
    path === "/v2/agent/commerce-sessions" ||
    path.startsWith("/v2/agent/commerce-sessions/") ||
    path === "/v2/agent/commerce-session-mutations" ||
    path.startsWith("/v2/agent/commerce-session-mutations/")
  );
}

/**
 * Exact bounded agent-family roots of the protected commerce-action surface.
 * The nine browser action routes share the control policy root and are already
 * classified as control; only the agent targets need their own exact match so
 * lookalike prefixes never capture authority. `/v2/agent/commerce-actions` and
 * `/v2/agent/commerce-action-mutations` are distinct from the commerce-session
 * agent roots and from the old `/v1/agent` machine routes.
 */
function isCommerceActionAgentPath(path: string): boolean {
  return (
    path === "/v2/agent/commerce-actions" ||
    path.startsWith("/v2/agent/commerce-actions/") ||
    path === "/v2/agent/commerce-action-mutations" ||
    path.startsWith("/v2/agent/commerce-action-mutations/")
  );
}

/**
 * Exact bounded HEADLESS roots of the protected authorization-grant surface.
 * The three browser grant routes share the control organization root and are
 * already classified as control; only the agent and provider targets need
 * their own exact match so lookalike prefixes never capture authority. The two
 * provider roots are deliberately disjoint from the seller browser prefix
 * `/v2/provider/organizations/`.
 */
function isCommerceGrantHeadlessPath(path: string): boolean {
  return (
    path === "/v2/agent/commerce-grants" ||
    path.startsWith("/v2/agent/commerce-grants/") ||
    path === "/v2/agent/commerce-grant-mutations" ||
    path.startsWith("/v2/agent/commerce-grant-mutations/") ||
    path === "/v2/provider/grants" ||
    path.startsWith("/v2/provider/grants/") ||
    path === "/v2/provider/grant-attempts" ||
    path.startsWith("/v2/provider/grant-attempts/")
  );
}

/**
 * Exact bounded AGENT roots of the migration-0015 payment surface. The seller
 * terms route lives under the marketplace provider root and is already
 * classified there; only the agent targets need their own exact match.
 */
function isCommercePaymentAgentPath(path: string): boolean {
  return (
    path === "/v2/agent/commerce-payment-requirements" ||
    path.startsWith("/v2/agent/commerce-payment-requirements/") ||
    path === "/v2/agent/commerce-payment-attempts" ||
    path.startsWith("/v2/agent/commerce-payment-attempts/")
  );
}

/** Any exact protected commerce-session family root (browser or agent). */
function isCommerceSessionFamilyPath(path: string): boolean {
  return isControlFamilyPath(path) || isCommerceSessionAgentPath(path);
}

function routeClass(url: string): RouteClass {
  const path = url.split("?", 1)[0] ?? url;
  if (path === "/healthz") return "health";
  if (path === "/readyz") return "readiness";
  if (path === "/metrics") return "metrics";
  if ((AUTH_ROUTE_PATHS as readonly string[]).includes(path)) return "auth";
  // Machine routes are labelled with the EXISTING bounded `auth` class; no new
  // route class or raw path is introduced.
  if (isMachinePath(path)) return "auth";
  if (isTenantFamilyPath(path)) return "tenant";
  // The protected market family maps to the EXISTING coarse `tenant` metrics
  // label; no new route class or label is introduced.
  if (isMarketFamilyPath(path)) return "tenant";
  // The new protected/public marketplace families also map to the EXISTING
  // coarse `tenant` label; still no raw path or new label is introduced.
  if (isModeratorFamilyPath(path)) return "tenant";
  if (isPublicMarketFamilyPath(path)) return "tenant";
  // The protected control policy family maps to the EXISTING coarse `tenant`
  // metrics label; no new route class or label is introduced.
  if (isControlFamilyPath(path)) return "tenant";
  // The two agent commerce-session routes also map to the EXISTING coarse
  // `tenant` metrics label; no new route class or raw path is introduced.
  if (isCommerceSessionAgentPath(path)) return "tenant";
  // The three agent commerce-action routes also map to the EXISTING coarse
  // `tenant` metrics label; no new route class or raw path is introduced.
  if (isCommerceActionAgentPath(path)) return "tenant";
  // The agent and provider authorization-grant routes also map to the EXISTING
  // coarse `tenant` metrics label; no new route class or raw path is introduced.
  if (isCommerceGrantHeadlessPath(path)) return "tenant";
  // The agent payment routes map to the EXISTING coarse `tenant` label too.
  if (isCommercePaymentAgentPath(path)) return "tenant";
  if (path === CAPABILITIES_PATH) return "capabilities";
  if (path === COMMERCE_CAPABILITIES_PATH) return "capabilities";
  if (path === MARKETPLACE_CAPABILITIES_PATH) return "capabilities";
  if (path === CONTROL_CAPABILITIES_PATH) return "capabilities";
  if (path === SESSION_CAPABILITIES_PATH) return "capabilities";
  if (path === ACTION_CAPABILITIES_PATH) return "capabilities";
  if (path === GRANT_CAPABILITIES_PATH) return "capabilities";
  if (path === PAYMENT_CAPABILITIES_PATH) return "capabilities";
  if (path === ARC_ACCOUNT_SNAPSHOT_PATH) return "arc_account";
  if (path === ARC_TRANSACTION_EVIDENCE_PATH) return "arc_transaction";
  if (path === AGENT_REGISTRY_EVIDENCE_PATH) return "agent_registry";
  if (path === JOB_EVIDENCE_PATH) return "agent_job";
  if (path === GATEWAY_TRANSFER_PATH) return "gateway_transfer";
  if (disabledPaths.some((candidate) => candidate === path)) return "disabled_source";
  return "not_found";
}

export function createApp({ config, logger = config.NODE_ENV !== "test", logSink, metrics = new AggregateMetrics(),
  sourceBudget, arcAccountService, arcTransactionService, agentRegistryService, jobService, gatewayTransferService,
  authService, authReady, tenantReadService, tenantReady,
  tenantWriteService, tenantMaxResponseBytes,
  marketService, marketLifecycleService, marketCatalogService, marketReady, marketMaxResponseBytes,
  machineManagementService, machineSessionService, machineReady,
  policyManagementService, policyReady,
  commerceSessionService, commerceSessionReady,
  commerceActionService, commerceActionReady,
  commerceGrantService, commerceGrantReady,
  commercePaymentService, commercePaymentReady }: CreateAppOptions): FastifyInstance {
  // Framework request/error logging is disabled, including parser failures.
  // `frameworkErrors` receives errors raised before the normal request
  // lifecycle (notably `FST_ERR_BAD_URL` from the router) which otherwise
  // bypass `setErrorHandler` and echo the raw URL. The holder is wired to the
  // same `sendError` used for lifecycle errors once it is defined below.
  const frameworkErrorHandler: {
    current:
      | ((
          cause: unknown,
          request: FastifyRequest,
          reply: FastifyReply,
        ) => unknown)
      | null;
  } = { current: null };
  const app = Fastify({ logger: false, trustProxy: false, bodyLimit: API_MAX_REQUEST_BYTES,
    requestIdHeader: false, genReqId: () => randomUUID(), exposeHeadRoutes: false,
    requestTimeout: 10_000, connectionTimeout: 10_000, keepAliveTimeout: 5_000,
    frameworkErrors: (cause, request, reply) => {
      if (frameworkErrorHandler.current !== null) {
        return frameworkErrorHandler.current(cause, request, reply);
      }
      return reply.send(cause as never);
    } });
  const failures = new WeakMap<FastifyRequest, ApiErrorCode>();
  const started = new WeakMap<FastifyRequest, number>();
  const headers = (request: FastifyRequest, reply: FastifyReply) => {
    reply.headers({ "Cache-Control": "no-store", Pragma: "no-cache",
      "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
      "X-OpenArc-Request-Id": request.id });
    if (config.NODE_ENV === "production") reply.header("Strict-Transport-Security", "max-age=31536000");
  };
  app.addHook("onRequest", async (request, reply) => { started.set(request, performance.now()); headers(request, reply); });
  app.addHook("onSend", async (request, reply, payload) => { headers(request, reply); return payload; });
  app.addHook("onResponse", async (request, reply) => {
    const duration = durationBucket(performance.now() - (started.get(request) ?? performance.now()));
    const route = routeClass(request.url);
    metrics.record(route, reply.statusCode, duration);
    const failure = failures.get(request);
    if (failure) metrics.recordFailure(route, failure);
    const entry: CompletionLog = { requestId: request.id, route, method: safeMethod(request.method),
      status: reply.statusCode, duration, failureCode: failures.get(request) ?? null, buildSha: config.COMMIT_SHA };
    if (logSink) logSink(Object.freeze(entry));
    else if (logger && config.LOG_LEVEL !== "silent" &&
      (config.LOG_LEVEL === "info" || (config.LOG_LEVEL === "warn" && reply.statusCode >= 400) || reply.statusCode >= 500)) {
      process.stdout.write(`${JSON.stringify(entry)}\n`);
    }
  });

  const sendError = (request: FastifyRequest, reply: FastifyReply, cause: unknown) => {
    if (cause instanceof AuthApiError) {
      failures.set(request, cause.metricsCode);
      if (cause.retryAfterSeconds !== undefined) reply.header("Retry-After", String(cause.retryAfterSeconds));
      return reply.code(cause.status).send(authErrorEnvelope(cause, request.id, config.COMMIT_SHA));
    }
    const rawPath = request.url.split("?", 1)[0] ?? request.url;
    const causeCode =
      typeof cause === "object" && cause !== null && "code" in cause
        ? (cause as { code?: unknown }).code
        : null;
    const machineSurface = isMachinePath(rawPath);
    const commerceCapabilitySurface =
      rawPath === COMMERCE_CAPABILITIES_PATH ||
      rawPath === MARKETPLACE_CAPABILITIES_PATH ||
      rawPath === CONTROL_CAPABILITIES_PATH ||
      rawPath === SESSION_CAPABILITIES_PATH ||
      rawPath === ACTION_CAPABILITIES_PATH ||
      rawPath === GRANT_CAPABILITIES_PATH ||
      rawPath === PAYMENT_CAPABILITIES_PATH;
    const controlSurface = isControlFamilyPath(rawPath);
    const commerceSessionAgentSurface = isCommerceSessionAgentPath(rawPath);
    const commerceActionAgentSurface = isCommerceActionAgentPath(rawPath);
    const commerceGrantHeadlessSurface = isCommerceGrantHeadlessPath(rawPath);
    const commercePaymentAgentSurface = isCommercePaymentAgentPath(rawPath);
    const v2Surface =
      rawPath.startsWith("/v2/auth/") ||
      isTenantFamilyPath(rawPath) ||
      isMarketplaceFamilyPath(rawPath) ||
      controlSurface ||
      isCommerceSessionFamilyPath(rawPath) ||
      commerceActionAgentSurface ||
      commerceGrantHeadlessSurface ||
      commercePaymentAgentSurface ||
      commerceCapabilitySurface ||
      machineSurface;
    if (
      machineSurface &&
      cause instanceof ApiBoundaryError &&
      cause.code === "NOT_FOUND"
    ) {
      // Disabled management and unsupported machine-family paths stay on the
      // bounded machine surface: a fixed v2 404 envelope with no raw URL echo.
      // This is narrower than the tenant family and never changes legacy
      // behavior for non-machine paths.
      const mapped = new AuthApiError("FEATURE_DISABLED", 404, "NOT_FOUND");
      failures.set(request, mapped.metricsCode);
      return reply
        .code(mapped.status)
        .send(authErrorEnvelope(mapped, request.id, config.COMMIT_SHA));
    }
    if (
      isMarketplaceFamilyPath(rawPath) &&
      cause instanceof ApiBoundaryError &&
      cause.code === "NOT_FOUND"
    ) {
      // An unknown or currently-disabled path under an EXACT new marketplace
      // family root stays on the bounded v2 surface: a fixed envelope with no
      // raw URL echo. Lookalike prefixes are deliberately not matched, so they
      // keep their legacy behavior.
      const mapped = new AuthApiError("FEATURE_DISABLED", 404, "NOT_FOUND");
      failures.set(request, mapped.metricsCode);
      return reply
        .code(mapped.status)
        .send(authErrorEnvelope(mapped, request.id, config.COMMIT_SHA));
    }
    if (
      controlSurface &&
      cause instanceof ApiBoundaryError &&
      cause.code === "NOT_FOUND"
    ) {
      // An unknown or currently-disabled path under the EXACT control family
      // root stays on the bounded v2 surface: a fixed envelope with no raw URL
      // echo. Lookalike prefixes are deliberately not matched, so they keep
      // their legacy behavior.
      const mapped = new AuthApiError("FEATURE_DISABLED", 404, "NOT_FOUND");
      failures.set(request, mapped.metricsCode);
      return reply
        .code(mapped.status)
        .send(authErrorEnvelope(mapped, request.id, config.COMMIT_SHA));
    }
    if (
      commerceActionAgentSurface &&
      cause instanceof ApiBoundaryError &&
      cause.code === "NOT_FOUND"
    ) {
      // An unknown or currently-disabled agent commerce-action path stays on
      // the bounded v2 surface: a fixed envelope with no raw URL echo. Lookalike
      // prefixes are deliberately not matched, so they keep legacy behavior.
      const mapped = new AuthApiError("FEATURE_DISABLED", 404, "NOT_FOUND");
      failures.set(request, mapped.metricsCode);
      return reply
        .code(mapped.status)
        .send(authErrorEnvelope(mapped, request.id, config.COMMIT_SHA));
    }
    if (
      commerceGrantHeadlessSurface &&
      cause instanceof ApiBoundaryError &&
      cause.code === "NOT_FOUND"
    ) {
      // An unknown or currently-disabled agent/provider authorization-grant
      // path stays on the bounded v2 surface: a fixed envelope with no raw URL
      // echo. Lookalike prefixes are deliberately not matched, so they keep
      // legacy behavior.
      const mapped = new AuthApiError("FEATURE_DISABLED", 404, "NOT_FOUND");
      failures.set(request, mapped.metricsCode);
      return reply
        .code(mapped.status)
        .send(authErrorEnvelope(mapped, request.id, config.COMMIT_SHA));
    }
    if (
      commercePaymentAgentSurface &&
      cause instanceof ApiBoundaryError &&
      cause.code === "NOT_FOUND"
    ) {
      // An unknown or disabled agent payment path stays on the bounded v2
      // surface: a fixed envelope with no raw URL echo.
      const mapped = new AuthApiError("FEATURE_DISABLED", 404, "NOT_FOUND");
      failures.set(request, mapped.metricsCode);
      return reply
        .code(mapped.status)
        .send(authErrorEnvelope(mapped, request.id, config.COMMIT_SHA));
    }
    if (
      commerceSessionAgentSurface &&
      cause instanceof ApiBoundaryError &&
      cause.code === "NOT_FOUND"
    ) {
      // An unknown or currently-disabled agent commerce-session path stays on
      // the bounded v2 surface: a fixed envelope with no raw URL echo. Lookalike
      // prefixes are deliberately not matched, so they keep legacy behavior.
      const mapped = new AuthApiError("FEATURE_DISABLED", 404, "NOT_FOUND");
      failures.set(request, mapped.metricsCode);
      return reply
        .code(mapped.status)
        .send(authErrorEnvelope(mapped, request.id, config.COMMIT_SHA));
    }
    if (v2Surface && !(cause instanceof ApiBoundaryError && cause.code === "NOT_FOUND")) {
      // Parser, body-limit, media, unexpected and response-schema failures on
      // the account and protected tenant surfaces must still return a strict
      // v2 envelope with a correct status and no raw cause or caller data.
      // The tenant family is exact (root or root + slash): lookalike prefixes
      // keep the legacy path. A genuine NOT_FOUND (unknown route) is excluded
      // so routes outside the four frozen handlers stay a normal legacy 404.
      const normalized = normalizeApiError(cause);
      const mapped =
        causeCode === "FST_ERR_BAD_URL" ||
        normalized.code === "INVALID_REQUEST"
          ? AUTH_ERRORS.invalidRequest()
          : normalized.code === "REQUEST_TOO_LARGE"
            ? AUTH_ERRORS.tooLarge()
            : normalized.code === "UNSUPPORTED_MEDIA_TYPE"
              ? AUTH_ERRORS.unsupportedMedia()
              : AUTH_ERRORS.internal();
      failures.set(request, mapped.metricsCode);
      return reply
        .code(mapped.status)
        .send(authErrorEnvelope(mapped, request.id, config.COMMIT_SHA));
    }
    // A malformed URL on any non-v2 surface keeps the legacy 400 shape instead
    // of being misclassified as an internal error.
    const error =
      causeCode === "FST_ERR_BAD_URL"
        ? new ApiBoundaryError("INVALID_REQUEST")
        : normalizeApiError(cause);
    failures.set(request, error.code);
    if (error.retryAfterSeconds !== undefined) reply.header("Retry-After", String(error.retryAfterSeconds));
    return reply.code(API_ERRORS[error.code].status).send(apiErrorEnvelope(error, request.id, config.COMMIT_SHA));
  };
  app.setErrorHandler((cause, request, reply) => sendError(request, reply, cause));
  app.setNotFoundHandler((request, reply) => sendError(request, reply, new ApiBoundaryError("NOT_FOUND")));
  frameworkErrorHandler.current = (cause, request, reply) =>
    sendError(request, reply, cause);

  const build = { service: "openarc-api", version: "0.0.0", commitSha: config.COMMIT_SHA } as const;
  const machineEnabled =
    config.MACHINE_CREDENTIAL_MANAGEMENT_ENABLED ||
    config.MACHINE_SESSION_EXCHANGE_ENABLED;
  // Any of the three independent marketplace families activates the single
  // bounded marketDatabase readiness check; none activates auth/tenant checks
  // by itself.
  const marketEnabled =
    config.MARKET_CATALOG_ENABLED ||
    config.LISTING_MANAGEMENT_ENABLED ||
    config.MARKET_MODERATION_ENABLED;
  const policyEnabled = config.POLICY_MANAGEMENT_ENABLED;
  const sessionEnabled = config.COMMERCE_SESSIONS_ENABLED;
  // The capability manifest declares `commerceActionDatabase` as a dependency
  // of the enabled action family, so an operator must be able to see it. The
  // gate is DEFAULT OFF: while it is off the key is ABSENT from every readiness
  // payload and the callback is never invoked.
  const actionEnabled = config.COMMERCE_ACTIONS_ENABLED;
  // Same discipline for the authorization-grant family: DEFAULT OFF, so while
  // the gate is off `commerceGrantDatabase` is ABSENT from every readiness
  // payload and the callback is never invoked.
  const grantEnabled = config.COMMERCE_GRANTS_ENABLED;
  // Same discipline for the payment family: `commercePaymentDatabase` is ABSENT
  // while the gate is off and the callback is never invoked.
  const paymentEnabled = config.COMMERCE_PAYMENTS_ENABLED;
  app.get("/healthz", async () => ({ status: "ok" as const, ...build }));
  app.get("/readyz", async (_request, reply) => {
    if (config.AUTH_ENABLED) {
      const authReadyResult = authReady ? await authReady().catch(() => false) : false;
      if (!authReadyResult) {
        return reply.code(503).send({ ok: false as const, status: "not_ready" as const,
          checks: { configuration: "up", sourceRoutes: config.ARC_OBSERVATION_ENABLED ? "enabled" : "disabled",
            redis: config.ARC_OBSERVATION_ENABLED ? "not_checked" : "not_required", authDatabase: "down" }, ...build });
      }
    }
    if (config.TENANT_READS_ENABLED) {
      const tenantReadyResult = tenantReady ? await tenantReady().catch(() => false) : false;
      if (!tenantReadyResult) {
        return reply.code(503).send({ ok: false as const, status: "not_ready" as const,
          checks: { configuration: "up", sourceRoutes: config.ARC_OBSERVATION_ENABLED ? "enabled" : "disabled",
            redis: config.ARC_OBSERVATION_ENABLED ? "not_checked" : "not_required",
            ...(config.AUTH_ENABLED ? { authDatabase: "up" as const } : {}), tenantDatabase: "down" }, ...build });
      }
    }
    if (marketEnabled) {
      const marketReadyResult = marketReady ? await marketReady().catch(() => false) : false;
      if (!marketReadyResult) {
        return reply.code(503).send({ ok: false as const, status: "not_ready" as const,
          checks: { configuration: "up", sourceRoutes: config.ARC_OBSERVATION_ENABLED ? "enabled" : "disabled",
            redis: config.ARC_OBSERVATION_ENABLED ? "not_checked" : "not_required",
            ...(config.AUTH_ENABLED ? { authDatabase: "up" as const } : {}),
            ...(config.TENANT_READS_ENABLED ? { tenantDatabase: "up" as const } : {}),
            marketDatabase: "down" }, ...build });
      }
    }
    if (machineEnabled) {
      const machineReadyResult = machineReady ? await machineReady().catch(() => false) : false;
      if (!machineReadyResult) {
        return reply.code(503).send({ ok: false as const, status: "not_ready" as const,
          checks: { configuration: "up", sourceRoutes: config.ARC_OBSERVATION_ENABLED ? "enabled" : "disabled",
            redis: config.ARC_OBSERVATION_ENABLED ? "not_checked" : "not_required",
            ...(marketEnabled ? { marketDatabase: "up" as const } : {}),
            machineDatabase: "down" }, ...build });
      }
    }
    if (policyEnabled) {
      const policyReadyResult = policyReady ? await policyReady().catch(() => false) : false;
      if (!policyReadyResult) {
        return reply.code(503).send({ ok: false as const, status: "not_ready" as const,
          checks: { configuration: "up", sourceRoutes: config.ARC_OBSERVATION_ENABLED ? "enabled" : "disabled",
            redis: config.ARC_OBSERVATION_ENABLED ? "not_checked" : "not_required",
            ...(config.AUTH_ENABLED ? { authDatabase: "up" as const } : {}),
            ...(config.TENANT_READS_ENABLED ? { tenantDatabase: "up" as const } : {}),
            ...(marketEnabled ? { marketDatabase: "up" as const } : {}),
            ...(machineEnabled ? { machineDatabase: "up" as const } : {}),
            policyDatabase: "down" }, ...build });
      }
    }
    if (sessionEnabled) {
      // The enabled commerce-session family composes the restricted tenant,
      // machine/credential, policy and commerceSession schema readiness into
      // ONE session dependency. A failure reflects as commerceSessionDatabase
      // down; the flag never invokes the callback when disabled.
      const sessionReadyResult = commerceSessionReady
        ? await commerceSessionReady().catch(() => false)
        : false;
      if (!sessionReadyResult) {
        return reply.code(503).send({ ok: false as const, status: "not_ready" as const,
          checks: { configuration: "up", sourceRoutes: config.ARC_OBSERVATION_ENABLED ? "enabled" : "disabled",
            redis: config.ARC_OBSERVATION_ENABLED ? "not_checked" : "not_required",
            ...(config.AUTH_ENABLED ? { authDatabase: "up" as const } : {}),
            ...(config.TENANT_READS_ENABLED ? { tenantDatabase: "up" as const } : {}),
            ...(marketEnabled ? { marketDatabase: "up" as const } : {}),
            ...(machineEnabled ? { machineDatabase: "up" as const } : {}),
            ...(policyEnabled ? { policyDatabase: "up" as const } : {}),
            commerceSessionDatabase: "down" }, ...build });
      }
    }
    if (actionEnabled) {
      // The enabled commerce-action family composes its injected store's
      // readiness into ONE action dependency. A failure reflects as
      // commerceActionDatabase down; the flag never invokes the callback when
      // disabled, and a missing callback is `down`, never silently ready.
      const actionReadyResult = commerceActionReady
        ? await commerceActionReady().catch(() => false)
        : false;
      if (!actionReadyResult) {
        return reply.code(503).send({ ok: false as const, status: "not_ready" as const,
          checks: { configuration: "up", sourceRoutes: config.ARC_OBSERVATION_ENABLED ? "enabled" : "disabled",
            redis: config.ARC_OBSERVATION_ENABLED ? "not_checked" : "not_required",
            ...(config.AUTH_ENABLED ? { authDatabase: "up" as const } : {}),
            ...(config.TENANT_READS_ENABLED ? { tenantDatabase: "up" as const } : {}),
            ...(marketEnabled ? { marketDatabase: "up" as const } : {}),
            ...(machineEnabled ? { machineDatabase: "up" as const } : {}),
            ...(policyEnabled ? { policyDatabase: "up" as const } : {}),
            ...(sessionEnabled ? { commerceSessionDatabase: "up" as const } : {}),
            commerceActionDatabase: "down" }, ...build });
      }
    }
    if (grantEnabled) {
      // The enabled authorization-grant family composes its injected store's
      // readiness into ONE grant dependency. A failure reflects as
      // commerceGrantDatabase down; the flag never invokes the callback when
      // disabled, and a missing callback is `down`, never silently ready.
      const grantReadyResult = commerceGrantReady
        ? await commerceGrantReady().catch(() => false)
        : false;
      if (!grantReadyResult) {
        return reply.code(503).send({ ok: false as const, status: "not_ready" as const,
          checks: { configuration: "up", sourceRoutes: config.ARC_OBSERVATION_ENABLED ? "enabled" : "disabled",
            redis: config.ARC_OBSERVATION_ENABLED ? "not_checked" : "not_required",
            ...(config.AUTH_ENABLED ? { authDatabase: "up" as const } : {}),
            ...(config.TENANT_READS_ENABLED ? { tenantDatabase: "up" as const } : {}),
            ...(marketEnabled ? { marketDatabase: "up" as const } : {}),
            ...(machineEnabled ? { machineDatabase: "up" as const } : {}),
            ...(policyEnabled ? { policyDatabase: "up" as const } : {}),
            ...(sessionEnabled ? { commerceSessionDatabase: "up" as const } : {}),
            ...(actionEnabled ? { commerceActionDatabase: "up" as const } : {}),
            commerceGrantDatabase: "down" }, ...build });
      }
    }
    if (paymentEnabled) {
      const paymentReadyResult = commercePaymentReady
        ? await commercePaymentReady().catch(() => false)
        : false;
      if (!paymentReadyResult) {
        return reply.code(503).send({ ok: false as const, status: "not_ready" as const,
          checks: { configuration: "up", sourceRoutes: config.ARC_OBSERVATION_ENABLED ? "enabled" : "disabled",
            redis: config.ARC_OBSERVATION_ENABLED ? "not_checked" : "not_required",
            ...(config.AUTH_ENABLED ? { authDatabase: "up" as const } : {}),
            ...(config.TENANT_READS_ENABLED ? { tenantDatabase: "up" as const } : {}),
            ...(marketEnabled ? { marketDatabase: "up" as const } : {}),
            ...(machineEnabled ? { machineDatabase: "up" as const } : {}),
            ...(policyEnabled ? { policyDatabase: "up" as const } : {}),
            ...(sessionEnabled ? { commerceSessionDatabase: "up" as const } : {}),
            ...(actionEnabled ? { commerceActionDatabase: "up" as const } : {}),
            ...(grantEnabled ? { commerceGrantDatabase: "up" as const } : {}),
            commercePaymentDatabase: "down" }, ...build });
      }
    }
    if (config.ARC_OBSERVATION_ENABLED) {
      const redisReady = sourceBudget ? await sourceBudget.ready(AbortSignal.timeout(750)) : false;
      if (!redisReady) return reply.code(503).send({ ok: false as const, status: "not_ready" as const,
        checks: { configuration: "up", sourceRoutes: "enabled", redis: "down",
          ...(marketEnabled ? { marketDatabase: "up" as const } : {}) }, ...build });
      return { ok: true as const, status: "ready" as const,
        checks: { configuration: "up", sourceRoutes: "enabled", redis: "up",
          ...(config.TENANT_READS_ENABLED ? { tenantDatabase: "up" as const } : {}),
          ...(marketEnabled ? { marketDatabase: "up" as const } : {}),
          ...(machineEnabled ? { machineDatabase: "up" as const } : {}),
          ...(policyEnabled ? { policyDatabase: "up" as const } : {}),
          ...(sessionEnabled ? { commerceSessionDatabase: "up" as const } : {}),
          ...(actionEnabled ? { commerceActionDatabase: "up" as const } : {}),
          ...(grantEnabled ? { commerceGrantDatabase: "up" as const } : {}),
        ...(paymentEnabled ? { commercePaymentDatabase: "up" as const } : {}) }, ...build };
    }
    return { ok: true as const, status: "ready" as const,
      checks: { configuration: "up", sourceRoutes: "disabled", redis: "not_required",
        ...(config.AUTH_ENABLED ? { authDatabase: "up" as const } : {}),
        ...(config.TENANT_READS_ENABLED ? { tenantDatabase: "up" as const } : {}),
        ...(marketEnabled ? { marketDatabase: "up" as const } : {}),
        ...(machineEnabled ? { machineDatabase: "up" as const } : {}),
        ...(policyEnabled ? { policyDatabase: "up" as const } : {}),
        ...(sessionEnabled ? { commerceSessionDatabase: "up" as const } : {}),
        ...(actionEnabled ? { commerceActionDatabase: "up" as const } : {}),
        ...(grantEnabled ? { commerceGrantDatabase: "up" as const } : {}),
        ...(paymentEnabled ? { commercePaymentDatabase: "up" as const } : {}) }, ...build };
  });

  if (config.AUTH_ENABLED) {
    if (!authService) throw new Error("Auth dependencies are unavailable");
    const secureCookies = config.APP_ORIGIN.startsWith("https://");
    registerAuthRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(secureCookies),
      service: authService,
      buildSha: config.COMMIT_SHA,
      enabled: true,
    });
  } else {
    registerAuthRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(false),
      // A disabled registration never invokes the service.
      service: authService as AuthService,
      buildSha: config.COMMIT_SHA,
      enabled: false,
    });
  }

  if (config.TENANT_READS_ENABLED) {
    if (!tenantReadService) throw new Error("Tenant read dependencies are unavailable");
    registerTenantRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(config.APP_ORIGIN.startsWith("https://")),
      service: tenantReadService,
      buildSha: config.COMMIT_SHA,
      enabled: true,
      excludePost: config.TENANT_WRITES_ENABLED,
      ...(tenantMaxResponseBytes !== undefined
        ? { maxResponseBytes: tenantMaxResponseBytes }
        : {}),
    });
  } else {
    registerTenantRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(false),
      // A disabled registration never invokes the service.
      service: tenantReadService as TenantReadService,
      buildSha: config.COMMIT_SHA,
      enabled: false,
    });
  }

  if (config.TENANT_WRITES_ENABLED) {
    if (!tenantWriteService) throw new Error("Tenant write dependencies are unavailable");
    registerTenantWriteRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(config.APP_ORIGIN.startsWith("https://")),
      service: tenantWriteService,
      buildSha: config.COMMIT_SHA,
      enabled: true,
      ...(tenantMaxResponseBytes !== undefined
        ? { maxResponseBytes: tenantMaxResponseBytes }
        : {}),
    });
  } else {
    registerTenantWriteRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(false),
      // A disabled registration never invokes the service.
      service: tenantWriteService as TenantWriteService,
      buildSha: config.COMMIT_SHA,
      enabled: false,
    });
  }

  if (config.LISTING_MANAGEMENT_ENABLED) {
    if (!marketService) throw new Error("Market listing dependencies are unavailable");
    registerMarketRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(config.APP_ORIGIN.startsWith("https://")),
      service: marketService,
      buildSha: config.COMMIT_SHA,
      enabled: true,
      ...(marketMaxResponseBytes !== undefined
        ? { maxResponseBytes: marketMaxResponseBytes }
        : {}),
    });
  } else {
    // Default-off registers NO market route; the request keeps the framework's
    // ordinary 404 instead of a simulated disabled response.
    registerMarketRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(false),
      service: marketService as MarketService,
      buildSha: config.COMMIT_SHA,
      enabled: false,
    });
  }

  // The provider lifecycle family rides the listing flag; the moderator family
  // rides the independent moderation flag. Either enabled family REQUIRES the
  // shared lifecycle service: a missing dependency is a fixed startup error,
  // never a silent drop of the six provider routes while the manifest still
  // advertises them. The listing flag is passed through unchanged.
  const lifecycleEnabled =
    config.LISTING_MANAGEMENT_ENABLED || config.MARKET_MODERATION_ENABLED;
  if (lifecycleEnabled && !marketLifecycleService) {
    throw new Error("Market lifecycle dependencies are unavailable");
  }
  registerMarketLifecycleRoutes(app, {
    listingManagementEnabled: config.LISTING_MANAGEMENT_ENABLED,
    moderationEnabled: config.MARKET_MODERATION_ENABLED,
    appOrigin: config.APP_ORIGIN,
    cookieNames: authCookieNames(config.APP_ORIGIN.startsWith("https://")),
    ...(marketLifecycleService !== undefined
      ? { service: marketLifecycleService }
      : {}),
    buildSha: config.COMMIT_SHA,
    ...(marketMaxResponseBytes !== undefined
      ? { maxResponseBytes: marketMaxResponseBytes }
      : {}),
  });

  // The public catalog family is independent of auth/tenant reads; it needs
  // only the catalog service, and its absence is a fixed startup error.
  if (config.MARKET_CATALOG_ENABLED) {
    if (!marketCatalogService) {
      throw new Error("Market catalog dependencies are unavailable");
    }
  }
  registerMarketCatalogRoutes(app, {
    enabled: config.MARKET_CATALOG_ENABLED,
    appOrigin: config.APP_ORIGIN,
    ...(marketCatalogService !== undefined
      ? { service: marketCatalogService }
      : {}),
    buildSha: config.COMMIT_SHA,
    ...(marketMaxResponseBytes !== undefined
      ? { maxResponseBytes: marketMaxResponseBytes }
      : {}),
  });

  if (config.MACHINE_CREDENTIAL_MANAGEMENT_ENABLED) {
    if (!machineManagementService) {
      throw new Error("Machine credential management dependencies are unavailable");
    }
    registerMachineManagementRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(config.APP_ORIGIN.startsWith("https://")),
      service: machineManagementService,
      buildSha: config.COMMIT_SHA,
      enabled: true,
      ...(tenantMaxResponseBytes !== undefined
        ? { maxResponseBytes: tenantMaxResponseBytes }
        : {}),
    });
  } else {
    registerMachineManagementRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(false),
      // A disabled registration never invokes the service.
      service: machineManagementService as MachineManagementService,
      buildSha: config.COMMIT_SHA,
      enabled: false,
    });
  }

  if (config.MACHINE_SESSION_EXCHANGE_ENABLED) {
    if (!machineSessionService) {
      throw new Error("Machine session exchange dependencies are unavailable");
    }
    registerMachineSessionRoutes(app, {
      service: machineSessionService,
      buildSha: config.COMMIT_SHA,
      enabled: true,
      ...(tenantMaxResponseBytes !== undefined
        ? { maxResponseBytes: tenantMaxResponseBytes }
        : {}),
    });
  } else {
    registerMachineSessionRoutes(app, {
      service: machineSessionService as MachineSessionService,
      buildSha: config.COMMIT_SHA,
      enabled: false,
    });
  }

  if (config.POLICY_MANAGEMENT_ENABLED) {
    if (!policyManagementService) {
      throw new Error("Policy management dependencies are unavailable");
    }
    registerPolicyRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(config.APP_ORIGIN.startsWith("https://")),
      service: policyManagementService,
      buildSha: config.COMMIT_SHA,
      enabled: true,
      ...(tenantMaxResponseBytes !== undefined
        ? { maxResponseBytes: tenantMaxResponseBytes }
        : {}),
    });
  } else {
    // Default-off registers NO control route; the request keeps the framework's
    // ordinary 404 instead of a simulated disabled response.
    registerPolicyRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(false),
      // A disabled registration never invokes the service.
      service: policyManagementService as PolicyService,
      buildSha: config.COMMIT_SHA,
      enabled: false,
    });
  }

  // Seven frozen commerce-session routes. Registration is default-off: with the
  // flag off NO route is installed and the framework's ordinary not-found
  // handler maps the exact family roots to the bounded v2 no-store 404. When
  // enabled the family REQUIRES its service: a missing dependency is a fixed
  // startup error, never a silent drop of routes while the manifest advertises
  // them.
  if (config.COMMERCE_SESSIONS_ENABLED) {
    if (!commerceSessionService) {
      throw new Error("Commerce session dependencies are unavailable");
    }
    registerCommerceSessionRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(config.APP_ORIGIN.startsWith("https://")),
      service: commerceSessionService,
      buildSha: config.COMMIT_SHA,
      enabled: true,
      ...(tenantMaxResponseBytes !== undefined
        ? { maxResponseBytes: tenantMaxResponseBytes }
        : {}),
    });
  } else {
    // Default-off registers NO route (fixed 404 via the not-found mapping).
    registerCommerceSessionRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(false),
      // A disabled registration never invokes the service.
      service: commerceSessionService as CommerceSessionService,
      buildSha: config.COMMIT_SHA,
      enabled: false,
    });
  }

  // Twelve frozen commerce-action routes in two strictly separated families
  // (nine browser management + three agent authorization). The gate is DEFAULT
  // OFF. While off the exact twelve targets are still installed and every one
  // of them answers the accepted FEATURE_DISABLED envelope before any service,
  // store or cookie work, so no static/SPA fallback can answer an API path with
  // HTML. When enabled the family REQUIRES its service: a missing dependency is
  // a fixed startup error, never a silent drop while the manifest advertises
  // the routes. An enabled action surface is a control surface only and never
  // implies a payment, settlement or delivery lane.
  if (config.COMMERCE_ACTIONS_ENABLED) {
    if (!commerceActionService) {
      throw new Error("Commerce action dependencies are unavailable");
    }
    registerCommerceActionRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(config.APP_ORIGIN.startsWith("https://")),
      service: commerceActionService,
      buildSha: config.COMMIT_SHA,
      enabled: true,
      ...(tenantMaxResponseBytes !== undefined
        ? { maxResponseBytes: tenantMaxResponseBytes }
        : {}),
    });
  } else {
    registerCommerceActionRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(false),
      // A disabled registration never invokes the service.
      service: commerceActionService as CommerceActionService,
      buildSha: config.COMMIT_SHA,
      enabled: false,
    });
  }

  // Nine frozen authorization-grant routes in three strictly separated families
  // (three agent authorization + three provider claim + three browser
  // management). The gate is DEFAULT OFF. While off the exact nine targets are
  // still installed and every one of them answers the accepted FEATURE_DISABLED
  // envelope before any service, store or cookie work, so no static/SPA
  // fallback can answer an API path with HTML. When enabled the family REQUIRES
  // its service: a missing dependency is a fixed startup error, never a silent
  // drop while the manifest advertises the routes. An enabled grant surface is
  // a control surface only and never implies a payment, settlement or delivery
  // lane.
  if (config.COMMERCE_GRANTS_ENABLED) {
    if (!commerceGrantService) {
      throw new Error("Commerce grant dependencies are unavailable");
    }
    registerCommerceGrantRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(config.APP_ORIGIN.startsWith("https://")),
      service: commerceGrantService,
      buildSha: config.COMMIT_SHA,
      enabled: true,
      ...(tenantMaxResponseBytes !== undefined
        ? { maxResponseBytes: tenantMaxResponseBytes }
        : {}),
    });
  } else {
    registerCommerceGrantRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(false),
      // A disabled registration never invokes the service.
      service: commerceGrantService as CommerceGrantService,
      buildSha: config.COMMIT_SHA,
      enabled: false,
    });
  }

  // Five frozen migration-0015 payment routes in two strictly separated
  // families (one seller browser terms write + four buyer agent attempt
  // routes). DEFAULT OFF: while off the exact five targets are still installed
  // and answer FEATURE_DISABLED before any service, store or cookie work. When
  // enabled the family REQUIRES its service. No observation route exists.
  if (config.COMMERCE_PAYMENTS_ENABLED) {
    if (!commercePaymentService) {
      throw new Error("Commerce payment dependencies are unavailable");
    }
    registerCommercePaymentRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(config.APP_ORIGIN.startsWith("https://")),
      service: commercePaymentService,
      buildSha: config.COMMIT_SHA,
      enabled: true,
      ...(tenantMaxResponseBytes !== undefined
        ? { maxResponseBytes: tenantMaxResponseBytes }
        : {}),
    });
  } else {
    registerCommercePaymentRoutes(app, {
      appOrigin: config.APP_ORIGIN,
      cookieNames: authCookieNames(false),
      // A disabled registration never invokes the service.
      service: commercePaymentService as CommercePaymentService,
      buildSha: config.COMMIT_SHA,
      enabled: false,
    });
  }

  app.all(CAPABILITIES_PATH, { onRequest: async (request, reply) => {
    if (!config.API_BOUNDARY_ENABLED) throw new ApiBoundaryError("FEATURE_DISABLED");
    if (request.url.includes("?") || (request.headers["content-length"] !== undefined && request.headers["content-length"] !== "0") || request.headers["transfer-encoding"] !== undefined) {
      throw new ApiBoundaryError("INVALID_REQUEST");
    }
    if (request.method === "OPTIONS") {
      verifyPreflight(request.headers, config.APP_ORIGIN, "GET");
      return reply.headers({ "Access-Control-Allow-Origin": config.APP_ORIGIN,
        "Access-Control-Allow-Methods": "GET", "Access-Control-Allow-Headers": "x-openarc-client, content-type",
        Vary: "Origin" }).code(204).send();
    }
    if (request.method !== "GET") throw new ApiBoundaryError("METHOD_NOT_ALLOWED");
    verifyBrowserOrigin(request.headers, config.APP_ORIGIN, true);
    if (request.headers.origin === config.APP_ORIGIN) reply.header("Access-Control-Allow-Origin", config.APP_ORIGIN);
    reply.header("Vary", "Origin");
  } }, async (request) => CapabilitiesEnvelopeSchema.parse({
    ok: true,
    data: { capabilityVersion: config.GATEWAY_EVIDENCE_ENABLED ? "openarc.capabilities.m07.v1" : config.AGENT_JOBS_ENABLED ? "openarc.capabilities.m06.v1" : config.AGENT_REGISTRY_ENABLED ? "openarc.capabilities.m05.v1" : "openarc.capabilities.m04.v1",
      environment: "testnet", network: ARC_TESTNET.caip2,
      sourceRevision: config.GATEWAY_EVIDENCE_ENABLED ? "circle-gateway-x402-2026-09-05" : config.AGENT_JOBS_ENABLED ? ARC_ERC8183.sourceRevision : config.AGENT_REGISTRY_ENABLED ? ARC_ERC8004.sourceRevision : ARC_TESTNET.sourceRevision,
      reviewedAt: config.GATEWAY_EVIDENCE_ENABLED ? "2026-09-05" : config.AGENT_REGISTRY_ENABLED ? ARC_ERC8004.reviewedAt : ARC_TESTNET.reviewedAt,
      writes: false, enabledConnectors: config.GATEWAY_EVIDENCE_ENABLED ? ["arc_primary_rpc", "erc8004_registries", "erc8183_reference", "circle_gateway_testnet"] : config.AGENT_JOBS_ENABLED ? ["arc_primary_rpc", "erc8004_registries", "erc8183_reference"] : config.AGENT_REGISTRY_ENABLED
        ? ["arc_primary_rpc", "erc8004_registries"] : config.ARC_OBSERVATION_ENABLED ? ["arc_primary_rpc"] : [],
      features: { arcObservation: config.ARC_OBSERVATION_ENABLED, agentRegistry: config.AGENT_REGISTRY_ENABLED,
        agentJobs: config.AGENT_JOBS_ENABLED, gatewayEvidence: config.GATEWAY_EVIDENCE_ENABLED },
      limits: { requestBytes: API_MAX_REQUEST_BYTES, responseBytes: API_MAX_RESPONSE_BYTES,
        sourceResponseBytes: config.SOURCE_MAX_RESPONSE_BYTES, sourceTimeoutMs: config.SOURCE_TIMEOUT_MS,
        sourceMaxSubcalls: config.SOURCE_MAX_SUBCALLS, requestsPerPeerHour: config.REQUESTS_PER_IP_HOUR,
        globalSourceUnitsPerDay: config.GLOBAL_SOURCE_UNITS_PER_DAY } },
    meta: { schemaVersion: API_SCHEMA_VERSION, requestId: request.id, buildSha: config.COMMIT_SHA },
  }));

  // Public, credentialless capability registry. Only the five explicit
  // deployment flags, the existing readiness callbacks, the build SHA and the
  // exact app origin cross this boundary; the full config, secrets, DB URLs,
  // role objects and private identities never do. This is metadata only and
  // performs no automatic network/provider/RPC request.
  registerCommerceCapabilities(app, {
    flags: {
      authEnabled: config.AUTH_ENABLED,
      tenantReadsEnabled: config.TENANT_READS_ENABLED,
      tenantWritesEnabled: config.TENANT_WRITES_ENABLED,
      machineCredentialManagementEnabled:
        config.MACHINE_CREDENTIAL_MANAGEMENT_ENABLED,
      machineSessionExchangeEnabled: config.MACHINE_SESSION_EXCHANGE_ENABLED,
    },
    readiness: {
      ...(authReady !== undefined ? { authReady } : {}),
      ...(tenantReady !== undefined ? { tenantReady } : {}),
      ...(machineReady !== undefined ? { machineReady } : {}),
    },
    buildSha: config.COMMIT_SHA,
    appOrigin: config.APP_ORIGIN,
    ...(tenantMaxResponseBytes !== undefined
      ? { maxResponseBytes: tenantMaxResponseBytes }
      : {}),
  });

  // Public, credentialless marketplace capability registry. It ALWAYS
  // registers, even with every flag off, and returns the accepted three-family
  // / 18-route manifest. Only the explicit own flags plus the AUTH/TENANT_READS
  // gating flags and the readiness callbacks actually required by an enabled
  // family cross this boundary; the full config, secrets, DB URLs and private
  // identities never do. Availability is not authorization and no automatic
  // network/provider/RPC request is performed.
  registerMarketplaceCapabilities(app, {
    flags: {
      authEnabled: config.AUTH_ENABLED,
      tenantReadsEnabled: config.TENANT_READS_ENABLED,
      marketCatalogEnabled: config.MARKET_CATALOG_ENABLED,
      listingManagementEnabled: config.LISTING_MANAGEMENT_ENABLED,
      marketModerationEnabled: config.MARKET_MODERATION_ENABLED,
    },
    readiness: {
      ...(authReady !== undefined ? { authReady } : {}),
      ...(tenantReady !== undefined ? { tenantReady } : {}),
      ...(marketReady !== undefined ? { marketReady } : {}),
    },
    buildSha: config.COMMIT_SHA,
    appOrigin: config.APP_ORIGIN,
    ...(marketMaxResponseBytes !== undefined
      ? { maxResponseBytes: marketMaxResponseBytes }
      : {}),
  });

  // Public, credentialless control capability registry. It ALWAYS registers,
  // even with the flag off, and returns the accepted one-family / ten-route
  // manifest. Only the enable flag, the AUTH_ENABLED gating flag and the
  // readiness callbacks actually required cross this boundary; the full config,
  // secrets, DB URLs and private identities never do. The family is independent
  // of tenant HTTP reads: the accepted policy store readiness composes the
  // restricted tenant database base readiness, so no separate tenant flag or
  // callback is passed. Availability is not authorization and no
  // execution/spend claim is made. It performs ZERO database or readiness calls
  // while the flag is off.
  registerControlCapabilities(app, {
    flags: {
      authEnabled: config.AUTH_ENABLED,
      policyManagementEnabled: config.POLICY_MANAGEMENT_ENABLED,
    },
    readiness: {
      ...(authReady !== undefined ? { authReady } : {}),
      ...(policyReady !== undefined ? { policyReady } : {}),
    },
    buildSha: config.COMMIT_SHA,
    appOrigin: config.APP_ORIGIN,
    ...(tenantMaxResponseBytes !== undefined
      ? { maxResponseBytes: tenantMaxResponseBytes }
      : {}),
  });

  // Public, credentialless commerce-session capability registry. It ALWAYS
  // registers and returns the accepted two-family / seven-route manifest. With
  // the flag off BOTH families are `built_disabled` and ZERO readiness probes
  // run. Only the two explicit flags, the auth/session readiness callbacks and
  // the build SHA/origin cross this boundary; the full config, secrets, DB URLs
  // and private identities never do. `sessionReady` composes the declared
  // tenant/machine/policy/commerceSession schema dependencies through the
  // accepted session store readiness; the old HTTP readiness callbacks are
  // never consulted. Availability is not authorization and grants no payment
  // authority; no automatic network/provider/RPC request is performed.
  registerSessionCapabilities(app, {
    flags: {
      authEnabled: config.AUTH_ENABLED,
      commerceSessionsEnabled: config.COMMERCE_SESSIONS_ENABLED,
    },
    readiness: {
      ...(authReady !== undefined ? { authReady } : {}),
      ...(commerceSessionReady !== undefined
        ? { sessionReady: commerceSessionReady }
        : {}),
    },
    buildSha: config.COMMIT_SHA,
    appOrigin: config.APP_ORIGIN,
    ...(tenantMaxResponseBytes !== undefined
      ? { maxResponseBytes: tenantMaxResponseBytes }
      : {}),
  });

  // Public, credentialless commerce-action capability registry. It ALWAYS
  // registers and returns the accepted two-family / twelve-route manifest. With
  // the gate off BOTH families are `built_disabled` and ZERO readiness probes
  // run. Only the three explicit flags, the readiness callbacks and the build
  // SHA/origin cross this boundary; the full config, secrets, DB URLs and
  // private identities never do. Availability is not authorization: an enabled
  // state grants no payment, settlement or delivery authority and triggers no
  // automatic network/provider/RPC request.
  registerActionCapabilities(app, {
    flags: {
      authEnabled: config.AUTH_ENABLED,
      commerceSessionsEnabled: config.COMMERCE_SESSIONS_ENABLED,
      commerceActionsEnabled: config.COMMERCE_ACTIONS_ENABLED,
    },
    readiness: {
      ...(authReady !== undefined ? { authReady } : {}),
      ...(commerceSessionReady !== undefined
        ? { sessionReady: commerceSessionReady }
        : {}),
      ...(commerceActionReady !== undefined
        ? { actionReady: commerceActionReady }
        : {}),
    },
    buildSha: config.COMMIT_SHA,
    appOrigin: config.APP_ORIGIN,
    ...(tenantMaxResponseBytes !== undefined
      ? { maxResponseBytes: tenantMaxResponseBytes }
      : {}),
  });

  // Public, credentialless authorization-grant capability registry. It ALWAYS
  // registers and returns the accepted three-family / nine-route manifest. With
  // the gate off ALL THREE families are `built_disabled` and ZERO readiness
  // probes run. Only the four explicit flags, the readiness callbacks and the
  // build SHA/origin cross this boundary; the full config, secrets, DB URLs and
  // private identities never do. Availability is not authorization: an enabled
  // state grants no payment, settlement or delivery authority and triggers no
  // automatic network/provider/RPC request.
  registerGrantCapabilities(app, {
    flags: {
      authEnabled: config.AUTH_ENABLED,
      commerceSessionsEnabled: config.COMMERCE_SESSIONS_ENABLED,
      commerceActionsEnabled: config.COMMERCE_ACTIONS_ENABLED,
      commerceGrantsEnabled: config.COMMERCE_GRANTS_ENABLED,
    },
    readiness: {
      ...(authReady !== undefined ? { authReady } : {}),
      ...(commerceSessionReady !== undefined
        ? { sessionReady: commerceSessionReady }
        : {}),
      ...(commerceActionReady !== undefined
        ? { actionReady: commerceActionReady }
        : {}),
      ...(commerceGrantReady !== undefined
        ? { grantReady: commerceGrantReady }
        : {}),
    },
    buildSha: config.COMMIT_SHA,
    appOrigin: config.APP_ORIGIN,
    ...(tenantMaxResponseBytes !== undefined
      ? { maxResponseBytes: tenantMaxResponseBytes }
      : {}),
  });

  // Public, credentialless payment capability registry. It ALWAYS registers the
  // frozen two-family / five-route manifest; with the gate off both families
  // are `built_disabled` and ZERO readiness probes run. Availability is not
  // authorization and never claims a payment was made or settled.
  registerPaymentCapabilities(app, {
    flags: {
      authEnabled: config.AUTH_ENABLED,
      commerceSessionsEnabled: config.COMMERCE_SESSIONS_ENABLED,
      commerceActionsEnabled: config.COMMERCE_ACTIONS_ENABLED,
      commerceGrantsEnabled: config.COMMERCE_GRANTS_ENABLED,
      commercePaymentsEnabled: config.COMMERCE_PAYMENTS_ENABLED,
    },
    readiness: {
      ...(authReady !== undefined ? { authReady } : {}),
      ...(commerceSessionReady !== undefined
        ? { sessionReady: commerceSessionReady }
        : {}),
      ...(commerceActionReady !== undefined
        ? { actionReady: commerceActionReady }
        : {}),
      ...(commerceGrantReady !== undefined
        ? { grantReady: commerceGrantReady }
        : {}),
      ...(commercePaymentReady !== undefined
        ? { paymentReady: commercePaymentReady }
        : {}),
    },
    buildSha: config.COMMIT_SHA,
    appOrigin: config.APP_ORIGIN,
    ...(tenantMaxResponseBytes !== undefined
      ? { maxResponseBytes: tenantMaxResponseBytes }
      : {}),
  });

  if (config.ARC_OBSERVATION_ENABLED) {
    if (!sourceBudget || !arcAccountService || !arcTransactionService) {
      throw new Error("Arc observation dependencies are unavailable");
    }
    registerSourceRoute<ArcAccountSnapshotRequest, ArcAccountSnapshotEnvelope>(app, {
      path: ARC_ACCOUNT_SNAPSHOT_PATH, source: "arc_rpc", route: "arc_account", enabled: true,
      appOrigin: config.APP_ORIGIN, proxySecret: config.SOURCE_PROXY_SECRET!,
      budget: sourceBudget, timeoutMs: config.SOURCE_TIMEOUT_MS,
      requestSchema: ArcAccountSnapshotRequestSchema, responseSchema: ArcAccountSnapshotEnvelopeSchema,
      execute: async (input, context) => ({ ok: true as const,
        data: await arcAccountService.observe(input, context.lease, context.signal),
        meta: { schemaVersion: API_SCHEMA_VERSION, requestId: context.requestId, buildSha: config.COMMIT_SHA } }),
    });
    registerSourceRoute<ArcTransactionEvidenceRequest, ArcTransactionEvidenceEnvelope>(app, {
      path: ARC_TRANSACTION_EVIDENCE_PATH, source: "arc_rpc", route: "arc_transaction", enabled: true,
      appOrigin: config.APP_ORIGIN, proxySecret: config.SOURCE_PROXY_SECRET!,
      budget: sourceBudget, timeoutMs: config.SOURCE_TIMEOUT_MS,
      requestSchema: ArcTransactionEvidenceRequestSchema, responseSchema: ArcTransactionEvidenceEnvelopeSchema,
      execute: async (input, context) => ({ ok: true as const,
        data: await arcTransactionService.observe(input, context.lease, context.signal),
        meta: { schemaVersion: API_SCHEMA_VERSION, requestId: context.requestId, buildSha: config.COMMIT_SHA } }),
    });
  } else {
    for (const path of [ARC_ACCOUNT_SNAPSHOT_PATH, ARC_TRANSACTION_EVIDENCE_PATH] as const) {
      app.all(path, { onRequest: async () => { throw new ApiBoundaryError("FEATURE_DISABLED"); } }, async () => undefined);
    }
  }

  if (config.AGENT_REGISTRY_ENABLED) {
    if (!sourceBudget || !agentRegistryService) throw new Error("Agent registry dependencies are unavailable");
    registerSourceRoute<AgentRegistryEvidenceRequest, AgentRegistryEvidenceEnvelope>(app, {
      path: AGENT_REGISTRY_EVIDENCE_PATH, source: "arc_rpc", route: "agent_registry", enabled: true,
      appOrigin: config.APP_ORIGIN, proxySecret: config.SOURCE_PROXY_SECRET!,
      budget: sourceBudget, timeoutMs: config.SOURCE_TIMEOUT_MS,
      requestSchema: AgentRegistryEvidenceRequestSchema, responseSchema: AgentRegistryEvidenceEnvelopeSchema,
      execute: async (input, context) => ({ ok: true as const,
        data: await agentRegistryService.observe(input, context.lease, context.signal),
        meta: { schemaVersion: API_SCHEMA_VERSION, requestId: context.requestId, buildSha: config.COMMIT_SHA } }),
    });
  } else {
    app.all(AGENT_REGISTRY_EVIDENCE_PATH,
      { onRequest: async () => { throw new ApiBoundaryError("FEATURE_DISABLED"); } }, async () => undefined);
  }

  if (config.AGENT_JOBS_ENABLED) {
    if (!sourceBudget || !jobService) throw new Error("Job evidence dependencies are unavailable");
    registerSourceRoute<JobEvidenceRequest, ReturnType<typeof JobEvidenceEnvelopeSchema.parse>>(app, {
      path: JOB_EVIDENCE_PATH, source: "arc_rpc", route: "agent_job", enabled: true,
      appOrigin: config.APP_ORIGIN, proxySecret: config.SOURCE_PROXY_SECRET!, budget: sourceBudget,
      timeoutMs: config.SOURCE_TIMEOUT_MS, requestSchema: JobEvidenceRequestSchema,
      responseSchema: JobEvidenceEnvelopeSchema,
      execute: async (input, context) => ({ ok: true as const,
        data: await jobService.observe(input, context.lease, context.signal),
        meta: { schemaVersion: API_SCHEMA_VERSION, requestId: context.requestId, buildSha: config.COMMIT_SHA } }),
    });
  } else {
    app.all(JOB_EVIDENCE_PATH, { onRequest: async () => { throw new ApiBoundaryError("FEATURE_DISABLED"); } }, async () => undefined);
  }

  if (config.GATEWAY_EVIDENCE_ENABLED) {
    if (!sourceBudget || !gatewayTransferService) throw new Error("Gateway evidence dependencies are unavailable");
    registerSourceRoute<GatewayTransferRequest, ReturnType<typeof GatewayTransferEnvelopeSchema.parse>>(app, {
      path: GATEWAY_TRANSFER_PATH, source: "gateway", route: "gateway_transfer", enabled: true,
      appOrigin: config.APP_ORIGIN, proxySecret: config.SOURCE_PROXY_SECRET!, budget: sourceBudget,
      timeoutMs: config.SOURCE_TIMEOUT_MS, requestSchema: GatewayTransferRequestSchema,
      responseSchema: GatewayTransferEnvelopeSchema,
      execute: async (input, context) => ({ ok: true as const,
        data: await gatewayTransferService.observe(input, context.lease, context.signal),
        meta: { schemaVersion: API_SCHEMA_VERSION, requestId: context.requestId, buildSha: config.COMMIT_SHA } }),
    });
  } else {
    app.all(GATEWAY_TRANSFER_PATH, { onRequest: async () => { throw new ApiBoundaryError("FEATURE_DISABLED"); } }, async () => undefined);
  }

  for (const path of disabledPaths) {
    app.all(path, { onRequest: async () => { throw new ApiBoundaryError("FEATURE_DISABLED"); } }, async () => undefined);
  }

  app.all("/metrics", { onRequest: async (request) => {
    if (request.method !== "GET") throw new ApiBoundaryError("METHOD_NOT_ALLOWED");
    if (request.url.includes("?") || !metricsAuthorized(request.headers.authorization, config.METRICS_TOKEN)) {
      throw new ApiBoundaryError("METRICS_UNAUTHORIZED");
    }
  } }, async (_request, reply) => reply.type("text/plain; version=0.0.4; charset=utf-8")
    .send(metrics.render(config.COMMIT_SHA, config.ARC_OBSERVATION_ENABLED)));
  return app;
}
