import { ARC_TESTNET, BuildMarkerSchema, WorkspaceOriginSchema } from "@openarc/shared";
import { z } from "zod";

const flag = () => z.enum(["true", "false"]).default("false").transform((value) => value === "true");
const secret = () => z.string().regex(/^[A-Za-z0-9_-]{32,128}$/u);
/**
 * Canonical unpadded base64url of exactly 32 bytes: 43 characters whose final
 * character carries zero padding bits. Used only for machine peppers and the
 * dedicated machine rate secret. `(?![\s\S])` requires an ABSOLUTE end, so a
 * trailing newline or CR can never be smuggled past a bare `$` anchor; the
 * explicit length check keeps the character count exact.
 */
const canonical32ByteSecret = () =>
  z
    .string()
    .length(43)
    .regex(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048](?![\s\S])/u);
/**
 * Canonical decimal pepper version: exactly the strings `1`..`16`, then parsed
 * to a number. `coerce.number()` would smuggle `01`, `1e0`, ` 1`, `1.0` and
 * booleans past the bound; the absolute-end lookahead rejects a trailing
 * newline/CR and every non-canonical textual form.
 */
const pepperVersion = () =>
  z
    .string()
    .regex(/^(?:[1-9]|1[0-6])(?![\s\S])/u)
    .transform((value) => Number(value));
const EnvironmentSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  HOST: z.string().min(1).max(255).default("0.0.0.0"),
  PORT: z.coerce.number().int().min(1).max(65_535).default(3000),
  APP_ORIGIN: WorkspaceOriginSchema.default("http://localhost:5183"),
  COMMIT_SHA: BuildMarkerSchema.default("local"),
  LOG_LEVEL: z.enum(["silent", "error", "warn", "info"]).default("info"),
  API_BOUNDARY_ENABLED: flag(),
  ARC_OBSERVATION_ENABLED: flag(),
  AGENT_REGISTRY_ENABLED: flag(),
  AGENT_JOBS_ENABLED: flag(),
  GATEWAY_EVIDENCE_ENABLED: flag(),
  AUTH_ENABLED: flag(),
  AUTH_DATABASE_URL: z
    .string()
    .max(4096)
    .regex(/^postgres(?:ql)?:\/\//u)
    .optional(),
  TENANT_READS_ENABLED: flag(),
  TENANT_WRITES_ENABLED: flag(),
  TENANT_DATABASE_URL: z
    .string()
    .max(4096)
    .regex(/^postgres(?:ql)?:\/\//u)
    .optional(),
  LISTING_MANAGEMENT_ENABLED: flag(),
  MARKET_CATALOG_ENABLED: flag(),
  MARKET_MODERATION_ENABLED: flag(),
  POLICY_MANAGEMENT_ENABLED: flag(),
  MACHINE_CREDENTIAL_MANAGEMENT_ENABLED: flag(),
  MACHINE_SESSION_EXCHANGE_ENABLED: flag(),
  COMMERCE_SESSIONS_ENABLED: flag(),
  COMMERCE_ACTIONS_ENABLED: flag(),
  COMMERCE_GRANTS_ENABLED: flag(),
  COMMERCE_PAYMENTS_ENABLED: flag(),
  MACHINE_CREDENTIAL_PEPPER_VERSION: pepperVersion().optional(),
  MACHINE_CREDENTIAL_PEPPER: canonical32ByteSecret().optional(),
  MACHINE_CREDENTIAL_PREVIOUS_VERSION: pepperVersion().optional(),
  MACHINE_CREDENTIAL_PREVIOUS_PEPPER: canonical32ByteSecret().optional(),
  MACHINE_RATE_SECRET: canonical32ByteSecret().optional(),
  AUTH_SECRET: secret().optional(),
  AUTH_RP_ID: z.string().min(1).max(253).optional(),
  AUTH_RATE_GLOBAL_PER_MINUTE: z.coerce.number().int().min(1).max(100_000).default(600),
  AUTH_RATE_PEER_PER_HOUR: z.coerce.number().int().min(1).max(100_000).default(120),
  AUTH_RATE_BINDING_PER_HOUR: z.coerce.number().int().min(1).max(100_000).default(120),
  AUTH_RATE_RECOVERY_PER_15MIN: z.coerce.number().int().min(1).max(10_000).default(5),
  ARC_TESTNET_RPC_URL: z.literal(ARC_TESTNET.rpcHttp).default(ARC_TESTNET.rpcHttp),
  ARC_TESTNET_EXPLORER_URL: z.literal(ARC_TESTNET.explorerOrigin).default(ARC_TESTNET.explorerOrigin),
  REDIS_URL: z.url({ protocol: /^rediss?$/u }).max(1024).optional(),
  ABUSE_LIMIT_SECRET: secret().optional(),
  SOURCE_PROXY_SECRET: secret().optional(),
  METRICS_TOKEN: secret().optional(),
  REQUESTS_PER_IP_HOUR: z.coerce.number().int().min(1).max(10_000).default(60),
  GLOBAL_SOURCE_UNITS_PER_DAY: z.coerce.number().int().min(1).max(1_000_000).default(10_000),
  SOURCE_TIMEOUT_MS: z.coerce.number().int().min(100).max(10_000).default(5_000),
  SOURCE_MAX_RESPONSE_BYTES: z.coerce.number().int().min(1024).max(256 * 1024).default(256 * 1024),
  SOURCE_MAX_SUBCALLS: z.coerce.number().int().min(1).max(16).default(8),
}).superRefine((config, context) => {
  if (config.NODE_ENV === "production") {
    if (!config.APP_ORIGIN.startsWith("https://")) {
      context.addIssue({ code: "custom", path: ["APP_ORIGIN"], message: "An exact HTTPS app origin is required" });
    }
    if (!/^[0-9a-f]{40}$/u.test(config.COMMIT_SHA)) {
      context.addIssue({ code: "custom", path: ["COMMIT_SHA"], message: "An exact Git SHA is required" });
    }
    if (!config.METRICS_TOKEN) {
      context.addIssue({ code: "custom", path: ["METRICS_TOKEN"], message: "A metrics secret is required" });
    }
  }
  const operatorSecrets = [config.ABUSE_LIMIT_SECRET, config.SOURCE_PROXY_SECRET, config.METRICS_TOKEN, config.AUTH_SECRET].filter(Boolean);
  if (new Set(operatorSecrets).size !== operatorSecrets.length) {
    context.addIssue({ code: "custom", message: "Operator secrets must be distinct" });
  }
  if (config.AUTH_ENABLED) {
    if (!config.AUTH_DATABASE_URL) {
      context.addIssue({ code: "custom", path: ["AUTH_DATABASE_URL"], message: "Authentication requires a dedicated database URL" });
    }
    if (!config.AUTH_SECRET) {
      context.addIssue({ code: "custom", path: ["AUTH_SECRET"], message: "Authentication requires a dedicated operator secret" });
    }
    if (!config.AUTH_RP_ID) {
      context.addIssue({ code: "custom", path: ["AUTH_RP_ID"], message: "Authentication requires an exact relying-party id" });
    } else {
      const rpId = config.AUTH_RP_ID;
      if (rpId.includes("*") || rpId.includes("/") || rpId.startsWith(".") || rpId.endsWith(".")) {
        context.addIssue({ code: "custom", path: ["AUTH_RP_ID"], message: "AUTH_RP_ID must be an exact hostname" });
      }
      let hostname: string | null = null;
      try {
        hostname = new URL(config.APP_ORIGIN).hostname;
      } catch {
        hostname = null;
      }
      if (hostname !== null && hostname !== rpId) {
        context.addIssue({ code: "custom", path: ["AUTH_RP_ID"], message: "AUTH_RP_ID must equal the APP_ORIGIN hostname" });
      }
    }
    if (config.NODE_ENV !== "production" && !config.APP_ORIGIN.startsWith("http://localhost") && !config.APP_ORIGIN.startsWith("http://127.0.0.1")) {
      context.addIssue({ code: "custom", path: ["APP_ORIGIN"], message: "Authentication development origin must be loopback" });
    }
  }
  if (config.TENANT_READS_ENABLED) {
    if (!config.AUTH_ENABLED) {
      context.addIssue({ code: "custom", path: ["TENANT_READS_ENABLED"], message: "Protected tenant reads require authentication" });
    }
    if (!config.TENANT_DATABASE_URL) {
      context.addIssue({ code: "custom", path: ["TENANT_DATABASE_URL"], message: "Protected tenant reads require a dedicated database URL" });
    } else if (
      config.AUTH_DATABASE_URL !== undefined &&
      config.TENANT_DATABASE_URL === config.AUTH_DATABASE_URL
    ) {
      context.addIssue({ code: "custom", path: ["TENANT_DATABASE_URL"], message: "Protected tenant reads require a dedicated restricted role connection" });
    }
  }
  if (config.TENANT_WRITES_ENABLED) {
    if (!config.TENANT_READS_ENABLED) {
      context.addIssue({ code: "custom", path: ["TENANT_WRITES_ENABLED"], message: "Tenant writes require the protected tenant read family" });
    }
    if (!config.AUTH_ENABLED) {
      context.addIssue({ code: "custom", path: ["TENANT_WRITES_ENABLED"], message: "Tenant writes require authentication" });
    }
    if (!config.TENANT_DATABASE_URL) {
      context.addIssue({ code: "custom", path: ["TENANT_DATABASE_URL"], message: "Tenant writes require a dedicated tenant database" });
    }
  }
  if (config.LISTING_MANAGEMENT_ENABLED) {
    if (!config.AUTH_ENABLED) {
      context.addIssue({ code: "custom", path: ["LISTING_MANAGEMENT_ENABLED"], message: "Listing management requires authentication" });
    }
    if (!config.TENANT_READS_ENABLED) {
      context.addIssue({ code: "custom", path: ["LISTING_MANAGEMENT_ENABLED"], message: "Listing management requires the protected tenant read family" });
    }
    if (!config.TENANT_DATABASE_URL) {
      context.addIssue({ code: "custom", path: ["LISTING_MANAGEMENT_ENABLED"], message: "Listing management requires a dedicated restricted database URL" });
    }
  }
  // Independent marketplace families. Each has its OWN flag and only the
  // gating it actually needs: catalog is public (no auth/tenant reads),
  // moderation needs authentication, listing management needs auth + tenant
  // reads. Every enabled family still requires the dedicated restricted
  // TENANT_DATABASE_URL; TENANT_WRITES and machine flags are never required.
  if (config.MARKET_CATALOG_ENABLED) {
    if (!config.TENANT_DATABASE_URL) {
      context.addIssue({ code: "custom", path: ["MARKET_CATALOG_ENABLED"], message: "Market catalog requires a dedicated restricted database URL" });
    }
  }
  if (config.MARKET_MODERATION_ENABLED) {
    if (!config.AUTH_ENABLED) {
      context.addIssue({ code: "custom", path: ["MARKET_MODERATION_ENABLED"], message: "Moderation requires authentication" });
    }
    if (!config.TENANT_DATABASE_URL) {
      context.addIssue({ code: "custom", path: ["MARKET_MODERATION_ENABLED"], message: "Moderation requires a dedicated restricted database URL" });
    }
  }
  const marketFamilyEnabled =
    config.MARKET_CATALOG_ENABLED ||
    config.LISTING_MANAGEMENT_ENABLED ||
    config.MARKET_MODERATION_ENABLED;
  if (
    marketFamilyEnabled &&
    config.TENANT_DATABASE_URL !== undefined &&
    config.AUTH_DATABASE_URL !== undefined &&
    config.TENANT_DATABASE_URL === config.AUTH_DATABASE_URL
  ) {
    context.addIssue({ code: "custom", path: ["TENANT_DATABASE_URL"], message: "Marketplace families require a dedicated restricted role connection" });
  }
  // Policy management is an INDEPENDENT protected browser family. It requires
  // authentication and the dedicated restricted TENANT_DATABASE_URL, but it is
  // deliberately independent of tenant HTTP reads/writes, marketplace,
  // machine, moderation and financial flags. A shared auth/tenant connection
  // would erase the restricted-role boundary, so the URLs must differ.
  if (config.POLICY_MANAGEMENT_ENABLED) {
    if (!config.AUTH_ENABLED) {
      context.addIssue({ code: "custom", path: ["POLICY_MANAGEMENT_ENABLED"], message: "Policy management requires authentication" });
    }
    if (!config.TENANT_DATABASE_URL) {
      context.addIssue({ code: "custom", path: ["POLICY_MANAGEMENT_ENABLED"], message: "Policy management requires a dedicated restricted database URL" });
    } else if (
      config.AUTH_DATABASE_URL !== undefined &&
      config.TENANT_DATABASE_URL === config.AUTH_DATABASE_URL
    ) {
      context.addIssue({ code: "custom", path: ["TENANT_DATABASE_URL"], message: "Policy management requires a dedicated restricted role connection" });
    }
  }
  const machineManagementEnabled = config.MACHINE_CREDENTIAL_MANAGEMENT_ENABLED;
  const machineExchangeEnabled = config.MACHINE_SESSION_EXCHANGE_ENABLED;
  if (machineManagementEnabled) {
    if (!config.AUTH_ENABLED) {
      context.addIssue({ code: "custom", path: ["MACHINE_CREDENTIAL_MANAGEMENT_ENABLED"], message: "Machine credential management requires authentication" });
    }
    if (!config.TENANT_READS_ENABLED) {
      context.addIssue({ code: "custom", path: ["MACHINE_CREDENTIAL_MANAGEMENT_ENABLED"], message: "Machine credential management requires the protected tenant read family" });
    }
    if (!config.TENANT_WRITES_ENABLED) {
      context.addIssue({ code: "custom", path: ["MACHINE_CREDENTIAL_MANAGEMENT_ENABLED"], message: "Machine credential management requires the protected tenant write family" });
    }
  }
  if (machineExchangeEnabled) {
    if (!config.AUTH_ENABLED) {
      context.addIssue({ code: "custom", path: ["MACHINE_SESSION_EXCHANGE_ENABLED"], message: "Machine session exchange requires authentication" });
    }
    if (!config.TENANT_READS_ENABLED) {
      context.addIssue({ code: "custom", path: ["MACHINE_SESSION_EXCHANGE_ENABLED"], message: "Machine session exchange requires the protected tenant read family" });
    }
    if (!config.TENANT_DATABASE_URL) {
      context.addIssue({ code: "custom", path: ["MACHINE_SESSION_EXCHANGE_ENABLED"], message: "Machine session exchange requires a dedicated tenant database" });
    }
  }
  if (machineManagementEnabled || machineExchangeEnabled) {
    if (config.MACHINE_CREDENTIAL_PEPPER_VERSION === undefined) {
      context.addIssue({ code: "custom", path: ["MACHINE_CREDENTIAL_PEPPER_VERSION"], message: "Machine credentials require a canonical pepper version" });
    }
    if (config.MACHINE_CREDENTIAL_PEPPER === undefined) {
      context.addIssue({ code: "custom", path: ["MACHINE_CREDENTIAL_PEPPER"], message: "Machine credentials require a current pepper" });
    }
    if (config.MACHINE_RATE_SECRET === undefined) {
      context.addIssue({ code: "custom", path: ["MACHINE_RATE_SECRET"], message: "Machine credentials require a dedicated rate secret" });
    }
    const machineMaterial = [
      config.MACHINE_CREDENTIAL_PEPPER,
      config.MACHINE_CREDENTIAL_PREVIOUS_PEPPER,
      config.MACHINE_RATE_SECRET,
      config.AUTH_SECRET,
    ].filter(Boolean);
    if (new Set(machineMaterial).size !== machineMaterial.length) {
      context.addIssue({ code: "custom", message: "Machine pepper material and rate secret must be distinct from each other and AUTH_SECRET" });
    }
    const hasPreviousVersion = config.MACHINE_CREDENTIAL_PREVIOUS_VERSION !== undefined;
    const hasPreviousPepper = config.MACHINE_CREDENTIAL_PREVIOUS_PEPPER !== undefined;
    if (hasPreviousVersion !== hasPreviousPepper) {
      context.addIssue({ code: "custom", message: "Machine previous pepper version and material must be configured together" });
    }
    if (hasPreviousVersion && config.MACHINE_CREDENTIAL_PREVIOUS_VERSION === config.MACHINE_CREDENTIAL_PEPPER_VERSION) {
      context.addIssue({ code: "custom", path: ["MACHINE_CREDENTIAL_PREVIOUS_VERSION"], message: "Machine previous pepper version must differ from the current version" });
    }
    if (hasPreviousPepper && config.MACHINE_CREDENTIAL_PREVIOUS_PEPPER === config.MACHINE_CREDENTIAL_PEPPER) {
      context.addIssue({ code: "custom", path: ["MACHINE_CREDENTIAL_PREVIOUS_PEPPER"], message: "Machine previous pepper material must differ from the current pepper" });
    }
  }
  // Commerce sessions are an INDEPENDENT protected family. Enabling them
  // requires authentication and the dedicated restricted TENANT_DATABASE_URL
  // (distinct from AUTH_DATABASE_URL), but is deliberately independent of
  // tenant HTTP reads/writes, marketplace, machine issuance/exchange, policy,
  // wallet and ARC observation flags. A shared auth/tenant connection would
  // erase the restricted-role boundary, so the URLs must differ.
  if (config.COMMERCE_SESSIONS_ENABLED) {
    if (!config.AUTH_ENABLED) {
      context.addIssue({ code: "custom", path: ["COMMERCE_SESSIONS_ENABLED"], message: "Commerce sessions require authentication" });
    }
    if (!config.TENANT_DATABASE_URL) {
      context.addIssue({ code: "custom", path: ["COMMERCE_SESSIONS_ENABLED"], message: "Commerce sessions require a dedicated restricted database URL" });
    } else if (
      config.AUTH_DATABASE_URL !== undefined &&
      config.TENANT_DATABASE_URL === config.AUTH_DATABASE_URL
    ) {
      context.addIssue({ code: "custom", path: ["TENANT_DATABASE_URL"], message: "Commerce sessions require a dedicated restricted role connection" });
    }
  }
  // Commerce actions are an INDEPENDENT protected family and ship DEFAULT OFF.
  // Enabling them requires authentication, the commerce-session family (the
  // agent authorization audience presents a commerce-session bearer) and the
  // dedicated restricted TENANT_DATABASE_URL, which must stay distinct from
  // AUTH_DATABASE_URL or the restricted-role boundary is erased. An enabled
  // action surface is a control surface only: it does not enable a payment,
  // settlement or delivery lane.
  if (config.COMMERCE_ACTIONS_ENABLED) {
    if (!config.AUTH_ENABLED) {
      context.addIssue({ code: "custom", path: ["COMMERCE_ACTIONS_ENABLED"], message: "Commerce actions require authentication" });
    }
    if (!config.COMMERCE_SESSIONS_ENABLED) {
      context.addIssue({ code: "custom", path: ["COMMERCE_ACTIONS_ENABLED"], message: "Commerce actions require the commerce session family" });
    }
    if (!config.TENANT_DATABASE_URL) {
      context.addIssue({ code: "custom", path: ["COMMERCE_ACTIONS_ENABLED"], message: "Commerce actions require a dedicated restricted database URL" });
    } else if (
      config.AUTH_DATABASE_URL !== undefined &&
      config.TENANT_DATABASE_URL === config.AUTH_DATABASE_URL
    ) {
      context.addIssue({ code: "custom", path: ["TENANT_DATABASE_URL"], message: "Commerce actions require a dedicated restricted role connection" });
    }
  }
  // Authorization grants are an INDEPENDENT protected family and ship DEFAULT
  // OFF. Enabling them requires authentication, the commerce-session family
  // (the agent authorization audience presents a commerce-session bearer), the
  // commerce-action family (every grant is bound to a reserved action and the
  // frozen manifest declares `commerceActionDatabase` as a prerequisite of all
  // three grant families) and the dedicated restricted TENANT_DATABASE_URL,
  // which must stay distinct from AUTH_DATABASE_URL or the restricted-role
  // boundary is erased. An enabled grant surface is a control surface only: it
  // does not enable a payment, settlement or delivery lane.
  if (config.COMMERCE_GRANTS_ENABLED) {
    if (!config.AUTH_ENABLED) {
      context.addIssue({ code: "custom", path: ["COMMERCE_GRANTS_ENABLED"], message: "Commerce grants require authentication" });
    }
    if (!config.COMMERCE_SESSIONS_ENABLED) {
      context.addIssue({ code: "custom", path: ["COMMERCE_GRANTS_ENABLED"], message: "Commerce grants require the commerce session family" });
    }
    if (!config.COMMERCE_ACTIONS_ENABLED) {
      context.addIssue({ code: "custom", path: ["COMMERCE_GRANTS_ENABLED"], message: "Commerce grants require the commerce action family" });
    }
    if (!config.TENANT_DATABASE_URL) {
      context.addIssue({ code: "custom", path: ["COMMERCE_GRANTS_ENABLED"], message: "Commerce grants require a dedicated restricted database URL" });
    } else if (
      config.AUTH_DATABASE_URL !== undefined &&
      config.TENANT_DATABASE_URL === config.AUTH_DATABASE_URL
    ) {
      context.addIssue({ code: "custom", path: ["TENANT_DATABASE_URL"], message: "Commerce grants require a dedicated restricted role connection" });
    }
  }
  // Payment attempts (migration 0015) are an INDEPENDENT protected family and
  // ship DEFAULT OFF. Enabling them requires authentication, the commerce
  // session, commerce action AND authorization grant families (an attempt is
  // persisted only against an issued grant of a reserved action) and the
  // dedicated restricted TENANT_DATABASE_URL, distinct from AUTH_DATABASE_URL.
  // An enabled payment surface persists and records attempts only: it never
  // signs, sends or settles anything.
  if (config.COMMERCE_PAYMENTS_ENABLED) {
    if (!config.AUTH_ENABLED) {
      context.addIssue({ code: "custom", path: ["COMMERCE_PAYMENTS_ENABLED"], message: "Commerce payments require authentication" });
    }
    if (!config.COMMERCE_SESSIONS_ENABLED) {
      context.addIssue({ code: "custom", path: ["COMMERCE_PAYMENTS_ENABLED"], message: "Commerce payments require the commerce session family" });
    }
    if (!config.COMMERCE_ACTIONS_ENABLED) {
      context.addIssue({ code: "custom", path: ["COMMERCE_PAYMENTS_ENABLED"], message: "Commerce payments require the commerce action family" });
    }
    if (!config.COMMERCE_GRANTS_ENABLED) {
      context.addIssue({ code: "custom", path: ["COMMERCE_PAYMENTS_ENABLED"], message: "Commerce payments require the commerce grant family" });
    }
    if (!config.TENANT_DATABASE_URL) {
      context.addIssue({ code: "custom", path: ["COMMERCE_PAYMENTS_ENABLED"], message: "Commerce payments require a dedicated restricted database URL" });
    } else if (
      config.AUTH_DATABASE_URL !== undefined &&
      config.TENANT_DATABASE_URL === config.AUTH_DATABASE_URL
    ) {
      context.addIssue({ code: "custom", path: ["TENANT_DATABASE_URL"], message: "Commerce payments require a dedicated restricted role connection" });
    }
  }
  if (config.GATEWAY_EVIDENCE_ENABLED) {
    if (!config.AGENT_JOBS_ENABLED) {
      context.addIssue({ code: "custom", path: ["GATEWAY_EVIDENCE_ENABLED"], message: "Gateway evidence requires the cumulative job evidence milestone" });
    }
  }
  if (config.ARC_OBSERVATION_ENABLED) {
    if (!config.API_BOUNDARY_ENABLED) {
      context.addIssue({ code: "custom", path: ["API_BOUNDARY_ENABLED"], message: "Arc observation requires the API boundary" });
    }
    if (!config.REDIS_URL || !config.ABUSE_LIMIT_SECRET || !config.SOURCE_PROXY_SECRET) {
      context.addIssue({ code: "custom", message: "Arc observation requires Redis and distinct abuse/proxy secrets" });
    }
    if (config.SOURCE_MAX_SUBCALLS < 5) {
      context.addIssue({ code: "custom", path: ["SOURCE_MAX_SUBCALLS"], message: "Arc observation requires five bounded source subcalls" });
    }
  }
  if (config.AGENT_REGISTRY_ENABLED) {
    if (!config.ARC_OBSERVATION_ENABLED) {
      context.addIssue({ code: "custom", path: ["AGENT_REGISTRY_ENABLED"], message: "Agent registry evidence requires Arc observation" });
    }
    if (config.SOURCE_MAX_SUBCALLS < 16) {
      context.addIssue({ code: "custom", path: ["SOURCE_MAX_SUBCALLS"], message: "Agent registry evidence requires sixteen bounded source subcalls" });
    }
  }
  if (config.AGENT_JOBS_ENABLED) {
    if (!config.AGENT_REGISTRY_ENABLED) {
      context.addIssue({ code: "custom", path: ["AGENT_JOBS_ENABLED"], message: "Job evidence requires the cumulative agent registry milestone" });
    }
    if (config.SOURCE_MAX_SUBCALLS < 11) {
      context.addIssue({ code: "custom", path: ["SOURCE_MAX_SUBCALLS"], message: "Job evidence requires eleven bounded source subcalls" });
    }
  }
});

export type ApiConfig = z.infer<typeof EnvironmentSchema>;

export function loadConfig(input: NodeJS.ProcessEnv = process.env): ApiConfig {
  return EnvironmentSchema.parse(input);
}
