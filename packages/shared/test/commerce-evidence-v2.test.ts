import { describe, expect, expectTypeOf, it } from "vitest";

import {
  EVIDENCE_V2_ADMITS_NO_SECRET_KEYS,
  EVIDENCE_V2_CONFLICT_RULE_VERSION,
  EVIDENCE_V2_GATEWAY_COMMITTED_LIMITATION,
  EVIDENCE_V2_KIND_SOURCE_CLASSES,
  EVIDENCE_V2_LANE_UNKNOWN_REASONS,
  EVIDENCE_V2_PAYMENT_ADMITS_NO_SETTLEMENT,
  EVIDENCE_V2_PAYMENT_CERTAINTIES,
  EVIDENCE_V2_PAYMENT_CERTAINTY_RULE_VERSION,
  EVIDENCE_V2_SCHEMA_VERSION,
  EVIDENCE_V2_SOURCE_CLASSES,
  EVIDENCE_V2_SOURCE_CLASS_LABELS,
  EVIDENCE_V2_UNKNOWN_PAYMENT_LIMITATION,
  EvidenceV2ActorSchema,
  EvidenceV2ConflictInputError,
  EvidenceV2ExposureSummarySchema,
  EvidenceV2FactSchema,
  EvidenceV2OperatorViewSchema,
  EvidenceV2ProviderViewSchema,
  EvidenceV2PublicViewSchema,
  InvestigationReportSchema,
  derivePaymentCertainty,
  evidenceV2JobRefundFromMirror,
  evidenceV2JobStateFromMirror,
  projectEvidenceV2OperatorView,
  projectEvidenceV2ProviderView,
  projectEvidenceV2PublicView,
  resolveEvidenceConflict,
  summarizeEvidenceV2Exposure,
  type EvidenceV2AdmitsNoSecretKeys,
  type EvidenceV2ChainObservation,
  type EvidenceV2ExposureSummary,
  type EvidenceV2Fact,
  type EvidenceV2FactOf,
  type EvidenceV2LaneExposure,
  type EvidenceV2PaymentAdmitsNoSettlement,
  type EvidenceV2PaymentCertainty,
  type EvidenceV2PaymentCertaintyResult,
  type EvidenceV2ProviderView,
  type EvidenceV2PublicView,
  type Erc8183RefundFact,
} from "../src/index.js";

// ───────────────────────── fixtures ─────────────────────────

const ORG = "openarc:org:11111111-1111-4111-8111-111111111111";
const PROVIDER = "openarc:provider:22222222-2222-4222-8222-222222222222";
const OTHER_PROVIDER = "openarc:provider:33333333-3333-4333-8333-333333333333";
const ACCOUNT = "openarc:account:44444444-4444-4444-8444-444444444444";
const AGENT = "openarc:agent:55555555-5555-4555-8555-555555555555";
const ACTION = "openarc:action:66666666-6666-4666-8666-666666666666";
const GRANT = "openarc:grant:77777777-7777-4777-8777-777777777777";
const LISTING = "openarc:listing:88888888-8888-4888-8888-888888888888:3";
const TRANSFER = "3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b";
const BATCH = `0x${"ab".repeat(32)}`;
const OTHER_TX = `0x${"cd".repeat(32)}`;
const BLOCK_HASH = `0x${"12".repeat(32)}`;
const OTHER_BLOCK_HASH = `0x${"34".repeat(32)}`;
const JOB = `eip155:5042002:erc8183:0x${"9a".repeat(20)}:7`;
const PAYER = `0x${"a1".repeat(20)}`;
const PAY_TO = `0x${"b2".repeat(20)}`;
const T1 = "2026-09-15T10:00:00Z";
const T2 = "2026-09-15T10:00:05Z";
const T3 = "2026-09-15T10:00:10Z";

const evd = (n: number) => `evd_${n.toString(16).padStart(32, "0")}`;
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const keys = (value: object) => Object.keys(value).sort();

const common = (n: number) => ({
  schemaVersion: EVIDENCE_V2_SCHEMA_VERSION,
  evidenceId: evd(n),
  occurredAt: null,
  observedAt: T1,
  digest: null,
  dataClass: "organization_protected" as const,
  limitations: ["Control-plane record; not an external observation."],
});
const control = { class: "local", sourceId: "openarc.control", origin: "openarc:control-plane", adapterVersion: "openarc.control-projection.v1" } as const;
const gatewaySource = { class: "gateway", sourceId: "circle_gateway_testnet", origin: "https://gateway-api-testnet.circle.com", adapterVersion: "openarc.gateway-transfer.v2" } as const;
const chainSource = { class: "onchain", sourceId: "arc_rpc_testnet", origin: "https://rpc.testnet.arc.io", adapterVersion: "openarc.arc-observer.v1" } as const;
const facilitatorSource = { ...gatewaySource, class: "facilitator", sourceId: "x402_facilitator" } as const;
const anchor = (finality: "finalized" | "unfinalized" = "finalized", blockHash = BLOCK_HASH) =>
  ({ network: "eip155:5042002", blockNumber: "1200", blockHash, finality }) as const;

function authorizationFact(n = 1): EvidenceV2FactOf<"authorization_decision"> {
  return { ...common(n), kind: "authorization_decision", source: control, subject: { kind: "action", canonicalId: ACTION },
    scope: { organizationId: ORG, providerId: null, actionId: ACTION }, actor: { kind: "human_account", accountId: ACCOUNT },
    chain: null, normalized: { decision: "approved" } };
}
function grantFact(n = 2, providerId = PROVIDER): EvidenceV2FactOf<"grant_state"> {
  return { ...common(n), kind: "grant_state", source: control, subject: { kind: "authorization_grant", canonicalId: GRANT },
    scope: { organizationId: ORG, providerId, actionId: ACTION }, actor: { kind: "provider", providerId },
    chain: null, normalized: { status: "claimed" } };
}
function listingFact(n = 3, dataClass: "public" | "organization_protected" = "public"): EvidenceV2FactOf<"listing_state"> {
  return { ...common(n), dataClass, kind: "listing_state", source: control, subject: { kind: "listing", canonicalId: LISTING },
    scope: { organizationId: ORG, providerId: PROVIDER, actionId: null }, actor: { kind: "system", component: "api" },
    chain: null, normalized: { status: "active" } };
}
function exposureFact(n = 4): EvidenceV2FactOf<"budget_exposure"> {
  return { ...common(n), kind: "budget_exposure", source: control, subject: { kind: "action", canonicalId: ACTION },
    scope: { organizationId: ORG, providerId: null, actionId: ACTION }, actor: { kind: "system", component: "worker" },
    chain: null, normalized: { exposure: { held: "10", claimed: "0", unknown: "5", committed: "0" } } };
}
function committedPayment(n = 5): EvidenceV2FactOf<"payment_observation"> {
  return { ...common(n), kind: "payment_observation", source: gatewaySource, subject: { kind: "action", canonicalId: ACTION },
    scope: { organizationId: ORG, providerId: PROVIDER, actionId: ACTION }, actor: { kind: "external_party", role: "gateway", address: null },
    chain: null, limitations: [EVIDENCE_V2_GATEWAY_COMMITTED_LIMITATION],
    normalized: { laneState: "committed", certainty: "submitted_pending_chain", gatewayStatus: "completed", transferId: TRANSFER,
      batchTransactionHash: BATCH, amountAtomic: "1000000", payer: PAYER, payTo: PAY_TO } };
}
function pendingPayment(n = 6, observedAt = T1): EvidenceV2FactOf<"payment_observation"> {
  return { ...common(n), observedAt, kind: "payment_observation", source: gatewaySource, subject: { kind: "action", canonicalId: ACTION },
    scope: { organizationId: ORG, providerId: PROVIDER, actionId: ACTION }, actor: { kind: "external_party", role: "gateway", address: null },
    chain: null, normalized: { laneState: "pending", certainty: "pending", gatewayStatus: "batched", transferId: TRANSFER,
      batchTransactionHash: null, amountAtomic: "1000000", payer: PAYER, payTo: PAY_TO } };
}
function unknownPayment(n = 7): EvidenceV2FactOf<"payment_observation"> {
  return { ...common(n), kind: "payment_observation", source: gatewaySource, subject: { kind: "action", canonicalId: ACTION },
    scope: { organizationId: ORG, providerId: null, actionId: ACTION }, actor: { kind: "system", component: "worker" },
    chain: null, limitations: [EVIDENCE_V2_UNKNOWN_PAYMENT_LIMITATION],
    normalized: { laneState: "unknown", certainty: "unknown", unknownReason: "timeout" } };
}
function arcTxFact(n = 8, finality: "finalized" | "unfinalized" = "finalized", observedAt = T1, blockHash = BLOCK_HASH): EvidenceV2FactOf<"arc_transaction"> {
  return { ...common(n), observedAt, kind: "arc_transaction", source: chainSource, subject: { kind: "arc_transaction", canonicalId: `eip155:5042002:tx:${BATCH}` },
    scope: { organizationId: ORG, providerId: null, actionId: ACTION }, actor: { kind: "external_party", role: "arc_chain", address: null },
    chain: anchor(finality, blockHash), normalized: { transactionHash: BATCH, receiptStatus: "success" } };
}
function jobStateFact(n = 9): EvidenceV2FactOf<"job_state"> {
  return { ...common(n), dataClass: "public", kind: "job_state", source: chainSource, subject: { kind: "erc8183_job", canonicalId: JOB },
    scope: { organizationId: ORG, providerId: null, actionId: null }, actor: { kind: "external_party", role: "erc8183_evaluator", address: PAY_TO },
    chain: anchor(), normalized: { knowledge: "known", status: "Completed", terminal: true } };
}
function jobRefundFact(n = 10): EvidenceV2FactOf<"job_refund"> {
  return { ...common(n), dataClass: "public", kind: "job_refund", source: chainSource, subject: { kind: "erc8183_job", canonicalId: JOB },
    scope: { organizationId: ORG, providerId: null, actionId: null }, actor: { kind: "external_party", role: "erc8183_client", address: PAYER },
    chain: anchor(), normalized: { cause: "rejected", amountAtomic: "2500000", transactionHash: OTHER_TX } };
}
function deliveryFact(n = 11): EvidenceV2FactOf<"provider_delivery"> {
  return { ...common(n), kind: "provider_delivery", source: { ...control, class: "provider", origin: "https://provider.example" },
    subject: { kind: "action", canonicalId: ACTION }, scope: { organizationId: ORG, providerId: PROVIDER, actionId: ACTION },
    actor: { kind: "provider", providerId: PROVIDER }, chain: null, normalized: { reported: "delivered", responseDigest: `sha256:${"0f".repeat(32)}` } };
}
function evaluatorFact(n = 12): EvidenceV2FactOf<"evaluator_result"> {
  return { ...common(n), kind: "evaluator_result", source: { ...control, class: "evaluator", origin: "openarc:reconciler" },
    subject: { kind: "action", canonicalId: ACTION }, scope: { organizationId: ORG, providerId: null, actionId: ACTION },
    actor: { kind: "agent", agentId: AGENT }, chain: null, normalized: { result: "accepted" } };
}

const ALL_FACTS: EvidenceV2Fact[] = [authorizationFact(), grantFact(), listingFact(), exposureFact(), committedPayment(),
  pendingPayment(), unknownPayment(), arcTxFact(), jobStateFact(), jobRefundFact(), deliveryFact(), evaluatorFact()];

const committedLane: EvidenceV2LaneExposure = { state: "committed", disposition: "committed", transferId: TRANSFER,
  gatewayStatus: "completed", batchTxHash: BATCH, onchainReceiptVerified: false };
const pendingLane: EvidenceV2LaneExposure = { state: "pending", disposition: "held", transferId: TRANSFER, gatewayStatus: "confirmed", batchTxHash: BATCH };
const chainObs = (overrides: Partial<EvidenceV2ChainObservation> = {}): EvidenceV2ChainObservation => ({
  network: "eip155:5042002", transactionHash: BATCH, blockNumber: "1200", blockHash: BLOCK_HASH, finality: "finalized",
  receiptStatus: "success", ...overrides });

// ───────────────────────── decision 1 ─────────────────────────

describe("evidence v2 source classes (decision 1)", () => {
  it("defines exactly the nine source classes of the source of truth", () => {
    expect([...EVIDENCE_V2_SOURCE_CLASSES]).toEqual(["local", "signed", "agent_reported", "provider", "facilitator", "gateway",
      "onchain", "evaluator", "openarc_derived"]);
    expect(keys(EVIDENCE_V2_SOURCE_CLASS_LABELS)).toEqual([...EVIDENCE_V2_SOURCE_CLASSES].sort());
    expect(EVIDENCE_V2_SOURCE_CLASS_LABELS.local).toBe("OpenArc control-plane record");
    expect(EVIDENCE_V2_SOURCE_CLASS_LABELS.onchain).toBe("Arc chain observation");
  });

  it("accepts every fixture fact", () => {
    for (const fact of ALL_FACTS) expect(EvidenceV2FactSchema.safeParse(fact).success, fact.kind).toBe(true);
  });

  it("enforces the kind by source-class authority matrix for all nine classes", () => {
    const byKind = new Map(ALL_FACTS.map((fact) => [fact.kind, fact]));
    expect(byKind.size).toBe(Object.keys(EVIDENCE_V2_KIND_SOURCE_CLASSES).length);
    for (const [kind, fact] of byKind) {
      for (const sourceClass of EVIDENCE_V2_SOURCE_CLASSES) {
        const candidate = clone(fact) as { source: { class: string }; actor: unknown };
        candidate.source.class = sourceClass;
        if (sourceClass === "provider") candidate.actor = { kind: "provider", providerId: PROVIDER };
        const allowed = EVIDENCE_V2_KIND_SOURCE_CLASSES[kind].includes(sourceClass);
        const scopedOk = sourceClass !== "provider" || (fact.scope.providerId === PROVIDER);
        // An OpenArc-derived grant fact can only be a derived expiry; the fixture grant is claimed.
        const derivedOk = !(kind === "grant_state" && sourceClass === "openarc_derived");
        expect(EvidenceV2FactSchema.safeParse(candidate).success, `${kind}/${sourceClass}`).toBe(allowed && scopedOk && derivedOk);
      }
    }
    const derivedExpiry = { ...grantFact(), source: { ...control, class: "openarc_derived", origin: "openarc:reconciler" },
      actor: { kind: "system", component: "reconciler" }, normalized: { status: "expired" } };
    expect(EvidenceV2FactSchema.safeParse(derivedExpiry).success).toBe(true);
    expect(EvidenceV2FactSchema.safeParse({ ...derivedExpiry, normalized: { status: "revoked" } }).success).toBe(false);
    expect(Object.values(EVIDENCE_V2_KIND_SOURCE_CLASSES).flat()).not.toContain("signed");
    expect(Object.values(EVIDENCE_V2_KIND_SOURCE_CLASSES).flat()).not.toContain("agent_reported");
  });

  it("requires source class, origin, adapter version and observedAt on every fact", () => {
    for (const fact of ALL_FACTS) {
      for (const field of ["class", "sourceId", "origin", "adapterVersion"] as const) {
        const candidate = clone(fact) as unknown as { source: Record<string, unknown> };
        delete candidate.source[field];
        expect(EvidenceV2FactSchema.safeParse(candidate).success, `${fact.kind}.source.${field}`).toBe(false);
      }
      const noObserved = clone(fact) as unknown as Record<string, unknown>;
      delete noObserved.observedAt;
      expect(EvidenceV2FactSchema.safeParse(noObserved).success).toBe(false);
    }
    const badOrigin = clone(authorizationFact());
    (badOrigin.source as { origin: string }).origin = "https://gateway.example/path?x=1";
    expect(EvidenceV2FactSchema.safeParse(badOrigin).success).toBe(false);
  });

  it("requires block number, block hash and finality on chain facts and forbids a chain anchor elsewhere", () => {
    for (const fact of ALL_FACTS) {
      const isChain = fact.source.class === "onchain";
      expect(fact.chain !== null).toBe(isChain);
      if (isChain) {
        for (const field of ["blockNumber", "blockHash", "finality"] as const) {
          const candidate = clone(fact) as unknown as { chain: Record<string, unknown> };
          delete candidate.chain[field];
          expect(EvidenceV2FactSchema.safeParse(candidate).success, `${fact.kind}.chain.${field}`).toBe(false);
        }
        expect(EvidenceV2FactSchema.safeParse({ ...clone(fact), chain: null }).success).toBe(false);
        expect(EvidenceV2FactSchema.safeParse({ ...clone(fact), chain: { ...anchor(), finality: "safe" } }).success).toBe(false);
      } else {
        expect(EvidenceV2FactSchema.safeParse({ ...clone(fact), chain: anchor() }).success, fact.kind).toBe(false);
      }
    }
  });

  it("rejects occurredAt after observedAt and an unfinalized job refund", () => {
    expect(EvidenceV2FactSchema.safeParse({ ...authorizationFact(), occurredAt: T2 }).success).toBe(false);
    expect(EvidenceV2FactSchema.safeParse({ ...jobRefundFact(), chain: anchor("unfinalized") }).success).toBe(false);
  });
});

// ───────────────────────── decision 2 ─────────────────────────

describe("evidence v2 actor attribution (decision 2)", () => {
  it("accepts exactly the five actor kinds with server-side IDs", () => {
    const actors = [
      { kind: "human_account", accountId: ACCOUNT },
      { kind: "agent", agentId: AGENT },
      { kind: "provider", providerId: PROVIDER },
      { kind: "system", component: "worker" },
      { kind: "external_party", role: "gateway", address: null },
    ];
    for (const actor of actors) expect(EvidenceV2ActorSchema.parse(actor)).toEqual(actor);
    expect(EvidenceV2ActorSchema.safeParse({ kind: "anonymous" }).success).toBe(false);
  });

  it("rejects token and session hashes as actor identifiers or extra actor fields", () => {
    const hash = `sha256:${"ee".repeat(32)}`;
    expect(EvidenceV2ActorSchema.safeParse({ kind: "human_account", accountId: hash }).success).toBe(false);
    expect(EvidenceV2ActorSchema.safeParse({ kind: "agent", agentId: "ee".repeat(32) }).success).toBe(false);
    expect(EvidenceV2ActorSchema.safeParse({ kind: "human_account", accountId: ACCOUNT, sessionHash: hash }).success).toBe(false);
    expect(EvidenceV2ActorSchema.safeParse({ kind: "agent", agentId: AGENT, tokenHash: hash }).success).toBe(false);
    expect(EvidenceV2ActorSchema.safeParse({ kind: "provider", providerId: PROVIDER, credentialId: "c1" }).success).toBe(false);
  });

  it("requires a provider actor and a provider attestation to match the provider scope", () => {
    expect(EvidenceV2FactSchema.safeParse({ ...grantFact(), actor: { kind: "provider", providerId: OTHER_PROVIDER } }).success).toBe(false);
    expect(EvidenceV2FactSchema.safeParse({ ...deliveryFact(), actor: { kind: "system", component: "api" } }).success).toBe(false);
    expect(EvidenceV2FactSchema.safeParse({ ...grantFact(), scope: { ...grantFact().scope, providerId: null } }).success).toBe(false);
  });
});

// ───────────────────────── decision 3 ─────────────────────────

const PUBLIC_KEYS = ["adapterVersion", "finality", "kind", "limitations", "observedAt", "occurredAt", "schemaVersion",
  "sourceClass", "status", "subject", "view"];
const PROVIDER_KEYS = ["actorKind", "evidenceId", "kind", "limitations", "observedAt", "occurredAt", "schemaVersion",
  "sourceClass", "status", "subject", "view"];
const OPERATOR_KEYS = ["actor", "chain", "dataClass", "digest", "evidenceId", "kind", "limitations", "normalized", "observedAt",
  "occurredAt", "schemaVersion", "scope", "source", "subject", "view"];

describe("evidence v2 audience views (decision 3)", () => {
  it("public view has the exact key set and no amount, address or internal ID", () => {
    expect(keys(EvidenceV2PublicViewSchema.shape)).toEqual(PUBLIC_KEYS);
    for (const fact of [listingFact(), jobStateFact(), jobRefundFact()]) {
      const view = projectEvidenceV2PublicView(fact) as EvidenceV2PublicView;
      expect(keys(view)).toEqual(PUBLIC_KEYS);
      expect(keys(view.subject)).toEqual(["canonicalId", "kind"]);
      const json = JSON.stringify(view);
      for (const hidden of [ORG, PROVIDER, fact.evidenceId, PAYER, PAY_TO, "2500000", OTHER_TX, BLOCK_HASH, "1200"]) {
        expect(json).not.toContain(hidden);
      }
    }
    expect(projectEvidenceV2PublicView(jobRefundFact())?.status).toBe("job_refund_paired");
    expectTypeOf<keyof EvidenceV2PublicView>().toEqualTypeOf<"adapterVersion" | "finality" | "kind" | "limitations" | "observedAt" |
      "occurredAt" | "schemaVersion" | "sourceClass" | "status" | "subject" | "view">();
    expectTypeOf<keyof EvidenceV2ProviderView>().toEqualTypeOf<"actorKind" | "evidenceId" | "kind" | "limitations" | "observedAt" |
      "occurredAt" | "schemaVersion" | "sourceClass" | "status" | "subject" | "view">();
  });

  it("public projection refuses organization-protected facts and kinds that cannot be public", () => {
    expect(projectEvidenceV2PublicView(listingFact(3, "organization_protected"))).toBeNull();
    for (const fact of ALL_FACTS.filter((candidate) => !["listing_state", "job_state", "job_refund"].includes(candidate.kind))) {
      expect(projectEvidenceV2PublicView(fact), fact.kind).toBeNull();
      expect(EvidenceV2FactSchema.safeParse({ ...clone(fact), dataClass: "public" }).success, fact.kind).toBe(false);
    }
    const draft = listingFact();
    expect(EvidenceV2FactSchema.safeParse({ ...draft, normalized: { status: "draft" } }).success).toBe(false);
  });

  it("provider view has the exact key set and only the viewer's own listing and grant facts", () => {
    expect(keys(EvidenceV2ProviderViewSchema.shape)).toEqual(PROVIDER_KEYS);
    for (const fact of [listingFact(), grantFact()]) {
      const view = projectEvidenceV2ProviderView(fact, PROVIDER) as EvidenceV2ProviderView;
      expect(keys(view)).toEqual(PROVIDER_KEYS);
      expect(JSON.stringify(view)).not.toContain(ORG);
      expect(JSON.stringify(view)).not.toContain(PROVIDER);
      expect(projectEvidenceV2ProviderView(fact, OTHER_PROVIDER)).toBeNull();
    }
    for (const fact of [committedPayment(), deliveryFact(), exposureFact()]) {
      expect(projectEvidenceV2ProviderView(fact, PROVIDER), fact.kind).toBeNull();
    }
    expect(() => projectEvidenceV2ProviderView(grantFact(), `sha256:${"aa".repeat(32)}`)).toThrow();
  });

  it("operator view has the exact key set of the full fact", () => {
    for (const fact of ALL_FACTS) {
      const view = projectEvidenceV2OperatorView(fact);
      expect(keys(view)).toEqual(OPERATOR_KEYS);
      const { view: tag, ...rest } = view;
      expect(tag).toBe("operator");
      expect(rest).toEqual(fact);
    }
  });

  it("view schemas are strict and reject passthrough keys", () => {
    const publicView = projectEvidenceV2PublicView(listingFact()) as EvidenceV2PublicView;
    const providerView = projectEvidenceV2ProviderView(grantFact(), PROVIDER) as EvidenceV2ProviderView;
    const operatorView = projectEvidenceV2OperatorView(committedPayment());
    expect(EvidenceV2PublicViewSchema.safeParse({ ...publicView, amountAtomic: "1" }).success).toBe(false);
    expect(EvidenceV2PublicViewSchema.safeParse({ ...publicView, organizationId: ORG }).success).toBe(false);
    expect(EvidenceV2ProviderViewSchema.safeParse({ ...providerView, scope: {} }).success).toBe(false);
    expect(EvidenceV2OperatorViewSchema.safeParse({ ...operatorView, extra: 1 }).success).toBe(false);
    expect(EvidenceV2OperatorViewSchema.safeParse({ ...operatorView, view: "public" }).success).toBe(false);
  });
});

// ───────────────────────── decision 4 ─────────────────────────

const CANARY_KEYS = ["signature", "authorization", "authorizationPayload", "payload", "rawPayload", "nonceSignature", "privateKey",
  "apiKey", "token", "accessToken", "sessionHash", "sessionTokenHash", "tokenHash", "secret", "password", "cookie"];
const CANARY_VALUES = [
  `0x${"5a".repeat(65)}`,
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl",
  `sk_live_${"A".repeat(40)}`,
  `Bearer ${"Zm9vYmFy".repeat(6)}`,
];

function objectPaths(value: unknown, path: string[] = []): string[][] {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return [];
  return [path, ...Object.entries(value).flatMap(([key, child]) => objectPaths(child, [...path, key]))];
}
function stringPaths(value: unknown, path: (string | number)[] = []): (string | number)[][] {
  if (typeof value === "string") return [path];
  if (Array.isArray(value)) return value.flatMap((child, index) => stringPaths(child, [...path, index]));
  if (value !== null && typeof value === "object") return Object.entries(value).flatMap(([key, child]) => stringPaths(child, [...path, key]));
  return [];
}
function at(root: unknown, path: readonly (string | number)[]): Record<string | number, unknown> {
  return path.reduce<unknown>((node, key) => (node as Record<string | number, unknown>)[key], root) as Record<string | number, unknown>;
}

describe("evidence v2 has no secret material (decision 4)", () => {
  it("proves at the type level that no secret-named key is representable", () => {
    expectTypeOf<EvidenceV2AdmitsNoSecretKeys>().toEqualTypeOf<true>();
    expect(EVIDENCE_V2_ADMITS_NO_SECRET_KEYS).toBe(true);
    // @ts-expect-error a signature cannot be attached to a fact
    const signed: EvidenceV2Fact = { ...authorizationFact(), signature: "0x00" };
    // @ts-expect-error an actor cannot carry a session hash
    const session: EvidenceV2Fact = { ...authorizationFact(), actor: { kind: "human_account", accountId: ACCOUNT, sessionHash: "x" } };
    // @ts-expect-error the public view cannot carry a token
    const tokenView: EvidenceV2PublicView = { ...(projectEvidenceV2PublicView(listingFact()) as EvidenceV2PublicView), token: "x" };
    expect([signed, session, tokenView]).toHaveLength(3);
  });

  it("rejects canary secret keys at every nesting level of every fact and view", () => {
    let checked = 0;
    for (const fact of ALL_FACTS) {
      const targets: [string, (value: unknown) => boolean, unknown][] = [
        ["fact", (value) => EvidenceV2FactSchema.safeParse(value).success, fact],
        ["operator", (value) => EvidenceV2OperatorViewSchema.safeParse(value).success, projectEvidenceV2OperatorView(fact)],
      ];
      const publicView = projectEvidenceV2PublicView(fact);
      if (publicView !== null) targets.push(["public", (value) => EvidenceV2PublicViewSchema.safeParse(value).success, publicView]);
      const providerView = projectEvidenceV2ProviderView(fact, PROVIDER);
      if (providerView !== null) targets.push(["provider", (value) => EvidenceV2ProviderViewSchema.safeParse(value).success, providerView]);
      for (const [label, accepts, original] of targets) {
        expect(accepts(original), label).toBe(true);
        for (const path of objectPaths(original)) {
          for (const canary of CANARY_KEYS) {
            const candidate = clone(original);
            at(candidate, path)[canary] = "canary";
            expect(accepts(candidate), `${label}:${fact.kind}:${path.join(".")}.${canary}`).toBe(false);
            checked += 1;
          }
        }
      }
    }
    expect(checked).toBeGreaterThan(1000);
  });

  it("rejects canary secret values in every string slot", () => {
    for (const fact of ALL_FACTS) {
      for (const path of stringPaths(fact)) {
        for (const canary of CANARY_VALUES) {
          const candidate = clone(fact);
          at(candidate, path.slice(0, -1))[path.at(-1) as string | number] = canary;
          expect(EvidenceV2FactSchema.safeParse(candidate).success, `${fact.kind}:${path.join(".")}`).toBe(false);
        }
      }
    }
  });

  it("projections throw on a smuggled key rather than passing it through", () => {
    const smuggled = { ...listingFact(), signature: CANARY_VALUES[0] } as unknown as EvidenceV2Fact;
    expect(() => projectEvidenceV2PublicView(smuggled)).toThrow();
    expect(() => projectEvidenceV2ProviderView(smuggled, PROVIDER)).toThrow();
    expect(() => projectEvidenceV2OperatorView(smuggled)).toThrow();
    expect(() => resolveEvidenceConflict([smuggled])).toThrow();
  });
});

// ───────────────────────── decision 5 ─────────────────────────

describe("evidence v2 payment certainty (decision 5)", () => {
  it("proves at the type level that no settled, paid, refunded, failed or released state exists", () => {
    expectTypeOf<EvidenceV2PaymentAdmitsNoSettlement>().toEqualTypeOf<true>();
    expect(EVIDENCE_V2_PAYMENT_ADMITS_NO_SETTLEMENT).toBe(true);
    expectTypeOf<EvidenceV2PaymentCertainty>().toEqualTypeOf<"unknown" | "pending" | "submitted_pending_chain" | "onchain_confirmed">();
    expectTypeOf<EvidenceV2PaymentCertaintyResult["exposure"]>().toEqualTypeOf<"held" | "committed">();
    expectTypeOf<EvidenceV2FactOf<"payment_observation">["normalized"]["certainty"]>()
      .toEqualTypeOf<"unknown" | "pending" | "submitted_pending_chain">();
    expectTypeOf<Extract<EvidenceV2PaymentCertaintyResult, { certainty: "onchain_confirmed" }>["chainCheck"]>()
      .toEqualTypeOf<"matched_finalized">();
    expect([...EVIDENCE_V2_PAYMENT_CERTAINTIES]).toEqual(["unknown", "pending", "submitted_pending_chain", "onchain_confirmed"]);

    // @ts-expect-error settled is not a payment certainty
    const settled: EvidenceV2PaymentCertainty = "settled";
    // @ts-expect-error a committed lane cannot be paired with a paid certainty
    const paid: EvidenceV2FactOf<"payment_observation">["normalized"] = { ...committedPayment().normalized, certainty: "paid" };
    // @ts-expect-error a Gateway observation cannot claim onchain confirmation
    const confirmed: EvidenceV2FactOf<"payment_observation">["normalized"] = { ...committedPayment().normalized, certainty: "onchain_confirmed" };
    // @ts-expect-error there is no released lane state
    const released: EvidenceV2LaneExposure = { state: "released", disposition: "released", reason: "timeout" };
    // @ts-expect-error an unknown lane cannot be committed
    const unheld: EvidenceV2LaneExposure = { state: "unknown", disposition: "committed", reason: "timeout" };
    expect([settled, paid, confirmed, released, unheld]).toHaveLength(5);
  });

  it("maps every lane unknown reason to unknown and held, with or without a matching chain observation", () => {
    expect(EVIDENCE_V2_LANE_UNKNOWN_REASONS).toHaveLength(12);
    for (const reason of EVIDENCE_V2_LANE_UNKNOWN_REASONS) {
      for (const chain of [undefined, chainObs()]) {
        expect(derivePaymentCertainty({ state: "unknown", disposition: "held", reason }, chain)).toEqual({
          ruleVersion: EVIDENCE_V2_PAYMENT_CERTAINTY_RULE_VERSION, certainty: "unknown", exposure: "held",
          chainCheck: "not_applicable_lane_not_committed" });
      }
    }
  });

  it("keeps pending as pending even with a finalized matching chain observation", () => {
    for (const chain of [undefined, chainObs(), chainObs({ finality: "unfinalized" })]) {
      expect(derivePaymentCertainty(pendingLane, chain)).toMatchObject({ certainty: "pending", exposure: "held" });
    }
  });

  it("maps committed without a chain observation to submitted_pending_chain", () => {
    expect(derivePaymentCertainty(committedLane)).toEqual({ ruleVersion: EVIDENCE_V2_PAYMENT_CERTAINTY_RULE_VERSION,
      certainty: "submitted_pending_chain", exposure: "committed", chainCheck: "not_observed" });
  });

  it("keeps committed at submitted_pending_chain for an unfinalized, mismatched-transaction or wrong-network observation", () => {
    expect(derivePaymentCertainty(committedLane, chainObs({ finality: "unfinalized" }))).toMatchObject({ certainty: "submitted_pending_chain", chainCheck: "unfinalized" });
    expect(derivePaymentCertainty(committedLane, chainObs({ transactionHash: OTHER_TX }))).toMatchObject({ certainty: "submitted_pending_chain", chainCheck: "transaction_mismatch" });
    expect(derivePaymentCertainty(committedLane, chainObs({ network: "eip155:1" }))).toMatchObject({ certainty: "submitted_pending_chain", chainCheck: "network_mismatch" });
    expect(derivePaymentCertainty(committedLane, chainObs({ transactionHash: OTHER_TX, finality: "unfinalized", receiptStatus: "reverted" })))
      .toMatchObject({ certainty: "submitted_pending_chain", chainCheck: "transaction_mismatch" });
  });

  it("yields onchain_confirmed only for a finalized, matching, successful Arc receipt", () => {
    expect(derivePaymentCertainty(committedLane, chainObs())).toEqual({ ruleVersion: EVIDENCE_V2_PAYMENT_CERTAINTY_RULE_VERSION,
      certainty: "onchain_confirmed", exposure: "committed", chainCheck: "matched_finalized" });
  });

  it("holds a finalized reverted receipt that contradicts Gateway as unknown", () => {
    expect(derivePaymentCertainty(committedLane, chainObs({ receiptStatus: "reverted" }))).toMatchObject({
      certainty: "unknown", exposure: "held", chainCheck: "reverted_contradicts_gateway" });
  });

  it("confirms exactly one combination across the exhaustive lane by chain table", () => {
    const lanes: EvidenceV2LaneExposure[] = [
      ...EVIDENCE_V2_LANE_UNKNOWN_REASONS.map((reason) => ({ state: "unknown", disposition: "held", reason }) as const),
      ...(["received", "batched", "confirmed"] as const).flatMap((gatewayStatus) => [BATCH, null].map((batchTxHash) =>
        ({ state: "pending", disposition: "held", transferId: TRANSFER, gatewayStatus, batchTxHash }) as const)),
      committedLane,
    ];
    const chains: (EvidenceV2ChainObservation | undefined)[] = [undefined];
    for (const network of ["eip155:5042002", "eip155:1"]) for (const transactionHash of [BATCH, OTHER_TX])
      for (const finality of ["finalized", "unfinalized"] as const) for (const receiptStatus of ["success", "reverted"] as const)
        chains.push(chainObs({ network, transactionHash, finality, receiptStatus }));
    const confirmedCells: string[] = [];
    const seen = new Set<string>();
    for (const lane of lanes) for (const chain of chains) {
      const result = derivePaymentCertainty(lane, chain);
      seen.add(result.certainty);
      expect(["settled", "paid", "refunded", "failed", "released"]).not.toContain(result.certainty);
      if (lane.state === "unknown") expect(result.certainty).toBe("unknown");
      if (lane.state === "pending") expect(result.certainty).toBe("pending");
      if (result.certainty === "onchain_confirmed") confirmedCells.push(JSON.stringify([lane.state, chain]));
    }
    expect(lanes.length * chains.length).toBe(19 * 17);
    expect(confirmedCells).toEqual([JSON.stringify(["committed", chainObs()])]);
    expect([...seen].sort()).toEqual([...EVIDENCE_V2_PAYMENT_CERTAINTIES].sort());
  });

  it("rejects malformed lane and chain input", () => {
    expect(() => derivePaymentCertainty({ ...committedLane, onchainReceiptVerified: true } as unknown as EvidenceV2LaneExposure)).toThrow();
    expect(() => derivePaymentCertainty({ state: "settled" } as unknown as EvidenceV2LaneExposure)).toThrow();
    expect(() => derivePaymentCertainty(committedLane, { ...chainObs(), finality: "safe" } as unknown as EvidenceV2ChainObservation)).toThrow();
    expect(() => derivePaymentCertainty(committedLane, { ...chainObs(), transactionHash: BATCH.toUpperCase().replace("0X", "0x") })).toThrow();
  });

  it("payment observation facts pair lane state with certainty and state their limitation", () => {
    const committed = committedPayment();
    expect(EvidenceV2FactSchema.safeParse({ ...committed, normalized: { ...committed.normalized, certainty: "onchain_confirmed" } }).success).toBe(false);
    expect(EvidenceV2FactSchema.safeParse({ ...committed, normalized: { ...committed.normalized, certainty: "pending" } }).success).toBe(false);
    expect(EvidenceV2FactSchema.safeParse({ ...committed, normalized: { ...committed.normalized, gatewayStatus: "failed" } }).success).toBe(false);
    expect(EvidenceV2FactSchema.safeParse({ ...committed, limitations: ["Gateway record."] }).success).toBe(false);
    expect(EvidenceV2FactSchema.safeParse({ ...unknownPayment(), limitations: ["No outcome."] }).success).toBe(false);
    expect(EvidenceV2FactSchema.safeParse({ ...unknownPayment(), normalized: { laneState: "unknown", certainty: "unknown", unknownReason: "settled" } }).success).toBe(false);
    for (const state of ["settled", "paid", "refunded", "failed", "released"]) {
      expect(EvidenceV2FactSchema.safeParse({ ...committed, normalized: { ...committed.normalized, laneState: state } }).success, state).toBe(false);
    }
  });

  it("creates an ERC-8183 job refund fact only for a paired mirror refund", () => {
    const refunds: Erc8183RefundFact[] = [
      { state: "not_applicable" },
      { state: "none_zero_budget", cause: "expired" },
      { state: "unknown", amount: "5", reason: "unpaired_refund" },
      { state: "unknown", amount: null, reason: "missing_refund_event" },
    ];
    for (const refund of refunds) expect(evidenceV2JobRefundFromMirror(refund), refund.state).toBeNull();
    expect(evidenceV2JobRefundFromMirror({ state: "refunded", amount: "2500000", cause: "rejected", transactionHash: OTHER_TX }))
      .toEqual(jobRefundFact().normalized);
    expect(evidenceV2JobStateFromMirror({ kind: "unknown", reason: "refund_unpaired", lastKnown: "Funded", asOfBlock: "9" }))
      .toEqual({ knowledge: "unknown", reason: "refund_unpaired", lastKnown: "Funded" });
    expect(EvidenceV2FactSchema.safeParse({ ...jobStateFact(), normalized: { knowledge: "known", status: "Completed", terminal: false } }).success).toBe(false);
    expect(EvidenceV2FactSchema.safeParse({ ...jobStateFact(), normalized: { knowledge: "known", status: "Settled", terminal: true } }).success).toBe(false);
  });
});

// ───────────────────────── decision 6 ─────────────────────────

describe("evidence v2 exposure buckets (decision 6)", () => {
  it("has exactly the held, claimed, unknown and committed buckets and no merged total", () => {
    expectTypeOf<keyof EvidenceV2ExposureSummary>().toEqualTypeOf<"held" | "claimed" | "unknown" | "committed">();
    expect(keys(EvidenceV2ExposureSummarySchema.shape)).toEqual(["claimed", "committed", "held", "unknown"]);
    // @ts-expect-error a merged reserved total is not representable
    const merged: EvidenceV2ExposureSummary = { reserved: "15", committed: "0" };
    // @ts-expect-error an unresolved total cannot replace the unknown bucket
    const unresolved: EvidenceV2ExposureSummary = { held: "10", claimed: "0", unresolved: "15", committed: "0" };
    expect([merged, unresolved]).toHaveLength(2);
  });

  it("keeps unknown in its own bucket and never folds it into another", () => {
    expect(summarizeEvidenceV2Exposure([{ bucket: "unknown", amountAtomic: "7" }])).toEqual({ held: "0", claimed: "0", unknown: "7", committed: "0" });
    const summary = summarizeEvidenceV2Exposure([
      { bucket: "held", amountAtomic: "10" }, { bucket: "unknown", amountAtomic: "5" }, { bucket: "claimed", amountAtomic: "3" },
      { bucket: "unknown", amountAtomic: "115792089237316195423570985008687907853269984665640564039457584007913129639930" },
      { bucket: "committed", amountAtomic: "2" },
    ]);
    expect(summary).toEqual({ held: "10", claimed: "3",
      unknown: "115792089237316195423570985008687907853269984665640564039457584007913129639935", committed: "2" });
    expect(() => summarizeEvidenceV2Exposure([
      { bucket: "unknown", amountAtomic: "115792089237316195423570985008687907853269984665640564039457584007913129639935" },
      { bucket: "unknown", amountAtomic: "1" }])).toThrow(RangeError);
  });

  it("rejects merged totals, missing buckets, released status and non-integer amounts", () => {
    const valid = { held: "10", claimed: "0", unknown: "5", committed: "0" };
    expect(EvidenceV2ExposureSummarySchema.parse(valid)).toEqual(valid);
    expect(EvidenceV2ExposureSummarySchema.safeParse({ ...valid, reserved: "15" }).success).toBe(false);
    expect(EvidenceV2ExposureSummarySchema.safeParse({ held: "15", claimed: "0", committed: "0" }).success).toBe(false);
    for (const amount of ["1.5", "-1", "01", " 1", "1e3"]) {
      expect(EvidenceV2ExposureSummarySchema.safeParse({ ...valid, unknown: amount }).success, amount).toBe(false);
    }
    expect(() => summarizeEvidenceV2Exposure([{ bucket: "released", amountAtomic: "1" } as never])).toThrow();
    expect(EvidenceV2FactSchema.safeParse({ ...exposureFact(), normalized: { exposure: { held: "15", claimed: "0", committed: "0" } } }).success).toBe(false);
  });
});

// ───────────────────────── decision 7 ─────────────────────────

function permutations<T>(items: readonly T[]): T[][] {
  if (items.length <= 1) return [[...items]];
  return items.flatMap((item, index) => permutations([...items.slice(0, index), ...items.slice(index + 1)]).map((rest) => [item, ...rest]));
}

describe("evidence v2 conflict resolution (decision 7)", () => {
  it("resolves identical single-source re-observations deterministically", () => {
    const facts = [pendingPayment(6, T1), pendingPayment(16, T3), pendingPayment(26, T2)];
    const expected = { outcome: "resolved", ruleVersion: EVIDENCE_V2_CONFLICT_RULE_VERSION, kind: "payment_observation",
      subject: { kind: "action", canonicalId: ACTION }, source: { class: "gateway", sourceId: "circle_gateway_testnet",
        origin: "https://gateway-api-testnet.circle.com" }, status: "pending", finality: null,
      evidenceIds: [evd(6), evd(16), evd(26)].sort(), firstObservedAt: T1, lastObservedAt: T3 };
    for (const order of permutations(facts)) expect(resolveEvidenceConflict(order)).toEqual(expected);
    expect(resolveEvidenceConflict([pendingPayment(), pendingPayment()])).toMatchObject({ outcome: "resolved", evidenceIds: [evd(6)] });
  });

  it("corroborates agreeing facts from different sources, listing every source, for every input order", () => {
    const gateway = pendingPayment(6, T1);
    const facilitator = { ...pendingPayment(17, T2), source: facilitatorSource } as EvidenceV2Fact;
    const gatewayAgain = pendingPayment(26, T3);
    const expected = { outcome: "corroborated", ruleVersion: EVIDENCE_V2_CONFLICT_RULE_VERSION, kind: "payment_observation",
      subject: { kind: "action", canonicalId: ACTION },
      sources: [
        { class: "facilitator", sourceId: "x402_facilitator", origin: "https://gateway-api-testnet.circle.com" },
        { class: "gateway", sourceId: "circle_gateway_testnet", origin: "https://gateway-api-testnet.circle.com" },
      ],
      status: "pending", finality: null, evidenceIds: [evd(6), evd(17), evd(26)].sort(), firstObservedAt: T1, lastObservedAt: T3 };
    for (const order of permutations([gateway, facilitator, gatewayAgain])) {
      const result = resolveEvidenceConflict(order);
      expect(result).toEqual(expected);
      expect(result).not.toHaveProperty("reasons");
    }
    expect(resolveEvidenceConflict([gateway, facilitator, facilitator])).toMatchObject({ outcome: "corroborated", evidenceIds: [evd(6), evd(17)] });
  });

  it("corroborates agreeing chain observations from two sources without regressing finality or lastObservedAt", () => {
    const backupSource = { ...chainSource, sourceId: "arc_rpc_backup", origin: "https://rpc-backup.testnet.arc.io" } as const;
    const finalizedEarly = arcTxFact(8, "finalized", T1);
    const unfinalizedLate = { ...arcTxFact(18, "unfinalized", T3), source: backupSource } as EvidenceV2Fact;
    const unfinalizedMiddle = arcTxFact(28, "unfinalized", T2);
    for (const order of permutations([finalizedEarly, unfinalizedLate, unfinalizedMiddle])) {
      expect(resolveEvidenceConflict(order)).toMatchObject({ outcome: "corroborated", status: "success", finality: "finalized",
        firstObservedAt: T1, lastObservedAt: T3,
        sources: [{ class: "onchain", sourceId: "arc_rpc_backup" }, { class: "onchain", sourceId: "arc_rpc_testnet" }] });
    }
  });

  it("keeps a real disagreement between different sources a conflict and never reports multiple_sources", () => {
    const cases: [EvidenceV2Fact[], string[]][] = [
      // status and payload differ
      [[pendingPayment(6), { ...committedPayment(15), source: facilitatorSource } as EvidenceV2Fact], ["normalized_mismatch", "status_mismatch"]],
      // payload only
      [[pendingPayment(6), { ...pendingPayment(17), source: facilitatorSource,
        normalized: { ...pendingPayment().normalized, amountAtomic: "2000000" } } as EvidenceV2Fact], ["normalized_mismatch"]],
      // anchor only
      [[arcTxFact(8), { ...arcTxFact(18, "finalized", T2, OTHER_BLOCK_HASH), source: { ...chainSource, sourceId: "arc_rpc_backup" } } as EvidenceV2Fact],
        ["chain_anchor_mismatch"]],
      // reused evidence ID with different content
      [[pendingPayment(6, T1), { ...pendingPayment(6, T2), source: facilitatorSource } as EvidenceV2Fact], ["evidence_id_reused"]],
    ];
    for (const [facts, reasons] of cases) {
      for (const order of permutations(facts)) {
        const result = resolveEvidenceConflict(order);
        expect(result).toMatchObject({ outcome: "conflict", reasons });
        expect(result.outcome === "conflict" && result.reasons).not.toContain("multiple_sources");
        expect(result.outcome === "conflict" && result.facts).toHaveLength(2);
      }
    }
  });

  it("flags the same source reporting a different status as a conflict, never last-write-wins", () => {
    const pending = pendingPayment(6, T1);
    const committed = { ...committedPayment(15), observedAt: T2 };
    for (const order of [[pending, committed], [committed, pending]]) {
      const result = resolveEvidenceConflict(order);
      expect(result).toMatchObject({ outcome: "conflict", reasons: ["normalized_mismatch", "status_mismatch"], evidenceIds: [evd(6), evd(15)] });
      expect(result.outcome === "conflict" && result.facts.map((fact) => fact.evidenceId)).toEqual([evd(6), evd(15)]);
    }
  });

  it("flags a changed block anchor for the same transaction as a conflict", () => {
    const result = resolveEvidenceConflict([arcTxFact(8), arcTxFact(18, "finalized", T2, OTHER_BLOCK_HASH)]);
    expect(result).toMatchObject({ outcome: "conflict", reasons: ["chain_anchor_mismatch"] });
  });

  it("does not regress finality or lastObservedAt when observations arrive out of order", () => {
    const finalizedEarly = arcTxFact(8, "finalized", T1);
    const unfinalizedLate = arcTxFact(18, "unfinalized", T3);
    const unfinalizedEarlier = arcTxFact(28, "unfinalized", T2);
    for (const order of permutations([finalizedEarly, unfinalizedLate, unfinalizedEarlier])) {
      expect(resolveEvidenceConflict(order)).toMatchObject({ outcome: "resolved", status: "success", finality: "finalized",
        firstObservedAt: T1, lastObservedAt: T3 });
    }
    expect(resolveEvidenceConflict([unfinalizedLate, unfinalizedEarlier])).toMatchObject({ finality: "unfinalized" });
  });

  it("gives the same result for every input order of a conflicting set", () => {
    const facts = [pendingPayment(6, T1), { ...committedPayment(15), observedAt: T3 }, pendingPayment(26, T2)];
    const results = permutations(facts).map((order) => JSON.stringify(resolveEvidenceConflict(order)));
    expect(new Set(results).size).toBe(1);
  });

  it("treats a reused evidence ID with different content as a conflict", () => {
    const result = resolveEvidenceConflict([pendingPayment(6, T1), pendingPayment(6, T2)]);
    expect(result).toMatchObject({ outcome: "conflict", reasons: ["evidence_id_reused"], evidenceIds: [evd(6)] });
    expect(result.outcome === "conflict" && result.facts).toHaveLength(2);
  });

  it("throws on empty input, mixed subjects and mixed kinds", () => {
    expect(() => resolveEvidenceConflict([])).toThrow(EvidenceV2ConflictInputError);
    expect(() => resolveEvidenceConflict([jobStateFact(), jobRefundFact()])).toThrow(/mixed_kind/u);
    const other = { ...authorizationFact(31), subject: { kind: "action", canonicalId: ACTION.replace("6666-4666", "6666-4667") },
      scope: { ...authorizationFact().scope, actionId: ACTION.replace("6666-4666", "6666-4667") } } as EvidenceV2Fact;
    expect(() => resolveEvidenceConflict([authorizationFact(), other])).toThrow(/mixed_subject/u);
  });
});

// ───────────────────────── decision 8 ─────────────────────────

describe("evidence v2 versioning (decision 8)", () => {
  it("versions the module and leaves the legacy investigation rule-version allowlist unchanged", () => {
    expect(EVIDENCE_V2_SCHEMA_VERSION).toBe("openarc.evidence.v2");
    expect(EVIDENCE_V2_CONFLICT_RULE_VERSION).toBe("openarc.evidence.v2.conflict.v2");
    expect(EVIDENCE_V2_PAYMENT_CERTAINTY_RULE_VERSION).toBe("openarc.evidence.v2.payment-certainty.v1");
    for (const fact of ALL_FACTS) {
      expect(EvidenceV2FactSchema.safeParse({ ...clone(fact), schemaVersion: "openarc.evidence.v1" }).success).toBe(false);
    }
    const ruleVersion = (InvestigationReportSchema.shape.comparisons.element.shape.ruleVersion.unwrap()).options;
    expect([...ruleVersion]).toEqual(["openarc.reconcile.v1", "openarc.x402-reconciliation.m07.v1", "openarc.agent-policy-rules.v1"]);
  });
});
