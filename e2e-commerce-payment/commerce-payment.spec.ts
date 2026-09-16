import { expect, test } from "@playwright/test";

import { AgentApiClient, runBuyerFlow, createReuseHandle, type HarnessRunReport } from "../tools/agent-harness/src/index.js";
import {
  createFakeFacilitatorFetch,
  startFakeFacilitator,
  startReferenceProvider,
  type FakeFacilitator,
  type FakeFacilitatorBehaviour,
  type ReferenceProvider,
} from "../tools/x402-reference-provider/src/index.js";
import { COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION, type CommerceGrantProviderView } from "../packages/shared/src/index.js";

import { startApi, type ApiStack } from "./api-stack.js";
import {
  countAttempts,
  prepareDatabase,
  readAttemptRow,
  readGrantState,
  recordFixtureObservation,
  seedChain,
  seedFixtureGrantChain,
  type SeededChain,
} from "./fixture-db.js";

/**
 * PORT-04 P04-03 whole buyer flow, OFFLINE.
 *
 * WHAT IS REAL: the API process (its own shipped entry point, configuration
 * validator and restricted role connections), PostgreSQL migrated to the
 * current head, the schema15 payment stores, the commerce session, action,
 * grant and payment HTTP families, the `packages/x402` lane, the EIP-712
 * signature and the provider's claim of the buyer's grant.
 *
 * WHAT IS FAKE: the facilitator, which is a loopback test double injected
 * through the lane's transport seam. It settles nothing and proves no payment.
 *
 * WHAT NEVER HAPPENS: no funds, no live Circle, Gateway or Arc endpoint, no
 * network egress, no persistent key. Every key is generated in memory per run.
 */

const PAY_TO = "0xabcdefabcdefabcdefabcdefabcdefabcdef2222";
const OTHER_PAY_TO = "0xfedcbafedcbafedcbafedcbafedcbafedcba3333";
const AMOUNT = "1000000";

/** Everything any component emitted, plus the raw secrets, for the canary. */
const emitted: string[] = [];
const secrets: string[] = [];

let api: ApiStack;
const open: { provider: ReferenceProvider | undefined; facilitator: FakeFacilitator | undefined } = {
  provider: undefined,
  facilitator: undefined,
};

test.beforeAll(async () => {
  test.setTimeout(300_000);
  const schema = await prepareDatabase();
  // Migration 0015 owns the payment attempts this suite exercises. Later
  // migrations are additive, so require the head to be AT OR PAST 0015 rather
  // than pinning it: pinning breaks this suite every time a migration lands.
  expect(schema.applied).toBeGreaterThanOrEqual(15);
  const head = /^(\d{4})_/u.exec(schema.head);
  expect(head, `unexpected schema head ${schema.head}`).not.toBeNull();
  expect(Number.parseInt(head?.[1] ?? "0", 10)).toBeGreaterThanOrEqual(15);
  api = await startApi();
});

test.afterAll(async () => {
  emitted.push(api?.logs() ?? "");
  await api?.stop();
});

test.afterEach(async () => {
  await open.provider?.close();
  await open.facilitator?.close();
  open.provider = undefined;
  open.facilitator = undefined;
});

interface Stack {
  readonly chain: SeededChain;
  readonly provider: ReferenceProvider;
  readonly facilitator: FakeFacilitator;
}

async function stack(
  behaviour: FakeFacilitatorBehaviour,
  providerPayTo: string = PAY_TO,
): Promise<Stack> {
  const chain = await seedChain(PAY_TO);
  secrets.push(chain.commerceSessionToken, chain.providerSessionToken);
  const facilitator = await startFakeFacilitator(behaviour);
  const provider = await startReferenceProvider({
    apiBaseUrl: api.baseUrl,
    providerSessionToken: chain.providerSessionToken,
    payToAddress: providerPayTo,
    amountAtomic: AMOUNT,
    facilitator: createFakeFacilitatorFetch(facilitator.url),
    // Short enough that a hung fake times out well inside the test budget.
    facilitatorTimeoutMs: 1_500,
  });
  open.provider = provider;
  open.facilitator = facilitator;
  return { chain, provider, facilitator };
}

async function run(
  stackUnderTest: Stack,
  reuse?: ReturnType<typeof createReuseHandle>,
): Promise<{ report: HarnessRunReport; reuse: ReturnType<typeof createReuseHandle> | null }> {
  const result = await runBuyerFlow({
    apiBaseUrl: api.baseUrl,
    providerResourceUrl: stackUnderTest.provider.resourceUrl,
    facilitatorUrl: stackUnderTest.facilitator.url,
    commerceSessionToken: stackUnderTest.chain.commerceSessionToken,
    listingId: stackUnderTest.chain.seller.listingId,
    input: { a: 2, b: 3 },
    facilitatorTimeoutMs: 1_500,
    ...(reuse === undefined ? {} : { reuse }),
  });
  const serialized = JSON.stringify(result.report);
  emitted.push(serialized);
  // Non-secret evidence: the report is asserted secret-free before it is built.
  process.stdout.write(`[p0403-evidence] ${serialized}\n`);
  return result;
}

test("(a) happy path: 402, register, authorize, grant, persist, dispatch, settle, delivery", async () => {
  const under = await stack({ settle: "accept", lookup: "completed" });
  const { report, reuse } = await run(under);

  expect(report.outcome).toBe("delivered");
  expect(report.resource).toMatchObject({ delivered: true, providerHttpStatus: 200, providerStatus: "delivered" });
  expect(report.steps.map((entry) => entry.step)).toEqual([
    "config", "fetch_402", "register_requirement", "verify_requirement", "authorize_action",
    "issue_grant", "prepare_sign", "persist_attempt", "record_dispatch", "dispatch_send",
    "resolve_exposure", "read_attempt",
  ]);
  // Persisted before dispatch, dispatched exactly once, never re-signed.
  expect(report.lane).toMatchObject({
    persistedBeforeDispatch: true,
    dispatchRecorded: true,
    sends: 1,
    resigned: false,
    releasedUnsent: false,
    transport: "returned",
  });
  expect(under.facilitator.counts().settle).toBe(1);
  expect(under.provider.counts()).toMatchObject({ delivered: 1, claims: 1, settles: 1, held: 0 });

  // The lane classifies the fake's report; the DURABLE attempt stays held.
  expect(report.exposure).toMatchObject({ state: "committed", disposition: "committed" });
  expect(report.apiAttempt).toMatchObject({ state: "unknown", dispatched: true, observed: false });
  const attemptId = report.ids.attemptId as string;
  const row = await readAttemptRow(attemptId);
  expect(row).toMatchObject({ state: "unknown", dispatched: true, valueAtomic: AMOUNT });
  expect(row?.payToAddress.toLowerCase()).toBe(PAY_TO);

  // The grant really was claimed by the provider, and nothing released.
  const grant = await readGrantState(under.chain.buyer.organizationId, report.ids.grantId as string);
  expect(grant).toMatchObject({ status: "claimed", claimed: true, claims: 1, releasedEvents: 0 });
  // The reservation may advance held -> claimed (schema12 allows that ONLY
  // because the attempt was durably dispatched first). It is never released.
  expect(["held", "claimed"]).toContain(grant?.reservationStatus);

  // Recording what the fake reported is migrator-private (no route exists).
  // With that observation the agent read is `committed`, never "settled".
  const state = await recordFixtureObservation(
    under.chain.buyer.organizationId,
    attemptId,
    "committed",
    (report.exposure?.transferId ?? "") as string,
    "completed",
    `0x${"ab".repeat(32)}`,
  );
  expect(state).toBe("committed");
  const client = new AgentApiClient({
    apiBaseUrl: api.baseUrl,
    commerceSessionToken: under.chain.commerceSessionToken,
  });
  const read = await client.readAttempt(attemptId);
  expect(read.ok && read.data?.state).toBe("committed");
  expect(["persisted", "unknown", "pending", "committed"]).toContain(read.ok ? read.data?.state : "");
  expect(reuse).not.toBeNull();
});

test("(b) facilitator timeout: unknown and held, one dispatch, no delivery", async () => {
  const under = await stack({ settle: "timeout", lookup: "empty" });
  const { report } = await run(under);

  expect(report.outcome).toBe("held");
  expect(report.resource.delivered).toBe(false);
  expect(report.resource.providerStatus).toBe("held");
  expect(report.lane).toMatchObject({ sends: 1, dispatchRecorded: true, resigned: false });
  expect(report.exposure).toMatchObject({ state: "unknown", disposition: "held" });
  expect(report.apiAttempt).toMatchObject({ state: "unknown", dispatched: true, observed: false });

  // Exactly one settle reached the fake and nothing retried it.
  expect(under.facilitator.counts().settle).toBe(1);
  expect(under.provider.counts()).toMatchObject({ delivered: 0, held: 1, settles: 1 });

  // A second dispatch of the same attempt is a non-retryable conflict.
  const client = new AgentApiClient({
    apiBaseUrl: api.baseUrl,
    commerceSessionToken: under.chain.commerceSessionToken,
  });
  const second = await client.recordDispatch(
    report.ids.attemptId as string,
    report.payment?.bindingDigest as string,
  );
  expect(second.ok).toBe(false);
  expect(second.ok ? null : second.httpStatus).toBe(409);
  expect(under.facilitator.counts().settle).toBe(1);

  // Exposure is never released: no release event and no released reservation.
  const grant = await readGrantState(under.chain.buyer.organizationId, report.ids.grantId as string);
  expect(["held", "claimed"]).toContain(grant?.reservationStatus);
  expect(grant?.releasedEvents).toBe(0);
  expect(await countAttempts(under.chain.buyer.organizationId)).toBe(1);
});

for (const [label, behaviour] of [
  ["nonce_already_used", { settle: "nonce_already_used", lookup: "empty" }],
  ["a 500", { settle: "http_500", lookup: "empty" }],
] as const) {
  test(`(c) ${label} from the fake: unknown and held, no retry, no delivery`, async () => {
    const under = await stack(behaviour as FakeFacilitatorBehaviour);
    const { report } = await run(under);

    expect(report.outcome).toBe("held");
    expect(report.resource.delivered).toBe(false);
    expect(report.exposure).toMatchObject({ state: "unknown", disposition: "held" });
    expect(report.apiAttempt).toMatchObject({ state: "unknown", dispatched: true });
    expect(report.lane.sends).toBe(1);
    // One settle, one send, no re-sign and no second attempt.
    expect(under.facilitator.counts().settle).toBe(1);
    expect(under.provider.counts()).toMatchObject({ delivered: 0, held: 1 });
    expect(await countAttempts(under.chain.buyer.organizationId)).toBe(1);
    const grant = await readGrantState(under.chain.buyer.organizationId, report.ids.grantId as string);
    expect(["held", "claimed"]).toContain(grant?.reservationStatus);
    expect(grant?.releasedEvents).toBe(0);
  });
}

test("(d) a provider advertising the wrong pay-to is refused with zero attempts", async () => {
  const under = await stack({ settle: "accept", lookup: "completed" }, OTHER_PAY_TO);
  const { report } = await run(under);

  expect(report.outcome).toBe("refused");
  expect(report.refusal).toMatchObject({ stage: "verify_requirement", code: "requirement_mismatch" });
  // Refused before any key, signature, attempt or send exists.
  expect(report.payment).toBeNull();
  expect(report.ids.attemptId).toBeNull();
  expect(report.lane.sends).toBe(0);
  expect(await countAttempts(under.chain.buyer.organizationId)).toBe(0);
  expect(under.provider.counts()).toMatchObject({ paidRequests: 0, claims: 0, settles: 0 });
  expect(under.facilitator.counts().settle).toBe(0);
});

test("(e) internal_fixture provenance is refused, with zero attempts", async () => {
  const under = await stack({ settle: "accept", lookup: "completed" });
  const fixtureChain = await seedFixtureGrantChain(under.chain, AMOUNT);
  secrets.push(fixtureChain.grantToken);

  // The production authorize route refuses fixture provenance outright.
  const client = new AgentApiClient({
    apiBaseUrl: api.baseUrl,
    commerceSessionToken: under.chain.commerceSessionToken,
  });
  const authorized = await client.authorizeAction(
    `openarc:action:${crypto.randomUUID()}`,
    fixtureChain.requirementId,
  );
  expect(authorized.ok).toBe(false);
  expect(authorized.ok ? null : authorized.httpStatus).toBe(503);

  // Even a fixture grant built through the migrator-private cores can never
  // gain a durable attempt through the payment route.
  const grantView: CommerceGrantProviderView = {
    schemaVersion: COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION,
    grantId: fixtureChain.grantId,
    actionId: fixtureChain.actionId,
    providerId: under.chain.seller.providerId,
    listingId: under.chain.seller.listingId,
    listingVersion: "1",
    requirementId: fixtureChain.requirementId,
    requirementDigest: fixtureChain.requirementDigest,
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    amountAtomic: AMOUNT,
    feeAtomic: "0",
    debitAtomic: AMOUNT,
    expiresAt: fixtureChain.expiresAt,
    status: "issued",
    claimedAttemptId: null,
  } as CommerceGrantProviderView;
  const handle = createReuseHandle({
    grant: grantView,
    grantToken: fixtureChain.grantToken,
    payToAddress: PAY_TO,
  });
  const { report } = await run(under, handle);

  expect(report.outcome).toBe("refused");
  expect(report.refusal?.stage).toBe("persist_attempt");
  expect(report.lane.sends).toBe(0);
  // Never sent, so the lane's one release applies.
  expect(report.lane.releasedUnsent).toBe(true);
  expect(await countAttempts(under.chain.buyer.organizationId)).toBe(0);
  expect(under.provider.counts()).toMatchObject({ paidRequests: 0, settles: 0 });
  expect(under.facilitator.counts().settle).toBe(0);
});

test("(f) a second run on the same grant is refused with no second dispatch", async () => {
  const under = await stack({ settle: "accept", lookup: "completed" });
  const first = await run(under);
  expect(first.report.outcome).toBe("delivered");
  expect(first.reuse).not.toBeNull();

  const second = await run(under, first.reuse as ReturnType<typeof createReuseHandle>);
  expect(second.report.outcome).toBe("refused");
  expect(second.report.refusal?.stage).toBe("persist_attempt");
  expect(second.report.lane.sends).toBe(0);
  expect(second.report.lane.releasedUnsent).toBe(true);

  // Exactly one attempt, one paid request, one claim and one settle in total.
  expect(await countAttempts(under.chain.buyer.organizationId)).toBe(1);
  expect(under.provider.counts()).toMatchObject({ paidRequests: 1, claims: 1, settles: 1, delivered: 1 });
  expect(under.facilitator.counts().settle).toBe(1);
});

test("(g) the harness refuses a non-loopback facilitator and the live stub exits non-zero", async () => {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const { resolve, dirname } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const { existsSync } = await import("node:fs");
  const run = promisify(execFile);
  const cli = resolve(dirname(fileURLToPath(import.meta.url)), "../tools/agent-harness/dist/cli.js");
  expect(existsSync(cli)).toBe(true);

  const nonLoopback = await run(
    process.execPath,
    [cli, "--api", "http://127.0.0.1:1", "--provider", "http://127.0.0.1:1/v1/sum",
      "--facilitator", "https://gateway-api-testnet.circle.com",
      "--listing", "openarc:listing:12345678-1234-4234-8123-123456789abc", "--a", "2", "--b", "3"],
    { env: { PATH: process.env["PATH"] ?? "", OPENARC_COMMERCE_SESSION_TOKEN: `oacs_v1_${"C".repeat(42)}Q` } },
  ).catch((error: { code?: number; stdout?: string }) => error);
  const refusal = JSON.parse(((nonLoopback as { stdout?: string }).stdout ?? "").trim()) as {
    outcome: string;
    refusal: { code: string; apiCode: string };
  };
  expect((nonLoopback as { code?: number }).code).toBe(64);
  expect(refusal.outcome).toBe("refused");
  expect(refusal.refusal).toMatchObject({ code: "non_loopback_url", apiCode: "facilitatorUrl" });
  emitted.push(JSON.stringify(refusal));

  const live = await run(process.execPath, [cli, "--live-testnet"], {
    env: { PATH: process.env["PATH"] ?? "" },
  }).catch((error: { code?: number; stdout?: string }) => error);
  const liveOut = (live as { stdout?: string }).stdout ?? "";
  expect((live as { code?: number }).code).toBeGreaterThan(0);
  expect(liveOut).toContain("NOT implemented");
  expect(liveOut).toContain("P04-07 prerequisites");
  expect(liveOut).toContain("DISPOSABLE buyer wallet");
  expect(liveOut).toContain("faucet");
  expect(liveOut).toMatch(/approve/u);
  expect(liveOut).toMatch(/deposit/u);
  emitted.push(liveOut);
});

test("canary: no key, signature or credential appears in any report, response or log", async () => {
  // Self-contained: this scenario performs its own complete delivered run, so
  // the canary never depends on state from another test.
  const under = await stack({ settle: "accept", lookup: "completed" });
  const { report } = await run(under);
  expect(report.outcome).toBe("delivered");

  const everything = [...emitted, api.logs()].join("\n");
  expect(everything.length).toBeGreaterThan(0);
  expect(secrets.length).toBeGreaterThanOrEqual(2);
  for (const secret of secrets) {
    expect(secret.length).toBeGreaterThan(20);
    expect(everything).not.toContain(secret);
  }
  for (const namespace of ["oacs_v1_", "oag_v1_", "oach_v1_", "oas_ag_", "oas_pr_"]) {
    expect(everything).not.toContain(namespace);
  }
  // A 65-byte EIP-712 signature and a 32-byte private key are both impossible.
  expect(everything).not.toMatch(/0x[0-9a-fA-F]{130}/u);
  expect(everything).not.toMatch(/"privateKey"|BEGIN [A-Z ]*PRIVATE KEY/u);
});
