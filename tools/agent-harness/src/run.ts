/**
 * The headless buyer agent.
 *
 * One pass of the whole lane against a LOCAL stack, using an `oacs_v1_`
 * commerce session:
 *
 *   402 → register the verified requirement → authorize the action → issue the
 *   grant → prepare and sign with an EPHEMERAL in-memory key → persist the
 *   attempt → record the one dispatch → send EXACTLY ONCE → resolve the lane's
 *   exposure → read the durable attempt back.
 *
 * LANE RULES, ENFORCED HERE AND BY `packages/x402`:
 *   * the attempt is durable BEFORE any signature may leave the process, and
 *     the dispatch is recorded before the send;
 *   * the send happens at most once. The lane refuses a second dispatch of the
 *     same handle, and this harness never re-signs, re-sends or retries;
 *   * any unclear outcome — a timeout, a transport failure, an unreadable
 *     answer, an unknown settlement — is UNKNOWN and HELD, never a failure and
 *     never a release;
 *   * the ONLY release is a payment that provably never reached a transport,
 *     which is exactly the pre-dispatch refusal path.
 *
 * The key exists only in this function's scope for the life of the run: it is
 * never returned, persisted, logged or placed in the report.
 */
import {
  COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION,
  CommerceGrantProviderViewSchema,
  type CommerceGrantProviderView,
} from "@openarc/shared";
import {
  LANE_PAYMENT_HEADER,
  createLaneFacilitatorClient,
  ARC_TESTNET_LANE,
  dispatchLanePayment,
  parseLanePaymentRequired,
  persistLanePayment,
  prepareLanePayment,
  releaseUnsentLanePayment,
  type LaneExposure,
  type LanePaymentBinding,
  type LanePaymentRequired,
} from "@openarc/x402";
import { randomBytes, randomUUID } from "node:crypto";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import { AgentApiClient } from "./api-client.js";
import { createLoopbackFacilitatorFetch } from "./facilitator-fetch.js";
import { sendHeadlessRequest } from "./http.js";
import { HarnessRefusal, assertLoopbackOrigin, assertLoopbackUrl } from "./loopback.js";
import {
  HARNESS_REPORT_SCHEMA,
  assertSecretFree,
  type HarnessRefusalReport,
  type HarnessRunReport,
  type HarnessStep,
} from "./report.js";

const LISTING_ID =
  /^openarc:listing:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/u;
const MAX_OPERAND = 1_000_000;

/**
 * An opaque carrier for a grant a LATER run may present. The raw grant token is
 * held outside the object, so the handle can be serialized or logged safely.
 */
export interface ReuseHandle {
  readonly kind: "openarc.agent-harness.reuse.v1";
  readonly grantId: string;
  readonly actionId: string;
  readonly requirementId: string;
  readonly payToAddress: string;
  readonly amountAtomic: string;
}

interface ReuseSecret {
  readonly grantToken: string;
  readonly grant: CommerceGrantProviderView;
}

const reuseSecrets = new WeakMap<ReuseHandle, ReuseSecret>();

export function createReuseHandle(input: {
  readonly grant: CommerceGrantProviderView;
  readonly grantToken: string;
  readonly payToAddress: string;
}): ReuseHandle {
  const grant = CommerceGrantProviderViewSchema.parse(input.grant);
  const handle: ReuseHandle = Object.freeze({
    kind: "openarc.agent-harness.reuse.v1",
    grantId: grant.grantId,
    actionId: grant.actionId,
    requirementId: grant.requirementId,
    payToAddress: input.payToAddress,
    amountAtomic: grant.amountAtomic,
  });
  reuseSecrets.set(handle, { grantToken: input.grantToken, grant });
  return handle;
}

export interface HarnessRunOptions {
  readonly apiBaseUrl: string;
  readonly providerResourceUrl: string;
  readonly facilitatorUrl: string;
  /** Optional; when given it must also be loopback. Unused in offline mode. */
  readonly rpcUrl?: string;
  readonly commerceSessionToken: string;
  readonly listingId: string;
  readonly input: { readonly a: number; readonly b: number };
  /** Present a grant a previous run obtained, instead of issuing a new one. */
  readonly reuse?: ReuseHandle;
  readonly timeoutMs?: number;
  readonly facilitatorTimeoutMs?: number;
  readonly nowUnixSeconds?: () => number;
}

export interface HarnessRunResult {
  readonly report: HarnessRunReport;
  /** Present only when this run issued its own grant. Never serialized. */
  readonly reuse: ReuseHandle | null;
}

interface Mutable {
  requirementId: string | null;
  actionId: string | null;
  grantId: string | null;
  attemptId: string | null;
  payment: HarnessRunReport["payment"];
  persistedBeforeDispatch: boolean;
  dispatchRecorded: boolean;
  sends: 0 | 1;
  releasedUnsent: boolean;
  transport: "returned" | "threw" | "not_sent";
  delivered: boolean;
  providerHttpStatus: number | null;
  providerStatus: string | null;
  exposure: HarnessRunReport["exposure"];
  apiAttempt: HarnessRunReport["apiAttempt"];
}

function freshState(): Mutable {
  return {
    requirementId: null,
    actionId: null,
    grantId: null,
    attemptId: null,
    payment: null,
    persistedBeforeDispatch: false,
    dispatchRecorded: false,
    sends: 0,
    releasedUnsent: false,
    transport: "not_sent",
    delivered: false,
    providerHttpStatus: null,
    providerStatus: null,
    exposure: null,
    apiAttempt: null,
  };
}

function exposureOf(exposure: LaneExposure): HarnessRunReport["exposure"] {
  return {
    state: exposure.state,
    disposition: exposure.disposition,
    reason: exposure.state === "unknown" ? exposure.reason : null,
    gatewayStatus: exposure.state === "unknown" ? null : exposure.gatewayStatus,
    transferId: exposure.state === "unknown" ? null : exposure.transferId,
  };
}

export async function runBuyerFlow(options: HarnessRunOptions): Promise<HarnessRunResult> {
  const steps: HarnessStep[] = [];
  const state = freshState();
  const heldSecrets: string[] = [];
  let refusal: HarnessRefusalReport | null = null;

  const step = (name: string, ok: boolean, httpStatus: number | null, code: string | null): void => {
    steps.push({ step: name, ok, httpStatus, code });
  };
  const refuse = (
    stage: string,
    code: string,
    httpStatus: number | null = null,
    apiCode: string | null = null,
  ): HarnessRunResult => {
    refusal = { stage, code, httpStatus, apiCode };
    step(stage, false, httpStatus, apiCode ?? code);
    return finish("refused");
  };
  const finish = (outcome: HarnessRunReport["outcome"]): HarnessRunResult => {
    const report: HarnessRunReport = {
      schemaVersion: HARNESS_REPORT_SCHEMA,
      mode: "offline_fake",
      outcome,
      refusal,
      steps: Object.freeze([...steps]),
      ids: {
        requirementId: state.requirementId,
        actionId: state.actionId,
        grantId: state.grantId,
        attemptId: state.attemptId,
      },
      payment: state.payment,
      lane: {
        persistedBeforeDispatch: state.persistedBeforeDispatch,
        dispatchRecorded: state.dispatchRecorded,
        sends: state.sends,
        resigned: false,
        releasedUnsent: state.releasedUnsent,
        transport: state.transport,
      },
      resource: {
        delivered: state.delivered,
        providerHttpStatus: state.providerHttpStatus,
        providerStatus: state.providerStatus,
      },
      exposure: state.exposure,
      apiAttempt: state.apiAttempt,
    };
    assertSecretFree(report, heldSecrets);
    return { report, reuse: issuedReuse };
  };

  let issuedReuse: ReuseHandle | null = null;

  /* ---- configuration: loopback only, before any key or request ---------- */
  let apiBaseUrl: string;
  let resourceUrl: string;
  let facilitatorUrl: string;
  try {
    apiBaseUrl = assertLoopbackOrigin(options.apiBaseUrl, "apiBaseUrl");
    resourceUrl = assertLoopbackUrl(options.providerResourceUrl, "providerResourceUrl");
    facilitatorUrl = assertLoopbackOrigin(options.facilitatorUrl, "facilitatorUrl");
    if (options.rpcUrl !== undefined) assertLoopbackOrigin(options.rpcUrl, "rpcUrl");
    if (!LISTING_ID.test(options.listingId)) {
      throw new HarnessRefusal("listing_id_invalid", "listingId");
    }
    for (const operand of [options.input.a, options.input.b]) {
      if (!Number.isInteger(operand) || operand < 0 || operand > MAX_OPERAND) {
        throw new HarnessRefusal("input_invalid", "input");
      }
    }
  } catch (error) {
    const known = error instanceof HarnessRefusal;
    return refuse("config", known ? error.code : "url_unparseable", null, known ? error.field : null);
  }
  heldSecrets.push(options.commerceSessionToken);

  let api: AgentApiClient;
  try {
    api = new AgentApiClient({ apiBaseUrl, commerceSessionToken: options.commerceSessionToken });
  } catch {
    return refuse("config", "commerce_token_invalid");
  }
  step("config", true, null, null);

  const now = options.nowUnixSeconds ?? (() => Math.floor(Date.now() / 1000));
  let reuse: ReuseSecret | null = null;
  if (options.reuse !== undefined) {
    const known = reuseSecrets.get(options.reuse);
    // Only a handle this module minted carries a grant; a forged one is refused.
    if (known === undefined) return refuse("config", "reuse_handle_unrecognised");
    reuse = known;
  }

  /* ---- 1. the provider's 402 -------------------------------------------- */
  let paymentRequired: LanePaymentRequired;
  try {
    const response = await sendHeadlessRequest({
      url: resourceUrl,
      method: "GET",
      headers: { accept: "application/json" },
      timeoutMs: options.timeoutMs ?? 15_000,
    });
    if (response.status !== 402) {
      return refuse("fetch_402", "not_payment_required", response.status);
    }
    paymentRequired = parseLanePaymentRequired(JSON.parse(response.text));
    step("fetch_402", true, 402, null);
  } catch {
    return refuse("fetch_402", "invalid_payment_required");
  }
  if (paymentRequired.resource.url !== resourceUrl) {
    return refuse("fetch_402", "resource_url_mismatch");
  }

  /* ---- 2. register the verified requirement (server-derived terms) ------ */
  let expectedPayTo: string;
  let grantView: CommerceGrantProviderView;
  let grantToken: string;

  if (reuse === null) {
    const requirementId = `openarc:requirement:${randomUUID()}`;
    const registered = await api.registerRequirement(requirementId, options.listingId);
    if (!registered.ok) {
      return refuse("register_requirement", "register_refused", registered.httpStatus, registered.code);
    }
    state.requirementId = requirementId;
    step("register_requirement", true, registered.httpStatus, null);
    expectedPayTo = registered.data.payToAddress;

    /* ---- 3. the 402 must describe the SELLER's recorded terms ----------- */
    if (
      paymentRequired.requirement.payTo.toLowerCase() !== expectedPayTo ||
      paymentRequired.requirement.amount !== registered.data.amountAtomic ||
      paymentRequired.requirement.network !== registered.data.networkId
    ) {
      // A misconfigured provider is refused BEFORE any key, signature or
      // attempt exists. Nothing is persisted and nothing is dispatched.
      return refuse("verify_requirement", "requirement_mismatch");
    }
    step("verify_requirement", true, null, null);

    /* ---- 4. authorize the action --------------------------------------- */
    const actionId = `openarc:action:${randomUUID()}`;
    const authorized = await api.authorizeAction(actionId, requirementId);
    if (!authorized.ok) {
      return refuse("authorize_action", "authorize_refused", authorized.httpStatus, authorized.code);
    }
    state.actionId = actionId;
    if (authorized.data.metadata.status !== "reserved_not_granted") {
      return refuse("authorize_action", `action_${authorized.data.metadata.status}`, authorized.httpStatus);
    }
    step("authorize_action", true, authorized.httpStatus, null);

    /* ---- 5. issue the grant -------------------------------------------- */
    const issued = await api.issueGrant(actionId);
    if (!issued.ok) {
      return refuse("issue_grant", "issue_refused", issued.httpStatus, issued.code);
    }
    if (issued.data.replayed) {
      return refuse("issue_grant", "grant_replayed_without_token", issued.httpStatus);
    }
    grantToken = issued.data.grantToken;
    heldSecrets.push(grantToken);
    state.grantId = issued.data.metadata.grantId;
    step("issue_grant", true, issued.httpStatus, null);

    const action = authorized.data.metadata;
    const composed = CommerceGrantProviderViewSchema.safeParse({
      schemaVersion: COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION,
      grantId: issued.data.metadata.grantId,
      actionId: action.actionId,
      providerId: action.providerId,
      listingId: action.listingId,
      listingVersion: action.listingVersion,
      requirementId: action.requirementId,
      requirementDigest: action.requirementDigest,
      networkId: registered.data.networkId,
      asset: registered.data.asset,
      representation: registered.data.representation,
      decimals: registered.data.decimals,
      amountAtomic: action.amountAtomic,
      feeAtomic: action.feeAtomic,
      debitAtomic: action.debitAtomic,
      expiresAt: issued.data.metadata.expiresAt,
      status: issued.data.metadata.status,
      claimedAttemptId: null,
    });
    if (!composed.success) return refuse("issue_grant", "grant_view_invalid");
    grantView = composed.data;
    issuedReuse = createReuseHandle({
      grant: grantView,
      grantToken,
      payToAddress: expectedPayTo,
    });
  } else {
    grantToken = reuse.grantToken;
    heldSecrets.push(grantToken);
    grantView = reuse.grant;
    expectedPayTo = options.reuse?.payToAddress ?? "";
    state.requirementId = grantView.requirementId;
    state.actionId = grantView.actionId;
    state.grantId = grantView.grantId;
    if (paymentRequired.requirement.payTo.toLowerCase() !== expectedPayTo) {
      return refuse("verify_requirement", "requirement_mismatch");
    }
    step("reuse_grant", true, null, null);
  }

  /* ---- 6. prepare and sign with an EPHEMERAL in-memory key -------------- */
  const attemptId = randomUUID();
  state.attemptId = attemptId;
  // Generated here, used here, never written anywhere and dropped with the run.
  const signer = privateKeyToAccount(generatePrivateKey());
  const nonce = `0x${randomBytes(32).toString("hex")}`;
  let unpersisted;
  try {
    unpersisted = await prepareLanePayment({
      paymentRequired,
      grant: grantView,
      attemptId,
      signer,
      nonce,
      nowUnixSeconds: now(),
    });
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    return refuse("prepare_sign", typeof code === "string" ? code : "prepare_failed");
  }
  const binding: LanePaymentBinding = unpersisted.binding;
  state.payment = {
    network: binding.network,
    payerAddress: binding.from,
    payToAddress: binding.to,
    amountAtomic: binding.value,
    bindingDigest: unpersisted.bindingDigest,
    laneRequirementDigest: binding.laneRequirementDigest,
  };
  step("prepare_sign", true, null, null);

  /* ---- 7. persist BEFORE the signature may leave ------------------------ */
  let persistFailure: { httpStatus: number | null; code: string } | null = null;
  let persisted;
  try {
    persisted = await persistLanePayment(unpersisted, async (record) => {
      const result = await api.persistAttempt({
        grantId: binding.grantId,
        actionId: binding.actionId,
        attemptId: binding.attemptId,
        laneRequirementDigest: binding.laneRequirementDigest,
        from: binding.from,
        to: binding.to,
        validAfter: binding.validAfter,
        validBefore: binding.validBefore,
        nonce: binding.nonce,
        bindingDigest: record.bindingDigest,
      });
      if (!result.ok) {
        persistFailure = { httpStatus: result.httpStatus, code: result.code };
        throw new Error("PERSIST_REFUSED");
      }
      return { bindingDigest: result.data.attempt.bindingDigest };
    });
  } catch {
    // Never persisted, so it provably never reached a transport: this is the
    // lane's ONE release, and it is safe precisely because nothing was sent.
    try {
      releaseUnsentLanePayment(unpersisted);
      state.releasedUnsent = true;
    } catch {
      state.releasedUnsent = false;
    }
    const failure = persistFailure as { httpStatus: number | null; code: string } | null;
    return refuse("persist_attempt", "persist_refused", failure?.httpStatus ?? null, failure?.code ?? null);
  }
  state.persistedBeforeDispatch = true;
  step("persist_attempt", true, 200, null);

  /* ---- 8. record the ONE dispatch before sending ------------------------ */
  const recorded = await api.recordDispatch(attemptId, persisted.bindingDigest);
  if (!recorded.ok) {
    // A refused or unclear dispatch record means DO NOT SEND. The attempt stays
    // exactly as durable as it was, and its exposure stays held.
    return refuse("record_dispatch", "dispatch_not_recorded", recorded.httpStatus, recorded.code);
  }
  if (recorded.data.state !== "unknown") {
    return refuse("record_dispatch", "dispatch_state_unexpected", recorded.httpStatus);
  }
  state.dispatchRecorded = true;
  step("record_dispatch", true, recorded.httpStatus, null);

  /* ---- 9. send EXACTLY ONCE: the paid retry of the resource ------------- */
  const dispatched = await dispatchLanePayment(
    persisted,
    async (request) => {
      state.sends = 1;
      const response = await sendHeadlessRequest({
        url: resourceUrl,
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          [request.headerName]: request.headerValue,
        },
        body: JSON.stringify({
          grantToken,
          actionId: binding.actionId,
          attemptId,
          input: options.input,
        }),
        timeoutMs: options.timeoutMs ?? 15_000,
      });
      const body = JSON.parse(response.text) as Record<string, unknown>;
      return { status: response.status, body };
    },
    now(),
  );

  if (dispatched.transport.outcome === "returned") {
    state.transport = "returned";
    const response = dispatched.transport.response as { status?: unknown; body?: unknown };
    state.providerHttpStatus = typeof response.status === "number" ? response.status : null;
    const body = response.body;
    if (typeof body === "object" && body !== null) {
      const status = (body as { status?: unknown }).status;
      state.providerStatus = typeof status === "string" ? status : null;
      const result = (body as { result?: unknown }).result;
      state.delivered =
        state.providerHttpStatus === 200 &&
        state.providerStatus === "delivered" &&
        typeof result === "object" &&
        result !== null &&
        typeof (result as { sum?: unknown }).sum === "number";
    }
  } else {
    // A throwing transport is still POSSIBLY EXPOSED. Never re-sent.
    state.transport = "threw";
  }
  step("dispatch_send", true, state.providerHttpStatus, state.providerStatus);

  /* ---- 10. classify the exposure through the facilitator (read only) ---- */
  try {
    const facilitator = createLaneFacilitatorClient({
      network: ARC_TESTNET_LANE.caip2,
      facilitatorOrigin: ARC_TESTNET_LANE.facilitatorOrigin,
      fetch: createLoopbackFacilitatorFetch(facilitatorUrl),
      timeoutMs: options.facilitatorTimeoutMs ?? 2_000,
    });
    const exposure = await facilitator.resolveAttempt(binding, { nowUnixSeconds: now() });
    state.exposure = exposureOf(exposure);
    step("resolve_exposure", true, null, exposure.state);
  } catch {
    // An unreadable resolution is unknown and held; it never releases.
    state.exposure = {
      state: "unknown",
      disposition: "held",
      reason: "transport_error",
      gatewayStatus: null,
      transferId: null,
    };
    step("resolve_exposure", false, null, "transport_error");
  }

  /* ---- 11. read the durable attempt back -------------------------------- */
  const read = await api.readAttempt(attemptId);
  if (read.ok && read.data !== null) {
    state.apiAttempt = {
      state: read.data.state,
      dispatched: read.data.dispatchedAt !== null,
      observed: read.data.observedAt !== null,
    };
    step("read_attempt", true, read.httpStatus, read.data.state);
  } else {
    step("read_attempt", false, read.ok ? read.httpStatus : read.httpStatus, read.ok ? "missing" : read.code);
  }

  return finish(state.delivered ? "delivered" : "held");
}

export { LANE_PAYMENT_HEADER };
