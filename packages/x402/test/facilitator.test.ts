import { describe, expect, it } from "vitest";

import {
  X402LaneError,
  createLaneFacilitatorClient,
  persistLanePayment,
  type LaneFacilitatorConfig,
  type LaneFetch,
  type PersistedLanePayment,
} from "../src/index.js";
import {
  NOW,
  jsonResponse,
  mockFetch,
  persistOk,
  persistedProviderPayment,
  preparedBuyerPayment,
} from "./fixtures.js";

const TESTNET = "https://gateway-api-testnet.circle.com";
const neverCalled: LaneFetch = async () => {
  throw new Error("must not be called");
};

async function codeOf(fn: () => unknown): Promise<string> {
  try {
    await fn();
  } catch (error) {
    return error instanceof X402LaneError ? error.code : `non_lane_error:${String(error)}`;
  }
  return "no_throw";
}

function client(fetch: LaneFetch, timeoutMs = 1000) {
  return createLaneFacilitatorClient({ network: "eip155:5042002", facilitatorOrigin: TESTNET, fetch, timeoutMs });
}

describe("facilitator client configuration", () => {
  it("refuses any non-testnet network or origin", async () => {
    for (const network of ["eip155:1", "eip155:8453", "eip155:1243", "", undefined]) {
      expect(
        await codeOf(() =>
          createLaneFacilitatorClient({ network, facilitatorOrigin: TESTNET, fetch: neverCalled, timeoutMs: 1000 } as LaneFacilitatorConfig),
        ),
      ).toBe("unknown_network");
    }
    for (const facilitatorOrigin of [
      "https://gateway-api.circle.com",
      `${TESTNET}/`,
      `${TESTNET}/v1`,
      "http://gateway-api-testnet.circle.com",
      undefined,
    ]) {
      expect(
        await codeOf(() =>
          createLaneFacilitatorClient({
            network: "eip155:5042002",
            facilitatorOrigin,
            fetch: neverCalled,
            timeoutMs: 1000,
          } as LaneFacilitatorConfig),
        ),
      ).toBe("facilitator_origin_rejected");
    }
  });

  it("refuses fallback, multi-facilitator, recovery-hook, retry and header options", async () => {
    for (const key of ["fallbackScheme", "facilitators", "onSettleFailure", "onVerifyFailure", "retry", "retries", "headers", "url", "networks"]) {
      expect(
        await codeOf(() =>
          createLaneFacilitatorClient({
            network: "eip155:5042002",
            facilitatorOrigin: TESTNET,
            fetch: neverCalled,
            timeoutMs: 1000,
            [key]: key === "facilitators" ? [TESTNET, "https://gateway-api.circle.com"] : () => ({ recovered: true }),
          } as LaneFacilitatorConfig),
        ),
      ).toBe("invalid_config");
    }
    for (const timeoutMs of [0, -1, 1.5, 120_001]) {
      expect(await codeOf(() => client(neverCalled, timeoutMs))).toBe("invalid_config");
    }
    expect(
      await codeOf(() =>
        createLaneFacilitatorClient({ network: "eip155:5042002", facilitatorOrigin: TESTNET, timeoutMs: 1000 } as unknown as LaneFacilitatorConfig),
      ),
    ).toBe("invalid_config");
  });

  it("exposes no hook registration surface", () => {
    const facilitator = client(neverCalled);
    expect(Object.keys(facilitator).sort()).toEqual(
      ["checkSupported", "facilitatorOrigin", "lookupTransfers", "network", "resolveAttempt", "settle"].sort(),
    );
    expect(Object.isFrozen(facilitator)).toBe(true);
  });
});

describe("settle: one request, no retry, no fallback", () => {
  it("posts once to the pinned testnet settle URL and reports acceptance, not settlement", async () => {
    const { persisted } = await persistedProviderPayment();
    const { fetch, calls } = mockFetch(async () =>
      jsonResponse(200, {
        success: true,
        transaction: "3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b",
        network: "eip155:5042002",
        payer: persisted.binding.from,
      }),
    );
    const outcome = await client(fetch).settle(persisted);
    expect(outcome).toEqual({
      outcome: "accepted",
      transferId: "3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b",
      network: "eip155:5042002",
      payer: persisted.binding.from,
    });
    expect(calls).toHaveLength(1);
    const call = calls[0]!;
    expect(call.url).toBe(`${TESTNET}/v1/x402/settle`);
    expect(call.init.method).toBe("POST");
    expect(call.init.redirect).toBe("error");
    expect(call.init.credentials).toBe("omit");
    const body = JSON.parse(call.init.body!) as { paymentPayload: { accepted: unknown }; paymentRequirements: unknown };
    expect(body.paymentRequirements).toEqual(body.paymentPayload.accepted);
  });

  it.each([
    ["nonce_already_used", 200, { success: false, errorReason: "nonce_already_used", transaction: "", network: "eip155:5042002" }, "settle_error_reason", "nonce_already_used"],
    ["settlement_pending (core retry trigger)", 200, { success: false, errorReason: "settlement_pending", transaction: "3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b", network: "eip155:5042002" }, "settle_error_reason", "unrecognized"],
    ["insufficient_balance", 200, { success: false, errorReason: "insufficient_balance", transaction: "", network: "eip155:5042002" }, "settle_error_reason", "insufficient_balance"],
    ["500 unexpected_error", 500, { success: false, errorReason: "unexpected_error", transaction: "", network: "eip155:5042002" }, "settle_error_reason", "unexpected_error"],
    ["400 malformed", 400, { error: "bad" }, "unexpected_response", null],
    ["success without payer", 200, { success: true, transaction: "3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b", network: "eip155:5042002" }, "incomplete_acceptance", null],
    ["success with empty transaction", 200, { success: true, transaction: "", network: "eip155:5042002" }, "incomplete_acceptance", null],
    ["success on another network", 200, { success: true, transaction: "3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b", network: "eip155:8453", payer: "0x0000000000000000000000000000000000000001" }, "acceptance_mismatch", null],
  ])("classifies %s as unknown after exactly one request", async (_label, status, body, reason, errorReason) => {
    const { persisted } = await persistedProviderPayment();
    const { fetch, calls } = mockFetch(async () => jsonResponse(status, body));
    const outcome = await client(fetch).settle(persisted);
    expect(outcome).toEqual({ outcome: "unknown", reason, httpStatus: status, errorReason });
    expect(calls).toHaveLength(1);
  });

  it("classifies a payer mismatch, non-JSON, a throw and a timeout as unknown with one request each", async () => {
    const mismatch = await persistedProviderPayment();
    const m = mockFetch(async () =>
      jsonResponse(200, {
        success: true,
        transaction: "3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b",
        network: "eip155:5042002",
        payer: "0x1111111111111111111111111111111111111111",
      }),
    );
    expect(await client(m.fetch).settle(mismatch.persisted)).toMatchObject({ outcome: "unknown", reason: "acceptance_mismatch" });
    expect(m.calls).toHaveLength(1);

    const html = await persistedProviderPayment();
    const h = mockFetch(async () => ({ status: 502, text: async () => "<html>bad gateway</html>" }));
    expect(await client(h.fetch).settle(html.persisted)).toMatchObject({ outcome: "unknown", reason: "unexpected_response" });
    expect(h.calls).toHaveLength(1);

    const thrown = await persistedProviderPayment();
    const t = mockFetch(async () => {
      throw new TypeError("fetch failed");
    });
    expect(await client(t.fetch).settle(thrown.persisted)).toMatchObject({ outcome: "unknown", reason: "transport_error" });
    expect(t.calls).toHaveLength(1);

    const silent = await persistedProviderPayment();
    const s = mockFetch(() => new Promise(() => undefined));
    expect(await client(s.fetch, 25).settle(silent.persisted)).toMatchObject({ outcome: "unknown", reason: "timeout" });
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0]!.init.signal.aborted).toBe(true);
  });

  it("refuses a second settle, an unpersisted payment and a buyer payment without any request", async () => {
    const { persisted } = await persistedProviderPayment();
    const { fetch, calls } = mockFetch(async () => jsonResponse(500, { success: false, errorReason: "unexpected_error" }));
    const facilitator = client(fetch);
    await facilitator.settle(persisted);
    expect(await codeOf(() => facilitator.settle(persisted))).toBe("already_dispatched");
    expect(calls).toHaveLength(1);

    const buyer = await preparedBuyerPayment();
    expect(await codeOf(() => facilitator.settle(buyer.unpersisted as unknown as PersistedLanePayment))).toBe("not_persisted");
    const buyerPersisted = await persistLanePayment(buyer.unpersisted, persistOk);
    expect(await codeOf(() => facilitator.settle(buyerPersisted))).toBe("wrong_role");
    expect(calls).toHaveLength(1);
  });
});

describe("transfer lookup and supported check", () => {
  it("queries by from, nonce and network with one GET", async () => {
    const { persisted } = await persistedProviderPayment();
    const { fetch, calls } = mockFetch(async () => jsonResponse(200, { transfers: [] }));
    const lookup = await client(fetch).lookupTransfers(persisted.binding);
    expect(lookup).toEqual({ kind: "records", transfers: [], hasMorePages: false });
    expect(calls).toHaveLength(1);
    const url = new URL(calls[0]!.url);
    expect(url.origin).toBe(TESTNET);
    expect(url.pathname).toBe("/v1/x402/transfers");
    expect(Object.fromEntries(url.searchParams)).toEqual({
      from: persisted.binding.from,
      nonce: persisted.binding.nonce,
      network: "eip155:5042002",
    });
    expect(calls[0]!.init.method).toBe("GET");
    expect(calls[0]!.init.body).toBeUndefined();
  });

  it("reports malformed records and http errors without retrying", async () => {
    const { persisted } = await persistedProviderPayment();
    const bad = mockFetch(async () => jsonResponse(200, { transfers: [{ id: 1 }] }));
    expect(await client(bad.fetch).lookupTransfers(persisted.binding)).toEqual({ kind: "malformed" });
    expect(bad.calls).toHaveLength(1);
    const limited = mockFetch(async () => jsonResponse(429, { error: "rate limited" }));
    expect(await client(limited.fetch).lookupTransfers(persisted.binding)).toEqual({ kind: "http_error", status: 429 });
    expect(limited.calls).toHaveLength(1);
  });

  it("detects drift from the live supported advertisement with one GET", async () => {
    const kind = {
      x402Version: 2,
      scheme: "exact",
      network: "eip155:5042002",
      extra: {
        name: "GatewayWalletBatched",
        version: "1",
        verifyingContract: "0x0077777d7eba4688bdef3e311b846f25870a19b9",
        minValiditySeconds: 604800,
        assets: [{ symbol: "USDC", address: "0x3600000000000000000000000000000000000000", decimals: 6 }],
      },
    };
    const ok = mockFetch(async () => jsonResponse(200, { kinds: [kind, { ...kind, network: "eip155:84532" }], extensions: [] }));
    expect(await client(ok.fetch).checkSupported()).toEqual({ outcome: "matches" });
    expect(ok.calls).toHaveLength(1);
    expect(ok.calls[0]!.url).toBe(`${TESTNET}/v1/x402/supported`);

    const drift = mockFetch(async () =>
      jsonResponse(200, { kinds: [{ ...kind, extra: { ...kind.extra, minValiditySeconds: 259200, version: "2" } }] }),
    );
    expect(await client(drift.fetch).checkSupported()).toEqual({
      outcome: "drift",
      fields: ["extra.version", "extra.minValiditySeconds"],
    });
    expect(drift.calls).toHaveLength(1);
    void NOW;
  });
});
