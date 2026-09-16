import { inspect } from "node:util";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  X402LaneError,
  acceptReceivedLanePayment,
  createLaneFacilitatorClient,
  dispatchLanePayment,
  parseLanePaymentRequired,
  persistLanePayment,
} from "../src/index.js";
import {
  ATTEMPT_ID,
  NOW,
  capturedBuyerHeader,
  claimedGrantView,
  jsonResponse,
  mockFetch,
  persistOk,
  persistedProviderPayment,
  preparedBuyerPayment,
} from "./fixtures.js";

const methods = ["log", "info", "warn", "error", "debug", "trace"] as const;

describe("no secret or signature is logged or exposed", () => {
  let spies: ReturnType<typeof vi.spyOn>[] = [];
  let stdout: ReturnType<typeof vi.spyOn>;
  let stderr: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    spies = methods.map((method) => vi.spyOn(console, method).mockImplementation(() => undefined));
    stdout = vi.spyOn(process.stdout, "write");
    stderr = vi.spyOn(process.stderr, "write");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("runs buyer, provider, settle, lookup and every failure path without writing anything", async () => {
    const { persisted, header, buyerKey, signature } = await persistedProviderPayment();
    const secretFragments = [buyerKey.slice(2), signature.slice(2)];

    const failures: unknown[] = [];
    const capture = async (fn: () => Promise<unknown>) => {
      try {
        return await fn();
      } catch (error) {
        failures.push(error);
        return undefined;
      }
    };

    const { fetch } = mockFetch(async (url) =>
      url.includes("/settle")
        ? jsonResponse(200, { success: false, errorReason: "nonce_already_used", transaction: "", network: "eip155:5042002" })
        : jsonResponse(200, { transfers: [] }),
    );
    const facilitator = createLaneFacilitatorClient({
      network: "eip155:5042002",
      facilitatorOrigin: "https://gateway-api-testnet.circle.com",
      fetch,
      timeoutMs: 1000,
    });
    const settle = await facilitator.settle(persisted);
    const exposure = await facilitator.resolveAttempt(persisted.binding, { nowUnixSeconds: NOW, settle });
    await capture(() => facilitator.settle(persisted));

    const buyer = await preparedBuyerPayment();
    await capture(() => persistLanePayment(buyer.unpersisted, async () => { throw new Error("db down"); }));
    const buyerPersisted = await persistLanePayment(buyer.unpersisted, persistOk);
    const dispatched = await dispatchLanePayment(buyerPersisted, async () => { throw new Error("socket"); }, NOW);
    await capture(() => dispatchLanePayment(buyerPersisted, async () => undefined, NOW));

    const buyerSide = await capturedBuyerHeader();
    const tampered = JSON.parse(Buffer.from(buyerSide.header, "base64").toString("utf8")) as {
      payload: { authorization: { value: string } };
    };
    tampered.payload.authorization.value = "99";
    await capture(() =>
      acceptReceivedLanePayment({
        header: Buffer.from(JSON.stringify(tampered)).toString("base64"),
        paymentRequired: buyerSide.paymentRequired,
        grant: claimedGrantView(),
        attemptId: ATTEMPT_ID,
        nowUnixSeconds: NOW + 10,
      }),
    );
    await capture(async () => parseLanePaymentRequired({ x402Version: 2, secret: buyerKey }));

    for (const spy of [...spies, stdout, stderr]) {
      expect(spy).not.toHaveBeenCalled();
    }

    expect(failures.length).toBeGreaterThanOrEqual(4);
    const surfaces = [
      inspect(persisted, { depth: 10, showHidden: true }),
      JSON.stringify(persisted),
      inspect(buyer.unpersisted, { depth: 10, showHidden: true }),
      JSON.stringify(dispatched),
      JSON.stringify(settle),
      JSON.stringify(exposure),
      ...failures.map((error) => `${String(error)} ${JSON.stringify(error)} ${(error as X402LaneError).issues?.join(",")}`),
    ];
    for (const surface of surfaces) {
      for (const fragment of secretFragments) {
        expect(surface.includes(fragment)).toBe(false);
      }
    }
    // The only place the signature exists outside the lane is the header value itself.
    expect(Buffer.from(header, "base64").toString("utf8")).toContain(signature.slice(2));
    expect(failures.every((error) => error instanceof X402LaneError)).toBe(true);
  });
});
