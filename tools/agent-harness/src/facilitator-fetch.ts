/**
 * The buyer side of the transport seam `packages/x402` leaves open.
 *
 * The lane's facilitator client always builds requests against the pinned
 * Circle testnet origin; this adapter refuses any other origin and re-targets
 * the path at a loopback fake, so the pinned host is never resolved and never
 * contacted. The harness uses it only to READ (a transfer lookup); it never
 * sends a payment through the facilitator.
 */
import { ARC_TESTNET_LANE, type LaneFetch, type LaneFetchResponse } from "@openarc/x402";

import { sendHeadlessRequest } from "./http.js";
import { assertLoopbackOrigin } from "./loopback.js";

export function createLoopbackFacilitatorFetch(fakeBaseUrl: string): LaneFetch {
  const base = assertLoopbackOrigin(fakeBaseUrl, "facilitatorUrl");
  return async (url, init): Promise<LaneFetchResponse> => {
    const target = new URL(url);
    if (target.origin !== ARC_TESTNET_LANE.facilitatorOrigin) {
      throw new Error("FACILITATOR_ORIGIN_REFUSED");
    }
    const response = await sendHeadlessRequest({
      url: new URL(`${target.pathname}${target.search}`, base).toString(),
      method: init.method,
      headers: { ...init.headers },
      ...(init.body === undefined ? {} : { body: init.body }),
      timeoutMs: 120_000,
      signal: init.signal,
    });
    return { status: response.status, text: async () => response.text };
  };
}
