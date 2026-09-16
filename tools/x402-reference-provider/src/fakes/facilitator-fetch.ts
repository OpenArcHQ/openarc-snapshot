/**
 * The transport seam `packages/x402` leaves open, wired to a LOCAL FAKE.
 *
 * `createLaneFacilitatorClient` still builds every request against the pinned
 * Circle testnet origin, and this adapter is the only thing that can carry one:
 * it refuses any URL whose origin is not that pinned origin, then re-targets the
 * path at a loopback fake. The pinned host is therefore never resolved and never
 * contacted, and no other host is reachable at all.
 */
import { ARC_TESTNET_LANE, type LaneFetch, type LaneFetchResponse } from "@openarc/x402";

import { sendHeadlessRequest } from "../http.js";
import { assertLoopbackBaseUrl } from "../loopback.js";

export function createFakeFacilitatorFetch(fakeBaseUrl: string): LaneFetch {
  const base = assertLoopbackBaseUrl(fakeBaseUrl, "facilitatorFakeUrl");
  return async (url, init): Promise<LaneFetchResponse> => {
    const target = new URL(url);
    if (target.origin !== ARC_TESTNET_LANE.facilitatorOrigin) {
      // Anything but the pinned origin is a defect, never an egress attempt.
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
