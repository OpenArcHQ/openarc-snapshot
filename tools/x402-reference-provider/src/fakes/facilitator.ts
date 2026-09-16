/**
 * LOCAL FAKE Circle Gateway facilitator. TEST DOUBLE ONLY.
 *
 * It is not Circle, it settles nothing, it moves no funds and it proves no
 * payment. It exists so the whole buyer flow can be exercised with zero network
 * egress: it listens on loopback, it is reached only through the injected
 * transport in `facilitator-fetch.ts`, and every behaviour it can show
 * (acceptance, a settle error reason, a 500 and a hang) is chosen by the test.
 *
 * It verifies the presented EIP-712 signature so an accepted settle really does
 * prove the buyer signed. Received payloads stay in memory for the life of the
 * server, are never written to disk and are never returned: only counts and the
 * non-secret transfer projection leave this module.
 */
import { ARC_TESTNET_LANE, LANE_AUTHORIZATION_TYPES } from "@openarc/x402";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { randomUUID } from "node:crypto";
import { verifyTypedData, type Address, type Hex } from "viem";

/** What the fake does when asked to settle. */
export type FakeSettleBehaviour =
  | "accept"
  /** Gateway's own closed error reason for a replayed authorization. */
  | "nonce_already_used"
  | "http_500"
  /** Never answers, so the lane's own timeout fires. */
  | "timeout";

/** What a later transfer lookup reports for an accepted settle. */
export type FakeLookupBehaviour = "completed" | "received" | "empty";

export interface FakeFacilitatorBehaviour {
  readonly settle: FakeSettleBehaviour;
  readonly lookup: FakeLookupBehaviour;
}

export interface FakeFacilitatorCounts {
  readonly settle: number;
  readonly transfers: number;
  readonly supported: number;
  readonly acceptedSettles: number;
}

export interface FakeFacilitator {
  /** Loopback base URL. Never a Circle host. */
  readonly url: string;
  counts(): FakeFacilitatorCounts;
  close(): Promise<void>;
}

interface StoredTransfer {
  readonly id: string;
  readonly status: string;
  readonly fromAddress: string;
  readonly toAddress: string;
  readonly amount: string;
  readonly nonce: string;
  readonly sendingNetwork: string;
  readonly recipientNetwork: string;
  readonly txHash: string | null;
}

interface PresentedAuthorization {
  readonly from: Address;
  readonly to: Address;
  readonly value: string;
  readonly validAfter: string;
  readonly validBefore: string;
  readonly nonce: Hex;
}

const MAX_BODY_BYTES = 64 * 1024;
const ADDRESS = /^0x[0-9a-fA-F]{40}(?![\s\S])/u;
const BYTES32 = /^0x[0-9a-f]{64}(?![\s\S])/u;
const SIGNATURE = /^0x[0-9a-fA-F]{130}(?![\s\S])/u;
const UINT = /^(?:0|[1-9][0-9]{0,77})(?![\s\S])/u;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readAuthorization(body: unknown): { auth: PresentedAuthorization; signature: Hex } | null {
  if (!isRecord(body) || !isRecord(body["paymentPayload"])) return null;
  const payload = body["paymentPayload"]["payload"];
  if (!isRecord(payload) || !isRecord(payload["authorization"])) return null;
  const raw = payload["authorization"];
  const signature = payload["signature"];
  const from = raw["from"];
  const to = raw["to"];
  const value = raw["value"];
  const validAfter = raw["validAfter"];
  const validBefore = raw["validBefore"];
  const nonce = raw["nonce"];
  if (
    typeof from !== "string" || !ADDRESS.test(from) ||
    typeof to !== "string" || !ADDRESS.test(to) ||
    typeof value !== "string" || !UINT.test(value) ||
    typeof validAfter !== "string" || !UINT.test(validAfter) ||
    typeof validBefore !== "string" || !UINT.test(validBefore) ||
    typeof nonce !== "string" || !BYTES32.test(nonce) ||
    typeof signature !== "string" || !SIGNATURE.test(signature)
  ) {
    return null;
  }
  return {
    auth: {
      from: from as Address,
      to: to as Address,
      value,
      validAfter,
      validBefore,
      nonce: nonce as Hex,
    },
    signature: signature as Hex,
  };
}

async function signatureIsValid(
  auth: PresentedAuthorization,
  signature: Hex,
): Promise<boolean> {
  try {
    return await verifyTypedData({
      address: auth.from,
      domain: {
        name: ARC_TESTNET_LANE.eip712.name,
        version: ARC_TESTNET_LANE.eip712.version,
        chainId: ARC_TESTNET_LANE.chainId,
        verifyingContract: ARC_TESTNET_LANE.eip712.verifyingContract,
      },
      types: LANE_AUTHORIZATION_TYPES,
      primaryType: "TransferWithAuthorization",
      message: {
        from: auth.from,
        to: auth.to,
        value: BigInt(auth.value),
        validAfter: BigInt(auth.validAfter),
        validBefore: BigInt(auth.validBefore),
        nonce: auth.nonce,
      },
      signature,
    });
  } catch {
    return false;
  }
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("BODY_TOO_LARGE"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", () => reject(new Error("BODY_READ_FAILED")));
  });
}

function json(response: ServerResponse, status: number, body: unknown): void {
  const serialized = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(serialized);
}

/** The exact `/v1/x402/supported` shape the lane manifest expects. */
function supportedBody(): Record<string, unknown> {
  return {
    kinds: [
      {
        x402Version: ARC_TESTNET_LANE.x402Version,
        scheme: ARC_TESTNET_LANE.scheme,
        network: ARC_TESTNET_LANE.caip2,
        extra: {
          name: ARC_TESTNET_LANE.eip712.name,
          version: ARC_TESTNET_LANE.eip712.version,
          verifyingContract: ARC_TESTNET_LANE.eip712.verifyingContract,
          minValiditySeconds: ARC_TESTNET_LANE.minValiditySeconds,
          assets: [
            {
              address: ARC_TESTNET_LANE.asset.address,
              decimals: ARC_TESTNET_LANE.asset.decimals,
              symbol: ARC_TESTNET_LANE.asset.symbol,
            },
          ],
        },
      },
    ],
  };
}

export async function startFakeFacilitator(
  behaviour: FakeFacilitatorBehaviour,
): Promise<FakeFacilitator> {
  const transfers: StoredTransfer[] = [];
  const counts = { settle: 0, transfers: 0, supported: 0, acceptedSettles: 0 };
  /** Sockets deliberately left hanging by the `timeout` behaviour. */
  const hanging = new Set<ServerResponse>();

  async function handleSettle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    counts.settle += 1;
    if (behaviour.settle === "timeout") {
      hanging.add(response);
      response.on("close", () => hanging.delete(response));
      return;
    }
    let body: unknown;
    try {
      body = JSON.parse(await readBody(request)) as unknown;
    } catch {
      json(response, 400, { success: false, errorReason: "invalid_payload" });
      return;
    }
    if (behaviour.settle === "http_500") {
      json(response, 500, { success: false, errorReason: "unexpected_error" });
      return;
    }
    const presented = readAuthorization(body);
    if (presented === null) {
      json(response, 400, { success: false, errorReason: "invalid_payload" });
      return;
    }
    if (!(await signatureIsValid(presented.auth, presented.signature))) {
      json(response, 400, { success: false, errorReason: "invalid_signature" });
      return;
    }
    if (behaviour.settle === "nonce_already_used") {
      json(response, 409, { success: false, errorReason: "nonce_already_used" });
      return;
    }
    const transferId = randomUUID();
    if (behaviour.lookup !== "empty") {
      transfers.push({
        id: transferId,
        status: behaviour.lookup,
        fromAddress: presented.auth.from,
        toAddress: presented.auth.to,
        amount: presented.auth.value,
        nonce: presented.auth.nonce,
        sendingNetwork: ARC_TESTNET_LANE.caip2,
        recipientNetwork: ARC_TESTNET_LANE.caip2,
        txHash: behaviour.lookup === "completed" ? `0x${"ab".repeat(32)}` : null,
      });
    }
    counts.acceptedSettles += 1;
    // `accepted` is accepted-and-locked, never a settlement claim.
    json(response, 200, {
      success: true,
      transaction: transferId,
      network: ARC_TESTNET_LANE.caip2,
      payer: presented.auth.from,
    });
  }

  function handleTransfers(url: URL, response: ServerResponse): void {
    counts.transfers += 1;
    const from = url.searchParams.get("from");
    const nonce = url.searchParams.get("nonce");
    const matching = transfers.filter(
      (record) =>
        from !== null &&
        nonce !== null &&
        record.fromAddress.toLowerCase() === from.toLowerCase() &&
        record.nonce.toLowerCase() === nonce.toLowerCase(),
    );
    json(response, 200, { transfers: matching });
  }

  const server: Server = createServer((request, response) => {
    void (async () => {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      try {
        if (request.method === "POST" && url.pathname === "/v1/x402/settle") {
          await handleSettle(request, response);
          return;
        }
        if (request.method === "GET" && url.pathname === "/v1/x402/transfers") {
          handleTransfers(url, response);
          return;
        }
        if (request.method === "GET" && url.pathname === "/v1/x402/supported") {
          counts.supported += 1;
          json(response, 200, supportedBody());
          return;
        }
        json(response, 404, { success: false, errorReason: "unexpected_error" });
      } catch {
        if (!response.headersSent) {
          json(response, 500, { success: false, errorReason: "unexpected_error" });
        }
      }
    })();
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${address.port}`,
    counts: () => Object.freeze({ ...counts }),
    close: async () => {
      for (const response of hanging) response.destroy();
      hanging.clear();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
