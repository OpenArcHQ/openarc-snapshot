/**
 * The ONE outbound transport of this provider.
 *
 * A raw `node:http`/`node:https` request that sends EXACTLY the headers the
 * caller names. Node's global `fetch` adds `sec-fetch-mode: cors`, and the
 * OpenArc provider claim surface rejects every browser-marker header, so a
 * claim issued through global `fetch` is refused with `400 INVALID_REQUEST`.
 * Those are forbidden header names that a caller cannot strip from a `fetch`
 * request, which is why the accepted production suites use `node:https`.
 *
 * Redirects are never followed, the response is bounded, and nothing is logged.
 */
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

export interface HeadlessResponse {
  readonly status: number;
  readonly text: string;
}

export interface HeadlessRequestInput {
  readonly url: string;
  readonly method: "GET" | "POST";
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: string;
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
}

const MAX_RESPONSE_BYTES = 1_048_576;

export function sendHeadlessRequest(input: HeadlessRequestInput): Promise<HeadlessResponse> {
  return new Promise((resolve, reject) => {
    let target: URL;
    try {
      target = new URL(input.url);
    } catch {
      reject(new Error("REQUEST_URL_INVALID"));
      return;
    }
    const send = target.protocol === "https:" ? httpsRequest : httpRequest;
    const headers: Record<string, string> = { ...input.headers };
    if (input.body !== undefined) {
      headers["content-length"] = String(Buffer.byteLength(input.body, "utf8"));
    }
    const req = send(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method: input.method,
        headers,
      },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) {
            response.destroy();
            reject(new Error("RESPONSE_TOO_LARGE"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            text: Buffer.concat(chunks).toString("utf8"),
          }),
        );
        response.on("error", () => reject(new Error("RESPONSE_FAILED")));
      },
    );
    req.setTimeout(input.timeoutMs, () => req.destroy(new Error("REQUEST_TIMEOUT")));
    req.on("error", (error: Error) => reject(error));
    if (input.signal !== undefined) {
      if (input.signal.aborted) {
        req.destroy(new Error("REQUEST_ABORTED"));
      } else {
        input.signal.addEventListener("abort", () => req.destroy(new Error("REQUEST_ABORTED")), {
          once: true,
        });
      }
    }
    if (input.body !== undefined) req.write(input.body);
    req.end();
  });
}
