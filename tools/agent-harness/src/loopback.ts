/**
 * Loopback-only admission for every endpoint this harness may touch.
 *
 * NOTHING in this package defaults to a live URL. The OpenArc API, the provider
 * resource, the facilitator and (when given) the RPC URL must each be loopback,
 * or the run is refused before any request, any key generation and any
 * signature. `--live-testnet` does not widen this: it is a refusing stub.
 */

export type HarnessRefusalCode =
  | "non_loopback_url"
  | "url_unparseable"
  | "url_not_http"
  | "url_has_credentials"
  | "url_has_fragment"
  | "commerce_token_invalid"
  | "listing_id_invalid"
  | "input_invalid"
  | "live_testnet_not_implemented";

export class HarnessRefusal extends Error {
  readonly code: HarnessRefusalCode;
  readonly field: string;

  constructor(code: HarnessRefusalCode, field: string) {
    super(`${code}: ${field}`);
    this.name = "HarnessRefusal";
    this.code = code;
    this.field = field;
  }
}

const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

function parse(value: unknown, field: string): URL {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) {
    throw new HarnessRefusal("url_unparseable", field);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new HarnessRefusal("url_unparseable", field);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new HarnessRefusal("url_not_http", field);
  }
  if (url.username !== "" || url.password !== "") {
    throw new HarnessRefusal("url_has_credentials", field);
  }
  if (url.hash !== "") throw new HarnessRefusal("url_has_fragment", field);
  if (!LOOPBACK_HOSTS.has(url.hostname)) {
    throw new HarnessRefusal("non_loopback_url", field);
  }
  return url;
}

/** Loopback origin, with any path and query discarded. */
export function assertLoopbackOrigin(value: unknown, field: string): string {
  return parse(value, field).origin;
}

/** Full loopback URL (a resource path is allowed, a fragment is not). */
export function assertLoopbackUrl(value: unknown, field: string): string {
  return parse(value, field).toString();
}
