/**
 * Loopback-only URL admission.
 *
 * Nothing in this package may ever reach a public host: the OpenArc API it
 * claims a grant through, and the facilitator base it is pointed at, must both
 * be loopback. There is no flag, environment variable or option that widens
 * this, and a refusal never echoes the rejected value.
 */

export type ProviderRefusalCode =
  | "non_loopback_url"
  | "url_unparseable"
  | "url_not_http"
  | "url_has_credentials"
  | "url_has_query_or_fragment";

export class ReferenceProviderError extends Error {
  readonly code: ProviderRefusalCode | "provider_misconfigured";
  readonly field: string;

  constructor(code: ProviderRefusalCode | "provider_misconfigured", field: string) {
    super(`${code}: ${field}`);
    this.name = "ReferenceProviderError";
    this.code = code;
    this.field = field;
  }
}

const LOOPBACK_HOSTS: ReadonlySet<string> = new Set([
  "127.0.0.1",
  "localhost",
  "[::1]",
  "::1",
]);

/** Exactly an http(s) loopback origin with no credentials, query or fragment. */
export function assertLoopbackBaseUrl(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) {
    throw new ReferenceProviderError("url_unparseable", field);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ReferenceProviderError("url_unparseable", field);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ReferenceProviderError("url_not_http", field);
  }
  if (url.username !== "" || url.password !== "") {
    throw new ReferenceProviderError("url_has_credentials", field);
  }
  if (url.search !== "" || url.hash !== "") {
    throw new ReferenceProviderError("url_has_query_or_fragment", field);
  }
  if (!LOOPBACK_HOSTS.has(url.hostname)) {
    throw new ReferenceProviderError("non_loopback_url", field);
  }
  return url.origin;
}
