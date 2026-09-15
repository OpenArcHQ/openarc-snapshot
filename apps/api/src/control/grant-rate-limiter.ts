import { createHmac } from "node:crypto";

import { AUTH_ERRORS } from "../auth/errors.js";
import type { CommerceGrantRateLimitStorePort } from "./grant-ports.js";

/**
 * Durable fixed-window authorization-grant rate limiting.
 *
 * Every bucket key is an HMAC-SHA256 over a private configured secret and a
 * domain/family/bucket/value tuple; no raw IP, account id, presented commerce
 * bearer, provider bearer or grant token ever reaches the database, a log line
 * or a response. The exact frozen limits are exported for tests. A
 * limiter/store outage fails CLOSED (fixed 503) BEFORE any database authority,
 * never open; a denied bucket is a fixed 429.
 *
 * The domain is separate from the commerce-session and commerce-action limiter
 * domains, so a burst on one family can never silently exhaust another
 * family's allowance.
 */

export const COMMERCE_GRANT_RATE_WINDOW_SECONDS = 60;
export const COMMERCE_GRANT_RATE_DOMAIN =
  "openarc.control.commerce-grant.rate.v1";

export const COMMERCE_GRANT_RATE_LIMITS = Object.freeze({
  /** Agent issue/replace: the two agent writes on this surface. */
  authorization: Object.freeze({ global: 600, peer: 120, token: 60 }),
  /** Provider claim: the single provider write that consumes a grant. */
  claim: Object.freeze({ global: 600, peer: 120, token: 60 }),
  /** Human revoke, the only browser write on this surface. */
  revoke: Object.freeze({ account: 30 }),
  /** Bounded browser, agent and provider reads (introspection included). */
  read: Object.freeze({ global: 600, peer: 120, subject: 60 }),
});

export type CommerceGrantRateBucket =
  | "global"
  | "peer"
  | "token"
  | "account"
  | "subject";

/**
 * Operation family. Agent authorization, provider claims, human revocation and
 * bounded reads have different fixed limits, so their keys must be
 * domain-separated.
 */
export type CommerceGrantRateFamily =
  | "authorization"
  | "claim"
  | "revoke"
  | "read";

export interface CommerceGrantRateCheck {
  readonly family: CommerceGrantRateFamily;
  readonly bucket: CommerceGrantRateBucket;
  readonly value: string;
  readonly limit: number;
}

export class CommerceGrantRateLimiter {
  readonly #secret: Buffer;
  readonly #store: CommerceGrantRateLimitStorePort;

  constructor(options: {
    secret: string;
    store: CommerceGrantRateLimitStorePort;
  }) {
    if (
      options === null ||
      typeof options !== "object" ||
      typeof options.secret !== "string" ||
      options.secret.length === 0 ||
      options.store === null ||
      typeof options.store !== "object" ||
      typeof options.store.consume !== "function"
    ) {
      throw new Error("COMMERCE_GRANT_RATE_CONFIG");
    }
    this.#secret = Buffer.from(options.secret, "utf8");
    this.#store = options.store;
  }

  #key(check: CommerceGrantRateCheck): string {
    return createHmac("sha256", this.#secret)
      .update(
        `${COMMERCE_GRANT_RATE_DOMAIN}:${check.family}:${check.bucket}:${check.value}`,
        "utf8",
      )
      .digest("hex");
  }

  /**
   * Consume one bucket. Ordered checks are enforced by `consumeAll`; global
   * first bounds bucket growth. A store error fails closed with the fixed
   * non-echoing 503 and never reports an allowed request.
   */
  async consume(check: CommerceGrantRateCheck): Promise<void> {
    let allowed: boolean;
    try {
      const result = await this.#store.consume({
        keyHash: this.#key(check),
        limit: check.limit,
        windowSeconds: COMMERCE_GRANT_RATE_WINDOW_SECONDS,
      });
      allowed = result.allowed === true;
    } catch {
      throw AUTH_ERRORS.unavailable();
    }
    if (!allowed) throw AUTH_ERRORS.rateLimited();
  }

  async consumeAll(checks: readonly CommerceGrantRateCheck[]): Promise<void> {
    for (const check of checks) await this.consume(check);
  }
}
