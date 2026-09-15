import { createHmac } from "node:crypto";

import { AUTH_ERRORS } from "../auth/errors.js";
import type { CommerceSessionRateLimitStorePort } from "./session-ports.js";

/**
 * Durable fixed-window commerce-session rate limiting.
 *
 * Every bucket key is an HMAC-SHA256 over a private configured secret and a
 * domain/family/bucket/value tuple; no raw IP, account id or token ever reaches
 * the database. The exact frozen limits are exported for tests. A limiter/store
 * outage fails CLOSED (fixed 503) before any token generation or database
 * authority, never open; a denied bucket is a fixed 429.
 */

export const COMMERCE_SESSION_RATE_WINDOW_SECONDS = 60;
export const COMMERCE_SESSION_RATE_DOMAIN =
  "openarc.control.commerce-session.rate.v1";

export const COMMERCE_SESSION_RATE_LIMITS = Object.freeze({
  exchange: Object.freeze({ global: 600, peer: 120, token: 60 }),
  issue: Object.freeze({ account: 10 }),
  read: Object.freeze({ global: 600, peer: 120, subject: 60 }),
});

export type CommerceSessionRateBucket =
  | "global"
  | "peer"
  | "token"
  | "account"
  | "subject";

/**
 * Operation family. Exchange, human issue and bounded reads have different
 * fixed limits, so their keys must be domain-separated: a burst of reads can
 * never silently exhaust the exchange peer/global allowance.
 */
export type CommerceSessionRateFamily = "exchange" | "issue" | "read";

export interface CommerceSessionRateCheck {
  readonly family: CommerceSessionRateFamily;
  readonly bucket: CommerceSessionRateBucket;
  readonly value: string;
  readonly limit: number;
}

export class CommerceSessionRateLimiter {
  readonly #secret: Buffer;
  readonly #store: CommerceSessionRateLimitStorePort;

  constructor(options: {
    secret: string;
    store: CommerceSessionRateLimitStorePort;
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
      throw new Error("COMMERCE_SESSION_RATE_CONFIG");
    }
    this.#secret = Buffer.from(options.secret, "utf8");
    this.#store = options.store;
  }

  #key(check: CommerceSessionRateCheck): string {
    return createHmac("sha256", this.#secret)
      .update(
        `${COMMERCE_SESSION_RATE_DOMAIN}:${check.family}:${check.bucket}:${check.value}`,
        "utf8",
      )
      .digest("hex");
  }

  /**
   * Consume one bucket. Ordered checks are enforced by `consumeAll`; global
   * first bounds bucket growth. A store error fails closed with the fixed
   * non-echoing 503 and never reports an allowed request.
   */
  async consume(check: CommerceSessionRateCheck): Promise<void> {
    let allowed: boolean;
    try {
      const result = await this.#store.consume({
        keyHash: this.#key(check),
        limit: check.limit,
        windowSeconds: COMMERCE_SESSION_RATE_WINDOW_SECONDS,
      });
      allowed = result.allowed === true;
    } catch {
      throw AUTH_ERRORS.unavailable();
    }
    if (!allowed) throw AUTH_ERRORS.rateLimited();
  }

  async consumeAll(checks: readonly CommerceSessionRateCheck[]): Promise<void> {
    for (const check of checks) await this.consume(check);
  }
}
