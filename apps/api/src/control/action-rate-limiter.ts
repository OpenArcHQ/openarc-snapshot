import { createHmac } from "node:crypto";

import { AUTH_ERRORS } from "../auth/errors.js";
import type { CommerceActionRateLimitStorePort } from "./action-ports.js";

/**
 * Durable fixed-window commerce-action rate limiting.
 *
 * Every bucket key is an HMAC-SHA256 over a private configured secret and a
 * domain/family/bucket/value tuple; no raw IP, account id or presented bearer
 * ever reaches the database, a log line or a response. The exact frozen limits
 * are exported for tests. A limiter/store outage fails CLOSED (fixed 503)
 * BEFORE any database authority, never open; a denied bucket is a fixed 429.
 *
 * The domain is separate from the commerce-session limiter domain, so a burst
 * on one family can never silently exhaust the other family's allowance.
 */

export const COMMERCE_ACTION_RATE_WINDOW_SECONDS = 60;
export const COMMERCE_ACTION_RATE_DOMAIN =
  "openarc.control.commerce-action.rate.v1";

export const COMMERCE_ACTION_RATE_LIMITS = Object.freeze({
  /** Agent authorization: the only agent write on this surface. */
  authorize: Object.freeze({ global: 600, peer: 120, token: 60 }),
  /** Human approve/reject/cancel decisions. */
  decision: Object.freeze({ account: 30 }),
  /** Bounded browser and agent reads. */
  read: Object.freeze({ global: 600, peer: 120, subject: 60 }),
});

export type CommerceActionRateBucket =
  | "global"
  | "peer"
  | "token"
  | "account"
  | "subject";

/**
 * Operation family. Agent authorization, human decisions and bounded reads
 * have different fixed limits, so their keys must be domain-separated.
 */
export type CommerceActionRateFamily = "authorize" | "decision" | "read";

export interface CommerceActionRateCheck {
  readonly family: CommerceActionRateFamily;
  readonly bucket: CommerceActionRateBucket;
  readonly value: string;
  readonly limit: number;
}

export class CommerceActionRateLimiter {
  readonly #secret: Buffer;
  readonly #store: CommerceActionRateLimitStorePort;

  constructor(options: {
    secret: string;
    store: CommerceActionRateLimitStorePort;
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
      throw new Error("COMMERCE_ACTION_RATE_CONFIG");
    }
    this.#secret = Buffer.from(options.secret, "utf8");
    this.#store = options.store;
  }

  #key(check: CommerceActionRateCheck): string {
    return createHmac("sha256", this.#secret)
      .update(
        `${COMMERCE_ACTION_RATE_DOMAIN}:${check.family}:${check.bucket}:${check.value}`,
        "utf8",
      )
      .digest("hex");
  }

  /**
   * Consume one bucket. Ordered checks are enforced by `consumeAll`; global
   * first bounds bucket growth. A store error fails closed with the fixed
   * non-echoing 503 and never reports an allowed request.
   */
  async consume(check: CommerceActionRateCheck): Promise<void> {
    let allowed: boolean;
    try {
      const result = await this.#store.consume({
        keyHash: this.#key(check),
        limit: check.limit,
        windowSeconds: COMMERCE_ACTION_RATE_WINDOW_SECONDS,
      });
      allowed = result.allowed === true;
    } catch {
      throw AUTH_ERRORS.unavailable();
    }
    if (!allowed) throw AUTH_ERRORS.rateLimited();
  }

  async consumeAll(checks: readonly CommerceActionRateCheck[]): Promise<void> {
    for (const check of checks) await this.consume(check);
  }
}
