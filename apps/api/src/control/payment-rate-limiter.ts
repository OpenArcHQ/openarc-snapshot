import { createHmac } from "node:crypto";

import { AUTH_ERRORS } from "../auth/errors.js";
import type { CommercePaymentRateLimitStorePort } from "./payment-ports.js";

/**
 * Durable fixed-window payment rate limiting.
 *
 * Every bucket key is an HMAC-SHA256 over the private configured secret and a
 * domain/family/bucket/value tuple; no raw IP, account id or presented bearer
 * reaches the database, a log line or a response. The domain is separate from
 * the session, action and grant limiter domains. A limiter outage fails CLOSED
 * (fixed 503) before any store authority; a denied bucket is a fixed 429.
 */

export const COMMERCE_PAYMENT_RATE_WINDOW_SECONDS = 60;
export const COMMERCE_PAYMENT_RATE_DOMAIN =
  "openarc.control.commerce-payment.rate.v1";

export const COMMERCE_PAYMENT_RATE_LIMITS = Object.freeze({
  /** Seller human terms record, the only browser write. */
  terms: Object.freeze({ account: 30 }),
  /** Agent verified requirement registration. */
  requirement: Object.freeze({ global: 600, peer: 120, token: 60 }),
  /** Agent attempt persistence. */
  attempt: Object.freeze({ global: 600, peer: 120, token: 60 }),
  /** Agent dispatch record. */
  dispatch: Object.freeze({ global: 600, peer: 120, token: 60 }),
  /** Agent attempt recovery read. */
  read: Object.freeze({ global: 600, peer: 120, subject: 60 }),
});

export type CommercePaymentRateBucket =
  | "global"
  | "peer"
  | "token"
  | "account"
  | "subject";

export type CommercePaymentRateFamily =
  | "terms"
  | "requirement"
  | "attempt"
  | "dispatch"
  | "read";

export interface CommercePaymentRateCheck {
  readonly family: CommercePaymentRateFamily;
  readonly bucket: CommercePaymentRateBucket;
  readonly value: string;
  readonly limit: number;
}

export class CommercePaymentRateLimiter {
  readonly #secret: Buffer;
  readonly #store: CommercePaymentRateLimitStorePort;

  constructor(options: {
    secret: string;
    store: CommercePaymentRateLimitStorePort;
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
      throw new Error("COMMERCE_PAYMENT_RATE_CONFIG");
    }
    this.#secret = Buffer.from(options.secret, "utf8");
    this.#store = options.store;
  }

  #key(check: CommercePaymentRateCheck): string {
    return createHmac("sha256", this.#secret)
      .update(
        `${COMMERCE_PAYMENT_RATE_DOMAIN}:${check.family}:${check.bucket}:${check.value}`,
        "utf8",
      )
      .digest("hex");
  }

  async consume(check: CommercePaymentRateCheck): Promise<void> {
    let allowed: boolean;
    try {
      const result = await this.#store.consume({
        keyHash: this.#key(check),
        limit: check.limit,
        windowSeconds: COMMERCE_PAYMENT_RATE_WINDOW_SECONDS,
      });
      allowed = result.allowed === true;
    } catch {
      throw AUTH_ERRORS.unavailable();
    }
    if (!allowed) throw AUTH_ERRORS.rateLimited();
  }

  async consumeAll(checks: readonly CommercePaymentRateCheck[]): Promise<void> {
    for (const check of checks) await this.consume(check);
  }
}
