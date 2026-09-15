import { createHmac } from "node:crypto";

import { describe, expect, it } from "vitest";

import { AuthApiError } from "../src/auth/errors.js";
import {
  COMMERCE_SESSION_RATE_DOMAIN,
  COMMERCE_SESSION_RATE_LIMITS,
  COMMERCE_SESSION_RATE_WINDOW_SECONDS,
  CommerceSessionRateLimiter,
} from "../src/control/session-rate-limiter.js";
import type { CommerceSessionRateLimitStorePort } from "../src/control/session-ports.js";

/**
 * Unit coverage for the commerce-session durable rate limiter.
 *
 * The durable consume port is HONESTLY MOCKED here: this suite proves
 * purpose-separated HMAC key derivation, the frozen bucket bounds, ordered
 * consumption and fixed fail-closed error mapping. No raw IP/account/token
 * value is observable to the store.
 */

const SECRET = "synthetic_session_rate_secret_0123456789";

interface ConsumeCall {
  readonly keyHash: string;
  readonly limit: number;
  readonly windowSeconds: number;
}

class FakeStore implements CommerceSessionRateLimitStorePort {
  readonly calls: ConsumeCall[] = [];
  allowed = true;
  error: unknown;

  async consume(input: ConsumeCall): Promise<{ allowed: boolean }> {
    this.calls.push({ ...input });
    if (this.error) throw this.error;
    return { allowed: this.allowed };
  }
}

function expectedKey(
  family: string,
  bucket: string,
  value: string,
): string {
  return createHmac("sha256", SECRET)
    .update(
      `${COMMERCE_SESSION_RATE_DOMAIN}:${family}:${bucket}:${value}`,
      "utf8",
    )
    .digest("hex");
}

describe("CommerceSessionRateLimiter", () => {
  it("derives purpose-separated HMAC keys and never exposes raw values", async () => {
    const store = new FakeStore();
    const limiter = new CommerceSessionRateLimiter({ secret: SECRET, store });

    await limiter.consume({
      family: "exchange",
      bucket: "token",
      value: "oas_ag_secret",
      limit: COMMERCE_SESSION_RATE_LIMITS.exchange.token,
    });

    expect(store.calls).toHaveLength(1);
    const call = store.calls[0]!;
    expect(call.keyHash).toBe(expectedKey("exchange", "token", "oas_ag_secret"));
    expect(call.keyHash).toMatch(/^[0-9a-f]{64}$/u);
    expect(call.keyHash).not.toContain("oas_ag_secret");
    expect(call.limit).toBe(60);
    expect(call.windowSeconds).toBe(COMMERCE_SESSION_RATE_WINDOW_SECONDS);
    expect(call.windowSeconds).toBe(60);
  });

  it("separates keys by family, bucket and value", async () => {
    const store = new FakeStore();
    const limiter = new CommerceSessionRateLimiter({ secret: SECRET, store });
    const base = {
      family: "read" as const,
      bucket: "subject" as const,
      value: "openarc:account:subject",
      limit: 60,
    };

    await limiter.consume(base);
    await limiter.consume({ ...base, family: "exchange" });
    await limiter.consume({ ...base, bucket: "global" });
    await limiter.consume({ ...base, value: "other-subject" });

    const hashes = store.calls.map((call) => call.keyHash);
    expect(new Set(hashes).size).toBe(4);
  });

  it("consumes ordered checks sequentially and stops at the first deny", async () => {
    const store = new FakeStore();
    let allowCount = 0;
    const gated: CommerceSessionRateLimitStorePort = {
      async consume(input) {
        store.calls.push({ ...input });
        allowCount += 1;
        return { allowed: allowCount <= 1 };
      },
    };
    const limiter = new CommerceSessionRateLimiter({ secret: SECRET, store: gated });

    await expect(
      limiter.consumeAll([
        { family: "exchange", bucket: "global", value: "*", limit: 600 },
        { family: "exchange", bucket: "peer", value: "127.0.0.1", limit: 120 },
        { family: "exchange", bucket: "token", value: "token", limit: 60 },
      ]),
    ).rejects.toMatchObject({ status: 429, code: "RATE_LIMITED" });

    // Only global and peer were consumed; the deny stopped the sequence.
    expect(store.calls).toHaveLength(2);
    expect(store.calls.map((call) => call.limit)).toEqual([600, 120]);
  });

  it("fails closed with a fixed 503 on a store outage", async () => {
    const store = new FakeStore();
    store.error = new Error("driver down with secret detail");
    const limiter = new CommerceSessionRateLimiter({ secret: SECRET, store });

    await expect(
      limiter.consume({
        family: "issue",
        bucket: "account",
        value: "openarc:account:x",
        limit: 10,
      }),
    ).rejects.toMatchObject({ status: 503, code: "INTERNAL_ERROR" });
  });

  it("rejects a malformed construction", () => {
    const store = new FakeStore();
    expect(
      () =>
        new CommerceSessionRateLimiter({
          secret: "",
          store,
        }),
    ).toThrow("COMMERCE_SESSION_RATE_CONFIG");
    expect(
      () =>
        new CommerceSessionRateLimiter({
          secret: SECRET,
          store: {} as CommerceSessionRateLimitStorePort,
        }),
    ).toThrow("COMMERCE_SESSION_RATE_CONFIG");
  });

  it("returns typed AuthApiError instances", async () => {
    const store = new FakeStore();
    store.allowed = false;
    const limiter = new CommerceSessionRateLimiter({ secret: SECRET, store });
    await expect(
      limiter.consume({
        family: "exchange",
        bucket: "global",
        value: "*",
        limit: 600,
      }),
    ).rejects.toBeInstanceOf(AuthApiError);
  });

  it("publishes the frozen bounds", () => {
    expect(COMMERCE_SESSION_RATE_LIMITS).toEqual({
      exchange: { global: 600, peer: 120, token: 60 },
      issue: { account: 10 },
      read: { global: 600, peer: 120, subject: 60 },
    });
    expect(Object.isFrozen(COMMERCE_SESSION_RATE_LIMITS)).toBe(true);
  });
});
