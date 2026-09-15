import { createHash } from "node:crypto";
import type * as NodeCrypto from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

// Hoisted, mutable control surface. The node:crypto mock delegates every
// operation to the real implementation unless a test arms one fault.
const cryptoControl = vi.hoisted(() => ({
  rngFault: null as null | "throw" | "short",
  deterministic: null as Uint8Array | null,
  calls: [] as unknown[][],
}));

vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof NodeCrypto>();
  return {
    ...actual,
    randomBytes: ((...args: unknown[]) => {
      cryptoControl.calls.push(args);
      if (cryptoControl.rngFault === "throw") {
        throw new Error("PRIVATE_RNG_DRIVER_CANARY");
      }
      if (cryptoControl.rngFault === "short") {
        return Buffer.alloc(31, 7);
      }
      if (cryptoControl.deterministic !== null) {
        // Fresh copy per call so the module zeroing its buffer cannot mutate
        // the fixture.
        return Buffer.from(cryptoControl.deterministic);
      }
      return (actual.randomBytes as (...inner: unknown[]) => unknown)(...args);
    }) as typeof actual.randomBytes,
  };
});

import {
  COMMERCE_CONTROL_HASH_VERSION,
  CommerceControlCryptoError,
  generateCommerceHandoffToken,
  generateCommerceSessionToken,
  hashCommerceHandoffToken,
  hashCommerceSessionToken,
} from "../src/control/session-crypto.js";

// Independent, literal domain strings. Recomputed here rather than imported so
// the vector does not trust the module under test.
const HANDOFF_DOMAIN = "openarc.control.commerce-handoff.v1";
const SESSION_DOMAIN = "openarc.control.commerce-session.v1";
const HANDOFF_PREFIX = "oach_v1_";
const SESSION_PREFIX = "oacs_v1_";
const NUL = "\u0000";

// Canonical 43-char base64url payloads whose final character carries zero
// padding bits; only synthetic values, never a live secret.
const P1 = "A".repeat(43);
const P2 = `${"B".repeat(42)}A`;
const HANDOFF1 = `${HANDOFF_PREFIX}${P1}`;
const HANDOFF2 = `${HANDOFF_PREFIX}${P2}`;
const SESSION1 = `${SESSION_PREFIX}${P1}`;

const sha256Hex = (input: string): string =>
  createHash("sha256").update(input, "utf8").digest("hex");

afterEach(() => {
  cryptoControl.rngFault = null;
  cryptoControl.deterministic = null;
  cryptoControl.calls.length = 0;
});

describe("known-vector hashing", () => {
  it("hashes a handoff token as UTF8 domain + NUL + full canonical token", () => {
    expect(COMMERCE_CONTROL_HASH_VERSION).toBe(1);
    expect(hashCommerceHandoffToken(HANDOFF1)).toBe(
      sha256Hex(`${HANDOFF_DOMAIN}${NUL}${HANDOFF1}`),
    );
    expect(hashCommerceHandoffToken(HANDOFF2)).toBe(
      sha256Hex(`${HANDOFF_DOMAIN}${NUL}${HANDOFF2}`),
    );
  });

  it("hashes a commerce session token with its own domain", () => {
    expect(hashCommerceSessionToken(SESSION1)).toBe(
      sha256Hex(`${SESSION_DOMAIN}${NUL}${SESSION1}`),
    );
  });

  it("returns 64 lower-case hex characters", () => {
    expect(hashCommerceHandoffToken(HANDOFF1)).toMatch(/^[0-9a-f]{64}$/u);
    expect(hashCommerceSessionToken(SESSION1)).toMatch(/^[0-9a-f]{64}$/u);
  });
});

describe("domain separation, NUL and full-prefix inclusion", () => {
  it("separates handoff from session for the same payload", () => {
    const samePayloadHandoff = hashCommerceHandoffToken(HANDOFF1);
    const samePayloadSession = hashCommerceSessionToken(SESSION1);
    expect(samePayloadHandoff).not.toBe(samePayloadSession);
  });

  it("binds the NUL separator (no NUL-free collision)", () => {
    const withNul = hashCommerceHandoffToken(HANDOFF1);
    const withoutNul = sha256Hex(`${HANDOFF_DOMAIN}${HANDOFF1}`);
    expect(withNul).not.toBe(withoutNul);
    expect(withNul).toBe(sha256Hex(`${HANDOFF_DOMAIN}${NUL}${HANDOFF1}`));
  });

  it("includes the full prefix, not just the 43-char payload", () => {
    // Hashing the bare payload is rejected outright, and a different prefix
    // never aliases the same digest.
    expect(() => hashCommerceHandoffToken(P1)).toThrowError(
      CommerceControlCryptoError,
    );
    const expected = sha256Hex(`${HANDOFF_DOMAIN}${NUL}${HANDOFF1}`);
    expect(expected).not.toBe(sha256Hex(`${HANDOFF_DOMAIN}${NUL}${P1}`));
    expect(hashCommerceHandoffToken(HANDOFF1)).toBe(expected);
  });
});

describe("CSPRNG generation", () => {
  it("calls randomBytes(32) and preserves all 32 bytes without masking", () => {
    const bytes = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
    cryptoControl.deterministic = bytes;
    const token = generateCommerceHandoffToken();
    expect(cryptoControl.calls.at(-1)).toEqual([32]);
    expect(token).toBe(`${HANDOFF_PREFIX}${Buffer.from(bytes).toString("base64url")}`);
    const decoded = Buffer.from(token.slice(HANDOFF_PREFIX.length), "base64url");
    expect(decoded).toHaveLength(32);
    expect(decoded.equals(Buffer.from(bytes))).toBe(true);
    // The fixture includes high bits (e.g. 0xff), so any masking would differ.
    expect(bytes[31]).toBe((31 * 7 + 3) & 0xff);
  });

  it("generates canonical schema-valid tokens for both namespaces", () => {
    const cases: [string, string][] = [
      [generateCommerceHandoffToken(), HANDOFF_PREFIX],
      [generateCommerceSessionToken(), SESSION_PREFIX],
    ];
    for (const [token, prefix] of cases) {
      expect(token.startsWith(prefix)).toBe(true);
      expect(token).toHaveLength(prefix.length + 43);
      const payload = token.slice(prefix.length);
      expect(payload).toMatch(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u);
      expect(Buffer.from(payload, "base64url")).toHaveLength(32);
    }
  });

  it("produces distinct tokens across calls", () => {
    const first = generateCommerceSessionToken();
    const second = generateCommerceSessionToken();
    expect(first).not.toBe(second);
  });
});

describe("strict rejection with fixed non-echoing error", () => {
  const rejects = (value: unknown, hash: (v: unknown) => string): void => {
    let caught: unknown;
    try {
      hash(value);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(CommerceControlCryptoError);
    expect((caught as CommerceControlCryptoError).code).toBe("INVALID_TOKEN");
    if (typeof value === "string" && value.length > 0) {
      expect(JSON.stringify(caught)).not.toContain(value);
    }
  };

  it.each([
    ["unknown prefix", `oax_v1_${P1}`],
    ["wrong version", `oach_v2_${P1}`],
    ["old oas_ag token", `oas_ag_${P1}`],
    ["old oas_pr token", `oas_pr_${P1}`],
    ["old oac token", `oac_${P1}`],
    ["missing prefix", P1],
    ["too short", `${HANDOFF_PREFIX}${"A".repeat(42)}`],
    ["too long", `${HANDOFF_PREFIX}${"A".repeat(44)}`],
    ["noncanonical padding bits", `${HANDOFF_PREFIX}${"A".repeat(42)}B`],
    ["padded base64", `${HANDOFF_PREFIX}${"A".repeat(42)}=`],
    ["trailing newline", `${HANDOFF1}\n`],
    ["trailing space", `${HANDOFF1} `],
    ["leading space", ` ${HANDOFF1}`],
    ["payload only", P1],
    ["empty", ""],
  ])("rejects %s for the handoff hash", (_label, value) => {
    rejects(value, hashCommerceHandoffToken);
  });

  it("rejects cross-namespace substitution in both directions", () => {
    rejects(SESSION1, hashCommerceHandoffToken);
    rejects(HANDOFF1, hashCommerceSessionToken);
  });

  it("rejects non-string values without normalizing", () => {
    for (const value of [undefined, null, 42, {}, [], true]) {
      rejects(value, hashCommerceSessionToken);
    }
    rejects(Buffer.from(HANDOFF1), hashCommerceHandoffToken);
  });

  it("does not trim or normalize a valid token wrapped in whitespace", () => {
    // A trim would make these pass; strict rejection proves it does not.
    rejects(`\t${HANDOFF1}`, hashCommerceHandoffToken);
    rejects(`${HANDOFF1}\r`, hashCommerceHandoffToken);
  });
});

describe("generation failure is a fixed input-free error", () => {
  const generate = (fn: () => string): unknown => {
    let caught: unknown;
    try {
      fn();
    } catch (error) {
      caught = error;
    }
    return caught;
  };

  it("maps a throwing CSPRNG to CRYPTO_FAILURE with no cause leak", () => {
    cryptoControl.rngFault = "throw";
    const caught = generate(generateCommerceHandoffToken);
    expect(caught).toBeInstanceOf(CommerceControlCryptoError);
    expect((caught as CommerceControlCryptoError).code).toBe("CRYPTO_FAILURE");
    expect(JSON.stringify(caught)).not.toContain("PRIVATE_RNG_DRIVER_CANARY");
  });

  it("maps an undersized CSPRNG result to CRYPTO_FAILURE", () => {
    cryptoControl.rngFault = "short";
    const caught = generate(generateCommerceSessionToken);
    expect(caught).toBeInstanceOf(CommerceControlCryptoError);
    expect((caught as CommerceControlCryptoError).code).toBe("CRYPTO_FAILURE");
  });

  it("recovers to a valid generated token after the fault clears", () => {
    cryptoControl.rngFault = "throw";
    expect(generate(generateCommerceHandoffToken)).toBeInstanceOf(
      CommerceControlCryptoError,
    );
    cryptoControl.rngFault = null;
    expect(generateCommerceHandoffToken()).toMatch(
      new RegExp(`^${HANDOFF_PREFIX}[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`, "u"),
    );
  });
});
