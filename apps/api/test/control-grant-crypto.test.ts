import { createHash } from "node:crypto";
import type * as NodeCrypto from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

// Hoisted, mutable control surface. The node:crypto mock delegates every
// operation to the real implementation unless a test arms one fault.
const cryptoControl = vi.hoisted(() => ({
  rngFault: null as null | "throw" | "short",
  deterministic: null as Uint8Array | null,
  hashFault: false,
  calls: [] as unknown[][],
  // Every buffer actually handed to the module by mocked randomBytes, so a
  // test can assert the module zeroed that exact instance.
  returnedBuffers: [] as Buffer[],
}));

vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof NodeCrypto>();
  const realCreateHash = actual.createHash;
  return {
    ...actual,
    randomBytes: ((...args: unknown[]) => {
      cryptoControl.calls.push(args);
      if (cryptoControl.rngFault === "throw") {
        throw new Error("PRIVATE_GRANT_RNG_CANARY");
      }
      if (cryptoControl.rngFault === "short") {
        const short = Buffer.alloc(31, 7);
        cryptoControl.returnedBuffers.push(short);
        return short;
      }
      if (cryptoControl.deterministic !== null) {
        // Fresh copy per call so the module zeroing its buffer cannot mutate
        // the fixture.
        const copy = Buffer.from(cryptoControl.deterministic);
        cryptoControl.returnedBuffers.push(copy);
        return copy;
      }
      const fresh = (actual.randomBytes as (...inner: unknown[]) => unknown)(
        ...args,
      );
      if (Buffer.isBuffer(fresh)) cryptoControl.returnedBuffers.push(fresh);
      return fresh;
    }) as typeof actual.randomBytes,
    createHash: ((...args: unknown[]) => {
      if (cryptoControl.hashFault) {
        throw new Error("PRIVATE_GRANT_HASH_CANARY");
      }
      return (
        realCreateHash as (...inner: unknown[]) => unknown
      )(...args);
    }) as typeof actual.createHash,
  };
});

import {
  COMMERCE_GRANT_HASH_VERSION,
  COMMERCE_GRANT_TOKEN_DOMAIN,
  CommerceGrantCryptoError,
  generateCommerceGrantToken,
  hashCommerceGrantToken,
} from "../src/control/grant-crypto.js";

// Independent, literal domain string. Recomputed here rather than imported so
// the vector does not trust the module under test.
const DOMAIN = "openarc.control.authorization-grant.v1";
const PREFIX = "oag_v1_";
const NUL = "\u0000";

// Canonical 43-char base64url payloads whose final character carries zero
// padding bits; only synthetic values, never a live secret.
const P1 = "A".repeat(43);
const P2 = `${"B".repeat(42)}A`;
const TOKEN1 = `${PREFIX}${P1}`;
const TOKEN2 = `${PREFIX}${P2}`;

const sha256Hex = (input: string): string =>
  createHash("sha256").update(input, "utf8").digest("hex");

afterEach(() => {
  cryptoControl.rngFault = null;
  cryptoControl.deterministic = null;
  cryptoControl.hashFault = false;
  cryptoControl.calls.length = 0;
  cryptoControl.returnedBuffers.length = 0;
});

describe("known-vector hashing", () => {
  it("exposes the fixed version and literal domain", () => {
    expect(COMMERCE_GRANT_HASH_VERSION).toBe(1);
    expect(COMMERCE_GRANT_TOKEN_DOMAIN).toBe(
      "openarc.control.authorization-grant.v1",
    );
  });

  it("hashes as SHA256(UTF8 domain + NUL + full canonical token)", () => {
    expect(hashCommerceGrantToken(TOKEN1)).toBe(
      sha256Hex(`${DOMAIN}${NUL}${TOKEN1}`),
    );
    expect(hashCommerceGrantToken(TOKEN2)).toBe(
      sha256Hex(`${DOMAIN}${NUL}${TOKEN2}`),
    );
  });

  it("returns 64 lower-case hex characters", () => {
    expect(hashCommerceGrantToken(TOKEN1)).toMatch(/^[0-9a-f]{64}$/u);
  });

  it("differs from a hash over another domain for the same payload", () => {
    const otherDomain =
      "openarc.control.commerce-session.v1";
    expect(hashCommerceGrantToken(TOKEN1)).not.toBe(
      sha256Hex(`${otherDomain}${NUL}${TOKEN1}`),
    );
  });

  it("binds the NUL separator and the full prefix", () => {
    const withNul = hashCommerceGrantToken(TOKEN1);
    expect(withNul).not.toBe(sha256Hex(`${DOMAIN}${TOKEN1}`));
    expect(withNul).not.toBe(sha256Hex(`${DOMAIN}${NUL}${P1}`));
  });
});

describe("CSPRNG generation", () => {
  it("calls randomBytes(32) and preserves all 32 bytes without masking", () => {
    const bytes = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
    cryptoControl.deterministic = bytes;
    const token = generateCommerceGrantToken();
    expect(cryptoControl.calls.at(-1)).toEqual([32]);
    expect(token).toBe(`${PREFIX}${Buffer.from(bytes).toString("base64url")}`);
    const decoded = Buffer.from(token.slice(PREFIX.length), "base64url");
    expect(decoded).toHaveLength(32);
    expect(decoded.equals(Buffer.from(bytes))).toBe(true);
    // The fixture includes high bits (e.g. 0xff), so any masking would differ.
    expect(bytes[31]).toBe((31 * 7 + 3) & 0xff);
  });

  it("generates canonical schema-valid tokens", () => {
    const token = generateCommerceGrantToken();
    expect(token.startsWith(PREFIX)).toBe(true);
    expect(token).toHaveLength(PREFIX.length + 43);
    const payload = token.slice(PREFIX.length);
    expect(payload).toMatch(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u);
    expect(Buffer.from(payload, "base64url")).toHaveLength(32);
  });

  it("produces distinct tokens across calls", () => {
    expect(generateCommerceGrantToken()).not.toBe(
      generateCommerceGrantToken(),
    );
  });
});

describe("strict rejection with fixed non-echoing error", () => {
  const rejects = (value: unknown): void => {
    let caught: unknown;
    try {
      hashCommerceGrantToken(value);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(CommerceGrantCryptoError);
    expect((caught as CommerceGrantCryptoError).code).toBe("INVALID_TOKEN");
    if (typeof value === "string" && value.length > 0) {
      expect(JSON.stringify(caught)).not.toContain(value);
    }
  };

  it.each([
    ["missing prefix", P1],
    ["too short", `${PREFIX}${"A".repeat(42)}`],
    ["too long", `${PREFIX}${"A".repeat(44)}`],
    ["noncanonical final bits", `${PREFIX}${"A".repeat(42)}B`],
    ["padded base64", `${PREFIX}${"A".repeat(42)}=`],
    ["trailing newline", `${TOKEN1}\n`],
    ["trailing space", `${TOKEN1} `],
    ["leading space", ` ${TOKEN1}`],
    ["wrong version", `oag_v2_${P1}`],
    ["session namespace", `oacs_v1_${P1}`],
    ["handoff namespace", `oach_v1_${P1}`],
    ["machine agent namespace", `oas_ag_${P1}`],
    ["machine provider namespace", `oas_pr_${P1}`],
    ["old oac namespace", `oac_${P1}`],
    ["empty", ""],
  ])("rejects %s", (_label, value) => {
    rejects(value);
  });

  it("rejects non-string values without normalizing", () => {
    for (const value of [undefined, null, 42, {}, [], true]) {
      rejects(value);
    }
    rejects(Buffer.from(TOKEN1));
  });

  it("does not trim or normalize a valid token wrapped in whitespace", () => {
    rejects(`\t${TOKEN1}`);
    rejects(`${TOKEN1}\r`);
  });

  it("does not echo the malformed value in the error", () => {
    const canary = `${TOKEN1}\n`;
    let caught: unknown;
    try {
      hashCommerceGrantToken(canary);
    } catch (error) {
      caught = error;
    }
    expect(JSON.stringify(caught)).not.toContain(canary);
    expect(JSON.stringify(caught)).not.toContain("A".repeat(43));
  });
});

describe("generation and hashing failure is a fixed input-free error", () => {
  const capture = (fn: () => unknown): unknown => {
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
    const caught = capture(generateCommerceGrantToken);
    expect(caught).toBeInstanceOf(CommerceGrantCryptoError);
    expect((caught as CommerceGrantCryptoError).code).toBe("CRYPTO_FAILURE");
    expect(JSON.stringify(caught)).not.toContain("PRIVATE_GRANT_RNG_CANARY");
  });

  it("maps an undersized CSPRNG result to CRYPTO_FAILURE", () => {
    cryptoControl.rngFault = "short";
    const caught = capture(generateCommerceGrantToken);
    expect(caught).toBeInstanceOf(CommerceGrantCryptoError);
    expect((caught as CommerceGrantCryptoError).code).toBe("CRYPTO_FAILURE");
  });

  it("maps a throwing hash primitive to CRYPTO_FAILURE with no cause leak", () => {
    cryptoControl.hashFault = true;
    const caught = capture(() => hashCommerceGrantToken(TOKEN1));
    expect(caught).toBeInstanceOf(CommerceGrantCryptoError);
    expect((caught as CommerceGrantCryptoError).code).toBe("CRYPTO_FAILURE");
    expect(JSON.stringify(caught)).not.toContain("PRIVATE_GRANT_HASH_CANARY");
  });

  it("rejects malformed input before ever calling the hash primitive", () => {
    cryptoControl.hashFault = true;
    const caught = capture(() => hashCommerceGrantToken(`${TOKEN1}\n`));
    // If the malformed token reached createHash, the armed fault would surface
    // as CRYPTO_FAILURE instead.
    expect(caught).toBeInstanceOf(CommerceGrantCryptoError);
    expect((caught as CommerceGrantCryptoError).code).toBe("INVALID_TOKEN");
    expect(cryptoControl.returnedBuffers).toHaveLength(0);
  });

  it("recovers to a valid generated token after the RNG fault clears", () => {
    cryptoControl.rngFault = "throw";
    expect(capture(generateCommerceGrantToken)).toBeInstanceOf(
      CommerceGrantCryptoError,
    );
    cryptoControl.rngFault = null;
    expect(generateCommerceGrantToken()).toMatch(
      new RegExp(`^${PREFIX}[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`, "u"),
    );
  });

  it("zeroes the exact entropy buffer after successful generation", () => {
    const bytes = Uint8Array.from({ length: 32 }, () => 0xff);
    const original = Buffer.from(bytes);
    cryptoControl.deterministic = bytes;
    const returned = generateCommerceGrantToken();
    // The module received exactly one buffer from randomBytes and zeroed it.
    expect(cryptoControl.returnedBuffers).toHaveLength(1);
    expect(cryptoControl.returnedBuffers[0]?.every((b) => b === 0)).toBe(true);
    // The caller's fixture is untouched.
    expect(Buffer.from(bytes).equals(original)).toBe(true);
    expect(returned).toMatch(
      new RegExp(`^${PREFIX}[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`, "u"),
    );
  });

  it("zeroes the exact entropy buffer on short-buffer failure", () => {
    cryptoControl.rngFault = "short";
    const caught = capture(generateCommerceGrantToken);
    expect((caught as CommerceGrantCryptoError).code).toBe("CRYPTO_FAILURE");
    expect(cryptoControl.returnedBuffers).toHaveLength(1);
    expect(cryptoControl.returnedBuffers[0]?.every((b) => b === 0)).toBe(true);
  });
});
