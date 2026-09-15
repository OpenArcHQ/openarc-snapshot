import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { controlEvidenceSha256Hex } from "../src/commerce/control-evidence-projection.js";
import { sha256HexUtf8 } from "../src/sha256.js";
import { sha256HexUtf8 as vaultSha256HexUtf8 } from "../src/vault-root-kinds.js";

const reference = (value: string) => createHash("sha256").update(new TextEncoder().encode(value)).digest("hex");

describe("shared SHA-256", () => {
  it("matches the FIPS 180-4 vectors", () => {
    expect(sha256HexUtf8("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256HexUtf8("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(sha256HexUtf8("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
      .toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  });

  it("encodes lone surrogates exactly as TextEncoder (U+FFFD) at every padding boundary", () => {
    for (const length of [0, 1, 54, 55, 56, 63, 64, 65, 119, 120, 1000]) {
      for (const probe of ["a", "\u00e9", "\u4e2d", "\ud83d\ude00", "\ud800", "\udc00", "x\ud800y", "\udc00\ud800"]) {
        const value = probe.repeat(Math.max(1, Math.ceil(length / probe.length))).slice(0, Math.max(length, probe.length));
        expect(sha256HexUtf8(value)).toBe(reference(value));
      }
    }
  });

  it("is the single implementation behind the Vault and evidence helpers", () => {
    for (const value of ["", "evidence", "\ud800", JSON.stringify({ a: "\u4e2d", b: [1, 2] })]) {
      expect(controlEvidenceSha256Hex(value)).toBe(sha256HexUtf8(value));
      expect(vaultSha256HexUtf8(value)).toBe(sha256HexUtf8(value));
    }
  });
});
