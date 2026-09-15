import { describe, expect, expectTypeOf, it } from "vitest";

import {
  CommerceGrantIdSchema,
  CommerceGrantTokenSchema,
  type CommerceGrantId,
  type CommerceGrantToken,
} from "../src/index.js";
import {
  CommerceGrantIdSchema as MODULE_GRANT_ID,
  CommerceGrantTokenSchema as MODULE_GRANT_TOKEN,
} from "../src/commerce/control-grant.js";

// Canonical lower-case UUIDv4 and a second distinct one.
const V4 = "12345678-1234-4234-8123-123456789abc";
const V4_B = "87654321-4321-4321-b123-cba987654321";
const GRANT_ID = `openarc:grant:${V4}`;

// Canonical 43-char base64url payloads whose final character carries zero
// padding bits; only synthetic values, never a live secret.
const P1 = "A".repeat(43);
const GRANT_TOKEN = `oag_v1_${P1}`;

describe("CommerceGrantIdSchema", () => {
  it("accepts a canonical openarc:grant: lower-case UUIDv4", () => {
    expect(CommerceGrantIdSchema.safeParse(GRANT_ID).success).toBe(true);
    expect(
      CommerceGrantIdSchema.safeParse(`openarc:grant:${V4_B}`).success,
    ).toBe(true);
  });

  it("is the same schema from the module and the index barrel", () => {
    expect(MODULE_GRANT_ID).toBe(CommerceGrantIdSchema);
    expect(MODULE_GRANT_TOKEN).toBe(CommerceGrantTokenSchema);
  });

  it.each([
    ["wrong prefix", `openarc:session:${V4}`],
    ["machine namespace", `openarc:agent:${V4}`],
    ["bare uuid", V4],
    ["upper-case hex", `openarc:grant:${V4.toUpperCase()}`],
    ["version 3", `openarc:grant:12345678-1234-3234-8123-123456789abc`],
    ["bad variant", `openarc:grant:12345678-1234-4234-7123-123456789abc`],
    ["trailing LF", `${GRANT_ID}\n`],
    ["trailing space", `${GRANT_ID} `],
    ["leading space", ` ${GRANT_ID}`],
    ["empty", ""],
  ])("rejects %s", (_label, value) => {
    expect(CommerceGrantIdSchema.safeParse(value).success).toBe(false);
  });

  it("rejects non-string values", () => {
    for (const value of [undefined, null, 42, {}, [], true]) {
      expect(CommerceGrantIdSchema.safeParse(value).success).toBe(false);
    }
  });
});

describe("CommerceGrantTokenSchema", () => {
  it("accepts a canonical oag_v1_ token with zero final padding bits", () => {
    expect(CommerceGrantTokenSchema.safeParse(GRANT_TOKEN).success).toBe(true);
    expect(
      CommerceGrantTokenSchema.safeParse(`oag_v1_${"B".repeat(42)}A`).success,
    ).toBe(true);
    expect(
      CommerceGrantTokenSchema.safeParse(`oag_v1_${"0".repeat(42)}8`).success,
    ).toBe(true);
  });

  it.each([
    ["missing prefix", P1],
    ["too short", `oag_v1_${"A".repeat(42)}`],
    ["too long", `oag_v1_${"A".repeat(44)}`],
    ["noncanonical final bits", `oag_v1_${"A".repeat(42)}B`],
    ["padded base64", `oag_v1_${"A".repeat(42)}=`],
    ["trailing newline", `${GRANT_TOKEN}\n`],
    ["trailing space", `${GRANT_TOKEN} `],
    ["leading space", ` ${GRANT_TOKEN}`],
    ["wrong version", `oag_v2_${P1}`],
    ["upper-case prefix", `OAG_V1_${P1}`],
    ["session namespace", `oacs_v1_${P1}`],
    ["handoff namespace", `oach_v1_${P1}`],
    ["machine agent namespace", `oas_ag_${P1}`],
    ["machine provider namespace", `oas_pr_${P1}`],
    ["old oac namespace", `oac_${P1}`],
    ["provider-ish namespace", `prov_v1_${P1}`],
    ["empty", ""],
  ])("rejects %s", (_label, value) => {
    expect(CommerceGrantTokenSchema.safeParse(value).success).toBe(false);
  });

  it("rejects non-string values", () => {
    for (const value of [undefined, null, 42, {}, [], true]) {
      expect(CommerceGrantTokenSchema.safeParse(value).success).toBe(false);
    }
  });

  it("strict safeParse stays total and non-echoing on malformed input", () => {
    const malformed = `${GRANT_TOKEN}\n`;
    const result = CommerceGrantTokenSchema.safeParse(malformed);
    expect(result.success).toBe(false);
    expect(JSON.stringify(result)).not.toContain(malformed);
  });

  it("keeps precise inferred types", () => {
    expectTypeOf<CommerceGrantId>().toBeString();
    expectTypeOf<CommerceGrantToken>().toBeString();
    expectTypeOf<CommerceGrantId>().toEqualTypeOf<string>();
    expectTypeOf<CommerceGrantToken>().toEqualTypeOf<string>();
  });
});
