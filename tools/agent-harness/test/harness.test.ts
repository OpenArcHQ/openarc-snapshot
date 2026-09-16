import { describe, expect, it } from "vitest";

import {
  EXIT_CONFIG_REFUSED,
  HarnessRefusal,
  HarnessSecretLeak,
  LIVE_TESTNET_EXIT_CODE,
  SESSION_TOKEN_ENV,
  assertLoopbackOrigin,
  assertLoopbackUrl,
  assertSecretFree,
  createLoopbackFacilitatorFetch,
  liveTestnetStub,
  main,
  parseCliArgs,
  runBuyerFlow,
} from "../src/index.js";

/**
 * Offline unit proofs for the harness guards. No API, no provider, no
 * facilitator and no key: these cover exactly the refusals that must happen
 * BEFORE any of those exist.
 */

const TOKEN = `oacs_v1_${"C".repeat(42)}Q`;
const LISTING = "openarc:listing:12345678-1234-4234-8123-123456789abc";

describe("loopback admission", () => {
  it.each([
    "https://gateway-api-testnet.circle.com",
    "https://api.openarc.example",
    "http://169.254.169.254",
    "http://user:pw@127.0.0.1:3000",
    "file:///etc/hosts",
    "127.0.0.1:3000",
  ])("refuses %s", (value) => {
    expect(() => assertLoopbackOrigin(value, "apiBaseUrl")).toThrow(HarnessRefusal);
  });

  it("accepts only loopback hosts", () => {
    expect(assertLoopbackOrigin("http://127.0.0.1:3000/ignored", "f")).toBe("http://127.0.0.1:3000");
    expect(assertLoopbackUrl("http://localhost:8080/v1/sum", "f")).toBe("http://localhost:8080/v1/sum");
  });

  it("refuses a facilitator transport that is not loopback", () => {
    expect(() => createLoopbackFacilitatorFetch("https://gateway-api-testnet.circle.com")).toThrow(
      HarnessRefusal,
    );
  });

  it("refuses a non-loopback run before any request, with zero attempts", async () => {
    const { report, reuse } = await runBuyerFlow({
      apiBaseUrl: "https://api.openarc.example",
      providerResourceUrl: "http://127.0.0.1:1/v1/sum",
      facilitatorUrl: "http://127.0.0.1:1",
      commerceSessionToken: TOKEN,
      listingId: LISTING,
      input: { a: 1, b: 2 },
    });
    expect(report.outcome).toBe("refused");
    expect(report.refusal).toMatchObject({ stage: "config", code: "non_loopback_url" });
    expect(report.ids.attemptId).toBeNull();
    expect(report.lane.sends).toBe(0);
    expect(reuse).toBeNull();
  });

  it("refuses a non-loopback facilitator even when the API is loopback", async () => {
    const { report } = await runBuyerFlow({
      apiBaseUrl: "http://127.0.0.1:1",
      providerResourceUrl: "http://127.0.0.1:1/v1/sum",
      facilitatorUrl: "https://gateway-api-testnet.circle.com",
      commerceSessionToken: TOKEN,
      listingId: LISTING,
      input: { a: 1, b: 2 },
    });
    expect(report.refusal).toMatchObject({ code: "non_loopback_url", apiCode: "facilitatorUrl" });
    expect(report.lane.sends).toBe(0);
  });
});

describe("the report is secret-free", () => {
  it("rejects a held secret and every credential namespace", () => {
    expect(() => assertSecretFree({ note: "clean" }, [TOKEN])).not.toThrow();
    expect(() => assertSecretFree({ token: TOKEN }, [TOKEN])).toThrow(HarnessSecretLeak);
    for (const leak of [
      { t: `oag_v1_${"F".repeat(43)}` },
      { t: `oas_pr_${"D".repeat(43)}` },
      { t: `oas_ag_${"E".repeat(43)}` },
      { t: `oach_v1_${"B".repeat(43)}` },
      { t: `0x${"a".repeat(130)}` },
    ]) {
      expect(() => assertSecretFree(leak, [])).toThrow(HarnessSecretLeak);
    }
  });
});

describe("the live-testnet stub", () => {
  it("never sends: it exits non-zero and states the user-owned prerequisites", async () => {
    const stub = liveTestnetStub();
    expect(stub.exitCode).toBeGreaterThan(0);
    expect(stub.text).toContain("NOT implemented");
    expect(stub.text).toContain("DISPOSABLE buyer wallet");
    expect(stub.text).toContain("faucet");
    expect(stub.text).toContain("approve");
    expect(stub.text).toContain("deposit");

    const written: string[] = [];
    const code = await main(["--live-testnet"], {}, (text) => written.push(text));
    expect(code).toBe(LIVE_TESTNET_EXIT_CODE);
    expect(written.join("")).toContain("P04-07 prerequisites");
  });
});

describe("the CLI", () => {
  it("requires every endpoint and never defaults one", () => {
    expect(parseCliArgs(["--api", "http://127.0.0.1:1"])).toMatchObject({
      error: "missing_argument:--provider",
    });
    expect(parseCliArgs(["--api", "http://127.0.0.1:1", "--api", "http://127.0.0.1:2"])).toMatchObject({
      error: "repeated_argument:--api",
    });
    expect(parseCliArgs(["--facilitator"])).toMatchObject({ error: "missing_value:--facilitator" });
    expect(parseCliArgs(["--live-testnet"])).toMatchObject({ liveTestnet: true });
  });

  it("takes the commerce session from the environment, never from argv", async () => {
    const written: string[] = [];
    const argv = [
      "--api", "http://127.0.0.1:1",
      "--provider", "http://127.0.0.1:1/v1/sum",
      "--facilitator", "http://127.0.0.1:1",
      "--listing", LISTING,
      "--a", "2",
      "--b", "3",
    ];
    const code = await main(argv, {}, (text) => written.push(text));
    expect(code).toBe(EXIT_CONFIG_REFUSED);
    const report = JSON.parse(written.join("")) as { refusal: { apiCode: string } };
    expect(report.refusal.apiCode).toBe(SESSION_TOKEN_ENV);
    expect(written.join("")).not.toContain("oacs_v1_");
  });
});
