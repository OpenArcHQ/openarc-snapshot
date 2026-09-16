#!/usr/bin/env node
/**
 * Headless buyer-agent CLI.
 *
 * OFFLINE BY CONSTRUCTION. Every endpoint must be loopback; there is no
 * default URL, no live fallback and no environment variable that widens this.
 * `--live-testnet` is a refusing stub that prints the P04-07 prerequisites and
 * exits non-zero.
 *
 * The commerce session is read from the environment, never from argv, so it
 * cannot appear in a process listing. Output is the structured, secret-free run
 * report on stdout; nothing else is ever printed.
 */
import { HarnessRefusal } from "./loopback.js";
import { LIVE_TESTNET_EXIT_CODE, liveTestnetStub } from "./live-testnet.js";
import { HARNESS_REPORT_SCHEMA } from "./report.js";
import { runBuyerFlow, type HarnessRunOptions } from "./run.js";

export const EXIT_DELIVERED = 0;
export const EXIT_HELD = 3;
export const EXIT_REFUSED = 4;
export const EXIT_CONFIG_REFUSED = 64;

export const SESSION_TOKEN_ENV = "OPENARC_COMMERCE_SESSION_TOKEN";

export interface ParsedCli {
  readonly liveTestnet: boolean;
  readonly api: string;
  readonly provider: string;
  readonly facilitator: string;
  readonly rpc: string | null;
  readonly listing: string;
  readonly a: number;
  readonly b: number;
}

const FLAGS = ["--api", "--provider", "--facilitator", "--rpc", "--listing", "--a", "--b"] as const;

/** Pure argv parser. A missing or repeated flag is a refusal, never a default. */
export function parseCliArgs(argv: readonly string[]): ParsedCli | { readonly error: string } {
  const values = new Map<string, string>();
  let liveTestnet = false;
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index] as string;
    if (token === "--live-testnet") {
      liveTestnet = true;
      continue;
    }
    if (!(FLAGS as readonly string[]).includes(token)) {
      return { error: `unknown_argument:${token.startsWith("--") ? token : "<value>"}` };
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) return { error: `missing_value:${token}` };
    if (values.has(token)) return { error: `repeated_argument:${token}` };
    values.set(token, value);
    index += 1;
  }
  if (liveTestnet) {
    return {
      liveTestnet: true,
      api: "",
      provider: "",
      facilitator: "",
      rpc: null,
      listing: "",
      a: 0,
      b: 0,
    };
  }
  for (const flag of ["--api", "--provider", "--facilitator", "--listing", "--a", "--b"]) {
    if (!values.has(flag)) return { error: `missing_argument:${flag}` };
  }
  const a = Number(values.get("--a"));
  const b = Number(values.get("--b"));
  if (!Number.isInteger(a) || !Number.isInteger(b)) return { error: "input_invalid" };
  return {
    liveTestnet: false,
    api: values.get("--api") as string,
    provider: values.get("--provider") as string,
    facilitator: values.get("--facilitator") as string,
    rpc: values.get("--rpc") ?? null,
    listing: values.get("--listing") as string,
    a,
    b,
  };
}

function refusalReport(code: string, field: string | null): string {
  return JSON.stringify({
    schemaVersion: HARNESS_REPORT_SCHEMA,
    mode: "offline_fake",
    outcome: "refused",
    refusal: { stage: "config", code, httpStatus: null, apiCode: field },
  });
}

export async function main(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  write: (text: string) => void,
): Promise<number> {
  const parsed = parseCliArgs(argv);
  if ("error" in parsed) {
    write(`${refusalReport("arguments_invalid", parsed.error)}\n`);
    return EXIT_CONFIG_REFUSED;
  }
  if (parsed.liveTestnet) {
    // NOT IMPLEMENTED and never sending. The user owns every prerequisite.
    write(liveTestnetStub().text);
    return LIVE_TESTNET_EXIT_CODE;
  }
  const token = env[SESSION_TOKEN_ENV];
  if (typeof token !== "string" || token.length === 0) {
    write(`${refusalReport("commerce_token_invalid", SESSION_TOKEN_ENV)}\n`);
    return EXIT_CONFIG_REFUSED;
  }
  const options: HarnessRunOptions = {
    apiBaseUrl: parsed.api,
    providerResourceUrl: parsed.provider,
    facilitatorUrl: parsed.facilitator,
    ...(parsed.rpc === null ? {} : { rpcUrl: parsed.rpc }),
    commerceSessionToken: token,
    listingId: parsed.listing,
    input: { a: parsed.a, b: parsed.b },
  };
  let report;
  try {
    ({ report } = await runBuyerFlow(options));
  } catch (error) {
    const code = error instanceof HarnessRefusal ? error.code : "run_failed";
    write(`${refusalReport(code, null)}\n`);
    return EXIT_CONFIG_REFUSED;
  }
  write(`${JSON.stringify(report)}\n`);
  if (report.outcome === "delivered") return EXIT_DELIVERED;
  if (report.outcome === "held") return EXIT_HELD;
  return report.refusal?.stage === "config" ? EXIT_CONFIG_REFUSED : EXIT_REFUSED;
}

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`;

if (invokedDirectly) {
  void main(process.argv.slice(2), process.env, (text) => process.stdout.write(text)).then(
    (code) => {
      process.exitCode = code;
    },
    () => {
      process.exitCode = EXIT_CONFIG_REFUSED;
    },
  );
}
