/**
 * `@openarc/agent-harness` — a headless buyer agent that drives the whole x402
 * lane against a LOCAL OpenArc stack with local fakes.
 *
 * It never contacts Circle, Gateway or Arc, never holds a persistent key and
 * never sends a live payment. `--live-testnet` is a refusing stub.
 */
export {
  createReuseHandle,
  runBuyerFlow,
  type HarnessRunOptions,
  type HarnessRunResult,
  type ReuseHandle,
} from "./run.js";
export {
  HARNESS_REPORT_SCHEMA,
  HarnessSecretLeak,
  assertSecretFree,
  type HarnessOutcome,
  type HarnessRefusalReport,
  type HarnessRunReport,
  type HarnessStep,
} from "./report.js";
export {
  HarnessRefusal,
  assertLoopbackOrigin,
  assertLoopbackUrl,
  type HarnessRefusalCode,
} from "./loopback.js";
export { createLoopbackFacilitatorFetch } from "./facilitator-fetch.js";
export {
  LIVE_TESTNET_EXIT_CODE,
  LIVE_TESTNET_PREREQUISITES,
  liveTestnetStub,
} from "./live-testnet.js";
export {
  EXIT_CONFIG_REFUSED,
  EXIT_DELIVERED,
  EXIT_HELD,
  EXIT_REFUSED,
  SESSION_TOKEN_ENV,
  main,
  parseCliArgs,
  type ParsedCli,
} from "./cli.js";
export { AgentApiClient, type AgentApiOptions, type ApiResult } from "./api-client.js";
