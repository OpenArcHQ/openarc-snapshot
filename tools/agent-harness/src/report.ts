/**
 * The harness run report: structured, bounded and SECRET-FREE by construction.
 *
 * No field can hold a credential, a private key, a signature or a nonce. The
 * commerce session, the grant token and the ephemeral key never enter it, and
 * `assertSecretFree` re-checks the serialized report against the exact secret
 * values the run held plus every credential prefix before it is returned. A
 * violation throws WITHOUT printing the offending text.
 */

export const HARNESS_REPORT_SCHEMA = "openarc.agent-harness.run-report.v1" as const;

export type HarnessOutcome = "delivered" | "held" | "refused";

export interface HarnessStep {
  readonly step: string;
  readonly ok: boolean;
  readonly httpStatus: number | null;
  readonly code: string | null;
}

export interface HarnessRefusalReport {
  readonly stage: string;
  readonly code: string;
  readonly httpStatus: number | null;
  readonly apiCode: string | null;
}

export interface HarnessRunReport {
  readonly schemaVersion: typeof HARNESS_REPORT_SCHEMA;
  /** There is no live mode. A live run is a refusing stub. */
  readonly mode: "offline_fake";
  readonly outcome: HarnessOutcome;
  readonly refusal: HarnessRefusalReport | null;
  readonly steps: readonly HarnessStep[];
  readonly ids: {
    readonly requirementId: string | null;
    readonly actionId: string | null;
    readonly grantId: string | null;
    readonly attemptId: string | null;
  };
  readonly payment: {
    readonly network: string;
    readonly payerAddress: string;
    readonly payToAddress: string;
    readonly amountAtomic: string;
    readonly bindingDigest: string;
    readonly laneRequirementDigest: string;
  } | null;
  /** The lane rules this run actually observed. */
  readonly lane: {
    readonly persistedBeforeDispatch: boolean;
    readonly dispatchRecorded: boolean;
    readonly sends: 0 | 1;
    readonly resigned: false;
    readonly releasedUnsent: boolean;
    readonly transport: "returned" | "threw" | "not_sent";
  };
  readonly resource: {
    readonly delivered: boolean;
    readonly providerHttpStatus: number | null;
    readonly providerStatus: string | null;
  };
  /** The lane's own classification of the attempt, from the fake's report. */
  readonly exposure: {
    readonly state: string;
    readonly disposition: string;
    readonly reason: string | null;
    readonly gatewayStatus: string | null;
    readonly transferId: string | null;
  } | null;
  /** What the OpenArc API says the durable attempt is. Never "settled". */
  readonly apiAttempt: {
    readonly state: string;
    readonly dispatched: boolean;
    readonly observed: boolean;
  } | null;
}

/** Credential namespaces and a 65-byte signature. None may ever be emitted. */
const FORBIDDEN_PATTERNS: readonly RegExp[] = Object.freeze([
  /oacs_v1_/u,
  /oag_v1_/u,
  /oach_v1_/u,
  /oas_ag_/u,
  /oas_pr_/u,
  /0x[0-9a-fA-F]{130}/u,
]);

export class HarnessSecretLeak extends Error {
  constructor() {
    // The offending text is deliberately NOT included.
    super("HARNESS_REPORT_SECRET_LEAK");
    this.name = "HarnessSecretLeak";
  }
}

/**
 * Throws if the serialized report contains any held secret or any credential
 * namespace. Called on every report before it is returned or printed.
 */
export function assertSecretFree(report: unknown, heldSecrets: readonly string[]): void {
  const serialized = JSON.stringify(report);
  if (serialized === undefined) throw new HarnessSecretLeak();
  for (const secret of heldSecrets) {
    if (secret.length > 0 && serialized.includes(secret)) throw new HarnessSecretLeak();
  }
  for (const pattern of FORBIDDEN_PATTERNS) {
    if (pattern.test(serialized)) throw new HarnessSecretLeak();
  }
}
