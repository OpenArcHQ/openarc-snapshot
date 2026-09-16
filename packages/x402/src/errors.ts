/**
 * Every lane refusal is an `X402LaneError` with a closed `code`. Messages and
 * `issues` carry field paths and codes only: never a received value, a
 * signature, a nonce or any key material, so an error can be logged safely.
 */
export type X402LaneErrorCode =
  | "unknown_network"
  | "facilitator_origin_rejected"
  | "invalid_config"
  | "invalid_requirement"
  | "invalid_payment_required"
  | "invalid_payment_payload"
  | "invalid_binding"
  | "invalid_amount"
  | "invalid_address"
  | "invalid_nonce"
  | "invalid_clock"
  | "validity_rejected"
  | "grant_mismatch"
  | "signer_mismatch"
  | "signature_mismatch"
  | "wrong_role"
  | "not_persisted"
  | "already_persisted"
  | "persistence_failed"
  | "persistence_mismatch"
  | "already_dispatched"
  | "already_released";

export class X402LaneError extends Error {
  readonly code: X402LaneErrorCode;
  readonly issues: readonly string[];

  constructor(code: X402LaneErrorCode, issues: readonly string[] = []) {
    super(issues.length > 0 ? `${code}: ${issues.join(", ")}` : code);
    this.name = "X402LaneError";
    this.code = code;
    this.issues = Object.freeze([...issues]);
  }
}

/** Reduce zod issues to `path:code` strings; received values never leak. */
export function issuePaths(
  issues: readonly { readonly path: readonly PropertyKey[]; readonly code: string }[],
): string[] {
  return issues.map((issue) => {
    const path = issue.path.map((segment) => String(segment)).join(".");
    return `${path === "" ? "<root>" : path}:${issue.code}`;
  });
}
