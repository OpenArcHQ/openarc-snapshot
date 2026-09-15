import { useEffect, useMemo, useState } from "react";

import type { CommerceAgentProfile, CommercePolicyContent } from "@openarc/shared";

import {
  buildPolicyContent,
  formatUsdcFromAtomic,
  parseCanonicalIdList,
  parseUsdcToAtomic,
} from "./policy-controller.js";

// Explicit policy-revision editor.
//
// The subject agent is chosen from the EXISTING current-organization agent read
// state (never a machine profile and never a new endpoint). Caps are canonical
// USDC decimals converted with strings/BigInt to 6-decimal atomic strings; zero
// is a valid deny-all and no float is used. At least one of per-action or
// rolling cap must be present, a rolling limit requires its paired duration,
// and the fee cap is required. Both empty allowlists mean deny-all; both
// populated intersect. Approval is none/always/above with `separateApprover`
// and an optional UTC expiry, using the accepted schema with no invented
// defaults.

interface PolicyFormValues {
  readonly subjectAgentId: string;
  readonly perActionLimit: string;
  readonly rollingLimit: string;
  readonly rollingWindowSeconds: string;
  readonly feeLimit: string;
  readonly allowedProviderIds: string;
  readonly allowedListingIds: string;
  readonly approvalMode: "none" | "always" | "above";
  readonly approvalThreshold: string;
  readonly separateApprover: boolean;
  readonly expiresAt: string;
}

function emptyForm(subjectAgentId = ""): PolicyFormValues {
  return {
    subjectAgentId,
    perActionLimit: "",
    rollingLimit: "",
    rollingWindowSeconds: "",
    feeLimit: "",
    allowedProviderIds: "",
    allowedListingIds: "",
    approvalMode: "none",
    approvalThreshold: "",
    separateApprover: false,
    expiresAt: "",
  };
}

export function emptyPolicyForm(subjectAgentId = ""): PolicyFormValues {
  return emptyForm(subjectAgentId);
}

function toUtcExpiry(input: string): string | null {
  const trimmed = input.trim();
  if (trimmed.length === 0) return null;
  const parsed = Date.parse(trimmed);
  if (!Number.isFinite(parsed)) return null;
  return new Date(parsed).toISOString();
}

export function formToContent(
  values: PolicyFormValues,
  organizationId: string,
): CommercePolicyContent | null {
  const perActionRaw = values.perActionLimit.trim();
  const rollingRaw = values.rollingLimit.trim();
  if (perActionRaw.length === 0 && rollingRaw.length === 0) return null;
  const perActionLimit = perActionRaw.length === 0 ? null : parseUsdcToAtomic(perActionRaw);
  if (perActionRaw.length > 0 && perActionLimit === null) return null;
  const rollingLimit = rollingRaw.length === 0 ? null : parseUsdcToAtomic(rollingRaw);
  if (rollingRaw.length > 0 && rollingLimit === null) return null;
  const windowRaw = values.rollingWindowSeconds.trim();
  if (rollingLimit === null && windowRaw.length > 0) return null;
  if (rollingLimit !== null && !/^[1-9][0-9]{0,8}$/u.test(windowRaw)) return null;
  const feeLimit = parseUsdcToAtomic(values.feeLimit.trim());
  if (feeLimit === null) return null;
  const allowedProviderIds = parseCanonicalIdList(values.allowedProviderIds, "provider");
  if (allowedProviderIds === null) return null;
  const allowedListingIds = parseCanonicalIdList(values.allowedListingIds, "listing");
  if (allowedListingIds === null) return null;
  const approval =
    values.approvalMode === "above"
      ? {
          threshold: parseUsdcToAtomic(values.approvalThreshold.trim()),
          separateApprover: values.separateApprover,
        }
      : { threshold: null, separateApprover: values.approvalMode === "always" ? values.separateApprover : false };
  if (values.approvalMode === "above" && approval.threshold === null) return null;
  const expiresRaw = values.expiresAt.trim();
  let expiresAt: string | null = null;
  if (expiresRaw.length > 0) {
    expiresAt = toUtcExpiry(expiresRaw);
    if (expiresAt === null) return null;
  }
  return buildPolicyContent({
    organizationId,
    subjectAgentId: values.subjectAgentId,
    perActionLimit,
    rollingLimit,
    rollingWindowSeconds: rollingLimit === null ? null : windowRaw,
    feeLimit,
    allowedProviderIds,
    allowedListingIds,
    approval: {
      mode: values.approvalMode,
      threshold: approval.threshold,
      separateApprover: approval.separateApprover,
    },
    expiresAt,
  });
}

function helpText(): string {
  return [
    "Amounts are canonical TestnetUSDC decimals with at most 6 fractional digits; a zero cap is an explicit deny-all.",
    "At least one cap is required. A rolling cap requires its paired duration in seconds (1..2592000).",
    "Leave both allowlists empty for deny-all. Populating both intersects them. One canonical id per line, ascending unique.",
    "Approval is none, always, or above a positive threshold. `above` needs a separate approver flag.",
    "An expiry is optional UTC ISO 8601 and must strictly follow the policy revision's creation time.",
  ].join(" ");
}

export function PolicyEditorPanel(props: {
  readonly mode: "create";
  readonly organizationId: string;
  readonly agents: readonly CommerceAgentProfile[];
  readonly agentsStatus: "none" | "loading" | "ready" | "error";
  readonly onLoadAgents: () => void;
  readonly onLoadMoreAgents: () => void;
  readonly hasNextAgents: boolean;
  readonly prefill: CommercePolicyContent | null;
  readonly canWrite: boolean;
  readonly onSubmit: (content: CommercePolicyContent) => void;
  readonly onCancel: () => void;
}) {
  const firstActive = props.agents.find((agent) => agent.status === "active")?.agentId ?? "";
  const [values, setValues] = useState<PolicyFormValues>(() => emptyForm(firstActive));
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (values.subjectAgentId.length > 0) return;
    if (firstActive.length === 0) return;
    setValues((current) =>
      current.subjectAgentId.length > 0 ? current : { ...current, subjectAgentId: firstActive },
    );
  }, [firstActive, values.subjectAgentId]);

  const content = useMemo(
    () => formToContent(values, props.organizationId),
    [values, props.organizationId],
  );

  const set = (key: keyof PolicyFormValues) => (value: string) => {
    setValues((current) => ({ ...current, [key]: value }));
  };

  const submit = () => {
    if (content === null) {
      setMessage("Some fields are invalid. Fix the highlighted constraints and try again.");
      return;
    }
    props.onSubmit(content);
  };

  return (
    <section className="tenant-policies__editor" aria-labelledby="policy-editor-title">
      <h2 className="tenant-title tenant-title--small" id="policy-editor-title">
        Create policy rules
      </h2>
      <p className="tenant-status" role="status">
        These are policy rules only. No funds are reserved, committed, moved, or executed here.
      </p>
      <fieldset className="tenant-policies__fieldset">
        <legend>Subject and caps</legend>
        <p className="tenant-policies__field">
          <label htmlFor="policy-subject-agent">Subject agent</label>
          {props.agentsStatus === "none" ? (
            <button type="button" className="tenant-button" onClick={props.onLoadAgents}>
              Load agents
            </button>
          ) : null}
          {props.agentsStatus === "loading" ? (
            <span className="tenant-policies__hint" role="status">Loading agents…</span>
          ) : null}
          {props.agentsStatus === "error" ? (
            <span className="tenant-policies__hint tenant-status--error" role="alert">
              Agents could not be loaded. A canonical subject agent id is still required.
            </span>
          ) : null}
          <select
            id="policy-subject-agent"
            value={values.subjectAgentId}
            onChange={(event) => set("subjectAgentId")(event.target.value)}
          >
            <option value="">Choose an active agent…</option>
            {props.agents
              .filter((agent) => agent.status === "active")
              .map((agent) => (
                <option key={agent.agentId} value={agent.agentId}>
                  {agent.displayName}
                </option>
              ))}
          </select>
          <span className="tenant-policies__hint">
            Only active agents of the current organization are offered, from the existing bounded tenant read.
          </span>
          {props.agentsStatus === "ready" && props.hasNextAgents ? (
            <button type="button" className="tenant-button" onClick={props.onLoadMoreAgents}>
              Next agents
            </button>
          ) : null}
        </p>
        <PolicyField
          id="policy-per-action"
          label="Per-action cap (USDC)"
          value={values.perActionLimit}
          onChange={set("perActionLimit")}
          hint="Optional. Zero is a valid deny-all. Exactly at most 6 fractional digits."
        />
        <PolicyField
          id="policy-rolling"
          label="Rolling cap (USDC)"
          value={values.rollingLimit}
          onChange={set("rollingLimit")}
          hint="Optional. Requires the paired rolling window below."
        />
        <PolicyField
          id="policy-rolling-window"
          label="Rolling window (seconds)"
          value={values.rollingWindowSeconds}
          onChange={set("rollingWindowSeconds")}
          hint="Canonical integer seconds 1..2592000. Must be paired with a rolling cap."
        />
        <PolicyField
          id="policy-fee-limit"
          label="Fee cap (USDC)"
          value={values.feeLimit}
          onChange={set("feeLimit")}
          hint="Required. Zero is a valid deny-all fee policy."
        />
      </fieldset>
      <fieldset className="tenant-policies__fieldset">
        <legend>Allowlists</legend>
        <p className="tenant-policies__field">
          <label htmlFor="policy-providers">Allowed provider IDs</label>
          <textarea
            id="policy-providers"
            rows={3}
            value={values.allowedProviderIds}
            onChange={(event) => set("allowedProviderIds")(event.target.value)}
          />
          <span className="tenant-policies__hint">
            One canonical provider id per line, ascending and unique. Empty means deny-all.
          </span>
        </p>
        <p className="tenant-policies__field">
          <label htmlFor="policy-listings">Allowed listing IDs</label>
          <textarea
            id="policy-listings"
            rows={3}
            value={values.allowedListingIds}
            onChange={(event) => set("allowedListingIds")(event.target.value)}
          />
          <span className="tenant-policies__hint">
            One canonical listing id per line, ascending and unique. Both populated intersect.
          </span>
        </p>
      </fieldset>
      <fieldset className="tenant-policies__fieldset">
        <legend>Approval and expiry</legend>
        <p className="tenant-policies__field">
          <label htmlFor="policy-approval-mode">Approval mode</label>
          <select
            id="policy-approval-mode"
            value={values.approvalMode}
            onChange={(event) =>
              setValues((current) => ({
                ...current,
                approvalMode: event.target.value === "always" ? "always" : event.target.value === "above" ? "above" : "none",
              }))
            }
          >
            <option value="none">none</option>
            <option value="always">always</option>
            <option value="above">above</option>
          </select>
        </p>
        {values.approvalMode === "above" ? (
          <PolicyField
            id="policy-approval-threshold"
            label="Approval threshold (USDC)"
            value={values.approvalThreshold}
            onChange={set("approvalThreshold")}
            hint="Positive amount above which a separate approval is required."
          />
        ) : null}
        {values.approvalMode === "none" ? null : (
          <p className="tenant-policies__field">
            <label className="tenant-policies__checkbox">
              <input
                type="checkbox"
                checked={values.separateApprover}
                onChange={(event) =>
                  setValues((current) => ({ ...current, separateApprover: event.target.checked }))
                }
              />
              Require a separate approver
            </label>
          </p>
        )}
        <PolicyField
          id="policy-expiry"
          label="Expiry (UTC, optional)"
          value={values.expiresAt}
          onChange={set("expiresAt")}
          hint="ISO 8601 UTC. It must strictly follow the revision creation time."
        />
      </fieldset>
      <p className="tenant-policies__hint">{helpText()}</p>
      {message === null ? null : (
        <p className="tenant-status tenant-status--error" role="alert">
          {message}
        </p>
      )}
      <div className="tenant-actions">
        <button
          type="button"
          className="tenant-button tenant-button--primary"
          disabled={!props.canWrite || content === null}
          onClick={submit}
        >
          Review policy
        </button>
        <button type="button" className="tenant-button" onClick={props.onCancel}>
          Cancel
        </button>
      </div>
    </section>
  );
}

function PolicyField(props: {
  readonly id: string;
  readonly label: string;
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly hint: string;
}) {
  return (
    <p className="tenant-policies__field">
      <label htmlFor={props.id}>{props.label}</label>
      <input
        id={props.id}
        type="text"
        value={props.value}
        onChange={(event) => props.onChange(event.target.value)}
      />
      <span className="tenant-policies__hint">{props.hint}</span>
    </p>
  );
}

export { formatUsdcFromAtomic };
