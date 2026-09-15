import { useId, useRef } from "react";

import { sessionSecretRevealable, type SessionController, type SessionControllerState, type SessionMutationState } from "./session-controller.js";

/**
 * Human issue form for a one-time commerce-session handoff.
 *
 * It uses the currently selected ACTIVE agent from TenantController, a policy
 * ID and a canonical duration 1..900 (blank = server default 300). When the
 * existing policy UI AND its capability are enabled the parent supplies a
 * bounded, current-organization policy picker; otherwise a manual canonical
 * policy ID stays usable and NO policy request is made.
 *
 * This gives an existing same-agent authenticated client a short-lived handoff.
 * It does NOT connect or sign a wallet, reserve money or make purchases. The
 * raw handoff secret is shown exactly once, held only in controller memory, and
 * is cleared by dismiss/expiry/hidden/navigation/context change. The panel holds
 * NO raw secret and NO durable form state: the parent keys it by the full bound
 * context so a context/privacy boundary remounts it with fresh state.
 */

export interface SessionIssuePanelProps {
  readonly state: SessionControllerState;
  readonly controller: SessionController | null;
  readonly agents: readonly { readonly agentId: string; readonly displayName: string; readonly status: string }[];
  readonly agentsStatus: "none" | "loading" | "ready" | "error";
  readonly onLoadAgents: () => void;
  /** When true, render the bounded existing-policy picker. */
  readonly policyPickerEnabled: boolean;
  readonly policyOptions: readonly { readonly policyId: string; readonly status: string }[];
  readonly policyOptionsStatus: "none" | "loading" | "ready" | "error";
  readonly hasNextPolicies: boolean;
  readonly onLoadPolicies: () => void;
  readonly onLoadMorePolicies: () => void;
  readonly selectedAgentId: string | null;
  readonly onSelectAgent: (agentId: string | null) => void;
  readonly onIssue: (input: { subjectAgentId: string; policyId: string; durationSeconds: string | null }) => void;
  readonly onDismissSecret: () => void;
  readonly onCopySecret: (secret: string) => void;
  readonly onCancel: () => void;
  readonly onConfirm: () => void;
  readonly onCheckStatus: () => void;
  readonly onNavigateDetail: (sessionId: string) => void;
}

export function SessionIssuePanel(props: SessionIssuePanelProps) {
  const { state, controller } = props;
  const formId = useId();
  const mutation = state.mutation;
  const freshSecret = state.availableOnce;
  const secretVisible = freshSecret !== null;
  const pending = mutation.kind === "pending";
  const unknown = mutation.kind === "outcome-unknown";
  const activeAgents = props.agents.filter((agent) => agent.status === "active");
  const selected = props.selectedAgentId ?? activeAgents[0]?.agentId ?? null;

  // The form is uncontrolled (defaultValue) and lives ONLY for the current keyed
  // mount. The parent remounts it on every context/privacy boundary, so a typed
  // policy or duration can never survive a hidden/pagehide/account/org/role/route
  // or agent change. This avoids any post-render effect that could paint a stale
  // value for one frame.
  const policyRef = useRef<HTMLInputElement | HTMLSelectElement | null>(null);
  const durationRef = useRef<HTMLInputElement | null>(null);

  function submitForm(): void {
    const policyId = policyRef.current?.value ?? "";
    const duration = durationRef.current?.value ?? "";
    if (selected === null || policyId.length === 0) return;
    props.onIssue({
      subjectAgentId: selected,
      policyId,
      durationSeconds: duration.trim().length === 0 ? null : duration.trim(),
    });
  }

  const canSubmit = state.canWrite && controller !== null && selected !== null && !pending && !unknown && !secretVisible;

  return (
    <section className="session-issue" aria-labelledby={`${formId}-title`}>
      <p className="tenant-eyebrow">ISSUE A SESSION</p>
      <h2 className="session-title" id={`${formId}-title`}>
        One-time handoff
      </h2>
      <p className="tenant-status tenant-status--warning" role="status">
        This gives an existing, same-agent authenticated client a short-lived handoff. It is NOT a
        wallet, a payment, a reservation or a purchase. There is no payment or financial authority
        here.
      </p>

      <SessionMutationView
        mutation={mutation}
        availableOnce={freshSecret}
        handoffExpiresAt={mutation.kind === "committed" ? mutation.committed.handoffExpiresAt : null}
        controller={controller}
        onDismissSecret={props.onDismissSecret}
        onCopySecret={props.onCopySecret}
        onCancel={props.onCancel}
        onConfirm={props.onConfirm}
        onCheckStatus={props.onCheckStatus}
      />

      {secretVisible || mutation.kind === "confirming" || pending ? null : (
        <form
          className="tenant-form session-form"
          aria-label="Issue commerce session"
          onSubmit={(event) => {
            event.preventDefault();
            submitForm();
          }}
        >
          <div className="tenant-field">
            <label htmlFor={`${formId}-agent`}>Active agent</label>
            {props.agentsStatus === "none" ? (
              <button type="button" className="tenant-button" onClick={props.onLoadAgents}>
                Load agents
              </button>
            ) : null}
            {props.agentsStatus === "loading" ? (
              <p className="tenant-status" role="status">Loading agents…</p>
            ) : null}
            <select
              id={`${formId}-agent`}
              className="tenant-input"
              value={selected ?? ""}
              disabled={props.agentsStatus === "loading" || activeAgents.length === 0}
              onChange={(event) => props.onSelectAgent(event.target.value)}
            >
              {activeAgents.length === 0 ? <option value="">No active agent available.</option> : null}
              {activeAgents.map((agent) => (
                <option key={agent.agentId} value={agent.agentId}>
                  {agent.displayName}
                </option>
              ))}
            </select>
            <p className="tenant-note">Only an active agent of the current organization can be used.</p>
          </div>

          <div className="tenant-field">
            <label htmlFor={`${formId}-policy`}>Policy ID</label>
            {props.policyPickerEnabled ? (
              <>
                <select
                  id={`${formId}-policy`}
                  className="tenant-input"
                  ref={policyRef as React.RefObject<HTMLSelectElement>}
                  defaultValue=""
                  disabled={props.policyOptionsStatus === "loading"}
                >
                  <option value="">Choose a policy…</option>
                  {props.policyOptions.map((policy) => (
                    <option key={policy.policyId} value={policy.policyId}>
                      {policy.policyId} ({policy.status})
                    </option>
                  ))}
                </select>
                <div className="tenant-actions">
                  <button
                    type="button"
                    className="tenant-button"
                    disabled={props.policyOptionsStatus === "loading"}
                    onClick={props.onLoadPolicies}
                  >
                    {props.policyOptions.length === 0 ? "Load policies" : "Refresh policies"}
                  </button>
                  <button
                    type="button"
                    className="tenant-button"
                    disabled={!props.hasNextPolicies || props.policyOptionsStatus === "loading"}
                    onClick={props.onLoadMorePolicies}
                  >
                    More policies
                  </button>
                </div>
                <p className="tenant-note">
                  Bounded current-organization policies bound to the selected active agent, via the
                  existing policy capability. No policy is created here.
                </p>
              </>
            ) : (
              <>
                <input
                  id={`${formId}-policy`}
                  className="tenant-input tenant-input--mono"
                  type="text"
                  ref={policyRef as React.RefObject<HTMLInputElement>}
                  defaultValue=""
                  placeholder="openarc:policy:…"
                />
                <p className="tenant-note">
                  The policy feature is off, so enter the exact canonical policy ID manually. No
                  policy request is made and no policy is created.
                </p>
              </>
            )}
          </div>

          <div className="tenant-field">
            <label htmlFor={`${formId}-duration`}>Duration (seconds, 1–900)</label>
            <input
              id={`${formId}-duration`}
              className="tenant-input tenant-input--mono"
              type="text"
              inputMode="numeric"
              ref={durationRef}
              defaultValue="300"
              placeholder="300"
            />
            <p className="tenant-note">Blank uses the server default of 300 seconds.</p>
          </div>

          <div className="tenant-actions">
            <button type="submit" className="tenant-button tenant-button--primary" disabled={!canSubmit}>
              Review issue
            </button>
          </div>
        </form>
      )}

      <HandoffLifecycleExplanation />
    </section>
  );
}

export interface SessionMutationViewProps {
  readonly mutation: SessionMutationState;
  readonly availableOnce: string | null;
  readonly handoffExpiresAt: string | null;
  readonly controller: SessionController | null;
  readonly onDismissSecret: () => void;
  readonly onCopySecret: (secret: string) => void;
  readonly onCancel: () => void;
  readonly onConfirm: () => void;
  readonly onCheckStatus: () => void;
}

export function SessionMutationView(props: SessionMutationViewProps) {
  const { mutation, controller } = props;
  if (mutation.kind === "idle") return null;
  if (mutation.kind === "confirming") {
    const draft = mutation.draft;
    return (
      <section className="session-confirm" aria-labelledby="session-confirm-title">
        <h3 className="session-title session-title--small" id="session-confirm-title">
          {draft.op === "issue" ? "Confirm issue" : "Confirm revoke"}
        </h3>
        {draft.op === "issue" ? (
          <p className="tenant-status">
            One explicit confirmation sends exactly one logical issue with a fresh mutation ID and
            an idempotency key held in memory only. The handoff token is shown once and cannot be
            retrieved later. There is no automatic retry.
          </p>
        ) : (
          <p className="tenant-status">
            Revoking session <span className="tenant-mono">{draft.sessionId}</span> is immediate. A
            lost handoff cannot be recreated: a revoked session needs a new human issue.
          </p>
        )}
        <p className="tenant-mono">
          {draft.op === "issue"
            ? `agent ${draft.subjectAgentId} · policy ${draft.policyId} · duration ${draft.durationSeconds ?? "server default 300"}`
            : `session ${draft.sessionId}`}
        </p>
        <div className="tenant-actions">
          <button
            type="button"
            className="tenant-button tenant-button--primary"
            onClick={() => void controller?.confirm()}
          >
            {draft.op === "issue" ? "Confirm issue" : "Confirm revoke"}
          </button>
          <button type="button" className="tenant-button" onClick={props.onCancel}>
            Cancel
          </button>
        </div>
      </section>
    );
  }
  if (mutation.kind === "pending") {
    return (
      <p className="tenant-status" role="status" aria-live="polite">
        Sending one session request… Do not resubmit.
      </p>
    );
  }
  if (mutation.kind === "committed") {
    return (
      <SessionCommittedView
        committed={mutation.committed}
        availableOnce={props.availableOnce}
        onDismissSecret={props.onDismissSecret}
        onCopySecret={props.onCopySecret}
      />
    );
  }
  if (mutation.kind === "rejected") {
    return <SessionRejected notice={mutation.notice} />;
  }
  return <SessionUnknown mutation={mutation} onCheckStatus={props.onCheckStatus} />;
}

function SessionCommittedView(props: {
  readonly committed: Extract<SessionMutationState, { kind: "committed" }>["committed"];
  readonly availableOnce: string | null;
  readonly onDismissSecret: () => void;
  readonly onCopySecret: (secret: string) => void;
}) {
  const secretRef = useRef<HTMLInputElement | null>(null);
  const { committed } = props;
  const isIssue = committed.receipt.operation === "control.commerce_session.issue";
  const freshSecret = props.availableOnce;
  const revealable = sessionSecretRevealable(committed.metadata, committed.handoffExpiresAt);
  return (
    <div className="session-receipt">
      <div role="status" aria-live="polite">
        <h3 className="session-title session-title--small">
          {committed.replayed ? "Session already committed" : "Session committed"}
        </h3>
        <dl className="tenant-meta">
          <dt>Operation</dt>
          <dd>{committed.receipt.operation}</dd>
          <dt>Session</dt>
          <dd className="tenant-mono">{committed.receipt.resourceId}</dd>
          <dt>Mutation</dt>
          <dd className="tenant-mono">{committed.receipt.mutationId}</dd>
          {committed.metadata !== null ? (
            <>
              <dt>Status</dt>
              <dd>{committed.metadata.revokedAt !== null ? "revoked" : committed.metadata.exchangedAt !== null ? "active" : "handoff_pending"}</dd>
              <dt>Expires</dt>
              <dd className="tenant-mono">{committed.metadata.expiresAt}</dd>
            </>
          ) : null}
          {committed.handoffExpiresAt !== null ? (
            <>
              <dt>Handoff expires</dt>
              <dd className="tenant-mono">{committed.handoffExpiresAt}</dd>
            </>
          ) : null}
        </dl>
        {committed.refreshError ? (
          <p className="tenant-status tenant-status--warning" role="status">
            The follow-up refresh failed, but the committed receipt stands.
          </p>
        ) : null}
        {isIssue && freshSecret !== null && revealable ? (
          <p className="tenant-status tenant-status--warning">
            This handoff is shown only once. OpenArc cannot retrieve it later. The client exchanges
            it once for a short-lived session token; store it only as long as needed, then dismiss.
          </p>
        ) : null}
        {isIssue && freshSecret === null ? (
          <p className="tenant-status tenant-status--warning">
            {committed.replayed
              ? "This session was already issued, so its handoff cannot be shown again. Revoke it explicitly and issue a new session if the handoff was lost."
              : "The handoff token is no longer available in this page (it expired or was cleared). Revoke this session and issue a new one if needed."}
          </p>
        ) : null}
        {!isIssue ? (
          <p className="tenant-status">The session was revoked. Any client holding it has lost access.</p>
        ) : null}
      </div>

      {isIssue && freshSecret !== null && revealable ? (
        <div className="session-secret" role="group" aria-label="New one-time handoff">
          <label htmlFor="session-secret-value">New one-time handoff token</label>
          <input
            id="session-secret-value"
            ref={secretRef}
            className="tenant-input tenant-input--mono session-secret__value"
            type="text"
            readOnly
            value={freshSecret}
            onFocus={(event) => event.currentTarget.select()}
          />
          <div className="tenant-actions">
            <button
              type="button"
              className="tenant-button"
              onClick={() => {
                secretRef.current?.focus();
                secretRef.current?.select();
              }}
            >
              Select handoff
            </button>
            <button
              type="button"
              className="tenant-button"
              onClick={() => props.onCopySecret(freshSecret)}
            >
              Copy handoff
            </button>
            <button type="button" className="tenant-button tenant-button--primary" onClick={props.onDismissSecret}>
              Dismiss
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function SessionRejected(props: { readonly notice: { readonly kind: string } }) {
  const messages: Record<string, string> = {
    validation: "The server rejected this request as invalid. Review the values and try again.",
    policy: "The server policy denied this session request. Nothing was applied.",
    conflict: "The server reported a conflict. Nothing was applied; confirm explicitly again.",
    unauthenticated: "Your sign-in is no longer valid. Sign in again before managing sessions.",
    csrf: "The page security check expired. Sign in again before managing sessions.",
    forbidden: "Your role cannot perform this session action.",
    "not-found": "The addressed session no longer exists.",
    "account-changed":
      "The signed-in account changed while this action was starting, so nothing was sent.",
    "capability-disabled": "Commerce sessions are not enabled in this deployment.",
    "no-access":
      "Only a current owner or operator on a non-recovery account may read or write sessions. Viewers, providers and unknown roles get no access.",
    "inactive-agent":
      "Choose an active agent of the current organization before issuing a session.",
  };
  const message = messages[props.notice.kind] ?? "The session action could not be started.";
  return (
    <p className="tenant-status tenant-status--error" role="alert">
      {message} <a href="/account">Go to account</a>
    </p>
  );
}

function SessionUnknown(props: {
  readonly mutation: Extract<SessionMutationState, { kind: "outcome-unknown" }>;
  readonly onCheckStatus: () => void;
}) {
  const messageRef = useRef<HTMLParagraphElement | null>(null);
  return (
    <section className="session-confirm" aria-labelledby="session-unknown-title">
      <h3 className="session-title session-title--small" id="session-unknown-title">
        The outcome is unknown
      </h3>
      <p className="tenant-status tenant-status--warning" role="status">
        The request was sent but no confirmed response arrived. It may still complete. There is no
        retry and no new key: only an explicit status check with the original mutation ID can
        resolve it. A committed status does not recover the one-time secret.
      </p>
      <p className="tenant-mono" ref={messageRef} tabIndex={-1}>
        Mutation {props.mutation.mutationId}
      </p>
      {props.mutation.statusMessage !== null ? (
        <p className="tenant-status" role="status" aria-live="polite">
          {props.mutation.statusMessage}
        </p>
      ) : null}
      <div className="tenant-actions">
        <button
          type="button"
          className="tenant-button tenant-button--primary"
          disabled={props.mutation.checking}
          onClick={props.onCheckStatus}
        >
          {props.mutation.checking ? "Checking…" : "Check status"}
        </button>
        <a className="tenant-button" href="/app/sessions">
          Leave this page
        </a>
      </div>
    </section>
  );
}

/** The exact one-time handoff lifecycle and recovery explanation. */
export function HandoffLifecycleExplanation() {
  return (
    <details className="session-lifecycle">
      <summary>How the one-time handoff works</summary>
      <ol className="session-lifecycle__steps">
        <li>
          Issuing creates a <span className="tenant-mono">handoff_pending</span> session and shows
          the raw <span className="tenant-mono">oach_v1_</span> handoff token exactly once.
        </li>
        <li>
          The existing same-agent authenticated client exchanges that handoff once for a short-lived
          session token. After a successful exchange the session becomes{" "}
          <span className="tenant-mono">active</span>.
        </li>
        <li>
          The handoff expires at <span className="tenant-mono">handoffExpiresAt</span> (at most 5
          minutes). The session itself expires at the duration you choose (at most 900 seconds).
        </li>
        <li>
          If the handoff is lost or already exchanged, it cannot be recreated or replayed. Repair is
          explicit: revoke this exact session, then issue a new one.
        </li>
        <li>
          A session can be revoked at any time; revocation is immediate. A committed status check
          never recovers a secret.
        </li>
      </ol>
    </details>
  );
}

export type { SessionController };
