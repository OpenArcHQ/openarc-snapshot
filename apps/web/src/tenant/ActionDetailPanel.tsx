import {
  actionDisplayFields,
  actionStatusExplanation,
  actionStatusLabel,
  decisionOutcomeLabel,
  decisionSummary,
  decisionVerb,
  type ActionController,
  type ActionControllerState,
  type ActionDecisionState,
  type ActionFailureNotice,
} from "./action-controller.js";

/**
 * One commerce action: the exact server-derived record plus the three explicit
 * decisions (approve, reject, cancel), each behind its own confirmation step.
 *
 * Nothing on this page is optimistic. A decision is shown as applied only after
 * a committed receipt, and a lost response is shown as genuinely unknown with a
 * single explicit status re-check — never an automatic retry or resubmission.
 * The requirement digest is deliberately never rendered.
 */

export interface ActionDetailPanelProps {
  readonly state: ActionControllerState;
  readonly controller: ActionController | null;
  readonly actionId: string;
  readonly onBack: () => void;
  readonly onOpenApproval: (approvalId: string) => void;
}

/** Only these statuses can still receive a human decision. */
const DECIDABLE_STATUSES = new Set(["pending_approval", "reserved_not_granted"]);

export function ActionDetailPanel(props: ActionDetailPanelProps) {
  const { state, controller } = props;
  const detail = state.detail;
  if (detail.status === "none" || detail.status === "loading") {
    return (
      <p className="tenant-status" role="status">
        Loading action detail…
      </p>
    );
  }
  if (detail.status === "not-found") {
    return (
      <p className="tenant-status tenant-status--warning" role="status">
        This action was not found. No empty or fabricated action is shown.
      </p>
    );
  }
  if (detail.status === "error" || detail.item === null) {
    return (
      <p className="tenant-status tenant-status--error" role="alert">
        The action detail could not be loaded.
      </p>
    );
  }
  const item = detail.item;
  const decidable = DECIDABLE_STATUSES.has(item.status);
  const busy = state.decision.kind === "pending" || state.decision.kind === "confirming";
  // Decision controls are hidden outright for a viewer and disabled once the
  // server has denied a decision in this context.
  const showDecisions = state.canDecide && decidable;
  return (
    <section className="tenant-actions-console__section" aria-labelledby="action-detail-title">
      <p className="tenant-eyebrow">ACTION DETAIL</p>
      <h2 className="tenant-title tenant-title--small" id="action-detail-title">
        Action <span className="tenant-mono">{item.actionId}</span>
      </h2>
      <p className="tenant-status" role="status">
        Server-derived status: <strong>{actionStatusLabel(item.status)}</strong>.{" "}
        {actionStatusExplanation(item.status)} The server is the final authority and can change
        this at any time.
      </p>

      <dl className="tenant-meta">
        {actionDisplayFields(item).map((field) => (
          <div key={field.key} style={{ display: "contents" }}>
            <dt>{field.label}</dt>
            <dd className="tenant-mono">{field.value}</dd>
          </div>
        ))}
      </dl>

      <div className="tenant-actions">
        <button
          type="button"
          className="tenant-button"
          onClick={() => void controller?.loadActionDetail(props.actionId)}
        >
          Refresh status
        </button>
        {item.approvalId !== null ? (
          <button
            type="button"
            className="tenant-button"
            onClick={() => props.onOpenApproval(item.approvalId as string)}
          >
            Open approval {item.approvalId}
          </button>
        ) : null}
        <button type="button" className="tenant-button" onClick={props.onBack}>
          Back to the action queue
        </button>
      </div>

      <ActionDecisionView
        decision={state.decision}
        controller={controller}
        onOpenApproval={props.onOpenApproval}
      />

      {showDecisions ? (
        <div className="tenant-actions-console__decisions" role="group" aria-label="Decisions">
          <p className="tenant-status tenant-status--warning">
            Each decision is sent exactly once after you confirm it. There is no automatic retry.
            None of these decisions pays, settles, delivers or refunds anything.
          </p>
          {(["approve", "reject", "cancel"] as const).map((decision) => (
            <button
              key={decision}
              type="button"
              className={
                decision === "approve" ? "tenant-button tenant-button--primary" : "tenant-button"
              }
              disabled={busy}
              onClick={() => controller?.beginDecision(decision, props.actionId)}
            >
              {decisionVerb(decision)}
            </button>
          ))}
        </div>
      ) : state.canRead && decidable ? (
        <p className="tenant-status tenant-status--warning" role="status">
          {state.serverDeniedDecision
            ? "The server refused your last decision on this action, so the decision controls are disabled here. Your local role is only a guess; the server decides."
            : "Your role can read this action but cannot decide it. Only an owner or operator may approve, reject or cancel."}
        </p>
      ) : (
        <p className="tenant-status" role="status">
          This action is no longer open to a decision.
        </p>
      )}
    </section>
  );
}

export interface ActionDecisionViewProps {
  readonly decision: ActionDecisionState;
  readonly controller: ActionController | null;
  readonly onOpenApproval?: (approvalId: string) => void;
}

/**
 * The single decision lifecycle view: confirm, in flight, committed, refused or
 * genuinely unknown. The unknown state offers exactly one explicit, user-driven
 * status re-check and never resends the decision.
 */
export function ActionDecisionView(props: ActionDecisionViewProps) {
  const { decision, controller } = props;
  if (decision.kind === "idle") return null;

  if (decision.kind === "confirming") {
    const draft = decision.draft;
    return (
      <section
        className="tenant-actions-console__confirm"
        aria-labelledby="action-confirm-title"
      >
        <h3 className="tenant-title tenant-title--small" id="action-confirm-title">
          Confirm: {decisionVerb(draft.decision)}
        </h3>
        <p className="tenant-status">{decisionSummary(draft.decision)}</p>
        <p className="tenant-status">
          Confirming sends exactly one request with a fresh mutation ID and an idempotency key held
          in memory only. If the response is lost, nothing is resent automatically.
        </p>
        <p className="tenant-mono">action {draft.actionId}</p>
        <div className="tenant-actions">
          <button
            type="button"
            className="tenant-button tenant-button--primary"
            onClick={() => void controller?.confirmDecision()}
          >
            {decisionVerb(draft.decision)} now
          </button>
          <button
            type="button"
            className="tenant-button"
            onClick={() => controller?.cancelDecision()}
          >
            Go back without deciding
          </button>
        </div>
      </section>
    );
  }

  if (decision.kind === "pending") {
    return (
      <p className="tenant-status" role="status" aria-live="polite">
        Sending one decision request… Do not resubmit.
      </p>
    );
  }

  if (decision.kind === "committed") {
    const committed = decision.committed;
    return (
      <div className="tenant-actions-console__receipt" role="status" aria-live="polite">
        <h3 className="tenant-title tenant-title--small">
          {committed.replayed ? "Decision already committed" : "Decision committed"}
        </h3>
        <p className="tenant-status">{decisionOutcomeLabel(decision)}</p>
        <dl className="tenant-meta">
          <dt>Operation</dt>
          <dd className="tenant-mono">{committed.receipt.operation}</dd>
          <dt>Action</dt>
          <dd className="tenant-mono">{committed.receipt.resourceId}</dd>
          <dt>Mutation</dt>
          <dd className="tenant-mono">{committed.receipt.mutationId}</dd>
          <dt>Committed at</dt>
          <dd className="tenant-mono">{committed.receipt.committedAt}</dd>
          {committed.metadata !== null ? (
            <>
              <dt>Action status now</dt>
              <dd>{actionStatusLabel(committed.metadata.status)}</dd>
            </>
          ) : null}
        </dl>
        <p className="tenant-status tenant-status--warning">
          A committed decision records a human choice. It does not mean anything was paid, settled,
          delivered, purchased, released or refunded.
        </p>
        {committed.refreshError ? (
          <p className="tenant-status tenant-status--warning" role="status">
            The follow-up refresh failed, but the committed receipt above stands.
          </p>
        ) : null}
      </div>
    );
  }

  if (decision.kind === "rejected") {
    return <ActionRejected notice={decision.notice} />;
  }

  return (
    <section className="tenant-actions-console__unknown" aria-labelledby="action-unknown-title">
      <h3 className="tenant-title tenant-title--small" id="action-unknown-title">
        The outcome is unknown
      </h3>
      <p className="tenant-status tenant-status--warning" role="status">
        {decisionOutcomeLabel(decision)} The request was sent but no confirmed response arrived. It
        may still complete. Nothing is retried and no new key is created: only an explicit status
        check with the original mutation ID can resolve it.
      </p>
      <p className="tenant-mono">
        {decisionVerb(decision.decision)} · action {decision.actionId} · mutation{" "}
        {decision.mutationId}
      </p>
      {decision.statusMessage !== null ? (
        <p className="tenant-status" role="status" aria-live="polite">
          {decision.statusMessage}
        </p>
      ) : null}
      <div className="tenant-actions">
        <button
          type="button"
          className="tenant-button tenant-button--primary"
          disabled={decision.checking}
          onClick={() => void controller?.checkDecisionStatus()}
        >
          {decision.checking ? "Checking…" : "Check status once"}
        </button>
        <a className="tenant-button" href="/app/actions">
          Leave this page
        </a>
      </div>
    </section>
  );
}

function ActionRejected(props: { readonly notice: ActionFailureNotice }) {
  return (
    <p className="tenant-status tenant-status--error" role="alert">
      {rejectionMessage(props.notice)}
    </p>
  );
}

function rejectionMessage(notice: ActionFailureNotice): string {
  switch (notice.kind) {
    case "validation":
      return "The request was refused as invalid before it could commit. Nothing changed.";
    case "policy":
      return "A policy rule refused this decision. Nothing changed and nothing was paid or released.";
    case "conflict":
      return "The server reported a conflicting state for this action. Nothing was resent. Refresh the action and look again.";
    case "unauthenticated":
      return "Your session is no longer signed in, so the decision was not sent. Sign in again.";
    case "csrf":
      return "The request was refused for a security check. Reload the page and decide again.";
    case "forbidden":
      return "The server refused this decision for your account. The server is the authority here, not this page.";
    case "not-found":
      return "The server does not have this action. Nothing changed.";
    case "account-changed":
      return "The signed-in account changed, so the decision was abandoned before it was sent.";
    case "capability-disabled":
      return "Commerce actions are not enabled in this deployment, so no decision was sent.";
    case "no-access":
      return "Your role cannot decide commerce actions. No request was made.";
  }
}
