import {
  approvalStatusLabel,
  type ActionController,
  type ActionControllerState,
} from "./action-controller.js";

/**
 * One approval record, read by approvalId.
 *
 * An approval is a recorded human decision about a commerce action. It is NOT a
 * payment, a settlement, a delivery or a purchase, and this panel never implies
 * one. A pending approval carries no decider and no decision time; those fields
 * are shown as genuinely absent rather than filled in with a guess.
 */

export interface ApprovalDetailPanelProps {
  readonly state: ActionControllerState;
  readonly controller: ActionController | null;
  readonly approvalId: string;
  readonly onBack: () => void;
  readonly onOpenAction: (actionId: string) => void;
}

export function ApprovalDetailPanel(props: ApprovalDetailPanelProps) {
  const detail = props.state.approvalDetail;
  if (detail.status === "none" || detail.status === "loading") {
    return (
      <p className="tenant-status" role="status">
        Loading approval detail…
      </p>
    );
  }
  if (detail.status === "not-found") {
    return (
      <p className="tenant-status tenant-status--warning" role="status">
        This approval was not found. No empty or fabricated approval is shown.
      </p>
    );
  }
  if (detail.status === "error" || detail.item === null) {
    return (
      <p className="tenant-status tenant-status--error" role="alert">
        The approval detail could not be loaded.
      </p>
    );
  }
  const item = detail.item;
  return (
    <section className="tenant-actions-console__section" aria-labelledby="approval-detail-title">
      <p className="tenant-eyebrow">APPROVAL DETAIL</p>
      <h2 className="tenant-title tenant-title--small" id="approval-detail-title">
        Approval <span className="tenant-mono">{item.approvalId}</span>
      </h2>
      <p className="tenant-status" role="status">
        Server-derived status: <strong>{approvalStatusLabel(item.status)}</strong>. An approval
        records a human decision only. It does not pay, settle, deliver or purchase anything.
      </p>

      <dl className="tenant-meta">
        <dt>Status</dt>
        <dd>
          <span className={`tenant-pill action-status action-status--${item.status}`}>
            {approvalStatusLabel(item.status)}
          </span>
        </dd>
        <dt>Action</dt>
        <dd className="tenant-mono">{item.actionId}</dd>
        <dt>Subject agent</dt>
        <dd className="tenant-mono">{item.subjectAgentId}</dd>
        <dt>Policy</dt>
        <dd className="tenant-mono">{item.policyId}</dd>
        <dt>Policy revision</dt>
        <dd className="tenant-mono">{item.policyRevision}</dd>
        <dt>Requested by</dt>
        <dd className="tenant-mono">{item.requestedBy}</dd>
        <dt>Separate approver</dt>
        <dd>
          {item.separateApprover
            ? "Required: the decider must differ from the requester."
            : "Not required."}
        </dd>
        <dt>Decided by</dt>
        <dd className="tenant-mono">{item.decidedBy ?? "not decided"}</dd>
        <dt>Decided at</dt>
        <dd className="tenant-mono">{item.decidedAt ?? "not decided"}</dd>
        <dt>Created</dt>
        <dd className="tenant-mono">{item.createdAt}</dd>
        <dt>Expires</dt>
        <dd className="tenant-mono">{item.expiresAt}</dd>
      </dl>

      <div className="tenant-actions">
        <button
          type="button"
          className="tenant-button"
          onClick={() => void props.controller?.loadApprovalDetail(props.approvalId)}
        >
          Refresh approval
        </button>
        <button
          type="button"
          className="tenant-button"
          onClick={() => props.onOpenAction(item.actionId)}
        >
          Open action {item.actionId}
        </button>
        <button type="button" className="tenant-button" onClick={props.onBack}>
          Back to the approval queue
        </button>
      </div>
    </section>
  );
}
