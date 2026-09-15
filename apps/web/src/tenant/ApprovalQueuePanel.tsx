import { useId } from "react";

import {
  ACTION_PAGE_LIMIT_EXPORT,
  approvalStatusLabel,
  type ActionController,
  type ActionControllerState,
  type CommerceApprovalMetadata,
} from "./action-controller.js";

/**
 * Bounded approval queue (at most 50 rows per page, explicit refresh and
 * explicit paging only).
 *
 * An approval row records a requested or decided human approval. An approval is
 * NOT a payment: no row here asserts that money moved, settled or was refunded.
 * A transport failure is an explicit error state and never a fabricated empty
 * queue.
 */

export interface ApprovalQueuePanelProps {
  readonly state: ActionControllerState;
  readonly controller: ActionController | null;
  readonly onOpenApproval: (approvalId: string) => void;
  readonly onOpenAction: (actionId: string) => void;
}

export function ApprovalQueuePanel(props: ApprovalQueuePanelProps) {
  const labelId = useId();
  const queue = props.state.approvals;
  return (
    <section className="tenant-actions-console__section" aria-labelledby={labelId}>
      <div className="tenant-actions-console__head">
        <h2 className="tenant-title tenant-title--small" id={labelId}>
          Approval queue
        </h2>
      </div>
      <p className="tenant-actions-console__hint">
        Human approvals recorded by the server for this organization. One page at a time, never
        more than {ACTION_PAGE_LIMIT_EXPORT} rows. An approval records a decision; it does not pay,
        settle or deliver anything.
      </p>

      {queue.status === "none" ? (
        <div className="tenant-actions">
          <button
            type="button"
            className="tenant-button"
            onClick={() => void props.controller?.loadApprovals()}
          >
            Load approvals
          </button>
        </div>
      ) : null}
      {queue.status === "loading" ? (
        <p className="tenant-status" role="status">
          Loading approvals…
        </p>
      ) : null}
      {queue.status === "error" ? (
        <p className="tenant-status tenant-status--error" role="alert">
          Approvals could not be loaded. No empty result is implied.
        </p>
      ) : null}
      {queue.status === "ready" && queue.items.length === 0 ? (
        <p className="tenant-empty">No approvals in this organization yet.</p>
      ) : null}

      {queue.items.length > 0 ? (
        <div className="tenant-table-wrap tenant-actions-console__table-scroll">
          <table className="tenant-table">
            <caption>Approvals in this organization</caption>
            <thead>
              <tr>
                <th scope="col">Approval</th>
                <th scope="col">Status</th>
                <th scope="col">Action</th>
                <th scope="col">Subject agent</th>
                <th scope="col">Separate approver</th>
                <th scope="col">Expires</th>
                <th scope="col">Open</th>
              </tr>
            </thead>
            <tbody>
              {queue.items.map((item) => (
                <ApprovalRow
                  key={item.approvalId}
                  item={item}
                  onOpenApproval={() => props.onOpenApproval(item.approvalId)}
                  onOpenAction={() => props.onOpenAction(item.actionId)}
                />
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <div className="tenant-actions-console__pagination tenant-pagination">
        {queue.hasPrevious ? (
          <button
            type="button"
            className="tenant-button"
            disabled={queue.status === "loading"}
            onClick={() => void props.controller?.loadPreviousApprovals()}
          >
            Previous page
          </button>
        ) : null}
        <button
          type="button"
          className="tenant-button"
          disabled={queue.status === "loading" || queue.nextCursor === null}
          onClick={() => void props.controller?.loadNextApprovals()}
        >
          Next page
        </button>
        <button
          type="button"
          className="tenant-button"
          disabled={queue.status === "loading"}
          onClick={() => void props.controller?.loadApprovals()}
        >
          Refresh queue
        </button>
        <span className="tenant-pagination__status">
          Page size ≤ {ACTION_PAGE_LIMIT_EXPORT}. Each page replaces the current one.
        </span>
      </div>
    </section>
  );
}

function ApprovalRow(props: {
  readonly item: CommerceApprovalMetadata;
  readonly onOpenApproval: () => void;
  readonly onOpenAction: () => void;
}) {
  const { item } = props;
  return (
    <tr>
      <td className="tenant-mono">{item.approvalId}</td>
      <td>
        <span className={`tenant-pill action-status action-status--${item.status}`}>
          {approvalStatusLabel(item.status)}
        </span>
      </td>
      <td>
        <button type="button" className="tenant-button" onClick={props.onOpenAction}>
          Open action {item.actionId}
        </button>
      </td>
      <td className="tenant-mono">{item.subjectAgentId}</td>
      <td>{item.separateApprover ? "Required" : "Not required"}</td>
      <td className="tenant-mono">{item.expiresAt}</td>
      <td>
        <button type="button" className="tenant-button" onClick={props.onOpenApproval}>
          Open approval {item.approvalId}
        </button>
      </td>
    </tr>
  );
}
