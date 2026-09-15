import { useId } from "react";

import {
  ACTION_PAGE_LIMIT_EXPORT,
  actionStatusLabel,
  formatAtomicAmount,
  type ActionController,
  type ActionControllerState,
  type CommerceActionMetadata,
} from "./action-controller.js";

/**
 * Bounded commerce-action queue (at most 50 rows per page, explicit refresh
 * and explicit paging only).
 *
 * It renders the server-derived status truthfully and never fabricates an empty
 * queue: a transport failure is an explicit error state. Amounts are shown
 * exactly as the server sent them, with the decimal separator placed by string
 * position only. No row claims that anything was paid, settled, delivered or
 * purchased, and no sample or placeholder row is ever rendered.
 */

export interface ActionQueuePanelProps {
  readonly state: ActionControllerState;
  readonly controller: ActionController | null;
  readonly onOpenAction: (actionId: string) => void;
}

export function ActionQueuePanel(props: ActionQueuePanelProps) {
  const labelId = useId();
  const queue = props.state.actions;
  return (
    <section className="tenant-actions-console__section" aria-labelledby={labelId}>
      <div className="tenant-actions-console__head">
        <h2 className="tenant-title tenant-title--small" id={labelId}>
          Action queue
        </h2>
      </div>
      <p className="tenant-actions-console__hint">
        Server-derived commerce actions for this organization. One page at a time, never more than{" "}
        {ACTION_PAGE_LIMIT_EXPORT} rows, and only when you ask. An action is a request awaiting a
        decision: it is not a payment and not a settlement.
      </p>

      {queue.status === "none" ? (
        <div className="tenant-actions">
          <button
            type="button"
            className="tenant-button"
            onClick={() => void props.controller?.loadActions()}
          >
            Load actions
          </button>
        </div>
      ) : null}
      {queue.status === "loading" ? (
        <p className="tenant-status" role="status">
          Loading actions…
        </p>
      ) : null}
      {queue.status === "error" ? (
        <p className="tenant-status tenant-status--error" role="alert">
          Actions could not be loaded. No empty result is implied.
        </p>
      ) : null}
      {queue.status === "ready" && queue.items.length === 0 ? (
        <p className="tenant-empty">No commerce actions in this organization yet.</p>
      ) : null}

      {queue.items.length > 0 ? (
        <div className="tenant-table-wrap tenant-actions-console__table-scroll">
          <table className="tenant-table">
            <caption>Commerce actions in this organization</caption>
            <thead>
              <tr>
                <th scope="col">Action</th>
                <th scope="col">Status</th>
                <th scope="col">Subject agent</th>
                <th scope="col">Total debit if granted</th>
                <th scope="col">Expires</th>
                <th scope="col">Open</th>
              </tr>
            </thead>
            <tbody>
              {queue.items.map((item) => (
                <ActionRow
                  key={item.actionId}
                  item={item}
                  onOpen={() => props.onOpenAction(item.actionId)}
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
            onClick={() => void props.controller?.loadPreviousActions()}
          >
            Previous page
          </button>
        ) : null}
        <button
          type="button"
          className="tenant-button"
          disabled={queue.status === "loading" || queue.nextCursor === null}
          onClick={() => void props.controller?.loadNextActions()}
        >
          Next page
        </button>
        <button
          type="button"
          className="tenant-button"
          disabled={queue.status === "loading"}
          onClick={() => void props.controller?.loadActions()}
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

function ActionRow(props: {
  readonly item: CommerceActionMetadata;
  readonly onOpen: () => void;
}) {
  const { item } = props;
  const debit = formatAtomicAmount(item.debitAtomic, item.exposureKey.decimals);
  return (
    <tr>
      <td className="tenant-mono">{item.actionId}</td>
      <td>
        <span className={`tenant-pill action-status action-status--${item.status}`}>
          {actionStatusLabel(item.status)}
        </span>
      </td>
      <td className="tenant-mono">{item.exposureKey.subjectAgentId}</td>
      <td>
        <span className="tenant-actions-console__amount">
          {debit ?? item.debitAtomic} {item.exposureKey.asset}
        </span>
        <span className="tenant-actions-console__atomic">{item.debitAtomic} atomic</span>
      </td>
      <td className="tenant-mono">{item.expiresAt}</td>
      <td>
        <button type="button" className="tenant-button" onClick={props.onOpen}>
          Open action {item.actionId}
        </button>
      </td>
    </tr>
  );
}
