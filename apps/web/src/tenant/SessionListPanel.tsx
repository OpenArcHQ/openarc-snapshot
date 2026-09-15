import type { CommerceControlSessionStatusItem } from "@openarc/shared";
import { useId } from "react";

import type { SessionController } from "./session-controller.js";
import type { SessionControllerState } from "./session-controller.js";

/**
 * Bounded commerce-session list (max 50/page, explicit refresh only).
 *
 * It renders the DB-derived status truthfully and never fabricates an empty
 * catalogue: a capability/transport failure is an explicit error state. No raw
 * handoff or session token can appear here; the shared list DTO cannot
 * represent one.
 */

export interface SessionListPanelProps {
  readonly state: SessionControllerState;
  readonly controller: SessionController | null;
  readonly onOpenSession: (sessionId: string) => void;
  readonly onStartIssue: () => void;
}

export function SessionListPanel(props: SessionListPanelProps) {
  const { state } = props;
  const labelId = useId();
  const list = state.list;
  return (
    <section className="session-list" aria-labelledby={labelId}>
      <div className="session-list__head">
        <h2 className="session-title session-title--small" id={labelId}>
          Existing sessions
        </h2>
        <button type="button" className="tenant-button tenant-button--primary" onClick={props.onStartIssue}>
          Issue a session
        </button>
      </div>
      <p className="tenant-note">
        Server-derived status for this organization. List is bounded and refreshes only when you ask.
      </p>

      {list.status === "none" ? (
        <div className="tenant-actions">
          <button
            type="button"
            className="tenant-button"
            onClick={() => void props.controller?.loadList()}
          >
            Load sessions
          </button>
        </div>
      ) : null}
      {list.status === "loading" ? (
        <p className="tenant-status" role="status">Loading sessions…</p>
      ) : null}
      {list.status === "error" ? (
        <p className="tenant-status tenant-status--error" role="alert">
          Sessions could not be loaded. No empty result is implied.
        </p>
      ) : null}
      {list.status === "ready" && list.items.length === 0 ? (
        <p className="tenant-empty">No sessions in this organization yet.</p>
      ) : null}
      {list.items.length > 0 ? (
        <div className="tenant-table-wrap">
          <table className="tenant-table session-table">
            <caption>Sessions in this organization</caption>
            <thead>
              <tr>
                <th scope="col">Session</th>
                <th scope="col">Status</th>
                <th scope="col">Agent</th>
                <th scope="col">Policy</th>
                <th scope="col">Expires</th>
                <th scope="col">Action</th>
              </tr>
            </thead>
            <tbody>
              {list.items.map((item) => (
                <SessionRow
                  key={item.metadata.sessionId}
                  item={item}
                  onOpen={() => props.onOpenSession(item.metadata.sessionId)}
                />
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <div className="tenant-pagination">
        {list.hasPrevious ? (
          <button
            type="button"
            className="tenant-button"
            disabled={list.status === "loading"}
            onClick={() => void props.controller?.loadPreviousList()}
          >
            Previous page
          </button>
        ) : null}
        <button
          type="button"
          className="tenant-button"
          disabled={list.status === "loading" || list.nextCursor === null}
          onClick={() => void props.controller?.loadNextList()}
        >
          Next page
        </button>
        <button
          type="button"
          className="tenant-button"
          disabled={list.status === "loading"}
          onClick={() => void props.controller?.loadList()}
        >
          Refresh list
        </button>
        <span className="tenant-pagination__status">Page size ≤ 50. Replaces the current page.</span>
      </div>
    </section>
  );
}

function SessionRow(props: {
  readonly item: CommerceControlSessionStatusItem;
  readonly onOpen: () => void;
}) {
  const { metadata, status } = props.item;
  return (
    <tr>
      <td className="tenant-mono">{metadata.sessionId}</td>
      <td>
        <span className={`tenant-pill session-status session-status--${status}`}>{statusLabel(status)}</span>
      </td>
      <td className="tenant-mono">{metadata.subjectAgentId}</td>
      <td className="tenant-mono">{metadata.policyId}</td>
      <td className="tenant-mono">{metadata.expiresAt}</td>
      <td>
        <button type="button" className="tenant-button" onClick={props.onOpen}>
          Open session {metadata.sessionId}
        </button>
      </td>
    </tr>
  );
}

export function statusLabel(status: string): string {
  switch (status) {
    case "handoff_pending":
      return "Handoff pending";
    case "active":
      return "Active";
    case "expired":
      return "Expired";
    case "invalidated":
      return "Invalidated";
    case "revoked":
      return "Revoked";
    default:
      return "Unknown";
  }
}
