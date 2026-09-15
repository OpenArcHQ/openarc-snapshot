import type { SessionController, SessionControllerState } from "./session-controller.js";

/**
 * One commerce-session detail: truthful DB-derived status and an exact-session
 * revoke. There is no payment action, no wallet and no token.
 */

export interface SessionStatusPanelProps {
  readonly state: SessionControllerState;
  readonly controller: SessionController | null;
  readonly sessionId: string;
  readonly onBack: () => void;
}

export function SessionStatusPanel(props: SessionStatusPanelProps) {
  const { state } = props;
  const detail = state.detail;
  if (detail.status === "none" || detail.status === "loading") {
    return <p className="tenant-status" role="status">Loading session detail…</p>;
  }
  if (detail.status === "not-found") {
    return (
      <p className="tenant-status tenant-status--warning" role="status">
        This session was not found. No empty or fabricated session is shown.
      </p>
    );
  }
  if (detail.status === "error" || detail.item === null) {
    return (
      <p className="tenant-status tenant-status--error" role="alert">
        The session detail could not be loaded.
      </p>
    );
  }
  const { metadata, status } = detail.item;
  const revocable = status !== "revoked";
  return (
    <section className="session-detail" aria-labelledby="session-detail-title">
      <p className="tenant-eyebrow">SESSION DETAIL</p>
      <h2 className="session-title" id="session-detail-title">
        Session <span className="tenant-mono">{metadata.sessionId}</span>
      </h2>
      <p className="tenant-status" role="status">
        Server-derived status: <strong>{statusLabel(status)}</strong>. The server is the final
        authority and can change this at any time.
      </p>
      <dl className="tenant-meta">
        <dt>Status</dt>
        <dd>
          <span className={`tenant-pill session-status session-status--${status}`}>
            {statusLabel(status)}
          </span>
        </dd>
        <dt>Subject agent</dt>
        <dd className="tenant-mono">{metadata.subjectAgentId}</dd>
        <dt>Policy</dt>
        <dd className="tenant-mono">{metadata.policyId}</dd>
        <dt>Scopes</dt>
        <dd className="tenant-mono">{metadata.scopes.join(", ")}</dd>
        <dt>Issued</dt>
        <dd className="tenant-mono">{metadata.issuedAt}</dd>
        <dt>Expires</dt>
        <dd className="tenant-mono">{metadata.expiresAt}</dd>
        <dt>Exchanged</dt>
        <dd className="tenant-mono">{metadata.exchangedAt ?? "not exchanged"}</dd>
        <dt>Revoked</dt>
        <dd className="tenant-mono">{metadata.revokedAt ?? "not revoked"}</dd>
      </dl>

      <div className="tenant-actions">
        <button
          type="button"
          className="tenant-button"
          onClick={() => void props.controller?.loadDetail(props.sessionId)}
        >
          Refresh status
        </button>
        <button type="button" className="tenant-button" onClick={props.onBack}>
          Back to sessions
        </button>
      </div>

      {revocable ? (
        <div className="session-detail__revoke">
          <p className="tenant-status tenant-status--warning">
            Revoking is immediate and cannot be undone. A lost or exchanged handoff cannot be
            recreated: revoke this exact session and issue a new one instead.
          </p>
          <button
            type="button"
            className="tenant-button"
            disabled={!state.canWrite || state.mutation.kind === "pending"}
            onClick={() => props.controller?.beginRevoke(props.sessionId)}
          >
            Revoke session {metadata.sessionId}
          </button>
        </div>
      ) : (
        <p className="tenant-status">This session is revoked and terminal.</p>
      )}
    </section>
  );
}

function statusLabel(status: string): string {
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
