import type { CommercePolicyRevision, CommercePolicyRevisionSummary } from "@openarc/shared";

import type { PolicyHistoryState, PolicyRevisionState } from "./policy-controller.js";

// Immutable, ascending revision history with explicit bounded pagination.
//
// History rows are METADATA-ONLY summaries. Only the explicit revision read
// reveals full content, so the selected revision is rendered as a separate
// full-content view. "Load more revisions" is the single explicit action that
// advances `afterRevision`; there is no auto-load and no unbounded
// accumulation. The CAS root is independent of this pagination.
export function PolicyRevisionHistory(props: {
  readonly history: PolicyHistoryState;
  readonly revision: PolicyRevisionState;
  readonly canWrite: boolean;
  readonly onLoadMore: () => void;
  readonly onReadRevision: (revision: string) => void;
  readonly onAppendFrom: () => void;
}) {
  const { history } = props;
  const latest = history.items.length > 0
    ? history.items[history.items.length - 1]?.revision
    : null;
  return (
    <section className="tenant-policies__history" aria-labelledby="policy-history-title">
      <h2 className="tenant-title tenant-title--small" id="policy-history-title">
        Revision history
      </h2>
      <p className="tenant-status" role="status">
        {history.historyComplete
          ? `All revisions loaded. Latest known revision: ${latest ?? "none"}.`
          : "Revision history is incomplete. Load more revisions to see the full immutable chain."}
      </p>
      {history.status === "loading" ? (
        <p className="tenant-status" role="status">Loading revisions…</p>
      ) : null}
      {history.status === "error" ? (
        <p className="tenant-status tenant-status--error" role="alert">
          Revision history could not be loaded. A missing history is not an empty one.
        </p>
      ) : null}
      {history.status === "ready" && history.items.length === 0 ? (
        <p className="tenant-empty">No revisions are available for this policy.</p>
      ) : null}
      {history.items.length > 0 ? (
        <div className="tenant-table-wrap">
          <table className="tenant-table">
            <caption>Immutable revision summaries (metadata only)</caption>
            <thead>
              <tr>
                <th scope="col">Revision</th>
                <th scope="col">Digest</th>
                <th scope="col">Created</th>
                <th scope="col">Expires</th>
                <th scope="col">Action</th>
              </tr>
            </thead>
            <tbody>
              {history.items.map((item) => (
                <tr key={item.revision}>
                  <td className="tenant-mono">{item.revision}</td>
                  <td className="tenant-mono tenant-policies__digest">{item.digest}</td>
                  <td className="tenant-mono">{item.createdAt}</td>
                  <td className="tenant-mono">{item.expiresAt ?? "none"}</td>
                  <td>
                    <button
                      type="button"
                      className="tenant-button"
                      onClick={() => props.onReadRevision(item.revision)}
                    >
                      Read revision {item.revision}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {!history.historyComplete && history.nextCursor !== null ? (
        <div className="tenant-actions">
          <button
            type="button"
            className="tenant-button"
            disabled={history.status === "loading"}
            onClick={props.onLoadMore}
          >
            Load more revisions
          </button>
        </div>
      ) : null}
      <PolicyRevisionDetail
        revision={props.revision}
        canWrite={props.canWrite}
        onAppendFrom={props.onAppendFrom}
      />
    </section>
  );
}

function PolicyRevisionDetail(props: {
  readonly revision: PolicyRevisionState;
  readonly canWrite: boolean;
  readonly onAppendFrom: () => void;
}) {
  const state = props.revision;
  if (state.status === "none") {
    return (
      <p className="tenant-status">
        Select a revision to read its full immutable content. Summaries above are metadata only.
      </p>
    );
  }
  if (state.status === "loading") {
    return <p className="tenant-status" role="status">Loading full revision…</p>;
  }
  if (state.status === "not-found") {
    return (
      <p className="tenant-status tenant-status--warning" role="status">
        This revision was not found. No fabricated revision is shown.
      </p>
    );
  }
  if (state.status === "error") {
    return (
      <p className="tenant-status tenant-status--error" role="alert">
        The full revision could not be loaded.
      </p>
    );
  }
  const revision = state.revision;
  if (revision === null) return null;
  return (
    <section className="tenant-policies__revision" aria-labelledby="policy-revision-title">
      <h3 className="tenant-title tenant-title--small" id="policy-revision-title">
        Full revision {revision.revision}
      </h3>
      <RevisionContent revision={revision} />
      <div className="tenant-actions">
        <button
          type="button"
          className="tenant-button tenant-button--primary"
          disabled={!props.canWrite}
          onClick={props.onAppendFrom}
        >
          Append revision from {revision.revision}
        </button>
      </div>
    </section>
  );
}

function RevisionContent(props: { readonly revision: CommercePolicyRevision }) {
  const revision = props.revision;
  return (
    <dl className="tenant-meta">
      <dt>Subject agent</dt>
      <dd className="tenant-mono">{revision.subjectAgentId}</dd>
      <dt>Per-action cap</dt>
      <dd className="tenant-mono">{revision.perActionLimit ?? "none"}</dd>
      <dt>Rolling cap</dt>
      <dd className="tenant-mono">
        {revision.rollingLimit ?? "none"}
        {revision.rollingLimit === null ? "" : ` / ${revision.rollingWindowSeconds}s`}
      </dd>
      <dt>Fee cap</dt>
      <dd className="tenant-mono">{revision.feeLimit}</dd>
      <dt>Allowed providers</dt>
      <dd className="tenant-mono">{revision.allowedProviderIds.join(", ") || "deny-all"}</dd>
      <dt>Allowed listings</dt>
      <dd className="tenant-mono">{revision.allowedListingIds.join(", ") || "deny-all"}</dd>
      <dt>Approval</dt>
      <dd className="tenant-mono">
        {revision.approval.mode}
        {revision.approval.mode === "above" ? ` @ ${revision.approval.threshold ?? "none"}` : ""}
        {revision.approval.separateApprover ? " · separate approver" : ""}
      </dd>
      <dt>Expires</dt>
      <dd className="tenant-mono">{revision.expiresAt ?? "none"}</dd>
      <dt>Digest</dt>
      <dd className="tenant-mono tenant-policies__digest">{revision.digest}</dd>
    </dl>
  );
}

export type { CommercePolicyRevisionSummary };
