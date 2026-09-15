import type {
  CommerceAgentProfile,
  CommercePolicyContent,
} from "@openarc/shared";

import { PolicyEditorPanel } from "./PolicyEditorPanel.js";
import type { PolicyControllerState } from "./policy-controller.js";

// Bounded policy root list (25/50 per page with an explicit next page).
//
// The list never auto-loads and never accumulates pages: "Next page" replaces
// the current page. This surface manages policy RULES only: there are no
// available/reserved/spent counters and no funds are moved here.
export function PolicyListPanel(props: {
  readonly state: PolicyControllerState;
  readonly creating: boolean;
  // Full bound context + external privacy generation. Used as the React key so
  // the create editor REMOUNTS (reinitializing every field) the instant an
  // account/organization/role/hidden/pagehide boundary changes, instead of
  // retaining a previous context's caps, allowlists, expiry or agent selection.
  readonly formKey: string;
  readonly agents: readonly CommerceAgentProfile[];
  readonly agentsStatus: "none" | "loading" | "ready" | "error";
  readonly onLoadAgents: () => void;
  readonly onLoadMoreAgents: () => void;
  readonly hasNextAgents: boolean;
  readonly organizationId: string;
  readonly onStartCreate: () => void;
  readonly onCancelCreate: () => void;
  readonly onLoadRoots: () => void;
  readonly onNextRoots: () => void;
  readonly onSubmitCreate: (content: CommercePolicyContent) => void;
  readonly onOpenPolicy: (policyId: string) => void;
}) {
  const { roots } = props.state;

  if (props.creating) {
    return (
      <PolicyEditorPanel
        key={props.formKey}
        mode="create"
        organizationId={props.organizationId}
        agents={props.agents}
        agentsStatus={props.agentsStatus}
        onLoadAgents={props.onLoadAgents}
        onLoadMoreAgents={props.onLoadMoreAgents}
        hasNextAgents={props.hasNextAgents}
        prefill={null}
        canWrite={props.state.canWrite}
        onSubmit={props.onSubmitCreate}
        onCancel={props.onCancelCreate}
      />
    );
  }

  return (
    <section className="tenant-policies__list" aria-labelledby="policy-list-title">
      <div className="tenant-policies__list-header">
        <h2 className="tenant-title tenant-title--small" id="policy-list-title">
          Policy rules
        </h2>
        {roots.status === "none" ? (
          <button type="button" className="tenant-button tenant-button--primary" onClick={props.onLoadRoots}>
            Load policy rules
          </button>
        ) : (
          <button
            type="button"
            className="tenant-button tenant-button--primary"
            disabled={!props.state.canWrite}
            onClick={props.onStartCreate}
          >
            Create policy
          </button>
        )}
      </div>
      {roots.status === "loading" ? (
        <p className="tenant-status" role="status">Loading policy rules…</p>
      ) : null}
      {roots.status === "error" ? (
        <p className="tenant-status tenant-status--error" role="alert">
          Policy rules could not be loaded right now.
        </p>
      ) : null}
      {roots.status === "ready" && roots.items.length === 0 ? (
        <p className="tenant-empty">No policy rules in this organization yet.</p>
      ) : null}
      {roots.items.length > 0 ? (
        <div className="tenant-table-wrap">
          <table className="tenant-table">
            <caption>Policy rules in this organization</caption>
            <thead>
              <tr>
                <th scope="col">Policy ID</th>
                <th scope="col">Subject agent</th>
                <th scope="col">Current revision</th>
                <th scope="col">Status</th>
                <th scope="col">Updated</th>
                <th scope="col">Open</th>
              </tr>
            </thead>
            <tbody>
              {roots.items.map((item) => (
                <tr key={item.policyId}>
                  <td className="tenant-mono">{item.policyId}</td>
                  <td className="tenant-mono">{item.subjectAgentId}</td>
                  <td className="tenant-mono">{item.currentRevision}</td>
                  <td>{item.status}</td>
                  <td className="tenant-mono">{item.updatedAt}</td>
                  <td>
                    <button
                      type="button"
                      className="tenant-button"
                      onClick={() => props.onOpenPolicy(item.policyId)}
                    >
                      Open policy
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {roots.status === "ready" ? (
        <div className="tenant-pagination">
          {roots.hasPrevious ? (
            <button type="button" className="tenant-button" onClick={props.onLoadRoots}>
              Back to page 1
            </button>
          ) : null}
          <button
            type="button"
            className="tenant-button"
            disabled={roots.nextCursor === null}
            onClick={props.onNextRoots}
          >
            Next page
          </button>
          <span className="tenant-pagination__status">Bounded page, replaces the current page.</span>
        </div>
      ) : null}
    </section>
  );
}
