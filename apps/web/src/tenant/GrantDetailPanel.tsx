import { useState } from "react";

import {
  GRANT_LIFETIME_NOTICE,
  grantDisplayFields,
  grantLifeState,
  grantStatusExplanation,
  grantStatusLabel,
  revokeOutcomeLabel,
  revokeRejectionMessage,
  revokeReleaseNotice,
  revokeSummary,
  type GrantController,
  type GrantControllerState,
  type GrantFailureNotice,
  type GrantRevokeState,
} from "./grant-controller.js";

/**
 * One authorization grant: the exact server-derived record plus the single
 * explicit revoke, behind its own confirmation step.
 *
 * Nothing on this page is optimistic. A revoke is shown as applied only after a
 * committed receipt, and a lost response is shown as genuinely unknown with a
 * single explicit status re-check — never an automatic retry or resubmission.
 *
 * The grant token is never rendered here because it never arrives here: the
 * browser grant family carries no token, no token hash and no digest, and the
 * displayed field list is a positive allowlist over accepted metadata.
 *
 * The expiry comparison uses an instant captured at render. Re-checking it is a
 * purely local button that issues NO request; the server's exact `expiresAt` is
 * always displayed verbatim beside it.
 */

export interface GrantDetailPanelProps {
  readonly state: GrantControllerState;
  readonly controller: GrantController | null;
  readonly grantId: string;
  readonly onBack: () => void;
}

export function GrantDetailPanel(props: GrantDetailPanelProps) {
  const { state, controller } = props;
  const [nowIso, setNowIso] = useState(() => new Date().toISOString());
  const detail = state.detail;

  if (detail.status === "none" || detail.status === "loading") {
    return (
      <p className="tenant-status" role="status">
        Loading grant detail…
      </p>
    );
  }
  if (detail.status === "not-found") {
    return (
      <section className="tenant-grants-console__section" aria-labelledby="grant-missing-title">
        <h2 className="tenant-title tenant-title--small" id="grant-missing-title">
          No such grant
        </h2>
        <p className="tenant-status tenant-status--warning" role="status">
          This organization has no grant with that ID. A grant that never existed and a grant
          belonging to another organization look the same here, on purpose. No empty or
          fabricated grant is shown.
        </p>
        <div className="tenant-actions">
          <button type="button" className="tenant-button" onClick={props.onBack}>
            Open a different grant
          </button>
        </div>
      </section>
    );
  }
  if (detail.status === "error" || detail.item === null) {
    return (
      <p className="tenant-status tenant-status--error" role="alert">
        The grant detail could not be loaded.
      </p>
    );
  }

  const item = detail.item;
  const life = grantLifeState(item, nowIso);
  const busy = state.revoke.kind === "pending" || state.revoke.kind === "confirming";
  // The revoke control is hidden outright for a viewer and disabled once the
  // server has denied a revoke in this context. An already-revoked grant has
  // nothing left to revoke.
  const showRevoke = state.canRevoke && item.status !== "revoked";

  return (
    <section className="tenant-grants-console__section" aria-labelledby="grant-detail-title">
      <p className="tenant-eyebrow">GRANT DETAIL</p>
      <h2 className="tenant-title tenant-title--small" id="grant-detail-title">
        Grant <span className="tenant-mono">{item.grantId}</span>
      </h2>

      <p
        className={
          life === "claimable"
            ? "tenant-status"
            : "tenant-status tenant-status--warning"
        }
        role="status"
      >
        Server-derived status: <strong>{grantStatusLabel(item.status)}</strong>.{" "}
        {grantStatusExplanation(item, nowIso)} The server is the final authority and can change
        this at any time.
      </p>

      <div className="tenant-grants-console__expiry">
        <p className="tenant-status">
          {life === "expired" ? (
            <strong>Expired. This grant can no longer be claimed.</strong>
          ) : life === "claimable" ? (
            <strong>Not expired at the instant checked below.</strong>
          ) : (
            <strong>Expiry is no longer the deciding fact for this grant.</strong>
          )}{" "}
          Expires at <span className="tenant-mono">{item.expiresAt}</span>; checked against{" "}
          <span className="tenant-mono">{nowIso}</span>.
        </p>
        <p className="tenant-grants-console__hint">{GRANT_LIFETIME_NOTICE}</p>
        <button
          type="button"
          className="tenant-button"
          onClick={() => setNowIso(new Date().toISOString())}
        >
          Re-check the expiry instant
        </button>
      </div>

      <dl className="tenant-meta">
        {grantDisplayFields(item, nowIso).map((field) => (
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
          onClick={() => void controller?.loadGrantDetail(props.grantId)}
        >
          Refresh from the server
        </button>
        <button type="button" className="tenant-button" onClick={props.onBack}>
          Open a different grant
        </button>
      </div>

      <GrantRevokeView revoke={state.revoke} controller={controller} />

      {showRevoke ? (
        <div className="tenant-grants-console__revoke" role="group" aria-label="Revoke">
          <p className="tenant-status tenant-status--warning">
            Revoking is sent exactly once after you confirm it. There is no automatic retry.
            Revoking retires permission only: it pays nothing, refunds nothing, settles nothing,
            delivers nothing and cancels no payment.
          </p>
          <button
            type="button"
            className="tenant-button tenant-button--danger"
            disabled={busy}
            onClick={() => controller?.beginRevoke(props.grantId)}
          >
            Revoke this grant
          </button>
        </div>
      ) : item.status === "revoked" ? (
        <p className="tenant-status" role="status">
          This grant is already revoked. There is nothing further to revoke.
        </p>
      ) : (
        <p className="tenant-status tenant-status--warning" role="status">
          {state.serverDeniedRevoke
            ? "The server refused your last revoke on this grant, so the revoke control is disabled here. Your local role is only a guess; the server decides."
            : "Your role can read this grant but cannot revoke it. Only an owner or operator may revoke."}
        </p>
      )}
    </section>
  );
}

export interface GrantRevokeViewProps {
  readonly revoke: GrantRevokeState;
  readonly controller: GrantController | null;
}

/**
 * The single revoke lifecycle view: confirm, in flight, committed, refused or
 * genuinely unknown. The unknown state offers exactly one explicit, user-driven
 * status re-check and never resends the revoke.
 */
export function GrantRevokeView(props: GrantRevokeViewProps) {
  const { revoke, controller } = props;
  if (revoke.kind === "idle") return null;

  if (revoke.kind === "confirming") {
    return (
      <section className="tenant-grants-console__confirm" aria-labelledby="grant-confirm-title">
        <h3 className="tenant-title tenant-title--small" id="grant-confirm-title">
          Confirm: revoke this grant
        </h3>
        <p className="tenant-status">{revokeSummary(null)}</p>
        <p className="tenant-status tenant-status--warning">
          If this grant has already been claimed, revoking it does not undo the claim and does not
          get money back. The claim fact is retained and the grant may still have been paid.
        </p>
        <p className="tenant-status">
          Confirming sends exactly one request with a fresh mutation ID and an idempotency key held
          in memory only. If the response is lost, nothing is resent automatically.
        </p>
        <p className="tenant-mono">grant {revoke.draft.grantId}</p>
        <div className="tenant-actions">
          <button
            type="button"
            className="tenant-button tenant-button--danger"
            onClick={() => void controller?.confirmRevoke()}
          >
            Revoke now
          </button>
          <button
            type="button"
            className="tenant-button"
            onClick={() => controller?.cancelRevoke()}
          >
            Go back without revoking
          </button>
        </div>
      </section>
    );
  }

  if (revoke.kind === "pending") {
    return (
      <p className="tenant-status" role="status" aria-live="polite">
        Sending one revoke request… Do not resubmit.
      </p>
    );
  }

  if (revoke.kind === "committed") {
    const committed = revoke.committed;
    return (
      <div className="tenant-grants-console__receipt" role="status" aria-live="polite">
        <h3 className="tenant-title tenant-title--small">
          {committed.replayed ? "Grant already revoked" : "Grant revoked"}
        </h3>
        <p className="tenant-status">{revokeOutcomeLabel(revoke)}</p>
        <dl className="tenant-meta">
          <dt>Operation</dt>
          <dd className="tenant-mono">{committed.receipt.operation}</dd>
          <dt>Grant</dt>
          <dd className="tenant-mono">{committed.receipt.resourceId}</dd>
          <dt>Mutation</dt>
          <dd className="tenant-mono">{committed.receipt.mutationId}</dd>
          <dt>Committed at</dt>
          <dd className="tenant-mono">{committed.receipt.committedAt}</dd>
          <dt>Grant status now</dt>
          <dd>
            {committed.metadata === null
              ? "Not reported by this result"
              : grantStatusLabel(committed.metadata.status)}
          </dd>
          <dt>Bound action status</dt>
          <dd>{committed.actionStatus ?? "Not reported by this result"}</dd>
        </dl>
        <p className="tenant-status tenant-status--warning">{revokeReleaseNotice(committed)}</p>
        <p className="tenant-status tenant-status--warning">
          A committed revoke records that permission was retired. It does not mean anything was
          paid, settled, delivered, purchased, released or refunded.
        </p>
        {committed.refreshError ? (
          <p className="tenant-status tenant-status--warning" role="status">
            The follow-up refresh failed, but the committed receipt above stands.
          </p>
        ) : null}
      </div>
    );
  }

  if (revoke.kind === "rejected") {
    return <GrantRejected notice={revoke.notice} />;
  }

  return (
    <section className="tenant-grants-console__unknown" aria-labelledby="grant-unknown-title">
      <h3 className="tenant-title tenant-title--small" id="grant-unknown-title">
        The outcome is unknown
      </h3>
      <p className="tenant-status tenant-status--warning" role="status">
        {revokeOutcomeLabel(revoke)} The request was sent but no confirmed response arrived. It may
        still complete. Nothing is retried and no new key is created: only an explicit status check
        with the original mutation ID can resolve it.
      </p>
      <p className="tenant-mono">
        revoke · grant {revoke.grantId} · mutation {revoke.mutationId}
      </p>
      {revoke.statusMessage !== null ? (
        <p className="tenant-status" role="status" aria-live="polite">
          {revoke.statusMessage}
        </p>
      ) : null}
      <div className="tenant-actions">
        <button
          type="button"
          className="tenant-button tenant-button--primary"
          disabled={revoke.checking}
          onClick={() => void controller?.checkRevokeStatus()}
        >
          {revoke.checking ? "Checking…" : "Check status once"}
        </button>
        <a className="tenant-button" href="/app/grants">
          Leave this page
        </a>
      </div>
    </section>
  );
}

function GrantRejected(props: { readonly notice: GrantFailureNotice }) {
  return (
    <p className="tenant-status tenant-status--error" role="alert">
      {revokeRejectionMessage(props.notice)}
    </p>
  );
}
