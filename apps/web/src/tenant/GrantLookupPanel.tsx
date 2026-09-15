import { useState } from "react";

import { CommerceGrantIdSchema } from "@openarc/shared";

import type { GrantController, GrantControllerState } from "./grant-controller.js";

/**
 * Grant lookup by exact canonical id.
 *
 * There is deliberately no grant list, queue or page: the accepted grant store
 * exposes no list method and the frozen registry publishes no browser list
 * route, so this panel opens a grant only when the operator already holds its
 * exact id. It renders no sample, demo or placeholder grant, and it issues NO
 * request of any kind until the operator submits a canonical id.
 */

export interface GrantLookupPanelProps {
  readonly state: GrantControllerState;
  readonly controller: GrantController | null;
  readonly onOpenGrant: (grantId: string) => void;
  /** Bumped on a context change so the typed id never survives one. */
  readonly formKey: string;
}

export function GrantLookupPanel(props: GrantLookupPanelProps) {
  return <GrantLookupForm key={props.formKey} {...props} />;
}

function GrantLookupForm(props: GrantLookupPanelProps) {
  const [draft, setDraft] = useState("");
  const [invalid, setInvalid] = useState(false);
  const inputId = "grant-lookup-id";
  const hintId = "grant-lookup-hint";
  const errorId = "grant-lookup-error";

  return (
    <section className="tenant-grants-console__section" aria-labelledby="grant-lookup-title">
      <p className="tenant-eyebrow">OPEN A GRANT</p>
      <h2 className="tenant-title tenant-title--small" id="grant-lookup-title">
        Open an authorization grant by ID
      </h2>
      <p className="tenant-status" role="status">
        Grants are not listed. Paste the exact grant ID you already hold; nothing is requested
        until you do. This page shows no example, sample or placeholder grant.
      </p>
      <form
        className="tenant-grants-console__field"
        onSubmit={(event) => {
          event.preventDefault();
          const candidate = draft.trim();
          if (!CommerceGrantIdSchema.safeParse(candidate).success) {
            setInvalid(true);
            return;
          }
          setInvalid(false);
          props.controller?.selectLookupGrantId(candidate);
          props.onOpenGrant(candidate);
        }}
      >
        <label htmlFor={inputId}>Grant ID</label>
        <input
          id={inputId}
          name="grantId"
          type="text"
          inputMode="text"
          autoComplete="off"
          spellCheck={false}
          value={draft}
          aria-describedby={invalid ? `${hintId} ${errorId}` : hintId}
          aria-invalid={invalid || undefined}
          onChange={(event) => {
            setDraft(event.target.value);
            if (invalid) setInvalid(false);
          }}
        />
        <p className="tenant-grants-console__hint" id={hintId}>
          The canonical form is <span className="tenant-mono">openarc:grant:</span> followed by a
          lower-case UUID. A grant ID is not a secret and is safe to paste here. Never paste a
          grant token: this console has no field for one and no route that would accept one.
        </p>
        {invalid ? (
          <p className="tenant-status tenant-status--error" id={errorId} role="alert">
            That is not a canonical grant ID. No request was made.
          </p>
        ) : null}
        <div className="tenant-actions">
          <button type="submit" className="tenant-button tenant-button--primary">
            Open this grant
          </button>
        </div>
      </form>
      <p className="tenant-grants-console__hint">
        Opening a grant reads its server record. It connects no wallet, signs nothing, moves no
        money and reports no payment, settlement or delivery.
      </p>
    </section>
  );
}
