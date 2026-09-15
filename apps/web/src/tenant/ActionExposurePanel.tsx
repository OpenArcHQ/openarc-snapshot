import { useId, useRef } from "react";

import {
  exposureRows,
  type ActionController,
  type ActionControllerState,
} from "./action-controller.js";

/**
 * The exact server exposure view for one subject agent under one policy.
 *
 * Every figure is printed exactly as the server sent it: the canonical atomic
 * string is always shown alongside the decimal placement, which is produced by
 * string position only. No amount is parsed into a JavaScript number, rounded,
 * truncated or approximated, and no total is recomputed here.
 *
 * These values are the server's `asOf` record of exposure. They are NOT wallet
 * balances, NOT proof of payment and NOT a settlement.
 */

export interface ActionExposurePanelProps {
  readonly state: ActionControllerState;
  readonly controller: ActionController | null;
  readonly formKey: string;
}

export function ActionExposurePanel(props: ActionExposurePanelProps) {
  const labelId = useId();
  const agentFieldId = `${labelId}-agent`;
  const policyFieldId = `${labelId}-policy`;
  const agentRef = useRef<HTMLInputElement | null>(null);
  const policyRef = useRef<HTMLInputElement | null>(null);
  const exposure = props.state.exposure;
  return (
    <section className="tenant-actions-console__section" aria-labelledby={labelId}>
      <h2 className="tenant-title tenant-title--small" id={labelId}>
        Exposure
      </h2>
      <p className="tenant-actions-console__hint">
        The server's exact exposure record for one agent under one policy. These figures are not
        wallet balances and are not proof that anything was paid or settled.
      </p>

      <form
        key={props.formKey}
        onSubmit={(event) => {
          event.preventDefault();
          const subjectAgentId = agentRef.current?.value.trim() ?? "";
          const policyId = policyRef.current?.value.trim() ?? "";
          if (subjectAgentId.length === 0 || policyId.length === 0) return;
          void props.controller?.loadExposure(subjectAgentId, policyId);
        }}
      >
        <div className="tenant-actions-console__field">
          <label htmlFor={agentFieldId}>Subject agent ID</label>
          <input
            id={agentFieldId}
            ref={agentRef}
            className="tenant-input tenant-input--mono"
            type="text"
            inputMode="text"
            autoComplete="off"
            spellCheck={false}
            defaultValue={exposure.subjectAgentId ?? ""}
            aria-describedby={`${agentFieldId}-hint`}
          />
          <p className="tenant-actions-console__hint" id={`${agentFieldId}-hint`}>
            A canonical <span className="tenant-mono">openarc:agent:</span> identifier.
          </p>
        </div>
        <div className="tenant-actions-console__field">
          <label htmlFor={policyFieldId}>Policy ID</label>
          <input
            id={policyFieldId}
            ref={policyRef}
            className="tenant-input tenant-input--mono"
            type="text"
            inputMode="text"
            autoComplete="off"
            spellCheck={false}
            defaultValue={exposure.policyId ?? ""}
            aria-describedby={`${policyFieldId}-hint`}
          />
          <p className="tenant-actions-console__hint" id={`${policyFieldId}-hint`}>
            A canonical <span className="tenant-mono">openarc:policy:</span> identifier.
          </p>
        </div>
        <div className="tenant-actions">
          <button
            type="submit"
            className="tenant-button tenant-button--primary"
            disabled={exposure.status === "loading"}
          >
            Read exposure
          </button>
        </div>
      </form>

      {exposure.status === "none" ? (
        <p className="tenant-status" role="status">
          No exposure has been read yet. Nothing is requested until you ask for a specific agent
          and policy.
        </p>
      ) : null}
      {exposure.status === "loading" ? (
        <p className="tenant-status" role="status">
          Reading exposure…
        </p>
      ) : null}
      {exposure.status === "not-found" ? (
        <p className="tenant-status tenant-status--warning" role="status">
          The server has no exposure record for that agent and policy. No zero balance is implied.
        </p>
      ) : null}
      {exposure.status === "error" ? (
        <p className="tenant-status tenant-status--error" role="alert">
          The exposure could not be read. No figure is shown rather than a guessed one.
        </p>
      ) : null}

      {exposure.status === "ready" && exposure.item !== null ? (
        <>
          <p className="tenant-status" role="status">
            Recorded by the server as of{" "}
            <span className="tenant-mono">{exposure.item.asOf}</span> for policy revision{" "}
            <span className="tenant-mono">{exposure.item.policyRevision}</span>
            {exposure.item.windowSeconds === null
              ? ", with no rolling window."
              : ` over a rolling window of ${exposure.item.windowSeconds} seconds.`}
          </p>
          <dl className="tenant-actions-console__exposure">
            {exposureRows(exposure.item).map((row) => (
              <div key={row.key}>
                <dt>{row.label}</dt>
                <dd>
                  {row.atomic === null ? (
                    <span className="tenant-actions-console__amount">No rolling cap</span>
                  ) : (
                    <>
                      <span className="tenant-actions-console__amount">
                        {row.display ?? row.atomic} {exposure.item?.asset}
                      </span>
                      <span className="tenant-actions-console__atomic">
                        {row.atomic} atomic ({exposure.item?.decimals} decimals)
                      </span>
                    </>
                  )}
                  <p className="tenant-actions-console__explain">{row.explanation}</p>
                </dd>
              </div>
            ))}
          </dl>
          <div className="tenant-actions">
            <button
              type="button"
              className="tenant-button"
              onClick={() => {
                const subjectAgentId = exposure.subjectAgentId;
                const policyId = exposure.policyId;
                if (subjectAgentId === null || policyId === null) return;
                void props.controller?.loadExposure(subjectAgentId, policyId);
              }}
            >
              Refresh exposure
            </button>
          </div>
        </>
      ) : null}
    </section>
  );
}
