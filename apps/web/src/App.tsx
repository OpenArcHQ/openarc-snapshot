import { ARC_TESTNET } from "@openarc/shared";
import { Component, lazy, Suspense, useEffect, useState, type ReactNode } from "react";

import type { BuildInfo } from "@openarc/shared";

import { FixtureExplorer } from "./evidence/FixtureExplorer.js";
import { investigationsEnabled, genericAgentImportEnabled, gatewayEvidenceEnabled, agentJobsEnabled, agentRegistryEnabled, apiBoundaryEnabled, arcObservationEnabled, encryptedWorkspaceEnabled } from "./app/availability.js";

// The encrypted workspace (Vault UI, IndexedDB and crypto) is split out of the
// main entry so public routes never download it. Session-end locking reaches
// Vault storage separately through the dynamic session bridge.
const VaultWorkspace = lazy(() => import("./vault/VaultWorkspace.js").then((module) => ({ default: module.VaultWorkspace })));
const SuppliedDesignApp = lazy(() => import("./supplied/DesignApp.js"));
const AccountPage = lazy(() => import("./account/AccountPage.js"));
const TenantApp = lazy(() => import("./tenant/TenantApp.js"));
const MarketApp = lazy(() => import("./market/MarketApp.js"));

/**
 * The new public marketplace routes. This is a pure route predicate: it only
 * selects the lazily-loaded public shell and never touches the wallet, Vault,
 * account or protected tenant controllers.
 */
function isMarketPublicPath(path: string): boolean {
  if (path === "/market" || path.startsWith("/market/")) return true;
  if (path.startsWith("/providers/")) return true;
  return path === "/docs" || path === "/status" || path === "/legal";
}

interface DesignErrorBoundaryProps {
  children: ReactNode;
}

interface DesignErrorBoundaryState {
  failed: boolean;
}

class DesignErrorBoundary extends Component<DesignErrorBoundaryProps, DesignErrorBoundaryState> {
  override state: DesignErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): DesignErrorBoundaryState {
    return { failed: true };
  }

  override render() {
    if (this.state.failed) {
      return (
        <main className="supplied-fallback" role="alert">
          <h1>The design preview could not load.</h1>
          <p>
            The rest of this build is unaffected. Return to the <a href="/">evidence workspace</a>.
          </p>
        </main>
      );
    }
    return this.props.children;
  }
}

interface AppProps {
  build: BuildInfo;
}

const evidenceSteps = [
  ["01", "Permission", "What was the agent allowed to do?"],
  ["02", "Attempt", "What did the agent or tool report trying?"],
  ["03", "Authorization", "What exact payment or action was approved?"],
  ["04", "Settlement", "What can an authoritative source actually prove?"],
] as const;

export function App({ build }: AppProps) {
  const [path, setPath] = useState(window.location.pathname);
  const workspaceEnabled = encryptedWorkspaceEnabled();
  const observationEnabled = workspaceEnabled && apiBoundaryEnabled() && arcObservationEnabled();
  const registryEnabled = observationEnabled && agentRegistryEnabled();
  const jobsEnabled = registryEnabled && agentJobsEnabled();
  const paymentsEnabled = jobsEnabled && gatewayEvidenceEnabled();
  const reportsEnabled = workspaceEnabled && genericAgentImportEnabled();
  const investigationEnabled = workspaceEnabled && investigationsEnabled();

  useEffect(() => {
    const onPopState = () => setPath(window.location.pathname);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    if (path === "/workspace" && !workspaceEnabled) {
      window.history.replaceState(null, "", "/");
      setPath("/");
    }
  }, [path, workspaceEnabled]);

  if (path === "/design" || path.startsWith("/design/")) {
    return (
      <DesignErrorBoundary>
        <Suspense
          fallback={
            <main className="supplied-fallback" role="status">
              Loading the design preview…
            </main>
          }
        >
          <SuppliedDesignApp />
        </Suspense>
      </DesignErrorBoundary>
    );
  }

  if (path === "/account" || path.startsWith("/account/")) {
    return (
      <Suspense
        fallback={
          <main className="supplied-fallback" role="status">
            Loading account…
          </main>
        }
      >
        <AccountPage />
      </Suspense>
    );
  }

  // The static `/app` workspace routes lazily construct the protected tenant
  // controller only when one of these paths is actually visited. Public routes
  // never mount it and never touch the account or tenant controllers.
  if (path === "/app" || path.startsWith("/app/")) {
    return (
      <Suspense
        fallback={
          <main className="supplied-fallback" role="status">
            Loading the organization workspace…
          </main>
        }
      >
        <TenantApp />
      </Suspense>
    );
  }

  // Public marketplace routes lazily construct the public catalog shell only
  // when one of these paths is visited. The shell owns its own flag gate, so a
  // disabled deployment makes zero catalog or auth requests.
  if (isMarketPublicPath(path)) {
    return (
      <Suspense
        fallback={
          <main className="supplied-fallback" role="status">
            Loading the public marketplace…
          </main>
        }
      >
        <MarketApp />
      </Suspense>
    );
  }

  if (path === "/workspace" && workspaceEnabled) {
    return (
      <Suspense
        fallback={
          <main className="supplied-fallback" role="status">
            Loading the encrypted workspace…
          </main>
        }
      >
        <VaultWorkspace build={build} />
      </Suspense>
    );
  }

  const skipToExplorer = () => {
    requestAnimationFrame(() => document.querySelector<HTMLElement>("#fixture-explorer")?.focus());
  };

  return (
    <main>
      <a className="skip-link" href="#fixture-explorer" onClick={skipToExplorer}>
        Skip to fixture explorer
      </a>
      <nav className="topbar" aria-label="Primary navigation">
        <a className="brand" href="#top" aria-label="OpenArc home">
          <img src="/openarc-logo.jpeg" alt="" />
          <span>OPENARC</span>
        </a>
        <div className="topbar-links">
          {workspaceEnabled ? <a href="/workspace">Workspace</a> : null}
          <a href="#fixture-explorer">Explorer</a>
          <a href="#network">Network</a>
          <span className="phase">{investigationEnabled ? "M09 · LOCAL INVESTIGATIONS" : reportsEnabled ? "M08 · LOCAL AGENT REPORTS" : paymentsEnabled ? "M07 · PAYMENT EVIDENCE" : jobsEnabled ? "M06 · JOB EVIDENCE" : registryEnabled ? "M05 · AGENT EVIDENCE" : observationEnabled
            ? "M04 · ARC OBSERVATION"
            : apiBoundaryEnabled() ? "M03 · API PRIVACY BOUNDARY" : "M02 · ENCRYPTED WORKSPACE"}</span>
        </div>
      </nav>

      <section className="hero" id="top" aria-labelledby="hero-title">
        <div className="hero-copy">
          <p className="eyebrow">SYNTHETIC FIXTURES · READ ONLY · LOCAL FIRST</p>
          <h1 id="hero-title">See the full arc of every agent action.</h1>
          <p className="lede">
            OpenArc is an evidence and investigation workspace for economic agents. This first
            engine keeps intent, attempt, authorization, fulfillment, settlement, and refund
            evidence distinct—then explains exactly what agrees, conflicts, or remains missing.
          </p>
          <div className="status-row" aria-label="Current build status">
            <span className="status-dot" aria-hidden="true" />
            <strong>{observationEnabled ? "Arc observation available" : "Fixture engine running"}</strong>
            <span>{paymentsEnabled ? "Local x402 metadata comparison and explicit read-only Gateway reports, alongside Arc Testnet account, transaction, registry and job evidence."
              : jobsEnabled
              ? "Explicit, read-only account, transaction, agent-registry, and reference-job observations on Arc Testnet."
              : registryEnabled ? "Explicit, read-only account, transaction, and agent-registry observations on Arc Testnet." : observationEnabled
              ? "Explicit, read-only account and transaction observations through the privacy boundary."
              : "Six deterministic local cases. Live connectors remain deliberately disabled."}</span>
          </div>
          {workspaceEnabled ? <a className="hero-action" href="/workspace">Open private workspace →</a> : null}
        </div>

        <div className="orbital" aria-hidden="true">
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
          <div className="core">OA</div>
          <span className="node node-a" />
          <span className="node node-b" />
          <span className="node node-c" />
        </div>
      </section>

      <FixtureExplorer />

      <section className="evidence" aria-labelledby="evidence-title">
        <header>
          <p className="eyebrow">THE CONTROL LAYER</p>
          <h2 id="evidence-title">One trail. No collapsed meanings.</h2>
        </header>
        <div className="evidence-grid">
          {evidenceSteps.map(([number, title, description]) => (
            <article key={number}>
              <span>{number}</span>
              <h3>{title}</h3>
              <p>{description}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="network" id="network" aria-labelledby="network-title">
        <div>
          <p className="eyebrow">PINNED NETWORK REGISTRY</p>
          <h2 id="network-title">Arc Testnet, exactly.</h2>
          <p>
            Arc's official documentation currently identifies Public Testnet as the active public
            network and Mainnet as upcoming. No public Mainnet registry is pinned here; OpenArc
            will not guess or copy Testnet values forward.
          </p>
        </div>
        <dl>
          <div>
            <dt>CAIP-2</dt>
            <dd>{ARC_TESTNET.caip2}</dd>
          </div>
          <div>
            <dt>CHAIN ID</dt>
            <dd>{ARC_TESTNET.chainId}</dd>
          </div>
          <div>
            <dt>GAS</dt>
            <dd>{ARC_TESTNET.currencySymbol}</dd>
          </div>
          <div>
            <dt>FINALITY</dt>
            <dd>{ARC_TESTNET.finality}</dd>
          </div>
        </dl>
      </section>

      <footer>
        <p>OpenArc is independent concept software and is not endorsed by Arc or Circle.</p>
        <code data-testid="build-sha">BUILD {build.commitSha}</code>
      </footer>
    </main>
  );
}
