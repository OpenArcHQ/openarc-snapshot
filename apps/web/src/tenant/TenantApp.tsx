import {
  ARC_TESTNET,
  CommerceAgentProfileSchema,
  CommerceProviderProfileSchema,
  type CommerceAgentProfile,
  type CommerceListingOwnerVersion,
  type CommerceHumanRole,
} from "@openarc/shared";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { flushSync } from "react-dom";

import { accountAccessEnabled } from "../account/availability.js";
import { AccountFlowController } from "../account/flow-controller.js";
import { VaultSessionEndWatcher } from "../app/vault-session-lock.js";
import type { TenantFetch } from "./tenant-client.js";
import {
  MAX_PAGE_LIMIT,
  TenantController,
  canReadAgents,
  canReadProviders,
  type TenantViewControllerState,
  initialTenantState,
} from "./tenant-controller.js";
import { machineCredentialEnabled, tenantMutationEnabled, tenantReadsEnabled } from "./availability.js";
import { listingManagementEnabledFromEnv } from "./listing-availability.js";
import { policyManagementEnabledFromEnv } from "./policy-availability.js";
import { commerceSessionsEnabledFromEnv } from "./session-availability.js";
import { commerceActionsEnabledFromEnv } from "./action-availability.js";
import { parseActionRoute, type ActionRoute } from "./action-routes.js";
import {
  ActionController,
  initialActionControllerState,
  renderActionState,
  suppressStaleActionContext,
  type ActionControllerState,
  type ActionReadCoordinator,
} from "./action-controller.js";
import { ActionQueuePanel } from "./ActionQueuePanel.js";
import { ApprovalQueuePanel } from "./ApprovalQueuePanel.js";
import { ActionDetailPanel, ActionDecisionView } from "./ActionDetailPanel.js";
import { ApprovalDetailPanel } from "./ApprovalDetailPanel.js";
import { ActionExposurePanel } from "./ActionExposurePanel.js";
import { commerceGrantsEnabledFromEnv } from "./grant-availability.js";
import { parseGrantRoute, type GrantRoute } from "./grant-routes.js";
import {
  GrantController,
  initialGrantControllerState,
  renderGrantState,
  suppressStaleGrantContext,
  type GrantControllerState,
  type GrantReadCoordinator,
} from "./grant-controller.js";
import { GrantLookupPanel } from "./GrantLookupPanel.js";
import { GrantDetailPanel } from "./GrantDetailPanel.js";
import { parseSessionRoute, type SessionRoute } from "./session-routes.js";
import {
  SessionController,
  initialSessionControllerState,
  renderSessionState,
  suppressStaleSessionContext,
  type SessionAgentSelection,
  type SessionControllerState,
  type SessionReadCoordinator,
} from "./session-controller.js";
import { SessionListPanel } from "./SessionListPanel.js";
import { SessionIssuePanel, SessionMutationView } from "./SessionIssuePanel.js";
import { SessionStatusPanel } from "./SessionStatusPanel.js";
import { PolicyClient, readPolicyManagementCapability } from "./policy-client.js";
import { TenantMutationPanel } from "./TenantMutationPanel.js";
import { MachineCredentialPanel } from "./MachineCredentialPanel.js";
import { ListingListPanel } from "./ListingListPanel.js";
import { ListingEditorPanel, ListingLifecycleActions } from "./ListingEditorPanel.js";
import { ListingVersionHistory } from "./ListingVersionHistory.js";
import { PolicyListPanel } from "./PolicyListPanel.js";
import { PolicyRevisionHistory } from "./PolicyRevisionHistory.js";
import {
  beginAppendFromRevision,
  PolicyController,
  initialPolicyControllerState,
  renderPolicyState,
  suppressStalePolicyContext,
  type PolicyControllerState,
} from "./policy-controller.js";
import { parsePolicyRoute, type PolicyRoute } from "./policy-routes.js";
import {
  ListingController,
  initialListingControllerState,
  suppressStaleListingContext,
  type ListingControllerState,
} from "./listing-controller.js";
import { parseListingRoute, type ListingRoute } from "./listing-routes.js";
import {
  MachineCredentialController,
  initialMachineConsoleState,
  initialMachineCredentialListState,
  suppressStaleMachineContext,
  type MachineConsoleState,
  type MachineCredentialListState,
  type MachineCredentialTarget,
  type MachineReadCoordinator,
  type MachineRenderContext,
} from "./machine-controller.js";
import {
  TenantWriteController,
  initialTenantMutationState,
  type TenantMutationState,
} from "./tenant-write-controller.js";
import {
  renderMutationState,
  suppressPriorAccountMutation,
} from "./tenant-mutation-render.js";

import tenantCssUrl from "./tenant.css?url";
import listingCssUrl from "./market-listing.css?url";
import policyCssUrl from "./control-policy.css?url";
import sessionCssUrl from "./commerce-session.css?url";
import actionCssUrl from "./control-action.css?url";
import grantCssUrl from "./control-grant.css?url";

/**
 * Protected organization workspace.
 *
 * The flag gate renders a static unavailable state and constructs no
 * controller, so a disabled deployment makes zero auth or tenant requests.
 * When enabled, the workspace is a same-origin link-loaded stylesheet scoped
 * entirely under `.tenant-shell`, mounted for the component lifetime only.
 */

type AppPath =
  | "/app/overview"
  | "/app/agents"
  | "/app/provider"
  | "/app/provider/listings"
  | "/app/provider/listings/new"
  | "/app/budgets"
  | "/app/budgets/new"
  | "/app/sessions"
  | "/app/sessions/new"
  | "/app/actions"
  | "/app/actions/approvals"
  | "/app/actions/exposure"
  | "/app/grants";

type WorkspacePath =
  | AppPath
  | "/app"
  | { readonly kind: "listing-detail"; readonly listingId: string }
  | { readonly kind: "policy-detail"; readonly policyId: string }
  | { readonly kind: "session-detail"; readonly sessionId: string }
  | { readonly kind: "action-detail"; readonly actionId: string }
  | { readonly kind: "approval-detail"; readonly approvalId: string }
  | { readonly kind: "grant-detail"; readonly grantId: string }
  | "unknown";

function useTenantStyles(): void {
  useEffect(() => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = tenantCssUrl;
    link.dataset.tenantStyle = "true";
    document.head.append(link);
    return () => link.remove();
  }, []);
}

/** Mounts the scoped listing stylesheet for the feature lifetime only. */
function useListingStyles(active: boolean): void {
  useEffect(() => {
    if (!active) return;
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = listingCssUrl;
    link.dataset.listingStyle = "true";
    document.head.append(link);
    return () => link.remove();
  }, [active]);
}

/** Mounts the scoped policy stylesheet for the feature lifetime only. */
function usePolicyStyles(active: boolean): void {
  useEffect(() => {
    if (!active) return;
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = policyCssUrl;
    link.dataset.policyStyle = "true";
    document.head.append(link);
    return () => link.remove();
  }, [active]);
}

/** Mounts the scoped commerce-session stylesheet for the feature lifetime only. */
function useSessionStyles(active: boolean): void {
  useEffect(() => {
    if (!active) return;
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = sessionCssUrl;
    link.dataset.sessionStyle = "true";
    document.head.append(link);
    return () => link.remove();
  }, [active]);
}

/**
 * Mounts the scoped control-grant stylesheet for the feature lifetime only.
 * With the grant flag off this never runs, so the stylesheet is never fetched.
 */
function useGrantStyles(active: boolean): void {
  useEffect(() => {
    if (!active) return;
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = grantCssUrl;
    link.dataset.grantStyle = "true";
    document.head.append(link);
    return () => link.remove();
  }, [active]);
}

/** Mounts the scoped control-action stylesheet for the feature lifetime only. */
function useActionStyles(active: boolean): void {
  useEffect(() => {
    if (!active) return;
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = actionCssUrl;
    link.dataset.actionStyle = "true";
    document.head.append(link);
    return () => link.remove();
  }, [active]);
}

function currentPath(): WorkspacePath {
  if (typeof window === "undefined") return "/app";
  const raw = window.location.pathname.replace(/\/+$/u, "") || "/";
  if (raw === "/app") return "/app";
  if (raw === "/app/overview") return "/app/overview";
  if (raw === "/app/agents") return "/app/agents";
  if (raw === "/app/provider") return "/app/provider";
  if (raw.startsWith("/app/provider/listings")) {
    const listing = parseListingRoute(raw);
    if (listing === null) return "unknown";
    if (listing.kind === "roots") return "/app/provider/listings";
    if (listing.kind === "new") return "/app/provider/listings/new";
    if (listing.kind === "detail") return { kind: "listing-detail", listingId: listing.listingId };
  }
  if (raw === "/app/budgets") return "/app/budgets";
  if (raw === "/app/budgets/new") return "/app/budgets/new";
  if (raw.startsWith("/app/budgets/")) {
    const policy = parsePolicyRoute(raw);
    if (policy === null) return "unknown";
    if (policy.kind === "detail") return { kind: "policy-detail", policyId: policy.policyId };
  }
  if (raw.startsWith("/app/sessions")) {
    const session = parseSessionRoute(raw);
    if (session === null) return "unknown";
    if (session.kind === "roots") return "/app/sessions";
    if (session.kind === "new") return "/app/sessions/new";
    if (session.kind === "detail") return { kind: "session-detail", sessionId: session.sessionId };
    return "unknown";
  }
  if (raw.startsWith("/app/actions")) {
    const action = parseActionRoute(raw);
    if (action === null) return "unknown";
    if (action.kind === "queue") return "/app/actions";
    if (action.kind === "approvals") return "/app/actions/approvals";
    if (action.kind === "exposure") return "/app/actions/exposure";
    if (action.kind === "detail") return { kind: "action-detail", actionId: action.actionId };
    if (action.kind === "approval-detail") {
      return { kind: "approval-detail", approvalId: action.approvalId };
    }
    return "unknown";
  }
  if (raw.startsWith("/app/grants")) {
    const grant = parseGrantRoute(raw);
    if (grant === null) return "unknown";
    if (grant.kind === "lookup") return "/app/grants";
    if (grant.kind === "detail") return { kind: "grant-detail", grantId: grant.grantId };
    return "unknown";
  }
  if (raw.startsWith("/app/")) return "unknown";
  return "unknown";
}

/** True only for an implemented static workspace or protected listing path. */
function isKnownPath(path: WorkspacePath): boolean {
  return path !== "unknown";
}

/** The route object for a listing workspace path, or null when not listing. */
function listingRouteOf(path: WorkspacePath): ListingRoute | null {
  if (path === "/app/provider/listings") return { kind: "roots" };
  if (path === "/app/provider/listings/new") return { kind: "new" };
  if (typeof path === "object" && path.kind === "listing-detail") {
    return { kind: "detail", listingId: path.listingId };
  }
  return null;
}

function isListingWorkspacePath(path: WorkspacePath): boolean {
  return listingRouteOf(path) !== null;
}

/** The route object for a policy workspace path, or null when not policy. */
function policyRouteOf(path: WorkspacePath): PolicyRoute | null {
  if (path === "/app/budgets") return { kind: "roots" };
  if (path === "/app/budgets/new") return { kind: "new" };
  if (typeof path === "object" && path.kind === "policy-detail") {
    return { kind: "detail", policyId: path.policyId };
  }
  return null;
}

function isPolicyWorkspacePath(path: WorkspacePath): boolean {
  return policyRouteOf(path) !== null;
}

/** The route object for a session workspace path, or null when not session. */
function sessionRouteOf(path: WorkspacePath): SessionRoute | null {
  if (path === "/app/sessions") return { kind: "roots" };
  if (path === "/app/sessions/new") return { kind: "new" };
  if (typeof path === "object" && path.kind === "session-detail") {
    return { kind: "detail", sessionId: path.sessionId };
  }
  return null;
}

function isSessionWorkspacePath(path: WorkspacePath): boolean {
  return sessionRouteOf(path) !== null;
}

/** The route object for an action workspace path, or null when not action. */
function actionRouteOf(path: WorkspacePath): ActionRoute | null {
  if (path === "/app/actions") return { kind: "queue" };
  if (path === "/app/actions/approvals") return { kind: "approvals" };
  if (path === "/app/actions/exposure") return { kind: "exposure" };
  if (typeof path === "object" && path.kind === "action-detail") {
    return { kind: "detail", actionId: path.actionId };
  }
  if (typeof path === "object" && path.kind === "approval-detail") {
    return { kind: "approval-detail", approvalId: path.approvalId };
  }
  return null;
}

function isActionWorkspacePath(path: WorkspacePath): boolean {
  return actionRouteOf(path) !== null;
}

/** The route object for a grant workspace path, or null when not a grant. */
function grantRouteOf(path: WorkspacePath): GrantRoute | null {
  if (path === "/app/grants") return { kind: "lookup" };
  if (typeof path === "object" && path.kind === "grant-detail") {
    return { kind: "detail", grantId: path.grantId };
  }
  return null;
}

function isGrantWorkspacePath(path: WorkspacePath): boolean {
  return grantRouteOf(path) !== null;
}

export default function TenantApp() {
  const enabled = useMemo(() => tenantReadsEnabled() && accountAccessEnabled(), []);
  const writesEnabled = useMemo(
    () =>
      tenantMutationEnabled(
        import.meta.env.VITE_TENANT_WRITES_ENABLED,
        import.meta.env.VITE_TENANT_READS_ENABLED,
        import.meta.env.VITE_ACCOUNT_ACCESS_ENABLED,
      ),
    [],
  );
  const machineEnabled = useMemo(
    () =>
      machineCredentialEnabled(
        import.meta.env.VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED,
        import.meta.env.VITE_TENANT_WRITES_ENABLED,
        import.meta.env.VITE_TENANT_READS_ENABLED,
        import.meta.env.VITE_ACCOUNT_ACCESS_ENABLED,
      ),
    [],
  );
  // The listing surface is independent of the write and machine flags: it has
  // its own server authority and its own capability probe. All defaults false.
  const listingEnabled = useMemo(() => listingManagementEnabledFromEnv(), []);
  // The policy surface is independent of tenant writes, machine, listing,
  // Vault, wallet and session flags: it has its own server authority and its
  // own credentialless capability probe. All defaults false.
  const policyEnabled = useMemo(() => policyManagementEnabledFromEnv(), []);
  // The commerce-session surface is independent of tenant writes, machine,
  // listing, policy, Vault, wallet and market flags: it has its own server
  // authority and its own separate PUBLIC credentialless capability probe. All
  // defaults false, so a disabled deployment makes ZERO session requests.
  const sessionsEnabled = useMemo(() => commerceSessionsEnabledFromEnv(), []);
  // The commerce action/approval console is independent of tenant writes,
  // machine, listing, policy, session, Vault, wallet and market flags: it has
  // its own server authority and its own separate PUBLIC credentialless
  // capability probe. All defaults false, so a disabled deployment makes ZERO
  // action requests.
  const actionsEnabled = useMemo(() => commerceActionsEnabledFromEnv(), []);
  // The authorization-grant console is a strict superset of the commerce-action
  // and commerce-session consoles and has its own server authority plus its own
  // separate PUBLIC credentialless capability probe. It defaults to false, so a
  // disabled deployment constructs no grant controller, no grant client and no
  // stylesheet, and makes ZERO grant requests — the capability probe included.
  const grantsEnabled = useMemo(() => commerceGrantsEnabledFromEnv(), []);
  const [state, setState] = useState<TenantViewControllerState>(initialTenantState);
  const [mutationState, setMutationState] = useState<TenantMutationState>(initialTenantMutationState);
  const [machineState, setMachineState] = useState<MachineConsoleState>(initialMachineConsoleState);
  const [machineList, setMachineList] = useState<MachineCredentialListState>(initialMachineCredentialListState);
  const [listingState, setListingState] = useState<ListingControllerState>(initialListingControllerState);
  const [listingCreating, setListingCreating] = useState(false);
  const [listingProviderId, setListingProviderId] = useState<string | null>(null);
  const [listingBaseVersion, setListingBaseVersion] = useState<CommerceListingOwnerVersion | null>(null);
  const [policyState, setPolicyState] = useState<PolicyControllerState>(initialPolicyControllerState);
  const [policyCreating, setPolicyCreating] = useState(false);
  const [sessionState, setSessionState] = useState<SessionControllerState>(initialSessionControllerState);
  const [sessionSelectedAgent, setSessionSelectedAgent] = useState<string | null>(null);
  const [sessionPolicyOptions, setSessionPolicyOptions] = useState<readonly { policyId: string; status: string }[]>([]);
  const [sessionPolicyStatus, setSessionPolicyStatus] = useState<"none" | "loading" | "ready" | "error">("none");
  const [sessionPolicyNext, setSessionPolicyNext] = useState<string | null>(null);
  const sessionPolicyControllerRef = useRef<AbortController | null>(null);
  const sessionPolicyGenerationRef = useRef(0);
  // A monotonic generation that forces the policy create editor to REMOUNT
  // (and therefore reinitialize every useState field) on an external privacy
  // boundary: hidden/pagehide. Account/organization/role changes are already
  // part of the editor key below, so they remount synchronously in the same
  // render the context changes. The generation is committed inside the same
  // flushSync as the controller clear, so no previous form frame is painted.
  const [policyFormGeneration, setPolicyFormGeneration] = useState(0);
  // Monotonic privacy generation that remounts the session form/secret subtree
  // on an external hidden/pagehide boundary, committed inside the same
  // flushSync as the controller clear so no previous form frame is painted.
  const [sessionFormGeneration, setSessionFormGeneration] = useState(0);
  const [actionState, setActionState] = useState<ActionControllerState>(initialActionControllerState);
  // Monotonic privacy generation that remounts the exposure form subtree on an
  // external hidden/pagehide boundary, committed inside the same flushSync as
  // the controller clear so no previous form frame is painted.
  const [actionFormGeneration, setActionFormGeneration] = useState(0);
  const [grantState, setGrantState] = useState<GrantControllerState>(initialGrantControllerState);
  // Monotonic privacy generation that remounts the grant lookup form subtree on
  // an external hidden/pagehide boundary, committed inside the same flushSync as
  // the controller clear so no previous form frame is painted.
  const [grantFormGeneration, setGrantFormGeneration] = useState(0);
  const [selectedProfile, setSelectedProfile] = useState<MachineCredentialTarget | null>(null);
  const [path, setPath] = useState<WorkspacePath>(currentPath);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const menuButtonRef = useRef<HTMLButtonElement | null>(null);
  const drawerRef = useRef<HTMLDivElement | null>(null);
  const drawerCloseRef = useRef<HTMLButtonElement | null>(null);
  const restoreFocusRef = useRef(false);
  const controllerRef = useRef<TenantController | null>(null);
  const writeControllerRef = useRef<TenantWriteController | null>(null);
  const machineControllerRef = useRef<MachineCredentialController | null>(null);
  const listingControllerRef = useRef<ListingController | null>(null);
  const policyControllerRef = useRef<PolicyController | null>(null);
  const sessionControllerRef = useRef<SessionController | null>(null);
  const actionControllerRef = useRef<ActionController | null>(null);
  const grantControllerRef = useRef<GrantController | null>(null);
  const sessionSelectedAgentRef = useRef<string | null>(null);
  const boundMachineContextRef = useRef<MachineRenderContext | null>(null);
  const boundListingContextRef = useRef<{ accountId: string; organizationId: string; role: string | null } | null>(null);
  const boundPolicyContextRef = useRef<{ accountId: string; organizationId: string; role: string | null } | null>(null);
  const boundSessionContextRef = useRef<{ accountId: string; organizationId: string; role: string | null } | null>(null);
  const boundActionContextRef = useRef<{ accountId: string; organizationId: string; role: string | null } | null>(null);
  const boundGrantContextRef = useRef<{ accountId: string; organizationId: string; role: string | null } | null>(null);
  const listingOpenRef = useRef<((listingId: string) => void) | null>(null);
  const policyOpenRef = useRef<((policyId: string) => void) | null>(null);
  const accountRef = useRef<AccountFlowController | null>(null);
  const known = isKnownPath(path);

  // Aborts any in-flight optional policy-picker page and clears its bounded
  // options. Safe to call on any privacy/context boundary; it makes no request.
  const invalidateSessionPolicies = useCallback(() => {
    sessionPolicyGenerationRef.current += 1;
    sessionPolicyControllerRef.current?.abort();
    sessionPolicyControllerRef.current = null;
    setSessionPolicyOptions([]);
    setSessionPolicyStatus("none");
    setSessionPolicyNext(null);
  }, []);

  // The effective selected agent mirrors the issue panel: an explicit selection
  // or the first active agent of the current organization. The picker load and
  // the controller both bind to exactly this agent.
  const firstActiveAgentId =
    state.agents.items.find((item) => item.status === "active")?.agentId ?? null;
  const sessionEffectiveAgentId = sessionSelectedAgent ?? firstActiveAgentId;
  const accountId = state.principal.accountId;

  useTenantStyles();
  useListingStyles(listingEnabled);
  usePolicyStyles(policyEnabled);
  useSessionStyles(sessionsEnabled);
  useActionStyles(actionsEnabled);
  useGrantStyles(grantsEnabled);

  useEffect(() => {
    const onPopState = () => setPath(currentPath());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    // An unknown /app/* route must construct no controller and make zero auth
    // or tenant requests; only the three implemented routes initialize.
    if (!enabled || !known) return;
    // A fresh controller per mount keeps React's development double-invoke
    // safe: the first instance is disposed and the second owns the reads.
    const account = new AccountFlowController();
    const controller = new TenantController({ account, onState: setState });
    accountRef.current = account;
    controllerRef.current = controller;
    // The write controller is constructed ONLY when the write flag and all its
    // prerequisites are enabled. With writes off, no write client, controller
    // or form is ever created, so the read-only surface is byte-identical to
    // the accepted build and makes zero ADDITIONAL auth/write calls.
    const writeController = writesEnabled
      ? new TenantWriteController({
          account,
          reads: controller,
          onState: setMutationState,
        })
      : null;
    writeControllerRef.current = writeController;
    // The machine credential console is constructed ONLY when its own flag and
    // all four prerequisites are enabled. With it off, no machine client,
    // controller, panel, profile-selection control or machine request exists and
    // the surface is byte-identical to the accepted build. It never uses a
    // machine browser session or bearer transport.
    const machineReads: MachineReadCoordinator = {
      currentOrganizationId: () => controller.currentOrganizationId(),
      currentRole: () => controller.currentRole(),
      currentAccountId: () => account.state.session.signedIn ? account.state.session.accountId : null,
      abortPendingReads: () => controller.abortPendingReads(),
      reloadAfterCommit: async (kind) => {
        await controller.reloadAfterCommit(kind === "agent" ? "agents" : "providers");
      },
    };
    const machineController = machineEnabled
      ? new MachineCredentialController({
          account,
          reads: machineReads,
          isProfileActive: (kind, profileId) => profileIsActive(controller, kind, profileId),
          onState: setMachineState,
          onListState: setMachineList,
        })
      : null;
    machineControllerRef.current = machineController;
    // The listing controller is constructed ONLY when its own flag and all its
    // prerequisites are enabled. It mounts no read/write client request until a
    // protected listing route initializes the independent capability gate, and
    // it never depends on the tenant-write or machine-credential flags.
    const listingController = listingEnabled
      ? new ListingController({
          account,
          reads: {
            currentOrganizationId: () => controller.currentOrganizationId(),
            currentRole: () => controller.currentRole(),
            currentAccountId: () =>
              account.state.session.signedIn ? account.state.session.accountId : null,
            abortPendingReads: () => controller.abortPendingReads(),
            reloadAfterCommit: async () => {
              await controller.reloadAfterCommit("providers");
            },
          },
          onState: setListingState,
          onCommittedListing: (listingId) => listingOpenRef.current?.(listingId),
        })
      : null;
    listingControllerRef.current = listingController;
    // The policy controller is constructed ONLY when its own flag and all its
    // prerequisites are enabled. It mounts no request until a protected policy
    // route initializes the independent credentialless capability gate, and it
    // never depends on the tenant-write, machine, listing, Vault, wallet or
    // session flags. With it off, ZERO policy/capability requests are made.
    const policyController = policyEnabled
      ? new PolicyController({
          account,
          reads: {
            currentOrganizationId: () => controller.currentOrganizationId(),
            currentRole: () => controller.currentRole(),
            currentAccountId: () =>
              account.state.session.signedIn ? account.state.session.accountId : null,
            abortPendingReads: () => controller.abortPendingReads(),
            reloadAfterCommit: async () => {
              // Policy revisions are independent of the tenant read sections.
              // A context reload here would transiently clear the authoritative
              // role and erase the just-committed receipt, so the controller
              // reloads its own bounded policy page after the commit instead.
            },
          },
          onState: setPolicyState,
          onCommittedPolicy: (policyId) => policyOpenRef.current?.(policyId),
        })
      : null;
    policyControllerRef.current = policyController;
    // The commerce-session controller is constructed ONLY when its own flag and
    // all prerequisites are enabled. It mounts no request until a protected
    // session route initializes the independent public credentialless capability
    // gate, and it never depends on tenant-write, machine, listing, policy,
    // Vault, wallet or market flags. With it off, ZERO session/capability
    // requests are made. It never puts a machine bearer or commerce-session
    // token into this browser.
    const sessionReads: SessionReadCoordinator = {
      currentOrganizationId: () => controller.currentOrganizationId(),
      currentRole: () => controller.currentRole(),
      currentAccountId: () =>
        account.state.session.signedIn ? account.state.session.accountId : null,
      abortPendingReads: () => controller.abortPendingReads(),
      selectedActiveAgent: (): SessionAgentSelection | null => {
        const selectedId = sessionSelectedAgentRef.current;
        const items = controller.state.agents.items;
        if (selectedId !== null) {
          const selected = items.find((item) => item.agentId === selectedId);
          return selected !== undefined && selected.status === "active"
            ? { agentId: selected.agentId, status: selected.status }
            : null;
        }
        const firstActive = items.find((item) => item.status === "active");
        return firstActive === undefined
          ? null
          : { agentId: firstActive.agentId, status: firstActive.status };
      },
      reloadAfterCommit: async () => {
        // Session revisions are independent of the tenant read sections. A
        // context reload here would transiently clear the authoritative role and
        // erase the just-committed receipt, so no tenant reload is performed.
      },
    };
    const sessionController = sessionsEnabled
      ? new SessionController({
          account,
          reads: sessionReads,
          onState: setSessionState,
          // Deliberately NOT auto-navigating after a fresh issue: the one-time
          // handoff must remain on the issue panel for exactly one reveal.
        })
      : null;
    sessionControllerRef.current = sessionController;
    // The commerce-action controller is constructed ONLY when its own flag and
    // all prerequisites are enabled. It mounts no request until a protected
    // action route initializes the independent public credentialless capability
    // gate, and it never depends on tenant-write, machine, listing, policy,
    // session, Vault, wallet or market flags. With it off, ZERO action or
    // action-capability requests are made, and it never calls any of the three
    // agent-audience authorization routes.
    const actionReads: ActionReadCoordinator = {
      currentOrganizationId: () => controller.currentOrganizationId(),
      currentRole: () => controller.currentRole(),
      currentAccountId: () =>
        account.state.session.signedIn ? account.state.session.accountId : null,
      abortPendingReads: () => controller.abortPendingReads(),
    };
    const actionController = actionsEnabled
      ? new ActionController({
          account,
          reads: actionReads,
          onState: setActionState,
        })
      : null;
    actionControllerRef.current = actionController;
    // The authorization-grant controller is constructed ONLY when its own flag
    // and all prerequisites are enabled. It mounts no request until a protected
    // grant route initializes the independent public credentialless capability
    // gate. With it off, ZERO grant or grant-capability requests are made, and
    // it never calls any of the three agent-audience or three provider-audience
    // grant routes — the only two places a raw grant token exists on the wire.
    const grantReads: GrantReadCoordinator = {
      currentOrganizationId: () => controller.currentOrganizationId(),
      currentRole: () => controller.currentRole(),
      currentAccountId: () =>
        account.state.session.signedIn ? account.state.session.accountId : null,
      abortPendingReads: () => controller.abortPendingReads(),
    };
    const grantController = grantsEnabled
      ? new GrantController({
          account,
          reads: grantReads,
          onState: setGrantState,
        })
      : null;
    grantControllerRef.current = grantController;
    const onVisibility = () => {
      if (document.visibilityState === "hidden") {
        // The hidden boundary is external and synchronous: a browser may
        // discard the page (or snapshot it) the moment this handler returns, so
        // clearing controller memory and committing the corresponding React
        // state must both finish before returning. flushSync forces
        // onState/onListState commits here instead of in a later render.
        flushSync(() => {
          setDrawerOpen(false);
          controller.onHidden();
          writeController?.clear();
          machineController?.clear();
          listingController?.clear();
          policyController?.clear();
          sessionController?.clear();
          actionController?.clear();
          grantController?.clear();
          setPolicyFormGeneration((value) => value + 1);
          setSessionFormGeneration((value) => value + 1);
          setActionFormGeneration((value) => value + 1);
          setGrantFormGeneration((value) => value + 1);
          invalidateSessionPolicies();
        });
      }
    };
    const onPageHide = () => {
      flushSync(() => {
        controller.onHidden();
        writeController?.clear();
        machineController?.clear();
        listingController?.clear();
        policyController?.clear();
        sessionController?.clear();
        actionController?.clear();
        grantController?.clear();
        setPolicyFormGeneration((value) => value + 1);
        setSessionFormGeneration((value) => value + 1);
        setActionFormGeneration((value) => value + 1);
        setGrantFormGeneration((value) => value + 1);
        invalidateSessionPolicies();
      });
    };
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("pagehide", onPageHide);
    void controller.initialize();
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("pagehide", onPageHide);
      controller.dispose();
      writeController?.dispose();
      machineController?.dispose();
      listingController?.dispose();
      policyController?.dispose();
      sessionController?.dispose();
      actionController?.dispose();
      grantController?.dispose();
      if (controllerRef.current === controller) controllerRef.current = null;
      if (writeControllerRef.current === writeController) writeControllerRef.current = null;
      if (machineControllerRef.current === machineController) machineControllerRef.current = null;
      if (listingControllerRef.current === listingController) listingControllerRef.current = null;
      if (policyControllerRef.current === policyController) policyControllerRef.current = null;
      if (sessionControllerRef.current === sessionController) sessionControllerRef.current = null;
      if (actionControllerRef.current === actionController) actionControllerRef.current = null;
      if (grantControllerRef.current === grantController) grantControllerRef.current = null;
      if (accountRef.current === account) accountRef.current = null;
    };
  }, [enabled, known, writesEnabled, machineEnabled, listingEnabled, policyEnabled, sessionsEnabled, actionsEnabled, grantsEnabled, invalidateSessionPolicies]);

  // Clear the create/version selection when leaving the listing subtree.
  useEffect(() => {
    if (isListingWorkspacePath(path)) return;
    setListingCreating(false);
    setListingProviderId(null);
    setListingBaseVersion(null);
    listingControllerRef.current?.clearSensitive();
  }, [path]);

  // Clear the create selection when leaving the policy subtree.
  useEffect(() => {
    if (isPolicyWorkspacePath(path)) return;
    setPolicyCreating(false);
    policyControllerRef.current?.clearSensitive();
  }, [path]);

  // Clear the session selection/secret when leaving the session subtree.
  useEffect(() => {
    if (isSessionWorkspacePath(path)) return;
    sessionSelectedAgentRef.current = null;
    setSessionSelectedAgent(null);
    sessionControllerRef.current?.clear();
    invalidateSessionPolicies();
  }, [path, invalidateSessionPolicies]);

  // Clear every action artifact when leaving the action subtree.
  useEffect(() => {
    if (isActionWorkspacePath(path)) return;
    actionControllerRef.current?.clear();
  }, [path]);

  // Clear every grant artifact when leaving the grant subtree.
  useEffect(() => {
    if (isGrantWorkspacePath(path)) return;
    grantControllerRef.current?.clear();
  }, [path]);

  // A selected-agent change invalidates the picker binding and aborts any
  // in-flight policy page so a late response cannot repopulate options for the
  // previous agent.
  useEffect(() => {
    invalidateSessionPolicies();
  }, [sessionSelectedAgent, firstActiveAgentId, invalidateSessionPolicies]);

  // A signed-in identity change must never expose a previous account's
  // committed confirmation. The receipt belongs to the account that produced
  // it; a signed-out/expired transition (for example a self-demotion that
  // revoked this session) keeps the same account's committed evidence on
  // screen. Hidden/logout/navigation clears run separately in the flow.
  // Account change or session expiry/sign-out locks the local Vault in every
  // tab (R55, P08-02). Only settled principals count: the transient `loading`
  // state of an explicit refresh never locks. The Vault code is lazy-loaded.
  const principalStatus = state.principal.status;
  const vaultWatcherRef = useRef<VaultSessionEndWatcher | null>(null);
  useEffect(() => {
    const watcher = new VaultSessionEndWatcher();
    vaultWatcherRef.current = watcher;
    return () => {
      watcher.dispose();
      if (vaultWatcherRef.current === watcher) vaultWatcherRef.current = null;
    };
  }, []);
  useEffect(() => {
    if (principalStatus === "idle" || principalStatus === "loading") return;
    void vaultWatcherRef.current?.observe(accountId);
  }, [accountId, principalStatus]);

  const lastAccountRef = useRef<string | null>(null);
  useEffect(() => {
    if (accountId === null) return;
    if (lastAccountRef.current === null) {
      lastAccountRef.current = accountId;
      return;
    }
    if (lastAccountRef.current !== accountId) {
      lastAccountRef.current = accountId;
      writeControllerRef.current?.clear();
      setMutationState(initialTenantMutationState());
      machineControllerRef.current?.clear();
      setMachineState(initialMachineConsoleState());
      setMachineList(initialMachineCredentialListState());
      listingControllerRef.current?.clear();
      setListingCreating(false);
      setListingProviderId(null);
      setListingBaseVersion(null);
      policyControllerRef.current?.clear();
      setPolicyCreating(false);
      setSelectedProfile(null);
      sessionSelectedAgentRef.current = null;
      setSessionSelectedAgent(null);
      sessionControllerRef.current?.clear();
      actionControllerRef.current?.clear();
      grantControllerRef.current?.clear();
    }
  }, [accountId]);

  // An explicit profile selection binds the machine controller to exactly that
  // profile. A change of organization, role or profile clears the previous
  // context's list, receipt and one-time secret through the controller.
  const organizationId = state.selectedOrganizationId;
  const role: CommerceHumanRole | null = state.context?.access.role ?? null;
  useEffect(() => {
    // The listing controller is independent of the machine flag, so reconcile
    // its role before the machine early-return below.
    listingControllerRef.current?.reconcileRole(role);
    policyControllerRef.current?.reconcileRole(role);
    sessionControllerRef.current?.reconcileRole(role);
    actionControllerRef.current?.reconcileRole(role);
    grantControllerRef.current?.reconcileRole(role);
    const machineController = machineControllerRef.current;
    if (machineController === null) return;
    // Role is authoritative from the current server context. Reconcile it
    // explicitly (before reselection) so an owner->viewer->owner round trip
    // clears a same-profile secret/receipt/list instead of resurrecting it once
    // the synchronous render guard releases.
    machineController.reconcileRole(role);
    machineController.select(selectedProfile);
  }, [selectedProfile, organizationId, role, accountId]);

  // Organization change clears an explicit profile selection so no credential
  // panel is shown for a stale profile.
  useEffect(() => {
    setSelectedProfile(null);
    setListingCreating(false);
    setListingProviderId(null);
    setListingBaseVersion(null);
    listingControllerRef.current?.clear();
    policyControllerRef.current?.clear();
    setPolicyCreating(false);
    sessionSelectedAgentRef.current = null;
    setSessionSelectedAgent(null);
    sessionControllerRef.current?.clear();
    actionControllerRef.current?.clear();
    grantControllerRef.current?.clear();
    invalidateSessionPolicies();
  }, [organizationId, invalidateSessionPolicies]);

  // Initialize the listing controller only for a protected listing route. This
  // effect is declared AFTER the organization/role reconciliation effects so it
  // observes the authoritative context. The capability probe runs first and,
  // when it is not `enabled`, no listing request is made and an honest
  // unavailable state is rendered.
  useEffect(() => {
    const listingController = listingControllerRef.current;
    if (listingController === null) return;
    const route = listingRouteOf(path);
    if (route === null) return;
    void listingController.initialize(route);
  }, [path, listingEnabled, organizationId, role, accountId]);

  // Initialize the policy controller only for a protected policy route. The
  // capability probe runs first; when it is not `enabled`, no policy request is
  // made and an honest unavailable state is rendered.
  useEffect(() => {
    const policyController = policyControllerRef.current;
    if (policyController === null) return;
    const route = policyRouteOf(path);
    if (route === null) return;
    void policyController.initialize(route);
    // The policy create form needs the EXISTING current-organization agent read
    // state. Load that bounded read once for the new route (never a machine
    // profile and never a new endpoint).
    if (route.kind === "new") void controllerRef.current?.loadAgents();
  }, [path, policyEnabled, organizationId, role, accountId]);

  // Initialize the session controller only for a protected session route. The
  // public credentialless capability probe runs first; when it is not
  // `enabled`, no session request is made and an honest unavailable state is
  // rendered. The issue form needs the EXISTING current-organization agent read
  // state, so it is loaded once for the new route (never a machine profile and
  // never a new endpoint).
  useEffect(() => {
    const sessionController = sessionControllerRef.current;
    if (sessionController === null) return;
    const route = sessionRouteOf(path);
    if (route === null) return;
    void sessionController.initialize(route);
    if (route.kind === "new") void controllerRef.current?.loadAgents();
  }, [path, sessionsEnabled, organizationId, role, accountId]);

  // Initialize the action controller only for a protected action route. The
  // public credentialless capability probe runs first; when it is not
  // `enabled`, no action request is made and an honest unavailable state is
  // rendered.
  useEffect(() => {
    const actionController = actionControllerRef.current;
    if (actionController === null) return;
    const route = actionRouteOf(path);
    if (route === null) return;
    void actionController.initialize(route);
  }, [path, actionsEnabled, organizationId, role, accountId]);

  // Initialize the grant controller only for a protected grant route. The
  // public credentialless capability probe runs first; when it is not
  // `enabled`, no grant request is made and an honest unavailable state is
  // rendered. The lookup route issues no request at all: there is no grant list
  // endpoint and this console will not invent one.
  useEffect(() => {
    const grantController = grantControllerRef.current;
    if (grantController === null) return;
    const route = grantRouteOf(path);
    if (route === null) return;
    void grantController.initialize(route);
  }, [path, grantsEnabled, organizationId, role, accountId]);

  // After the render where the grant context is current, record the bound
  // account/organization/role so the NEXT transition render suppresses
  // synchronously before any child can read a stale grant detail or revoke.
  useEffect(() => {
    if (
      grantControllerRef.current === null ||
      !isGrantWorkspacePath(path) ||
      organizationId === null ||
      accountId === null
    ) {
      boundGrantContextRef.current = null;
      return;
    }
    boundGrantContextRef.current = { accountId, organizationId, role };
  }, [path, organizationId, accountId, role]);

  // After the render where the action context is current, record the bound
  // account/organization/role so the NEXT transition render suppresses
  // synchronously before any child can read a stale queue, detail or decision.
  useEffect(() => {
    if (
      actionControllerRef.current === null ||
      !isActionWorkspacePath(path) ||
      organizationId === null ||
      accountId === null
    ) {
      boundActionContextRef.current = null;
      return;
    }
    boundActionContextRef.current = { accountId, organizationId, role };
  }, [path, organizationId, accountId, role]);

  // After the render where the session context is current, record the bound
  // account/organization/role so the NEXT transition render suppresses
  // synchronously before any child can read a stale draft, receipt or secret.
  useEffect(() => {
    if (
      sessionControllerRef.current === null ||
      !isSessionWorkspacePath(path) ||
      organizationId === null ||
      accountId === null
    ) {
      boundSessionContextRef.current = null;
      return;
    }
    boundSessionContextRef.current = { accountId, organizationId, role };
  }, [path, organizationId, accountId, role]);

  // After the render where the machine context is current, record the bound
  // context so the NEXT transition render can suppress synchronously. When the
  // controller is cleared/absent the bound context is null.
  useEffect(() => {
    const machineController = machineControllerRef.current;
    if (machineController === null || selectedProfile === null || organizationId === null || accountId === null) {
      boundMachineContextRef.current = null;
      return;
    }
    boundMachineContextRef.current = {
      accountId,
      organizationId,
      role,
      kind: selectedProfile.kind,
      profileId: selectedProfile.profileId,
    };
  }, [selectedProfile, organizationId, accountId, role]);

  // After the render where the listing context is current, record the bound
  // account/organization/role so the NEXT transition render suppresses
  // synchronously before any child can read a stale draft, receipt or list.
  useEffect(() => {
    if (
      listingControllerRef.current === null ||
      !isListingWorkspacePath(path) ||
      organizationId === null ||
      accountId === null
    ) {
      boundListingContextRef.current = null;
      return;
    }
    boundListingContextRef.current = { accountId, organizationId, role };
  }, [path, organizationId, accountId, role]);

  // After the render where the policy context is current, record the bound
  // account/organization/role so the NEXT transition render suppresses
  // synchronously before any child can read a stale draft, receipt or list.
  useEffect(() => {
    if (
      policyControllerRef.current === null ||
      !isPolicyWorkspacePath(path) ||
      organizationId === null ||
      accountId === null
    ) {
      boundPolicyContextRef.current = null;
      return;
    }
    boundPolicyContextRef.current = { accountId, organizationId, role };
  }, [path, organizationId, accountId, role]);

  // Synchronous privacy guard: effects run after render, so the effect above
  // alone would paint one stale frame of account A's receipt/form for account
  // B. Compute this during render and expose only the guarded state/controller
  // to the Workspace, because the mutation panel also reads controller.state
  // directly. A->null is intentionally allowed so a self-demotion receipt from
  // the same account survives the session revocation.
  const suppressPriorMutation = suppressPriorAccountMutation(lastAccountRef.current, accountId);
  const renderedMutationState = renderMutationState(
    lastAccountRef.current,
    accountId,
    mutationState,
    initialTenantMutationState,
  );
  const renderedWriteController = suppressPriorMutation ? null : writeControllerRef.current;

  // Synchronous machine context guard. The credential console may hold a
  // one-time secret and a receipt bound to an exact account/organization/role
  // and profile. `boundMachineContextRef` is the context the controller was last
  // bound to; it is updated in an effect, so during a transition render the ref
  // still names the OLD context and the guard suppresses synchronously before
  // any child can read stale state. Effects alone would paint one stale frame.
  const currentMachineContext: MachineRenderContext = {
    accountId,
    organizationId,
    role,
    kind: selectedProfile?.kind ?? null,
    profileId: selectedProfile?.profileId ?? null,
  };
  const suppressMachine =
    machineControllerRef.current !== null &&
    (suppressPriorMutation ||
      suppressStaleMachineContext(boundMachineContextRef.current, currentMachineContext));

  const suppressListing =
    listingControllerRef.current !== null &&
    (suppressPriorMutation ||
      suppressStaleListingContext(
        boundListingContextRef.current !== null && accountId !== null && organizationId !== null
          ? {
              accountId: boundListingContextRef.current.accountId,
              organizationId: boundListingContextRef.current.organizationId,
              role: boundListingContextRef.current.role,
            }
          : null,
        { accountId, organizationId, role },
      ));

  const suppressPolicy =
    policyControllerRef.current !== null &&
    (suppressPriorMutation ||
      suppressStalePolicyContext(
        boundPolicyContextRef.current !== null && accountId !== null && organizationId !== null
          ? {
              accountId: boundPolicyContextRef.current.accountId,
              organizationId: boundPolicyContextRef.current.organizationId,
              role: boundPolicyContextRef.current.role,
            }
          : null,
        { accountId, organizationId, role },
      ));

  const suppressSession =
    sessionControllerRef.current !== null &&
    (suppressPriorMutation ||
      suppressStaleSessionContext(
        boundSessionContextRef.current,
        { accountId, organizationId, role },
      ));

  const suppressAction =
    actionControllerRef.current !== null &&
    (suppressPriorMutation ||
      suppressStaleActionContext(
        boundActionContextRef.current,
        { accountId, organizationId, role },
      ));

  const suppressGrant =
    grantControllerRef.current !== null &&
    (suppressPriorMutation ||
      suppressStaleGrantContext(
        boundGrantContextRef.current,
        { accountId, organizationId, role },
      ));

  // The policy create editor is keyed by its FULL bound context plus the
  // external privacy generation. A context change remounts it in the SAME
  // render (so no stale caps/allowlists/expiry/agent selection survive), and a
  // hidden/pagehide boundary bumps the generation inside flushSync so the
  // remount happens before the next paint. This is a privacy guard only: it
  // never derives server authority.
  const policyFormKey = `${accountId ?? "anon"}|${organizationId ?? "none"}|${role ?? "none"}|${policyFormGeneration}`;

  // The session issue/list subtree is keyed by its FULL bound context so a
  // context change remounts it and no typed policy id or one-time secret can
  // survive a same-route organization/role transition.
  const sessionFormKey = `${accountId ?? "anon"}|${organizationId ?? "none"}|${role ?? "none"}|${
    sessionSelectedAgent ?? "none"
  }|${path === "/app/sessions/new" ? "new" : "list"}|${sessionFormGeneration}`;

  // The action console subtree is keyed by its FULL bound context so a context
  // change remounts it and no typed exposure subject or pending confirmation
  // can survive a same-route organization/role transition.
  const actionFormKey = `${accountId ?? "anon"}|${organizationId ?? "none"}|${role ?? "none"}|${actionFormGeneration}`;

  // The grant console subtree is keyed by its FULL bound context so a context
  // change remounts it and no typed grant id or pending confirmation can
  // survive a same-route organization/role transition.
  const grantFormKey = `${accountId ?? "anon"}|${organizationId ?? "none"}|${role ?? "none"}|${grantFormGeneration}`;

  useEffect(() => {
    if (!drawerOpen) return;
    // Initial focus moves into the dialog.
    drawerCloseRef.current?.focus();
    const main = document.querySelector<HTMLElement>(".tenant-main");
    const rail = document.querySelector<HTMLElement>(".tenant-rail--static");
    main?.setAttribute("inert", "");
    rail?.setAttribute("inert", "");
    return () => {
      main?.removeAttribute("inert");
      rail?.removeAttribute("inert");
    };
  }, [drawerOpen]);

  // Restore focus to the trigger only AFTER the drawer has unmounted, so the
  // browser cannot move focus to the body when the dialog's node is removed.
  useEffect(() => {
    if (drawerOpen || !restoreFocusRef.current) return;
    restoreFocusRef.current = false;
    menuButtonRef.current?.focus();
  }, [drawerOpen]);

  const closeDrawer = useCallback(() => {
    restoreFocusRef.current = true;
    setDrawerOpen(false);
  }, []);

  const onDrawerKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeDrawer();
        return;
      }
      if (event.key !== "Tab") return;
      const focusables = drawerRef.current?.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
      );
      if (focusables === undefined || focusables.length === 0) return;
      const first = focusables[0]!;
      const last = focusables[focusables.length - 1]!;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    },
    [closeDrawer],
  );

  const navigate = useCallback((next: AppPath) => {
    writeControllerRef.current?.clear();
    listingControllerRef.current?.clearSensitive();
    policyControllerRef.current?.clearSensitive();
    sessionControllerRef.current?.clear();
    actionControllerRef.current?.clear();
    grantControllerRef.current?.clear();
    setListingCreating(false);
    setListingProviderId(null);
    setListingBaseVersion(null);
    setPolicyCreating(false);
    sessionSelectedAgentRef.current = null;
    setSessionSelectedAgent(null);
    setMutationState(initialTenantMutationState());
    setDrawerOpen(false);
    window.history.pushState(null, "", next);
    setPath(next);
  }, []);

  const openListing = useCallback((listingId: string) => {
    const route = parseListingRoute(`/app/provider/listings/${encodeURIComponent(listingId)}`);
    if (route === null || route.kind !== "detail") return;
    setDrawerOpen(false);
    window.history.pushState(null, "", `/app/provider/listings/${encodeURIComponent(route.listingId)}`);
    setPath({ kind: "listing-detail", listingId: route.listingId });
  }, []);
  useEffect(() => {
    listingOpenRef.current = openListing;
  }, [openListing]);

  const openPolicy = useCallback((policyId: string) => {
    const route = parsePolicyRoute(`/app/budgets/${encodeURIComponent(policyId)}`);
    if (route === null || route.kind !== "detail") return;
    setDrawerOpen(false);
    window.history.pushState(null, "", `/app/budgets/${encodeURIComponent(route.policyId)}`);
    setPath({ kind: "policy-detail", policyId: route.policyId });
  }, []);
  useEffect(() => {
    policyOpenRef.current = openPolicy;
  }, [openPolicy]);

  const openSession = useCallback((sessionId: string) => {
    const route = parseSessionRoute(`/app/sessions/${encodeURIComponent(sessionId)}`);
    if (route === null || route.kind !== "detail") return;
    setDrawerOpen(false);
    window.history.pushState(null, "", `/app/sessions/${encodeURIComponent(route.sessionId)}`);
    setPath({ kind: "session-detail", sessionId: route.sessionId });
  }, []);
  const openSessionCreate = useCallback(() => {
    navigate("/app/sessions/new");
  }, [navigate]);

  const openAction = useCallback((actionId: string) => {
    const route = parseActionRoute(`/app/actions/${encodeURIComponent(actionId)}`);
    if (route === null || route.kind !== "detail") return;
    setDrawerOpen(false);
    window.history.pushState(null, "", `/app/actions/${encodeURIComponent(route.actionId)}`);
    setPath({ kind: "action-detail", actionId: route.actionId });
  }, []);

  const openApproval = useCallback((approvalId: string) => {
    const route = parseActionRoute(`/app/actions/approvals/${encodeURIComponent(approvalId)}`);
    if (route === null || route.kind !== "approval-detail") return;
    setDrawerOpen(false);
    window.history.pushState(
      null,
      "",
      `/app/actions/approvals/${encodeURIComponent(route.approvalId)}`,
    );
    setPath({ kind: "approval-detail", approvalId: route.approvalId });
  }, []);

  const openGrant = useCallback((grantId: string) => {
    const route = parseGrantRoute(`/app/grants/${encodeURIComponent(grantId)}`);
    if (route === null || route.kind !== "detail") return;
    setDrawerOpen(false);
    window.history.pushState(null, "", `/app/grants/${encodeURIComponent(route.grantId)}`);
    setPath({ kind: "grant-detail", grantId: route.grantId });
  }, []);

  // Bounded current-organization policy picker via the accepted PolicyClient
  // directly. It runs ONLY when the existing policy UI and capability are
  // enabled; with policy off it makes NO policy request and the manual field
  // stays usable. The picker binds the active policy to the selected agent's
  // current organization and never borrows a stale org.
  // The picker is an OPTIONAL, frozen dependency. It runs ONLY when the policy
  // UI is enabled AND the independent policy capability is `enabled` (a
  // credentialless probe). It binds each option to the selected current-org
  // active agent and REPLACES the bounded page instead of accumulating pages.
  // With policy off (or capability not enabled) it makes NO policy request and
  // the manual canonical policy ID stays usable.
  const loadSessionPolicies = useCallback(
    async (cursor: string | null, selectedAgentId: string | null) => {
      if (!policyEnabled) return;
      const organizationId = controllerRef.current?.currentOrganizationId() ?? null;
      if (organizationId === null || selectedAgentId === null) return;
      sessionPolicyGenerationRef.current += 1;
      const generation = sessionPolicyGenerationRef.current;
      sessionPolicyControllerRef.current?.abort();
      const abort = new AbortController();
      sessionPolicyControllerRef.current = abort;
      setSessionPolicyStatus("loading");
      try {
        // A bounded keyed same-paint remount already cleared the previous page;
        // this replaces it (no unbounded accumulation across pages).
        const capability = await readPolicyManagementCapability(abort.signal);
        if (abort.signal.aborted || generation !== sessionPolicyGenerationRef.current) return;
        if (capability !== "enabled") {
          setSessionPolicyOptions([]);
          setSessionPolicyNext(null);
          setSessionPolicyStatus("none");
          return;
        }
        const page = await new PolicyClient().listRoots(
          { organizationId, ...(cursor === null ? {} : { afterPolicyId: cursor }), limit: 50 },
          abort.signal,
        );
        if (abort.signal.aborted || generation !== sessionPolicyGenerationRef.current) return;
        if (controllerRef.current?.currentOrganizationId() !== organizationId) return;
        if (controllerRef.current?.currentRole() !== role) return;
        setSessionPolicyOptions(
          page.items
            .filter(
              (item) =>
                item.subjectAgentId === selectedAgentId &&
                item.status === "active" &&
                item.organizationId === organizationId,
            )
            .map((item) => ({ policyId: item.policyId, status: item.status })),
        );
        setSessionPolicyNext(page.nextCursor);
        setSessionPolicyStatus("ready");
      } catch {
        if (abort.signal.aborted || generation !== sessionPolicyGenerationRef.current) return;
        setSessionPolicyOptions([]);
        setSessionPolicyNext(null);
        setSessionPolicyStatus("error");
      }
    },
    [policyEnabled, role],
  );

  const loadMoreSessionPolicies = useCallback(() => {
    const cursor = sessionPolicyNext;
    if (cursor === null) return;
    void loadSessionPolicies(cursor, sessionEffectiveAgentId);
  }, [loadSessionPolicies, sessionPolicyNext, sessionEffectiveAgentId]);

  const selectOrganization = useCallback(
    (organizationId: string) => {
      writeControllerRef.current?.clear();
      setMutationState(initialTenantMutationState());
      const controller = controllerRef.current;
      if (controller === null) return;
      void controller.selectOrganization(organizationId as never);
    },
    [],
  );

  if (!enabled) return <TenantUnavailable />;

  const context = state.context;
  const selectedId = state.selectedOrganizationId;
  const currentOrganization =
    context !== null
      ? { displayName: context.organization.displayName, role: context.access.role, status: context.access.membershipStatus }
      : null;

  const activePath: AppPath | null =
    path === "/app"
      ? "/app/overview"
      : path === "unknown"
        ? null
        : typeof path === "object"
          ? path.kind === "policy-detail"
            ? "/app/budgets"
            : path.kind === "session-detail"
              ? "/app/sessions"
              : "/app/provider/listings"
          : path;

  return (
    <div className="tenant-shell">
      <a className="tenant-skip" href="#tenant-main">
        Skip to workspace content
      </a>

      <Rail
        staticRail
        state={state}
        currentPath={activePath}
        currentOrganization={currentOrganization}
        onSelect={selectOrganization}
        onNavigate={navigate}
      />

      {drawerOpen ? (
        <>
          <div className="tenant-scrim" onClick={closeDrawer} aria-hidden="true" />
          <div
            id="tenant-drawer"
            ref={drawerRef}
            className="tenant-drawer"
            role="dialog"
            aria-modal="true"
            aria-label="Workspace navigation"
            onKeyDown={onDrawerKeyDown}
          >
            <button
              type="button"
              ref={drawerCloseRef}
              className="tenant-menu-button"
              style={{ margin: "12px 18px" }}
              onClick={closeDrawer}
            >
              Close navigation menu
            </button>
            <Rail
              state={state}
              currentPath={activePath}
              currentOrganization={currentOrganization}
              onSelect={(id) => {
                closeDrawer();
                selectOrganization(id);
              }}
              onNavigate={(next) => {
                closeDrawer();
                navigate(next);
              }}
            />
          </div>
        </>
      ) : null}

      <div className="tenant-main">
        <header className="tenant-topbar">
          <a className="tenant-topbar__brand" href="/design" aria-label="OpenArc home">
            <img src="/openarc-logo.jpeg" alt="" width={32} height={32} />
            <span>OPENARC</span>
          </a>
          <button
            type="button"
            ref={menuButtonRef}
            className="tenant-menu-button"
            aria-expanded={drawerOpen}
            aria-controls="tenant-drawer"
            onClick={() => setDrawerOpen((open) => !open)}
          >
            {drawerOpen ? "Close menu" : "Menu"}
          </button>
        </header>

        <main id="tenant-main" className="tenant-content" tabIndex={-1}>
          {/*
            Keyed subtree + synchronous guard: while the machine context is
            suppressed the immediate subtree is keyed to the new context AND the
            machine props are null, so no credential state, secret or list can
            be read by a child during the transition render.
          */}
          <Workspace
            key={`machine-context:${suppressMachine ? "suppressed" : `${organizationId ?? "none"}/${
              selectedProfile?.kind ?? "none"
            }/${selectedProfile?.profileId ?? "none"}`}`}
            path={path}
            state={state}
            selectedId={selectedId}
            currentOrganization={currentOrganization}
            onSelect={selectOrganization}
            onNavigate={navigate}
            controller={controllerRef.current}
            writeController={renderedWriteController}
            mutationState={renderedMutationState}
            machineController={suppressMachine ? null : machineControllerRef.current}
            machineState={suppressMachine ? initialMachineConsoleState() : machineState}
            machineList={suppressMachine ? initialMachineCredentialListState() : machineList}
            onSelectProfile={setSelectedProfile}
            machineEnabled={machineEnabled}
            listingEnabled={listingEnabled}
            listingState={suppressListing ? initialListingControllerState() : listingState}
            listingController={suppressListing ? null : listingControllerRef.current}
            listingCreating={listingCreating}
            listingProviderId={listingProviderId}
            listingBaseVersion={listingBaseVersion}
            onSelectListingProvider={setListingProviderId}
            onStartListingCreate={() => {
              setListingCreating(true);
              void listingControllerRef.current?.loadProviderOptions();
            }}
            onCancelListingCreate={() => setListingCreating(false)}
            onSelectListingBaseVersion={(version) => {
              setListingBaseVersion(version);
              listingControllerRef.current?.selectVersion(version);
            }}
            onOpenListing={openListing}
            policyEnabled={policyEnabled}
            policyState={renderPolicyState(suppressPolicy, policyState)}
            policyController={suppressPolicy ? null : policyControllerRef.current}
            policyCreating={policyCreating}
            policyFormKey={policyFormKey}
            onStartPolicyCreate={() => {
              setPolicyCreating(true);
              void controllerRef.current?.loadAgents();
            }}
            onCancelPolicyCreate={() => setPolicyCreating(false)}
            onOpenPolicy={openPolicy}
            sessionsEnabled={sessionsEnabled}
            sessionState={renderSessionState(suppressSession, sessionState)}
            sessionController={suppressSession ? null : sessionControllerRef.current}
            sessionSelectedAgentId={sessionSelectedAgent}
            onSelectSessionAgent={(agentId) => {
              sessionSelectedAgentRef.current = agentId;
              setSessionSelectedAgent(agentId);
              sessionControllerRef.current?.selectAgent(agentId);
            }}
            policyPickerEnabled={policyEnabled}
            policyOptions={sessionPolicyOptions}
            policyOptionsStatus={sessionPolicyStatus}
            hasNextPolicies={sessionPolicyNext !== null}
            onLoadPolicies={() => void loadSessionPolicies(null, sessionEffectiveAgentId)}
            onLoadMorePolicies={() => void loadMoreSessionPolicies()}
            onOpenSession={openSession}
            onStartSessionIssue={openSessionCreate}
            sessionFormKey={sessionFormKey}
            actionsEnabled={actionsEnabled}
            actionState={renderActionState(suppressAction, actionState)}
            actionController={suppressAction ? null : actionControllerRef.current}
            actionFormKey={actionFormKey}
            onOpenAction={openAction}
            onOpenApproval={openApproval}
            grantsEnabled={grantsEnabled}
            grantState={renderGrantState(suppressGrant, grantState)}
            grantController={suppressGrant ? null : grantControllerRef.current}
            grantFormKey={grantFormKey}
            onOpenGrant={openGrant}
          />
        </main>

        <footer className="tenant-footer">
          <span className="tenant-mono">
            {machineEnabled
              ? `NON-CUSTODIAL · NO PAYMENTS · MACHINE CREDENTIALS · ${ARC_TESTNET.caip2}`
              : writesEnabled
              ? `NON-CUSTODIAL · NO PAYMENTS · ${ARC_TESTNET.caip2}`
              : `NON-CUSTODIAL · READ-ONLY WORKSPACE · ${ARC_TESTNET.caip2}`}
          </span>
        </footer>
      </div>
    </div>
  );
}

interface RailProps {
  state: TenantViewControllerState;
  currentPath: AppPath | null;
  currentOrganization: { displayName: string; role: CommerceHumanRole; status: "active" | "suspended" } | null;
  onSelect: (organizationId: string) => void;
  onNavigate: (path: AppPath) => void;
  staticRail?: boolean;
}

function Rail(props: RailProps) {
  const { organizations, principal } = props.state;
  const navItems: Array<{ path: AppPath; label: string }> = [
    { path: "/app/overview", label: "Overview" },
    { path: "/app/agents", label: "Agents" },
    { path: "/app/provider", label: "Provider" },
    { path: "/app/provider/listings", label: "Listings" },
    { path: "/app/budgets", label: "Budgets" },
    { path: "/app/sessions", label: "Sessions" },
    { path: "/app/actions", label: "Actions" },
    { path: "/app/grants", label: "Grants" },
  ];
  return (
    <nav
      className={props.staticRail === true ? "tenant-rail tenant-rail--static" : "tenant-rail"}
      aria-label="Organization workspace"
    >
      <a className="tenant-brand" href="/design" aria-label="OpenArc home">
        <img className="tenant-brand__logo" src="/openarc-logo.jpeg" alt="" width={38} height={38} />
        <span>
          <span className="tenant-brand__name">OPENARC</span>
          <span className="tenant-brand__sub">AGENT CONSOLE</span>
        </span>
      </a>

      <div className="tenant-rail__section">
        <p className="tenant-rail__label" id="tenant-org-label">
          Organization
        </p>
        {principal.status === "signed-in" ? (
          <select
            className="tenant-org-select"
            aria-labelledby="tenant-org-label"
            value={props.state.selectedOrganizationId ?? ""}
            disabled={organizations.status === "loading"}
            onChange={(event) => {
              if (event.target.value.length > 0) props.onSelect(event.target.value);
            }}
          >
            <option value="">Choose an organization to continue.</option>
            {organizations.items.map((organization) => (
              <option key={organization.organizationId} value={organization.organizationId}>
                {organization.displayName}
              </option>
            ))}
          </select>
        ) : null}
        {props.currentOrganization !== null ? (
          <p className="tenant-org-current">
            <strong>{props.currentOrganization.displayName}</strong>
            <br />
            <span className="tenant-org-role">
              {roleLabel(props.currentOrganization.role)} ·{" "}
              {props.currentOrganization.status === "active" ? "ACTIVE" : "SUSPENDED"}
            </span>
          </p>
        ) : null}
      </div>

      <div className="tenant-rail__section">
        <p className="tenant-rail__label">Workspace</p>
        <ul className="tenant-nav">
          {navItems.map((item) => (
            <li key={item.path}>
              <a
                href={item.path}
                aria-current={props.currentPath === item.path ? "page" : undefined}
                onClick={(event) => {
                  event.preventDefault();
                  props.onNavigate(item.path);
                }}
              >
                {item.label}
              </a>
            </li>
          ))}
        </ul>
      </div>

      <div className="tenant-rail__section">
        <p className="tenant-rail__label">Elsewhere</p>
        <ul className="tenant-nav">
          <li>
            <a href="/account">Account</a>
          </li>
          <li>
            <a href="/design/docs">Docs</a>
          </li>
          <li>
            <a href="/workspace">Local workspace</a>
          </li>
        </ul>
      </div>

      <div className="tenant-rail__spacer" />
      <span className="tenant-testnet">
        <span className="tenant-testnet__dot" aria-hidden="true" />
        TESTNET
      </span>
      <p className="tenant-rail__meta">
        chain {ARC_TESTNET.chainId}
        <br />
        {ARC_TESTNET.currencySymbol}
      </p>
    </nav>
  );
}

interface WorkspaceProps {
  path: WorkspacePath;
  state: TenantViewControllerState;
  selectedId: string | null;
  currentOrganization: { displayName: string; role: CommerceHumanRole; status: "active" | "suspended" } | null;
  onSelect: (organizationId: string) => void;
  onNavigate: (path: AppPath) => void;
  controller: TenantController | null;
  writeController: TenantWriteController | null;
  mutationState: TenantMutationState;
  machineController: MachineCredentialController | null;
  machineState: MachineConsoleState;
  machineList: MachineCredentialListState;
  onSelectProfile: (target: MachineCredentialTarget | null) => void;
  machineEnabled: boolean;
  listingEnabled: boolean;
  listingState: ListingControllerState;
  listingController: ListingController | null;
  listingCreating: boolean;
  listingProviderId: string | null;
  listingBaseVersion: CommerceListingOwnerVersion | null;
  onSelectListingProvider: (providerId: string) => void;
  onStartListingCreate: () => void;
  onCancelListingCreate: () => void;
  onSelectListingBaseVersion: (version: CommerceListingOwnerVersion) => void;
  onOpenListing: (listingId: string) => void;
  policyEnabled: boolean;
  policyState: PolicyControllerState;
  policyController: PolicyController | null;
  policyCreating: boolean;
  policyFormKey: string;
  onStartPolicyCreate: () => void;
  onCancelPolicyCreate: () => void;
  onOpenPolicy: (policyId: string) => void;
  sessionsEnabled: boolean;
  sessionState: SessionControllerState;
  sessionController: SessionController | null;
  sessionSelectedAgentId: string | null;
  onSelectSessionAgent: (agentId: string | null) => void;
  policyPickerEnabled: boolean;
  policyOptions: readonly { policyId: string; status: string }[];
  policyOptionsStatus: "none" | "loading" | "ready" | "error";
  hasNextPolicies: boolean;
  onLoadPolicies: () => void;
  onLoadMorePolicies: () => void;
  onOpenSession: (sessionId: string) => void;
  onStartSessionIssue: () => void;
  sessionFormKey: string;
  actionsEnabled: boolean;
  actionState: ActionControllerState;
  actionController: ActionController | null;
  actionFormKey: string;
  onOpenAction: (actionId: string) => void;
  onOpenApproval: (approvalId: string) => void;
  grantsEnabled: boolean;
  grantState: GrantControllerState;
  grantController: GrantController | null;
  grantFormKey: string;
  onOpenGrant: (grantId: string) => void;
}

function Workspace(props: WorkspaceProps) {
  const { state } = props;
  const { principal } = state;

  // A committed receipt or an unconfirmed outcome must stay visible while the
  // organization list refreshes after a bootstrap create and no organization
  // is selected yet. These are terminal, form-free states: they never enable a
  // new create outside the real first-organization context.
  const stickyMutation =
    props.writeController !== null &&
    (props.mutationState.kind === "committed" || props.mutationState.kind === "outcome-unknown");
  // After a session revocation only the authoritative committed receipt is
  // kept: never a draft, an in-flight unknown or a recoverable check action.
  const committedReceipt =
    props.writeController !== null && props.mutationState.kind === "committed";

  // Unknown /app/* routes are bounded before any principal or read handling:
  // no controller is constructed and no auth or tenant request is made.
  if (props.path === "unknown") return <NotAvailable onNavigate={props.onNavigate} />;

  const listingRoute = listingRouteOf(props.path);
  if (listingRoute !== null) {
    // A listing route is known (not "unknown"): with the flag off nothing was
    // constructed and the section is honestly unavailable. With the flag on the
    // controller's independent capability gate decides the rendered state.
    if (!props.listingEnabled) return <NotAvailable onNavigate={props.onNavigate} />;
  }

  const policyRoute = policyRouteOf(props.path);
  if (policyRoute !== null) {
    // A policy route is known (not "unknown"): with the flag off nothing was
    // constructed and the section is honestly unavailable. With the flag on the
    // controller's independent capability gate decides the rendered state.
    if (!props.policyEnabled) return <NotAvailable onNavigate={props.onNavigate} />;
  }

  const actionRoute = actionRouteOf(props.path);
  if (actionRoute !== null) {
    // An action route is known (not "unknown"): with the flag off nothing was
    // constructed and the section is honestly unavailable. With the flag on the
    // controller's independent public capability gate decides the rendered state.
    if (!props.actionsEnabled) return <NotAvailable onNavigate={props.onNavigate} />;
  }

  const grantRoute = grantRouteOf(props.path);
  if (grantRoute !== null) {
    // A grant route is known (not "unknown"): with the flag off nothing was
    // constructed and the section is honestly unavailable. With the flag on the
    // controller's independent public capability gate decides the rendered state.
    if (!props.grantsEnabled) return <NotAvailable onNavigate={props.onNavigate} />;
  }

  const sessionRoute = sessionRouteOf(props.path);
  if (sessionRoute !== null) {
    // A session route is known (not "unknown"): with the flag off nothing was
    // constructed and the section is honestly unavailable. With the flag on the
    // controller's independent public capability gate decides the rendered state.
    if (!props.sessionsEnabled) return <NotAvailable onNavigate={props.onNavigate} />;
  }

  if (state.refreshRequired && principal.status === "signed-in" && state.organizations.status === "none") {
    return (
      <section aria-labelledby="tenant-refresh-title">
        <p className="tenant-eyebrow">WORKSPACE HIDDEN</p>
        <h1 className="tenant-title" id="tenant-refresh-title">Refresh required</h1>
        <p className="tenant-status tenant-status--warning" role="status">
          This page was hidden, so protected organization data was cleared. Refresh to sign in
          again and reload the workspace.
        </p>
        <div className="tenant-actions">
          <button
            type="button"
            className="tenant-button tenant-button--primary"
            disabled={state.busy}
            onClick={() => void props.controller?.refreshSession()}
          >
            Refresh workspace
          </button>
        </div>
      </section>
    );
  }

  if (principal.status === "idle" || principal.status === "loading") {
    return <p className="tenant-status" role="status">Loading the organization workspace…</p>;
  }
  if (principal.status === "signed-out") {
    return (
      <section aria-labelledby="tenant-signin-title">
        <p className="tenant-eyebrow">PROTECTED WORKSPACE</p>
        <h1 className="tenant-title" id="tenant-signin-title">Sign in required</h1>
        <p className="tenant-status" role="status">
          Organization access needs an active OpenArc session.
        </p>
        {committedReceipt ? (
          <TenantMutationPanel
            controller={props.writeController}
            role={props.currentOrganization?.role ?? "owner"}
            organizationId={props.selectedId ?? ""}
            mode="receipt"
          />
        ) : null}
        <div className="tenant-actions">
          <a className="tenant-button tenant-button--primary" href="/account">Go to account</a>
          <a className="tenant-button" href="/design/docs">Read the docs</a>
        </div>
      </section>
    );
  }
  if (principal.status === "expired") {
    return (
      <section aria-labelledby="tenant-expired-title">
        <p className="tenant-eyebrow">SESSION</p>
        <h1 className="tenant-title" id="tenant-expired-title">Session expired. Sign in again.</h1>
        {committedReceipt ? (
          <TenantMutationPanel
            controller={props.writeController}
            role={props.currentOrganization?.role ?? "owner"}
            organizationId={props.selectedId ?? ""}
            mode="receipt"
          />
        ) : null}
        <div className="tenant-actions">
          <a className="tenant-button tenant-button--primary" href="/account">Go to account</a>
        </div>
      </section>
    );
  }

  if (state.organizations.status === "error") {
    return (
      <section aria-labelledby="tenant-org-error-title">
        <p className="tenant-eyebrow">ORGANIZATIONS</p>
        <h1 className="tenant-title" id="tenant-org-error-title">Organizations could not be loaded</h1>
        <p className="tenant-status tenant-status--error" role="alert">
          The organization service is unavailable right now. Try again in a moment.
        </p>
      </section>
    );
  }

  if (state.organizations.status === "loading" && state.organizations.items.length === 0) {
    return (
      <>
        <p className="tenant-status" role="status">Loading organizations…</p>
        {stickyMutation ? (
          <TenantMutationPanel
            controller={props.writeController}
            role={props.currentOrganization?.role ?? "owner"}
            organizationId={props.selectedId ?? ""}
            mode="receipt"
          />
        ) : null}
      </>
    );
  }

  if (state.organizations.items.length === 0 && state.organizations.nextCursor === null) {
    // First-organization bootstrap: a signed-in, writes-enabled user with zero
    // organizations gets the create-organization action. A known-recovery
    // session never sees the form (the server alone decides proof freshness),
    // and the failed reads/signed-out/flag-off paths returned above.
    const bootstrapAllowed =
      props.writeController !== null &&
      principal.method !== "recovery" &&
      principal.status === "signed-in";
    return (
      <section aria-labelledby="tenant-noorg-title">
        <p className="tenant-eyebrow">ORGANIZATIONS</p>
        <h1 className="tenant-title" id="tenant-noorg-title">No organizations available.</h1>
        <p className="tenant-lede">
          This account is not a member of any organization yet. If that seems wrong, an owner
          must invite this account first.
        </p>
        {bootstrapAllowed ? (
          <TenantMutationPanel
            controller={props.writeController}
            role={props.currentOrganization?.role ?? "owner"}
            organizationId={props.selectedId ?? ""}
            mode="bootstrap"
          />
        ) : stickyMutation ? (
          <TenantMutationPanel
            controller={props.writeController}
            role={props.currentOrganization?.role ?? "owner"}
            organizationId={props.selectedId ?? ""}
            mode="receipt"
          />
        ) : null}
      </section>
    );
  }

  if (props.selectedId === null || props.currentOrganization === null) {
    return (
      <section aria-labelledby="tenant-choose-title">
        <p className="tenant-eyebrow">ORGANIZATIONS</p>
        <h1 className="tenant-title" id="tenant-choose-title">Choose an organization to continue.</h1>
        {stickyMutation ? (
          <TenantMutationPanel
            controller={props.writeController}
            role={props.currentOrganization?.role ?? "owner"}
            organizationId={props.selectedId ?? ""}
            mode="receipt"
          />
        ) : null}
        <OrganizationList state={state} onSelect={props.onSelect} controller={props.controller} />
      </section>
    );
  }

  if (listingRoute !== null) {
    return (
      <ListingWorkspace
        route={listingRoute}
        state={props.listingState}
        controller={props.controller}
        listingController={props.listingController}
        creating={props.listingCreating}
        providerId={props.listingProviderId}
        baseVersion={props.listingBaseVersion}
        onSelectProvider={props.onSelectListingProvider}
        onStartCreate={props.onStartListingCreate}
        onCancelCreate={props.onCancelListingCreate}
        onSelectBaseVersion={props.onSelectListingBaseVersion}
        onOpenListing={props.onOpenListing}
        onNavigate={props.onNavigate}
      />
    );
  }

  if (policyRoute !== null) {
    return (
      <PolicyWorkspace
        route={policyRoute}
        state={props.policyState}
        tenantController={props.controller}
        policyController={props.policyController}
        creating={props.policyCreating}
        formKey={props.policyFormKey}
        onStartCreate={props.onStartPolicyCreate}
        onCancelCreate={props.onCancelPolicyCreate}
        onOpenPolicy={props.onOpenPolicy}
      />
    );
  }

  if (actionRoute !== null) {
    return (
      <ActionWorkspace
        key={`action-context:${props.actionFormKey}`}
        route={actionRoute}
        state={props.actionState}
        controller={props.actionController}
        formKey={props.actionFormKey}
        onOpenAction={props.onOpenAction}
        onOpenApproval={props.onOpenApproval}
        onNavigate={props.onNavigate}
      />
    );
  }

  if (grantRoute !== null) {
    return (
      <GrantWorkspace
        key={`grant-context:${props.grantFormKey}`}
        route={grantRoute}
        state={props.grantState}
        controller={props.grantController}
        formKey={props.grantFormKey}
        onOpenGrant={props.onOpenGrant}
        onNavigate={props.onNavigate}
      />
    );
  }

  if (sessionRoute !== null) {
    return (
      <SessionWorkspace
        key={`session-context:${props.sessionFormKey}`}
        route={sessionRoute}
        state={props.sessionState}
        controller={props.sessionController}
        tenantController={props.controller}
        selectedAgentId={props.sessionSelectedAgentId}
        onSelectAgent={props.onSelectSessionAgent}
        policyPickerEnabled={props.policyPickerEnabled}
        policyOptions={props.policyOptions}
        policyOptionsStatus={props.policyOptionsStatus}
        hasNextPolicies={props.hasNextPolicies}
        onLoadPolicies={props.onLoadPolicies}
        onLoadMorePolicies={props.onLoadMorePolicies}
        onOpenSession={props.onOpenSession}
        onStartIssue={props.onStartSessionIssue}
        onNavigate={props.onNavigate}
      />
    );
  }

  switch (props.path) {
    case "/app/agents":
      return (
        <AgentPanel
          state={state}
          role={props.currentOrganization.role}
          controller={props.controller}
          writeController={props.writeController}
          organizationId={props.selectedId}
          machineController={props.machineController}
          machineState={props.machineState}
          machineList={props.machineList}
          onSelectProfile={props.onSelectProfile}
          machineEnabled={props.machineEnabled}
        />
      );
    case "/app/provider":
      return (
        <ProviderPanel
          state={state}
          role={props.currentOrganization.role}
          controller={props.controller}
          writeController={props.writeController}
          organizationId={props.selectedId}
          machineController={props.machineController}
          machineState={props.machineState}
          machineList={props.machineList}
          onSelectProfile={props.onSelectProfile}
          machineEnabled={props.machineEnabled}
        />
      );
    default:
      return (
        <Overview
          state={state}
          currentOrganization={props.currentOrganization}
          writeController={props.writeController}
          organizationId={props.selectedId}
        />
      );
  }
}

function OrganizationList(props: {
  state: TenantViewControllerState;
  onSelect: (organizationId: string) => void;
  controller: TenantController | null;
}) {
  const { organizations } = props.state;
  return (
    <>
      <ul className="tenant-table-wrap tenant-table" style={{ listStyle: "none", margin: 0, padding: 0 }}>
        {organizations.items.map((organization) => (
          <li key={organization.organizationId} style={{ display: "contents" }}>
            <button
              type="button"
              className="tenant-button"
              style={{ display: "flex", width: "100%", justifyContent: "flex-start" }}
              onClick={() => props.onSelect(organization.organizationId)}
            >
              {organization.displayName}{" "}
              <span className="tenant-mono" style={{ marginLeft: 12 }}>
                {organization.organizationId}
              </span>
            </button>
          </li>
        ))}
      </ul>
      <Pagination
        status={organizations.status}
        hasNext={organizations.nextCursor !== null}
        hasPrevious={organizations.hasPrevious}
        onNext={() => void props.controller?.loadNextOrganizations()}
        onFirst={() => void props.controller?.loadOrganizations()}
      />
    </>
  );
}

function Overview(props: {
  state: TenantViewControllerState;
  currentOrganization: { displayName: string; role: CommerceHumanRole; status: "active" | "suspended" };
  writeController: TenantWriteController | null;
  organizationId: string;
}) {
  const { currentOrganization, state } = props;
  return (
    <section aria-labelledby="tenant-overview-title">
      <p className="tenant-eyebrow">OVERVIEW</p>
      <h1 className="tenant-title" id="tenant-overview-title">
        {currentOrganization.displayName}
      </h1>
      <dl className="tenant-meta">
        <dt>Role</dt>
        <dd>
          {roleLabel(currentOrganization.role)}{" "}
          <span className="tenant-pill tenant-pill--active">{currentOrganization.status}</span>
        </dd>
        <dt>Network</dt>
        <dd>Arc Testnet ({ARC_TESTNET.chainId})</dd>
        <dt>Organization ID</dt>
        <dd className="tenant-mono">{state.selectedOrganizationId}</dd>
      </dl>
      <p className="tenant-lede">Choose Agents or Provider to view this organization.</p>
      {currentOrganization.role === "owner" ? (
        <TenantMutationPanel
          controller={props.writeController}
          role={currentOrganization.role}
          organizationId={props.organizationId}
        />
      ) : null}
    </section>
  );
}

function AgentPanel(props: {
  state: TenantViewControllerState;
  role: CommerceHumanRole;
  controller: TenantController | null;
  writeController: TenantWriteController | null;
  organizationId: string;
  machineController: MachineCredentialController | null;
  machineState: MachineConsoleState;
  machineList: MachineCredentialListState;
  onSelectProfile: (target: MachineCredentialTarget | null) => void;
  machineEnabled: boolean;
}) {
  if (!canReadAgents(props.role)) return <RoleNotAllowed role={props.role} action="agents" />;
  const { agents } = props.state;
  const selected = props.machineList.target;
  return (
    <section aria-labelledby="tenant-agents-title">
      <p className="tenant-eyebrow">AGENTS</p>
      <h1 className="tenant-title" id="tenant-agents-title">Agents</h1>
      {agents.status === "none" ? (
        <div className="tenant-actions">
          <button
            type="button"
            className="tenant-button tenant-button--primary"
            onClick={() => void props.controller?.loadAgents()}
          >
            Load agents
          </button>
        </div>
      ) : null}
      {agents.status === "loading" ? <p className="tenant-status" role="status">Loading agents…</p> : null}
      {agents.status === "error" ? (
        <p className="tenant-status tenant-status--error" role="alert">
          Agents could not be loaded right now.
        </p>
      ) : null}
      {agents.status === "ready" && agents.items.length === 0 ? (
        <p className="tenant-empty">No agents in this organization.</p>
      ) : null}
      {agents.items.length > 0 ? (
        <ProfileTable
          kind="agent"
          items={agents.items}
          machineEnabled={props.machineEnabled && (props.role === "owner" || props.role === "operator")}
          selectedProfileId={selected?.kind === "agent" ? selected.profileId : null}
          onSelectProfile={(profileId) =>
            props.onSelectProfile(
              profileId === null ? null : { kind: "agent", profileId },
            )
          }
        />
      ) : null}
      <Pagination
        status={agents.status}
        hasNext={agents.nextCursor !== null}
        hasPrevious={agents.hasPrevious}
        onNext={() => void props.controller?.loadNextAgents()}
        onFirst={() => void props.controller?.loadAgents()}
      />
      {props.machineEnabled &&
      selected?.kind === "agent" &&
      props.machineController !== null &&
      (props.role === "owner" || props.role === "operator") ? (
        <MachineCredentialPanel
          controller={props.machineController}
          role={props.role}
          target={selected}
          credentials={props.machineList}
        />
      ) : null}
      {props.role === "owner" || props.role === "operator" ? (
        <TenantMutationPanel
          controller={props.writeController}
          role={props.role}
          organizationId={props.organizationId}
        />
      ) : null}
    </section>
  );
}

function ProviderPanel(props: {
  state: TenantViewControllerState;
  role: CommerceHumanRole;
  controller: TenantController | null;
  writeController: TenantWriteController | null;
  organizationId: string;
  machineController: MachineCredentialController | null;
  machineState: MachineConsoleState;
  machineList: MachineCredentialListState;
  onSelectProfile: (target: MachineCredentialTarget | null) => void;
  machineEnabled: boolean;
}) {
  if (!canReadProviders(props.role)) return <RoleNotAllowed role={props.role} action="providers" />;
  const { providers } = props.state;
  const selected = props.machineList.target;
  return (
    <section aria-labelledby="tenant-providers-title">
      <p className="tenant-eyebrow">PROVIDER</p>
      <h1 className="tenant-title" id="tenant-providers-title">Provider</h1>
      {providers.status === "none" ? (
        <div className="tenant-actions">
          <button
            type="button"
            className="tenant-button tenant-button--primary"
            onClick={() => void props.controller?.loadProviders()}
          >
            Load providers
          </button>
        </div>
      ) : null}
      {providers.status === "loading" ? (
        <p className="tenant-status" role="status">Loading providers…</p>
      ) : null}
      {providers.status === "error" ? (
        <p className="tenant-status tenant-status--error" role="alert">
          Providers could not be loaded right now.
        </p>
      ) : null}
      {providers.status === "ready" && providers.items.length === 0 ? (
        <p className="tenant-empty">No providers in this organization.</p>
      ) : null}
      {providers.items.length > 0 ? (
        <ProfileTable
          kind="provider"
          items={providers.items}
          machineEnabled={props.machineEnabled && props.role === "owner"}
          selectedProfileId={selected?.kind === "provider" ? selected.profileId : null}
          onSelectProfile={(profileId) =>
            props.onSelectProfile(
              profileId === null ? null : { kind: "provider", profileId },
            )
          }
        />
      ) : null}
      <Pagination
        status={providers.status}
        hasNext={providers.nextCursor !== null}
        hasPrevious={providers.hasPrevious}
        onNext={() => void props.controller?.loadNextProviders()}
        onFirst={() => void props.controller?.loadProviders()}
      />
      {props.machineEnabled &&
      selected?.kind === "provider" &&
      props.machineController !== null &&
      props.role === "owner" ? (
        <MachineCredentialPanel
          controller={props.machineController}
          role={props.role}
          target={selected}
          credentials={props.machineList}
        />
      ) : null}
      {props.role === "owner" ? (
        <TenantMutationPanel
          controller={props.writeController}
          role={props.role}
          organizationId={props.organizationId}
        />
      ) : null}
    </section>
  );
}

type ProfileItems = TenantViewControllerState["agents"]["items"] | TenantViewControllerState["providers"]["items"];

function ProfileTable(props: {
  kind: "agent" | "provider";
  items: ProfileItems;
  machineEnabled: boolean;
  selectedProfileId: string | null;
  onSelectProfile: (profileId: string | null) => void;
}) {
  const isAgent = props.kind === "agent";
  return (
    <div className="tenant-table-wrap">
      <table className="tenant-table">
        <caption>{isAgent ? "Agents" : "Providers"} in this organization</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Status</th>
            <th scope="col">{isAgent ? "Agent ID" : "Provider ID"}</th>
            <th scope="col">Created</th>
            <th scope="col">Updated</th>
            {props.machineEnabled ? <th scope="col">Credentials</th> : null}
          </tr>
        </thead>
        <tbody>
          {props.items.map((item) => {
            const parsed = isAgent
              ? CommerceAgentProfileSchema.safeParse(item)
              : CommerceProviderProfileSchema.safeParse(item);
            const id = isAgent
              ? (item as TenantViewControllerState["agents"]["items"][number]).agentId
              : (item as TenantViewControllerState["providers"]["items"][number]).providerId;
            if (!parsed.success) return null;
            return (
              <tr key={id}>
                <td>{parsed.data.displayName}</td>
                <td>
                  <span className={`tenant-pill ${parsed.data.status === "active" ? "tenant-pill--active" : ""}`}>
                    {parsed.data.status}
                  </span>
                </td>
                <td className="tenant-mono">{id}</td>
                <td className="tenant-mono">{parsed.data.createdAt}</td>
                <td className="tenant-mono">{parsed.data.updatedAt}</td>
                {props.machineEnabled ? (
                  <td>
                    {props.selectedProfileId === id ? (
                      <button
                        type="button"
                        className="tenant-button tenant-button--primary"
                        aria-pressed="true"
                        onClick={() => props.onSelectProfile(null)}
                      >
                        Close credentials
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="tenant-button"
                        aria-pressed="false"
                        onClick={() => props.onSelectProfile(id)}
                      >
                        Manage credentials
                      </button>
                    )}
                  </td>
                ) : null}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Pagination(props: {
  status: TenantViewControllerState["agents"]["status"];
  hasNext: boolean;
  hasPrevious: boolean;
  onNext: () => void;
  onFirst: () => void;
}) {
  if (props.status !== "ready" && !props.hasNext && !props.hasPrevious) return null;
  const loading = props.status === "loading";
  return (
    <div className="tenant-pagination">
      {props.hasPrevious ? (
        <button
          type="button"
          className="tenant-button"
          disabled={loading}
          onClick={props.onFirst}
        >
          Back to page 1
        </button>
      ) : null}
      <button
        type="button"
        className="tenant-button"
        disabled={loading || !props.hasNext}
        onClick={props.onNext}
      >
        Next page
      </button>
      <span className="tenant-pagination__status">
        Page size ≤ {MAX_PAGE_LIMIT}. Replaces the current page.
      </span>
    </div>
  );
}

/**
 * Protected listing workspace. The independent capability gate is rendered
 * honestly: `checking` is a status, `unavailable` is never fake empty data.
 */
function ListingWorkspace(props: {
  route: ListingRoute;
  state: ListingControllerState;
  controller: TenantController | null;
  listingController: ListingController | null;
  creating: boolean;
  providerId: string | null;
  baseVersion: CommerceListingOwnerVersion | null;
  onSelectProvider: (providerId: string) => void;
  onStartCreate: () => void;
  onCancelCreate: () => void;
  onSelectBaseVersion: (version: CommerceListingOwnerVersion) => void;
  onOpenListing: (listingId: string) => void;
  onNavigate: (path: AppPath) => void;
}) {
  const controller = props.listingController;
  if (props.state.capability === "unknown" || props.state.capability === "checking") {
    return <p className="tenant-status" role="status">Checking listing availability…</p>;
  }
  if (props.state.capability === "unavailable") {
    return (
      <section aria-labelledby="listing-unavailable-title">
        <p className="tenant-eyebrow">LISTINGS</p>
        <h1 className="tenant-title" id="listing-unavailable-title">
          Listing management is not available in this deployment
        </h1>
        <p className="tenant-status tenant-status--warning" role="status">
          The marketplace capability manifest does not enable listing management here. No listing
          request was made and no empty catalogue is implied.
        </p>
      </section>
    );
  }
  return (
    <div className="tenant-listings">
      <p className="tenant-eyebrow">PROVIDER LISTINGS</p>
      <h1 className="tenant-title">Listings</h1>
      <p className="tenant-status" role="status">
        {props.state.canWrite
          ? "You can create and manage listings. Every write requires an explicit confirmation and is server-authorized."
          : "Your role is read-only here. Only owner, provider admin and provider developer roles can write."}
      </p>
      <ListingMutationStatusView state={props.state.mutation} controller={controller} />
      {props.route.kind === "roots" || props.route.kind === "new" ? (
        <ListingListPanel
          state={props.state}
          creating={props.creating || props.route.kind === "new"}
          selectedProviderId={props.providerId}
          onSelectProvider={props.onSelectProvider}
          onStartCreate={props.onStartCreate}
          onCancelCreate={props.onCancelCreate}
          onLoadRoots={() => void controller?.loadRoots()}
          onNextRoots={() => void controller?.loadNextRoots()}
          onLoadMoreProviders={() => void controller?.loadNextProviderOptions()}
          onSubmitDraft={(providerId, content) => controller?.beginCreateDraft(providerId, content)}
          onOpenListing={props.onOpenListing}
        />
      ) : (
        <ListingDetailView
          state={props.state}
          controller={controller}
          baseVersion={props.baseVersion}
          onSelectBaseVersion={props.onSelectBaseVersion}
        />
      )}
    </div>
  );
}

function ListingMutationStatusView(props: {
  state: ListingControllerState["mutation"];
  controller: ListingController | null;
}) {
  const mutation = props.state;
  if (mutation.kind === "idle") return null;
  if (mutation.kind === "confirming") {
    const draft = mutation.draft;
    if (draft.op === "publish" || draft.op === "pause" || draft.op === "retire") {
      const heading =
        draft.op === "publish"
          ? `Publish version ${draft.version}`
          : draft.op === "pause"
            ? `Pause version ${draft.version}`
            : `Retire version ${draft.version}`;
      return (
        <section className="tenant-listings__disclosure" aria-labelledby="listing-lifecycle-confirm-title">
          <h3 className="tenant-title tenant-title--small" id="listing-lifecycle-confirm-title">
            {heading}
          </h3>
          <p className="tenant-status">
            {draft.op === "publish"
              ? "Publishing makes the title, description, provider name, fixed price, terms revision and privacy summary public. The protected endpoint path is NOT disclosed. Publishing atomically pauses the prior active version; origin review approval remains a manual moderation step and is never self-service."
              : draft.op === "pause"
                ? "Pausing removes the active pointer. Buyers can no longer purchase this version until another is published."
                : "Retiring is terminal. This version cannot be reactivated."}
          </p>
          <p className="tenant-mono">
            version {draft.version} · expectedUpdatedAt {draft.expectedUpdatedAt} · expectedActiveVersion{" "}
            {draft.expectedActiveVersion ?? "null"}
          </p>
          <div className="tenant-actions">
            <button
              type="button"
              className="tenant-button tenant-button--primary"
              onClick={() => void props.controller?.confirm()}
            >
              Confirm {draft.op}
            </button>
            <button type="button" className="tenant-button" onClick={() => props.controller?.cancel()}>
              Cancel
            </button>
          </div>
        </section>
      );
    }
    return (
      <section className="tenant-listings__disclosure" aria-labelledby="listing-confirm-title">
        <h3 className="tenant-title tenant-title--small" id="listing-confirm-title">
          Confirm this write
        </h3>
        <p className="tenant-status">
          One explicit confirmation sends exactly one logical write with a fresh mutation id and an
          idempotency key held in memory only. There is no automatic retry.
        </p>
        <p className="tenant-mono">operation {mutation.draft.op}</p>
        <div className="tenant-actions">
          <button
            type="button"
            className="tenant-button tenant-button--primary"
            onClick={() => void props.controller?.confirm()}
          >
            Confirm write
          </button>
          <button type="button" className="tenant-button" onClick={() => props.controller?.cancel()}>
            Cancel
          </button>
        </div>
      </section>
    );
  }
  if (mutation.kind === "pending") {
    return <p className="tenant-status" role="status">Sending the confirmed write…</p>;
  }
  if (mutation.kind === "committed") {
    return (
      <p className="tenant-status" role="status">
        Committed operation {mutation.receipt.operation}
        {mutation.resourceVersion === null ? "" : ` (resource version ${mutation.resourceVersion})`}.
        {mutation.refreshError ? " The follow-up refresh failed; the committed receipt stands." : ""}
      </p>
    );
  }
  if (mutation.kind === "rejected") {
    const notice = mutation.notice;
    return (
      <p className="tenant-status tenant-status--error" role="alert">
        {notice.kind === "conflict"
          ? "A conflict was detected. Review the latest state and confirm explicitly again; no automatic retry was performed."
          : notice.kind === "forbidden"
            ? "Your role cannot perform this write."
            : notice.kind === "unauthenticated"
              ? "Your session needs re-authentication before this write."
              : notice.kind === "csrf"
                ? "The request origin or anti-forgery token was rejected."
                : notice.kind === "not-found"
                  ? "The target no longer exists."
                  : notice.kind === "account-changed"
                    ? "The account changed during the write; nothing was applied to the new account."
                    : notice.kind === "capability-disabled"
                      ? "Listing management is not enabled."
                      : "The write was rejected. Review the values and confirm explicitly again."}
      </p>
    );
  }
  return (
    <section aria-labelledby="listing-unknown-title">
      <h3 className="tenant-title tenant-title--small" id="listing-unknown-title">
        The write outcome is unknown
      </h3>
      <p className="tenant-status tenant-status--warning" role="status">
        {mutation.statusMessage ??
          "The write may have committed. Only an explicit status check with the original mutation id can resolve it."}
      </p>
      <div className="tenant-actions">
        <button
          type="button"
          className="tenant-button"
          disabled={mutation.checking}
          onClick={() => void props.controller?.checkStatus()}
        >
          Check status
        </button>
      </div>
    </section>
  );
}

/**
 * Protected policy-rules workspace.
 *
 * These are policy RULES only. No funds are reserved, committed, moved or
 * executed here, and no available/reserved/spent counter exists. The
 * independent capability gate is rendered honestly: `checking` is a status,
 * `unavailable` is never fake empty data.
 */
function PolicyWorkspace(props: {
  route: PolicyRoute;
  state: PolicyControllerState;
  tenantController: TenantController | null;
  policyController: PolicyController | null;
  creating: boolean;
  formKey: string;
  onStartCreate: () => void;
  onCancelCreate: () => void;
  onOpenPolicy: (policyId: string) => void;
}) {
  const controller = props.policyController;
  if (props.state.capability === "unknown" || props.state.capability === "checking") {
    return <p className="tenant-status" role="status">Checking policy availability…</p>;
  }
  if (props.state.capability === "unavailable") {
    return (
      <section aria-labelledby="policy-unavailable-title">
        <p className="tenant-eyebrow">POLICY RULES</p>
        <h1 className="tenant-title" id="policy-unavailable-title">
          Policy management is not available in this deployment
        </h1>
        <p className="tenant-status tenant-status--warning" role="status">
          The control capability manifest does not enable policy management here. No policy
          request was made and no empty rule set is implied.
        </p>
      </section>
    );
  }
  const agents: readonly CommerceAgentProfile[] = props.tenantController?.state.agents.items ?? [];
  const agentsStatus = props.tenantController?.state.agents.status ?? "none";
  const agentsNextCursor = props.tenantController?.state.agents.nextCursor ?? null;
  return (
    <div className="tenant-policies">
      <p className="tenant-eyebrow">POLICY RULES</p>
      <h1 className="tenant-title">Budgets</h1>
      {/*
        Prominent truthful copy required by the contract: these are rules only.
      */}
      <p className="tenant-status tenant-status--warning" role="status">
        These are policy rules only. No funds are reserved, committed, moved, or executed here.
      </p>
      <p className="tenant-status" role="status">
        {props.state.canWrite
          ? "You can create and manage policy rules. Every write requires an explicit confirmation and is server-authorized."
          : "Your role is read-only here. Only owner and operator roles can write."}
      </p>
      <PolicyMutationStatusView state={props.state.mutation} controller={controller} />
      {props.route.kind === "roots" || props.route.kind === "new" ? (
        <PolicyListPanel
          state={props.state}
          creating={props.creating || props.route.kind === "new"}
          formKey={props.formKey}
          agents={agents}
          agentsStatus={agentsStatus}
          onLoadAgents={() => void props.tenantController?.loadAgents()}
          onLoadMoreAgents={() => void props.tenantController?.loadNextAgents()}
          hasNextAgents={agentsNextCursor !== null}
          organizationId={props.tenantController?.currentOrganizationId() ?? ""}
          onStartCreate={props.onStartCreate}
          onCancelCreate={props.onCancelCreate}
          onLoadRoots={() => void controller?.loadRoots()}
          onNextRoots={() => void controller?.loadNextRoots()}
          onSubmitCreate={(content) => controller?.beginCreate(content)}
          onOpenPolicy={props.onOpenPolicy}
        />
      ) : (
        <PolicyDetailView state={props.state} controller={controller} onNavigate={undefined} />
      )}
    </div>
  );
}

/**
 * Protected commerce-session workspace.
 *
 * Owner/operator on a current non-recovery account may read and write; viewers,
 * providers and unknown/recovery get a clear no-access state and no request or
 * control. The independent public capability gate is rendered honestly:
 * `checking` is a status and `unavailable` is never fake empty data. No wallet
 * is connected, no money is reserved and no purchase is made.
 */
function SessionWorkspace(props: {
  route: SessionRoute;
  state: SessionControllerState;
  controller: SessionController | null;
  tenantController: TenantController | null;
  selectedAgentId: string | null;
  onSelectAgent: (agentId: string | null) => void;
  policyPickerEnabled: boolean;
  policyOptions: readonly { policyId: string; status: string }[];
  policyOptionsStatus: "none" | "loading" | "ready" | "error";
  hasNextPolicies: boolean;
  onLoadPolicies: () => void;
  onLoadMorePolicies: () => void;
  onOpenSession: (sessionId: string) => void;
  onStartIssue: () => void;
  onNavigate: (path: AppPath) => void;
}) {
  const controller = props.controller;
  if (props.state.capability === "unknown" || props.state.capability === "checking") {
    return <p className="tenant-status" role="status">Checking commerce-session availability…</p>;
  }
  if (props.state.capability === "unavailable") {
    return (
      <section aria-labelledby="session-unavailable-title">
        <p className="tenant-eyebrow">COMMERCE SESSIONS</p>
        <h1 className="tenant-title" id="session-unavailable-title">
          Commerce sessions are not available in this deployment
        </h1>
        <p className="tenant-status tenant-status--warning" role="status">
          The public session capability manifest does not enable commerce sessions here. No session
          request was made and no empty list is implied.
        </p>
      </section>
    );
  }
  // Owner/operator only. Viewers, providers, unknown and recovery accounts get a
  // clear no-access state and NO request or control. Viewer readonly access is
  // never inferred here.
  if (!props.state.canRead) {
    return <SessionNoAccess />;
  }
  const agents =
    props.tenantController?.state.agents.items.map((agent) => ({
      agentId: agent.agentId,
      displayName: agent.displayName,
      status: agent.status,
    })) ?? [];
  const agentsStatus = props.tenantController?.state.agents.status ?? "none";
  const onLoadAgents = () => void props.tenantController?.loadAgents();
  const issuePanel = (
    <SessionIssuePanel
      state={props.state}
      controller={controller}
      agents={agents}
      agentsStatus={agentsStatus}
      onLoadAgents={onLoadAgents}
      policyPickerEnabled={props.policyPickerEnabled}
      policyOptions={props.policyOptions}
      policyOptionsStatus={props.policyOptionsStatus}
      hasNextPolicies={props.hasNextPolicies}
      onLoadPolicies={props.onLoadPolicies}
      onLoadMorePolicies={props.onLoadMorePolicies}
      selectedAgentId={props.selectedAgentId}
      onSelectAgent={props.onSelectAgent}
      onIssue={(input) => controller?.beginIssue(input)}
      onDismissSecret={() => controller?.dismissSecret()}
      onCopySecret={(secret) => {
        // Clipboard only on an explicit user click; never automatic.
        void navigator.clipboard?.writeText(secret).catch(() => undefined);
      }}
      onCancel={() => controller?.cancel()}
      onConfirm={() => void controller?.confirm()}
      onCheckStatus={() => void controller?.checkStatus()}
      onNavigateDetail={props.onOpenSession}
    />
  );
  return (
    <div className="tenant-sessions">
      <p className="tenant-eyebrow">COMMERCE SESSIONS</p>
      <h1 className="tenant-title">Sessions</h1>
      <p className="tenant-status tenant-status--warning" role="status">
        These are one-time, short-lived handoffs for an existing same-agent authenticated client.
        They do not connect or sign a wallet, reserve money or make purchases.
      </p>
      {props.route.kind === "detail" ? (
        <>
          {/*
            The DETAIL route for a session also renders the shared mutation view
            so a revoke confirm/cancel, a committed receipt or an unknown-outcome
            status recovery is never invisible. Fresh issue delivery stays on the
            new/list panel only and is never auto-navigated away.
          */}
          <SessionMutationView
            mutation={props.state.mutation}
            availableOnce={props.state.availableOnce}
            handoffExpiresAt={
              props.state.mutation.kind === "committed"
                ? props.state.mutation.committed.handoffExpiresAt
                : null
            }
            controller={controller}
            onDismissSecret={() => controller?.dismissSecret()}
            onCopySecret={(secret) => {
              void navigator.clipboard?.writeText(secret).catch(() => undefined);
            }}
            onCancel={() => controller?.cancel()}
            onConfirm={() => void controller?.confirm()}
            onCheckStatus={() => void controller?.checkStatus()}
          />
          <SessionStatusPanel
            state={props.state}
            controller={controller}
            sessionId={props.route.sessionId}
            onBack={() => props.onNavigate("/app/sessions")}
          />
        </>
      ) : props.route.kind === "new" ? (
        issuePanel
      ) : (
        <>
          {issuePanel}
          <SessionListPanel
            state={props.state}
            controller={controller}
            onOpenSession={props.onOpenSession}
            onStartIssue={props.onStartIssue}
          />
        </>
      )}
    </div>
  );
}

interface GrantWorkspaceProps {
  route: GrantRoute;
  state: GrantControllerState;
  controller: GrantController | null;
  formKey: string;
  onOpenGrant: (grantId: string) => void;
  onNavigate: (path: AppPath) => void;
}

/**
 * The authorization-grant console shell.
 *
 * The independent public capability probe runs before any grant request, so a
 * deployment without the grant surface renders an honest unavailable state and
 * issues zero requests. Nothing here is a demo: every field comes from the
 * server or is not shown at all, and there is no earnings, reputation or
 * payment card anywhere on this surface.
 */
function GrantWorkspace(props: GrantWorkspaceProps) {
  const controller = props.controller;
  if (props.route.kind === "invalid") {
    return (
      <p className="tenant-status tenant-status--warning" role="status">
        That grant address is not valid. No request was made.
      </p>
    );
  }
  if (props.state.capability === "unknown" || props.state.capability === "checking") {
    return (
      <p className="tenant-status" role="status">
        Checking authorization-grant availability…
      </p>
    );
  }
  if (props.state.capability === "unavailable") {
    return (
      <section aria-labelledby="grant-unavailable-title">
        <p className="tenant-eyebrow">AUTHORIZATION GRANTS</p>
        <h1 className="tenant-title" id="grant-unavailable-title">
          Authorization grants are not available in this deployment
        </h1>
        <p className="tenant-status tenant-status--warning" role="status">
          The public grant capability manifest does not enable the grant console here. No grant
          request was made and no grant record is implied.
        </p>
      </section>
    );
  }
  if (!props.state.canRead) {
    return <GrantNoAccess />;
  }
  return (
    <div className="tenant-grants-console">
      <p className="tenant-eyebrow">AUTHORIZATION GRANTS</p>
      <h1 className="tenant-title">Authorization grants</h1>
      <p className="tenant-status tenant-status--warning" role="status">
        This console reads and revokes authorization grants. It connects no wallet, signs nothing,
        moves no money, and never reports a payment, settlement, delivery or refund. Revoking
        retires permission; it does not get money back.
      </p>
      {props.route.kind === "lookup" ? (
        <GrantLookupPanel
          state={props.state}
          controller={controller}
          onOpenGrant={props.onOpenGrant}
          formKey={props.formKey}
        />
      ) : null}
      {props.route.kind === "detail" ? (
        <GrantDetailPanel
          state={props.state}
          controller={controller}
          grantId={props.route.grantId}
          onBack={() => props.onNavigate("/app/grants")}
        />
      ) : null}
    </div>
  );
}

function GrantNoAccess() {
  return (
    <section aria-labelledby="grant-no-access-title">
      <p className="tenant-eyebrow">NOT ALLOWED</p>
      <h1 className="tenant-title" id="grant-no-access-title">
        You do not have access to authorization grants
      </h1>
      <p className="tenant-status tenant-status--warning" role="status">
        Your role in this organization cannot read authorization grants. No grant request was made
        and no grant record is implied.
      </p>
    </section>
  );
}

interface ActionWorkspaceProps {
  route: ActionRoute;
  state: ActionControllerState;
  controller: ActionController | null;
  formKey: string;
  onOpenAction: (actionId: string) => void;
  onOpenApproval: (approvalId: string) => void;
  onNavigate: (path: AppPath) => void;
}

/**
 * The commerce action/approval console shell.
 *
 * The independent public capability probe runs before any action request, so a
 * deployment without the action surface renders an honest unavailable state and
 * issues zero requests. Nothing here is a demo: every row and figure comes from
 * the server or is not shown at all.
 */
function ActionWorkspace(props: ActionWorkspaceProps) {
  const controller = props.controller;
  if (props.route.kind === "invalid") {
    return (
      <p className="tenant-status tenant-status--warning" role="status">
        That action address is not valid. No request was made.
      </p>
    );
  }
  if (props.state.capability === "unknown" || props.state.capability === "checking") {
    return (
      <p className="tenant-status" role="status">
        Checking commerce-action availability…
      </p>
    );
  }
  if (props.state.capability === "unavailable") {
    return (
      <section aria-labelledby="action-unavailable-title">
        <p className="tenant-eyebrow">COMMERCE ACTIONS</p>
        <h1 className="tenant-title" id="action-unavailable-title">
          Commerce actions are not available in this deployment
        </h1>
        <p className="tenant-status tenant-status--warning" role="status">
          The public action capability manifest does not enable the action console here. No action
          request was made and no empty queue is implied.
        </p>
      </section>
    );
  }
  if (!props.state.canRead) {
    return <ActionNoAccess />;
  }
  return (
    <div className="tenant-actions-console">
      <p className="tenant-eyebrow">COMMERCE ACTIONS</p>
      <h1 className="tenant-title">Actions and approvals</h1>
      <p className="tenant-status tenant-status--warning" role="status">
        This console reviews and decides pending commerce actions. It connects no wallet, signs
        nothing, moves no money, and never reports a payment, settlement, delivery or purchase.
      </p>
      <ul className="tenant-actions-console__tabs">
        <li>
          <a
            href="/app/actions"
            aria-current={props.route.kind === "detail" || props.route.kind === "queue" ? "page" : undefined}
            onClick={(event) => {
              event.preventDefault();
              props.onNavigate("/app/actions");
            }}
          >
            Action queue
          </a>
        </li>
        <li>
          <a
            href="/app/actions/approvals"
            aria-current={
              props.route.kind === "approvals" || props.route.kind === "approval-detail"
                ? "page"
                : undefined
            }
            onClick={(event) => {
              event.preventDefault();
              props.onNavigate("/app/actions/approvals");
            }}
          >
            Approval queue
          </a>
        </li>
        <li>
          <a
            href="/app/actions/exposure"
            aria-current={props.route.kind === "exposure" ? "page" : undefined}
            onClick={(event) => {
              event.preventDefault();
              props.onNavigate("/app/actions/exposure");
            }}
          >
            Exposure
          </a>
        </li>
      </ul>

      {props.route.kind === "queue" ? (
        <ActionQueuePanel
          state={props.state}
          controller={controller}
          onOpenAction={props.onOpenAction}
        />
      ) : null}
      {props.route.kind === "approvals" ? (
        <ApprovalQueuePanel
          state={props.state}
          controller={controller}
          onOpenApproval={props.onOpenApproval}
          onOpenAction={props.onOpenAction}
        />
      ) : null}
      {props.route.kind === "exposure" ? (
        <ActionExposurePanel state={props.state} controller={controller} formKey={props.formKey} />
      ) : null}
      {props.route.kind === "detail" ? (
        <ActionDetailPanel
          state={props.state}
          controller={controller}
          actionId={props.route.actionId}
          onBack={() => props.onNavigate("/app/actions")}
          onOpenApproval={props.onOpenApproval}
        />
      ) : null}
      {props.route.kind === "approval-detail" ? (
        <>
          <ActionDecisionView decision={props.state.decision} controller={controller} />
          <ApprovalDetailPanel
            state={props.state}
            controller={controller}
            approvalId={props.route.approvalId}
            onBack={() => props.onNavigate("/app/actions/approvals")}
            onOpenAction={props.onOpenAction}
          />
        </>
      ) : null}
    </div>
  );
}

function ActionNoAccess() {
  return (
    <section aria-labelledby="action-no-access-title">
      <p className="tenant-eyebrow">NOT ALLOWED</p>
      <h1 className="tenant-title" id="action-no-access-title">
        You do not have access to commerce actions
      </h1>
      <p className="tenant-status tenant-status--warning" role="status">
        Only a current owner, operator or viewer on a non-recovery account may read commerce
        actions, and only an owner or operator may decide them. No request was made.
      </p>
      <div className="tenant-actions">
        <a className="tenant-button" href="/app/overview">Back to overview</a>
      </div>
    </section>
  );
}

function SessionNoAccess() {
  return (
    <section aria-labelledby="session-no-access-title">
      <p className="tenant-eyebrow">NOT ALLOWED</p>
      <h1 className="tenant-title" id="session-no-access-title">
        You do not have access to commerce sessions
      </h1>
      <p className="tenant-status tenement-status--warning" role="status">
        Only a current owner or operator on a non-recovery account may read or write commerce
        sessions. Viewers, providers, unknown roles and recovery sign-in get no access. No request
        was made and no readonly access is inferred.
      </p>
      <div className="tenant-actions">
        <a className="tenant-button" href="/app/overview">Back to overview</a>
      </div>
    </section>
  );
}

function PolicyDetailView(props: {
  state: PolicyControllerState;
  controller: PolicyController | null;
  onNavigate: undefined;
}) {
  const detail = props.state.detail;
  const controller = props.controller;
  if (detail.status === "loading" || detail.status === "none") {
    return <p className="tenant-status" role="status">Loading policy detail…</p>;
  }
  if (detail.status === "not-found") {
    return (
      <p className="tenant-status tenant-status--warning" role="status">
        This policy was not found. No empty or fabricated policy is shown.
      </p>
    );
  }
  if (detail.status === "error") {
    return (
      <p className="tenant-status tenant-status--error" role="alert">
        The policy detail could not be loaded.
      </p>
    );
  }
  const root = detail.root;
  if (root === null) return null;
  return (
    <>
      <section aria-labelledby="policy-root-title">
        <h2 className="tenant-title tenant-title--small" id="policy-root-title">
          Policy {root.policyId}
        </h2>
        <dl className="tenant-meta">
          <dt>Subject agent</dt>
          <dd className="tenant-mono">{root.subjectAgentId}</dd>
          <dt>Status</dt>
          <dd>{root.status}</dd>
          <dt>Current revision (authoritative CAS root)</dt>
          <dd className="tenant-mono">{root.currentRevision}</dd>
          <dt>Updated</dt>
          <dd className="tenant-mono">{root.updatedAt}</dd>
        </dl>
      </section>
      <PolicyLifecycleActions state={props.state} controller={controller} />
      <PolicyRevisionHistory
        history={detail.history}
        revision={props.state.revision}
        canWrite={props.state.canWrite}
        onLoadMore={() => void controller?.loadMoreRevisions()}
        onReadRevision={(revision) => void controller?.readRevision(revision)}
        onAppendFrom={() => {
          const revision = props.state.revision.revision;
          if (revision === null || controller === null) return;
          beginAppendFromRevision(controller, revision);
        }}
      />
    </>
  );
}

function PolicyLifecycleActions(props: {
  state: PolicyControllerState;
  controller: PolicyController | null;
}) {
  const status = props.state.detail.root?.status;
  if (status === undefined) return null;
  return (
    <div className="tenant-actions tenant-policies__lifecycle">
      {status === "active" ? (
        <button
          type="button"
          className="tenant-button"
          disabled={!props.state.canWrite}
          onClick={() => props.controller?.beginLifecycle("pause")}
        >
          Pause policy
        </button>
      ) : null}
      {status === "paused" ? (
        <button
          type="button"
          className="tenant-button tenant-button--primary"
          disabled={!props.state.canWrite}
          onClick={() => props.controller?.beginLifecycle("resume")}
        >
          Resume policy
        </button>
      ) : null}
      {status !== "revoked" ? (
        <button
          type="button"
          className="tenant-button"
          disabled={!props.state.canWrite}
          onClick={() => props.controller?.beginLifecycle("revoke")}
        >
          Revoke policy
        </button>
      ) : (
        <p className="tenant-status">This policy is revoked and terminal.</p>
      )}
    </div>
  );
}

function PolicyMutationStatusView(props: {
  state: PolicyControllerState["mutation"];
  controller: PolicyController | null;
}) {
  const mutation = props.state;
  if (mutation.kind === "idle") return null;
  if (mutation.kind === "confirming") {
    const draft = mutation.draft;
    const label =
      draft.op === "create"
        ? "Create policy"
        : draft.op === "append"
          ? `Append revision ${(BigInt(draft.cas.expectedRevision) + 1n).toString()}`
          : `${draft.op === "pause" ? "Pause" : draft.op === "resume" ? "Resume" : "Revoke"} policy`;
    return (
      <section className="tenant-policies__disclosure" aria-labelledby="policy-confirm-title">
        <h3 className="tenant-title tenant-title--small" id="policy-confirm-title">
          Confirm: {label}
        </h3>
        <p className="tenant-status">
          These are policy rules only. No funds are reserved, committed, moved, or executed here.
          One explicit confirmation sends exactly one logical write with a fresh mutation id and an
          idempotency key held in memory only. There is no automatic retry.
        </p>
        {draft.op === "append" || draft.op === "pause" || draft.op === "resume" || draft.op === "revoke" ? (
          <p className="tenant-mono">
            expectedRevision {draft.cas.expectedRevision} · expectedUpdatedAt {draft.cas.expectedUpdatedAt}
          </p>
        ) : null}
        <div className="tenant-actions">
          <button
            type="button"
            className="tenant-button tenant-button--primary"
            onClick={() => void props.controller?.confirm()}
          >
            Confirm write
          </button>
          <button type="button" className="tenant-button" onClick={() => props.controller?.cancel()}>
            Cancel
          </button>
        </div>
      </section>
    );
  }
  if (mutation.kind === "pending") {
    return <p className="tenant-status" role="status">Sending the confirmed write…</p>;
  }
  if (mutation.kind === "committed") {
    return (
      <p className="tenant-status" role="status">
        Committed operation {mutation.receipt.operation}
        {mutation.resourceRevision === null ? "" : ` (revision ${mutation.resourceRevision})`}.
        {mutation.refreshError ? " The follow-up refresh failed; the committed receipt stands." : ""}
      </p>
    );
  }
  if (mutation.kind === "rejected") {
    const notice = mutation.notice;
    return (
      <p className="tenant-status tenant-status--error" role="alert">
        {notice.kind === "conflict"
          ? "A conflict was detected. Review the latest state and confirm explicitly again; no automatic retry was performed."
          : notice.kind === "forbidden"
            ? "Your role cannot perform this write."
            : notice.kind === "unauthenticated"
              ? "Your session needs re-authentication before this write."
              : notice.kind === "csrf"
                ? "The request origin or anti-forgery token was rejected."
                : notice.kind === "not-found"
                  ? "The target no longer exists."
                  : notice.kind === "account-changed"
                    ? "The account changed during the write; nothing was applied to the new account."
                    : notice.kind === "capability-disabled"
                      ? "Policy management is not enabled."
                      : "The write was rejected. Review the values and confirm explicitly again."}
      </p>
    );
  }
  return (
    <section aria-labelledby="policy-unknown-title">
      <h3 className="tenant-title tenant-title--small" id="policy-unknown-title">
        The write outcome is unknown
      </h3>
      <p className="tenant-status tenant-status--warning" role="status">
        {mutation.statusMessage ??
          "The write may have committed. Only an explicit status check with the original mutation id can resolve it."}
      </p>
      <div className="tenant-actions">
        <button
          type="button"
          className="tenant-button"
          disabled={mutation.checking}
          onClick={() => void props.controller?.checkStatus()}
        >
          Check status
        </button>
      </div>
    </section>
  );
}

function ListingDetailView(props: {
  state: ListingControllerState;
  controller: ListingController | null;
  baseVersion: CommerceListingOwnerVersion | null;
  onSelectBaseVersion: (version: CommerceListingOwnerVersion) => void;
}) {
  const detail = props.state.detail;
  const controller = props.controller;
  if (detail.status === "loading" || detail.status === "none") {
    return <p className="tenant-status" role="status">Loading listing detail…</p>;
  }
  if (detail.status === "not-found") {
    return (
      <p className="tenant-status tenant-status--warning" role="status">
        This listing was not found. No empty or fabricated listing is shown.
      </p>
    );
  }
  if (detail.status === "error") {
    return (
      <p className="tenant-status tenant-status--error" role="alert">
        The listing detail could not be loaded.
      </p>
    );
  }
  const root = detail.root;
  if (root === null) return null;
  const historyComplete = detail.history.historyComplete;
  const selected = props.baseVersion;
  return (
    <>
      <section aria-labelledby="listing-root-title">
        <h2 className="tenant-title tenant-title--small" id="listing-root-title">
          Listing {root.listingId}
        </h2>
        <dl className="tenant-meta">
          <dt>Provider</dt>
          <dd className="tenant-mono">{root.providerId}</dd>
          <dt>Active version</dt>
          <dd className="tenant-mono">{root.activeVersion ?? "none"}</dd>
          <dt>Updated</dt>
          <dd className="tenant-mono">{root.updatedAt}</dd>
        </dl>
      </section>
      <ListingVersionHistory
        history={detail.history}
        selectedVersion={selected}
        onLoadMore={() => void controller?.loadMoreVersions()}
        onSelect={props.onSelectBaseVersion}
      />
      {!historyComplete ? (
        <p className="tenant-status tenant-status--warning" role="status">
          Create version is disabled while the version history is incomplete.
        </p>
      ) : null}
      {historyComplete && selected !== null ? (
        <>
          <ListingLifecycleActions
            version={selected}
            activeVersion={root.activeVersion}
            canWrite={props.state.canWrite}
            onPublish={() => controller?.beginLifecycle("publish", selected)}
            onPause={() => controller?.beginLifecycle("pause", selected)}
            onRetire={() => controller?.beginLifecycle("retire", selected)}
          />
          <ListingEditorPanel
            mode="create-version"
            providerOptions={[]}
            providerOptionsStatus="ready"
            selectedProviderId={null}
            onSelectProvider={() => undefined}
            prefill={props.state.selection.prefill}
            baseVersion={selected}
            canWrite={props.state.canWrite}
            onSubmitDraft={() => undefined}
            onSubmitVersion={(content) => controller?.beginCreateVersion(content)}
            onCancel={() => controller?.cancel()}
            onLoadMoreProviders={() => undefined}
            hasNextProviders={false}
          />
        </>
      ) : null}
    </>
  );
}

function RoleNotAllowed(props: { role: CommerceHumanRole; action: "agents" | "providers" }) {
  return (
    <section aria-labelledby="tenant-role-denied-title">
      <p className="tenant-eyebrow">NOT ALLOWED</p>
      <h1 className="tenant-title" id="tenant-role-denied-title">
        Your role cannot view {props.action === "agents" ? "agents" : "providers"}
      </h1>
      <p className="tenant-status tenant-status--warning" role="status">
        The current organization role <strong>{roleLabel(props.role)}</strong> is not permitted to
        read this panel. No request was made.
      </p>
      <div className="tenant-actions">
        <a className="tenant-button" href="/app/overview">Back to overview</a>
      </div>
    </section>
  );
}

function NotAvailable(props: { onNavigate: (path: AppPath) => void }) {
  return (
    <section aria-labelledby="tenant-unavailable-title">
      <p className="tenant-eyebrow">WORKSPACE</p>
      <h1 className="tenant-title" id="tenant-unavailable-title">This section is not available yet</h1>
      <p className="tenant-lede">
        The requested workspace route does not exist. Nothing was loaded for it.
      </p>
      <div className="tenant-actions">
        <a
          className="tenant-button tenant-button--primary"
          href="/app/overview"
          onClick={(event) => {
            event.preventDefault();
            props.onNavigate("/app/overview");
          }}
        >
          Go to overview
        </a>
      </div>
    </section>
  );
}

function TenantUnavailable() {
  return (
    <div className="tenant-shell" style={{ gridTemplateColumns: "minmax(0, 1fr)" }}>
      <main className="tenant-content" style={{ gridColumn: "1" }}>
        <p className="tenant-eyebrow">ORGANIZATION WORKSPACE</p>
        <h1 className="tenant-title">Organization workspace is not available in this deployment</h1>
        <p className="tenant-lede">
          Protected organization reads are disabled here. You can keep using the public docs or
          open the local workspace.
        </p>
        <div className="tenant-actions">
          <a className="tenant-button" href="/design/docs">Read the docs</a>
          <a className="tenant-button tenant-button--primary" href="/workspace">Local workspace</a>
        </div>
      </main>
    </div>
  );
}

function roleLabel(role: CommerceHumanRole): string {
  switch (role) {
    case "owner":
      return "Owner";
    case "operator":
      return "Operator";
    case "provider_admin":
      return "Provider admin";
    case "provider_developer":
      return "Provider developer";
    case "viewer":
      return "Viewer";
  }
}

/**
 * Reads the addressed profile's status from the bounded read controller so an
 * issue for an inactive (suspended/revoked/retired) profile is refused before
 * any request. An unknown profile is treated as inactive.
 */
function profileIsActive(
  controller: TenantController,
  kind: "agent" | "provider",
  profileId: string,
): boolean {
  const state = controller.state;
  if (kind === "agent") {
    return state.agents.items.some(
      (item) => item.agentId === profileId && item.status === "active",
    );
  }
  return state.providers.items.some(
    (item) => item.providerId === profileId && item.status === "active",
  );
}

export type { TenantFetch };
