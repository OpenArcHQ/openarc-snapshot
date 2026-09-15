import {
  M01_FIXTURES,
  ARC_ACCOUNT_SNAPSHOT_PATH,
  AGENT_REGISTRY_DISCLOSURE,
  AGENT_REGISTRY_EVIDENCE_PATH,
  ARC_OBSERVATION_DISCLOSURE,
  ARC_TESTNET,
  ARC_TRANSACTION_EVIDENCE_PATH,
  ArcAccountSnapshotRequestSchema,
  ArcTransactionEvidenceRequestSchema,
  AgentRegistryEvidenceRequestSchema,
  describeDeploymentCheck,
  JobEvidenceRequestSchema, JOB_DISCLOSURE, JOB_EVIDENCE_PATH,
  compareIsoTimestamps,
  type JobEvidenceRequest, type JobObservationRecord,
  type GatewayTransferRequest, type GatewayObservationRecord,
  CAPABILITIES_PATH,
  CAPABILITY_DISCLOSURE,
  type ArcObservationRecord,
  type ArcObservationPermissionReceiptRecord,
  type AgentRegistryEvidenceRequest,
  type AgentRegistryObservationRecord,
  type CapabilitiesEnvelope,
  type AgentProfileRecord,
  type MonitoringPolicyRecord,
  type WorkspaceRecord,
  type WorkspaceSettingsRecord,
} from "@openarc/shared";
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";

import type { BuildInfo } from "@openarc/shared";

import { investigationsEnabled, genericAgentImportEnabled, agentRegistryEnabled, agentJobsEnabled, gatewayEvidenceEnabled, apiBoundaryEnabled, arcObservationEnabled, workspaceSectionUsesNetwork } from "../app/availability.js";
import { requestGatewayTransfer } from "../api/gateway-transfer.js";
import { GatewayFinalizationError, runGatewayPermissionFlow } from "../api/gateway-permission-flow.js";
import { PaymentsPanel } from "./PaymentsPanel.js";
import { AgentReportsPanel } from "./AgentReportsPanel.js";
import { InvestigationsPanel } from "./InvestigationsPanel.js";
import { requestJobEvidence } from "../api/job-evidence.js";
import { JobFinalizationError, runJobPermissionFlow } from "../api/job-permission-flow.js";
import { requestAgentRegistryEvidence } from "../api/agent-registry.js";
import {
  AgentRegistryFinalizationError,
  runAgentRegistryPermissionFlow,
} from "../api/agent-registry-permission-flow.js";
import { requestArcAccountSnapshot, requestArcTransactionEvidence } from "../api/arc-observation.js";
import {
  ArcObservationFinalizationError,
  runArcObservationPermissionFlow,
  type ArcObservationInput,
} from "../api/arc-permission-flow.js";
import { CapabilityRequestError, requestCapabilities } from "../api/capabilities.js";
import { OpenArcRequestError } from "../api/client.js";
import { PermissionFinalizationError, runCapabilityPermissionFlow } from "../api/permission-flow.js";
import { subscribeVaultSessionEnd } from "../app/vault-session-lock.js";

import {
  VAULT_COORDINATION_CHANNEL,
  handleCoordinationMessage,
  handleLocalSessionEnd,
  type CoordinationMessage,
  type CoordinationTarget,
  type VaultScreen,
} from "./coordination.js";
import { assertStoredWorkspaceRevision } from "./revision-guard.js";
import {
  observeVaultDatabase,
  readStorageStatus,
  readVaultMeta,
  requestPersistentStorage,
} from "./db.js";
import { VaultError, vaultErrorMessage } from "./errors.js";
import {
  bootstrapWorkspace,
  createAgentProfileRecord,
  createFixtureWorkspaceRecords,
  createLocalWorkspace,
  createMonitoringPolicyRecord,
  deleteWorkspaceRecords,
  destroyLocalWorkspace,
  exportLocalWorkspace,
  exportOpaqueRescue,
  importLocalWorkspace,
  markTourSeen,
  parseBackupFile,
  prepareLocalWorkspaceDeletion,
  recoverLocalWorkspace,
  saveWorkspaceRecords,
  signalWorkspaceLock,
  unlockLocalWorkspace,
  updateWorkspacePassphrase,
  type AgentProfileDraft,
  type MonitoringPolicyDraft,
} from "./service.js";
import { probeVaultPlatform } from "./crypto.js";
import type {
  CreatedWorkspace,
  PublicVaultMeta,
  UnlockedWorkspace,
  VaultStorageStatus,
} from "./types.js";

type WorkspaceView = "overview" | "agents" | "activity" | "policies" | "evidence" | "settings" | "sources" | "jobs" | "payments" | "agent-reports" | "investigations";
type Screen = VaultScreen;

type SessionGuard = {
  signal: AbortSignal;
  assertActive: () => void;
  isActive: () => boolean;
};

const INACTIVITY_MS = 10 * 60 * 1_000;
const API_BOUNDARY_ENABLED = apiBoundaryEnabled();
const ARC_OBSERVATION_ENABLED = API_BOUNDARY_ENABLED && arcObservationEnabled();
const AGENT_REGISTRY_ENABLED = ARC_OBSERVATION_ENABLED && agentRegistryEnabled();
const AGENT_JOBS_ENABLED = AGENT_REGISTRY_ENABLED && agentJobsEnabled();
const GATEWAY_EVIDENCE_ENABLED = AGENT_JOBS_ENABLED && gatewayEvidenceEnabled();
const VIEWS: readonly { id: WorkspaceView; label: string; note: string }[] = [
  { id: "overview", label: "Overview", note: "Local workspace status" },
  { id: "agents", label: "Agents", note: AGENT_REGISTRY_ENABLED ? "Local profiles + registry evidence" : "Owner-supplied profiles" },
  ...(ARC_OBSERVATION_ENABLED ? [{ id: "activity" as const, label: "Activity", note: "Explicit Arc observations" }] : []),
  { id: "policies", label: "Policies", note: "Local monitoring rules" },
  { id: "evidence", label: "Evidence", note: "Encrypted fixture records" },
  { id: "settings", label: "Settings", note: "Backup, recovery, delete" },
  ...(API_BOUNDARY_ENABLED ? [{ id: "sources" as const, label: "Sources", note: "Explicit connection checks" }] : []),
  ...(AGENT_JOBS_ENABLED ? [{ id: "jobs" as const, label: "Jobs", note: "Reference contract evidence" }] : []),
  ...(GATEWAY_EVIDENCE_ENABLED ? [{ id: "payments" as const, label: "Payments", note: "x402 metadata + Gateway reports" }] : []),
  ...(genericAgentImportEnabled() ? [{ id: "agent-reports" as const, label: "Agent reports", note: "Local imports + policy comparisons" }] : []),
  ...(investigationsEnabled() ? [{ id: "investigations" as const, label: "Investigations", note: "Search saved evidence locally" }] : []),
];

export function VaultWorkspace({ build }: { build: BuildInfo }) {
  const [screen, setScreen] = useState<Screen>({ phase: "probing" });
  const [view, setViewState] = useState<WorkspaceView>(() => viewFromLocation());
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusyState] = useState(false);
  const [recoverySecret, setRecoverySecret] = useState<string | null>(null);
  const [tourOpen, setTourOpen] = useState(false);
  const [fatalDeleteConfirmed, setFatalDeleteConfirmed] = useState(false);
  const [sessionGeneration, setSessionGeneration] = useState(0);
  const screenRef = useRef<Screen>({ phase: "probing" });
  const unlockedRef = useRef<UnlockedWorkspace | null>(null);
  const generationRef = useRef(0);
  const channelRef = useRef<BroadcastChannel | null>(null);
  const senderRef = useRef("");
  const deadlineRef = useRef(0);
  const tourReturnFocusRef = useRef<HTMLElement | null>(null);
  const sessionAbortRef = useRef(new AbortController());
  const pendingRef = useRef(false);

  const setBusy = useCallback((value: boolean) => {
    pendingRef.current = value;
    setBusyState(value);
  }, []);

  useEffect(() => {
    screenRef.current = screen;
  }, [screen]);

  const rotateSessionBoundary = useCallback(() => {
    sessionAbortRef.current.abort(new Error("Vault session changed"));
    sessionAbortRef.current = new AbortController();
    generationRef.current += 1;
    setSessionGeneration(generationRef.current);
  }, []);

  const createSessionGuard = useCallback((): SessionGuard => {
    const generation = generationRef.current;
    const signal = sessionAbortRef.current.signal;
    const isActive = () => !signal.aborted && generation === generationRef.current;
    return {
      signal,
      isActive,
      assertActive: () => {
        if (!isActive()) throw new Error("Vault session changed");
      },
    };
  }, []);

  const clearPrivateState = useCallback((next: Screen, message?: string) => {
    rotateSessionBoundary();
    unlockedRef.current = null;
    deadlineRef.current = 0;
    setRecoverySecret(null);
    setTourOpen(false);
    setBusy(false);
    setScreen(next);
    setNotice(message ?? null);
    setError(null);
  }, [rotateSessionBoundary, setBusy]);

  const enterDeleting = useCallback((meta: PublicVaultMeta): boolean => {
    if (!meta.deletionPending) return false;
    clearPrivateState(
      { phase: "deleting", meta },
      "This workspace is being deleted. Workspace controls are unavailable.",
    );
    return true;
  }, [clearPrivateState]);

  const handleObservedVaultBoundary = useCallback(async (
    cause: unknown,
    isActive: () => boolean,
  ): Promise<boolean> => {
    if (!(cause instanceof VaultError) || !["VAULT_CONFLICT", "VAULT_EXISTS"].includes(cause.code)) {
      return false;
    }
    try {
      const meta = await readVaultMeta();
      if (!isActive()) return true;
      if (meta && enterDeleting(meta)) return true;
      if (cause.code === "VAULT_EXISTS") {
        clearPrivateState(
          meta
            ? { phase: "locked", meta }
            : { phase: "fatal", message: "Encrypted workspace bytes exist without readable metadata." },
          meta ? "An encrypted workspace already exists here. Unlock it to continue." : undefined,
        );
        return true;
      }
      clearPrivateState(
        meta ? { phase: "locked", meta } : { phase: "empty" },
        meta
          ? "The encrypted workspace changed while this action was finishing. Unlock again to load the latest revision."
          : "The local workspace was deleted while this action was finishing.",
      );
      return true;
    } catch (readCause) {
      if (!isActive()) return true;
      clearPrivateState({ phase: "fatal", message: vaultErrorMessage(readCause) });
      return true;
    }
  }, [clearPrivateState, enterDeleting]);

  const coordinationTarget = useCallback((): CoordinationTarget => ({
    sender: () => senderRef.current,
    unlocked: () => unlockedRef.current,
    screen: () => screenRef.current,
    generation: () => generationRef.current,
    clearPrivateState,
    setScreen,
    setNotice,
    readMeta: readVaultMeta,
  }), [clearPrivateState]);

  const broadcast = useCallback((type: CoordinationMessage["type"], vaultId: string) => {
    channelRef.current?.postMessage({ sender: senderRef.current, type, vaultId } satisfies CoordinationMessage);
  }, []);

  const acceptUnlocked = useCallback(
    (workspace: UnlockedWorkspace, options: { boundary?: boolean; message?: string } = {}) => {
      if (options.boundary !== false) {
        rotateSessionBoundary();
      }
      unlockedRef.current = workspace;
      deadlineRef.current = Date.now() + INACTIVITY_MS;
      setScreen({ phase: "unlocked", workspace });
      setBusy(false);
      setError(null);
      setNotice(options.message ?? null);
    },
    [rotateSessionBoundary, setBusy],
  );

  const lockImmediately = useCallback(
    (message = "Workspace locked. The in-memory key and decrypted UI state were released.") => {
      const current = unlockedRef.current;
      if (!current) return;
      const lockSignal = signalWorkspaceLock(current.meta);
      // Release private state immediately, but do not expose unlock controls
      // until the durable coordination revision written by signalWorkspaceLock
      // has been read back. Otherwise a slow unlock can start against the old
      // revision and then be invalidated by this tab's own lock signal.
      clearPrivateState({ phase: "locking", meta: current.meta }, message);
      const boundaryGeneration = generationRef.current;
      void lockSignal
        .then((meta) => {
          if (boundaryGeneration !== generationRef.current) return;
          if (meta.deletionPending) {
            enterDeleting(meta);
            return;
          }
          setScreen({ phase: "locked", meta });
        })
        .catch((cause) => void handleObservedVaultBoundary(
          cause,
          () => boundaryGeneration === generationRef.current,
        ));
      broadcast("lock", current.meta.vaultId);
    },
    [broadcast, clearPrivateState, enterDeleting, handleObservedVaultBoundary],
  );

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        if (!(await probeVaultPlatform())) {
          if (!cancelled) setScreen({ phase: "unsupported" });
          return;
        }
        const meta = await bootstrapWorkspace();
        if (!cancelled) {
          setScreen(
            meta
              ? meta.deletionPending
                ? { phase: "deleting", meta }
                : { phase: "locked", meta }
              : { phase: "empty" },
          );
        }
      } catch (cause) {
        if (!cancelled) setScreen({ phase: "fatal", message: vaultErrorMessage(cause) });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    // React development StrictMode intentionally runs an effect cleanup/setup
    // probe without unmounting the component. Start that second setup with a
    // fresh boundary while retaining the real-unmount abort behavior.
    if (sessionAbortRef.current.signal.aborted) {
      sessionAbortRef.current = new AbortController();
    }
    return () => {
      sessionAbortRef.current.abort(new Error("Workspace unmounted"));
      generationRef.current += 1;
      unlockedRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (typeof BroadcastChannel === "undefined" || typeof crypto.randomUUID !== "function") return;
    senderRef.current = crypto.randomUUID();
    const channel = new BroadcastChannel(VAULT_COORDINATION_CHANNEL);
    channelRef.current = channel;
    const target = coordinationTarget();
    channel.onmessage = (event: MessageEvent<unknown>) => handleCoordinationMessage(event.data, target);
    return () => {
      channelRef.current = null;
      channel.close();
    };
  }, [coordinationTarget]);

  // Logout, account change or session expiry in THIS document (P08-02). Other
  // tabs receive the existing `lock` coordination message instead.
  useEffect(() => {
    const target = coordinationTarget();
    return subscribeVaultSessionEnd(() => handleLocalSessionEnd(target));
  }, [coordinationTarget]);

  useEffect(() => {
    if (screen.phase !== "unlocked" && screen.phase !== "locked") return;
    let cancelled = false;
    let closeObserver: (() => void) | null = null;
    void observeVaultDatabase((reason) => {
      if (cancelled) return;
      if (reason === "deletion") {
        const currentScreen = screenRef.current;
        const currentMeta =
          unlockedRef.current?.meta ??
          (currentScreen.phase === "locked" ? currentScreen.meta : null);
        clearPrivateState(
          { phase: "deleting", meta: currentMeta },
          "The local database is being deleted. Workspace controls are unavailable.",
        );
      } else if (reason === "versionchange") {
        const currentScreen = screenRef.current;
        const currentMeta =
          unlockedRef.current?.meta ??
          (currentScreen.phase === "locked" ? currentScreen.meta : null);
        clearPrivateState(
          currentMeta ? { phase: "locking", meta: currentMeta } : { phase: "probing" },
          "The local database changed. OpenArc is rechecking it before exposing any controls.",
        );
        const boundaryGeneration = generationRef.current;
        void readVaultMeta()
          .then((meta) => {
            if (boundaryGeneration !== generationRef.current) return;
            if (!meta) {
              setScreen({ phase: "empty" });
              setNotice("The local workspace database was removed outside OpenArc.");
            } else if (meta.deletionPending) {
              setScreen({ phase: "deleting", meta });
              setNotice("Another tab is deleting this workspace. Workspace controls are unavailable.");
            } else {
              setScreen({ phase: "locked", meta });
              setNotice("The local database changed. Unlock again only after verifying this build.");
            }
          })
          .catch((cause) => {
            if (boundaryGeneration !== generationRef.current) return;
            setScreen({ phase: "fatal", message: vaultErrorMessage(cause) });
            setNotice(null);
          });
      } else {
        const currentScreen = screenRef.current;
        if (unlockedRef.current) {
          lockImmediately("The local database closed unexpectedly. Unlock again before continuing.");
        } else if (currentScreen.phase === "locked") {
          clearPrivateState(
            { phase: "locked", meta: currentScreen.meta },
            "The local database closed unexpectedly. Unlock again only after verifying this browser state.",
          );
        }
      }
    }).then((close) => {
      if (cancelled) close();
      else closeObserver = close;
    });
    return () => {
      cancelled = true;
      closeObserver?.();
    };
  }, [clearPrivateState, lockImmediately, screen.phase, sessionGeneration]);

  useEffect(() => {
    if (!["empty", "unlocked", "locked", "unlocking"].includes(screen.phase)) return;
    let stopped = false;
    const verifyRevision = async () => {
      const boundaryGeneration = generationRef.current;
      try {
        const currentWorkspace = unlockedRef.current;
        const currentMeta =
          currentWorkspace?.meta ??
          (screen.phase === "locked" || screen.phase === "unlocking" ? screen.meta : null);
        // Creation/import can commit before their completion callback delivers
        // the new session and recovery secret. Do not mistake that own commit
        // for a peer-created vault. Existing-session polling remains active.
        if (!currentMeta && pendingRef.current) return;
        const meta = await readVaultMeta();
        if (stopped || boundaryGeneration !== generationRef.current) return;
        if (currentWorkspace && unlockedRef.current !== currentWorkspace) return;
        if (!currentMeta) {
          if (pendingRef.current || unlockedRef.current) return;
          if (!stopped && meta) {
            clearPrivateState(
              meta.deletionPending ? { phase: "deleting", meta } : { phase: "locked", meta },
              meta.deletionPending
                ? "Another tab is deleting this workspace. Workspace controls are unavailable."
                : "An encrypted workspace was created or restored in another tab. Unlock it here to continue.",
            );
          }
          return;
        }
        if (
          !stopped &&
          (!meta ||
            meta.vaultId !== currentMeta.vaultId ||
            meta.revision !== currentMeta.revision ||
            meta.coordinationRevision !== currentMeta.coordinationRevision ||
            meta.deletionPending)
        ) {
          clearPrivateState(
            meta?.deletionPending
              ? { phase: "deleting", meta }
              : meta
                ? { phase: "locked", meta }
                : { phase: "empty" },
            meta
              ? meta.deletionPending
                ? "Another tab is deleting this workspace. Workspace controls are unavailable."
                : "Workspace changed or locked in another tab. Unlock again to load the latest encrypted revision."
              : "The local workspace was deleted in another tab.",
          );
        }
      } catch (cause) {
        if (!stopped && boundaryGeneration === generationRef.current) {
          clearPrivateState({ phase: "fatal", message: vaultErrorMessage(cause) });
        }
      }
    };
    const interval = window.setInterval(() => void verifyRevision(), 2_000);
    return () => {
      stopped = true;
      window.clearInterval(interval);
    };
  }, [clearPrivateState, screen, sessionGeneration]);

  useEffect(() => {
    if (screen.phase !== "deleting") return;
    let cancelled = false;
    if (screen.meta?.deletionPending) {
      void destroyLocalWorkspace(() => {
        if (!cancelled) {
          setNotice(
            "Deletion is waiting for another tab to release the database. No workspace controls are available.",
          );
        }
      })
        .then(() => {
          if (!cancelled) {
            clearPrivateState({ phase: "empty" }, "The encrypted workspace was permanently deleted from this browser.");
          }
        })
        .catch((cause) => {
          if (!cancelled) {
            setError(vaultErrorMessage(cause));
          }
        });
    }
    const interval = window.setInterval(() => {
      void readVaultMeta()
        .then((meta) => {
          if (cancelled) return;
          if (!meta) {
            clearPrivateState({ phase: "empty" }, "The local encrypted workspace was deleted.");
          } else if (meta.deletionPending && screenRef.current.phase === "deleting") {
            const current = screenRef.current.meta;
            if (!current?.deletionPending || current.coordinationRevision !== meta.coordinationRevision) {
              setScreen({ phase: "deleting", meta });
            }
          }
        })
        .catch(() => undefined);
    }, 500);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [clearPrivateState, screen]);

  useEffect(() => {
    const cancelPendingOrLock = () => {
      const current = unlockedRef.current;
      if (current) {
        lockImmediately("Workspace locked when this page was hidden or left.");
        return;
      }
      const currentScreen = screenRef.current;
      if (currentScreen.phase === "unlocking") {
        clearPrivateState(
          { phase: "locked", meta: currentScreen.meta },
          "Pending local unlock was cancelled when this page was hidden or left.",
        );
      } else if (currentScreen.phase === "locked") {
        clearPrivateState(
          currentScreen,
          pendingRef.current
            ? "Pending local operation was cancelled when this page was hidden or left."
            : "Private access drafts were cleared when this page was hidden or left.",
        );
      } else if (currentScreen.phase === "empty") {
        clearPrivateState(
          currentScreen,
          pendingRef.current
            ? "Pending local operation was cancelled when this page was hidden or left."
            : "Private access drafts were cleared when this page was hidden or left.",
        );
      }
    };
    const visibility = () => {
      if (document.visibilityState === "hidden") cancelPendingOrLock();
    };
    window.addEventListener("pagehide", cancelPendingOrLock);
    document.addEventListener("visibilitychange", visibility);
    return () => {
      window.removeEventListener("pagehide", cancelPendingOrLock);
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [clearPrivateState, lockImmediately]);

  useEffect(() => {
    if (screen.phase !== "unlocked") return;
    const activity = () => {
      deadlineRef.current = Date.now() + INACTIVITY_MS;
    };
    const checkDeadline = () => {
      if (deadlineRef.current > 0 && Date.now() >= deadlineRef.current) {
        lockImmediately("Workspace locked after 10 minutes of inactivity.");
      }
    };
    const timer = window.setInterval(checkDeadline, 1_000);
    window.addEventListener("pointerdown", activity, { passive: true });
    window.addEventListener("keydown", activity);
    window.addEventListener("pageshow", checkDeadline);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("pointerdown", activity);
      window.removeEventListener("keydown", activity);
      window.removeEventListener("pageshow", checkDeadline);
    };
  }, [lockImmediately, screen.phase, sessionGeneration]);

  useEffect(() => {
    const popState = () => setViewState(viewFromLocation());
    window.addEventListener("popstate", popState);
    return () => window.removeEventListener("popstate", popState);
  }, []);

  useEffect(() => {
    if (error) requestAnimationFrame(() => document.querySelector<HTMLElement>(".workspace-error")?.focus());
  }, [error]);

  const navigate = (next: WorkspaceView) => {
    window.history.pushState(null, "", `/workspace?view=${next}`);
    setViewState(next);
  };

  const create = async (passphrase: string) => {
    const guard = createSessionGuard();
    let metaRead = false;
    setBusy(true);
    setError(null);
    try {
      const existing = await readVaultMeta();
      metaRead = true;
      guard.assertActive();
      if (existing) {
        if (enterDeleting(existing)) return;
        clearPrivateState(
          { phase: "locked", meta: existing },
          "An encrypted workspace already exists here. Unlock it to continue.",
        );
        return;
      }
      const created = await createLocalWorkspace(passphrase, guard.assertActive, guard.signal);
      guard.assertActive();
      acceptCreated(created, "Encrypted workspace created in this browser.");
      broadcast("changed", created.meta.vaultId);
    } catch (cause) {
      if (!guard.isActive()) return;
      if (await handleObservedVaultBoundary(cause, guard.isActive)) return;
      if (!guard.isActive()) return;
      if (!metaRead) {
        clearPrivateState({ phase: "fatal", message: vaultErrorMessage(cause) });
        return;
      }
      setBusy(false);
      setError(vaultErrorMessage(cause));
    }
  };

  const acceptCreated = (created: CreatedWorkspace, message: string) => {
    acceptUnlocked(created, { message });
    setRecoverySecret(created.recoverySecret || null);
  };

  const unlock = async (passphrase: string) => {
    const guard = createSessionGuard();
    let currentMeta: PublicVaultMeta | null = null;
    let metaRead = false;
    setBusy(true);
    setError(null);
    try {
      currentMeta = await readVaultMeta();
      metaRead = true;
      guard.assertActive();
      if (!currentMeta) {
        clearPrivateState({ phase: "empty" }, "No local workspace remains in this browser.");
        return;
      }
      if (enterDeleting(currentMeta)) return;
      setScreen({ phase: "unlocking", meta: currentMeta });
      const workspace = await unlockLocalWorkspace(currentMeta, passphrase);
      guard.assertActive();
      acceptUnlocked(workspace);
      const settings = workspace.records.find(
        (record): record is WorkspaceSettingsRecord => record.kind === "workspace_settings",
      );
      if (settings && !settings.tourSeen) setTourOpen(true);
    } catch (cause) {
      if (!guard.isActive()) return;
      if (await handleObservedVaultBoundary(cause, guard.isActive)) return;
      if (!guard.isActive()) return;
      if (!metaRead) {
        clearPrivateState({ phase: "fatal", message: vaultErrorMessage(cause) });
        return;
      }
      setScreen(currentMeta ? { phase: "locked", meta: currentMeta } : { phase: "empty" });
      setBusy(false);
      setError(vaultErrorMessage(cause));
    }
  };

  const recover = async (secret: string, nextPassphrase: string) => {
    const guard = createSessionGuard();
    let metaRead = false;
    setBusy(true);
    setError(null);
    try {
      const currentMeta = await readVaultMeta();
      metaRead = true;
      guard.assertActive();
      if (!currentMeta) {
        clearPrivateState({ phase: "empty" });
        return;
      }
      if (enterDeleting(currentMeta)) return;
      const recovered = await recoverLocalWorkspace(
        currentMeta,
        secret,
        nextPassphrase,
        guard.assertActive,
        guard.signal,
      );
      guard.assertActive();
      acceptCreated(recovered, "Recovery succeeded. Save the new recovery secret now.");
      broadcast("changed", recovered.meta.vaultId);
    } catch (cause) {
      if (!guard.isActive()) return;
      if (await handleObservedVaultBoundary(cause, guard.isActive)) return;
      if (!guard.isActive()) return;
      if (!metaRead) {
        clearPrivateState({ phase: "fatal", message: vaultErrorMessage(cause) });
        return;
      }
      setBusy(false);
      setError(vaultErrorMessage(cause));
    }
  };

  const importBackup = async (file: File, backupPassphrase: string, nextPassphrase: string) => {
    const guard = createSessionGuard();
    let metaRead = false;
    setBusy(true);
    setError(null);
    try {
      const freshMeta = await readVaultMeta();
      metaRead = true;
      guard.assertActive();
      if (freshMeta && enterDeleting(freshMeta)) return;
      const expected = unlockedRef.current?.meta ?? freshMeta;
      const parsed = await parseBackupFile(file);
      guard.assertActive();
      const restored = await importLocalWorkspace(
        parsed,
        backupPassphrase,
        nextPassphrase,
        expected,
        guard.assertActive,
        guard.signal,
      );
      guard.assertActive();
      acceptCreated(restored, "Backup restored into fresh encryption keys. Save the new recovery secret.");
      broadcast("changed", restored.meta.vaultId);
    } catch (cause) {
      if (!guard.isActive()) return;
      if (await handleObservedVaultBoundary(cause, guard.isActive)) return;
      if (!guard.isActive()) return;
      if (!metaRead) {
        clearPrivateState({ phase: "fatal", message: vaultErrorMessage(cause) });
        return;
      }
      setBusy(false);
      setError(vaultErrorMessage(cause));
    }
  };

  const downloadOpaqueRescue = async () => {
    const guard = createSessionGuard();
    setBusy(true);
    setError(null);
    try {
      const rescue = await exportOpaqueRescue();
      guard.assertActive();
      downloadJson(
        rescue,
        `openarc-opaque-rescue-${new Date().toISOString().slice(0, 10)}.json`,
      );
      setBusy(false);
      setNotice(
        "Opaque encrypted rescue downloaded. This build cannot import it; retain it for diagnostics or future recovery tooling.",
      );
    } catch (cause) {
      if (!guard.isActive()) return;
      if (await handleObservedVaultBoundary(cause, guard.isActive)) return;
      if (!guard.isActive()) return;
      setBusy(false);
      setError(vaultErrorMessage(cause));
    }
  };

  const saveRecords = async (records: readonly WorkspaceRecord[], message: string) => {
    const current = unlockedRef.current;
    if (!current) return false;
    const guard = createSessionGuard();
    setBusy(true);
    setError(null);
    try {
      const assertActive = () => {
        guard.assertActive();
        if (unlockedRef.current !== current) throw new Error("Vault session changed");
      };
      const saved = await saveWorkspaceRecords(current, records, assertActive, guard.signal);
      assertActive();
      acceptUnlocked(saved, { boundary: false, message });
      broadcast("changed", saved.meta.vaultId);
      return true;
    } catch (cause) {
      if (!guard.isActive()) return false;
      if (await handleObservedVaultBoundary(cause, guard.isActive)) return false;
      if (!guard.isActive()) return false;
      setBusy(false);
      setError(vaultErrorMessage(cause));
      return false;
    }
  };

  const checkCapabilities = async (): Promise<CapabilitiesEnvelope | null> => {
    const current = unlockedRef.current;
    if (!current || !API_BOUNDARY_ENABLED) return null;
    const guard = createSessionGuard();
    let expected = current;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await runCapabilityPermissionFlow({ workspace: current, origin: window.location.origin,
        signal: guard.signal, assertActive: () => {
          guard.assertActive();
          if (unlockedRef.current !== expected) throw new Error("Vault session changed");
        },
        save: (workspace, receipts, assertActive, signal) => saveWorkspaceRecords(workspace, receipts, assertActive, signal),
        verifyStored: (workspace) => assertStoredWorkspaceRevision(workspace),
        request: requestCapabilities,
        onCommitted: (workspace) => {
          expected = workspace;
          unlockedRef.current = workspace;
          deadlineRef.current = Date.now() + INACTIVITY_MS;
          setScreen({ phase: "unlocked", workspace });
          broadcast("changed", workspace.meta.vaultId);
        } });
      guard.assertActive();
      setBusy(false);
      setNotice(result.capabilities.data.features.agentRegistry
        ? "Capability check completed. Arc observation and bounded ERC-8004 registry evidence are enabled in this build."
        : result.capabilities.data.features.arcObservation
        ? "Capability check completed. The Arc read-only observation connector is enabled in this build."
        : "Capability check completed. Live Arc observation remains disabled in this build.");
      return result.capabilities;
    } catch (cause) {
      if (!guard.isActive()) return null;
      const storageBoundary = cause instanceof PermissionFinalizationError ? cause.storageCause : cause;
      if (await handleObservedVaultBoundary(storageBoundary, guard.isActive)) return null;
      if (!guard.isActive()) return null;
      setBusy(false);
      setError(cause instanceof PermissionFinalizationError
        ? cause.phase === "completed-request"
          ? "The request reached OpenArc and its response was accepted, but completion could not be saved. The encrypted approval remains in your permission history."
          : "The request may have reached OpenArc, but its failed outcome could not be saved. The encrypted approval remains in your permission history."
        : cause instanceof CapabilityRequestError
        ? cause.phase === "pre-send"
          ? "The capability request was not sent. Its encrypted approval remains in the permission history."
          : "The capability request may have reached OpenArc, but no valid result was accepted. Review the encrypted permission history."
        : vaultErrorMessage(cause));
      return null;
    }
  };

  const observeArc = async (input: ArcObservationInput): Promise<ArcObservationRecord | null> => {
    const current = unlockedRef.current;
    if (!current || !ARC_OBSERVATION_ENABLED) return null;
    const guard = createSessionGuard();
    let expected = current;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await runArcObservationPermissionFlow({ workspace: current,
        origin: window.location.origin, input, signal: guard.signal,
        assertActive: () => {
          guard.assertActive();
          if (unlockedRef.current !== expected) throw new Error("Vault session changed");
        },
        save: async (workspace, records, assertActive, signal) => {
          const saved = await saveWorkspaceRecords(workspace, records, assertActive, signal);
          assertActive();
          expected = saved;
          unlockedRef.current = saved;
          deadlineRef.current = Date.now() + INACTIVITY_MS;
          setScreen({ phase: "unlocked", workspace: saved });
          broadcast("changed", saved.meta.vaultId);
          return saved;
        },
        verifyStored: (workspace) => assertStoredWorkspaceRevision(workspace),
        request: (requestInput, signal) => requestInput.kind === "account"
          ? requestArcAccountSnapshot(requestInput.request, signal)
          : requestArcTransactionEvidence(requestInput.request, signal),
      });
      guard.assertActive();
      setBusy(false);
      setNotice(input.kind === "account"
        ? "Arc account snapshot validated and encrypted locally. Nothing was signed or broadcast."
        : "Arc transaction evidence validated and encrypted locally. Matching ERC-20 logs were not double-counted.");
      return result.observation;
    } catch (cause) {
      if (!guard.isActive()) return null;
      const storageBoundary = cause instanceof ArcObservationFinalizationError ? cause.storageCause : cause;
      if (await handleObservedVaultBoundary(storageBoundary, guard.isActive)) return null;
      if (!guard.isActive()) return null;
      setBusy(false);
      setError(cause instanceof ArcObservationFinalizationError
        ? cause.phase === "completed-request"
          ? "The public identifier reached OpenArc and a result was accepted, but the result could not be saved. The encrypted approval remains; prior evidence was not changed."
          : "The public identifier may have reached OpenArc, but the failed outcome could not be saved. The encrypted approval remains; prior evidence was not changed."
        : cause instanceof OpenArcRequestError
          ? cause.phase === "pre-send"
            ? "The Arc request was not sent. Check the public identifier and try again."
            : `No new Arc evidence was accepted (${cause.code}). Prior encrypted evidence remains unchanged and should be treated as stale.`
          : vaultErrorMessage(cause));
      return null;
    }
  };

  const observeAgentRegistry = async (request: AgentRegistryEvidenceRequest,
    linkedAgentProfileRecordId: string | null): Promise<AgentRegistryObservationRecord | null> => {
    const current = unlockedRef.current;
    if (!current || !AGENT_REGISTRY_ENABLED) return null;
    const guard = createSessionGuard();
    let expected = current;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await runAgentRegistryPermissionFlow({ workspace: current, origin: window.location.origin,
        request, linkedAgentProfileRecordId, signal: guard.signal,
        assertActive: () => {
          guard.assertActive();
          if (unlockedRef.current !== expected) throw new Error("Vault session changed");
        },
        save: async (workspace, records, assertActive, signal) => {
          const saved = await saveWorkspaceRecords(workspace, records, assertActive, signal);
          assertActive();
          expected = saved;
          unlockedRef.current = saved;
          deadlineRef.current = Date.now() + INACTIVITY_MS;
          setScreen({ phase: "unlocked", workspace: saved });
          broadcast("changed", saved.meta.vaultId);
          return saved;
        },
        verifyStored: (workspace) => assertStoredWorkspaceRevision(workspace),
        fetch: requestAgentRegistryEvidence,
      });
      guard.assertActive();
      setBusy(false);
      setNotice("ERC-8004 registry evidence validated and encrypted locally. Claims remain source- and observer-specific.");
      return result.observation;
    } catch (cause) {
      if (!guard.isActive()) return null;
      const storageBoundary = cause instanceof AgentRegistryFinalizationError ? cause.storageCause : cause;
      if (await handleObservedVaultBoundary(storageBoundary, guard.isActive)) return null;
      if (!guard.isActive()) return null;
      setBusy(false);
      setError(cause instanceof AgentRegistryFinalizationError
        ? cause.phase === "completed-request"
          ? "Registry evidence was accepted but could not be saved. The encrypted approval remains; prior evidence was not changed."
          : "The registry request may have reached OpenArc, but its failed outcome could not be saved."
        : cause instanceof OpenArcRequestError
          ? cause.phase === "pre-send"
            ? "The registry request was not sent. Check the exact public identifiers and try again."
            : `No registry evidence was accepted (${cause.code}). Prior encrypted evidence remains unchanged.`
          : vaultErrorMessage(cause));
      return null;
    }
  };

  const observeJob = async (request: JobEvidenceRequest,
    linkedActionRecordId: string | null): Promise<JobObservationRecord | null> => {
    const current = unlockedRef.current;
    if (!current || !AGENT_JOBS_ENABLED) return null;
    const guard = createSessionGuard();
    let expected = current;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await runJobPermissionFlow({ workspace: current, origin: window.location.origin,
        request, linkedActionRecordId, signal: guard.signal,
        assertActive: () => {
          guard.assertActive();
          if (unlockedRef.current !== expected) throw new Error("Vault session changed");
        },
        save: async (workspace, records, assertActive, signal) => {
          const saved = await saveWorkspaceRecords(workspace, records, assertActive, signal);
          assertActive();
          expected = saved;
          unlockedRef.current = saved;
          deadlineRef.current = Date.now() + INACTIVITY_MS;
          setScreen({ phase: "unlocked", workspace: saved });
          broadcast("changed", saved.meta.vaultId);
          return saved;
        },
        verifyStored: (workspace) => assertStoredWorkspaceRevision(workspace),
        fetch: requestJobEvidence,
      });
      guard.assertActive();
      setBusy(false);
      setNotice("Job evidence validated and encrypted locally. Contract status and local action claims remain separate.");
      return result.observation;
    } catch (cause) {
      if (!guard.isActive()) return null;
      const storageBoundary = cause instanceof JobFinalizationError ? cause.storageCause : cause;
      if (await handleObservedVaultBoundary(storageBoundary, guard.isActive)) return null;
      if (!guard.isActive()) return null;
      setBusy(false);
      setError(cause instanceof JobFinalizationError
        ? cause.phase === "completed-request"
          ? "Job evidence was accepted but could not be saved. The encrypted approval remains; prior evidence was not changed."
          : "The job request may have reached OpenArc, but its failed outcome could not be saved."
        : cause instanceof OpenArcRequestError
          ? cause.phase === "pre-send"
            ? "The job request was not sent. Check the exact public identifiers and try again."
            : `No job evidence was accepted (${cause.code}). Prior encrypted evidence remains unchanged.`
          : vaultErrorMessage(cause));
      return null;
    }
  };

  const observeGateway = async (request: GatewayTransferRequest,
    linkedBundleRecordId: string | null): Promise<GatewayObservationRecord | null> => {
    const current = unlockedRef.current;
    if (!current || !GATEWAY_EVIDENCE_ENABLED) return null;
    const guard = createSessionGuard();
    let expected = current;
    setBusy(true); setError(null); setNotice(null);
    try {
      const result = await runGatewayPermissionFlow({ workspace: current, origin: window.location.origin,
        request, linkedBundleRecordId, signal: guard.signal,
        assertActive: () => {
          guard.assertActive();
          if (unlockedRef.current !== expected) throw new Error("Vault session changed");
        },
        save: async (workspace, records, assertActive, signal) => {
          const saved = await saveWorkspaceRecords(workspace, records, assertActive, signal);
          assertActive(); expected = saved; unlockedRef.current = saved;
          deadlineRef.current = Date.now() + INACTIVITY_MS;
          setScreen({ phase: "unlocked", workspace: saved }); broadcast("changed", saved.meta.vaultId);
          return saved;
        },
        verifyStored: (workspace) => assertStoredWorkspaceRevision(workspace),
        fetch: requestGatewayTransfer,
      });
      guard.assertActive(); setBusy(false);
      setNotice("Gateway report encrypted locally. Imported metadata, Gateway status and fulfillment remain separate.");
      return result.observation;
    } catch (cause) {
      if (!guard.isActive()) return null;
      const storageBoundary = cause instanceof GatewayFinalizationError ? cause.storageCause : cause;
      if (await handleObservedVaultBoundary(storageBoundary, guard.isActive)) return null;
      if (!guard.isActive()) return null;
      setBusy(false);
      setError(cause instanceof GatewayFinalizationError
        ? "The Gateway request may have reached the source, but its outcome could not be saved. The encrypted approval remains."
        : cause instanceof OpenArcRequestError
          ? cause.phase === "pre-send" ? "The Gateway request was not sent. Check the transfer UUID."
            : `No Gateway evidence was accepted (${cause.code}). Prior evidence remains unchanged.`
          : vaultErrorMessage(cause));
      return null;
    }
  };

  const deleteRecords = async (ids: readonly string[], message: string) => {
    const current = unlockedRef.current;
    if (!current) return false;
    const guard = createSessionGuard();
    setBusy(true);
    setError(null);
    try {
      const assertActive = () => {
        guard.assertActive();
        if (unlockedRef.current !== current) throw new Error("Vault session changed");
      };
      const saved = await deleteWorkspaceRecords(current, ids, assertActive, guard.signal);
      assertActive();
      acceptUnlocked(saved, { boundary: false, message });
      broadcast("changed", saved.meta.vaultId);
      return true;
    } catch (cause) {
      if (!guard.isActive()) return false;
      if (await handleObservedVaultBoundary(cause, guard.isActive)) return false;
      if (!guard.isActive()) return false;
      setBusy(false);
      setError(vaultErrorMessage(cause));
      return false;
    }
  };

  const manualLock = () => {
    const current = unlockedRef.current;
    if (!current) return;
    lockImmediately("Workspace locked locally and signalled to other active tabs.");
  };

  const destroy = async () => {
    let meta = unlockedRef.current?.meta ?? null;
    let metaUnreadable = false;
    if (!meta) {
      try {
        meta = await readVaultMeta();
      } catch {
        metaUnreadable = true;
      }
    }
    rotateSessionBoundary();
    unlockedRef.current = null;
    setRecoverySecret(null);
    setTourOpen(false);
    setBusy(true);
    setScreen({ phase: "deleting", meta });
    if (metaUnreadable) {
      try {
        await destroyLocalWorkspace(() => {
          setNotice("Deletion is waiting for another tab to release the unreadable database.");
        });
        clearPrivateState({ phase: "empty" }, "The unreadable local workspace was permanently deleted.");
      } catch (cause) {
        clearPrivateState({ phase: "fatal", message: vaultErrorMessage(cause) });
      }
      return;
    }
    if (!meta) {
      clearPrivateState({ phase: "empty" }, "No local encrypted workspace remains.");
      return;
    }
    try {
      const marked = await prepareLocalWorkspaceDeletion(meta);
      setScreen({ phase: "deleting", meta: marked });
      broadcast("deleting", marked.vaultId);
    } catch (cause) {
      try {
        const current = await readVaultMeta();
        clearPrivateState(current ? { phase: "locked", meta: current } : { phase: "empty" });
        setError(vaultErrorMessage(cause));
      } catch (readCause) {
        clearPrivateState({ phase: "fatal", message: vaultErrorMessage(readCause) });
      }
    }
  };

  const closeTour = async () => {
    setTourOpen(false);
    const current = unlockedRef.current;
    const settings = current?.records.find(
      (record): record is WorkspaceSettingsRecord => record.kind === "workspace_settings",
    );
    if (settings && !settings.tourSeen) {
      await saveRecords([markTourSeen(settings)], "Tour preference saved inside the encrypted workspace.");
    }
  };

  const messageRegion = (
    <div className="workspace-messages" aria-live="polite" aria-atomic="true">
      {error ? <p className="workspace-error" role="alert" tabIndex={-1}>{error}</p> : null}
      {notice ? <p className="workspace-notice">{notice}</p> : null}
    </div>
  );

  if (screen.phase === "probing") return <WorkspaceWait label="Checking local encryption support…" />;
  if (screen.phase === "unsupported") {
    return (
      <WorkspaceGate title="Encrypted workspace unavailable" build={build}>
        <p>
          OpenArc needs a secure context, WebCrypto with AES-GCM/AES-KW/PBKDF2, secure randomness,
          and IndexedDB. This browser did not pass the capability probe, so no private controls were mounted.
        </p>
      </WorkspaceGate>
    );
  }
  if (screen.phase === "fatal") {
    return (
      <WorkspaceGate title="Local workspace could not start" build={build}>
        <p>{screen.message}</p>
        {messageRegion}
        <label className="confirm-row">
          <input type="checkbox" checked={fatalDeleteConfirmed} onChange={(event) => setFatalDeleteConfirmed(event.target.checked)} />
          I understand deleting unreadable local data cannot be undone without a rescue or backup.
        </label>
        <div className="modal-actions">
          <button type="button" disabled={busy} onClick={() => void downloadOpaqueRescue()}>Export opaque rescue</button>
          <button type="button" disabled={busy || !fatalDeleteConfirmed} onClick={() => void destroy()}>Delete unreadable local data</button>
          <button className="button" disabled={busy} onClick={() => window.location.reload()}>Retry safely</button>
        </div>
      </WorkspaceGate>
    );
  }
  if (screen.phase === "deleting") {
    return (
      <WorkspaceGate title="Deleting encrypted workspace" build={build}>
        <p>No unlock, create, import, or recovery action is available while browser deletion is pending.</p>
        {messageRegion}
        <div className="workspace-spinner" aria-hidden="true" />
      </WorkspaceGate>
    );
  }
  if (screen.phase === "empty" || screen.phase === "locked" || screen.phase === "unlocking") {
    return (
      <AccessScreen
        key={`access:${sessionGeneration}`}
        build={build}
        locked={screen.phase !== "empty"}
        busy={busy || screen.phase === "unlocking"}
        messages={messageRegion}
        onCreate={create}
        onUnlock={unlock}
        onRecover={recover}
        onImport={importBackup}
        onRescue={downloadOpaqueRescue}
        onDestroy={destroy}
      />
    );
  }
  if (screen.phase === "locking") return <WorkspaceWait label="Locking every active local view…" />;

  const workspace = screen.workspace;
  return (
    <div className="workspace-shell" key={`${workspace.meta.vaultId}:${sessionGeneration}`}>
      <a className="skip-link" href="#workspace-main" onClick={() => {
        requestAnimationFrame(() => document.querySelector<HTMLElement>("#workspace-main")?.focus());
      }}>
        Skip workspace navigation
      </a>
      <aside className="workspace-rail" aria-label="Workspace navigation">
        <a className="workspace-brand" href="/" aria-label="OpenArc home">
          <img src="/openarc-logo.jpeg" alt="" />
          <span><strong>OPENARC</strong><small>PRIVATE WORKSPACE</small></span>
        </a>
        <div className="workspace-rail-state">
          <span className="status-dot" aria-hidden="true" />
          <span>UNLOCKED LOCALLY</span>
        </div>
        <nav>
          {VIEWS.map((item, index) => (
            <button
              key={item.id}
              type="button"
              aria-current={view === item.id ? "page" : undefined}
              onClick={() => navigate(item.id)}
            >
              <span>{String(index + 1).padStart(2, "0")}</span>
              <strong>{item.label}</strong>
              <small>{item.note}</small>
            </button>
          ))}
        </nav>
        <button className="workspace-tour" type="button" onClick={(event) => {
          tourReturnFocusRef.current = event.currentTarget;
          setTourOpen(true);
        }} disabled={busy}>
          Show quick tour
        </button>
        <button className="workspace-lock" type="button" onClick={() => void manualLock()}>
          Lock workspace
        </button>
      </aside>
      <main className="workspace-main" id="workspace-main" tabIndex={-1}>
        <header className="workspace-mobile-header">
          <a href="/" className="brand"><img src="/openarc-logo.jpeg" alt="" /><span>OPENARC</span></a>
          <button type="button" className="button button-small" onClick={() => void manualLock()}>Lock</button>
        </header>
        <nav className="workspace-mobile-nav" aria-label="Compact workspace navigation">
          {VIEWS.map((item) => (
            <button key={item.id} type="button" aria-current={view === item.id ? "page" : undefined} onClick={() => navigate(item.id)}>
              {item.label}
            </button>
          ))}
        </nav>
        {messageRegion}
        <WorkspaceViewPanel
          key={`${sessionGeneration}:${view}`}
          view={view}
          workspace={workspace}
          busy={busy}
          onSave={saveRecords}
          onDelete={deleteRecords}
          onCheckCapabilities={checkCapabilities}
          onObserveArc={observeArc}
          onObserveAgentRegistry={observeAgentRegistry}
          onObserveJob={observeJob}
          onObserveGateway={observeGateway}
          onImport={importBackup}
          onAcceptCreated={acceptCreated}
          onDestroy={destroy}
          onLock={lockImmediately}
          onOpenTour={(target) => {
            tourReturnFocusRef.current = target;
            setTourOpen(true);
          }}
          setBusy={setBusy}
          setError={setError}
          setNotice={setNotice}
          onOperationError={handleObservedVaultBoundary}
          createSessionGuard={createSessionGuard}
          broadcast={broadcast}
        />
        <footer className="workspace-footer">
          <span>{API_BOUNDARY_ENABLED ? "LOCAL PRIVATE DATA · EXPLICIT NETWORK PERMISSION" : "LOCAL-ONLY · ZERO NETWORK CALLS"}</span>
          <code data-testid="build-sha">BUILD {build.commitSha}</code>
        </footer>
      </main>
      {recoverySecret ? (
        <RecoveryDialog secret={recoverySecret} onClose={() => {
          setRecoverySecret(null);
          const settings = unlockedRef.current?.records.find(
            (record): record is WorkspaceSettingsRecord => record.kind === "workspace_settings",
          );
          setTourOpen(Boolean(settings && !settings.tourSeen));
        }} />
      ) : null}
      {tourOpen && !recoverySecret ? <TourDialog returnFocus={tourReturnFocusRef.current} onClose={() => void closeTour()} /> : null}
    </div>
  );
}

function AccessScreen(props: {
  build: BuildInfo;
  locked: boolean;
  busy: boolean;
  messages: ReactNode;
  onCreate: (passphrase: string) => Promise<void>;
  onUnlock: (passphrase: string) => Promise<void>;
  onRecover: (secret: string, nextPassphrase: string) => Promise<void>;
  onImport: (file: File, backupPassphrase: string, nextPassphrase: string) => Promise<void>;
  onRescue: () => Promise<void>;
  onDestroy: () => Promise<void>;
}) {
  const [mode, setMode] = useState<"primary" | "recover" | "import" | "rescue" | "delete">("primary");
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [recovery, setRecovery] = useState("");
  const [backupPassphrase, setBackupPassphrase] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [deleteConfirmed, setDeleteConfirmed] = useState(false);
  const submitPrimary = (event: FormEvent) => {
    event.preventDefault();
    if (props.locked) void props.onUnlock(passphrase);
    else if (passphrase === confirmation) void props.onCreate(passphrase);
  };
  return (
    <WorkspaceGate title={props.locked ? "Unlock your private workspace" : "Create a private workspace"} build={props.build}>
      <p>
        Records are encrypted in this browser before IndexedDB persistence. OpenArc does not receive
        the workspace passphrase, recovery secret, key, profiles, policies, or evidence.
      </p>
      {props.messages}
      <div className="access-mode-tabs" role="group" aria-label="Workspace access method">
        <button type="button" aria-pressed={mode === "primary"} onClick={() => setMode("primary")}>{props.locked ? "Unlock" : "Create"}</button>
        <button type="button" aria-pressed={mode === "import"} onClick={() => setMode("import")}>Import backup</button>
        {props.locked ? <button type="button" aria-pressed={mode === "recover"} onClick={() => setMode("recover")}>Recovery</button> : null}
        {props.locked ? <button type="button" aria-pressed={mode === "rescue"} onClick={() => setMode("rescue")}>Rescue</button> : null}
        {props.locked ? <button type="button" aria-pressed={mode === "delete"} onClick={() => setMode("delete")}>Delete</button> : null}
      </div>
      {mode === "primary" ? (
        <form className="workspace-form" onSubmit={submitPrimary}>
          <Field label="Workspace passphrase" hint="12–128 characters. It never leaves this browser.">
            <input type="password" autoComplete={props.locked ? "current-password" : "new-password"} value={passphrase} onChange={(event) => setPassphrase(event.target.value)} required minLength={12} maxLength={128} />
          </Field>
          {!props.locked ? (
            <Field label="Confirm passphrase"><input type="password" autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} required minLength={12} maxLength={128} /></Field>
          ) : null}
          {!props.locked && confirmation && confirmation !== passphrase ? <p className="field-error">Passphrases do not match.</p> : null}
          <button className="button" disabled={props.busy || (!props.locked && confirmation !== passphrase)}>{props.busy ? "Working locally…" : props.locked ? "Unlock workspace" : "Create encrypted workspace"}</button>
        </form>
      ) : null}
      {mode === "recover" ? (
        <form className="workspace-form" onSubmit={(event) => { event.preventDefault(); if (confirmation === passphrase) void props.onRecover(recovery, passphrase); }}>
          <Field label="Recovery secret" hint="Use the current secret saved when this workspace was created or last recovered."><input value={recovery} onChange={(event) => setRecovery(event.target.value)} required autoComplete="off" /></Field>
          <Field label="New workspace passphrase"><input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} required minLength={12} maxLength={128} autoComplete="new-password" /></Field>
          <Field label="Confirm new passphrase"><input type="password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} required minLength={12} maxLength={128} autoComplete="new-password" /></Field>
          <button className="button" disabled={props.busy || confirmation !== passphrase}>Recover and rotate credentials</button>
        </form>
      ) : null}
      {mode === "import" ? (
        <form className="workspace-form" onSubmit={(event) => { event.preventDefault(); if (file && confirmation === passphrase) void props.onImport(file, backupPassphrase, passphrase); }}>
          <Field label="Encrypted .openarc backup"><input type="file" accept="application/json,.openarc" required onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></Field>
          <Field label="Backup passphrase"><input type="password" value={backupPassphrase} onChange={(event) => setBackupPassphrase(event.target.value)} required minLength={12} maxLength={128} /></Field>
          <Field label="New workspace passphrase" hint="Import creates new local encryption and a new recovery secret."><input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} required minLength={12} maxLength={128} /></Field>
          <Field label="Confirm new passphrase"><input type="password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} required minLength={12} maxLength={128} /></Field>
          {props.locked ? <p className="warning-copy">This replaces the current encrypted workspace only if its revision has not changed.</p> : null}
          <button className="button" disabled={props.busy || !file || confirmation !== passphrase}>Verify and restore backup</button>
        </form>
      ) : null}
      {mode === "rescue" ? (
        <div className="danger-panel">
          <h2>Export unreadable encrypted bytes</h2>
          <p>
            This does not decrypt or validate records. It preserves the opaque IndexedDB values for
            diagnostics or possible future tooling and cannot be imported by this build.
          </p>
          <button className="button" type="button" disabled={props.busy} onClick={() => void props.onRescue()}>
            Download opaque rescue
          </button>
        </div>
      ) : null}
      {mode === "delete" ? (
        <div className="danger-panel">
          <h2>Delete this browser’s workspace?</h2>
          <p>This permanently removes the encrypted records and wrappers. Export a backup first if you may need them.</p>
          <label className="confirm-row"><input type="checkbox" checked={deleteConfirmed} onChange={(event) => setDeleteConfirmed(event.target.checked)} /> I understand this cannot be undone without a backup.</label>
          <button className="button button-danger" type="button" disabled={props.busy || !deleteConfirmed} onClick={() => void props.onDestroy()}>Permanently delete local workspace</button>
        </div>
      ) : null}
    </WorkspaceGate>
  );
}

function WorkspaceViewPanel(props: {
  view: WorkspaceView;
  workspace: UnlockedWorkspace;
  busy: boolean;
  onSave: (records: readonly WorkspaceRecord[], message: string) => Promise<boolean>;
  onDelete: (ids: readonly string[], message: string) => Promise<boolean>;
  onCheckCapabilities: () => Promise<CapabilitiesEnvelope | null>;
  onObserveArc: (input: ArcObservationInput) => Promise<ArcObservationRecord | null>;
  onObserveAgentRegistry: (request: AgentRegistryEvidenceRequest,
    linkedAgentProfileRecordId: string | null) => Promise<AgentRegistryObservationRecord | null>;
  onObserveJob: (request: JobEvidenceRequest, linkedActionRecordId: string | null) => Promise<JobObservationRecord | null>;
  onObserveGateway: (request: GatewayTransferRequest, linkedBundleRecordId: string | null) => Promise<GatewayObservationRecord | null>;
  onImport: (file: File, backupPassphrase: string, nextPassphrase: string) => Promise<void>;
  onAcceptCreated: (created: CreatedWorkspace, message: string) => void;
  onDestroy: () => Promise<void>;
  onLock: (message?: string) => void;
  onOpenTour: (target: HTMLElement) => void;
  setBusy: (value: boolean) => void;
  setError: (value: string | null) => void;
  setNotice: (value: string | null) => void;
  onOperationError: (cause: unknown, isActive: () => boolean) => Promise<boolean>;
  createSessionGuard: () => SessionGuard;
  broadcast: (type: CoordinationMessage["type"], vaultId: string) => void;
}) {
  if (props.view === "overview") return <Overview records={props.workspace.records} onNavigate={navigateFromPanel} onOpenTour={props.onOpenTour} />;
  if (props.view === "agents") return <AgentsPanel {...props} />;
  if (props.view === "activity") return <ActivityPanel {...props} />;
  if (props.view === "policies") return <PoliciesPanel {...props} />;
  if (props.view === "evidence") return <EvidencePanel {...props} />;
  if (props.view === "sources") return <SourcesPanel {...props} />;
  if (props.view === "jobs") return <JobsPanel {...props} />;
  if (props.view === "payments") return <PaymentsPanel {...props} />;
  if (props.view === "agent-reports") return <AgentReportsPanel {...props} />;
  if (props.view === "investigations" && investigationsEnabled()) return <InvestigationsPanel key={props.workspace.meta.revision} {...props} />;
  return <SettingsPanel {...props} />;

  function navigateFromPanel(view: WorkspaceView) {
    window.history.pushState(null, "", `/workspace?view=${view}`);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }
}

function Overview({ records, onNavigate, onOpenTour }: { records: readonly WorkspaceRecord[]; onNavigate: (view: WorkspaceView) => void; onOpenTour: (target: HTMLElement) => void }) {
  const counts = recordCounts(records);
  return (
    <section className="workspace-section" aria-labelledby="workspace-overview-title">
      <SectionHeading eyebrow="ENCRYPTED LOCAL CONTROL LAYER" title="Your agent evidence, held here." id="workspace-overview-title" onLearn={onOpenTour}>
        OpenArc keeps owner-supplied profiles, monitoring rules, actions, and evidence distinct. This milestone makes those records private and durable without introducing a server data plane.
      </SectionHeading>
      <div className="workspace-stat-grid">
        <Stat value={counts.agents} label="Agent profiles" />
        <Stat value={counts.policies} label="Monitoring policies" />
        <Stat value={counts.actions} label="Action envelopes" />
        <Stat value={counts.evidence} label="Evidence records" />
        {genericAgentImportEnabled() ? <Stat value={counts.agentReports} label="Agent reports" /> : null}
        {ARC_OBSERVATION_ENABLED ? <Stat value={counts.observations} label="Arc observations" /> : null}
        {AGENT_REGISTRY_ENABLED ? <Stat value={counts.registryObservations} label="Registry evidence" /> : null}
        {AGENT_JOBS_ENABLED ? <Stat value={counts.jobObservations} label="Job observations" /> : null}
      </div>
      <div className="workspace-callouts">
        <article><span>01</span><h3>Describe an agent</h3><p>Add only what you know and label wallet associations as owner-supplied.</p><button type="button" onClick={() => onNavigate("agents")}>Open Agents →</button></article>
        <article><span>02</span><h3>Define a local rule</h3><p>Record a monitoring boundary. OpenArc does not enforce it or execute transactions.</p><button type="button" onClick={() => onNavigate("policies")}>Open Policies →</button></article>
        <article><span>03</span><h3>Inspect evidence</h3><p>Copy one of the six synthetic M01 cases into your encrypted workspace.</p><button type="button" onClick={() => onNavigate("evidence")}>Open Evidence →</button></article>
        {ARC_OBSERVATION_ENABLED ? <article><span>04</span><h3>Observe Arc explicitly</h3><p>Review exactly what is released, then read one public address or transaction at an exact final block.</p><button type="button" onClick={() => onNavigate("activity")}>Open Activity →</button></article> : null}
        {genericAgentImportEnabled() ? <article><span>05</span><h3>Compare an agent report</h3><p>Preview a local report and compare supplied attempts with monitoring rules. Authorship and enforcement remain unverified.</p><button type="button" onClick={() => onNavigate("agent-reports")}>Open Agent reports →</button></article> : null}
        {investigationsEnabled() ? <article><span>LOCAL</span><h3>Investigate saved evidence</h3><p>Search actions, inspect exceptions and compare cited facts without contacting a source.</p><button type="button" onClick={() => onNavigate("investigations")}>Open Investigations →</button></article> : null}
      </div>
      <div className="privacy-strip"><strong>Nothing refreshes automatically.</strong><span>Only an explicitly approved source lookup may call the network. Agent-report imports and comparisons stay local. Reload starts locked.</span></div>
    </section>
  );
}

function AgentsPanel(props: Pick<Parameters<typeof WorkspaceViewPanel>[0], "workspace" | "busy" | "onSave" |
  "onDelete" | "onOpenTour" | "onObserveAgentRegistry">) {
  const agents = props.workspace.records.filter((record): record is AgentProfileRecord => record.kind === "agent_profile");
  const [editing, setEditing] = useState<AgentProfileRecord | null | undefined>(undefined);
  return (
    <section className="workspace-section" aria-labelledby="agents-title">
      <SectionHeading eyebrow="OWNER-SUPPLIED IDENTITY" title="Agents" id="agents-title" onLearn={props.onOpenTour}>Profiles organize local evidence. A wallet entered here is not discovered, authenticated, or proven to belong to an agent.</SectionHeading>
      <button className="button" type="button" disabled={props.busy} onClick={() => setEditing(null)}>Add agent profile</button>
      <div className="workspace-list">
        {agents.length === 0 ? <EmptyState title="No agent profiles yet" body="Create one locally or import a synthetic evidence fixture." /> : agents.map((agent) => (
          <article key={agent.recordId}>
            <div><p className="eyebrow">{agent.frameworkLabel ?? "UNLABELED FRAMEWORK"}</p><h3>{agent.displayName}</h3><ExactIdentifier label="Agent ID" value={agent.agentId} /></div>
            <dl><div><dt>Wallets</dt><dd>{agent.wallets.length}</dd></div><div><dt>Linked policy records</dt><dd>{agent.policyRecordIds.length}</dd></div><div><dt>Purpose note</dt><dd>{agent.purposeNote ?? "Not supplied"}</dd></div></dl>
            <div className="row-actions"><button type="button" onClick={() => setEditing(agent)}>Edit</button><button type="button" className="danger-link" onClick={() => void props.onDelete([agent.recordId], "Agent profile deleted from the encrypted workspace.")}>Delete</button></div>
          </article>
        ))}
      </div>
      {editing !== undefined ? <AgentDialog key={editing?.recordId ?? "new"} existing={editing} busy={props.busy} onClose={() => setEditing(undefined)} onSave={async (draft) => {
        const saved = await props.onSave([createAgentProfileRecord(draft, props.workspace.meta.revision, editing ?? undefined)], editing ? "Agent profile updated." : "Agent profile encrypted and saved.");
        if (saved) setEditing(undefined);
        return saved;
      }} /> : null}
      {AGENT_REGISTRY_ENABLED ? <AgentRegistryPanel {...props} agents={agents} /> : null}
    </section>
  );
}

function AgentRegistryPanel(props: Pick<Parameters<typeof WorkspaceViewPanel>[0], "workspace" | "busy" |
  "onDelete" | "onObserveAgentRegistry"> & { agents: readonly AgentProfileRecord[] }) {
  const [agentId, setAgentId] = useState("");
  const [linkedProfile, setLinkedProfile] = useState("");
  const [includeFeedback, setIncludeFeedback] = useState(false);
  const [observer, setObserver] = useState("");
  const [feedbackIndex, setFeedbackIndex] = useState("0");
  const [includeValidation, setIncludeValidation] = useState(false);
  const [validationHash, setValidationHash] = useState("");
  const [pending, setPending] = useState<{ request: AgentRegistryEvidenceRequest; linked: string | null } | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const observations = props.workspace.records
    .filter((record): record is AgentRegistryObservationRecord => record.kind === "agent_registry_observation")
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  const profileByRecordId = new Map(props.agents.map((profile) => [profile.recordId, profile]));

  const review = (event: FormEvent) => {
    event.preventDefault();
    const parsed = AgentRegistryEvidenceRequestSchema.safeParse({ network: ARC_TESTNET.caip2, agentId,
      ...(includeFeedback ? { feedbackQuery: { clientAddress: observer, feedbackIndex } } : {}),
      ...(includeValidation ? { validationRequestHash: validationHash } : {}) });
    if (!parsed.success) {
      setValidationError("Enter a canonical registry agent ID and complete every enabled exact-claim identifier.");
      return;
    }
    setValidationError(null);
    setPending({ request: parsed.data, linked: linkedProfile || null });
  };
  const approve = async () => {
    if (!pending) return;
    const approved = pending;
    setPending(null);
    const saved = await props.onObserveAgentRegistry(approved.request, approved.linked);
    if (saved) {
      setAgentId("");
      setLinkedProfile("");
      setIncludeFeedback(false);
      setObserver("");
      setFeedbackIndex("0");
      setIncludeValidation(false);
      setValidationHash("");
    }
  };

  return <div className="registry-evidence" aria-labelledby="registry-evidence-title">
    <div className="section-heading compact">
      <p className="eyebrow">ARC TESTNET · ERC-8004 DRAFT</p>
      <h2 id="registry-evidence-title">Registry evidence</h2>
      <p>Read one identity and, optionally, one exact observer or validator claim. This is source-linked evidence—not a verification badge or universal reputation score.</p>
    </div>
    <form className="workspace-form settings-wide" onSubmit={review}>
      <Field label="ERC-8004 agent ID" hint="A canonical decimal token ID from the fixed Arc Testnet IdentityRegistry.">
        <input value={agentId} onChange={(event) => setAgentId(event.target.value)} inputMode="numeric" required />
      </Field>
      <Field label="Link to a local profile (optional)" hint="This link stays encrypted in your browser and is never released to the API.">
        <select value={linkedProfile} onChange={(event) => setLinkedProfile(event.target.value)}>
          <option value="">No local profile link</option>
          {props.agents.map((profile) => <option key={profile.recordId} value={profile.recordId}>{profile.displayName}</option>)}
        </select>
      </Field>
      <label className="confirm-row"><input type="checkbox" checked={includeFeedback}
        onChange={(event) => setIncludeFeedback(event.target.checked)} /> Include one exact observer feedback record</label>
      {includeFeedback ? <div className="form-grid">
        <Field label="Observer address"><input value={observer} onChange={(event) => setObserver(event.target.value)} required /></Field>
        <Field label="Feedback index"><input value={feedbackIndex} onChange={(event) => setFeedbackIndex(event.target.value)} inputMode="numeric" required /></Field>
      </div> : null}
      <label className="confirm-row"><input type="checkbox" checked={includeValidation}
        onChange={(event) => setIncludeValidation(event.target.checked)} /> Include one exact validation request</label>
      {includeValidation ? <Field label="Validation request hash"><input value={validationHash}
        onChange={(event) => setValidationHash(event.target.value)} required /></Field> : null}
      {validationError ? <p className="field-error">{validationError}</p> : null}
      <button className="button" type="submit" disabled={props.busy}>Review permission</button>
    </form>
    <div className="workspace-list">
      {observations.length === 0 ? <EmptyState title="No registry evidence yet"
        body="Nothing is queried automatically. Review one bounded request to save source-linked facts here." /> : observations.map((record) => {
        const evidence = record.observation;
        const localProfile = record.linkedAgentProfileRecordId ? profileByRecordId.get(record.linkedAgentProfileRecordId) : undefined;
        return <article key={record.recordId}>
          <div><p className="eyebrow">REGISTRY IDENTITY · NOT VERIFIED</p>
            <h3>{localProfile ? localProfile.displayName : `Agent ${evidence.agentId}`}</h3>
            {localProfile ? <p>Local label above is owner-supplied. Registry facts below remain separate.</p> : null}
            <ExactIdentifier label="Registry agent ID" value={evidence.agentId} />
          </div>
          <dl className="source-facts">
            <div><dt>Registry owner</dt><dd><code>{evidence.identity.owner}</code></dd></div>
            <div><dt>Registry agent wallet</dt><dd><code>{evidence.identity.agentWallet}</code></dd></div>
            <div><dt>Metadata</dt><dd><code>{evidence.identity.metadata.uri || "None"}</code>
              {evidence.identity.metadata.kind === "https" ? <> · <a href={evidence.identity.metadata.uri}
                target="_blank" rel="noopener noreferrer">Open untrusted metadata</a></> : null}<br />Not fetched or rendered by OpenArc.</dd></div>
            <div><dt>Exact block</dt><dd>{evidence.anchor.blockNumber} · <code>{evidence.anchor.blockHash}</code></dd></div>
          </dl>
          {evidence.feedback ? <div className="evidence-claim">
            <p className="eyebrow">OBSERVER-SPECIFIC FEEDBACK</p>
            <p><strong>{evidence.feedback.decimal}</strong> · {evidence.feedback.revoked ? "Revoked" : "Active"}</p>
            <ExactIdentifier label="Observer" value={evidence.feedback.observer} />
            <p>Tags: {evidence.feedback.tag1 || "none"} / {evidence.feedback.tag2 || "none"}. This is one observer’s claim.</p>
          </div> : null}
          {evidence.schemaVersion === "openarc.agent-registry-evidence.v2" ? <>
            <div className="evidence-claim">
              <p className="eyebrow">{evidence.deployment.status === "verified" ? "REGISTRY DEPLOYMENT MATCHES REVIEWED PINS"
                : evidence.deployment.status === "drift" ? "REGISTRY DEPLOYMENT DRIFT · EVIDENCE NOT VERIFIED"
                  : "REGISTRY DEPLOYMENT UNKNOWN · EVIDENCE NOT VERIFIED"}</p>
              {evidence.deployment.status === "verified"
                ? <p>Implementation and proxy owner of all three registries matched the reviewed pins at this block.</p>
                : <ul>{describeDeploymentCheck(evidence.deployment).map((reason) => <li key={reason}>{reason}</li>)}</ul>}
            </div>
            {evidence.validation?.state === "responded" ? <div className="evidence-claim">
              <p className="eyebrow">VALIDATOR-SPECIFIC RESPONSE</p>
              <p><strong>{evidence.validation.response}/100</strong> · {evidence.validation.tag || "No tag"}</p>
              <ExactIdentifier label="Validator" value={evidence.validation.validator} />
              <ExactIdentifier label="Request hash" value={evidence.validation.requestHash} />
              <p>Attributed from ValidationResponse event {evidence.validation.responseEvent.transactionHash} at block {evidence.validation.responseEvent.blockNumber}.
                This response belongs to the named validator; it is not a general safety certification.</p>
            </div> : null}
            {evidence.validation?.state === "pending_or_unobserved" ? <div className="evidence-claim">
              <p className="eyebrow">VALIDATION PENDING OR UNOBSERVED</p>
              <p><strong>Pending</strong> · no validator response is attributed</p>
              <ExactIdentifier label="Named validator" value={evidence.validation.namedValidator} />
              <ExactIdentifier label="Request hash" value={evidence.validation.requestHash} />
              <p>{evidence.validation.reason}</p>
            </div> : null}
          </> : <>
            <div className="evidence-claim">
              <p className="eyebrow">LEGACY RECORD · DEPLOYMENT NOT CHECKED</p>
              <p>Saved before registry implementation pins and pending-validation detection. Refresh to re-observe.</p>
            </div>
            {evidence.validation ? <div className="evidence-claim">
              <p className="eyebrow">LEGACY VALIDATION STATUS · NOT ATTRIBUTED</p>
              <p>Registry getter value {evidence.validation.response}/100 with no observed ValidationResponse event. It may be a pending request, so no validator response is attributed.</p>
              <ExactIdentifier label="Named validator" value={evidence.validation.validator} />
              <ExactIdentifier label="Request hash" value={evidence.validation.requestHash} />
            </div> : null}
          </>}
          <details><summary>Source and limitations</summary>
            <p>Arc public RPC · ERC-8004 {evidence.source.specificationStatus} · source {evidence.source.sourceRevision}</p>
            <ul>{evidence.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul>
          </details>
          <div className="row-actions">
            <button type="button" disabled={props.busy} onClick={() => {
              setAgentId(evidence.agentId);
              setLinkedProfile(record.linkedAgentProfileRecordId ?? "");
              setIncludeFeedback(Boolean(evidence.feedback));
              setObserver(evidence.feedback?.observer ?? "");
              setFeedbackIndex(evidence.feedback?.feedbackIndex ?? "0");
              setIncludeValidation(Boolean(evidence.validation));
              setValidationHash(evidence.validation?.requestHash ?? "");
            }}>Load identifiers to refresh</button>
            <button type="button" className="danger-link" disabled={props.busy}
              onClick={() => void props.onDelete([record.recordId, record.permissionReceiptId], "Registry evidence and its permission receipt deleted.")}>Delete evidence</button>
          </div>
        </article>;
      })}
    </div>
    {pending ? <Modal title="Allow this registry observation?" onClose={() => setPending(null)}>
      <p>OpenArc will read one public ERC-8004 identity at one exact final Arc Testnet block. Optional claims are limited to the exact identifiers below.</p>
      <dl className="permission-disclosure">
        <div><dt>OpenArc request</dt><dd><code>POST {AGENT_REGISTRY_EVIDENCE_PATH}</code></dd></div>
        <div><dt>Upstream source</dt><dd><code>{ARC_TESTNET.rpcHttp}</code></dd></div>
        <div><dt>Released registry agent ID</dt><dd><code>{pending.request.agentId}</code></dd></div>
        {pending.request.feedbackQuery ? <div><dt>Released feedback lookup</dt><dd><code>{pending.request.feedbackQuery.clientAddress}</code> · index {pending.request.feedbackQuery.feedbackIndex}</dd></div> : null}
        {pending.request.validationRequestHash ? <div><dt>Released validation lookup</dt><dd><code>{pending.request.validationRequestHash}</code></dd></div> : null}
        <div><dt>Local profile and label</dt><dd>Not released</dd></div>
        <div><dt>Credentials</dt><dd>Omitted; no cookie, wallet connection, private key, or account token</dd></div>
        <div><dt>OpenArc retention</dt><dd>{AGENT_REGISTRY_DISCLOSURE.openArcRetention}</dd></div>
        <div><dt>Provider handling</dt><dd>{AGENT_REGISTRY_DISCLOSURE.providerRetention}</dd></div>
        <div><dt>Network metadata</dt><dd>{AGENT_REGISTRY_DISCLOSURE.hostingMetadata}</dd></div>
      </dl>
      <p>The approval is encrypted first. Remote metadata is not fetched. OpenArc does not sign or broadcast anything.</p>
      <div className="modal-actions"><button type="button" onClick={() => setPending(null)}>Cancel</button>
        <button className="button" type="button" disabled={props.busy} onClick={() => void approve()}>Approve and observe</button></div>
    </Modal> : null}
  </div>;
}

function JobsPanel(props: Pick<Parameters<typeof WorkspaceViewPanel>[0], "workspace" | "busy" | "onObserveJob" | "onDelete" | "onOpenTour">) {
  const [jobId, setJobId] = useState("");
  const [submissionHash, setSubmissionHash] = useState("");
  const [linkedAction, setLinkedAction] = useState("");
  const [confirmedLink, setConfirmedLink] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [pending, setPending] = useState<{ request: JobEvidenceRequest; linked: string | null } | null>(null);
  const actions = props.workspace.records.filter((record) => record.kind === "action_envelope");
  const observations = props.workspace.records.filter((record): record is JobObservationRecord => record.kind === "job_observation")
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  const review = (event: FormEvent) => {
    event.preventDefault();
    const parsed = JobEvidenceRequestSchema.safeParse({ network: ARC_TESTNET.caip2, jobId,
      ...(submissionHash ? { submissionTransactionHash: submissionHash } : {}) });
    if (!parsed.success || (linkedAction && !confirmedLink)) {
      setValidationError("Use a positive decimal job ID, a complete optional transaction hash, and confirm any local action link.");
      return;
    }
    setValidationError(null);
    setPending({ request: parsed.data, linked: linkedAction || null });
  };
  const approve = async () => {
    if (!pending) return;
    const approved = pending;
    setPending(null);
    if (await props.onObserveJob(approved.request, approved.linked)) {
      setJobId(""); setSubmissionHash(""); setLinkedAction(""); setConfirmedLink(false);
    }
  };
  return <section className="workspace-section job-evidence" aria-labelledby="jobs-title">
    <SectionHeading eyebrow="ARC TESTNET · REVIEWED REFERENCE CONTRACT" title="Jobs" id="jobs-title" onLearn={props.onOpenTour}>
      See who commissioned, provides, and evaluates a job, its USDC budget, and its recorded status. This covers one ERC-8183 reference deployment—not every Arc job.
    </SectionHeading>
    <form className="workspace-form settings-wide" onSubmit={review}>
      <Field label="ERC-8183 job ID" hint="Use the positive decimal ID from the Arc reference contract. No wallet connection is needed.">
        <input value={jobId} onChange={(event) => setJobId(event.target.value)} inputMode="numeric" required maxLength={78} />
      </Field>
      <Field label="Submission transaction hash (optional)" hint="The job record does not store its deliverable hash. Supply the exact submission transaction to observe that event; nothing is searched automatically.">
        <input value={submissionHash} onChange={(event) => setSubmissionHash(event.target.value)} maxLength={66} />
      </Field>
      {actions.length ? <>
        <Field label="Link to a local action (optional)" hint="This is your private association, not an onchain conclusion.">
          <select value={linkedAction} onChange={(event) => { setLinkedAction(event.target.value); setConfirmedLink(false); }}>
            <option value="">No local action link</option>
            {actions.map((record) => <option value={record.recordId} key={record.recordId}>{record.action.kind} · {record.action.actionId}</option>)}
          </select>
        </Field>
        {linkedAction ? <label className="confirm-row"><input type="checkbox" checked={confirmedLink}
          onChange={(event) => setConfirmedLink(event.target.checked)} required /> I explicitly associate this job with this local action. This does not verify matching intent or fulfillment.</label> : null}
      </> : <p>Local action links become available when this workspace contains action records. You can observe a job without a link.</p>}
      {validationError ? <p role="alert" className="field-error">{validationError}</p> : null}
      <button className="button" type="submit" disabled={props.busy}>Review job permission</button>
    </form>
    <div className="workspace-list">
      {observations.length === 0 ? <EmptyState title="No job evidence yet" body="Enter a public job ID and review the request. No jobs are fetched in the background." /> : observations.map((record) => {
        const job = record.observation;
        const action = actions.find((candidate) => candidate.recordId === record.linkedActionRecordId);
        const failedAfter = props.workspace.records.some((candidate) => candidate.kind === "permission_receipt" &&
          candidate.recordSchema === "openarc.permission-receipt.v4" && candidate.outcome === "failed" &&
          candidate.released.jobId === job.jobId && compareIsoTimestamps(candidate.resolvedAt ?? candidate.approvedAt, record.createdAt) > 0);
        return <article key={record.recordId}>
          <div><p className="eyebrow">{failedAfter ? "STALE · LAST REFRESH FAILED" : "SAVED BLOCK OBSERVATION · NOT LIVE"}</p>
            <h3>Job {job.jobId}</h3><p>Recorded status: <strong>{job.status}</strong>. This is not a service-quality verdict.</p>
          </div>
          <dl className="source-facts">
            <div><dt>Client · commissions the job</dt><dd><code>{job.client}</code></dd></div>
            <div><dt>Provider · performs the work</dt><dd><code>{job.provider === `0x${"0".repeat(40)}` ? "Not assigned" : job.provider}</code></dd></div>
            <div><dt>Evaluator · decides acceptance</dt><dd><code>{job.evaluator}</code></dd></div>
            <div><dt>Recorded budget</dt><dd>{job.budget.decimal} USDC · {job.budget.explicitlySet ? "Explicitly assigned" : "Default zero; not explicitly assigned"}<br />Not a current escrow balance or net payment amount.</dd></div>
            <div><dt>Deadline</dt><dd>{job.expiry.timestamp}<br />{job.expiry.deadlineReachedAtAnchor ? "Reached at observation block" : "Not reached at observation block"}. Deadline timing does not change the recorded status.</dd></div>
            <div><dt>Contract description · untrusted text</dt><dd>{job.description || "No description"}</dd></div>
            <div><dt>Deliverable digest</dt><dd>{job.deliverable.availability === "submission_event" ? <><code>{job.deliverable.digest}</code><br />Observed submission event; content and quality not verified.</> : "Not observed. getJob does not return a digest."}</dd></div>
          </dl>
          {action ? <div className="evidence-claim"><p className="eyebrow">EXPLICIT LOCAL ASSOCIATION · NOT VERIFIED</p>
            <ExactIdentifier label="Local action" value={action.action.actionId} /><p>Local kind: {action.action.kind}. The contract description above does not overwrite this action or prove that they match.</p></div> : null}
          <details><summary>Exact source, block, and limitations</summary>
            <dl className="source-facts">
              <div><dt>Reference contract</dt><dd><code>{job.source.contract}</code></dd></div>
              <div><dt>Reviewed implementation</dt><dd><code>{job.source.implementation}</code></dd></div>
              <div><dt>Hook · not executed</dt><dd><code>{job.hook}</code></dd></div>
              <div><dt>Observation block</dt><dd>{job.anchor.blockNumber} · <code>{job.anchor.blockHash}</code><br />{job.anchor.blockTimestamp}</dd></div>
              <div><dt>Observed at</dt><dd>{job.source.observedAt}</dd></div>
              <div><dt>Source revision</dt><dd>{job.source.sourceRevision}</dd></div>
              {job.deliverable.availability === "submission_event" ? <div><dt>Submission transaction / log</dt><dd><code>{job.deliverable.transactionHash}</code> · log {job.deliverable.logIndex}</dd></div> : null}
            </dl>
            <ul>{job.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul>
          </details>
          <div className="row-actions"><button type="button" disabled={props.busy} onClick={() => {
            setJobId(job.jobId); setSubmissionHash(job.deliverable.availability === "submission_event" ? job.deliverable.transactionHash : "");
            setLinkedAction(record.linkedActionRecordId ?? ""); setConfirmedLink(false);
          }}>Load identifiers to refresh</button>
            <button type="button" className="danger-link" disabled={props.busy} onClick={() => void props.onDelete(
              [record.recordId, record.permissionReceiptId], "Job evidence and its permission receipt deleted.")}>Delete job evidence</button></div>
        </article>;
      })}
    </div>
    {pending ? <Modal title="Allow this job observation?" onClose={() => setPending(null)}>
      <p>Read one job from the fixed Arc Testnet reference contract. Nothing is signed, funded, submitted, or broadcast.</p>
      <dl className="permission-disclosure">
        <div><dt>OpenArc request</dt><dd><code>POST {JOB_EVIDENCE_PATH}</code></dd></div>
        <div><dt>Upstream source</dt><dd><code>{ARC_TESTNET.rpcHttp}</code></dd></div>
        <div><dt>Released network and job ID</dt><dd>{pending.request.network} · {pending.request.jobId}</dd></div>
        {pending.request.submissionTransactionHash ? <div><dt>Released submission transaction</dt><dd><code>{pending.request.submissionTransactionHash}</code></dd></div> : null}
        <div><dt>Local action link, labels, and notes</dt><dd>Not released</dd></div>
        <div><dt>Credentials</dt><dd>Omitted; no cookies, wallet connection, private key, or account token</dd></div>
        <div><dt>OpenArc retention</dt><dd>{JOB_DISCLOSURE.openArcRetention}</dd></div>
        <div><dt>Provider handling</dt><dd>{JOB_DISCLOSURE.providerRetention}</dd></div>
        <div><dt>Network metadata</dt><dd>{JOB_DISCLOSURE.hostingMetadata}</dd></div>
      </dl>
      <p>The approval is encrypted first. If saving it fails, no lookup is sent. A failed lookup never replaces earlier evidence.</p>
      <div className="modal-actions"><button type="button" onClick={() => setPending(null)}>Cancel</button>
        <button className="button" type="button" disabled={props.busy} onClick={() => void approve()}>Approve and observe job</button></div>
    </Modal> : null}
  </section>;
}

function PoliciesPanel(props: Pick<Parameters<typeof WorkspaceViewPanel>[0], "workspace" | "busy" | "onSave" | "onDelete" | "onOpenTour">) {
  const policies = props.workspace.records.filter((record): record is MonitoringPolicyRecord => record.kind === "monitoring_policy");
  const [editing, setEditing] = useState<MonitoringPolicyRecord | null | undefined>(undefined);
  return (
    <section className="workspace-section" aria-labelledby="policies-title">
      <SectionHeading eyebrow="LOCAL MONITORING ONLY" title="Policies" id="policies-title" onLearn={props.onOpenTour}>Policies describe review boundaries. They do not grant permission, stop an agent, sign a transaction, or broadcast anything.</SectionHeading>
      <button className="button" type="button" disabled={props.busy} onClick={() => setEditing(null)}>Add monitoring policy</button>
      <div className="workspace-list">
        {policies.length === 0 ? <EmptyState title="No monitoring policies" body="Add a bounded amount or recipient rule for local review." /> : policies.map((record) => (
          <article key={record.recordId}>
            <div><p className="eyebrow">REVISION {record.revision}</p><h3>{record.policy.label}</h3><ExactIdentifier label="Policy ID" value={record.policy.policyId} /></div>
            <dl><div><dt>Max base units</dt><dd>{record.policy.maximumAmountBaseUnits ?? "Not set"}</dd></div><div><dt>Recipients</dt><dd>{record.policy.allowedRecipients.length || "Any"}</dd></div><div><dt>Expires</dt><dd>{record.policy.expiresAt ?? "No expiry"}</dd></div></dl>
            <div className="row-actions"><button type="button" onClick={() => setEditing(record)}>Edit</button><button type="button" className="danger-link" onClick={() => void props.onDelete([record.recordId], "Monitoring policy deleted.")}>Delete</button></div>
          </article>
        ))}
      </div>
      {editing !== undefined ? <PolicyDialog key={editing?.recordId ?? "new"} existing={editing} busy={props.busy} onClose={() => setEditing(undefined)} onSave={async (draft) => {
        const saved = await props.onSave([createMonitoringPolicyRecord(draft, props.workspace.meta.revision, editing ?? undefined)], editing ? "Monitoring policy updated." : "Monitoring policy encrypted and saved.");
        if (saved) setEditing(undefined);
        return saved;
      }} /> : null}
    </section>
  );
}

function EvidencePanel(props: Pick<Parameters<typeof WorkspaceViewPanel>[0], "workspace" | "busy" | "onSave" | "onOpenTour">) {
  const actions = props.workspace.records.filter((record) => record.kind === "action_envelope");
  const evidence = props.workspace.records.filter((record) => record.kind === "evidence_record");
  const actionIds = new Set(actions.map((record) => record.action.actionId));
  const importFixture = async (fixture: (typeof M01_FIXTURES)[number]) => {
    await props.onSave(createFixtureWorkspaceRecords(fixture, props.workspace.meta.revision), `${fixture.title} copied into encrypted local records.`);
  };
  return (
    <section className="workspace-section" aria-labelledby="evidence-workspace-title">
      <SectionHeading eyebrow="M01 ENGINE · NOW ENCRYPTED" title="Evidence" id="evidence-workspace-title" onLearn={props.onOpenTour}>Import deterministic examples to inspect how the private workspace retains actions and their cited evidence separately.</SectionHeading>
      <div className="fixture-import-grid">
        {M01_FIXTURES.map((fixture) => {
          const imported = actionIds.has(fixture.action.actionId);
          return <article key={fixture.fixtureId}><span className={`state-badge state-${fixture.expectedState.toLowerCase()}`}>{fixture.expectedState.replaceAll("_", " ")}</span><h3>{fixture.title}</h3><p>{fixture.summary}</p><button type="button" disabled={props.busy || imported} onClick={() => void importFixture(fixture)}>{imported ? "Already encrypted" : "Copy into workspace"}</button></article>;
        })}
      </div>
      <div className="workspace-record-summary"><strong>{actions.length} action envelopes</strong><span>{evidence.length} evidence records</span></div>
      <div className="workspace-list compact">
        {actions.map((record) => (
          <article key={record.recordId}><div><p className="eyebrow">{record.action.kind.replaceAll("_", " ")}</p><h3>Encrypted action</h3><ExactIdentifier label="Action ID" value={record.action.actionId} /></div><dl><div><dt>Agent</dt><dd>{record.action.agentId}</dd></div><div><dt>State</dt><dd>{record.action.reconciliation?.state ?? "NOT RECONCILED"}</dd></div><div><dt>Cited evidence</dt><dd>{record.action.reconciliation?.evidenceIds.length ?? 0}</dd></div></dl></article>
        ))}
      </div>
    </section>
  );
}

function ActivityPanel(props: Pick<Parameters<typeof WorkspaceViewPanel>[0], "workspace" | "busy" | "onObserveArc" | "onOpenTour">) {
  const [kind, setKind] = useState<"account" | "transaction">("account");
  const [identifier, setIdentifier] = useState("");
  const [pending, setPending] = useState<ArcObservationInput | null>(null);
  const [validation, setValidation] = useState<string | null>(null);
  const observations = props.workspace.records
    .filter((record): record is ArcObservationRecord => record.kind === "arc_observation")
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  const failedReceipts = props.workspace.records
    .filter((record): record is ArcObservationPermissionReceiptRecord =>
      record.kind === "permission_receipt" &&
      record.recordSchema === "openarc.permission-receipt.v2" && record.outcome === "failed");

  const review = (nextKind: "account" | "transaction", value: string) => {
    const parsed = nextKind === "account"
      ? ArcAccountSnapshotRequestSchema.safeParse({ network: ARC_TESTNET.caip2, address: value.trim() })
      : ArcTransactionEvidenceRequestSchema.safeParse({ network: ARC_TESTNET.caip2, transactionHash: value.trim() });
    if (!parsed.success) {
      setValidation(nextKind === "account"
        ? "Enter one complete 0x-prefixed Arc address (40 hexadecimal characters)."
        : "Enter one complete 0x-prefixed transaction hash (64 hexadecimal characters).");
      return;
    }
    setValidation(null);
    setPending({ kind: nextKind, request: parsed.data } as ArcObservationInput);
  };
  const approve = async () => {
    if (!pending) return;
    const accepted = await props.onObserveArc(pending);
    setPending(null);
    if (accepted) {
      setIdentifier("");
    }
  };
  return (
    <section className="workspace-section" aria-labelledby="activity-title">
      <SectionHeading eyebrow="EXPLICIT · READ ONLY · ARC TESTNET" title="Activity" id="activity-title" onLearn={props.onOpenTour}>
        Observe one public address or transaction at a time. OpenArc saves an encrypted permission receipt before contact, pins the exact final block, and never signs or broadcasts.
      </SectionHeading>
      <div className="settings-grid sources-grid activity-controls">
        <article className="settings-wide">
          <div className="access-mode-tabs" role="group" aria-label="Arc observation type">
            <button type="button" aria-pressed={kind === "account"} onClick={() => { setKind("account"); setValidation(null); }}>Account snapshot</button>
            <button type="button" aria-pressed={kind === "transaction"} onClick={() => { setKind("transaction"); setValidation(null); }}>Transaction evidence</button>
          </div>
          <form className="workspace-form" onSubmit={(event) => { event.preventDefault(); review(kind, identifier); }}>
            <Field label={kind === "account" ? "Public Arc Testnet address" : "Public Arc Testnet transaction hash"}
              hint="Only this public identifier and the fixed network ID will leave the browser after approval.">
              <input required spellCheck={false} autoComplete="off" value={identifier}
                placeholder={kind === "account" ? "0x…40 hex characters" : "0x…64 hex characters"}
                onChange={(event) => { setIdentifier(event.target.value); setValidation(null); }} />
            </Field>
            {validation ? <DialogValidationError message={validation} /> : null}
            <button className="button" disabled={props.busy}>Review permission</button>
          </form>
        </article>
        <article>
          <h3>What is proven</h3>
          <p>Chain ID, exact block number/hash/time, deterministic finality, native USDC precision, and—when requested—receipt status, fee, and canonical USDC movements.</p>
        </article>
        <article>
          <h3>What is not proven</h3>
          <p>A wallet is not automatically an agent. A transaction does not prove intent, authorization, fulfillment, service quality, or ownership.</p>
        </article>
      </div>
      <div className="workspace-list activity-list">
        {observations.length === 0 ? <EmptyState title="No Arc observations yet"
          body="Choose one public identifier above. Nothing refreshes automatically." /> : observations.map((record) => {
          const observation = record.observation;
          const accountObservation = observation.schemaVersion === "openarc.arc-account-snapshot.v1";
          const connector = accountObservation ? "arc_account_snapshot" : "arc_transaction_evidence";
          const subject = observation.schemaVersion === "openarc.arc-account-snapshot.v1"
            ? observation.address
            : observation.transaction.hash;
          const failedAfter = failedReceipts.some((receipt) => {
            if (receipt.connectorId !== connector || receipt.approvedAt < record.updatedAt) return false;
            return observation.schemaVersion === "openarc.arc-account-snapshot.v1"
              ? receipt.connectorId === "arc_account_snapshot" && receipt.released.address === subject
              : receipt.connectorId === "arc_transaction_evidence" && receipt.released.transactionHash === subject;
          });
          const freshness = observationFreshness(record, failedAfter);
          const explorerPath = accountObservation ? `/address/${subject}` : `/tx/${subject}`;
          return <article key={record.recordId} className="activity-card">
            <div>
              <p className="eyebrow">{accountObservation ? "ACCOUNT SNAPSHOT" : "TRANSACTION EVIDENCE"}</p>
              <h3>{freshness}</h3>
              <ExactIdentifier label={accountObservation ? "Address" : "Transaction"} value={subject} />
            </div>
            <dl className="source-facts">
              <div><dt>Observed</dt><dd><time dateTime={observation.source.observedAt}>{observation.source.observedAt}</time></dd></div>
              <div><dt>Block</dt><dd>{observation.anchor.blockNumber}</dd></div>
              <div><dt>Block hash</dt><dd><code>{observation.anchor.blockHash}</code></dd></div>
              <div><dt>Finality</dt><dd>Deterministic · 1 inclusion</dd></div>
              {observation.schemaVersion === "openarc.arc-account-snapshot.v1" ? <>
                <div><dt>Native USDC</dt><dd>{observation.nativeUsdc.amount.decimal} USDC</dd></div>
                <div><dt>ERC-20 view</dt><dd>{observation.erc20UsdcView.amount.decimal} USDC · 6 decimals, truncating</dd></div>
              </> : <>
                <div><dt>Receipt</dt><dd>{observation.receipt.status}</dd></div>
                <div><dt>Fee</dt><dd>{observation.receipt.fee.decimal} USDC</dd></div>
                <div><dt>Canonical movements</dt><dd>{observation.coverage.canonicalMovements} ({observation.coverage.corroboratedMovements} ERC-20 corroborated)</dd></div>
              </>}
              <div><dt>Source</dt><dd><a href={`${ARC_TESTNET.explorerOrigin}${explorerPath}`} target="_blank" rel="noreferrer">Verify in Arc explorer ↗</a></dd></div>
            </dl>
            <details><summary>Limitations and source details</summary>
              <p><code>{observation.source.origin}</code> · adapter {observation.source.adapterVersion}</p>
              {observation.schemaVersion === "openarc.arc-transaction-evidence.v1" && observation.movements.length > 0
                ? <ol className="movement-list">{observation.movements.map((movement) =>
                  <li key={movement.logIndex}>
                    <strong>{movement.amount.decimal} USDC</strong>
                    <span>Canonical system log {movement.logIndex}: <code>{movement.from}</code> → <code>{movement.to}</code></span>
                    <span>{movement.erc20Corroboration
                      ? `ERC-20 log ${movement.erc20Corroboration.logIndex} corroborates this movement; it is not counted twice.`
                      : "No matching ERC-20 corroboration was present; the system event remains canonical."}</span>
                  </li>)}</ol>
                : null}
              <ul>{observation.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul>
            </details>
            <button type="button" disabled={props.busy} onClick={() => review(accountObservation ? "account" : "transaction", subject)}>Review permission to refresh</button>
          </article>;
        })}
      </div>
      {pending ? <Modal title={pending.kind === "account" ? "Allow this account observation?" : "Allow this transaction observation?"}
        onClose={() => setPending(null)}>
        <p>{pending.kind === "account"
          ? "Observe one public Arc Testnet address at one exact final block."
          : "Observe one public Arc Testnet transaction, receipt, anchor, fee, and USDC movement set."}</p>
        <dl className="permission-disclosure">
          <div><dt>OpenArc request</dt><dd><code>POST {pending.kind === "account" ? ARC_ACCOUNT_SNAPSHOT_PATH : ARC_TRANSACTION_EVIDENCE_PATH}</code></dd></div>
          <div><dt>Upstream source</dt><dd><code>{ARC_TESTNET.rpcHttp}</code></dd></div>
          <div><dt>Released fields</dt><dd><code>{ARC_TESTNET.caip2}</code> and <code>{pending.kind === "account" ? pending.request.address : pending.request.transactionHash}</code></dd></div>
          <div><dt>Credentials</dt><dd>Omitted; no cookies, wallet connection, private key, or account token</dd></div>
          <div><dt>OpenArc retention</dt><dd>{ARC_OBSERVATION_DISCLOSURE.openArcRetention}</dd></div>
          <div><dt>Provider handling</dt><dd>{ARC_OBSERVATION_DISCLOSURE.providerRetention}</dd></div>
          <div><dt>Network metadata</dt><dd>{ARC_OBSERVATION_DISCLOSURE.hostingMetadata}</dd></div>
        </dl>
        <p>The approval is encrypted first. If that save fails, no request is sent. A failed refresh never replaces prior evidence.</p>
        <div className="modal-actions"><button type="button" onClick={() => setPending(null)}>Cancel</button>
          <button className="button" type="button" disabled={props.busy} onClick={() => void approve()}>Approve and observe</button></div>
      </Modal> : null}
    </section>
  );
}

function observationFreshness(record: ArcObservationRecord, failedAfter: boolean): string {
  if (failedAfter) return "STALE · LAST REFRESH FAILED";
  const age = Date.now() - Date.parse(record.observation.source.observedAt);
  if (!Number.isFinite(age) || age > 60 * 60 * 1_000) return "STALE · SAVED EVIDENCE";
  if (age > 5 * 60 * 1_000) return "AGING · SAVED EVIDENCE";
  return "FRESH · SAVED EVIDENCE";
}

function SourcesPanel(props: Pick<Parameters<typeof WorkspaceViewPanel>[0], "workspace" | "busy" | "onCheckCapabilities" | "onOpenTour">) {
  const [confirming, setConfirming] = useState(false);
  const [capabilities, setCapabilities] = useState<CapabilitiesEnvelope | null>(null);
  const receipts = props.workspace.records
    .filter((record) => record.kind === "permission_receipt")
    .sort((left, right) => right.approvedAt.localeCompare(left.approvedAt));
  const confirm = async () => {
    setConfirming(false);
    const result = await props.onCheckCapabilities();
    if (result) setCapabilities(result);
  };
  return (
    <section className="workspace-section" aria-labelledby="sources-title">
      <SectionHeading eyebrow="CONSENTED NETWORK BOUNDARY" title="Sources" id="sources-title" onLearn={props.onOpenTour}>
        Nothing checks automatically. You choose when OpenArc may contact its own same-origin API, and an encrypted receipt is saved before the request leaves this tab.
      </SectionHeading>
      <div className="settings-grid sources-grid">
        <article className="settings-wide">
          <p className="eyebrow">OPENARC CAPABILITIES</p>
          <h3>Check what this build can connect to</h3>
          <p>This reads configuration metadata only. It releases no wallet, transaction, label, policy, note, prompt, or workspace field, and it contacts no Arc provider.</p>
          <button className="button" type="button" disabled={props.busy} onClick={() => setConfirming(true)}>Review permission and check</button>
        </article>
        <article>
          <h3>Latest accepted capability result</h3>
          {capabilities ? <dl className="source-facts">
            <div><dt>Network</dt><dd>{capabilities.data.network}</dd></div>
            <div><dt>Writes</dt><dd>{capabilities.data.writes ? "Enabled" : "Disabled"}</dd></div>
            <div><dt>Connectors</dt><dd>{capabilities.data.enabledConnectors.length}</dd></div>
            <div><dt>Build</dt><dd><code>{capabilities.meta.buildSha}</code></dd></div>
          </dl> : <p>No accepted result in this unlocked session. Results are displayed only after strict schema validation.</p>}
        </article>
        <article>
          <h3>Encrypted permission history</h3>
          <p>{receipts.length === 0 ? "No network permissions have been approved in this workspace." : `${receipts.length} encrypted receipt${receipts.length === 1 ? "" : "s"} stored locally.`}</p>
          {receipts[0] ? <p>Latest: <strong>{receipts[0].outcome}</strong> at <time dateTime={receipts[0].updatedAt}>{receipts[0].updatedAt}</time>{receipts[0].failureCode ? ` · ${receipts[0].failureCode}` : ""}</p> : null}
        </article>
      </div>
      {confirming ? <Modal title="Allow this capability check?" onClose={() => setConfirming(false)}>
        <p>{CAPABILITY_DISCLOSURE.purpose}</p>
        <dl className="permission-disclosure">
          <div><dt>Destination</dt><dd>This OpenArc site at <code>{window.location.origin}</code></dd></div>
          <div><dt>Request</dt><dd><code>GET {CAPABILITIES_PATH}</code></dd></div>
          <div><dt>Released workspace fields</dt><dd>None</dd></div>
          <div><dt>Credentials</dt><dd>Omitted; no cookies or account token</dd></div>
          <div><dt>Upstream providers</dt><dd>None</dd></div>
          <div><dt>OpenArc retention</dt><dd>{CAPABILITY_DISCLOSURE.openArcRetention}</dd></div>
          <div><dt>Provider retention</dt><dd>{CAPABILITY_DISCLOSURE.providerRetention}</dd></div>
          <div><dt>Hosting metadata</dt><dd>{CAPABILITY_DISCLOSURE.hostingMetadata}</dd></div>
        </dl>
        <p>The approval is encrypted into this workspace first. If that local save fails, no request is sent.</p>
        <div className="modal-actions"><button type="button" onClick={() => setConfirming(false)}>Cancel</button><button className="button" type="button" onClick={() => void confirm()}>Approve and check</button></div>
      </Modal> : null}
    </section>
  );
}

function SettingsPanel(props: Omit<Parameters<typeof WorkspaceViewPanel>[0], "view">) {
  const [backupPassphrase, setBackupPassphrase] = useState("");
  const [currentPassphrase, setCurrentPassphrase] = useState("");
  const [nextPassphrase, setNextPassphrase] = useState("");
  const [nextPassphraseConfirmation, setNextPassphraseConfirmation] = useState("");
  const [importPassphrase, setImportPassphrase] = useState("");
  const [importNewPassphrase, setImportNewPassphrase] = useState("");
  const [importNewConfirmation, setImportNewConfirmation] = useState("");
  const [importFile, setImportFile] = useState<File | null>(null);
  const [storage, setStorage] = useState<VaultStorageStatus | null>(null);
  const [deleteConfirmed, setDeleteConfirmed] = useState(false);
  useEffect(() => { void readStorageStatus().then(setStorage).catch(() => setStorage(null)); }, []);

  const exportBackup = async () => {
    const guard = props.createSessionGuard();
    props.setBusy(true);
    props.setError(null);
    try {
      const backup = await exportLocalWorkspace(props.workspace, backupPassphrase);
      guard.assertActive();
      downloadJson(backup, `openarc-workspace-${new Date().toISOString().slice(0, 10)}.openarc`);
      setBackupPassphrase("");
      props.setBusy(false);
      props.setNotice("Encrypted logical backup downloaded. It requires its separate backup passphrase.");
    } catch (cause) {
      if (!guard.isActive()) return;
      if (await props.onOperationError(cause, guard.isActive)) return;
      if (!guard.isActive()) return;
      props.setBusy(false);
      props.setError(vaultErrorMessage(cause));
    }
  };

  const exportRescue = async () => {
    const guard = props.createSessionGuard();
    props.setBusy(true);
    props.setError(null);
    try {
      const rescue = await exportOpaqueRescue();
      guard.assertActive();
      downloadJson(rescue, `openarc-opaque-rescue-${new Date().toISOString().slice(0, 10)}.json`);
      props.setBusy(false);
      props.setNotice("Opaque encrypted rescue downloaded. This build cannot import it; keep it for diagnostics or future recovery tooling.");
    } catch (cause) {
      if (!guard.isActive()) return;
      if (await props.onOperationError(cause, guard.isActive)) return;
      if (!guard.isActive()) return;
      props.setBusy(false);
      props.setError(vaultErrorMessage(cause));
    }
  };

  const changePassphrase = async () => {
    const guard = props.createSessionGuard();
    props.setBusy(true);
    props.setError(null);
    try {
      const updated = await updateWorkspacePassphrase(
        props.workspace,
        currentPassphrase,
        nextPassphrase,
        guard.assertActive,
        guard.signal,
      );
      guard.assertActive();
      props.broadcast("changed", updated.meta.vaultId);
      props.onAcceptCreated({ ...updated, recoverySecret: "" }, "Workspace passphrase changed. Existing backups still require their own backup passphrases.");
      setCurrentPassphrase("");
      setNextPassphrase("");
      setNextPassphraseConfirmation("");
    } catch (cause) {
      if (!guard.isActive()) return;
      if (await props.onOperationError(cause, guard.isActive)) return;
      if (!guard.isActive()) return;
      props.setBusy(false);
      props.setError(vaultErrorMessage(cause));
    }
  };

  return (
    <section className="workspace-section" aria-labelledby="settings-title">
      <SectionHeading eyebrow="LOCAL CUSTODY" title="Settings" id="settings-title" onLearn={props.onOpenTour}>Manage browser storage, export a portable encrypted backup, rotate the passphrase, or permanently delete this origin-bound workspace.</SectionHeading>
      <div className="settings-grid">
        <article><h3>Encrypted backup</h3><p>A separate password encrypts validated logical records. It does not reuse or contain the local Vault wrappers.</p><Field label="Backup passphrase"><input type="password" minLength={12} maxLength={128} value={backupPassphrase} onChange={(event) => setBackupPassphrase(event.target.value)} /></Field><button className="button" type="button" disabled={props.busy || backupPassphrase.length < 12} onClick={() => void exportBackup()}>Download encrypted backup</button></article>
        <article><h3>Replace from backup</h3><p>Import verifies the whole file, then creates fresh local keys, revisions, IVs, and a new recovery secret.</p><Field label="Backup file"><input type="file" accept="application/json,.openarc" onChange={(event) => setImportFile(event.target.files?.[0] ?? null)} /></Field><Field label="Backup passphrase"><input type="password" minLength={12} maxLength={128} value={importPassphrase} onChange={(event) => setImportPassphrase(event.target.value)} /></Field><Field label="New local passphrase"><input type="password" minLength={12} maxLength={128} value={importNewPassphrase} onChange={(event) => setImportNewPassphrase(event.target.value)} /></Field><Field label="Confirm new local passphrase"><input type="password" minLength={12} maxLength={128} value={importNewConfirmation} onChange={(event) => setImportNewConfirmation(event.target.value)} /></Field><button className="button" type="button" disabled={props.busy || !importFile || importPassphrase.length < 12 || importNewPassphrase.length < 12 || importNewConfirmation !== importNewPassphrase} onClick={() => { if (importFile) void props.onImport(importFile, importPassphrase, importNewPassphrase); }}>Replace after verification</button></article>
        <article><h3>Change local passphrase</h3><p>This rotates only the local passphrase wrapper after authenticating every encrypted record.</p><Field label="Current passphrase"><input type="password" minLength={12} maxLength={128} value={currentPassphrase} onChange={(event) => setCurrentPassphrase(event.target.value)} /></Field><Field label="New passphrase"><input type="password" minLength={12} maxLength={128} value={nextPassphrase} onChange={(event) => setNextPassphrase(event.target.value)} /></Field><Field label="Confirm new passphrase"><input type="password" minLength={12} maxLength={128} value={nextPassphraseConfirmation} onChange={(event) => setNextPassphraseConfirmation(event.target.value)} /></Field><button className="button" type="button" disabled={props.busy || currentPassphrase.length < 12 || nextPassphrase.length < 12 || nextPassphraseConfirmation !== nextPassphrase} onClick={() => void changePassphrase()}>Change passphrase</button></article>
        <article><h3>Browser storage</h3><p>{storage ? `Usage ${formatBytes(storage.usage)} of ${formatBytes(storage.quota)}. Persistence ${storage.persistent === true ? "granted" : storage.persistent === false ? "not granted" : "not reported"}.` : "Storage estimate unavailable."}</p><button type="button" onClick={() => void requestPersistentStorage().then(setStorage)}>Request persistent storage</button><button type="button" onClick={(event) => props.onOpenTour(event.currentTarget)}>Open workspace tour</button><button type="button" onClick={() => void exportRescue()}>Export opaque rescue</button></article>
        <article className="settings-wide"><h3>What local encryption does—and does not—protect</h3><p>Encryption protects private records at rest from casual IndexedDB or backup inspection and authenticates record contents. It does not protect an unlocked tab, XSS or hostile future same-origin code, browser extensions, a compromised browser, operating system, or device, screen or clipboard capture, JavaScript heap recovery, deliberate storage clearing, whole-database rollback, or availability.</p><p>Public metadata can reveal that a workspace exists, format and KDF versions, approximate record count, ciphertext and file sizes, and access/write timing. Weak passwords remain vulnerable to offline guessing even though the KDF raises the cost.</p><div className="row-actions"><a href="/#fixture-explorer">Read the evidence guide</a><a href="/#network">Review the pinned network registry</a></div></article>
        <article className="danger-panel"><h3>Delete workspace</h3><p>Deletion is permanent for this browser and removes encrypted records, metadata, and wrappers. A blocked request stays pending and non-interactive.</p><label className="confirm-row"><input type="checkbox" checked={deleteConfirmed} onChange={(event) => setDeleteConfirmed(event.target.checked)} /> I understand this cannot be undone without a backup.</label><button className="button button-danger" type="button" disabled={props.busy || !deleteConfirmed} onClick={() => void props.onDestroy()}>Permanently delete</button></article>
      </div>
    </section>
  );
}

function AgentDialog({ existing, busy, onClose, onSave }: { existing: AgentProfileRecord | null; busy: boolean; onClose: () => void; onSave: (draft: AgentProfileDraft) => Promise<boolean> }) {
  const [draft, setDraft] = useState<AgentProfileDraft>({ displayName: existing?.displayName ?? "", walletAddress: existing?.wallets[0]?.address ?? "", frameworkLabel: existing?.frameworkLabel ?? "", purposeNote: existing?.purposeNote ?? "" });
  const [validationError, setValidationError] = useState<string | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setValidationError(null);
    try {
      if (!(await onSave(draft))) {
        setValidationError("OpenArc could not save this encrypted profile. Nothing changed. Close this dialog to review the local storage or revision-conflict details.");
      }
    } catch {
      setValidationError("Check the profile fields. The display name must contain visible text, and optional values must match the stated formats and limits.");
    }
  };
  return <Modal title={existing ? "Edit agent profile" : "Add agent profile"} onClose={onClose}><form className="workspace-form" onChange={() => setValidationError(null)} onSubmit={(event) => void submit(event)}>{validationError ? <DialogValidationError message={validationError} /> : null}<Field label="Display name"><input required maxLength={80} value={draft.displayName} onChange={(event) => setDraft({ ...draft, displayName: event.target.value })} /></Field><Field label="Arc Testnet wallet (optional)" hint="Owner-supplied association; not proof of identity."><input pattern="0x[0-9a-fA-F]{40}" value={draft.walletAddress} onChange={(event) => setDraft({ ...draft, walletAddress: event.target.value })} /></Field><Field label="Framework label (optional)"><input maxLength={80} value={draft.frameworkLabel} onChange={(event) => setDraft({ ...draft, frameworkLabel: event.target.value })} /></Field><Field label="Purpose note (optional)"><textarea maxLength={500} value={draft.purposeNote} onChange={(event) => setDraft({ ...draft, purposeNote: event.target.value })} /></Field><div className="modal-actions"><button type="button" onClick={onClose}>Cancel</button><button className="button" disabled={busy}>Encrypt and save</button></div></form></Modal>;
}

function PolicyDialog({ existing, busy, onClose, onSave }: { existing: MonitoringPolicyRecord | null; busy: boolean; onClose: () => void; onSave: (draft: MonitoringPolicyDraft) => Promise<boolean> }) {
  const [draft, setDraft] = useState<MonitoringPolicyDraft>({ label: existing?.policy.label ?? "", maximumAmountBaseUnits: existing?.policy.maximumAmountBaseUnits ?? "0", allowedRecipient: existing?.policy.allowedRecipients[0] ?? "", expiresAt: existing?.policy.expiresAt ?? "" });
  const [validationError, setValidationError] = useState<string | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setValidationError(null);
    try {
      if (!(await onSave(draft))) {
        setValidationError("OpenArc could not save this encrypted policy. Nothing changed. Close this dialog to review the local storage or revision-conflict details.");
      }
    } catch {
      setValidationError("Check the policy fields. Use a visible label, a whole-number amount, an optional Arc Testnet address, and an optional UTC timestamp ending in Z.");
    }
  };
  return <Modal title={existing ? "Edit monitoring policy" : "Add monitoring policy"} onClose={onClose}><form className="workspace-form" onChange={() => setValidationError(null)} onSubmit={(event) => void submit(event)}>{validationError ? <DialogValidationError message={validationError} /> : null}<Field label="Policy label"><input required maxLength={100} value={draft.label} onChange={(event) => setDraft({ ...draft, label: event.target.value })} /></Field><Field label="Maximum amount (base units)"><input required inputMode="numeric" pattern="[0-9]+" value={draft.maximumAmountBaseUnits} onChange={(event) => setDraft({ ...draft, maximumAmountBaseUnits: event.target.value })} /></Field><Field label="Allowed recipient (optional)"><input pattern="0x[0-9a-fA-F]{40}" value={draft.allowedRecipient} onChange={(event) => setDraft({ ...draft, allowedRecipient: event.target.value })} /></Field><Field label="Expiry (UTC ISO timestamp, optional)" hint="Example: 2026-09-16T12:00:00Z"><input value={draft.expiresAt} onChange={(event) => setDraft({ ...draft, expiresAt: event.target.value })} /></Field><div className="modal-actions"><button type="button" onClick={onClose}>Cancel</button><button className="button" disabled={busy}>Encrypt and save</button></div></form></Modal>;
}

function DialogValidationError({ message }: { message: string }) {
  const errorRef = useRef<HTMLParagraphElement>(null);
  useEffect(() => {
    errorRef.current?.focus();
  }, []);
  return <p ref={errorRef} className="workspace-error" role="alert" tabIndex={-1}>{message}</p>;
}

function RecoveryDialog({ secret, onClose }: { secret: string; onClose: () => void }) {
  const [confirmed, setConfirmed] = useState(false);
  const [copyStatus, setCopyStatus] = useState("");
  const copy = async () => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(secret);
      setCopyStatus("Recovery secret copied locally.");
    } catch {
      setCopyStatus("Copy is unavailable in this browser. Nothing was sent. Select and copy the recovery secret manually.");
    }
  };
  return <Modal title="Save this recovery secret now" onClose={() => { if (confirmed) onClose(); }} closeDisabled={!confirmed}><p>This is shown once. It can rotate the local passphrase and recovery wrapper, but it cannot decrypt a separately password-protected backup.</p><code className="recovery-secret" data-testid="recovery-secret">{secret}</code><button type="button" onClick={() => void copy()}>Copy recovery secret</button><small role="status">{copyStatus}</small><label className="confirm-row"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /> I saved it somewhere private.</label><button className="button" type="button" disabled={!confirmed} onClick={onClose}>Continue to workspace</button></Modal>;
}

function TourDialog({ onClose, returnFocus }: { onClose: () => void; returnFocus: HTMLElement | null }) {
  const [step, setStep] = useState(0);
  const steps = [
    ["What OpenArc can prove", "OpenArc can reconcile cited evidence and expose agreement, conflict, or missing facts. An owner label, attempted action, or fixture is never treated as proof of identity or settlement."],
    ["Where private data lives", "Your browser encrypts every workspace record before IndexedDB persistence. The API retains no request or response body, and reload always begins locked."],
    ["Add an agent wallet label", "Use Agents to attach an owner-supplied Arc Testnet address and optional context. The label organizes local records; it does not authenticate ownership."],
    ["Permission before every refresh", "When Activity is enabled in this build, it shows the exact OpenArc route, Arc RPC upstream, and public identifier before contact. The encrypted approval must save first, and nothing refreshes on unlock, navigation, focus, or a timer."],
    ["Read evidence and incomplete states", "Intent, attempt, authorization, fulfillment, settlement, and refund stay distinct. Missing or conflicting evidence remains visible instead of being guessed away."],
    ["Lock, export, recover, and delete", "Lock clears decrypted UI state. Backups use a separate password, recovery rotates local wrappers, and Settings can permanently delete this origin-bound workspace."],
  ] as const;
  return <Modal title={steps[step]![0]} onClose={onClose} returnFocus={returnFocus}><p className="tour-count">STEP {step + 1} OF {steps.length}</p><p>{steps[step]![1]}</p><div className="tour-dots" aria-label={`Tour step ${step + 1} of ${steps.length}`}>{steps.map((_, index) => <span key={index} className={index === step ? "active" : ""} />)}</div><div className="modal-actions">{step > 0 ? <button type="button" onClick={() => setStep(step - 1)}>Back</button> : <button type="button" onClick={onClose}>Skip</button>}<button className="button" type="button" onClick={() => { if (step === steps.length - 1) onClose(); else setStep(step + 1); }}>{step === steps.length - 1 ? "Open workspace" : "Next"}</button></div></Modal>;
}

export function Modal({ title, children, onClose, closeDisabled = false, returnFocus: explicitReturnFocus = null }: { title: string; children: ReactNode; onClose: () => void; closeDisabled?: boolean; returnFocus?: HTMLElement | null }) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const closeRef = useRef(onClose);
  const closeDisabledRef = useRef(closeDisabled);
  useEffect(() => {
    closeRef.current = onClose;
    closeDisabledRef.current = closeDisabled;
  }, [closeDisabled, onClose]);
  useEffect(() => {
    returnFocus.current = explicitReturnFocus ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    const background = document.querySelector<HTMLElement>(".workspace-shell");
    const previousAriaHidden = background?.getAttribute("aria-hidden") ?? null;
    if (background) {
      background.inert = true;
      background.setAttribute("aria-hidden", "true");
    }
    const dialog = dialogRef.current;
    dialog?.querySelector<HTMLElement>("button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])")?.focus();
    const keyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !closeDisabledRef.current) { event.preventDefault(); closeRef.current(); return; }
      if (event.key !== "Tab" || !dialog) return;
      const items = [...dialog.querySelectorAll<HTMLElement>("button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href]")];
      if (items.length === 0) return;
      const first = items[0]!;
      const last = items.at(-1)!;
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", keyDown);
    return () => {
      document.removeEventListener("keydown", keyDown);
      if (background) {
        background.inert = false;
        if (previousAriaHidden === null) background.removeAttribute("aria-hidden");
        else background.setAttribute("aria-hidden", previousAriaHidden);
      }
      const target = returnFocus.current;
      if (target?.isConnected) target.focus();
    };
  }, [explicitReturnFocus]);
  return createPortal(<div className="modal-backdrop" role="presentation"><div className="workspace-modal" role="dialog" aria-modal="true" aria-labelledby="workspace-dialog-title" ref={dialogRef}><header><p className="eyebrow">PRIVATE WORKSPACE</p><h2 id="workspace-dialog-title">{title}</h2>{!closeDisabled ? <button type="button" aria-label="Close dialog" onClick={onClose}>×</button> : null}</header>{children}</div></div>, document.body);
}

function WorkspaceGate({ title, build, children }: { title: string; build: BuildInfo; children: ReactNode }) {
  return <main className="workspace-gate"><a className="workspace-brand" href="/"><img src="/openarc-logo.jpeg" alt="" /><span><strong>OPENARC</strong><small>ENCRYPTED WORKSPACE</small></span></a><section><p className="eyebrow">LOCAL FIRST · NO ACCOUNT · NO NETWORK</p><h1>{title}</h1>{children}</section><footer><a href="/">← Back to evidence engine</a><code data-testid="build-sha">BUILD {build.commitSha}</code></footer></main>;
}

function WorkspaceWait({ label }: { label: string }) {
  return <main className="workspace-wait"><img src="/openarc-logo.jpeg" alt="" /><div className="workspace-spinner" aria-hidden="true" /><p role="status">{label}</p></main>;
}

export function SectionHeading({ eyebrow, title, id, children, onLearn }: { eyebrow: string; title: string; id: string; children: ReactNode; onLearn: (target: HTMLElement) => void }) {
  const usesNetwork = workspaceSectionUsesNetwork(id, { apiBoundary: API_BOUNDARY_ENABLED,
    arcObservation: ARC_OBSERVATION_ENABLED, agentRegistry: AGENT_REGISTRY_ENABLED, agentJobs: AGENT_JOBS_ENABLED,
    gatewayEvidence: GATEWAY_EVIDENCE_ENABLED });
  return <header className="workspace-section-heading"><div><p className="eyebrow">{eyebrow}</p><div className="workspace-title-row"><h1 id={id}>{title}</h1><details className="workspace-info"><summary role="button" aria-label={`About ${title}`} title={`About ${title}`}>i</summary><p>{children}</p></details></div></div><div className="workspace-heading-context"><p>{children}</p><div><span className="workspace-view-status">{usesNetwork ? "EXPLICIT READ-ONLY LOOKUPS" : "ENABLED · LOCAL ONLY"}</span><a href="#workspace-tour" onClick={(event) => { event.preventDefault(); onLearn(event.currentTarget); }}>Learn how this works</a></div></div></header>;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <label className="field"><span>{label}</span>{children}{hint ? <small>{hint}</small> : null}</label>;
}

function ExactIdentifier({ label, value }: { label: string; value: string }) {
  const [copyStatus, setCopyStatus] = useState("");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopyStatus("Copied locally.");
    } catch {
      setCopyStatus("Copy is unavailable in this browser. Nothing was sent.");
    }
  };
  return <div className="exact-identifier"><span>{label}</span><code>{value}</code><button type="button" aria-label={`Copy ${label}`} onClick={() => void copy()}>Copy</button><small role="status">{copyStatus}</small></div>;
}

function Stat({ value, label }: { value: number; label: string }) {
  return <article><strong>{value}</strong><span>{label}</span></article>;
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return <div className="workspace-empty"><h3>{title}</h3><p>{body}</p></div>;
}

function recordCounts(records: readonly WorkspaceRecord[]) {
  return {
    agents: records.filter((record) => record.kind === "agent_profile").length,
    policies: records.filter((record) => record.kind === "monitoring_policy" || record.kind === "agent_monitoring_policy").length,
    agentReports: records.filter((record) => record.kind === "agent_import").length,
    actions: records.filter((record) => record.kind === "action_envelope").length,
    evidence: records.filter((record) => record.kind === "evidence_record").length,
    observations: records.filter((record) => record.kind === "arc_observation").length,
    registryObservations: records.filter((record) => record.kind === "agent_registry_observation").length,
    jobObservations: records.filter((record) => record.kind === "job_observation").length,
  };
}

function viewFromLocation(): WorkspaceView {
  const value = new URLSearchParams(window.location.search).get("view");
  return VIEWS.some((item) => item.id === value) ? (value as WorkspaceView) : "overview";
}

function downloadJson(value: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(value)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function formatBytes(value: number | null): string {
  if (value === null) return "not reported";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 / 1024).toFixed(1)} MiB`;
}
