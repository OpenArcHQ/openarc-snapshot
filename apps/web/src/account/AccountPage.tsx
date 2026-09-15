import {
  AccountEmptyRequestSchema,
  AccountPasskeyAddVerifyRequestSchema,
  AccountPasskeyAuthenticationOptionsResponseSchema,
  AccountPasskeyLoginVerifyRequestSchema,
  AccountPasskeyRegistrationOptionsResponseSchema,
  AccountPasskeyRegisterVerifyRequestSchema,
  AccountRegisterOptionsRequestSchema,
  AccountRecoveryCodesResponseSchema,
  AccountRecoveryRedeemRequestSchema,
  AccountSessionResponseSchema,
  AccountWalletAddressRequestSchema,
  AccountWalletOptionsResponseSchema,
  AccountWalletVerifyRequestSchema,
  type AccountSessionView,
} from "@openarc/shared";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  VAULT_LOCK_ATTENTION_NOTICE,
  VaultSessionEndWatcher,
  vaultLockNeedsAttention,
} from "../app/vault-session-lock.js";
import { accountAccessEnabled } from "./availability.js";
import { logoutFailureLocksVault } from "./logout-vault-lock.js";
import {
  ACCOUNT_API_PATHS,
  AccountApiError,
  requestAccount,
} from "./auth-client.js";
import { createConfirmation, type PendingConfirmation } from "./confirmation.js";
import { AccountFlowController, type AccountBoundToken } from "./flow-controller.js";
import { ACCOUNT_NOTICES, type AccountNotice, noticeForApiFailure } from "./messages.js";
import {
  EMPTY_RECOVERY_DISPLAY,
  RecoveryDisplayGuard,
  type RecoveryDisplay,
} from "./recovery.js";
import {
  accountIdOf,
  AccountSessionEnvelopeDataSchema,
  initialAccountState,
  type AccountSessionState,
} from "./session-store.js";
import {
  beginPasskeyAuthentication,
  beginPasskeyRegistration,
  cancelPasskeyCeremony,
  PasskeyCeremonyError,
} from "./webauthn.js";
import {
  assertWalletMessage,
  injectedProvider,
  isWalletCancelled,
  openWalletSession,
  personalSign,
  WalletError,
} from "./wallet-provider.js";

import "./account.css";

type WalletConfirmValue = { flowId: string; message: string; address: string };

const EMPTY_STATE = initialAccountState();

function methodLabel(method: "passkey" | "wallet" | "recovery"): string {
  if (method === "wallet") return "Wallet";
  if (method === "recovery") return "Recovery code";
  return "Passkey";
}

export default function AccountPage() {
  const enabled = useMemo(() => accountAccessEnabled(), []);
  const [state, setState] = useState<AccountSessionState>(EMPTY_STATE);
  const [notice, setNotice] = useState<AccountNotice | null>(null);
  const [busy, setBusy] = useState(false);
  const [minimalAccepted, setMinimalAccepted] = useState(false);
  const [recovery, setRecovery] = useState<RecoveryDisplay>(EMPTY_RECOVERY_DISPLAY);
  const [redeemCode, setRedeemCode] = useState("");
  const [walletConfirm, setWalletConfirm] = useState<WalletConfirmValue | null>(null);
  const [replacePending, setReplacePending] = useState(false);
  const [vaultLockNotice, setVaultLockNotice] = useState<string | null>(null);

  // Logout, account change and detected expiry lock the local Vault in every
  // tab (R55, P08-02). The watcher holds no Vault code; it lazy-loads it.
  const vaultWatcherRef = useRef<VaultSessionEndWatcher | null>(null);
  if (vaultWatcherRef.current === null) {
    vaultWatcherRef.current = new VaultSessionEndWatcher({
      onStatus: (status) => setVaultLockNotice(vaultLockNeedsAttention(status) ? VAULT_LOCK_ATTENTION_NOTICE : null),
    });
  }

  const controllerRef = useRef<AccountFlowController | null>(null);
  const confirmationRef = useRef<PendingConfirmation<WalletConfirmValue> | null>(null);
  const recoveryGuardRef = useRef<RecoveryDisplayGuard | null>(null);
  // The account identity that the currently displayed recovery codes belong
  // to. `undefined` means no authoritative session has been observed yet, so
  // the first read never spuriously clears a fresh result.
  const identityRef = useRef<string | null | undefined>(undefined);

  const clearRecovery = useCallback(() => {
    const guard = recoveryGuardRef.current;
    setRecovery(guard === null ? EMPTY_RECOVERY_DISPLAY : guard.clear());
    confirmationRef.current?.cancel();
    confirmationRef.current = null;
    setWalletConfirm(null);
  }, []);

  // Every authoritative session transition flows through here. When the
  // identity changes or becomes a guest, sensitive recovery state is
  // invalidated and cleared immediately (covering read refresh, adopt and
  // bootstrap alike). A same-account CSRF rotation does not clear, so an
  // ordinary bootstrap cannot suppress a freshly requested code result.
  const handleState = useCallback((next: AccountSessionState) => {
    const nextIdentity = accountIdOf(next.session);
    const previousIdentity = identityRef.current;
    if (previousIdentity !== undefined && previousIdentity !== nextIdentity) {
      const guard = recoveryGuardRef.current;
      setRecovery(guard === null ? EMPTY_RECOVERY_DISPLAY : guard.clear());
      setReplacePending(false);
      confirmationRef.current?.cancel();
      confirmationRef.current = null;
      setWalletConfirm(null);
    }
    identityRef.current = nextIdentity;
    void vaultWatcherRef.current?.observe(nextIdentity);
    setState(next);
  }, []);

  if (enabled && controllerRef.current === null) {
    controllerRef.current = new AccountFlowController({ onState: handleState });
  }
  if (enabled && recoveryGuardRef.current === null) {
    recoveryGuardRef.current = new RecoveryDisplayGuard();
  }

  // Manual Hide must also invalidate any in-flight replacement response.
  const hideRecovery = useCallback(() => {
    const guard = recoveryGuardRef.current;
    setRecovery(guard === null ? EMPTY_RECOVERY_DISPLAY : guard.clear());
  }, []);

  const mapError = useCallback((error: unknown, freshHint = false): AccountNotice => {
    if (error instanceof AccountApiError) {
      const mapped = noticeForApiFailure(error.failure);
      return freshHint && mapped.needsFreshSession
        ? { ...mapped, message: ACCOUNT_NOTICES.freshSessionRequired }
        : mapped;
    }
    if (error instanceof PasskeyCeremonyError) {
      if (error.failure === "cancelled") {
        return { tone: "info", message: "Passkey prompt was cancelled.", needsFreshSession: false };
      }
      if (error.failure === "unsupported") {
        return { tone: "warning", message: "This browser does not support passkeys. Nothing was created.", needsFreshSession: false };
      }
      return { tone: "error", message: "The passkey response could not be verified. Nothing was changed.", needsFreshSession: false };
    }
    if (error instanceof WalletError) {
      if (error.failure === "no-provider") {
        return { tone: "warning", message: "No browser wallet was found. Install or enable one to continue.", needsFreshSession: false };
      }
      if (error.failure === "rejected") {
        return { tone: "info", message: "The wallet request was declined. Nothing was signed in.", needsFreshSession: false };
      }
      if (error.failure === "wrong-chain") {
        return { tone: "warning", message: "Your wallet is not on Arc Testnet. Switch networks there, then try again.", needsFreshSession: false };
      }
      if (error.failure === "no-account") {
        return { tone: "warning", message: "No wallet account was available.", needsFreshSession: false };
      }
      if (error.failure === "invalid-message") {
        return { tone: "error", message: "The sign-in message did not match the expected contract. Nothing was signed.", needsFreshSession: false };
      }
      return { tone: "warning", message: "The wallet account or network changed. Start again.", needsFreshSession: false };
    }
    return { tone: "error", message: "Something unexpected happened, and the outcome is unknown. Refresh your session before retrying.", needsFreshSession: false };
  }, []);

  const refreshSession = useCallback(async () => {
    const controller = controllerRef.current;
    if (!enabled || controller === null) return;
    try {
      await controller.refreshSession();
    } catch (error) {
      if (error instanceof AccountApiError && error.failure.kind === "aborted") return;
      setNotice(mapError(error));
    }
  }, [enabled, mapError]);

  useEffect(() => {
    if (!enabled) return;
    // Navigation/hide must also abort an in-flight WebAuthn ceremony, which
    // rejects the SDK promise and surfaces an honest cancellation.
    const onHide = () => {
      clearRecovery();
      cancelPasskeyCeremony();
    };
    const onVisibility = () => {
      if (document.visibilityState === "hidden") {
        clearRecovery();
        cancelPasskeyCeremony();
      }
    };
    const onPageHide = () => {
      clearRecovery();
      cancelPasskeyCeremony();
    };
    window.addEventListener("pagehide", onPageHide);
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("popstate", onHide);
    vaultWatcherRef.current?.resume();
    void refreshSession();
    return () => {
      window.removeEventListener("pagehide", onPageHide);
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("popstate", onHide);
      cancelPasskeyCeremony();
      clearRecovery();
      // Unmount is not a session end: stop observing before the local reset.
      vaultWatcherRef.current?.dispose();
      controllerRef.current?.reset();
    };
  }, [enabled, clearRecovery, refreshSession]);

  const runMutation = useCallback(
    async <T,>(
      work: (context: {
        csrfToken: string;
        signal: AbortSignal;
        adopt: (data: unknown) => void;
        isCurrent: () => boolean;
      }) => Promise<T>,
      options: {
        freshHint?: boolean;
        accountBound?: AccountBoundToken;
        unknownNotice?: string;
      } = {},
    ): Promise<T | null> => {
      const controller = controllerRef.current;
      if (controller === null) return null;
      const generation = controller.generation;
      let operationSignal: AbortSignal | undefined;
      const isCurrent = (): boolean =>
        controller.generation === generation &&
        !(operationSignal?.aborted ?? false);
      setBusy(true);
      setNotice(null);
      try {
        const result = await controller.mutate(async ({ csrfToken, signal, adopt: adoptBound }) => {
          operationSignal = signal;
          const adopt = (data: unknown) => {
            const parsed = AccountSessionResponseSchema.safeParse(data);
            if (parsed.success) {
              // Guarded at the exact moment of application: a stale operation
              // that resolves after a reset/cancel never adopts.
              adoptBound(parsed.data);
            }
          };
          return work({ csrfToken, signal, adopt, isCurrent });
        }, options.accountBound === undefined ? {} : { accountBound: options.accountBound });
        return result;
      } catch (error) {
        if (!isCurrent()) {
          // A superseded operation must not surface a notice; its successor
          // owns the notice/busy state.
          if (error instanceof AccountApiError && error.failure.kind === "aborted") {
            return null;
          }
          return null;
        }
        if (error instanceof AccountApiError && error.failure.kind === "aborted") {
          // A superseded/aborted flow writes no notice or state.
          return null;
        }
        if (error instanceof AccountApiError && error.failure.kind === "account-changed") {
          // Synchronize the displayed account to the actual session and clear
          // sensitive state; a new explicit action is required.
          clearRecovery();
          setReplacePending(false);
        }
        if (
          options.unknownNotice !== undefined &&
          error instanceof AccountApiError &&
          error.failure.kind === "outcome-unknown"
        ) {
          setNotice({ tone: "warning", message: options.unknownNotice, needsFreshSession: false });
          return null;
        }
        setNotice(mapError(error, options.freshHint ?? false));
        return null;
      } finally {
        if (isCurrent()) setBusy(false);
      }
    },
    [clearRecovery, mapError],
  );

  const postJson = useCallback(
    <T,>(input: {
      path: (typeof ACCOUNT_API_PATHS)[keyof typeof ACCOUNT_API_PATHS];
      requestSchema: Parameters<typeof requestAccount>[0]["requestSchema"];
      responseSchema: Parameters<typeof requestAccount>[0]["responseSchema"];
      body?: unknown;
      csrfToken: string;
      signal: AbortSignal;
    }) =>
      requestAccount({
        path: input.path,
        method: "POST",
        requestSchema: input.requestSchema,
        responseSchema: input.responseSchema,
        ...(input.body === undefined ? {} : { body: input.body }),
        csrfToken: input.csrfToken,
        signal: input.signal,
      } as Parameters<typeof requestAccount>[0]) as Promise<T>,
    [],
  );

  /** Fresh bootstrap + intended-account capture for account-bound actions. */
  const accountBound = useCallback((): AccountBoundToken | undefined => {
    return controllerRef.current?.captureAccountBound();
  }, []);

  const createPasskey = useCallback(async () => {
    if (!minimalAccepted) {
      setNotice({ tone: "warning", message: "Confirm the minimal-record notice before creating an account.", needsFreshSession: false });
      return;
    }
    await runMutation(async ({ csrfToken, signal, adopt, isCurrent }) => {
      const options = await postJson<{
        flowId: string;
        options: Parameters<typeof beginPasskeyRegistration>[0];
      }>({
        path: ACCOUNT_API_PATHS.registerOptions,
        requestSchema: AccountRegisterOptionsRequestSchema,
        responseSchema: AccountPasskeyRegistrationOptionsResponseSchema,
        body: { acceptMinimalRecords: true as const },
        csrfToken,
        signal,
      });
      const response = await beginPasskeyRegistration(options.options);
      const session = await postJson<unknown>({
        path: ACCOUNT_API_PATHS.registerVerify,
        requestSchema: AccountPasskeyRegisterVerifyRequestSchema,
        responseSchema: AccountSessionResponseSchema,
        body: { flowId: options.flowId, response },
        csrfToken,
        signal,
      });
      adopt(session);
      if (isCurrent()) {
        setNotice({ tone: "info", message: "Passkey created. You are signed in.", needsFreshSession: false });
      }
    });
  }, [minimalAccepted, postJson, runMutation]);

  const signInPasskey = useCallback(async () => {
    await runMutation(async ({ csrfToken, signal, adopt, isCurrent }) => {
      const options = await postJson<{
        flowId: string;
        options: Parameters<typeof beginPasskeyAuthentication>[0];
      }>({
        path: ACCOUNT_API_PATHS.loginOptions,
        requestSchema: AccountEmptyRequestSchema,
        responseSchema: AccountPasskeyAuthenticationOptionsResponseSchema,
        body: {},
        csrfToken,
        signal,
      });
      const response = await beginPasskeyAuthentication(options.options);
      const session = await postJson<unknown>({
        path: ACCOUNT_API_PATHS.loginVerify,
        requestSchema: AccountPasskeyLoginVerifyRequestSchema,
        responseSchema: AccountSessionResponseSchema,
        body: { flowId: options.flowId, response },
        csrfToken,
        signal,
      });
      adopt(session);
      if (isCurrent()) {
        setNotice({ tone: "info", message: "Signed in with your passkey.", needsFreshSession: false });
      }
    });
  }, [postJson, runMutation]);

  const walletFlow = useCallback(
    async (mode: "login" | "link", bound: AccountBoundToken | undefined) => {
      const provider = injectedProvider();
      if (provider === null) {
        setNotice(mapError(new WalletError("no-provider")));
        return;
      }
      await runMutation(
        async ({ csrfToken, signal, adopt, isCurrent }) => {
          const session = await openWalletSession(provider);
          const walletSignal = session.signal;
          try {
            const optionsPath = mode === "login" ? ACCOUNT_API_PATHS.walletLoginOptions : ACCOUNT_API_PATHS.walletLinkOptions;
            const options = await postJson<{ flowId: string; message: string }>({
              path: optionsPath,
              requestSchema: AccountWalletAddressRequestSchema,
              responseSchema: AccountWalletOptionsResponseSchema,
              body: { address: session.address },
              csrfToken,
              signal,
            });
            if (isWalletCancelled([signal, walletSignal])) throw new WalletError("changed");
            assertWalletMessage(options.message, window.location.origin, session.address);
            const pending = createConfirmation({ flowId: options.flowId, message: options.message, address: session.address });
            confirmationRef.current = pending;
            setWalletConfirm(pending.value);
            const confirmed = await waitWithCancellation(pending.promise, signal, walletSignal);
            confirmationRef.current = null;
            setWalletConfirm(null);
            if (!confirmed) throw new WalletError("changed");
            if (isWalletCancelled([signal, walletSignal])) throw new WalletError("changed");
            // Revalidate freshness immediately before personal_sign.
            assertWalletMessage(options.message, window.location.origin, session.address);
            const signature = await personalSign(provider, {
              message: options.message,
              address: session.address,
              signal,
              walletSignal,
            });
            if (isWalletCancelled([signal, walletSignal])) throw new WalletError("changed");
            const verifyPath = mode === "login" ? ACCOUNT_API_PATHS.walletLoginVerify : ACCOUNT_API_PATHS.walletLinkVerify;
            const result = await postJson<unknown>({
              path: verifyPath,
              requestSchema: AccountWalletVerifyRequestSchema,
              responseSchema: AccountSessionResponseSchema,
              body: { flowId: options.flowId, message: options.message, signature },
              csrfToken,
              signal,
            });
            if (isWalletCancelled([signal, walletSignal])) throw new WalletError("changed");
            adopt(result);
            if (isCurrent()) {
              setNotice({
                tone: "info",
                message: mode === "login" ? "Signed in with your wallet." : "Wallet linked.",
                needsFreshSession: false,
              });
            }
          } finally {
            // Listener disposal runs on success, rejection, abort and chain
            // failure alike.
            session.abort();
          }
        },
        bound === undefined ? {} : { accountBound: bound },
      );
    },
    [mapError, postJson, runMutation],
  );

  const addPasskey = useCallback(async () => {
    const bound = accountBound();
    await runMutation(async ({ csrfToken, signal, adopt, isCurrent }) => {
      const options = await postJson<{
        flowId: string;
        options: Parameters<typeof beginPasskeyRegistration>[0];
      }>({
        path: ACCOUNT_API_PATHS.addOptions,
        requestSchema: AccountEmptyRequestSchema,
        responseSchema: AccountPasskeyRegistrationOptionsResponseSchema,
        body: {},
        csrfToken,
        signal,
      });
      const response = await beginPasskeyRegistration(options.options);
      const result = await postJson<unknown>({
        path: ACCOUNT_API_PATHS.addVerify,
        requestSchema: AccountPasskeyAddVerifyRequestSchema,
        responseSchema: AccountSessionResponseSchema,
        body: { flowId: options.flowId, response },
        csrfToken,
        signal,
      });
      adopt(result);
      if (isCurrent()) {
        setNotice({ tone: "info", message: "Passkey added.", needsFreshSession: false });
      }
    }, { freshHint: true, ...(bound === undefined ? {} : { accountBound: bound }) });
  }, [accountBound, postJson, runMutation]);

  const generateCodes = useCallback(async () => {
    const guard = recoveryGuardRef.current;
    if (guard === null) return;
    const bound = accountBound();
    // A new display request invalidates any prior in-flight response.
    const token = guard.start();
    await runMutation(async ({ csrfToken, signal, isCurrent }) => {
      const payload = await postJson<unknown>({
        path: ACCOUNT_API_PATHS.recoveryCodes,
        requestSchema: AccountEmptyRequestSchema,
        responseSchema: AccountRecoveryCodesResponseSchema,
        body: {},
        csrfToken,
        signal,
      });
      if (isCurrent()) {
        setRecovery((current) => guard.apply(token, payload, current));
        setNotice({ tone: "warning", message: "New recovery codes shown once. Existing codes were replaced.", needsFreshSession: false });
        setReplacePending(false);
      }
    }, {
      freshHint: true,
      unknownNotice: ACCOUNT_NOTICES.codeReplaceUnknown,
      ...(bound === undefined ? {} : { accountBound: bound }),
    });
  }, [accountBound, postJson, runMutation]);

  const redeemRecovery = useCallback(async () => {
    const code = redeemCode;
    setRedeemCode("");
    await runMutation(async ({ csrfToken, signal, adopt, isCurrent }) => {
      const result = await postJson<unknown>({
        path: ACCOUNT_API_PATHS.recoveryRedeem,
        requestSchema: AccountRecoveryRedeemRequestSchema,
        responseSchema: AccountSessionResponseSchema,
        body: { code },
        csrfToken,
        signal,
      });
      adopt(result);
      if (isCurrent()) {
        setNotice({ tone: "info", message: "Signed in with a recovery code. Add a replacement passkey now.", needsFreshSession: false });
      }
    });
  }, [postJson, redeemCode, runMutation]);

  const logout = useCallback(async () => {
    const controller = controllerRef.current;
    if (controller === null) return;
    const generation = controller.generation;
    let operationSignal: AbortSignal | undefined;
    const isCurrent = (): boolean =>
      controller.generation === generation &&
      !(operationSignal?.aborted ?? false);
    const bound = controller.captureAccountBound();
    // Clear visible codes immediately, before any response is awaited.
    clearRecovery();
    setReplacePending(false);
    setBusy(true);
    setNotice(null);
    let sent = false;
    try {
      await controller.mutate(async ({ csrfToken, signal }) => {
        operationSignal = signal;
        sent = true;
        await requestAccount({
          path: ACCOUNT_API_PATHS.logout,
          method: "POST",
          requestSchema: AccountEmptyRequestSchema,
          responseSchema: AccountSessionEnvelopeDataSchema,
          body: {},
          csrfToken,
          signal,
        });
      }, { accountBound: bound });
      // Lock every tab's Vault before this page resets to the guest view. The
      // lock is bounded in time and never rejects, so it cannot block logout.
      await vaultWatcherRef.current?.logout("logout");
      if (isCurrent()) {
        clearRecovery();
        setNotice({ tone: "info", message: "Signed out.", needsFreshSession: false });
        // Clear the UI busy state before reset invalidates this operation's
        // generation; the finally below would otherwise no longer match.
        setBusy(false);
        controller.reset();
      }
    } catch (error) {
      // Once the logout request may have left the browser, treat this tab as
      // logged out for the Vault: lock it everywhere even though the server
      // outcome is unconfirmed (and even if this operation was superseded).
      if (logoutFailureLocksVault(sent, error)) {
        await vaultWatcherRef.current?.logout("logout-unconfirmed");
      }
      if (!isCurrent()) return;
      if (error instanceof AccountApiError && error.failure.kind === "aborted") return;
      if (error instanceof AccountApiError && error.failure.kind === "account-changed") {
        clearRecovery();
        setNotice(mapError(error));
        return;
      }
      // The response was lost: the outcome is unknown, and we never claim the
      // server session ended or that nothing changed.
      setNotice({ tone: "warning", message: ACCOUNT_NOTICES.logoutUnconfirmed, needsFreshSession: false });
    } finally {
      if (isCurrent()) setBusy(false);
    }
  }, [clearRecovery, mapError]);

  const confirmWallet = useCallback(() => {
    confirmationRef.current?.confirm();
  }, []);
  const cancelWallet = useCallback(() => {
    confirmationRef.current?.cancel();
    confirmationRef.current = null;
    setWalletConfirm(null);
    setNotice({ tone: "info", message: "Wallet sign-in cancelled. Nothing was signed.", needsFreshSession: false });
  }, []);

  if (!enabled) {
    return <AccountUnavailable />;
  }

  const signedIn = state.session.signedIn;
  const session = state.session;

  return (
    <div className="account-shell">
      <a className="account-skip" href="#account-main">Skip to account content</a>
      <header className="account-header">
        <a className="account-brand" href="/design" aria-label="OpenArc home">
          <img src="/openarc-logo.jpeg" alt="" width={30} height={30} className="account-brand__logo" />
          <span>OPENARC</span>
        </a>
        <a className="account-header__help" href="/design/docs">Account help</a>
      </header>
      <main id="account-main" className="account-main" tabIndex={-1}>
        <p className="account-eyebrow">ACCOUNT</p>
        <h1 className="account-title">{signedIn ? "Your OpenArc account" : "Sign in or create an account"}</h1>
        <p className="account-lede">
          Account access is passwordless and payment-free. Sign in with a wallet or a passkey,
          or continue as a guest without creating an account.
        </p>
        <p className="account-origin-warning" role="note">{ACCOUNT_NOTICES.originWarning}</p>

        {notice !== null ? (
          <p className={`account-notice account-notice--${notice.tone}`} role="status" data-testid="account-notice">
            {notice.message}
          </p>
        ) : null}

        {vaultLockNotice !== null ? (
          <p className="account-notice account-notice--warning" role="status" data-testid="account-vault-lock-status">
            {vaultLockNotice}
          </p>
        ) : null}

        {walletConfirm !== null ? (
          <section className="account-card" aria-labelledby="wallet-confirm-title" data-testid="wallet-confirm">
            <h2 id="wallet-confirm-title" className="account-card__title">Confirm wallet sign-in</h2>
            <p className="account-card__hint">{ACCOUNT_NOTICES.walletSignOnly}</p>
            <pre className="account-message" data-testid="wallet-message">{walletConfirm.message}</pre>
            <div className="account-actions">
              <button type="button" className="account-button account-button--primary" onClick={confirmWallet}>
                Sign in
              </button>
              <button type="button" className="account-button" onClick={cancelWallet}>Cancel</button>
            </div>
          </section>
        ) : busy ? (
          <p className="account-busy" role="status">Working…</p>
        ) : null}

        {!signedIn ? (
          <SignedOut
            busy={busy}
            walletPending={walletConfirm !== null}
            minimalAccepted={minimalAccepted}
            onMinimalChange={setMinimalAccepted}
            onCreatePasskey={createPasskey}
            onSignInPasskey={signInPasskey}
            onWalletSignIn={() => void walletFlow("login", undefined)}
            redeemCode={redeemCode}
            onRedeemCode={setRedeemCode}
            onRedeem={() => void redeemRecovery()}
          />
        ) : (
          <SignedIn
            session={session}
            busy={busy}
            recovery={recovery}
            replacePending={replacePending}
            onAddPasskey={() => void addPasskey()}
            onLinkWallet={() => void walletFlow("link", accountBound())}
            onGenerateCodes={() => {
              if (replacePending) {
                setReplacePending(false);
                void generateCodes();
              } else {
                setReplacePending(true);
              }
            }}
            onConfirmReplace={() => void generateCodes()}
            onCancelReplace={() => setReplacePending(false)}
            onHideRecovery={hideRecovery}
            onRefresh={() => void refreshSession()}
            onLogout={() => void logout()}
          />
        )}
      </main>
      <footer className="account-footer">
        <p>OpenArc is independent concept software and is not endorsed by Arc or Circle.</p>
      </footer>
    </div>
  );
}

/**
 * Resolves a confirmation only while neither the flow nor the wallet session
 * has been cancelled. A wallet event during the wait resolves false at once.
 */
function waitWithCancellation(
  promise: Promise<boolean>,
  flowSignal: AbortSignal,
  walletSignal: AbortSignal,
): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const finish = (value: boolean) => {
      flowSignal.removeEventListener("abort", onAbort);
      walletSignal.removeEventListener("abort", onAbort);
      resolve(value);
    };
    const onAbort = () => finish(false);
    if (isWalletCancelled([flowSignal, walletSignal])) {
      finish(false);
      return;
    }
    flowSignal.addEventListener("abort", onAbort, { once: true });
    walletSignal.addEventListener("abort", onAbort, { once: true });
    void promise.then((value) => finish(value && !isWalletCancelled([flowSignal, walletSignal])));
  });
}

function AccountUnavailable() {
  return (
    <div className="account-shell">
      <header className="account-header">
        <a className="account-brand" href="/design" aria-label="OpenArc home">
          <img src="/openarc-logo.jpeg" alt="" width={30} height={30} className="account-brand__logo" />
          <span>OPENARC</span>
        </a>
      </header>
      <main className="account-main" id="account-main">
        <p className="account-eyebrow">ACCOUNT</p>
        <h1 className="account-title">Accounts are not available here yet</h1>
        <p className="account-lede">
          Account access is disabled in this deployment. You can keep using the public
          documentation and continue as a guest.
        </p>
        <div className="account-actions">
          <a className="account-button" href="/design/docs">Read the docs</a>
          <a className="account-button account-button--primary" href="/design">Continue as guest</a>
        </div>
      </main>
    </div>
  );
}

interface SignedOutProps {
  busy: boolean;
  walletPending: boolean;
  minimalAccepted: boolean;
  onMinimalChange: (value: boolean) => void;
  onCreatePasskey: () => void;
  onSignInPasskey: () => void;
  onWalletSignIn: () => void;
  redeemCode: string;
  onRedeemCode: (value: string) => void;
  onRedeem: () => void;
}

function SignedOut(props: SignedOutProps) {
  return (
    <div className="account-grid">
      <section className="account-card" aria-labelledby="wallet-title">
        <h2 id="wallet-title" className="account-card__title">Wallet sign-in</h2>
        <p className="account-card__hint">{ACCOUNT_NOTICES.walletPublic}</p>
        <button type="button" className="account-button account-button--primary" onClick={props.onWalletSignIn} disabled={props.busy || props.walletPending}>
          Sign in with wallet
        </button>
      </section>

      <section className="account-card" aria-labelledby="passkey-title">
        <h2 id="passkey-title" className="account-card__title">Create a passkey</h2>
        <label className="account-check">
          <input type="checkbox" checked={props.minimalAccepted} onChange={(event) => props.onMinimalChange(event.target.checked)} />
          <span>{ACCOUNT_NOTICES.minimalRecord}</span>
        </label>
        <button type="button" className="account-button account-button--primary" onClick={props.onCreatePasskey} disabled={props.busy || !props.minimalAccepted}>
          Create a passkey
        </button>
      </section>

      <section className="account-card" aria-labelledby="login-title">
        <h2 id="login-title" className="account-card__title">Sign in with passkey</h2>
        <p className="account-card__hint">Use a passkey already registered to this site.</p>
        <button type="button" className="account-button" onClick={props.onSignInPasskey} disabled={props.busy}>
          Sign in with passkey
        </button>
      </section>

      <section className="account-card" aria-labelledby="recover-title">
        <h2 id="recover-title" className="account-card__title">Recovery code</h2>
        <p className="account-card__hint">Redeem one saved recovery code. There is no email or fund recovery.</p>
        <label className="account-field">
          <span>Recovery code</span>
          <input
            type="password"
            autoComplete="off"
            value={props.redeemCode}
            onChange={(event) => props.onRedeemCode(event.target.value)}
            className="account-input"
            data-testid="recovery-redeem"
          />
        </label>
        <button type="button" className="account-button" onClick={props.onRedeem} disabled={props.busy || props.redeemCode.length === 0}>
          Redeem recovery code
        </button>
      </section>

      <section className="account-card" aria-labelledby="guest-title">
        <h2 id="guest-title" className="account-card__title">Continue as guest</h2>
        <p className="account-card__hint">Guests create no account and no stored records.</p>
        <a className="account-button" href="/design">Continue as guest</a>
      </section>
    </div>
  );
}

interface SignedInProps {
  session: AccountSessionView;
  busy: boolean;
  recovery: RecoveryDisplay;
  replacePending: boolean;
  onAddPasskey: () => void;
  onLinkWallet: () => void;
  onGenerateCodes: () => void;
  onConfirmReplace: () => void;
  onCancelReplace: () => void;
  onHideRecovery: () => void;
  onRefresh: () => void;
  onLogout: () => void;
}

function SignedIn(props: SignedInProps) {
  if (!props.session.signedIn) return null;
  const session = props.session;
  const isRecovery = session.method === "recovery";
  return (
    <div className="account-grid">
      <section className="account-card account-card--wide" aria-labelledby="session-title">
        <h2 id="session-title" className="account-card__title">Signed in</h2>
        <dl className="account-details">
          <div><dt>Account</dt><dd data-testid="account-id">{session.accountId}</dd></div>
          <div><dt>Method</dt><dd>{methodLabel(session.method)}</dd></div>
          <div><dt>Expires</dt><dd>{session.expiresAt}</dd></div>
        </dl>
        <div className="account-actions">
          <button type="button" className="account-button" onClick={props.onRefresh} disabled={props.busy}>Refresh sign-in</button>
          <button type="button" className="account-button" onClick={props.onLogout} disabled={props.busy}>Sign out</button>
        </div>
      </section>

      <section className="account-card" aria-labelledby="add-key-title">
        <h2 id="add-key-title" className="account-card__title">Add a passkey</h2>
        <p className="account-card__hint">{isRecovery ? "From a recovery session you can add a replacement passkey." : "Register another passkey on this account."}</p>
        <button type="button" className="account-button account-button--primary" onClick={props.onAddPasskey} disabled={props.busy}>Add passkey</button>
      </section>

      <section className="account-card" aria-labelledby="link-wallet-title">
        <h2 id="link-wallet-title" className="account-card__title">Link a wallet</h2>
        <p className="account-card__hint">{ACCOUNT_NOTICES.walletPublic}</p>
        <button type="button" className="account-button" onClick={props.onLinkWallet} disabled={props.busy}>Link wallet</button>
      </section>

      <section className="account-card" aria-labelledby="codes-title">
        <h2 id="codes-title" className="account-card__title">Recovery codes</h2>
        {isRecovery ? (
          <p className="account-card__hint">Replacing recovery codes requires a fresh wallet or passkey sign-in.</p>
        ) : props.replacePending ? (
          <div>
            <p className="account-card__hint account-card__hint--warning">
              Generating a new set replaces all existing recovery codes. The old codes stop working immediately.
            </p>
            <div className="account-actions">
              <button type="button" className="account-button account-button--primary" onClick={props.onConfirmReplace} disabled={props.busy}>Replace codes</button>
              <button type="button" className="account-button" onClick={props.onCancelReplace} disabled={props.busy}>Cancel</button>
            </div>
          </div>
        ) : (
          <button type="button" className="account-button" onClick={props.onGenerateCodes} disabled={props.busy}>Generate recovery codes</button>
        )}
      </section>

      {props.recovery.visible ? (
        <section className="account-card account-card--wide" aria-labelledby="shown-codes-title" data-testid="recovery-codes">
          <h2 id="shown-codes-title" className="account-card__title">Save these codes now</h2>
          <p className="account-card__hint">Shown once. Store them somewhere safe; each can be used a single time.</p>
          <ol className="account-codes">
            {props.recovery.codes.map((code, index) => (
              <li key={index}><code>{code}</code></li>
            ))}
          </ol>
          <button type="button" className="account-button" onClick={props.onHideRecovery}>Hide codes</button>
        </section>
      ) : null}
    </div>
  );
}
