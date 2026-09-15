import type { CommerceHumanRole } from "@openarc/shared";
import { describe, expect, it, vi } from "vitest";

import type { AccountFlowController } from "../src/account/flow-controller.js";
import { GrantClient } from "../src/tenant/grant-client.js";
import {
  GRANT_CLAIMED_THEN_REVOKED_NOTICE,
  GRANT_LIFETIME_NOTICE,
  GRANT_MAX_LIFETIME_SECONDS,
  GRANT_RELEASED_REVOKE_NOTICE,
  GRANT_RELEASE_UNKNOWN_NOTICE,
  GrantController,
  UNKNOWN_GRANT_STATUS_MESSAGE,
  canReadGrants,
  canRevokeGrants,
  grantDisplayFields,
  grantExpired,
  grantLifeState,
  grantStatusExplanation,
  grantStatusLabel,
  initialGrantControllerState,
  renderGrantState,
  revokeOutcomeLabel,
  revokeRejectionMessage,
  revokeReleaseNotice,
  revokeSummary,
  suppressStaleGrantContext,
  type CommerceGrantMetadata,
  type GrantReadCoordinator,
} from "../src/tenant/grant-controller.js";
import {
  ACCOUNT_A,
  ACCOUNT_B,
  FAKE_GRANT_TOKEN,
  GRANT,
  GRANT_B,
  ISO_CLAIMED,
  ISO_EXPIRES,
  ISO_REVOKED,
  NOW_AFTER_EXPIRY,
  NOW_BEFORE_EXPIRY,
  ORG,
  ORG_B,
  claimedGrantMetadata,
  claimedRevokeData,
  claimedThenRevokedGrantMetadata,
  errorEnvelope,
  expiredGrantMetadata,
  grantDetail,
  grantMetadata,
  grantReceipt,
  releasedRevokeData,
  success,
  unclaimedRevokedGrantMetadata,
} from "./grant-test-fixtures.js";

const CSRF = "csrf-from-bootstrap";

const asMetadata = (record: Record<string, unknown>): CommerceGrantMetadata =>
  record as unknown as CommerceGrantMetadata;

function fakeReads(
  role: CommerceHumanRole | null = "owner",
  organizationId: string | null = ORG,
): GrantReadCoordinator & { abortCalls: number } {
  const reads = {
    abortCalls: 0,
    currentOrganizationId: () => organizationId,
    currentRole: () => role,
    currentAccountId: () => ACCOUNT_A,
    abortPendingReads() {
      reads.abortCalls += 1;
    },
  };
  return reads;
}

function fakeAccount(initialAccountId: string | null = ACCOUNT_A, method = "passkey") {
  const account = {
    state:
      initialAccountId === null
        ? { status: "signed-out", csrfToken: null, session: { signedIn: false as const } }
        : {
            status: "signed-in",
            csrfToken: "csrf",
            session: {
              signedIn: true as const,
              accountId: initialAccountId,
              method,
              expiresAt: "2030-01-01T00:00:00.000Z",
            },
          },
    captureAccountBound() {
      return { generation: 0, accountId: initialAccountId };
    },
    async mutate<T>(
      run: (context: { csrfToken: string; signal: AbortSignal }) => Promise<T>,
    ): Promise<T> {
      return run({ csrfToken: CSRF, signal: new AbortController().signal });
    },
  };
  return account as unknown as AccountFlowController;
}

function controllerWith(
  fetcher: unknown,
  options: {
    role?: CommerceHumanRole | null;
    organizationId?: string | null;
    capability?: "enabled" | "built_disabled" | "unavailable";
    account?: AccountFlowController;
  } = {},
) {
  const reads = fakeReads(
    options.role === undefined ? "owner" : options.role,
    options.organizationId === undefined ? ORG : options.organizationId,
  );
  const account = options.account ?? fakeAccount();
  const controller = new GrantController({
    account,
    reads,
    client: new GrantClient({ fetcher: fetcher as typeof fetch }),
    capabilityReader: async () => options.capability ?? "enabled",
  });
  return { controller, reads };
}

/** A fetcher that serves a detail read and lets the caller shape the POST. */
function detailFetcher(
  item: Record<string, unknown> | null,
  onPost?: (init: RequestInit) => Response | Promise<Response>,
  onStatus?: () => Response,
) {
  return vi.fn(async (path: string, init: RequestInit) => {
    if (init.method === "POST") {
      if (onPost === undefined) throw new TypeError("no POST configured");
      return onPost(init);
    }
    if (String(path).includes("/grant-mutations/")) {
      if (onStatus === undefined) return success({ status: "not_found" });
      return onStatus();
    }
    return success(grantDetail(item));
  });
}

function postCalls(fetcher: ReturnType<typeof vi.fn>): unknown[] {
  return fetcher.mock.calls.filter(([, init]) => (init as RequestInit).method === "POST");
}

/** Drains pending microtasks and real macrotasks so any stray work can run. */
async function drain(): Promise<void> {
  for (let index = 0; index < 30; index += 1) await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setTimeout(resolve, 20));
  for (let index = 0; index < 30; index += 1) await Promise.resolve();
}

describe("grant role matrix", () => {
  it("lets owner, operator and viewer read; only owner and operator may revoke", () => {
    for (const role of ["owner", "operator"] as const) {
      expect(canReadGrants(role)).toBe(true);
      expect(canRevokeGrants(role)).toBe(true);
    }
    expect(canReadGrants("viewer")).toBe(true);
    expect(canRevokeGrants("viewer")).toBe(false);
    for (const role of ["provider_admin", "provider_developer", null, "unknown"] as const) {
      expect(canReadGrants(role)).toBe(false);
      expect(canRevokeGrants(role)).toBe(false);
    }
  });

  it("grants a viewer read access but refuses the revoke without any request", async () => {
    const fetcher = detailFetcher(grantMetadata());
    const { controller } = controllerWith(fetcher, { role: "viewer" });
    await controller.initialize({ kind: "detail", grantId: GRANT });
    expect(controller.state.canRead).toBe(true);
    expect(controller.state.canRevoke).toBe(false);
    expect(controller.state.detail.status).toBe("ready");
    const readCalls = fetcher.mock.calls.length;

    expect(controller.beginRevoke(GRANT)).toBe(false);
    expect(controller.state.revoke).toEqual({
      kind: "rejected",
      notice: { kind: "no-access" },
    });
    expect(fetcher.mock.calls.length).toBe(readCalls);
    expect(postCalls(fetcher)).toHaveLength(0);
  });

  it("lets an owner reach the confirmation step without sending anything", async () => {
    const fetcher = detailFetcher(grantMetadata());
    const { controller } = controllerWith(fetcher, { role: "owner" });
    await controller.initialize({ kind: "detail", grantId: GRANT });
    const before = fetcher.mock.calls.length;
    expect(controller.beginRevoke(GRANT)).toBe(true);
    expect(controller.state.revoke.kind).toBe("confirming");
    // Confirming creates NO mutation id, NO key and NO request.
    expect(fetcher.mock.calls.length).toBe(before);
    expect(JSON.stringify(controller.state)).not.toContain("mutationId");
  });

  it("refuses every read and revoke for a recovery sign-in", async () => {
    const fetcher = vi.fn();
    const { controller } = controllerWith(fetcher, {
      account: fakeAccount(ACCOUNT_A, "recovery"),
    });
    await controller.initialize({ kind: "detail", grantId: GRANT });
    expect(controller.state.canRead).toBe(false);
    expect(controller.state.canRevoke).toBe(false);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("refuses a revoke for a malformed grant id without any request", async () => {
    const fetcher = detailFetcher(grantMetadata());
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    const before = fetcher.mock.calls.length;
    expect(controller.beginRevoke("not-a-grant")).toBe(false);
    expect(controller.state.revoke).toEqual({
      kind: "rejected",
      notice: { kind: "validation" },
    });
    expect(fetcher.mock.calls.length).toBe(before);
  });
});

describe("grant capability gate", () => {
  it("renders an honest unavailable state and makes zero grant requests when disabled", async () => {
    for (const capability of ["built_disabled", "unavailable"] as const) {
      const fetcher = vi.fn();
      const { controller } = controllerWith(fetcher, { capability });
      await controller.initialize({ kind: "detail", grantId: GRANT });
      expect(controller.state.capability).toBe("unavailable");
      expect(controller.state.detail.status).toBe("none");
      expect(controller.state.detail.item).toBeNull();
      expect(fetcher).not.toHaveBeenCalled();
    }
  });

  it("reports unavailable rather than a fabricated grant when the probe itself fails", async () => {
    const fetcher = vi.fn();
    const controller = new GrantController({
      account: fakeAccount(),
      reads: fakeReads(),
      client: new GrantClient({ fetcher: fetcher as unknown as typeof fetch }),
      capabilityReader: async () => {
        throw new Error("probe down");
      },
    });
    await controller.initialize({ kind: "detail", grantId: GRANT });
    expect(controller.state.capability).toBe("unavailable");
    expect(controller.state.detail.item).toBeNull();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("refuses a revoke outright while the capability is not enabled", async () => {
    const fetcher = vi.fn();
    const { controller } = controllerWith(fetcher, { capability: "built_disabled" });
    await controller.initialize({ kind: "detail", grantId: GRANT });
    expect(controller.beginRevoke(GRANT)).toBe(false);
    expect(controller.state.revoke).toEqual({
      kind: "rejected",
      notice: { kind: "capability-disabled" },
    });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("makes no request at all on the lookup route, because there is no grant list", async () => {
    const fetcher = vi.fn();
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "lookup" });
    expect(controller.state.capability).toBe("enabled");
    expect(controller.state.detail.status).toBe("none");
    expect(fetcher).not.toHaveBeenCalled();
    // An explicit lookup selection still issues nothing.
    controller.selectLookupGrantId(GRANT);
    expect(controller.state.lookupGrantId).toBe(GRANT);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("probes nothing until an explicit initialize on a real route", async () => {
    const fetcher = vi.fn();
    const capabilityReader = vi.fn(async () => "enabled" as const);
    const controller = new GrantController({
      account: fakeAccount(),
      reads: fakeReads(),
      client: new GrantClient({ fetcher: fetcher as unknown as typeof fetch }),
      capabilityReader,
    });
    // Constructing the controller alone probes nothing.
    expect(capabilityReader).not.toHaveBeenCalled();
    expect(fetcher).not.toHaveBeenCalled();
    // Pointing it at a route probes nothing either.
    controller.setRoute({ kind: "lookup" });
    controller.selectLookupGrantId(GRANT);
    expect(capabilityReader).not.toHaveBeenCalled();
    // An invalid route probes nothing.
    await controller.initialize({ kind: "invalid" });
    expect(capabilityReader).not.toHaveBeenCalled();
    // Only an explicit initialize on a real route probes, and exactly once.
    await controller.initialize({ kind: "detail", grantId: GRANT });
    await controller.initialize({ kind: "lookup" });
    expect(capabilityReader).toHaveBeenCalledTimes(1);
  });

  it("makes no request for an invalid route and leaves the capability unchecked", async () => {
    const fetcher = vi.fn();
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "invalid" });
    expect(controller.state.capability).toBe("unknown");
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("grant detail reads", () => {
  it("reads one grant and keeps every server field verbatim", async () => {
    const fetcher = detailFetcher(grantMetadata());
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    expect(controller.state.detail.status).toBe("ready");
    expect(controller.state.detail.item?.grantId).toBe(GRANT);
    expect(controller.state.detail.item?.expiresAt).toBe(ISO_EXPIRES);
  });

  it("treats a missing and a foreign grant identically as not-found", async () => {
    const fetcher = detailFetcher(null);
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    expect(controller.state.detail.status).toBe("not-found");
    expect(controller.state.detail.item).toBeNull();
  });

  it("records an error rather than a fabricated grant when the record does not parse", async () => {
    const fetcher = detailFetcher(grantMetadata(GRANT, { status: "paid" }));
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    expect(controller.state.detail.status).toBe("error");
    expect(controller.state.detail.item).toBeNull();
  });

  it("refuses a malformed grant id locally without a request", async () => {
    const fetcher = detailFetcher(grantMetadata());
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "lookup" });
    await controller.loadGrantDetail("not-a-grant");
    expect(controller.state.detail.status).toBe("error");
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("grant expiry", () => {
  const issued = asMetadata(grantMetadata());

  it("never exceeds the fixed 300-second lifetime bound", () => {
    expect(GRANT_MAX_LIFETIME_SECONDS).toBe(300);
    expect(GRANT_LIFETIME_NOTICE).toContain("300 seconds");
    expect(GRANT_LIFETIME_NOTICE).toContain("runs no countdown");
  });

  it("calls an issued grant claimable before its expiry and expired at or after it", () => {
    expect(grantExpired(issued, NOW_BEFORE_EXPIRY)).toBe(false);
    expect(grantLifeState(issued, NOW_BEFORE_EXPIRY)).toBe("claimable");
    expect(grantExpired(issued, NOW_AFTER_EXPIRY)).toBe(true);
    expect(grantLifeState(issued, NOW_AFTER_EXPIRY)).toBe("expired");
    // The boundary instant itself is already expired.
    expect(grantExpired(issued, ISO_EXPIRES)).toBe(true);
    expect(grantLifeState(issued, ISO_EXPIRES)).toBe("expired");
  });

  it("fails closed on an unreadable clock rather than implying a live grant", () => {
    expect(grantExpired(issued, "not-a-timestamp")).toBe(true);
    expect(grantLifeState(issued, "not-a-timestamp")).toBe("expired");
  });

  it("renders an expired grant as expired and not claimable", () => {
    const expired = asMetadata(expiredGrantMetadata());
    expect(grantLifeState(expired, NOW_BEFORE_EXPIRY)).toBe("expired");
    const fields = grantDisplayFields(expired, NOW_BEFORE_EXPIRY);
    const claimable = fields.find((field) => field.key === "life");
    expect(claimable?.value).toBe("No");
    expect(grantStatusLabel(expired.status)).toBe("Expired");
    const explanation = grantStatusExplanation(expired, NOW_BEFORE_EXPIRY);
    expect(explanation).toContain("expired without ever being claimed");
    expect(explanation).toContain("not evidence");
  });

  it("never implies a stale issued record is still claimable once its expiry has passed", () => {
    // The server's stored status can lag. A lagging `issued` past expiry must
    // still read as expired everywhere.
    const fields = grantDisplayFields(issued, NOW_AFTER_EXPIRY);
    expect(fields.find((field) => field.key === "life")?.value).toBe("No");
    expect(fields.find((field) => field.key === "status")?.value).toBe("Issued");
    const explanation = grantStatusExplanation(issued, NOW_AFTER_EXPIRY);
    expect(explanation).toContain("expiry instant has passed");
    expect(explanation).toContain("can no longer be claimed");
  });

  it("always shows the exact server expiry instant", () => {
    for (const now of [NOW_BEFORE_EXPIRY, NOW_AFTER_EXPIRY]) {
      const fields = grantDisplayFields(issued, now);
      expect(fields.find((field) => field.key === "expiresAt")?.value).toBe(ISO_EXPIRES);
    }
  });
});

describe("a claimed-then-revoked grant retains the claim and may still have been paid", () => {
  const claimedThenRevoked = asMetadata(claimedThenRevokedGrantMetadata());

  it("renders the claim-retained, may-have-been-paid state and never a refund", () => {
    const explanation = grantStatusExplanation(claimedThenRevoked, NOW_AFTER_EXPIRY);
    // The single load-bearing sentence set is used verbatim.
    expect(explanation).toBe(GRANT_CLAIMED_THEN_REVOKED_NOTICE);
    expect(explanation).toContain("was claimed before it was revoked");
    expect(explanation).toContain("the claim fact is retained");
    expect(explanation).toContain("the held exposure is retained");
    expect(explanation).toContain("may still have been paid");
    expect(explanation).toContain("not a refund");
    expect(explanation).toContain("not a release");
    expect(explanation).toContain("not a cancellation of payment");

    // The claim fact survives in the rendered record, not only in the prose.
    const fields = grantDisplayFields(claimedThenRevoked, NOW_AFTER_EXPIRY);
    expect(fields.find((field) => field.key === "claimedAt")?.value).toBe(ISO_CLAIMED);
    expect(fields.find((field) => field.key === "revokedAt")?.value).toBe(ISO_REVOKED);
    expect(fields.find((field) => field.key === "status")?.value).toBe("Revoked");

    // It is never described as a refund, a reversal or money coming back.
    for (const forbidden of [
      /\brefunded\b/iu,
      /\bwas refunded\b/iu,
      /\bmoney back\b/iu,
      /\breversed\b/iu,
      /\bpayment cancelled\b/iu,
      /\bpayment reversed\b/iu,
      /\bfunds returned\b/iu,
    ]) {
      expect(explanation).not.toMatch(forbidden);
    }
  });

  it("shows the same claim-retained notice on the committed revoke receipt", async () => {
    const fetcher = detailFetcher(claimedThenRevokedGrantMetadata(), (init) => {
      const mutationId = (JSON.parse(String(init.body)) as { mutationId: string }).mutationId;
      return success(claimedRevokeData(mutationId));
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    controller.beginRevoke(GRANT);
    await controller.confirmRevoke();

    const revoke = controller.state.revoke;
    expect(revoke.kind).toBe("committed");
    if (revoke.kind !== "committed") throw new Error("expected a committed revoke");
    expect(revoke.committed.released).toBe(false);
    expect(revoke.committed.metadata?.claimedAt).toBe(ISO_CLAIMED);
    expect(revokeReleaseNotice(revoke.committed)).toBe(GRANT_CLAIMED_THEN_REVOKED_NOTICE);
    expect(revokeOutcomeLabel(revoke)).toBe("The server revoked this grant.");
  });

  it("warns before sending that a claimed grant will not be undone", () => {
    const claimed = asMetadata(claimedGrantMetadata());
    const summary = revokeSummary(claimed);
    expect(summary).toContain("refunds nothing");
    expect(summary).toContain(GRANT_CLAIMED_THEN_REVOKED_NOTICE);
  });

  it("keeps a never-claimed release a cap adjustment, never a refund", async () => {
    const fetcher = detailFetcher(unclaimedRevokedGrantMetadata(), (init) => {
      const mutationId = (JSON.parse(String(init.body)) as { mutationId: string }).mutationId;
      return success(releasedRevokeData(mutationId));
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    controller.beginRevoke(GRANT);
    await controller.confirmRevoke();

    const revoke = controller.state.revoke;
    if (revoke.kind !== "committed") throw new Error("expected a committed revoke");
    expect(revoke.committed.released).toBe(true);
    expect(revoke.committed.actionStatus).toBe("cancelled");
    const notice = revokeReleaseNotice(revoke.committed);
    expect(notice).toBe(GRANT_RELEASED_REVOKE_NOTICE);
    expect(notice).toContain("cap adjustment, not a refund");
    expect(notice).toContain("no money moved");
  });
});

describe("no optimistic or implied payment status anywhere", () => {
  /**
   * Every occurrence of a money/fulfilment word in this console's copy must sit
   * in a sentence that hedges or negates it. This is stricter than a keyword
   * blocklist: honest copy has to NAME these things in order to deny them.
   */
  const MONEY_WORD =
    /\b(?:pay|pays|paid|payment|payments|settle\w*|deliver\w*|delivery|refund\w*|releas\w*|reimburs\w*|purchas\w*)\b/giu;
  const HEDGE =
    /\b(?:not|never|no|nothing|none|neither|nor|may|might|cannot|without|whether|unknown|n't)\b/iu;

  function unhedgedMoneyClaims(text: string): string[] {
    const offenders: string[] = [];
    for (const sentence of text.split(/(?<=[.;:])\s+/u)) {
      MONEY_WORD.lastIndex = 0;
      if (!MONEY_WORD.test(sentence)) continue;
      if (!HEDGE.test(sentence)) offenders.push(sentence);
    }
    return offenders;
  }

  function allCopy(): string[] {
    const statuses = ["issued", "claimed", "revoked", "expired", "wat"] as const;
    const metadataCases = [
      grantMetadata(),
      claimedGrantMetadata(),
      claimedThenRevokedGrantMetadata(),
      unclaimedRevokedGrantMetadata(),
      expiredGrantMetadata(),
    ].map(asMetadata);
    const copy: string[] = [
      GRANT_LIFETIME_NOTICE,
      GRANT_CLAIMED_THEN_REVOKED_NOTICE,
      GRANT_RELEASED_REVOKE_NOTICE,
      GRANT_RELEASE_UNKNOWN_NOTICE,
      UNKNOWN_GRANT_STATUS_MESSAGE,
      revokeSummary(null),
      revokeSummary(asMetadata(grantMetadata())),
      revokeSummary(asMetadata(claimedGrantMetadata())),
    ];
    for (const status of statuses) copy.push(grantStatusLabel(status));
    for (const metadata of metadataCases) {
      for (const now of [NOW_BEFORE_EXPIRY, NOW_AFTER_EXPIRY]) {
        copy.push(grantStatusExplanation(metadata, now));
        for (const field of grantDisplayFields(metadata, now)) {
          copy.push(field.label, field.value);
        }
      }
    }
    for (const kind of [
      "validation",
      "policy",
      "conflict",
      "unauthenticated",
      "csrf",
      "forbidden",
      "not-found",
      "account-changed",
      "capability-disabled",
      "no-access",
    ] as const) {
      copy.push(revokeRejectionMessage({ kind }));
    }
    for (const revoke of [
      { kind: "idle" } as const,
      { kind: "confirming", draft: { grantId: GRANT } } as const,
      { kind: "pending", draft: { grantId: GRANT }, mutationId: "m" } as const,
      { kind: "rejected", notice: { kind: "policy" } } as const,
      {
        kind: "outcome-unknown",
        mutationId: "m",
        organizationId: ORG,
        grantId: GRANT,
        checking: false,
        statusMessage: null,
      } as const,
    ]) {
      copy.push(revokeOutcomeLabel(revoke));
    }
    return copy;
  }

  it("uses a detector that actually fires on an unhedged payment claim", () => {
    // Without this, the assertion below could pass vacuously.
    expect(unhedgedMoneyClaims("This grant was paid.")).toEqual(["This grant was paid."]);
    expect(unhedgedMoneyClaims("Your payment settled and the goods were delivered.")).toHaveLength(
      1,
    );
    expect(unhedgedMoneyClaims("We refunded you.")).toHaveLength(1);
    expect(unhedgedMoneyClaims("The held amount was released.")).toHaveLength(1);
    // And that it accepts a properly hedged sentence.
    expect(unhedgedMoneyClaims("This grant may still have been paid.")).toEqual([]);
  });

  it("never states that anything was paid, settled, delivered or refunded", () => {
    const copy = allCopy();
    // The corpus really does discuss money/fulfilment, so the check has work
    // to do: a console that simply never mentions payment would be easy to
    // pass and useless to a reader.
    const withMoneyWords = copy.filter((text) => {
      MONEY_WORD.lastIndex = 0;
      return MONEY_WORD.test(text);
    });
    expect(withMoneyWords.length).toBeGreaterThan(8);
    const offenders = copy.flatMap(unhedgedMoneyClaims);
    expect(offenders).toEqual([]);
  });

  it("offers no paid, settled, delivered or refunded status label", () => {
    for (const status of [
      "paid",
      "settled",
      "delivered",
      "refunded",
      "complete",
      "success",
    ]) {
      // No such status exists on the accepted wire, so each reads as Unknown.
      expect(grantStatusLabel(status)).toBe("Unknown");
    }
    expect(["Issued", "Claimed", "Revoked", "Expired"]).toEqual([
      grantStatusLabel("issued"),
      grantStatusLabel("claimed"),
      grantStatusLabel("revoked"),
      grantStatusLabel("expired"),
    ]);
  });

  it("renders no money field at all, so nothing needs a numeric conversion", () => {
    for (const metadata of [grantMetadata(), claimedThenRevokedGrantMetadata()].map(asMetadata)) {
      const fields = grantDisplayFields(metadata, NOW_BEFORE_EXPIRY);
      for (const field of fields) {
        expect(field.key).not.toMatch(/amount|fee|debit|price|balance|atomic/iu);
        // No display value is a bare decimal that could read as money.
        expect(field.value).not.toMatch(/^\s*-?\d+\.\d+\s*$/u);
      }
      expect(fields.map((field) => field.key)).not.toContain("amountAtomic");
    }
  });

  it("describes a claim as a claim, never as a receipt of payment", () => {
    const claimed = asMetadata(claimedGrantMetadata());
    const explanation = grantStatusExplanation(claimed, NOW_BEFORE_EXPIRY);
    expect(explanation).toContain("A claim records that the grant was presented and accepted");
    expect(explanation).toContain("it is not a receipt");
    expect(explanation).toContain("is not reported to this console");
  });
});

describe("grant revoke", () => {
  it("sends exactly one revoke with a frozen id and key and commits on a receipt", async () => {
    let seenMutationId = "";
    let seenKey = "";
    const fetcher = detailFetcher(claimedThenRevokedGrantMetadata(), (init) => {
      seenMutationId = (JSON.parse(String(init.body)) as { mutationId: string }).mutationId;
      seenKey = (init.headers as Record<string, string>)["Idempotency-Key"]!;
      return success(claimedRevokeData(seenMutationId));
    });
    const { controller, reads } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    controller.beginRevoke(GRANT);
    await controller.confirmRevoke();

    expect(postCalls(fetcher)).toHaveLength(1);
    expect(seenKey).toHaveLength(43);
    expect(controller.state.revoke.kind).toBe("committed");
    if (controller.state.revoke.kind !== "committed") throw new Error("expected committed");
    expect(controller.state.revoke.committed.receipt.mutationId).toBe(seenMutationId);
    expect(controller.state.revoke.committed.receipt.operation).toBe("control.grant.revoke");
    // Pending reads are aborted before the write, exactly once.
    expect(reads.abortCalls).toBe(1);
  });

  it("cancelling before confirmation sends nothing and keeps no key", async () => {
    const fetcher = detailFetcher(grantMetadata());
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    controller.beginRevoke(GRANT);
    controller.cancelRevoke();
    expect(controller.state.revoke).toEqual({ kind: "idle" });
    expect(postCalls(fetcher)).toHaveLength(0);
  });

  it("records a server denial and disables the local revoke control", async () => {
    const fetcher = detailFetcher(grantMetadata(), () => errorEnvelope("FORBIDDEN", 403));
    const { controller } = controllerWith(fetcher, { role: "owner" });
    await controller.initialize({ kind: "detail", grantId: GRANT });
    // The LOCAL guess said this owner may revoke.
    expect(controller.state.canRevoke).toBe(true);
    controller.beginRevoke(GRANT);
    await controller.confirmRevoke();

    expect(controller.state.serverDeniedRevoke).toBe(true);
    expect(controller.state.revoke).toEqual({
      kind: "rejected",
      notice: { kind: "forbidden" },
    });
    // The server is authoritative: the local guess no longer stands.
    expect(controller.state.canRevoke).toBe(false);
    expect(postCalls(fetcher)).toHaveLength(1);
    expect(revokeRejectionMessage({ kind: "forbidden" })).toContain(
      "The server is the authority here",
    );

    // A denial is not retried, and beginning again is refused locally.
    expect(controller.beginRevoke(GRANT)).toBe(false);
    expect(postCalls(fetcher)).toHaveLength(1);
  });

  it("clears the server denial only on an explicit context change", async () => {
    const fetcher = detailFetcher(grantMetadata(), () => errorEnvelope("FORBIDDEN", 403));
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    controller.beginRevoke(GRANT);
    await controller.confirmRevoke();
    expect(controller.state.serverDeniedRevoke).toBe(true);
    controller.clear();
    expect(controller.state.serverDeniedRevoke).toBe(false);
    expect(controller.state.revoke).toEqual({ kind: "idle" });
  });

  it("maps a policy refusal, a conflict and a CSRF rejection to their own honest notices", async () => {
    for (const [code, status, kind] of [
      ["GRANT_ALREADY_USED", 403, "policy"],
      ["GRANT_REVOKED", 403, "policy"],
      ["IDEMPOTENCY_CONFLICT", 409, "conflict"],
      ["CSRF_REJECTED", 403, "csrf"],
      ["UNAUTHENTICATED", 401, "unauthenticated"],
    ] as const) {
      const fetcher = detailFetcher(grantMetadata(), () => errorEnvelope(code, status));
      const { controller } = controllerWith(fetcher);
      await controller.initialize({ kind: "detail", grantId: GRANT });
      controller.beginRevoke(GRANT);
      await controller.confirmRevoke();
      expect(controller.state.revoke).toEqual({ kind: "rejected", notice: { kind } });
      expect(postCalls(fetcher)).toHaveLength(1);
    }
  });

  it("keeps a committed receipt even when the follow-up refresh fails", async () => {
    let posted = false;
    const fetcher = vi.fn(async (path: string, init: RequestInit) => {
      if (init.method === "POST") {
        posted = true;
        const mutationId = (JSON.parse(String(init.body)) as { mutationId: string }).mutationId;
        return success(claimedRevokeData(mutationId));
      }
      if (posted) return errorEnvelope("INTERNAL_ERROR", 500);
      return success(grantDetail(claimedGrantMetadata()));
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    controller.beginRevoke(GRANT);
    await controller.confirmRevoke();
    const revoke = controller.state.revoke;
    if (revoke.kind !== "committed") throw new Error("expected committed");
    expect(revoke.committed.refreshError).toBe(true);
    expect(revoke.committed.receipt.resourceId).toBe(GRANT);
  });
});

describe("lost-response recovery", () => {
  it("offers only an explicit status re-check after a lost response and issues no automatic retry", async () => {
    const fetcher = detailFetcher(grantMetadata(), () => {
      throw new TypeError("connection lost");
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    const readsBefore = fetcher.mock.calls.length;

    controller.beginRevoke(GRANT);
    await controller.confirmRevoke();

    expect(controller.state.revoke.kind).toBe("outcome-unknown");
    expect(postCalls(fetcher)).toHaveLength(1);
    expect(fetcher.mock.calls.length).toBe(readsBefore + 1);

    // Drain every pending microtask and real macrotask: still nothing resent
    // and nothing re-read.
    await drain();
    expect(postCalls(fetcher)).toHaveLength(1);
    expect(fetcher.mock.calls.length).toBe(readsBefore + 1);
  });

  it("issues no request at all after a lost response even once every timer has fired", async () => {
    const fetcher = detailFetcher(grantMetadata(), () => {
      throw new TypeError("connection lost");
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    controller.beginRevoke(GRANT);
    await controller.confirmRevoke();
    expect(controller.state.revoke.kind).toBe("outcome-unknown");
    const before = fetcher.mock.calls.length;

    vi.useFakeTimers();
    try {
      // Ten minutes of virtual time: no interval, no poll, no backoff exists.
      await vi.advanceTimersByTimeAsync(600_000);
      for (let index = 0; index < 50; index += 1) await Promise.resolve();
    } finally {
      vi.useRealTimers();
    }
    expect(fetcher.mock.calls.length).toBe(before);
    expect(postCalls(fetcher)).toHaveLength(1);
    expect(controller.state.revoke.kind).toBe("outcome-unknown");
  });

  it("re-checks with the ORIGINAL mutation id using a GET and mints no new key", async () => {
    let capturedMutationId = "";
    const fetcher = vi.fn(async (path: string, init: RequestInit) => {
      if (init.method === "POST") {
        capturedMutationId = (JSON.parse(String(init.body)) as { mutationId: string }).mutationId;
        throw new TypeError("connection lost");
      }
      if (String(path).includes("/grant-mutations/")) return success({ status: "not_found" });
      return success(grantDetail(grantMetadata()));
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    controller.beginRevoke(GRANT);
    await controller.confirmRevoke();
    const unknown = controller.state.revoke;
    expect(unknown.kind === "outcome-unknown" && unknown.mutationId).toBe(capturedMutationId);

    await controller.checkRevokeStatus();
    const statusCalls = fetcher.mock.calls.filter(([path]) =>
      String(path).includes("/grant-mutations/"),
    );
    expect(statusCalls).toHaveLength(1);
    expect((statusCalls[0]![1] as RequestInit).method).toBe("GET");
    expect(String(statusCalls[0]![0])).toContain(encodeURIComponent(capturedMutationId));
    // Still exactly one POST: a status check never resubmits.
    expect(postCalls(fetcher)).toHaveLength(1);
  });

  it("keeps a not_found status genuinely unknown and never calls it success or failure", async () => {
    const fetcher = vi.fn(async (path: string, init: RequestInit) => {
      if (init.method === "POST") throw new TypeError("connection lost");
      if (String(path).includes("/grant-mutations/")) return success({ status: "not_found" });
      return success(grantDetail(grantMetadata()));
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    controller.beginRevoke(GRANT);
    await controller.confirmRevoke();
    await controller.checkRevokeStatus();

    const revoke = controller.state.revoke;
    expect(revoke.kind).toBe("outcome-unknown");
    if (revoke.kind !== "outcome-unknown") throw new Error("expected unknown");
    expect(revoke.checking).toBe(false);
    expect(revoke.statusMessage).toBe(UNKNOWN_GRANT_STATUS_MESSAGE);
    expect(revoke.statusMessage).toContain("may still complete");
    expect(revoke.statusMessage).toContain("Nothing was resent");
    expect(revokeOutcomeLabel(revoke)).toBe(
      "The outcome is unknown. It is not a success, not a failure, not a refund and not a release.",
    );
    expect(postCalls(fetcher)).toHaveLength(1);
  });

  it("keeps the outcome unknown when the status read itself fails, and still never resends", async () => {
    const fetcher = vi.fn(async (path: string, init: RequestInit) => {
      if (init.method === "POST") throw new TypeError("connection lost");
      if (String(path).includes("/grant-mutations/")) throw new TypeError("still down");
      return success(grantDetail(grantMetadata()));
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    controller.beginRevoke(GRANT);
    await controller.confirmRevoke();
    await controller.checkRevokeStatus();
    await drain();

    const revoke = controller.state.revoke;
    expect(revoke.kind).toBe("outcome-unknown");
    if (revoke.kind !== "outcome-unknown") throw new Error("expected unknown");
    expect(revoke.statusMessage).toBe(UNKNOWN_GRANT_STATUS_MESSAGE);
    expect(postCalls(fetcher)).toHaveLength(1);
    // One status GET, made only because the user asked for it.
    expect(
      fetcher.mock.calls.filter(([path]) => String(path).includes("/grant-mutations/")),
    ).toHaveLength(1);
  });

  it("resolves a recovered commit with an UNKNOWN release, never an implied release", async () => {
    let capturedMutationId = "";
    const fetcher = vi.fn(async (path: string, init: RequestInit) => {
      if (init.method === "POST") {
        capturedMutationId = (JSON.parse(String(init.body)) as { mutationId: string }).mutationId;
        throw new TypeError("connection lost");
      }
      if (String(path).includes("/grant-mutations/")) {
        return success({
          status: "committed",
          receipt: grantReceipt(GRANT, capturedMutationId),
        });
      }
      return success(grantDetail(claimedThenRevokedGrantMetadata()));
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    controller.beginRevoke(GRANT);
    await controller.confirmRevoke();
    await controller.checkRevokeStatus();

    const revoke = controller.state.revoke;
    expect(revoke.kind).toBe("committed");
    if (revoke.kind !== "committed") throw new Error("expected committed");
    // A status receipt carries no release flag and no action status: both stay
    // null and are described as unknown, never as a release or a refund.
    expect(revoke.committed.released).toBeNull();
    expect(revoke.committed.actionStatus).toBeNull();
    expect(revoke.committed.metadata).toBeNull();
    expect(revokeReleaseNotice(revoke.committed)).toBe(GRANT_RELEASE_UNKNOWN_NOTICE);
    expect(GRANT_RELEASE_UNKNOWN_NOTICE).toContain("unknown, not a release and not a refund");
    expect(revokeOutcomeLabel(revoke)).toBe(
      "The server reports this grant was already revoked.",
    );
    expect(postCalls(fetcher)).toHaveLength(1);
  });

  it("does nothing when a status check is asked for outside the unknown state", async () => {
    const fetcher = detailFetcher(grantMetadata());
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    const before = fetcher.mock.calls.length;
    await controller.checkRevokeStatus();
    expect(fetcher.mock.calls.length).toBe(before);
  });
});

describe("grant console secrecy", () => {
  it("never places a raw grant token in any display field or notice", () => {
    const metadataCases = [
      grantMetadata(),
      claimedGrantMetadata(),
      claimedThenRevokedGrantMetadata(),
      expiredGrantMetadata(),
    ].map(asMetadata);
    for (const metadata of metadataCases) {
      for (const now of [NOW_BEFORE_EXPIRY, NOW_AFTER_EXPIRY]) {
        for (const field of grantDisplayFields(metadata, now)) {
          expect(field.value).not.toContain("oag_v1_");
          expect(field.value).not.toContain(FAKE_GRANT_TOKEN);
          expect(field.value).not.toContain("sha256:");
          expect(field.key).not.toMatch(/token|secret|hash|digest|cookie|csrf/iu);
        }
        expect(grantStatusExplanation(metadata, now)).not.toContain("oag_v1_");
      }
    }
    // The field list is a positive allowlist over the accepted metadata, and
    // the accepted metadata has no token key to leak in the first place.
    expect(Object.keys(grantMetadata())).not.toContain("grantToken");
    expect(grantDisplayFields(metadataCases[0]!, NOW_BEFORE_EXPIRY).map((f) => f.key)).toEqual([
      "grantId",
      "status",
      "life",
      "organizationId",
      "subjectAgentId",
      "actionId",
      "reservationId",
      "commerceSessionId",
      "providerId",
      "listingId",
      "listingVersion",
      "generation",
      "issuedAt",
      "expiresAt",
      "updatedAt",
      "claimedAt",
      "revokedAt",
    ]);
  });

  it("keeps the CSRF token, idempotency key and any grant secret out of the controller state", async () => {
    let idempotencyKey = "";
    const fetcher = detailFetcher(claimedThenRevokedGrantMetadata(), (init) => {
      idempotencyKey = (init.headers as Record<string, string>)["Idempotency-Key"]!;
      const mutationId = (JSON.parse(String(init.body)) as { mutationId: string }).mutationId;
      return success(claimedRevokeData(mutationId));
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    controller.beginRevoke(GRANT);
    await controller.confirmRevoke();
    expect(controller.state.revoke.kind).toBe("committed");
    expect(idempotencyKey).toHaveLength(43);

    const serialized = JSON.stringify(controller.state);
    expect(serialized).not.toContain(idempotencyKey);
    expect(serialized).not.toContain(CSRF);
    expect(serialized).not.toContain("csrf");
    expect(serialized).not.toContain("oag_v1_");
    expect(serialized).not.toContain("sha256:");
    expect(serialized.toLowerCase()).not.toContain("authorization:");
    expect(serialized.toLowerCase()).not.toContain("cookie");
  });
});

describe("grant render guards", () => {
  it("does not suppress the first binding", () => {
    expect(
      suppressStaleGrantContext(null, {
        accountId: ACCOUNT_A,
        organizationId: ORG,
        role: "owner",
      }),
    ).toBe(false);
  });

  it("suppresses an account, organization or role change synchronously", () => {
    const bound = { accountId: ACCOUNT_A, organizationId: ORG, role: "owner" };
    expect(suppressStaleGrantContext(bound, { ...bound, accountId: ACCOUNT_B })).toBe(true);
    expect(suppressStaleGrantContext(bound, { ...bound, organizationId: ORG_B })).toBe(true);
    expect(suppressStaleGrantContext(bound, { ...bound, role: "viewer" })).toBe(true);
    expect(suppressStaleGrantContext(bound, { ...bound, accountId: null })).toBe(true);
    expect(suppressStaleGrantContext(bound, bound)).toBe(false);
  });

  it("substitutes the initial state while suppressed", async () => {
    const fetcher = detailFetcher(grantMetadata());
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    expect(renderGrantState(false, controller.state).detail.item?.grantId).toBe(GRANT);
    expect(renderGrantState(true, controller.state)).toEqual(initialGrantControllerState());
  });

  it("clears every detail, lookup and revoke artifact on clear and dispose", async () => {
    const fetcher = detailFetcher(grantMetadata());
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    controller.selectLookupGrantId(GRANT_B);
    controller.clear();
    expect(controller.state.detail).toEqual(initialGrantControllerState().detail);
    expect(controller.state.lookupGrantId).toBeNull();
    expect(controller.state.revoke).toEqual({ kind: "idle" });
    controller.dispose();
    expect(controller.disposed).toBe(true);
    expect(controller.state.detail.item).toBeNull();
    // A disposed controller accepts nothing further.
    expect(controller.beginRevoke(GRANT)).toBe(false);
  });

  it("clears everything when the role changes", async () => {
    const fetcher = detailFetcher(grantMetadata());
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", grantId: GRANT });
    expect(controller.state.detail.item?.grantId).toBe(GRANT);
    controller.reconcileRole("viewer");
    expect(controller.state.detail.item).toBeNull();
  });
});
