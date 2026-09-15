import type { CommerceHumanRole } from "@openarc/shared";
import { describe, expect, it, vi } from "vitest";

import type { AccountFlowController } from "../src/account/flow-controller.js";
import { ActionClient } from "../src/tenant/action-client.js";
import {
  ACTION_CURSOR_STACK_LIMIT,
  ActionController,
  appendActionCursor,
  actionDisplayFields,
  actionStatusExplanation,
  actionStatusLabel,
  approvalStatusLabel,
  canDecideActions,
  canReadActions,
  decisionOutcomeLabel,
  decisionSummary,
  exposureRows,
  formatAtomicAmount,
  initialActionControllerState,
  renderActionState,
  suppressStaleActionContext,
  type ActionReadCoordinator,
} from "../src/tenant/action-controller.js";
import {
  ACCOUNT_A,
  ACCOUNT_B,
  ACTION,
  ACTION_B,
  AGENT,
  APPROVAL,
  DIGEST,
  ORG,
  ORG_B,
  POLICY,
  actionMetadata,
  actionReceipt,
  approvalMetadata,
  errorEnvelope,
  exposureData,
  exposureView,
  success,
} from "./action-test-fixtures.js";

const CSRF = "csrf-from-bootstrap";

function fakeReads(
  role: CommerceHumanRole | null = "owner",
  organizationId: string | null = ORG,
): ActionReadCoordinator & { abortCalls: number } {
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
  const controller = new ActionController({
    account,
    reads,
    client: new ActionClient({ fetcher: fetcher as typeof fetch }),
    capabilityReader: async () => options.capability ?? "enabled",
  });
  return { controller, reads };
}

function bodyMutationId(init: RequestInit): string {
  return (JSON.parse(String(init.body)) as { mutationId: string }).mutationId;
}

describe("action role matrix", () => {
  it("lets owner, operator and viewer read; only owner and operator may decide", () => {
    for (const role of ["owner", "operator"] as const) {
      expect(canReadActions(role)).toBe(true);
      expect(canDecideActions(role)).toBe(true);
    }
    expect(canReadActions("viewer")).toBe(true);
    expect(canDecideActions("viewer")).toBe(false);
    for (const role of ["provider_admin", "provider_developer", null, "unknown"] as const) {
      expect(canReadActions(role)).toBe(false);
      expect(canDecideActions(role)).toBe(false);
    }
  });

  it("grants a viewer read access but refuses the decision without any request", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, items: [actionMetadata(ACTION)], nextCursor: ACTION }),
    );
    const { controller } = controllerWith(fetcher, { role: "viewer" });
    await controller.initialize({ kind: "queue" });
    expect(controller.state.canRead).toBe(true);
    expect(controller.state.canDecide).toBe(false);
    expect(controller.state.actions.items).toHaveLength(1);
    const readCalls = fetcher.mock.calls.length;

    expect(controller.beginDecision("approve", ACTION)).toBe(false);
    expect(controller.state.decision).toEqual({
      kind: "rejected",
      notice: { kind: "no-access" },
    });
    expect(fetcher.mock.calls.length).toBe(readCalls);
  });

  it("refuses every read and decision for a recovery sign-in", async () => {
    const fetcher = vi.fn();
    const { controller } = controllerWith(fetcher, {
      account: fakeAccount(ACCOUNT_A, "recovery"),
    });
    await controller.initialize({ kind: "queue" });
    expect(controller.state.canRead).toBe(false);
    expect(controller.state.canDecide).toBe(false);
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("action capability gate", () => {
  it("renders an honest unavailable state and makes zero action requests when disabled", async () => {
    for (const capability of ["built_disabled", "unavailable"] as const) {
      const fetcher = vi.fn();
      const { controller } = controllerWith(fetcher, { capability });
      await controller.initialize({ kind: "queue" });
      expect(controller.state.capability).toBe("unavailable");
      expect(controller.state.actions.status).toBe("none");
      expect(controller.state.actions.items).toEqual([]);
      expect(fetcher).not.toHaveBeenCalled();
    }
  });

  it("reports unavailable rather than an empty queue when the probe itself fails", async () => {
    const fetcher = vi.fn();
    const controller = new ActionController({
      account: fakeAccount(),
      reads: fakeReads(),
      client: new ActionClient({ fetcher: fetcher as unknown as typeof fetch }),
      capabilityReader: async () => {
        throw new Error("probe down");
      },
    });
    await controller.initialize({ kind: "queue" });
    expect(controller.state.capability).toBe("unavailable");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("refuses a decision outright while the capability is not enabled", async () => {
    const fetcher = vi.fn();
    const { controller } = controllerWith(fetcher, { capability: "built_disabled" });
    await controller.initialize({ kind: "detail", actionId: ACTION });
    expect(controller.beginDecision("approve", ACTION)).toBe(false);
    expect(controller.state.decision).toEqual({
      kind: "rejected",
      notice: { kind: "capability-disabled" },
    });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("makes no request for an invalid route", async () => {
    const fetcher = vi.fn();
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "invalid" });
    expect(controller.state.selection.route).toEqual({ kind: "invalid" });
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("action queue pagination", () => {
  it("loads one bounded page, then the next page by cursor, replacing the rows", async () => {
    const fetcher = vi.fn(async (path: string) =>
      path.includes("afterActionId")
        ? success({ organizationId: ORG, items: [actionMetadata(ACTION_B)], nextCursor: null })
        : success({ organizationId: ORG, items: [actionMetadata(ACTION)], nextCursor: ACTION }),
    );
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "queue" });
    expect(controller.state.actions.items.map((item) => item.actionId)).toEqual([ACTION]);
    expect(controller.state.actions.nextCursor).toBe(ACTION);

    await controller.loadNextActions();
    // The page REPLACES the previous page; it never accumulates.
    expect(controller.state.actions.items.map((item) => item.actionId)).toEqual([ACTION_B]);
    expect(controller.state.actions.nextCursor).toBeNull();
    expect(controller.state.actions.hasPrevious).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("never auto-loads a further page when a cursor exists", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, items: [actionMetadata(ACTION)], nextCursor: ACTION }),
    );
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "queue" });
    expect(controller.state.actions.nextCursor).toBe(ACTION);
    // No timer, no follow-up: exactly one page was fetched.
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("does not request a next page when there is no cursor", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, items: [], nextCursor: null }),
    );
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "queue" });
    await controller.loadNextActions();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("surfaces a load failure as an explicit error, never as an empty queue", async () => {
    const fetcher = vi.fn(async () => errorEnvelope("INTERNAL_ERROR", 500));
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "queue" });
    expect(controller.state.actions.status).toBe("error");
    expect(controller.state.actions.items).toEqual([]);
  });

  it("pages the approval queue with its own bounded cursor", async () => {
    const fetcher = vi.fn(async (path: string) =>
      path.includes("afterApprovalId")
        ? success({ organizationId: ORG, items: [], nextCursor: null })
        : success({
            organizationId: ORG,
            items: [approvalMetadata(APPROVAL)],
            nextCursor: APPROVAL,
          }),
    );
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "approvals" });
    expect(controller.state.approvals.items).toHaveLength(1);
    await controller.loadNextApprovals();
    expect(controller.state.approvals.items).toEqual([]);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("bounds the previous-page cursor stack to 20 entries", () => {
    let stack: readonly string[] = [];
    for (let index = 0; index < 30; index += 1) {
      stack = appendActionCursor(stack, `cursor-${index}`);
    }
    expect(stack).toHaveLength(ACTION_CURSOR_STACK_LIMIT);
    expect(stack[stack.length - 1]).toBe("cursor-29");
  });
});

describe("action and approval detail", () => {
  it("reports a missing action as not-found rather than inventing one", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, actionId: ACTION, item: null }),
    );
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", actionId: ACTION });
    expect(controller.state.detail.status).toBe("not-found");
    expect(controller.state.detail.item).toBeNull();
  });

  it("loads one approval by approvalId", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, approvalId: APPROVAL, item: approvalMetadata(APPROVAL) }),
    );
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "approval-detail", approvalId: APPROVAL });
    expect(controller.state.approvalDetail.status).toBe("ready");
    expect(controller.state.approvalDetail.item?.approvalId).toBe(APPROVAL);
  });
});

describe("exposure values", () => {
  it("places the decimal separator by exact string position, never by float maths", () => {
    expect(formatAtomicAmount("1750000", 6)).toBe("1.750000");
    expect(formatAtomicAmount("1", 6)).toBe("0.000001");
    expect(formatAtomicAmount("0", 6)).toBe("0.000000");
    expect(formatAtomicAmount("123", 0)).toBe("123");
    // A value far beyond IEEE-754 exact integer range survives digit for digit.
    const huge = "123456789012345678901234567890123";
    expect(formatAtomicAmount(huge, 6)).toBe("123456789012345678901234567.890123");
    // A float round-trip would have lost digits here; assert it did not.
    expect(formatAtomicAmount(huge, 6)?.replace(".", "")).toBe(huge);
  });

  it("refuses a non-canonical amount instead of guessing a number", () => {
    for (const bad of ["1.5", "01", "-1", "", " 1", "1e3", "abc"]) {
      expect(formatAtomicAmount(bad, 6)).toBeNull();
    }
    expect(formatAtomicAmount("1", -1)).toBeNull();
    expect(formatAtomicAmount("1", 1.5)).toBeNull();
  });

  it("renders available, reserved, committed, total and deficit exactly as sent", async () => {
    const fetcher = vi.fn(async () => success(exposureData()));
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "exposure" });
    // The exposure route issues nothing until an explicit subject is supplied.
    expect(fetcher).not.toHaveBeenCalled();

    await controller.loadExposure(AGENT, POLICY);
    const item = controller.state.exposure.item;
    expect(item).not.toBeNull();
    const rows = exposureRows(item!);
    const byKey = Object.fromEntries(rows.map((row) => [row.key, row]));
    expect(byKey.available!.atomic).toBe("8750000");
    expect(byKey.available!.display).toBe("8.750000");
    expect(byKey.unresolved!.atomic).toBe("250000");
    expect(byKey.unresolved!.display).toBe("0.250000");
    expect(byKey.committed!.atomic).toBe("1000000");
    expect(byKey.committed!.display).toBe("1.000000");
    expect(byKey.total!.atomic).toBe("1250000");
    expect(byKey.deficit!.atomic).toBe("0");
    for (const row of rows) {
      expect(row.atomic === null || typeof row.atomic === "string").toBe(true);
    }
  });

  it("states a null available as no rolling cap instead of a zero balance", async () => {
    const fetcher = vi.fn(async () =>
      success(
        exposureData(
          exposureView({ availableAtomic: null, deficitAtomic: "0", windowSeconds: null }),
        ),
      ),
    );
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "exposure" });
    await controller.loadExposure(AGENT, POLICY);
    const rows = exposureRows(controller.state.exposure.item!);
    const available = rows.find((row) => row.key === "available")!;
    expect(available.atomic).toBeNull();
    expect(available.display).toBeNull();
    expect(available.explanation).toContain("no rolling cap");
  });

  it("refuses a malformed agent or policy before any exposure request", async () => {
    const fetcher = vi.fn();
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "exposure" });
    await controller.loadExposure("not-an-agent", POLICY);
    expect(controller.state.exposure.status).toBe("error");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("never claims a paid, settled, delivered or purchased state in any label", () => {
    const forbidden = /\b(paid|settled|delivered|purchased)\b/iu;
    const statuses = [
      "pending_approval",
      "reserved_not_granted",
      "grant_issued",
      "rejected",
      "cancelled",
      "expired",
      "made-up",
    ];
    for (const status of statuses) {
      expect(actionStatusLabel(status)).not.toMatch(forbidden);
      // An explanation may only ever DENY those words ("nothing has been
      // paid"), never assert them. The lookbehind excludes the denial form.
      expect(actionStatusExplanation(status)).not.toMatch(
        /(?<!nothing )\b(?:was|is|has been)\s+(?:paid|settled|delivered|purchased)\b/iu,
      );
    }
    for (const status of ["pending", "approved", "rejected", "expired", "made-up"]) {
      expect(approvalStatusLabel(status)).not.toMatch(forbidden);
    }
    for (const decision of ["approve", "reject", "cancel"] as const) {
      expect(decisionSummary(decision)).not.toMatch(
        /\b(?:pays|settles|delivers|purchases)\b/iu,
      );
    }
    expect(actionStatusLabel("something-new")).toBe("Unknown");
    expect(approvalStatusLabel("something-new")).toBe("Unknown");
  });
});

describe("action decisions", () => {
  function decisionFetcher(operation: string) {
    return vi.fn(async (path: string, init: RequestInit) => {
      if (init.method === "POST") {
        return success({
          replayed: false,
          metadata: actionMetadata(ACTION, { status: operation.endsWith("approve") ? "reserved_not_granted" : "rejected", reservationId: operation.endsWith("approve") ? `openarc:reservation:12345678-1234-4234-8123-123456789abc` : null }),
          receipt: actionReceipt(operation, ACTION, bodyMutationId(init)),
        });
      }
      return success({ organizationId: ORG, actionId: ACTION, item: actionMetadata(ACTION) });
    });
  }

  it("requires an explicit confirmation before anything is sent", async () => {
    const fetcher = decisionFetcher("control.commerce_action.approve");
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", actionId: ACTION });
    const before = fetcher.mock.calls.length;
    expect(controller.beginDecision("approve", ACTION)).toBe(true);
    expect(controller.state.decision.kind).toBe("confirming");
    expect(fetcher.mock.calls.length).toBe(before);

    controller.cancelDecision();
    expect(controller.state.decision).toEqual({ kind: "idle" });
    expect(fetcher.mock.calls.length).toBe(before);
  });

  it("commits approve, reject and cancel, each with exactly one POST", async () => {
    for (const [decision, operation] of [
      ["approve", "control.commerce_action.approve"],
      ["reject", "control.commerce_action.reject"],
      ["cancel", "control.commerce_action.cancel"],
    ] as const) {
      const fetcher = decisionFetcher(operation);
      const { controller } = controllerWith(fetcher);
      await controller.initialize({ kind: "detail", actionId: ACTION });
      controller.beginDecision(decision, ACTION);
      await controller.confirmDecision();
      expect(controller.state.decision.kind).toBe("committed");
      const posts = fetcher.mock.calls.filter(
        ([, init]) => (init as RequestInit).method === "POST",
      );
      expect(posts).toHaveLength(1);
      expect(String(posts[0]![0])).toContain(`/${decision === "cancel" ? "cancel" : decision}`);
    }
  });

  it("describes a committed decision without implying a payment or settlement", async () => {
    const fetcher = decisionFetcher("control.commerce_action.approve");
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", actionId: ACTION });
    controller.beginDecision("approve", ACTION);
    await controller.confirmDecision();
    const label = decisionOutcomeLabel(controller.state.decision);
    expect(label).toContain("committed");
    expect(label).not.toMatch(/\b(paid|settled|delivered|purchased|refund)\b/iu);
  });

  it("disables the decision controls after a server denial instead of trusting the local role", async () => {
    const fetcher = vi.fn(async (path: string, init: RequestInit) =>
      init.method === "POST"
        ? errorEnvelope("FORBIDDEN", 403)
        : success({ organizationId: ORG, actionId: ACTION, item: actionMetadata(ACTION) }),
    );
    const { controller } = controllerWith(fetcher, { role: "owner" });
    await controller.initialize({ kind: "detail", actionId: ACTION });
    expect(controller.state.canDecide).toBe(true);

    controller.beginDecision("approve", ACTION);
    await controller.confirmDecision();
    expect(controller.state.decision).toEqual({
      kind: "rejected",
      notice: { kind: "forbidden" },
    });
    expect(controller.state.serverDeniedDecision).toBe(true);
    expect(controller.state.canDecide).toBe(false);

    // A second attempt is refused locally without another POST.
    const posts = () =>
      fetcher.mock.calls.filter(([, init]) => (init as RequestInit).method === "POST").length;
    const before = posts();
    expect(controller.beginDecision("approve", ACTION)).toBe(false);
    expect(posts()).toBe(before);
  });

  it("clears the server denial only on an explicit context change", async () => {
    const fetcher = vi.fn(async (path: string, init: RequestInit) =>
      init.method === "POST"
        ? errorEnvelope("FORBIDDEN", 403)
        : success({ organizationId: ORG, actionId: ACTION, item: actionMetadata(ACTION) }),
    );
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", actionId: ACTION });
    controller.beginDecision("approve", ACTION);
    await controller.confirmDecision();
    expect(controller.state.serverDeniedDecision).toBe(true);
    controller.clear();
    expect(controller.state.serverDeniedDecision).toBe(false);
    expect(controller.state.decision).toEqual({ kind: "idle" });
  });

  it("maps a policy refusal and a conflict to their own honest notices", async () => {
    for (const [code, status, kind] of [
      ["APPROVAL_REQUIRED", 403, "policy"],
      ["IDEMPOTENCY_CONFLICT", 409, "conflict"],
      ["CSRF_REJECTED", 403, "csrf"],
    ] as const) {
      const fetcher = vi.fn(async (path: string, init: RequestInit) =>
        init.method === "POST"
          ? errorEnvelope(code, status)
          : success({ organizationId: ORG, actionId: ACTION, item: actionMetadata(ACTION) }),
      );
      const { controller } = controllerWith(fetcher);
      await controller.initialize({ kind: "detail", actionId: ACTION });
      controller.beginDecision("reject", ACTION);
      await controller.confirmDecision();
      expect(controller.state.decision).toEqual({ kind: "rejected", notice: { kind } });
    }
  });
});

describe("lost-response recovery", () => {
  it("offers only an explicit status re-check after a lost response and issues no automatic retry", async () => {
    const fetcher = vi.fn(async (path: string, init: RequestInit) => {
      if (init.method === "POST") throw new TypeError("connection lost");
      return success({ organizationId: ORG, actionId: ACTION, item: actionMetadata(ACTION) });
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", actionId: ACTION });
    const readsBefore = fetcher.mock.calls.length;

    controller.beginDecision("approve", ACTION);
    await controller.confirmDecision();

    const decision = controller.state.decision;
    expect(decision.kind).toBe("outcome-unknown");
    // Exactly ONE POST was attempted and nothing followed it on its own.
    const posts = fetcher.mock.calls.filter(
      ([, init]) => (init as RequestInit).method === "POST",
    );
    expect(posts).toHaveLength(1);
    expect(fetcher.mock.calls.length).toBe(readsBefore + 1);

    // Let any stray timer/microtask fire: still nothing is resent.
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(
      fetcher.mock.calls.filter(([, init]) => (init as RequestInit).method === "POST"),
    ).toHaveLength(1);
    expect(fetcher.mock.calls.length).toBe(readsBefore + 1);
  });

  it("re-checks with the ORIGINAL mutation id using a GET and mints no new key", async () => {
    let capturedMutationId = "";
    const fetcher = vi.fn(async (path: string, init: RequestInit) => {
      if (init.method === "POST") {
        capturedMutationId = bodyMutationId(init);
        throw new TypeError("connection lost");
      }
      if (path.includes("/action-mutations/")) return success({ status: "not_found" });
      return success({ organizationId: ORG, actionId: ACTION, item: actionMetadata(ACTION) });
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", actionId: ACTION });
    controller.beginDecision("approve", ACTION);
    await controller.confirmDecision();
    const unknown = controller.state.decision;
    expect(unknown.kind === "outcome-unknown" && unknown.mutationId).toBe(capturedMutationId);

    await controller.checkDecisionStatus();
    const statusCalls = fetcher.mock.calls.filter(([path]) =>
      String(path).includes("/action-mutations/"),
    );
    expect(statusCalls).toHaveLength(1);
    expect((statusCalls[0]![1] as RequestInit).method).toBe("GET");
    expect(String(statusCalls[0]![0])).toContain(encodeURIComponent(capturedMutationId));
    // Still exactly one POST: a status check never resubmits.
    expect(
      fetcher.mock.calls.filter(([, init]) => (init as RequestInit).method === "POST"),
    ).toHaveLength(1);
  });

  it("keeps a not_found status genuinely unknown and never calls it success or failure", async () => {
    const fetcher = vi.fn(async (path: string, init: RequestInit) => {
      if (init.method === "POST") throw new TypeError("connection lost");
      if (path.includes("/action-mutations/")) return success({ status: "not_found" });
      return success({ organizationId: ORG, actionId: ACTION, item: actionMetadata(ACTION) });
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", actionId: ACTION });
    controller.beginDecision("cancel", ACTION);
    await controller.confirmDecision();
    await controller.checkDecisionStatus();

    const decision = controller.state.decision;
    expect(decision.kind).toBe("outcome-unknown");
    if (decision.kind !== "outcome-unknown") throw new Error("unreachable");
    expect(decision.checking).toBe(false);
    expect(decision.statusMessage).toContain("may still complete");
    const label = decisionOutcomeLabel(decision);
    // The label must say "unknown" and must explicitly deny every optimistic
    // reading; it must never assert one.
    expect(label).toContain("unknown");
    expect(label).toContain("not a success");
    expect(label).toContain("not a failure");
    expect(label).toContain("not a refund");
    expect(label).toContain("not a release");
    expect(label).not.toMatch(/\b(succeeded|completed|paid|settled|delivered|purchased)\b/iu);
  });

  it("resolves an unknown outcome to committed only when the server returns a bound receipt", async () => {
    const fetcher = vi.fn(async (path: string, init: RequestInit) => {
      if (init.method === "POST") throw new TypeError("connection lost");
      if (path.includes("/action-mutations/")) {
        const mutationId = decodeURIComponent(String(path).split("/action-mutations/")[1]!);
        return success({
          status: "committed",
          receipt: actionReceipt("control.commerce_action.approve", ACTION, mutationId),
        });
      }
      return success({ organizationId: ORG, actionId: ACTION, item: actionMetadata(ACTION) });
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", actionId: ACTION });
    controller.beginDecision("approve", ACTION);
    await controller.confirmDecision();
    await controller.checkDecisionStatus();

    const decision = controller.state.decision;
    expect(decision.kind).toBe("committed");
    if (decision.kind !== "committed") throw new Error("unreachable");
    expect(decision.committed.replayed).toBe(true);
    expect(decision.committed.receipt.resourceId).toBe(ACTION);
    // The status check itself is still the only extra request; no POST repeat.
    expect(
      fetcher.mock.calls.filter(([, init]) => (init as RequestInit).method === "POST"),
    ).toHaveLength(1);
  });

  it("does not re-check anything when there is no unknown outcome", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, actionId: ACTION, item: actionMetadata(ACTION) }),
    );
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", actionId: ACTION });
    const before = fetcher.mock.calls.length;
    await controller.checkDecisionStatus();
    expect(fetcher.mock.calls.length).toBe(before);
  });
});

describe("action console secrecy", () => {
  it("never renders the requirement digest in any displayed field", () => {
    const metadata = actionMetadata(ACTION) as unknown as Parameters<
      typeof actionDisplayFields
    >[0];
    const fields = actionDisplayFields(metadata);
    expect(fields.length).toBeGreaterThan(0);
    for (const field of fields) {
      expect(field.value).not.toContain(DIGEST);
      expect(field.value).not.toContain("sha256:");
      expect(field.key).not.toBe("requirementDigest");
    }
    // The digest is present on the record itself, so this is a real omission.
    expect(metadata.requirementDigest).toBe(DIGEST);
  });

  it("keeps the CSRF token and idempotency key out of the controller state entirely", async () => {
    let idempotencyKey = "";
    const fetcher = vi.fn(async (path: string, init: RequestInit) => {
      if (init.method === "POST") {
        idempotencyKey = (init.headers as Record<string, string>)["Idempotency-Key"]!;
        return success({
          replayed: false,
          metadata: actionMetadata(ACTION),
          receipt: actionReceipt("control.commerce_action.approve", ACTION, bodyMutationId(init)),
        });
      }
      return success({ organizationId: ORG, actionId: ACTION, item: actionMetadata(ACTION) });
    });
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "detail", actionId: ACTION });
    controller.beginDecision("approve", ACTION);
    await controller.confirmDecision();
    expect(controller.state.decision.kind).toBe("committed");
    expect(idempotencyKey).toHaveLength(43);

    const serialized = JSON.stringify(controller.state);
    expect(serialized).not.toContain(idempotencyKey);
    expect(serialized).not.toContain(CSRF);
    expect(serialized).not.toContain("csrf");
    expect(serialized.toLowerCase()).not.toContain("authorization");
  });
});

describe("action render guards", () => {
  it("does not suppress the first binding", () => {
    expect(
      suppressStaleActionContext(null, {
        accountId: ACCOUNT_A,
        organizationId: ORG,
        role: "owner",
      }),
    ).toBe(false);
  });

  it("suppresses an account, organization or role change synchronously", () => {
    const bound = { accountId: ACCOUNT_A, organizationId: ORG, role: "owner" };
    expect(
      suppressStaleActionContext(bound, { ...bound, accountId: ACCOUNT_B }),
    ).toBe(true);
    expect(
      suppressStaleActionContext(bound, { ...bound, organizationId: ORG_B }),
    ).toBe(true);
    expect(suppressStaleActionContext(bound, { ...bound, role: "viewer" })).toBe(true);
    expect(suppressStaleActionContext(bound, { ...bound, accountId: null })).toBe(true);
    expect(suppressStaleActionContext(bound, bound)).toBe(false);
  });

  it("substitutes the initial state while suppressed", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, items: [actionMetadata(ACTION)], nextCursor: ACTION }),
    );
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "queue" });
    expect(renderActionState(false, controller.state).actions.items).toHaveLength(1);
    expect(renderActionState(true, controller.state)).toEqual(initialActionControllerState());
  });

  it("clears every queue, detail, exposure and decision artifact on clear and dispose", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, items: [actionMetadata(ACTION)], nextCursor: ACTION }),
    );
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "queue" });
    controller.clear();
    expect(controller.state.actions).toEqual(initialActionControllerState().actions);
    expect(controller.state.exposure).toEqual(initialActionControllerState().exposure);
    expect(controller.state.decision).toEqual({ kind: "idle" });
    controller.dispose();
    expect(controller.disposed).toBe(true);
    expect(controller.state.actions.items).toEqual([]);
  });

  it("clears everything when the role changes", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, items: [actionMetadata(ACTION)], nextCursor: ACTION }),
    );
    const { controller } = controllerWith(fetcher);
    await controller.initialize({ kind: "queue" });
    expect(controller.state.actions.items).toHaveLength(1);
    controller.reconcileRole("viewer");
    expect(controller.state.actions.items).toEqual([]);
  });
});
