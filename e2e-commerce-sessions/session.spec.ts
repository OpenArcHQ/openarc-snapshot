import { expect, test, type Page } from "@playwright/test";

// Protected commerce-session journeys (Chromium + WebKit).
//
// Every account, tenant read, session capability and session read/write/status
// endpoint is intercepted with strict synthetic HTTP fixtures. These are
// honestly labelled UI CONTRACT tests: they prove the UI and transport contract
// only. They are NOT proof of a live API, PostgreSQL, a fresh passkey proof,
// TLS, the production nginx proxy, a wallet or any payment behavior.
//
// The server runs with tenant reads ON while tenant writes, machine
// credentials, listing management and policy management are OFF, proving
// commerce sessions are independent of all of them.

const META = {
  schemaVersion: "openarc.api.v2",
  requestId: "018f47a2-3b4c-7def-8123-456789abcdef",
  buildSha: "0123456789abcdef0123456789abcdef01234567",
};

const UUID = "12345678-1234-4234-8123-123456789abc";
const UUID_B = "87654321-4321-4321-b123-abcdefabcdef";
const ORG_A = `openarc:org:${UUID}`;
const ORG_B = `openarc:org:${UUID_B}`;
const ACCOUNT_A = `openarc:account:${UUID}`;
const AGENT_A = `openarc:agent:${UUID}`;
const AGENT_B = `openarc:agent:${UUID_B}`;
const POLICY_A = `openarc:policy:${UUID}`;
const SESSION_A = UUID;
const SESSION_B = UUID_B;
// The synthetic fixtures use a FUTURE issued/expiry window so the browser's
// local one-time-secret expiry timer (which only erases a local copy and never
// claims server authority) does not erase a fresh handoff before the explicit
// reveal assertions can observe it. The server response metadata remains the
// single source of the expiry instant.
const CREATED = "2031-01-01T00:00:00.000Z";
const EXCHANGED = "2031-01-01T00:01:00.000Z";
const ISSUED6 = "2031-01-01T00:00:00.000000Z";
const EXPIRES6 = "2031-01-01T00:15:00.000000Z";
const HANDOFF_EXPIRES = "2031-01-01T00:05:00.000Z";
const HANDOFF = `oach_v1_${"A".repeat(42)}A`;

function envelope(data: unknown): string {
  return JSON.stringify({ ok: true, data, meta: META });
}

function organization(organizationId: string, index = 0) {
  return {
    schemaVersion: "openarc.organization.v1",
    organizationId,
    displayName: `Organization ${index}`,
    createdAt: CREATED,
    updatedAt: CREATED,
  };
}

function context(role: string, organizationId = ORG_A) {
  return {
    organization: organization(organizationId),
    access: {
      schemaVersion: "openarc.organization-access.v1",
      organizationId,
      accountId: ACCOUNT_A,
      role,
      membershipStatus: "active",
      sessionExpiresAt: "2030-01-01T00:00:00.000Z",
    },
    network: "eip155:5042002",
  };
}

function agent(agentId = AGENT_A, status = "active") {
  return {
    schemaVersion: "openarc.agent-profile.v1",
    agentId,
    organizationId: ORG_A,
    displayName: "Support Agent",
    status,
    createdAt: CREATED,
    updatedAt: CREATED,
  };
}

function sessionMetadata(sessionId = SESSION_A, overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: "openarc.control.commerce-session.v1",
    sessionId,
    organizationId: ORG_A,
    subjectAgentId: AGENT_A,
    policyId: POLICY_A,
    scopes: ["commerce.authorize"],
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    issuedAt: ISSUED6,
    expiresAt: EXPIRES6,
    exchangedAt: null,
    revokedAt: null,
    ...overrides,
  };
}

function statusItem(sessionId = SESSION_A, status = "handoff_pending", overrides: Record<string, unknown> = {}) {
  return { metadata: sessionMetadata(sessionId, overrides), status };
}

function receipt(operation: string, resourceId: string, mutationId: string) {
  return { mutationId, operation, resourceType: "commerce_session", resourceId, committedAt: CREATED };
}

// The exact frozen session capability manifest: two families / seven routes.
const SESSION_CAPABILITY_MANIFEST = {
  capabilityVersion: "openarc.capabilities.commerce-sessions.v1",
  environment: "testnet",
  network: "eip155:5042002",
  capabilities: [
    {
      family: "commerce_session_management",
      audience: "browser",
      state: "enabled",
      dependencies: ["auth", "tenantDatabase", "machineDatabase", "policyDatabase", "commerceSessionDatabase"],
    },
    {
      family: "commerce_session_exchange",
      audience: "agent",
      state: "enabled",
      dependencies: ["auth", "tenantDatabase", "machineDatabase", "policyDatabase", "commerceSessionDatabase"],
    },
  ],
  routes: [
    { id: "commerce_session_list", family: "commerce_session_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/commerce-sessions" },
    { id: "commerce_session_issue", family: "commerce_session_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/commerce-sessions" },
    { id: "commerce_session_status", family: "commerce_session_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/commerce-sessions/:sessionId" },
    { id: "commerce_session_revoke", family: "commerce_session_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/commerce-sessions/:sessionId/revoke" },
    { id: "commerce_session_human_mutation_status", family: "commerce_session_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/commerce-session-mutations/:mutationId" },
    { id: "commerce_session_exchange", family: "commerce_session_exchange", audience: "agent", method: "POST", path: "/v2/agent/commerce-sessions/exchange" },
    { id: "commerce_session_agent_mutation_status", family: "commerce_session_exchange", audience: "agent", method: "GET", path: "/v2/agent/commerce-session-mutations/:mutationId" },
  ],
};

function capabilityManifest(state = "enabled") {
  return {
    ...SESSION_CAPABILITY_MANIFEST,
    capabilities: SESSION_CAPABILITY_MANIFEST.capabilities.map((entry) => ({ ...entry, state })),
  };
}

async function stubSession(page: Page, role = "owner"): Promise<void> {
  await page.route("**/v2/auth/session", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({ session: { signedIn: true, accountId: ACCOUNT_A, method: "passkey", expiresAt: "2030-01-01T00:00:00.000Z" } }),
    });
  });
  await page.route("**/v2/auth/bootstrap", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({
        csrfToken: "csrf-from-bootstrap",
        session: { signedIn: true, accountId: ACCOUNT_A, method: "passkey", expiresAt: "2030-01-01T00:00:00.000Z" },
      }),
    });
  });
  await page.route("**/v2/public/session-capabilities", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope(capabilityManifest("enabled")) });
  });
  await page.route("**/v1/operator/organizations?*", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope({ items: [organization(ORG_A)], nextCursor: null }) });
  });
  await page.route("**/v1/operator/organizations", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope({ items: [organization(ORG_A)], nextCursor: null }) });
  });
  await page.route("**/v1/operator/organizations/*/agents*", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope({ organizationId: ORG_A, items: [agent()], nextCursor: null }) });
  });
  await page.route("**/v1/operator/organizations/*", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (route.request().method() !== "GET" || /\/(agents|providers)/u.test(path)) {
      await route.fallback();
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope(context(role)) });
  });
}

interface SessionFixtureState {
  readonly items?: Array<{ sessionId: string; status: string; revokedAt?: string | null; exchangedAt?: string | null }>;
  readonly capability?: "enabled" | "built_disabled" | "unavailable";
  readonly writeStatus?: number;
  readonly failRefresh?: boolean;
  readonly replayNoSecret?: boolean;
}

async function stubSessionRoutes(page: Page, state: SessionFixtureState): Promise<void> {
  await page.route("**/v2/public/session-capabilities", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope(capabilityManifest(state.capability ?? "enabled")),
    });
  });
  await page.route("**/v2/control/organizations/*/commerce-session-mutations/*", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope({ organizationId: ORG_A, mutationId: UUID, status: "not_found" }) });
  });
  await page.route("**/v2/control/organizations/*/commerce-sessions?*", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({
        organizationId: ORG_A,
        items: (state.items ?? []).map((item) => statusItem(item.sessionId, item.status, {
          ...(item.revokedAt === undefined ? {} : { revokedAt: item.revokedAt }),
          ...(item.exchangedAt === undefined ? {} : { exchangedAt: item.exchangedAt }),
        })),
        nextCursor: null,
      }),
    });
  });
  await page.route("**/v2/control/organizations/*/commerce-sessions", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: envelope({ organizationId: ORG_A, items: (state.items ?? []).map((item) => statusItem(item.sessionId, item.status)), nextCursor: null }),
      });
      return;
    }
    if (state.writeStatus !== undefined && state.writeStatus >= 400) {
      await route.fulfill({ status: state.writeStatus, contentType: "application/json", body: "{}" });
      return;
    }
    const body = JSON.parse(route.request().postData() ?? "{}") as { mutationId: string };
    const created = state.items?.[0]?.sessionId ?? SESSION_B;
    if (state.replayNoSecret === true) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: envelope({
          organizationId: ORG_A,
          replayed: true,
          metadata: sessionMetadata(created),
          receipt: receipt("control.commerce_session.issue", created, body.mutationId),
          delivery: { state: "not_replayable" },
        }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({
        organizationId: ORG_A,
        replayed: false,
        metadata: sessionMetadata(created),
        receipt: receipt("control.commerce_session.issue", created, body.mutationId),
        delivery: { state: "available_once", handoffToken: HANDOFF, handoffExpiresAt: HANDOFF_EXPIRES },
      }),
    });
  });
  await page.route("**/v2/control/organizations/*/commerce-sessions/*/revoke", async (route) => {
    const body = JSON.parse(route.request().postData() ?? "{}") as { mutationId: string };
    const path = new URL(route.request().url()).pathname.split("/");
    const sessionId = decodeURIComponent(path.at(-2) ?? SESSION_A);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({
        organizationId: ORG_A,
        replayed: false,
        metadata: sessionMetadata(sessionId, { revokedAt: CREATED }),
        receipt: receipt("control.commerce_session.revoke", sessionId, body.mutationId),
      }),
    });
  });
  await page.route("**/v2/control/organizations/*/commerce-sessions/*", async (route) => {
    if (route.request().method() !== "GET") {
      await route.fallback();
      return;
    }
    if (state.failRefresh === true) {
      await route.fulfill({ status: 500, contentType: "application/json", body: "{}" });
      return;
    }
    const path = new URL(route.request().url()).pathname.split("/");
    const sessionId = decodeURIComponent(path.at(-1) ?? SESSION_A);
    const known = state.items?.find((item) => item.sessionId === sessionId);
    // The detail view must carry the SAME exchange/revocation state as the list
    // row, otherwise an `active` status would be paired with a null exchangedAt
    // and correctly fail the strict shared status schema.
    const overrides: Record<string, unknown> = {};
    if (known?.exchangedAt !== undefined) overrides.exchangedAt = known.exchangedAt;
    if (known?.revokedAt !== undefined) overrides.revokedAt = known.revokedAt;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({
        organizationId: ORG_A,
        item: statusItem(sessionId, known?.status ?? "handoff_pending", overrides),
      }),
    });
  });
}

async function openSessions(page: Page, path = "/app/sessions"): Promise<void> {
  await page.goto(path);
  const viewport = page.viewportSize();
  if (viewport !== null && viewport.width <= 860) {
    await page.getByRole("button", { name: "Menu" }).click();
    await page.locator(".tenant-drawer .tenant-org-select").selectOption(ORG_A);
  } else {
    await page.locator(".tenant-rail--static .tenant-org-select").selectOption(ORG_A);
  }
  await expect(page.locator(".tenant-org-select").first()).toHaveValue(ORG_A);
}

test("shows the truthful non-custodial copy and no payment controls", async ({ page }) => {
  await stubSession(page);
  await stubSessionRoutes(page, { items: [{ sessionId: SESSION_A, status: "handoff_pending" }] });
  await openSessions(page);
  await expect(page.getByRole("heading", { name: "Sessions", level: 1 })).toBeVisible();
  await expect(page.getByText(/do not connect or sign a wallet, reserve money or make purchases/i).first()).toBeVisible();
  const paymentButtons = page.getByRole("button", { name: /pay|purchase|buy|reserve/i });
  await expect(paymentButtons).toHaveCount(0);
});

test("lists sessions and opens a detail with accurate status", async ({ page }) => {
  await stubSession(page);
  await stubSessionRoutes(page, { items: [{ sessionId: SESSION_A, status: "active", exchangedAt: EXCHANGED }] });
  await openSessions(page);
  await expect(page.getByRole("cell", { name: SESSION_A, exact: true })).toBeVisible();
  await page.getByRole("button", { name: `Open session ${SESSION_A}` }).click();
  await expect(page.getByRole("heading", { name: new RegExp(`Session\\s+${SESSION_A}`) })).toBeVisible();
  await expect(page.getByText("Active", { exact: false }).first()).toBeVisible();
});

test("issues a session only after explicit confirmation and shows the handoff exactly once", async ({ page }) => {
  await stubSession(page);
  await stubSessionRoutes(page, { items: [] });
  await openSessions(page, "/app/sessions/new");
  await expect(page.getByRole("heading", { name: "One-time handoff" })).toBeVisible();
  await page.getByLabel("Policy ID").fill(POLICY_A);
  await page.getByLabel("Duration (seconds, 1–900)").fill("300");
  await page.getByRole("button", { name: "Review issue" }).click();
  await expect(page.getByRole("heading", { name: "Confirm issue" })).toBeVisible();
  await page.getByRole("button", { name: "Confirm issue" }).click();
  await expect(page.getByLabel("New one-time handoff token")).toHaveValue(HANDOFF);
  // The fresh issue MUST stay on its one-time delivery screen: no automatic
  // navigation, no hidden secret memory, no detail heading until an explicit
  // navigation happens.
  await expect(page).toHaveURL(/\/app\/sessions\/new$/u);
  await expect(page.getByRole("heading", { name: "One-time handoff" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: new RegExp(`Session\\s+(${SESSION_A}|${SESSION_B})`) }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "Dismiss" }).click();
  await expect(page.getByLabel("New one-time handoff token")).toHaveCount(0);
});

test("clears the typed issue draft in the actual DOM on pagehide before the next paint", async ({ page }) => {
  await stubSession(page);
  await stubSessionRoutes(page, { items: [] });
  await openSessions(page, "/app/sessions/new");
  await page.getByLabel("Policy ID").fill(POLICY_A);
  await page.getByLabel("Duration (seconds, 1–900)").fill("420");
  // The typed draft is live in the real input DOM before the privacy boundary.
  await expect(page.getByLabel("Policy ID")).toHaveValue(POLICY_A);
  await expect(page.getByLabel("Duration (seconds, 1–900)")).toHaveValue("420");
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pagehide")));
  // Same-task: the input nodes are gone and the workspace was cleared.
  await expect(page.getByRole("heading", { name: "Refresh required" })).toBeVisible();
  await expect(page.getByLabel("Policy ID")).toHaveCount(0);
  await expect(page.getByLabel("Duration (seconds, 1–900)")).toHaveCount(0);
});

test("keeps the committed receipt but cannot recover a replay secret", async ({ page }) => {
  await stubSession(page);
  await stubSessionRoutes(page, { items: [{ sessionId: SESSION_A, status: "handoff_pending" }], replayNoSecret: true });
  await openSessions(page, "/app/sessions/new");
  await page.getByLabel("Policy ID").fill(POLICY_A);
  await page.getByRole("button", { name: "Review issue" }).click();
  await page.getByRole("button", { name: "Confirm issue" }).click();
  await expect(page.getByText(/already issued, so its handoff cannot be shown again/i)).toBeVisible();
  await expect(page.getByLabel("New one-time handoff token")).toHaveCount(0);
});

test("shows no access for a viewer with no request or control", async ({ page }) => {
  await stubSession(page, "viewer");
  await stubSessionRoutes(page, { items: [] });
  await openSessions(page);
  await expect(page.getByRole("heading", { name: /do not have access to commerce sessions/i })).toBeVisible();
  await expect(page.getByRole("button", { name: "Issue a session" })).toHaveCount(0);
});

test("denies provider roles any access", async ({ page }) => {
  await stubSession(page, "provider_admin");
  await stubSessionRoutes(page, { items: [] });
  await openSessions(page);
  await expect(page.getByRole("heading", { name: /do not have access to commerce sessions/i })).toBeVisible();
});

test("shows an honest unavailable state when the capability is not enabled", async ({ page }) => {
  await stubSession(page);
  await stubSessionRoutes(page, { items: [], capability: "built_disabled" });
  await openSessions(page);
  await expect(page.getByRole("heading", { name: /Commerce sessions are not available/ })).toBeVisible();
  await expect(page.getByText(/No session request was made/)).toBeVisible();
});

test("resolves an unknown issue outcome only by an explicit original-id status GET", async ({ page }) => {
  await stubSession(page);
  await stubSessionRoutes(page, { items: [] });
  await page.route("**/v2/control/organizations/*/commerce-sessions", async (route) => {
    if (route.request().method() === "POST") {
      await route.abort("connectionreset");
      return;
    }
    await route.fallback();
  });
  await openSessions(page, "/app/sessions/new");
  await page.getByLabel("Policy ID").fill(POLICY_A);
  await page.getByRole("button", { name: "Review issue" }).click();
  await page.getByRole("button", { name: "Confirm issue" }).click();
  await expect(page.getByRole("heading", { name: "The outcome is unknown" })).toBeVisible();
  await expect(page.getByText(/only an explicit status check with the original mutation ID/i)).toBeVisible();
  await page.getByRole("button", { name: "Check status" }).click();
  await expect(page.getByText(/it may still complete/)).toBeVisible();
});

test("revokes the exact session only after confirmation", async ({ page }) => {
  await stubSession(page);
  await stubSessionRoutes(page, { items: [{ sessionId: SESSION_A, status: "handoff_pending" }] });
  await openSessions(page, `/app/sessions/${encodeURIComponent(SESSION_A)}`);
  await page.getByRole("button", { name: `Revoke session ${SESSION_A}` }).click();
  await expect(page.getByRole("heading", { name: "Confirm revoke" })).toBeVisible();
  await page.getByRole("button", { name: "Confirm revoke" }).click();
  await expect(page.getByText(/was revoked\. Any client holding it has lost access/i)).toBeVisible();
});

test("keeps the committed receipt when the follow-up refresh fails", async ({ page }) => {
  await stubSession(page);
  await stubSessionRoutes(page, { items: [{ sessionId: SESSION_A, status: "handoff_pending" }], failRefresh: true });
  await openSessions(page, "/app/sessions/new");
  await page.getByLabel("Policy ID").fill(POLICY_A);
  await page.getByRole("button", { name: "Review issue" }).click();
  await page.getByRole("button", { name: "Confirm issue" }).click();
  await expect(page.getByText(/follow-up refresh failed, but the committed receipt stands/i)).toBeVisible();
  await expect(page.getByLabel("New one-time handoff token")).toHaveValue(HANDOFF);
});

test("clears the one-time handoff on pagehide before the next paint", async ({ page }) => {
  await stubSession(page);
  await stubSessionRoutes(page, { items: [{ sessionId: SESSION_A, status: "handoff_pending" }] });
  await openSessions(page, "/app/sessions/new");
  await page.getByLabel("Policy ID").fill(POLICY_A);
  await page.getByRole("button", { name: "Review issue" }).click();
  await page.getByRole("button", { name: "Confirm issue" }).click();
  await expect(page.getByLabel("New one-time handoff token")).toHaveValue(HANDOFF);
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pagehide")));
  await expect(page.getByRole("heading", { name: "Refresh required" })).toBeVisible();
  await expect(page.getByLabel("New one-time handoff token")).toHaveCount(0);
});

test("clears the one-time handoff when the tab becomes hidden", async ({ page }) => {
  await stubSession(page);
  await stubSessionRoutes(page, { items: [{ sessionId: SESSION_A, status: "handoff_pending" }] });
  await openSessions(page, "/app/sessions/new");
  await page.getByLabel("Policy ID").fill(POLICY_A);
  await page.getByRole("button", { name: "Review issue" }).click();
  await page.getByRole("button", { name: "Confirm issue" }).click();
  await expect(page.getByLabel("New one-time handoff token")).toHaveValue(HANDOFF);
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect(page.getByRole("heading", { name: "Refresh required" })).toBeVisible();
  await expect(page.getByLabel("New one-time handoff token")).toHaveCount(0);
});

test("preserves the pre-existing workspace routes and navigation", async ({ page }) => {
  await stubSession(page);
  await stubSessionRoutes(page, { items: [] });
  await openSessions(page, "/app/provider");
  await expect(page.getByRole("heading", { name: "Provider" })).toBeVisible();
  await page.getByRole("link", { name: "Sessions" }).first().click();
  await expect(page.getByRole("heading", { name: "Sessions", level: 1 })).toBeVisible();
});

test("clears the one-time handoff and typed policy on a same-route organization change", async ({ page }) => {
  await stubSession(page);
  await stubSessionRoutes(page, { items: [{ sessionId: SESSION_A, status: "handoff_pending" }] });
  // Two organizations plus a mutable role, so a same-route selection change
  // forces a context reload without remounting the surrounding app.
  await page.route("**/v1/operator/organizations?*", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({ items: [organization(ORG_A, 0), organization(ORG_B, 1)], nextCursor: null }),
    });
  });
  await page.route("**/v1/operator/organizations", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({ items: [organization(ORG_A, 0), organization(ORG_B, 1)], nextCursor: null }),
    });
  });
  await page.route("**/v1/operator/organizations/*", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (route.request().method() !== "GET" || /\/(agents|providers)/u.test(path)) {
      await route.fallback();
      return;
    }
    const requested = decodeURIComponent(path.slice(path.lastIndexOf("/") + 1));
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope(context("owner", requested)) });
  });
  await page.route("**/v1/operator/organizations/*/agents*", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({ organizationId: ORG_A, items: [agent(AGENT_A), agent(AGENT_B)], nextCursor: null }),
    });
  });
  await openSessions(page, "/app/sessions/new");
  await page.getByLabel("Policy ID").fill(POLICY_A);
  await page.getByRole("button", { name: "Review issue" }).click();
  await page.getByRole("button", { name: "Confirm issue" }).click();
  await expect(page.getByLabel("New one-time handoff token")).toHaveValue(HANDOFF);

  // SAME route, different organization: the one-time handoff and the typed
  // policy must not survive.
  await page.locator(".tenant-org-select").first().selectOption(ORG_B);
  await expect(page.locator(".tenant-org-select").first()).toHaveValue(ORG_B);
  await expect(page.getByLabel("New one-time handoff token")).toHaveCount(0);
  await expect(page.getByLabel("Policy ID")).toHaveValue("");
  await expect(page.getByRole("heading", { name: "Refresh required" })).toHaveCount(0);
});
