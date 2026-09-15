import { expect, test, type Page } from "@playwright/test";

// Protected policy-rules journeys (Chromium + WebKit).
//
// Every account, tenant read, control capability, policy read and policy
// write/status endpoint is intercepted with strict synthetic HTTP fixtures.
// These are honestly labelled UI CONTRACT tests: they prove the UI and
// transport contract only. They are NOT proof of a live API, PostgreSQL, a
// fresh passkey proof, TLS, the production nginx proxy, or any fund movement.
//
// The server runs with tenant reads ON while tenant writes, machine
// credentials and listing management are OFF, proving policy management is
// independent of all of them. These are policy RULES only: no funds are
// reserved, committed, moved or executed and no counter is shown.

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
const POLICY_A = `openarc:policy:${UUID}`;
const POLICY_B = `openarc:policy:${UUID_B}`;
const CREATED = "2026-01-01T00:00:00.000Z";
const UPDATED = "2026-01-02T00:00:00.000000Z";
const DIGEST_A = `sha256:${"a".repeat(64)}`;

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

function context(role: string) {
  return {
    organization: organization(ORG_A),
    access: {
      schemaVersion: "openarc.organization-access.v1",
      organizationId: ORG_A,
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

function policyRoot(policyId: string, currentRevision = "1", status = "active") {
  return {
    schemaVersion: "openarc.control.policy-root.v1",
    policyId,
    organizationId: ORG_A,
    subjectAgentId: AGENT_A,
    currentRevision,
    status,
    createdAt: CREATED,
    updatedAt: UPDATED,
  };
}

function policyContent(overrides: Record<string, unknown> = {}) {
  return {
    organizationId: ORG_A,
    subjectAgentId: AGENT_A,
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    perActionLimit: "1000000",
    rollingLimit: null,
    rollingWindowSeconds: null,
    feeLimit: "10000",
    allowedProviderIds: [],
    allowedListingIds: [],
    approval: { mode: "none", threshold: null, separateApprover: false },
    expiresAt: null,
    ...overrides,
  };
}

function policyRevision(revisionNumber: string, overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: "openarc.control.policy.v1",
    policyId: POLICY_A,
    revision: revisionNumber,
    ...policyContent(),
    createdAt: CREATED,
    digest: DIGEST_A,
    ...overrides,
  };
}

function policySummary(revisionNumber: string) {
  return {
    policyId: POLICY_A,
    organizationId: ORG_A,
    subjectAgentId: AGENT_A,
    revision: revisionNumber,
    digest: DIGEST_A,
    createdAt: CREATED,
    expiresAt: null,
  };
}

// The exact frozen control capability manifest: one family / ten routes.
const CONTROL_CAPABILITY_MANIFEST = {
  capabilityVersion: "openarc.capabilities.control.v1",
  environment: "testnet",
  network: "eip155:5042002",
  capabilities: [
    {
      family: "policy_management",
      audience: "browser",
      state: "enabled",
      dependencies: ["auth", "tenantDatabase", "policyDatabase"],
    },
  ],
  routes: [
    { id: "policy_roots", family: "policy_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/policies" },
    { id: "policy_create", family: "policy_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/policies" },
    { id: "policy_root", family: "policy_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/policies/:policyId" },
    { id: "policy_revisions", family: "policy_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/policies/:policyId/revisions" },
    { id: "policy_revision_create", family: "policy_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/policies/:policyId/revisions" },
    { id: "policy_revision", family: "policy_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/policies/:policyId/revisions/:revision" },
    { id: "policy_pause", family: "policy_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/policies/:policyId/pause" },
    { id: "policy_resume", family: "policy_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/policies/:policyId/resume" },
    { id: "policy_revoke", family: "policy_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/policies/:policyId/revoke" },
    { id: "policy_mutation_status", family: "policy_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/policy-mutations/:mutationId" },
  ],
};

function capabilityManifest(state = "enabled") {
  return {
    ...CONTROL_CAPABILITY_MANIFEST,
    capabilities: [{ ...CONTROL_CAPABILITY_MANIFEST.capabilities[0]!, state }],
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
  await page.route("**/v2/public/control-capabilities", async (route) => {
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

interface PolicyFixtureState {
  readonly roots: Array<{ policyId: string; currentRevision: string; status?: string }>;
  readonly revisions: Record<string, Array<{ revision: string; perActionLimit?: string | null }>>;
  readonly writeStatus?: number;
  readonly capability?: "enabled" | "built_disabled" | "unavailable";
  readonly failRefresh?: boolean;
  readonly createdPolicyId?: string;
}

async function stubPolicyRoutes(page: Page, state: PolicyFixtureState): Promise<void> {
  await page.route("**/v2/public/control-capabilities", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope(capabilityManifest(state.capability ?? "enabled")),
    });
  });
  await page.route("**/v2/control/organizations/*/policy-mutations/*", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope({ organizationId: ORG_A, mutationId: UUID, status: "not_found" }) });
  });
  await page.route("**/v2/control/organizations/*/policies?*", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({
        organizationId: ORG_A,
        items: state.roots.map((root) => policyRoot(root.policyId, root.currentRevision, root.status ?? "active")),
        nextCursor: null,
      }),
    });
  });
  await page.route("**/v2/control/organizations/*/policies", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: envelope({ organizationId: ORG_A, items: state.roots.map((root) => policyRoot(root.policyId, root.currentRevision, root.status ?? "active")), nextCursor: null }),
      });
      return;
    }
    if (state.writeStatus !== undefined && state.writeStatus >= 400) {
      await route.fulfill({ status: state.writeStatus, contentType: "application/json", body: "{}" });
      return;
    }
    const body = JSON.parse(route.request().postData() ?? "{}") as { mutationId: string };
    const createdPolicyId = state.createdPolicyId ?? POLICY_B;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({
        organizationId: ORG_A,
        replayed: false,
        receipt: {
          mutationId: body.mutationId,
          operation: "control.policy.create",
          resourceType: "budget_policy",
          resourceId: createdPolicyId,
          committedAt: CREATED,
        },
      }),
    });
  });
  await page.route("**/v2/control/organizations/*/policies/*/revisions?*", async (route) => {
    const path = new URL(route.request().url()).pathname.split("/");
    const policyId = decodeURIComponent(path.at(-2) ?? POLICY_A);
    const items = (state.revisions[policyId] ?? [{ revision: "1" }]).map((entry) => policySummary(entry.revision));
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope({ organizationId: ORG_A, policyId, items, nextCursor: null }) });
  });
  await page.route("**/v2/control/organizations/*/policies/*/revisions/*", async (route) => {
    if (route.request().method() !== "GET") {
      await route.fallback();
      return;
    }
    const path = new URL(route.request().url()).pathname.split("/");
    const revisionNumber = path.at(-1) ?? "1";
    const policyId = decodeURIComponent(path.at(-3) ?? POLICY_A);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({ organizationId: ORG_A, policyId, revision: revisionNumber, item: policyRevision(revisionNumber) }),
    });
  });
  await page.route("**/v2/control/organizations/*/policies/*/revisions", async (route) => {
    const path = new URL(route.request().url()).pathname.split("/");
    const policyId = decodeURIComponent(path.at(-2) ?? POLICY_A);
    if (route.request().method() === "POST") {
      const body = JSON.parse(route.request().postData() ?? "{}") as { mutationId: string; expectedRevision: string };
      const nextRevision = (BigInt(body.expectedRevision) + 1n).toString();
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: envelope({
          organizationId: ORG_A,
          replayed: false,
          receipt: {
            mutationId: body.mutationId,
            operation: "control.policy.revision.create",
            resourceType: "budget_policy_revision",
            resourceId: `${policyId}@${nextRevision}`,
            committedAt: CREATED,
          },
        }),
      });
      return;
    }
    const items = (state.revisions[policyId] ?? [{ revision: "1" }]).map((entry) => policySummary(entry.revision));
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope({ organizationId: ORG_A, policyId, items, nextCursor: null }) });
  });
  for (const op of ["pause", "resume", "revoke"] as const) {
    await page.route(`**/v2/control/organizations/*/policies/*/${op}`, async (route) => {
      if (state.writeStatus !== undefined && state.writeStatus >= 400) {
        await route.fulfill({ status: state.writeStatus, contentType: "application/json", body: "{}" });
        return;
      }
      const body = JSON.parse(route.request().postData() ?? "{}") as { mutationId: string };
      const path = new URL(route.request().url()).pathname.split("/");
      const policyId = decodeURIComponent(path.at(-2) ?? POLICY_A);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: envelope({
          organizationId: ORG_A,
          replayed: false,
          receipt: {
            mutationId: body.mutationId,
            operation: `control.policy.${op}`,
            resourceType: "budget_policy",
            resourceId: policyId,
            committedAt: CREATED,
          },
        }),
      });
    });
  }
  await page.route("**/v2/control/organizations/*/policies/*", async (route) => {
    if (route.request().method() !== "GET") {
      await route.fallback();
      return;
    }
    const path = new URL(route.request().url()).pathname.split("/");
    const policyId = decodeURIComponent(path.at(-1) ?? POLICY_A);
    const known = state.roots.find((root) => root.policyId === policyId);
    const root = known ?? { policyId, currentRevision: "1", status: "active" };
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({ organizationId: ORG_A, policyId, item: policyRoot(root.policyId, root.currentRevision, root.status ?? "active") }),
    });
  });
}

async function openPolicies(page: Page, path = "/app/budgets"): Promise<void> {
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

// Two organizations plus a MUTABLE role returned for every organization
// context read. Selecting an organization on the same route forces a context
// reload without remounting the surrounding app, which is exactly the
// same-route account/organization/role transition that must erase the create
// form. These remain synthetic UI-contract fixtures.
interface TwoOrgState {
  role: string;
}

async function stubTwoOrgs(page: Page, state: TwoOrgState): Promise<void> {
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
    const organizationId = requested === ORG_B ? ORG_B : ORG_A;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({
        organization: organization(organizationId, organizationId === ORG_B ? 1 : 0),
        access: {
          schemaVersion: "openarc.organization-access.v1",
          organizationId,
          accountId: ACCOUNT_A,
          role: state.role,
          membershipStatus: "active",
          sessionExpiresAt: "2030-01-01T00:00:00.000Z",
        },
        network: "eip155:5042002",
      }),
    });
  });
}

async function fillCreateForm(page: Page): Promise<void> {
  await page.getByLabel("Per-action cap (USDC)").fill("42");
  await page.getByLabel("Rolling cap (USDC)").fill("7");
  await page.getByLabel("Rolling window (seconds)").fill("3600");
  await page.getByLabel("Fee cap (USDC)").fill("0.01");
  await page.getByLabel("Allowed provider IDs").fill(`openarc:provider:${UUID}`);
  await page.getByLabel("Allowed listing IDs").fill(`openarc:listing:${UUID}`);
  await page.getByLabel("Expiry (UTC, optional)").fill("2030-01-01T00:00:00.000Z");
  await expect(page.getByLabel("Per-action cap (USDC)")).toHaveValue("42");
}

async function expectCreateFormCleared(page: Page): Promise<void> {
  await expect(page.getByRole("heading", { name: "Create policy rules" })).toBeVisible();
  await expect(page.getByLabel("Per-action cap (USDC)")).toHaveValue("");
  await expect(page.getByLabel("Rolling cap (USDC)")).toHaveValue("");
  await expect(page.getByLabel("Rolling window (seconds)")).toHaveValue("");
  await expect(page.getByLabel("Fee cap (USDC)")).toHaveValue("");
  await expect(page.getByLabel("Allowed provider IDs")).toHaveValue("");
  await expect(page.getByLabel("Allowed listing IDs")).toHaveValue("");
  await expect(page.getByLabel("Expiry (UTC, optional)")).toHaveValue("");
}

test("shows the truthful rules-only copy and no exposure counters", async ({ page }) => {
  await stubSession(page);
  await stubPolicyRoutes(page, { roots: [{ policyId: POLICY_A, currentRevision: "1" }], revisions: {} });
  await openPolicies(page);
  await expect(page.getByRole("heading", { name: "Budgets", level: 1 })).toBeVisible();
  await expect(page.getByText("These are policy rules only. No funds are reserved, committed, moved, or executed here.").first()).toBeVisible();
  // No available/reserved/spent exposure counters are present. The truthful
  // rules-only sentence itself legitimately contains the word "reserved", so
  // this targets counter-style definition labels, not substring text.
  const counterLabels = page.locator("dt", { hasText: /^(Available|Reserved|Spent)$/i });
  await expect(counterLabels).toHaveCount(0);
  await expect(page.getByText(/reserved\s*[:=]\s*\d/i)).toHaveCount(0);
});

test("lists policy roots and opens a detail with metadata-only history and a full revision read", async ({ page }) => {
  await stubSession(page);
  await stubPolicyRoutes(page, {
    roots: [{ policyId: POLICY_A, currentRevision: "2" }],
    revisions: { [POLICY_A]: [{ revision: "1" }, { revision: "2" }] },
  });
  await openPolicies(page);
  await expect(page.getByRole("cell", { name: POLICY_A })).toBeVisible();
  await page.getByRole("button", { name: "Open policy" }).click();
  await expect(page.getByRole("heading", { name: `Policy ${POLICY_A}` })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Revision history" })).toBeVisible();
  await expect(page.getByText("All revisions loaded. Latest known revision: 2.")).toBeVisible();
  await page.getByRole("button", { name: "Read revision 1" }).click();
  await expect(page.getByRole("heading", { name: "Full revision 1" })).toBeVisible();
  await expect(page.getByText("Append revision from 1")).toBeVisible();
});

test("creates a policy only after explicit confirmation and opens the DB-generated resource", async ({ page }) => {
  await stubSession(page);
  await stubPolicyRoutes(page, { roots: [], revisions: {}, createdPolicyId: POLICY_B });
  await openPolicies(page, "/app/budgets/new");
  await expect(page.getByRole("heading", { name: "Create policy rules" })).toBeVisible();
  await page.getByLabel("Subject agent").selectOption(AGENT_A);
  await page.getByLabel("Per-action cap (USDC)").fill("1");
  await page.getByLabel("Fee cap (USDC)").fill("0.01");
  await page.getByRole("button", { name: "Review policy" }).click();
  await expect(page.getByRole("heading", { name: /Confirm: Create policy/ })).toBeVisible();
  await page.getByRole("button", { name: "Confirm write" }).click();
  await expect(page.getByText(/Committed operation control\.policy\.create/)).toBeVisible();
  await expect(page.getByRole("heading", { name: `Policy ${POLICY_B}` })).toBeVisible();
});

test("validates caps, rolling pairing, fee cap and allowlists in the form", async ({ page }) => {
  await stubSession(page);
  await stubPolicyRoutes(page, { roots: [], revisions: {} });
  await openPolicies(page, "/app/budgets/new");
  await page.getByLabel("Subject agent").selectOption(AGENT_A);
  // No cap and no fee cap: the review action stays disabled.
  await expect(page.getByRole("button", { name: "Review policy" })).toBeDisabled();
  await page.getByLabel("Per-action cap (USDC)").fill("1");
  await page.getByLabel("Fee cap (USDC)").fill("0.01");
  await expect(page.getByRole("button", { name: "Review policy" })).toBeEnabled();
  // A rolling cap requires its paired duration.
  await page.getByLabel("Rolling cap (USDC)").fill("10");
  await expect(page.getByRole("button", { name: "Review policy" })).toBeDisabled();
  await page.getByLabel("Rolling window (seconds)").fill("3600");
  await expect(page.getByRole("button", { name: "Review policy" })).toBeEnabled();
  // A duplicate provider id is rejected.
  await page.getByLabel("Allowed provider IDs").fill(`openarc:provider:${UUID}\nopenarc:provider:${UUID}`);
  await expect(page.getByRole("button", { name: "Review policy" })).toBeDisabled();
});


test("appends an immutable revision after explicit confirmation", async ({ page }) => {
  await stubSession(page);
  await stubPolicyRoutes(page, {
    roots: [{ policyId: POLICY_A, currentRevision: "2" }],
    revisions: { [POLICY_A]: [{ revision: "1" }, { revision: "2" }] },
  });
  await openPolicies(page, `/app/budgets/${encodeURIComponent(POLICY_A)}`);
  await page.getByRole("button", { name: "Read revision 2" }).click();
  await page.getByRole("button", { name: "Append revision from 2" }).click();
  await expect(page.getByRole("heading", { name: /Confirm: Append revision 3/ })).toBeVisible();
  await page.getByRole("button", { name: "Confirm write" }).click();
  await expect(page.getByText(/Committed operation control\.policy\.revision\.create/)).toBeVisible();
});

test("pauses and revokes only after an explicit confirmation with the exact root CAS", async ({ page }) => {
  await stubSession(page);
  await stubPolicyRoutes(page, {
    roots: [{ policyId: POLICY_A, currentRevision: "1", status: "active" }],
    revisions: { [POLICY_A]: [{ revision: "1" }] },
  });
  await openPolicies(page, `/app/budgets/${encodeURIComponent(POLICY_A)}`);
  await page.getByRole("button", { name: "Pause policy" }).click();
  await expect(page.getByRole("heading", { name: /Confirm: Pause policy/ })).toBeVisible();
  await expect(page.getByText(/expectedRevision 1/)).toBeVisible();
  await page.getByRole("button", { name: "Confirm write" }).click();
  await expect(page.getByText(/Committed operation control\.policy\.pause/)).toBeVisible();
});

test("shows no write controls for a viewer role", async ({ page }) => {
  await stubSession(page, "viewer");
  await stubPolicyRoutes(page, { roots: [], revisions: {} });
  await openPolicies(page);
  await expect(page.getByText(/read-only here/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Create policy" })).toBeDisabled();
});

test("denies provider roles any write control", async ({ page }) => {
  await stubSession(page, "provider_admin");
  await stubPolicyRoutes(page, { roots: [{ policyId: POLICY_A, currentRevision: "1" }], revisions: {} });
  await openPolicies(page);
  await page.getByRole("button", { name: "Open policy" }).click();
  await expect(page.getByText("provider_admin")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Pause policy" })).toBeDisabled();
});

test("shows an honest unavailable state when the control capability is not enabled", async ({ page }) => {
  await stubSession(page);
  await stubPolicyRoutes(page, { roots: [], revisions: {}, capability: "built_disabled" });
  await openPolicies(page);
  await expect(page.getByRole("heading", { name: /Policy management is not available/ })).toBeVisible();
  await expect(page.getByText(/No policy request was made/)).toBeVisible();
});

test("resolves an unknown write outcome only by an explicit original-id status GET", async ({ page }) => {
  await stubSession(page);
  await stubPolicyRoutes(page, {
    roots: [{ policyId: POLICY_A, currentRevision: "1", status: "active" }],
    revisions: { [POLICY_A]: [{ revision: "1" }] },
  });
  // Make the pause POST drop its connection so the outcome is unknown.
  await page.route("**/v2/control/organizations/*/policies/*/pause", async (route) => {
    await route.abort("connectionreset");
  });
  await openPolicies(page, `/app/budgets/${encodeURIComponent(POLICY_A)}`);
  await page.getByRole("button", { name: "Pause policy" }).click();
  await page.getByRole("button", { name: "Confirm write" }).click();
  await expect(page.getByRole("heading", { name: "The write outcome is unknown" })).toBeVisible();
  await expect(page.getByText(/Only an explicit status check with the original mutation id/)).toBeVisible();
  await page.getByRole("button", { name: "Check status" }).click();
  await expect(page.getByText(/it may still complete/)).toBeVisible();
});

test("erases a selected revision on pagehide before the next paint", async ({ page }) => {
  await stubSession(page);
  await stubPolicyRoutes(page, {
    roots: [{ policyId: POLICY_A, currentRevision: "1" }],
    revisions: { [POLICY_A]: [{ revision: "1" }] },
  });
  await openPolicies(page, `/app/budgets/${encodeURIComponent(POLICY_A)}`);
  await page.getByRole("button", { name: "Read revision 1" }).click();
  await expect(page.getByRole("heading", { name: "Full revision 1" })).toBeVisible();
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pagehide")));
  await expect(page.getByRole("heading", { name: "Refresh required" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Full revision 1" })).toHaveCount(0);
});

test("keeps the committed receipt visible when the follow-up refresh fails", async ({ page }) => {
  await stubSession(page);
  await stubPolicyRoutes(page, {
    roots: [{ policyId: POLICY_A, currentRevision: "1", status: "active" }],
    revisions: { [POLICY_A]: [{ revision: "1" }] },
  });
  await openPolicies(page, `/app/budgets/${encodeURIComponent(POLICY_A)}`);
  await page.getByRole("button", { name: "Pause policy" }).click();
  await page.getByRole("button", { name: "Confirm write" }).click();
  await expect(page.getByText(/Committed operation control\.policy\.pause/)).toBeVisible();
});

test("clears every filled field on a same-route organization change and never reappears when the prior org returns", async ({ page }) => {
  const state: TwoOrgState = { role: "owner" };
  await stubSession(page);
  await stubTwoOrgs(page, state);
  await stubPolicyRoutes(page, { roots: [], revisions: {} });
  await openPolicies(page, "/app/budgets/new");
  await fillCreateForm(page);

  // SAME route, different organization. The route still forces the create
  // editor to stay mounted, so only a full-context key remount can erase the
  // previously typed caps, allowlists and expiry.
  await page.locator(".tenant-org-select").first().selectOption(ORG_B);
  await expect(page.locator(".tenant-org-select").first()).toHaveValue(ORG_B);
  await expectCreateFormCleared(page);

  // Returning to the prior organization must never resurrect the old values.
  await page.locator(".tenant-org-select").first().selectOption(ORG_A);
  await expect(page.locator(".tenant-org-select").first()).toHaveValue(ORG_A);
  await expectCreateFormCleared(page);
});

test("clears every filled field and resets the agent selection on a same-route owner->viewer->owner change", async ({ page }) => {
  const state: TwoOrgState = { role: "owner" };
  await stubSession(page);
  await stubTwoOrgs(page, state);
  // Two active agents so a manual (second-agent) selection is distinguishable
  // from the fresh first-active prefill after a context remount.
  await page.route("**/v1/operator/organizations/*/agents*", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: envelope({ organizationId: ORG_A, items: [agent(AGENT_A, "active"), agent(`openarc:agent:${UUID_B}`, "active")], nextCursor: null }),
    });
  });
  await stubPolicyRoutes(page, { roots: [], revisions: {} });
  await openPolicies(page, "/app/budgets/new");
  await fillCreateForm(page);
  await page.getByLabel("Subject agent").selectOption(`openarc:agent:${UUID_B}`);
  await expect(page.getByLabel("Subject agent")).toHaveValue(`openarc:agent:${UUID_B}`);

  // owner -> viewer while the SAME route forces the editor to stay mounted.
  state.role = "viewer";
  await page.locator(".tenant-org-select").first().selectOption(ORG_B);
  await expect(page.locator(".tenant-org-select").first()).toHaveValue(ORG_B);
  await expectCreateFormCleared(page);
  // The stale second-agent choice is gone; a fresh mount may prefill the first
  // active agent but must never retain the previous selection.
  await expect(page.getByLabel("Subject agent")).not.toHaveValue(`openarc:agent:${UUID_B}`);

  // viewer -> owner: prior caps and agent choice never reappear.
  state.role = "owner";
  await page.locator(".tenant-org-select").first().selectOption(ORG_A);
  await expect(page.locator(".tenant-org-select").first()).toHaveValue(ORG_A);
  await expectCreateFormCleared(page);
  await expect(page.getByLabel("Subject agent")).not.toHaveValue(`openarc:agent:${UUID_B}`);
});

test("erases a filled create form on pagehide before the next paint", async ({ page }) => {
  await stubSession(page);
  await stubPolicyRoutes(page, { roots: [], revisions: {} });
  await openPolicies(page, "/app/budgets/new");
  await fillCreateForm(page);
  // A hidden boundary is synchronous: the editor must be gone and the typed
  // values must not be painted again.
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pagehide")));
  await expect(page.getByRole("heading", { name: "Refresh required" })).toBeVisible();
  await expect(page.getByLabel("Per-action cap (USDC)")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Create policy rules" })).toHaveCount(0);
});

test("erases a filled create form when the tab becomes hidden before the next paint", async ({ page }) => {
  await stubSession(page);
  await stubPolicyRoutes(page, { roots: [], revisions: {} });
  await openPolicies(page, "/app/budgets/new");
  await fillCreateForm(page);
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect(page.getByRole("heading", { name: "Refresh required" })).toBeVisible();
  await expect(page.getByLabel("Per-action cap (USDC)")).toHaveCount(0);
});

test("preserves the pre-existing workspace routes and navigation", async ({ page }) => {
  await stubSession(page);
  await stubPolicyRoutes(page, { roots: [], revisions: {} });
  await openPolicies(page, "/app/provider");
  await expect(page.getByRole("heading", { name: "Provider" })).toBeVisible();
  await page.getByRole("link", { name: "Budgets" }).first().click();
  await expect(page.getByRole("heading", { name: "Budgets", level: 1 })).toBeVisible();
});
