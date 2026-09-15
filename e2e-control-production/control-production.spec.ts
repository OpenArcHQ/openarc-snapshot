import { randomBytes, randomUUID } from "node:crypto";

import {
  expect,
  test,
  type Browser,
  type CDPSession,
  type Page,
} from "@playwright/test";

import {
  countDurableRows,
  countPolicyRevisions,
  readDurableReceipt,
  readPolicyRevision,
  readPolicyRoot,
  seedAgents,
  seedOrganizationWithRole,
  seedOwnOrganizations,
  type SeededOrganization,
  type SeededProfile,
} from "./fixture-db.js";

/**
 * Real production control-policy acceptance.
 *
 * Every journey targets the REAL API + PostgreSQL + production nginx through
 * the lead-provisioned loopback origins. Human accounts are created through the
 * real passkey sign-up UI and the account id is read from the rendered UI. Only
 * synthetic tenant organizations/agents/memberships are provisioned by the
 * guarded node fixture; the policy rules themselves are created exclusively
 * through the real policy UI. There is no route interception or HTTP mock for
 * any positive journey, no session-cookie injection and no test-only endpoint.
 * The single deterministic browser delivery fault (unknown outcome) is a CDP
 * Fetch response-stage failure applied AFTER the real API has committed and the
 * fixture has independently confirmed the commit.
 */

const ENABLED_ORIGIN = "https://account.openarc.test:5461";

const CANONICAL_ACCOUNT =
  /^openarc:account:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_AGENT =
  /^openarc:agent:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_POLICY =
  /^openarc:policy:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_MUTATION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

const CONTROL_BASE = "/v2/control/organizations";
const CAPABILITIES_PATH = "/v2/public/control-capabilities";

/* -------------------------------------------------------------------------- */
/* Real passkey UI sign-up (reused accepted pattern)                          */
/* -------------------------------------------------------------------------- */

interface VirtualAuthenticator {
  readonly client: CDPSession;
  readonly id: string;
}

async function addVirtualAuthenticator(page: Page): Promise<VirtualAuthenticator> {
  const client = await page.context().newCDPSession(page);
  await client.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { client, id: authenticatorId };
}

async function removeAuthenticator(authenticator: VirtualAuthenticator): Promise<void> {
  await authenticator.client.send("WebAuthn.removeVirtualAuthenticator", {
    authenticatorId: authenticator.id,
  });
}

async function gotoAccount(page: Page): Promise<void> {
  await page.goto("/account");
  await expect(
    page.getByRole("heading", { name: "Sign in or create an account" }),
  ).toBeVisible();
}

async function createPasskeyAccount(page: Page): Promise<string> {
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Create a passkey" }).click();
  const accountIdElement = page.getByTestId("account-id");
  await expect(accountIdElement).toBeVisible();
  const accountId = (await accountIdElement.innerText()).trim();
  expect(CANONICAL_ACCOUNT.test(accountId)).toBe(true);
  return accountId;
}

async function withSignedInAccount(
  page: Page,
  run: (accountId: string) => Promise<void>,
): Promise<void> {
  await gotoAccount(page);
  const authenticator = await addVirtualAuthenticator(page);
  try {
    const accountId = await createPasskeyAccount(page);
    await run(accountId);
  } finally {
    await removeAuthenticator(authenticator);
  }
}

/**
 * Runs one real-UI passkey journey in its OWN isolated browser context. The
 * Chromium host-resolver rule is a browser-level launch flag (see the production
 * config), so this context resolves the same reserved loopback hostname; only
 * the base URL and the HTTPS fixture exemption are copied. No cookie is read,
 * injected or serialized.
 */
async function withIsolatedSignedInAccount(
  browser: Browser,
  origin: string,
  run: (page: Page, accountId: string) => Promise<void>,
): Promise<void> {
  const context = await browser.newContext({ baseURL: origin, ignoreHTTPSErrors: true });
  try {
    const isolated = await context.newPage();
    const authenticator = await addVirtualAuthenticator(isolated);
    try {
      await gotoAccount(isolated);
      const accountId = await createPasskeyAccount(isolated);
      await run(isolated, accountId);
    } finally {
      await removeAuthenticator(authenticator);
    }
  } finally {
    await context.close();
  }
}

/* -------------------------------------------------------------------------- */
/* Real UI navigation and organization selection                              */
/* -------------------------------------------------------------------------- */

async function selectOrganization(page: Page, organizationId: string): Promise<void> {
  const viewport = page.viewportSize();
  if (viewport !== null && viewport.width <= 860) {
    await page.getByRole("button", { name: "Menu" }).click();
    const drawer = page.locator("#tenant-drawer");
    await expect(drawer).toBeVisible();
    await drawer.locator(".tenant-org-select").selectOption({ value: organizationId });
    await expect(drawer).toHaveCount(0);
    await expect(page.locator(".tenant-org-select")).toHaveValue(organizationId);
    return;
  }
  await page
    .locator(".tenant-rail--static .tenant-org-select")
    .selectOption({ value: organizationId });
  await expect(page.locator(".tenant-org-select").first()).toHaveValue(organizationId);
}

async function openPolicies(page: Page, organizationId: string): Promise<void> {
  await page.goto("/app/budgets");
  await selectOrganization(page, organizationId);
  await expect(page.getByRole("heading", { name: "Budgets", level: 1 })).toBeVisible();
}

async function openPolicyDetail(
  page: Page,
  organizationId: string,
  policyId: string,
): Promise<void> {
  await page.goto(`/app/budgets/${encodeURIComponent(policyId)}`);
  await selectOrganization(page, organizationId);
  await expect(
    page.getByRole("heading", { name: `Policy ${policyId}` }),
  ).toBeVisible();
}

async function expectRulesOnlyWording(page: Page): Promise<void> {
  await expect(
    page
      .getByText(
        "These are policy rules only. No funds are reserved, committed, moved, or executed here.",
      )
      .first(),
  ).toBeVisible();
  // No fake exposure counters are rendered.
  await expect(
    page.locator("dt", { hasText: /^(Available|Reserved|Spent)$/i }),
  ).toHaveCount(0);
  await expect(page.getByText(/reserved\s*[:=]\s*\d/i)).toHaveCount(0);
}

/* -------------------------------------------------------------------------- */
/* Observed real policy writes and the rendered resource id                   */
/* -------------------------------------------------------------------------- */

interface ObservedPolicyWrite {
  readonly pathname: string;
  readonly mutationId: string;
}

/** Records every real control policy POST and its client mutation id. */
function observePolicyWrites(page: Page): ObservedPolicyWrite[] {
  const writes: ObservedPolicyWrite[] = [];
  page.on("request", (request) => {
    if (request.method() !== "POST") return;
    const url = new URL(request.url());
    if (!url.pathname.startsWith(`${CONTROL_BASE}/`)) return;
    try {
      const parsed = JSON.parse(request.postData() ?? "{}") as { mutationId?: unknown };
      if (typeof parsed.mutationId === "string") {
        writes.push({ pathname: url.pathname, mutationId: parsed.mutationId });
      }
    } catch {
      // A malformed body is not a write observation; the committed assertion
      // below still fails loudly because no mutation id was observed.
    }
  });
  return writes;
}

function lastWrite(
  writes: readonly ObservedPolicyWrite[],
  matcher: RegExp,
): ObservedPolicyWrite {
  const matches = writes.filter((entry) => matcher.test(entry.pathname));
  const found = matches[matches.length - 1];
  if (found === undefined) throw new Error("POLICY_MUTATION_NOT_OBSERVED");
  expect(CANONICAL_MUTATION.test(found.mutationId)).toBe(true);
  return found;
}

const CREATE_WRITE = /\/policies$/u;
const APPEND_WRITE = /\/policies\/[^/]+\/revisions$/u;

async function readOpenPolicyId(page: Page): Promise<string> {
  const heading = page.getByRole("heading", { name: /^Policy openarc:policy:/u });
  await expect(heading).toBeVisible({ timeout: 20_000 });
  const policyId = (await heading.innerText()).trim().replace(/^Policy\s+/u, "");
  expect(CANONICAL_POLICY.test(policyId)).toBe(true);
  return policyId;
}

/* -------------------------------------------------------------------------- */
/* Policy create / append / lifecycle through the real UI                     */
/* -------------------------------------------------------------------------- */

async function fillCreatePolicyForm(page: Page): Promise<void> {
  const subject = page.getByLabel("Subject agent");
  await expect(subject).toBeVisible();
  // The editor offers the current organization's agents from the accepted
  // bounded tenant read; load them explicitly when they are not yet loaded.
  const loadAgents = page.getByRole("button", { name: "Load agents" });
  if ((await loadAgents.count()) > 0) {
    await loadAgents.click();
    await expect(loadAgents).toHaveCount(0);
  }
  const canonicalAgentOption = subject.locator("option", { hasText: /.+/u }).filter({
    hasNotText: "Choose an active agent",
  });
  await expect(canonicalAgentOption.first()).toBeAttached();
  const value = await subject.inputValue();
  expect(CANONICAL_AGENT.test(value)).toBe(true);
  await page.getByLabel("Per-action cap (USDC)").fill("1");
  await page.getByLabel("Fee cap (USDC)").fill("0.01");
  await expect(page.getByRole("button", { name: "Review policy" })).toBeEnabled();
}

async function createPolicyThroughUi(
  page: Page,
  organizationId: string,
): Promise<string> {
  await openPolicies(page, organizationId);
  await expectRulesOnlyWording(page);
  const load = page.getByRole("button", { name: "Load policy rules" });
  if ((await load.count()) > 0) {
    await load.click();
    await expect(page.getByText("No policy rules in this organization yet.")).toBeVisible();
  }
  await page.getByRole("button", { name: "Create policy" }).click();
  await expect(page.getByRole("heading", { name: "Create policy rules" })).toBeVisible();
  await fillCreatePolicyForm(page);
  await page.getByRole("button", { name: "Review policy" }).click();
  await expect(page.getByRole("heading", { name: /Confirm: Create policy/u })).toBeVisible();
  await page.getByRole("button", { name: "Confirm write" }).click();
  await expect(page.getByText(/Committed operation control\.policy\.create/u)).toBeVisible({
    timeout: 20_000,
  });
  return readOpenPolicyId(page);
}

async function appendRevisionTwoThroughUi(
  page: Page,
  organizationId: string,
  policyId: string,
): Promise<void> {
  await openPolicyDetail(page, organizationId, policyId);
  await page.getByRole("button", { name: "Read revision 1" }).click();
  await expect(page.getByRole("heading", { name: "Full revision 1" })).toBeVisible();
  await page.getByRole("button", { name: "Append revision from 1" }).click();
  await expect(
    page.getByRole("heading", { name: /Confirm: Append revision 2/u }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Confirm write" }).click();
  await expect(
    page.getByText(/Committed operation control\.policy\.revision\.create/u),
  ).toBeVisible({ timeout: 20_000 });
}

async function transitionPolicyThroughUi(
  page: Page,
  organizationId: string,
  policyId: string,
  action: "Pause" | "Resume" | "Revoke",
): Promise<void> {
  await openPolicyDetail(page, organizationId, policyId);
  await page.getByRole("button", { name: `${action} policy` }).click();
  await expect(
    page.getByRole("heading", { name: new RegExp(`Confirm: ${action} policy`, "u") }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Confirm write" }).click();
  await expect(
    page.getByText(new RegExp(`Committed operation control\\.policy\\.${action.toLowerCase()}`, "u")),
  ).toBeVisible({ timeout: 20_000 });
}

/* -------------------------------------------------------------------------- */
/* Bounded same-origin fetch (real session/CSRF, transient closure)           */
/* -------------------------------------------------------------------------- */

/**
 * Bounded safe projection of an ACTUAL HTTP JSON response. Only non-secret
 * shape metadata crosses back: the status, the closed error code, whether a
 * data key/Set-Cookie was present, the on-path policy mutation id echoed by the
 * API, the committed receipt leaves, and a fixed SPA marker boolean. No raw
 * body, session hash, token, cookie, CSRF value or idempotency key is returned.
 */
interface BrowserWriteOutcome {
  readonly status: number;
  readonly envelopeOk: boolean;
  readonly errorCode: string | null;
  readonly hasDataKey: boolean;
  readonly setCookie: boolean;
  readonly spaShell: boolean;
  readonly hasPrivateMetadata: boolean;
  readonly mutationId: string | null;
  readonly operation: string | null;
  readonly resourceType: string | null;
  readonly resourceId: string | null;
  readonly replayed: boolean | null;
}

/**
 * Deliberate same-origin write probe. The real signed-in browser context
 * attaches its own session cookie (credentials same-origin); the CSRF token is
 * fetched from the real bootstrap endpoint and used once. No cookie is read,
 * injected or serialized.
 */
async function sameOriginWrite(
  page: Page,
  request: {
    readonly path: string;
    readonly body: string;
    readonly idempotencyKey: string;
  },
): Promise<BrowserWriteOutcome> {
  return page.evaluate(async (input) => {
    const bootstrap = await fetch("/v2/auth/bootstrap", {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        "X-OpenArc-Client": "browser-v1",
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: "{}",
    });
    const bootstrapJson = (await bootstrap.json()) as {
      data?: { csrfToken?: unknown };
    };
    const csrfToken = bootstrapJson.data?.csrfToken;
    if (typeof csrfToken !== "string" || csrfToken.length === 0) {
      throw new Error("BOOTSTRAP_CSRF_UNAVAILABLE");
    }
    const response = await fetch(input.path, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers: {
        "X-OpenArc-Client": "browser-v1",
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-OpenArc-CSRF": csrfToken,
        "Idempotency-Key": input.idempotencyKey,
      },
      body: input.body,
    });
    const text = await response.text();
    let envelopeOk = false;
    let errorCode: string | null = null;
    let hasDataKey = false;
    let mutationId: string | null = null;
    let operation: string | null = null;
    let resourceType: string | null = null;
    let resourceId: string | null = null;
    let replayed: boolean | null = null;
    try {
      const parsed = JSON.parse(text) as {
        ok?: unknown;
        data?: {
          replayed?: unknown;
          receipt?: {
            mutationId?: unknown;
            operation?: unknown;
            resourceType?: unknown;
            resourceId?: unknown;
          };
        };
        error?: { code?: unknown };
      };
      if (typeof parsed === "object" && parsed !== null) {
        envelopeOk = parsed.ok === true;
        hasDataKey = Object.prototype.hasOwnProperty.call(parsed, "data");
        if (typeof parsed.error === "object" && parsed.error !== null) {
          errorCode = typeof parsed.error.code === "string" ? parsed.error.code : null;
        }
        const receipt = parsed.data?.receipt;
        if (typeof parsed.data?.replayed === "boolean") replayed = parsed.data.replayed;
        if (typeof receipt === "object" && receipt !== null) {
          mutationId = typeof receipt.mutationId === "string" ? receipt.mutationId : null;
          operation = typeof receipt.operation === "string" ? receipt.operation : null;
          resourceType =
            typeof receipt.resourceType === "string" ? receipt.resourceType : null;
          resourceId = typeof receipt.resourceId === "string" ? receipt.resourceId : null;
        }
      }
    } catch {
      errorCode = null;
    }
    return {
      status: response.status,
      envelopeOk,
      errorCode,
      hasDataKey,
      setCookie: response.headers.get("set-cookie") !== null,
      spaShell: [
        'id="root"',
        'id="app"',
        "data-openarc",
        "<script",
        'type="module"',
        "/assets/",
        "openarc-web",
      ].some((marker) => text.includes(marker)),
      hasPrivateMetadata: /"(?:sessionHash|tokenHash|idempotencyKey|csrfToken|session_token)"\s*:/u.test(
        text,
      ),
      mutationId,
      operation,
      resourceType,
      resourceId,
      replayed,
    };
  }, request);
}

interface BrowserReadOutcome {
  readonly status: number;
  readonly contentType: string;
  readonly spaShell: boolean;
  readonly envelopeOk: boolean;
  readonly hasDataKey: boolean;
  readonly errorCode: string | null;
  readonly hasPrivateMetadata: boolean;
  readonly capabilityStates: readonly string[] | null;
  readonly buildSha: string | null;
  /** True only for the bounded nginx generic 404 title/heading. */
  readonly nginx404Title: boolean;
}

/**
 * Bounded credentialless GET used only for the explicit OFF probes. No raw
 * body crosses back: only the status/content-type, the closed error code, the
 * capability states, the exact `meta.buildSha` leaf and fixed booleans proving
 * the response is either the strict JSON capability envelope or the bounded
 * nginx generic 404 — never the SPA shell, never arbitrary HTML and never a
 * protected/success DTO.
 */
async function credentiallessGet(
  page: Page,
  path: string,
): Promise<BrowserReadOutcome> {
  return page.evaluate(async (input) => {
    const response = await fetch(input, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      headers: { "X-OpenArc-Client": "browser-v1", Accept: "application/json" },
    });
    const text = await response.text();
    let envelopeOk = false;
    let hasDataKey = false;
    let errorCode: string | null = null;
    let capabilityStates: string[] | null = null;
    let buildSha: string | null = null;
    const nginx404Title = text.includes("404 Not Found");
    try {
      const parsed = JSON.parse(text) as {
        ok?: unknown;
        data?: { capabilities?: Array<{ state?: unknown }> };
        meta?: { buildSha?: unknown };
        error?: { code?: unknown };
      };
      if (typeof parsed === "object" && parsed !== null) {
        envelopeOk = parsed.ok === true;
        hasDataKey = Object.prototype.hasOwnProperty.call(parsed, "data");
        buildSha =
          typeof parsed.meta?.buildSha === "string" ? parsed.meta.buildSha : null;
        if (typeof parsed.error === "object" && parsed.error !== null) {
          errorCode = typeof parsed.error.code === "string" ? parsed.error.code : null;
        }
        if (Array.isArray(parsed.data?.capabilities)) {
          capabilityStates = parsed.data.capabilities.map((entry) =>
            typeof entry.state === "string" ? entry.state : "",
          );
        }
      }
    } catch {
      errorCode = null;
    }
    return {
      status: response.status,
      contentType: response.headers.get("content-type") ?? "",
      spaShell: [
        'id="root"',
        'id="app"',
        "data-openarc",
        "<script",
        'type="module"',
        "/assets/",
        "openarc-web",
      ].some((marker) => text.includes(marker)),
      envelopeOk,
      hasDataKey,
      errorCode,
      hasPrivateMetadata: /"(?:sessionHash|tokenHash|idempotencyKey|csrfToken|session_token)"\s*:/u.test(
        text,
      ),
      capabilityStates,
      buildSha,
      nginx404Title,
    };
  }, path);
}

function newIdempotencyKey(): string {
  return randomBytes(32).toString("base64url");
}

function newMutationId(): string {
  return randomUUID();
}

function policyContent(organizationId: string, subjectAgentId: string): { readonly [key: string]: unknown } {
  return {
    organizationId,
    subjectAgentId,
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
  };
}

function firstOrganization(
  seeded: readonly SeededOrganization[],
): SeededOrganization {
  const organization = seeded[0];
  if (organization === undefined) throw new Error("SEED_ORGANIZATION_MISSING");
  return organization;
}

function firstProfile(seeded: readonly SeededProfile[]): SeededProfile {
  const profile = seeded[0];
  if (profile === undefined) throw new Error("SEED_PROFILE_MISSING");
  return profile;
}

/* -------------------------------------------------------------------------- */
/* @control-on                                                                */
/* -------------------------------------------------------------------------- */

test.describe("control policy production acceptance", { tag: "@control-on" }, () => {
  test("owner creates an immutable policy v1, appends v2, reads the frozen v1 and history, then pauses, resumes and revokes every logical write with durable receipts", async ({
    page,
  }) => {
    await withSignedInAccount(page, async (accountId) => {
      expect(CANONICAL_ACCOUNT.test(accountId)).toBe(true);
      const organization = firstOrganization(
        await seedOwnOrganizations(accountId, ["Synthetic Control Owner"]),
      );
      const agent = firstProfile(await seedAgents(organization.organizationId, 1));
      expect(CANONICAL_AGENT.test(agent.id)).toBe(true);

      const writes = observePolicyWrites(page);

      const policyId = await createPolicyThroughUi(page, organization.organizationId);
      expect(CANONICAL_POLICY.test(policyId)).toBe(true);
      const createWrite = lastWrite(writes, CREATE_WRITE);
      const createReceipt = await readDurableReceipt(
        organization.organizationId,
        createWrite.mutationId,
      );
      expect(createReceipt?.operation).toBe("control.policy.create");
      expect(createReceipt?.resourceType).toBe("budget_policy");
      expect(createReceipt?.resourceId).toBe(policyId);
      expect(
        await countDurableRows(organization.organizationId, createWrite.mutationId),
      ).toEqual({ idempotency: 1, audit: 1, outbox: 1 });

      const rootV1 = await readPolicyRoot(organization.organizationId, policyId);
      expect(rootV1?.subjectAgentId).toBe(agent.id);
      expect(rootV1?.currentRevision).toBe("1");
      expect(rootV1?.status).toBe("active");
      const revisionV1 = await readPolicyRevision(
        organization.organizationId,
        policyId,
        "1",
      );
      expect(revisionV1?.subjectAgentId).toBe(agent.id);
      expect(revisionV1?.perActionLimit).toBe("1000000");
      expect(revisionV1?.feeLimit).toBe("10000");
      expect(await countPolicyRevisions(organization.organizationId, policyId)).toBe(1);

      // Immutable v1 and full-history inspection through the real UI.
      await page.getByRole("button", { name: "Read revision 1" }).click();
      await expect(page.getByRole("heading", { name: "Full revision 1" })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Revision history" })).toBeVisible();
      await expect(page.getByText("All revisions loaded. Latest known revision: 1.")).toBeVisible();

      await appendRevisionTwoThroughUi(page, organization.organizationId, policyId);
      const appendWrite = lastWrite(writes, APPEND_WRITE);
      const appendReceipt = await readDurableReceipt(
        organization.organizationId,
        appendWrite.mutationId,
      );
      expect(appendReceipt?.operation).toBe("control.policy.revision.create");
      expect(appendReceipt?.resourceType).toBe("budget_policy_revision");
      expect(appendReceipt?.resourceId).toBe(`${policyId}@2`);
      expect(
        await countDurableRows(organization.organizationId, appendWrite.mutationId),
      ).toEqual({ idempotency: 1, audit: 1, outbox: 1 });

      const rootV2 = await readPolicyRoot(organization.organizationId, policyId);
      expect(rootV2?.currentRevision).toBe("2");
      const revisionV2 = await readPolicyRevision(
        organization.organizationId,
        policyId,
        "2",
      );
      expect(revisionV2?.revision).toBe("2");
      expect(revisionV2?.subjectAgentId).toBe(agent.id);
      // Appending v2 never rewrites the frozen v1 digest/creation.
      const revisionV1After = await readPolicyRevision(
        organization.organizationId,
        policyId,
        "1",
      );
      expect(revisionV1After?.digest).toBe(revisionV1?.digest);
      expect(revisionV1After?.createdAt).toBe(revisionV1?.createdAt);
      expect(await countPolicyRevisions(organization.organizationId, policyId)).toBe(2);
      await expect(page.getByText("All revisions loaded. Latest known revision: 2.")).toBeVisible();

      await transitionPolicyThroughUi(page, organization.organizationId, policyId, "Pause");
      const pauseWrite = lastWrite(writes, /\/pause$/u);
      expect(
        await readDurableReceipt(organization.organizationId, pauseWrite.mutationId),
      ).toMatchObject({ operation: "control.policy.pause", resourceId: policyId });
      expect(
        await countDurableRows(organization.organizationId, pauseWrite.mutationId),
      ).toEqual({ idempotency: 1, audit: 1, outbox: 1 });
      expect((await readPolicyRoot(organization.organizationId, policyId))?.status).toBe(
        "paused",
      );

      await transitionPolicyThroughUi(page, organization.organizationId, policyId, "Resume");
      const resumeWrite = lastWrite(writes, /\/resume$/u);
      expect(
        await readDurableReceipt(organization.organizationId, resumeWrite.mutationId),
      ).toMatchObject({ operation: "control.policy.resume", resourceId: policyId });
      expect(
        await countDurableRows(organization.organizationId, resumeWrite.mutationId),
      ).toEqual({ idempotency: 1, audit: 1, outbox: 1 });
      expect((await readPolicyRoot(organization.organizationId, policyId))?.status).toBe(
        "active",
      );

      await transitionPolicyThroughUi(page, organization.organizationId, policyId, "Revoke");
      const revokeWrite = lastWrite(writes, /\/revoke$/u);
      expect(
        await readDurableReceipt(organization.organizationId, revokeWrite.mutationId),
      ).toMatchObject({ operation: "control.policy.revoke", resourceId: policyId });
      expect(
        await countDurableRows(organization.organizationId, revokeWrite.mutationId),
      ).toEqual({ idempotency: 1, audit: 1, outbox: 1 });
      expect((await readPolicyRoot(organization.organizationId, policyId))?.status).toBe(
        "revoked",
      );
      // One durable record per logical mutation, five mutations in total.
      expect(writes).toHaveLength(5);
    });
  });

  test("operator and viewer: operator writes successfully while a viewer reads with no write UI and a deliberate valid-session CSRF POST is denied 403 with no durable rows", async ({
    browser,
    page,
  }) => {
    await withSignedInAccount(page, async (ownerAccountId) => {
      expect(CANONICAL_ACCOUNT.test(ownerAccountId)).toBe(true);

      await withIsolatedSignedInAccount(
        browser,
        ENABLED_ORIGIN,
        async (operatorPage, operatorAccountId) => {
          const operatorOrganization = await seedOrganizationWithRole(
            ownerAccountId,
            operatorAccountId,
            "Synthetic Control Operator",
            "operator",
          );
          const operatorAgent = firstProfile(
            await seedAgents(operatorOrganization.organizationId, 1),
          );
          const operatorWrites = observePolicyWrites(operatorPage);
          const policyId = await createPolicyThroughUi(
            operatorPage,
            operatorOrganization.organizationId,
          );
          const operatorWrite = lastWrite(operatorWrites, CREATE_WRITE);
          expect(
            await readDurableReceipt(
              operatorOrganization.organizationId,
              operatorWrite.mutationId,
            ),
          ).toMatchObject({
            operation: "control.policy.create",
            resourceType: "budget_policy",
            resourceId: policyId,
          });
          expect(
            await countDurableRows(
              operatorOrganization.organizationId,
              operatorWrite.mutationId,
            ),
          ).toEqual({ idempotency: 1, audit: 1, outbox: 1 });
          expect(
            (
              await readPolicyRoot(operatorOrganization.organizationId, policyId)
            )?.subjectAgentId,
          ).toBe(operatorAgent.id);
        },
      );

      await withIsolatedSignedInAccount(
        browser,
        ENABLED_ORIGIN,
        async (viewerPage, viewerAccountId) => {
          const viewerOrganization = await seedOrganizationWithRole(
            ownerAccountId,
            viewerAccountId,
            "Synthetic Control Viewer",
            "viewer",
          );
          const viewerAgent = firstProfile(
            await seedAgents(viewerOrganization.organizationId, 1),
          );

          // The known policy in this organization is created by the REAL owner
          // through the real policy UI (never by SQL fabrication). The viewer
          // journey below must then read this exact known content.
          const ownerWrites = observePolicyWrites(page);
          const knownPolicyId = await createPolicyThroughUi(
            page,
            viewerOrganization.organizationId,
          );
          expect(CANONICAL_POLICY.test(knownPolicyId)).toBe(true);
          const ownerWrite = lastWrite(ownerWrites, CREATE_WRITE);
          expect(
            await readDurableReceipt(
              viewerOrganization.organizationId,
              ownerWrite.mutationId,
            ),
          ).toMatchObject({
            operation: "control.policy.create",
            resourceType: "budget_policy",
            resourceId: knownPolicyId,
          });

          await openPolicies(viewerPage, viewerOrganization.organizationId);
          await expectRulesOnlyWording(viewerPage);
          await expect(viewerPage.getByText(/read-only here/u)).toBeVisible();
          await expect(
            viewerPage.getByRole("button", { name: "Create policy" }),
          ).toBeDisabled();
          // The viewer read is required UNCONDITIONALLY and must surface the
          // known real policy content, never a vacuous empty organization. The
          // controller auto-loads the bounded roots on initialize(); when the
          // explicit control is still offered (capability probe settling) use
          // it. Either way the known-content assertions below ALWAYS run.
          const viewerLoad = viewerPage.getByRole("button", {
            name: "Load policy rules",
          });
          if ((await viewerLoad.count()) > 0) {
            await viewerLoad.click();
          }
          await expect(
            viewerPage.getByText("No policy rules in this organization yet."),
          ).toHaveCount(0);
          const knownRow = viewerPage.getByRole("row", {
            name: new RegExp(knownPolicyId, "u"),
          });
          await expect(knownRow).toBeVisible();
          await expect(
            knownRow.getByRole("cell", { name: viewerAgent.id, exact: true }),
          ).toBeVisible();
          await expect(
            knownRow.getByRole("cell", { name: "1", exact: true }),
          ).toBeVisible();
          await expect(
            knownRow.getByRole("cell", { name: "active", exact: true }),
          ).toBeVisible();
          await knownRow.getByRole("button", { name: "Open policy" }).click();
          await expect(
            viewerPage.getByRole("heading", { name: `Policy ${knownPolicyId}` }),
          ).toBeVisible();
          const fullRevision = viewerPage.locator("section.tenant-policies__revision");
          await viewerPage.getByRole("button", { name: "Read revision 1" }).click();
          await expect(
            viewerPage.getByRole("heading", { name: "Full revision 1" }),
          ).toBeVisible();
          await expect(fullRevision.getByText("1000000", { exact: true })).toBeVisible();
          await expect(fullRevision.getByText("10000", { exact: true })).toBeVisible();

          const viewerMutation = newMutationId();
          const denied = await sameOriginWrite(viewerPage, {
            path: `${CONTROL_BASE}/${encodeURIComponent(
              viewerOrganization.organizationId,
            )}/policies`,
            idempotencyKey: newIdempotencyKey(),
            body: JSON.stringify({
              mutationId: viewerMutation,
              content: policyContent(
                viewerOrganization.organizationId,
                viewerAgent.id,
              ),
            }),
          });
          expect(denied.status).toBe(403);
          expect(denied.errorCode).toBe("FORBIDDEN");
          expect(denied.envelopeOk).toBe(false);
          expect(denied.hasDataKey).toBe(false);
          expect(denied.setCookie).toBe(false);
          expect(denied.spaShell).toBe(false);
          expect(denied.hasPrivateMetadata).toBe(false);
          expect(denied.mutationId).toBeNull();
          expect(
            await countDurableRows(
              viewerOrganization.organizationId,
              viewerMutation,
            ),
          ).toEqual({ idempotency: 0, audit: 0, outbox: 0 });
          expect(
            await readPolicyRoot(
              viewerOrganization.organizationId,
              `openarc:policy:${viewerMutation}`,
            ),
          ).toBeNull();
        },
      );
    });
  });

  test("deterministic lost response: the real create commits first, only the CDP response stage fails, and an explicit original-id status check recovers with exactly one outgoing POST", async ({
    page,
  }) => {
    await withSignedInAccount(page, async (accountId) => {
      const organization = firstOrganization(
        await seedOwnOrganizations(accountId, ["Synthetic Control Lost Reply"]),
      );
      const agent = firstProfile(await seedAgents(organization.organizationId, 1));
      expect(CANONICAL_AGENT.test(agent.id)).toBe(true);

      await openPolicies(page, organization.organizationId);
      await page.getByRole("button", { name: "Create policy" }).click();
      await expect(page.getByRole("heading", { name: "Create policy rules" })).toBeVisible();
      await fillCreatePolicyForm(page);

      // Unconditional request-event observer, registered BEFORE submission. It
      // counts EVERY outgoing policy POST under the control base across the
      // whole attempt and recovery, including any retry that could fail before
      // reaching the CDP response stage. A request is recorded even if its
      // mutation-id body cannot be parsed. It also records every recovery
      // status GET on the wire.
      const outgoingCreatePosts: { mutationId: string | null }[] = [];
      page.on("request", (request) => {
        if (request.method() !== "POST") return;
        const pathname = new URL(request.url()).pathname;
        if (!pathname.startsWith(`${CONTROL_BASE}/`)) return;
        let mutationId: string | null = null;
        try {
          const parsed = JSON.parse(request.postData() ?? "{}") as { mutationId?: unknown };
          if (typeof parsed.mutationId === "string") mutationId = parsed.mutationId;
        } catch {
          mutationId = null;
        }
        outgoingCreatePosts.push({ mutationId });
      });
      const recoveryStatusGets: string[] = [];
      page.on("request", (request) => {
        if (request.method() !== "GET") return;
        const pathname = new URL(request.url()).pathname;
        if (new RegExp(`^${CONTROL_BASE}/[^/]+/policy-mutations/[^/]+$`, "u").test(pathname)) {
          recoveryStatusGets.push(pathname);
        }
      });

      const client = await page.context().newCDPSession(page);
      const capture: { mutationId: string | null } = { mutationId: null };
      let createPosts = 0;
      let faultInstalled = true;
      let preFaultCommitConfirmed = false;
      let settleFaultDecision:
        | ((value: { confirmed: boolean; mutationId: string | null }) => void)
        | null = null;
      const faultDecision = new Promise<{ confirmed: boolean; mutationId: string | null }>(
        (resolve) => {
          settleFaultDecision = resolve;
        },
      );

      client.on("Fetch.requestPaused", async (event) => {
        const isCreate =
          event.request.method === "POST" &&
          new RegExp(`^${CONTROL_BASE}/[^/]+/policies$`, "u").test(
            new URL(event.request.url).pathname,
          );
        if (!isCreate || event.responseStatusCode === undefined) {
          await client
            .send("Fetch.continueRequest", { requestId: event.requestId })
            .catch(() => undefined);
          return;
        }
        createPosts += 1;
        if (!faultInstalled) {
          await client
            .send("Fetch.continueRequest", { requestId: event.requestId })
            .catch(() => undefined);
          return;
        }
        try {
          const parsed = JSON.parse(event.request.postData ?? "{}") as {
            mutationId?: unknown;
          };
          if (typeof parsed.mutationId === "string") capture.mutationId = parsed.mutationId;
        } catch {
          capture.mutationId = null;
        }
        const mutationId = capture.mutationId;
        let confirmed = false;
        if (mutationId !== null) {
          for (let attempt = 0; attempt < 40; attempt += 1) {
            const receipt = await readDurableReceipt(
              organization.organizationId,
              mutationId,
            );
            if (receipt?.operation === "control.policy.create") {
              confirmed = true;
              break;
            }
            await new Promise<void>((resolveTick) => setTimeout(resolveTick, 50));
          }
        }
        settleFaultDecision?.({ confirmed, mutationId });
        if (!confirmed) {
          await client
            .send("Fetch.continueRequest", { requestId: event.requestId })
            .catch(() => undefined);
          return;
        }
        // The real database commit is independently observed BEFORE the single
        // selected response delivery is failed. The request is never replayed.
        preFaultCommitConfirmed = true;
        await client
          .send("Fetch.failRequest", { requestId: event.requestId, errorReason: "Failed" })
          .catch(() => undefined);
      });
      await client.send("Fetch.enable", {
        patterns: [{ urlPattern: "*", requestStage: "Response" }],
      });

      await page.getByRole("button", { name: "Review policy" }).click();
      await page.getByRole("button", { name: "Confirm write" }).click();
      const decision = await faultDecision;
      expect(decision.confirmed).toBe(true);
      expect(preFaultCommitConfirmed).toBe(true);
      expect(decision.mutationId).toBe(capture.mutationId);
      expect(createPosts).toBe(1);

      await expect(
        page.getByRole("heading", { name: "The write outcome is unknown" }),
      ).toBeVisible();
      const mutationId = capture.mutationId;
      if (mutationId === null) throw new Error("MUTATION_ID_NOT_OBSERVED");
      expect(CANONICAL_MUTATION.test(mutationId)).toBe(true);
      // Independently of the CDP response stage, exactly ONE policy create POST
      // left the browser and carried this original mutation id.
      expect(outgoingCreatePosts).toHaveLength(1);
      expect(outgoingCreatePosts[0]?.mutationId).toBe(mutationId);
      expect(
        await countDurableRows(organization.organizationId, mutationId),
      ).toEqual({ idempotency: 1, audit: 1, outbox: 1 });

      // Recovery is only an explicit status GET with the original mutation id.
      faultInstalled = false;
      await page.getByRole("button", { name: "Check status" }).click();
      await expect(
        page.getByText("Committed operation control.policy.create"),
      ).toBeVisible({ timeout: 20_000 });
      await expect(
        page.getByRole("heading", { name: "The write outcome is unknown" }),
      ).toHaveCount(0);
      // Exactly one outgoing policy POST across the whole recovery, observed at
      // the request stage rather than only on create responses reaching CDP.
      expect(createPosts).toBe(1);
      expect(outgoingCreatePosts).toHaveLength(1);
      expect(outgoingCreatePosts[0]?.mutationId).toBe(mutationId);
      // The recovery GET used the SAME original mutation id on the wire, not
      // merely the rendered operation string.
      expect(recoveryStatusGets).toHaveLength(1);
      expect(recoveryStatusGets[0]).toBe(
        `${CONTROL_BASE}/${encodeURIComponent(organization.organizationId)}/policy-mutations/${mutationId}`,
      );
      await client.send("Fetch.disable");
      // One-per-mutation durability is unchanged by the recovery.
      expect(
        await countDurableRows(organization.organizationId, mutationId),
      ).toEqual({ idempotency: 1, audit: 1, outbox: 1 });
      const recoveryReceipt = await readDurableReceipt(
        organization.organizationId,
        mutationId,
      );
      expect(recoveryReceipt?.operation).toBe("control.policy.create");
      const policyId = recoveryReceipt?.resourceId;
      if (policyId === undefined) throw new Error("RECOVERY_POLICY_ID_MISSING");
      expect(CANONICAL_POLICY.test(policyId)).toBe(true);
      expect(
        (await readPolicyRoot(organization.organizationId, policyId))?.currentRevision,
      ).toBe("1");
      expect(await countPolicyRevisions(organization.organizationId, policyId)).toBe(1);
    });
  });
});

/* -------------------------------------------------------------------------- */
/* @control-off: policy disabled, account/tenant reads ON                     */
/* -------------------------------------------------------------------------- */

test.describe("control policy OFF", { tag: "@control-off" }, () => {
  test("the disabled policy surface keeps real account and tenant reads usable, makes no automatic control request, reports strict built_disabled credentiallessly and serves the accepted bounded nginx 404 for the canonical policy path, never SPA", async ({
    page,
  }) => {
    await withSignedInAccount(page, async (accountId) => {
      const automaticControlRequests: string[] = [];
      page.on("request", (request) => {
        const path = new URL(request.url()).pathname;
        if (
          path === CAPABILITIES_PATH ||
          path.startsWith(`${CONTROL_BASE}/`)
        ) {
          automaticControlRequests.push(path);
        }
      });

      // The off deployment renders the policy subtree unavailable without
      // issuing any control-capability or policy request.
      await page.goto("/app/budgets");
      await expect(
        page.getByRole("heading", { name: "This section is not available yet" }),
      ).toBeVisible();
      await expect(page.getByRole("button", { name: "Create policy" })).toHaveCount(0);
      expect(automaticControlRequests).toEqual([]);

      // The accepted account/tenant read experience is preserved.
      const organization = firstOrganization(
        await seedOwnOrganizations(accountId, ["Synthetic Control Off Read"]),
      );
      const agent = firstProfile(await seedAgents(organization.organizationId, 1));
      await page.goto("/app/overview");
      await selectOrganization(page, organization.organizationId);
      await expect(
        page.getByRole("heading", {
          name: "Synthetic Control Off Read",
          exact: true,
        }),
      ).toBeVisible();
      await page.getByRole("link", { name: "Agents" }).click();
      await expect(
        page.getByRole("heading", { name: "Agents", exact: true }),
      ).toBeVisible();
      const loadAgents = page.getByRole("button", { name: "Load agents" });
      if ((await loadAgents.count()) > 0) await loadAgents.click();
      await expect(page.getByText(agent.displayName)).toBeVisible();
      expect(automaticControlRequests).toEqual([]);

      // Explicit credentialless capability probe reports the frozen
      // built_disabled state and never a fabricated empty enabled family.
      const capability = await credentiallessGet(page, CAPABILITIES_PATH);
      expect(capability.status).toBe(200);
      expect(capability.contentType).toContain("application/json");
      expect(capability.envelopeOk).toBe(true);
      expect(capability.hasDataKey).toBe(true);
      expect(capability.capabilityStates).toEqual(["built_disabled"]);
      expect(capability.buildSha).toMatch(/^[0-9a-f]{40}$/u);
      expect(capability.hasPrivateMetadata).toBe(false);

      // The direct canonical policy path fails closed at the nginx boundary.
      // With the policy business include omitted by the frozen OFF image the
      // plain-prefix deny returns nginx's bounded generic 404 (the SAME accepted
      // disabled-family contract as the PORT-01 tenant-off journey): exact 404,
      // text/html, the expected 404 title/heading, no app root, no script/module
      // or asset reference and no protected/success DTO. Arbitrary HTML is not
      // accepted and no parsing/assertion failure is swallowed.
      const direct = await credentiallessGet(
        page,
        `${CONTROL_BASE}/${encodeURIComponent(organization.organizationId)}/policies`,
      );
      expect(direct.status).toBe(404);
      expect(direct.contentType.startsWith("text/html")).toBe(true);
      expect(direct.nginx404Title).toBe(true);
      expect(direct.spaShell).toBe(false);
      expect(direct.envelopeOk).toBe(false);
      expect(direct.hasDataKey).toBe(false);
      expect(direct.capabilityStates).toBeNull();
      expect(direct.hasPrivateMetadata).toBe(false);
    });
  });
});
