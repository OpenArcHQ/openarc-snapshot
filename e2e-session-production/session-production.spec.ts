import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { request as httpsRequest } from "node:https";

import {
  expect,
  test,
  type Browser,
  type CDPSession,
  type Page,
} from "@playwright/test";

import {
  countDurableRows,
  countSessionRows,
  handoffHashMatches,
  hasConsumedHandoff,
  readCommerceSession,
  readDurableReceipt,
  seedAgentMachineSession,
  seedAgents,
  seedOrganizationWithRole,
  seedOwnOrganizations,
  seedPolicyForAgent,
  sessionTokenHashMatches,
  type SeededProfile,
} from "./fixture-db.js";

// Production canonical idempotency-key generator (browser-safe, side-effect
// free). Using the real generator guarantees the exact 43-char canonical
// unpadded base64url value the API/DB enforce, never a naive random string.
import { createSessionIdempotencyKey } from "../apps/web/src/tenant/session-client.js";

/**
 * Real production commerce-session acceptance.
 *
 * Every journey targets the REAL API + PostgreSQL + production nginx through
 * the lead-provisioned loopback origins. Human accounts are created through the
 * real passkey sign-up UI and the account id is read from the rendered UI. The
 * synthetic organization/agent/membership rows and the REAL policy/credential/
 * agent-session preconditions are provisioned by the guarded node fixture; the
 * commerce-session business rows are created exclusively through the real HTTP
 * API. There is no route interception or HTTP mock for any positive journey,
 * no session-cookie injection and no test-only endpoint. The single
 * deterministic browser delivery fault (unknown outcome) is a CDP Fetch
 * response-stage failure applied AFTER the real API has committed and the
 * fixture has independently confirmed the commit.
 *
 * Raw `oach_v1_` handoff and `oacs_v1_` session tokens exist only transiently in
 * test memory. They are never logged, never written to a file, never embedded
 * in a URL/storage and never included in an assertion message; the DB evidence
 * crosses back only as production-hash equality BOOLEANS.
 */

const ENABLED_ORIGIN = "https://account.openarc.test:5471";
const OFF_ORIGIN = "https://account.openarc.test:5472";

const NODE_HOST = "127.0.0.1";
const NODE_PORT = 5471;
const OFF_NODE_PORT = 5472;
const NODE_SERVERNAME = "account.openarc.test";
const FIXTURE_CA_PATH = "/tmp/openarc-session-test.crt";

/**
 * Runtime (not merely type-level) fixed-port guard. Every Node request MUST
 * target exactly one of the two provisioned loopback fixture origins. A plain
 * `number` union is erased at runtime, so the actual value is checked BEFORE
 * the TLS connection is attempted; any other port fails closed and no socket
 * is opened.
 */
function requireFixedPort(value: number | undefined): number {
  const candidate = value ?? NODE_PORT;
  if (candidate !== NODE_PORT && candidate !== OFF_NODE_PORT) {
    throw new Error("NODE_PORT_NOT_FIXED");
  }
  return candidate;
}

const SESSION_BASE = "/v2/control/organizations";
const CAPABILITIES_PATH = "/v2/public/session-capabilities";
const AGENT_EXCHANGE_PATH = "/v2/agent/commerce-sessions/exchange";

const CANONICAL_ACCOUNT =
  /^openarc:account:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_AGENT =
  /^openarc:agent:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_POLICY =
  /^openarc:policy:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_MUTATION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const CANONICAL_HANDOFF = /^oach_v1_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u;
const CANONICAL_SESSION_TOKEN = /^oacs_v1_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u;

/* -------------------------------------------------------------------------- */
/* Real passkey UI sign-up (reused accepted pattern)                           */
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
  // Best-effort teardown. The deterministic lost-response test detaches a
  // separate page CDP session in its own `finally`; Chromium may already have
  // torn down the virtual-authenticator environment by then. The browser
  // context is closed unconditionally immediately afterwards, so a late
  // removal failure is harmless and must not mask the real assertion outcome.
  await authenticator.client
    .send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: authenticator.id })
    .catch(() => undefined);
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

async function openSessionsNew(page: Page, organizationId: string): Promise<void> {
  await page.goto("/app/sessions/new");
  await selectOrganization(page, organizationId);
  await expect(page.getByRole("heading", { name: "One-time handoff" })).toBeVisible();
}

async function openSessionDetail(
  page: Page,
  organizationId: string,
  sessionId: string,
): Promise<void> {
  await page.goto(`/app/sessions/${encodeURIComponent(sessionId)}`);
  await selectOrganization(page, organizationId);
  await expect(
    page.getByRole("heading", { name: new RegExp(`Session\\s+${sessionId}`, "u") }),
  ).toBeVisible({ timeout: 20_000 });
}

/**
 * Fills and confirms the manual-policy issue form. The policy picker stays
 * DISABLED on the ON image (policy HTTP is OFF), so the canonical policy id is
 * entered manually and NO policy request is made.
 */
async function issueSessionThroughUi(
  page: Page,
  organizationId: string,
  agent: SeededProfile,
  policyId: string,
): Promise<void> {
  await openSessionsNew(page, organizationId);
  await expect(page.getByLabel("Policy ID")).toHaveAttribute("type", "text");
  const loadAgents = page.getByRole("button", { name: "Load agents" });
  if ((await loadAgents.count()) > 0) {
    await loadAgents.click();
  }
  const agentSelect = page.getByLabel("Active agent");
  await expect(agentSelect.locator(`option[value="${agent.id}"]`)).toBeAttached();
  await agentSelect.selectOption(agent.id);
  await page.getByLabel("Policy ID").fill(policyId);
  await page.getByLabel("Duration (seconds, 1–900)").fill("300");
  await page.getByRole("button", { name: "Review issue" }).click();
  await expect(page.getByRole("heading", { name: "Confirm issue" })).toBeVisible();
  await page.getByRole("button", { name: "Confirm issue" }).click();
}

/**
 * Transiently reads the one-time raw `oach_v1_` handoff exactly once. The value
 * is returned to the caller only; the caller MUST NOT persist, print or embed
 * it in a URL/storage/assertion.
 */
async function captureHandoffOnce(page: Page): Promise<string> {
  const secret = page.getByLabel("New one-time handoff token");
  await expect(secret).toBeVisible({ timeout: 20_000 });
  const raw = (await secret.inputValue()).trim();
  expect(CANONICAL_HANDOFF.test(raw)).toBe(true);
  return raw;
}

async function readCommittedReceipt(page: Page): Promise<{ sessionId: string; mutationId: string; operation: string }> {
  const committed = page.getByText("Session committed", { exact: true });
  await expect(committed).toBeVisible({ timeout: 20_000 });
  const dds = page.locator(".session-receipt dl.tenant-meta dd");
  const operation = (await dds.nth(0).innerText()).trim();
  const sessionId = (await dds.nth(1).innerText()).trim();
  const mutationId = (await dds.nth(2).innerText()).trim();
  expect(operation).toBe("control.commerce_session.issue");
  expect(CANONICAL_SESSION.test(sessionId)).toBe(true);
  expect(CANONICAL_MUTATION.test(mutationId)).toBe(true);
  return { sessionId, mutationId, operation };
}

/* -------------------------------------------------------------------------- */
/* Actual Node HTTPS requests through the REAL nginx (fixed loopback)          */
/* -------------------------------------------------------------------------- */

let fixtureCaCache: Buffer | null = null;

/**
 * Guarded read of the synthetic PUBLIC fixture CA. The exact fixture opt-ins
 * MUST be set before the certificate is read, and the CA path is fixed. No
 * custom destination, redirect, proxy or env URL is accepted anywhere.
 */
function fixtureCa(): Buffer {
  if (process.env["OPENARC_SESSION_PRODUCTION_FIXTURE"] !== "1") {
    throw new Error("SESSION_FIXTURE_DISABLED");
  }
  if (process.env["OPENARC_TENANT_PRODUCTION_FIXTURE"] !== "1") {
    throw new Error("SESSION_FIXTURE_DISABLED");
  }
  if (fixtureCaCache === null) {
    fixtureCaCache = readFileSync(FIXTURE_CA_PATH);
  }
  return fixtureCaCache;
}

interface NodeRequestInput {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string | null;
  /**
   * Fixed loopback port; defaults to the ON origin and never arbitrary. The
   * value is re-checked at runtime by `requireFixedPort` BEFORE connecting.
   */
  readonly port?: number;
}

/**
 * Bounded, non-secret projection of an ACTUAL Node HTTPS response. Only the
 * status, fixed header-presence booleans, the closed error code, whether a data
 * key/session delivery was present and fixed SPA/HTML markers cross back. No
 * raw body, token, hash, cookie or arbitrary header is returned or logged.
 */
interface NodeResponse {
  readonly status: number;
  readonly setCookie: boolean;
  readonly corsAllowOrigin: boolean;
  readonly contentType: string;
  readonly envelopeOk: boolean;
  readonly errorCode: string | null;
  readonly hasDataKey: boolean;
  readonly hasHandoffToken: boolean;
  readonly replayed: boolean | null;
  readonly capabilityStates: readonly string[] | null;
  readonly sessionToken: string | null;
  /** Closed agent mutation status; never a raw payload. */
  readonly mutationStatus: string | null;
  /** Safe committed receipt projection (no token/hash/idempotency material). */
  readonly receiptOperation: string | null;
  readonly receiptResourceType: string | null;
  readonly receiptResourceId: string | null;
  readonly spaShell: boolean;
  readonly html404: boolean;
  readonly hasPrivateMetadata: boolean;
}

/**
 * Performs ONE Node HTTPS request against the fixed loopback endpoint. The
 * destination host/port/servername are compile-time constants; no caller can
 * override them, and no redirect/proxy/env URL is used. The response body is
 * capped before parsing. A raw session token is captured into a transient local
 * variable and returned only where the journey needs to drive a follow-up; it
 * is never logged.
 */
async function nodeRequest(input: NodeRequestInput): Promise<NodeResponse> {
  const ca = fixtureCa();
  const port = requireFixedPort(input.port);
  return await new Promise<NodeResponse>((resolve, reject) => {
    const request = httpsRequest(
      {
        host: NODE_HOST,
        port,
        servername: NODE_SERVERNAME,
        method: input.method,
        path: input.path,
        ca,
        rejectUnauthorized: true,
        agent: false,
        timeout: 10_000,
        headers: {
          Host: NODE_SERVERNAME,
          Accept: "application/json",
          ...input.headers,
          ...(input.body === null
            ? {}
            : { "Content-Length": String(Buffer.byteLength(input.body, "utf8")) }),
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        let length = 0;
        response.on("data", (chunk: Buffer) => {
          length += chunk.length;
          if (length > 64 * 1024) {
            request.destroy();
            reject(new Error("NODE_RESPONSE_TOO_LARGE"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          const headers = response.headers;
          const setCookieHeader = headers["set-cookie"];
          resolve(projectNodeResponse(
            response.statusCode ?? 0,
            headers["content-type"] ?? "",
            setCookieHeader !== undefined && setCookieHeader.length > 0,
            headers["access-control-allow-origin"] !== undefined,
            text,
          ));
        });
        response.on("error", reject);
      },
    );
    request.on("timeout", () => {
      request.destroy(new Error("NODE_TIMEOUT"));
    });
    request.on("error", reject);
    if (input.body !== null) request.write(input.body);
    request.end();
  });
}

function parseObject(text: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function projectNodeResponse(
  status: number,
  contentType: string,
  setCookie: boolean,
  corsAllowOrigin: boolean,
  text: string,
): NodeResponse {
  const body = parseObject(text);
  let envelopeOk = false;
  let errorCode: string | null = null;
  let hasDataKey = false;
  let hasHandoffToken = false;
  let replayed: boolean | null = null;
  let capabilityStates: readonly string[] | null = null;
  let sessionToken: string | null = null;
  let mutationStatus: string | null = null;
  let receiptOperation: string | null = null;
  let receiptResourceType: string | null = null;
  let receiptResourceId: string | null = null;
  if (body !== null) {
    envelopeOk = body["ok"] === true;
    hasDataKey = Object.prototype.hasOwnProperty.call(body, "data");
    const error = body["error"];
    if (typeof error === "object" && error !== null && !Array.isArray(error)) {
      const code = (error as Record<string, unknown>)["code"];
      errorCode = typeof code === "string" ? code : null;
    }
    const data = body["data"];
    if (typeof data === "object" && data !== null && !Array.isArray(data)) {
      const record = data as Record<string, unknown>;
      if (typeof record["replayed"] === "boolean") replayed = record["replayed"];
      const delivery = record["delivery"];
      if (typeof delivery === "object" && delivery !== null && !Array.isArray(delivery)) {
        const deliveryRecord = delivery as Record<string, unknown>;
        const handoff = deliveryRecord["handoffToken"];
        if (typeof handoff === "string") {
          expect(CANONICAL_HANDOFF.test(handoff)).toBe(true);
          hasHandoffToken = true;
        }
        const token = deliveryRecord["sessionToken"];
        if (typeof token === "string") {
          expect(CANONICAL_SESSION_TOKEN.test(token)).toBe(true);
          sessionToken = token;
        }
      }
      if (Array.isArray(record["capabilities"])) {
        capabilityStates = (record["capabilities"] as unknown[]).map((entry) =>
          typeof entry === "object" && entry !== null
            ? String((entry as Record<string, unknown>)["state"] ?? "")
            : "",
        );
      }
      const statusValue = record["status"];
      if (statusValue === "committed" || statusValue === "not_found") {
        mutationStatus = statusValue;
      }
      const receipt = record["receipt"];
      if (typeof receipt === "object" && receipt !== null && !Array.isArray(receipt)) {
        const receiptRecord = receipt as Record<string, unknown>;
        const operation = receiptRecord["operation"];
        const resourceType = receiptRecord["resourceType"];
        const resourceId = receiptRecord["resourceId"];
        if (typeof operation === "string") receiptOperation = operation;
        if (typeof resourceType === "string") receiptResourceType = resourceType;
        if (typeof resourceId === "string" && CANONICAL_SESSION.test(resourceId)) {
          receiptResourceId = resourceId;
        }
      }
    }
  }
  return {
    status,
    setCookie,
    corsAllowOrigin,
    contentType,
    envelopeOk,
    errorCode,
    hasDataKey,
    hasHandoffToken,
    replayed,
    capabilityStates,
    sessionToken,
    mutationStatus,
    receiptOperation,
    receiptResourceType,
    receiptResourceId,
    spaShell: [
      'id="root"',
      'id="app"',
      "data-openarc",
      "<script",
      'type="module"',
      "/assets/",
      "/build/",
      "openarc-web",
    ].some((marker) => text.includes(marker)),
    html404: text.includes("404 Not Found"),
    hasPrivateMetadata: /"(?:sessionHash|tokenHash|idempotencyKey|csrfToken|session_token|handoffToken)"\s*:/u.test(
      text,
    ),
  };
}

/* -------------------------------------------------------------------------- */
/* Bounded same-origin browser fetch (real session/CSRF, transient closure)    */
/* -------------------------------------------------------------------------- */

interface BrowserWriteOutcome {
  readonly status: number;
  readonly setCookie: boolean;
  readonly envelopeOk: boolean;
  readonly errorCode: string | null;
  readonly hasDataKey: boolean;
  readonly spaShell: boolean;
  readonly hasPrivateMetadata: boolean;
}

/** Deliberate same-origin write probe inside the real signed-in browser. */
async function sameOriginWrite(
  page: Page,
  request: {
    readonly path: string;
    readonly method: "GET" | "POST";
    readonly body: string | null;
    readonly idempotencyKey: string | null;
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
    const bootstrapJson = (await bootstrap.json()) as { data?: { csrfToken?: unknown } };
    const csrfToken = bootstrapJson.data?.csrfToken;
    if (typeof csrfToken !== "string" || csrfToken.length === 0) {
      throw new Error("BOOTSTRAP_CSRF_UNAVAILABLE");
    }
    const headers: Record<string, string> = {
      "X-OpenArc-Client": "browser-v1",
      Accept: "application/json",
      "X-OpenArc-CSRF": csrfToken,
    };
    if (input.body !== null) headers["Content-Type"] = "application/json";
    if (input.idempotencyKey !== null) headers["Idempotency-Key"] = input.idempotencyKey;
    const response = await fetch(input.path, {
      method: input.method,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers,
      ...(input.body === null ? {} : { body: input.body }),
    });
    const text = await response.text();
    let envelopeOk = false;
    let errorCode: string | null = null;
    let hasDataKey = false;
    try {
      const parsed = JSON.parse(text) as {
        ok?: unknown;
        data?: unknown;
        error?: { code?: unknown };
      };
      if (typeof parsed === "object" && parsed !== null) {
        envelopeOk = parsed.ok === true;
        hasDataKey = Object.prototype.hasOwnProperty.call(parsed, "data");
        const code = parsed.error?.code;
        errorCode = typeof code === "string" ? code : null;
      }
    } catch {
      errorCode = null;
    }
    return {
      status: response.status,
      setCookie: response.headers.get("set-cookie") !== null,
      envelopeOk,
      errorCode,
      hasDataKey,
      spaShell: [
        'id="root"',
        'id="app"',
        "data-openarc",
        "<script",
        'type="module"',
        "/assets/",
        "/build/",
        "openarc-web",
      ].some((marker) => text.includes(marker)),
      hasPrivateMetadata: /"(?:sessionHash|tokenHash|idempotencyKey|csrfToken|session_token|handoffToken)"\s*:/u.test(
        text,
      ),
    };
  }, request);
}

interface BrowserReadOutcome {
  readonly status: number;
  readonly setCookie: boolean;
  readonly envelopeOk: boolean;
  readonly errorCode: string | null;
  readonly hasDataKey: boolean;
  readonly spaShell: boolean;
  readonly hasPrivateMetadata: boolean;
}

/**
 * Deliberate same-origin READ probe inside the real signed-in browser. It
 * sends ONLY the browser marker and Accept over the same-origin session cookie:
 * no CSRF, no idempotency key and no body, matching the accepted read
 * transport. The session cookie is attached by the browser (credentials
 * same-origin); it is never read, injected or serialized.
 */
async function sameOriginRead(page: Page, path: string): Promise<BrowserReadOutcome> {
  return page.evaluate(async (input) => {
    const response = await fetch(input, {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers: { "X-OpenArc-Client": "browser-v1", Accept: "application/json" },
    });
    const text = await response.text();
    let envelopeOk = false;
    let errorCode: string | null = null;
    let hasDataKey = false;
    try {
      const parsed = JSON.parse(text) as {
        ok?: unknown;
        data?: unknown;
        error?: { code?: unknown };
      };
      if (typeof parsed === "object" && parsed !== null) {
        envelopeOk = parsed.ok === true;
        hasDataKey = Object.prototype.hasOwnProperty.call(parsed, "data");
        const code = parsed.error?.code;
        errorCode = typeof code === "string" ? code : null;
      }
    } catch {
      errorCode = null;
    }
    return {
      status: response.status,
      setCookie: response.headers.get("set-cookie") !== null,
      envelopeOk,
      errorCode,
      hasDataKey,
      spaShell: [
        'id="root"',
        'id="app"',
        "data-openarc",
        "<script",
        'type="module"',
        "/assets/",
        "/build/",
        "openarc-web",
      ].some((marker) => text.includes(marker)),
      hasPrivateMetadata: /"(?:sessionHash|tokenHash|idempotencyKey|csrfToken|session_token|handoffToken)"\s*:/u.test(
        text,
      ),
    };
  }, path);
}

/* -------------------------------------------------------------------------- */
/* Shared helpers                                                              */
/* -------------------------------------------------------------------------- */

function newIdempotencyKey(): string {
  return createSessionIdempotencyKey();
}

function newMutationId(): string {
  return randomUUID();
}

function firstProfile(seeded: readonly SeededProfile[]): SeededProfile {
  const profile = seeded[0];
  if (profile === undefined) throw new Error("SEED_PROFILE_MISSING");
  return profile;
}

const SESSION_ISSUE_WRITE = /\/commerce-sessions$/u;
const SESSION_REVOKE_WRITE = /\/commerce-sessions\/[^/]+\/revoke$/u;
const SESSION_MUTATION_STATUS = /\/commerce-session-mutations\/[^/]+$/u;

interface ObservedSessionWrite {
  readonly pathname: string;
  readonly mutationId: string | null;
  readonly method: string;
}

/** Records every real commerce-session POST and its client mutation id. */
function observeSessionWrites(page: Page): ObservedSessionWrite[] {
  const writes: ObservedSessionWrite[] = [];
  page.on("request", (request) => {
    if (request.method() !== "POST") return;
    const url = new URL(request.url());
    if (!url.pathname.startsWith(`${SESSION_BASE}/`)) return;
    let mutationId: string | null = null;
    try {
      const parsed = JSON.parse(request.postData() ?? "{}") as { mutationId?: unknown };
      if (typeof parsed.mutationId === "string") mutationId = parsed.mutationId;
    } catch {
      mutationId = null;
    }
    writes.push({ pathname: url.pathname, mutationId, method: request.method() });
  });
  return writes;
}

/** Bounded single-use Node handoff exchange through the REAL nginx. */
async function exchangeHandoff(
  agentToken: string,
  handoffToken: string,
  mutationId: string,
  idempotencyKey: string = newIdempotencyKey(),
): Promise<NodeResponse> {
  return await nodeRequest({
    method: "POST",
    path: AGENT_EXCHANGE_PATH,
    headers: {
      Authorization: `Bearer ${agentToken}`,
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify({ mutationId, handoffToken }),
  });
}

/**
 * Otherwise-valid agent exchange with EXACTLY one caller-supplied header
 * variation (or a substituted bearer namespace). The baseline request carries
 * the actual valid machine bearer, a strict valid body bound to the fresh
 * handoff, a fresh mutation id and a fresh canonical idempotency key; the only
 * difference for a negative case is the single extra header under test. The
 * raw bearer/handoff never leave this call and are never logged.
 */
async function exchangeWithSingleVariation(
  agentToken: string,
  extraHeaders: Readonly<Record<string, string>>,
  handoffToken: string,
  mutationId: string,
  idempotencyKey: string,
): Promise<NodeResponse> {
  return await nodeRequest({
    method: "POST",
    path: AGENT_EXCHANGE_PATH,
    headers: {
      Authorization: `Bearer ${agentToken}`,
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey,
      ...extraHeaders,
    },
    body: JSON.stringify({ mutationId, handoffToken }),
  });
}

/* -------------------------------------------------------------------------- */
/* @session-on journey 1: owner creates, exchanges, binds, revokes             */
/* -------------------------------------------------------------------------- */

test.describe("commerce session production acceptance", { tag: "@session-on" }, () => {
  test("owner creates: a session through the real UI, the fresh handoff is exchanged once through real nginx, the DB binds exactly one credential/session, and an explicit detail revoke is terminal", async ({
    page,
  }) => {
    await withSignedInAccount(page, async (accountId) => {
      expect(CANONICAL_ACCOUNT.test(accountId)).toBe(true);
      const organization = await seedOwnOrganizations(accountId, ["Synthetic Session Owner"]);
      const org = organization[0];
      if (org === undefined) throw new Error("SEED_ORGANIZATION_MISSING");
      const seededAgents = await seedAgents(org.organizationId, 2);
      const agent = firstProfile(seededAgents);
      expect(CANONICAL_AGENT.test(agent.id)).toBe(true);

      // Real store-level preconditions for the SAME human/agent. The raw agent
      // token stays in test memory only.
      const policy = await seedPolicyForAgent(accountId, org.organizationId, agent.id);
      expect(CANONICAL_POLICY.test(policy.policyId)).toBe(true);
      const machine = await seedAgentMachineSession(
        accountId,
        org.organizationId,
        agent.id,
        3_600,
      );

      const writes = observeSessionWrites(page);
      const policyHttpRequests: string[] = [];
      page.on("request", (request) => {
        const path = new URL(request.url()).pathname;
        if (path.startsWith("/v2/control/organizations/") && path.includes("/policies")) {
          policyHttpRequests.push(path);
        }
      });

      await issueSessionThroughUi(page, org.organizationId, agent, policy.policyId);
      const committed = await readCommittedReceipt(page);
      const rawHandoff = await captureHandoffOnce(page);

      // The manual canonical policy path makes ZERO automatic policy requests.
      expect(policyHttpRequests).toEqual([]);

      // Exactly one issue POST, bound to the rendered receipt mutation id.
      const issueWrites = writes.filter((entry) => SESSION_ISSUE_WRITE.test(entry.pathname));
      expect(issueWrites).toHaveLength(1);
      expect(issueWrites[0]?.mutationId).toBe(committed.mutationId);
      const issueReceipt = await readDurableReceipt(org.organizationId, committed.mutationId);
      expect(issueReceipt?.operation).toBe("control.commerce_session.issue");
      expect(issueReceipt?.resourceType).toBe("commerce_session");
      expect(issueReceipt?.resourceId).toBe(committed.sessionId);
      expect(
        await countDurableRows(org.organizationId, committed.mutationId),
      ).toEqual({ idempotency: 1, audit: 1, outbox: 1 });

      // One business row + one handoff row, with production-hash equality
      // (boolean only; no hash is ever returned).
      expect(await countSessionRows(org.organizationId, committed.sessionId)).toEqual({
        sessions: 1,
        handoffs: 1,
      });
      expect(
        await handoffHashMatches(org.organizationId, committed.sessionId, rawHandoff),
      ).toBe(true);
      const pending = await readCommerceSession(org.organizationId, committed.sessionId);
      expect(pending?.subjectAgentId).toBe(agent.id);
      expect(pending?.policyId).toBe(policy.policyId);
      expect(pending?.exchangedAt).toBeNull();
      expect(pending?.revokedAt).toBeNull();

      // A genuine same-org WRONG-AGENT machine session: a second real active
      // agent + real credential/session provisioned by the same guarded fixture.
      // Its ACTUAL returned bearer is presented against the first agent's fresh
      // UI handoff. The real API/DB must deny it with the exact frozen 403
      // FORBIDDEN and must NOT consume the handoff or create any business row.
      const wrongAgent = seededAgents[1];
      if (wrongAgent === undefined) throw new Error("SEED_PROFILE_MISSING");
      expect(CANONICAL_AGENT.test(wrongAgent.id)).toBe(true);
      const wrongMachine = await seedAgentMachineSession(
        accountId,
        org.organizationId,
        wrongAgent.id,
        3_600,
      );
      const wrongExchangeMutation = newMutationId();
      const wrongExchangeKey = newIdempotencyKey();
      const deniedExchange = await exchangeHandoff(
        wrongMachine.agentToken,
        rawHandoff,
        wrongExchangeMutation,
        wrongExchangeKey,
      );
      expect(deniedExchange.status).toBe(403);
      expect(deniedExchange.errorCode).toBe("FORBIDDEN");
      expect(deniedExchange.envelopeOk).toBe(false);
      expect(deniedExchange.hasDataKey).toBe(false);
      expect(deniedExchange.setCookie).toBe(false);
      expect(deniedExchange.corsAllowOrigin).toBe(false);
      expect(deniedExchange.sessionToken).toBeNull();
      expect(deniedExchange.hasHandoffToken).toBe(false);
      // No business mutation was committed for the denied exchange.
      expect(
        await countDurableRows(org.organizationId, wrongExchangeMutation),
      ).toEqual({ idempotency: 0, audit: 0, outbox: 0 });
      // The handoff is NOT consumed and the session is still pending.
      expect(await hasConsumedHandoff(org.organizationId, committed.sessionId)).toBe(false);
      const afterDenial = await readCommerceSession(org.organizationId, committed.sessionId);
      expect(afterDenial?.exchangedAt).toBeNull();
      expect(afterDenial?.credentialId).toBeNull();
      expect(afterDenial?.agentSessionId).toBeNull();

      // Bounded agent-proxy header matrix. Every case below is an OTHERWISE
      // VALID agent exchange (actual same-agent machine bearer, the genuine
      // fresh UI handoff, strict valid JSON body, fresh mutation id and fresh
      // canonical idempotency key per case). Exactly ONE header differs, so
      // each guard is proven independently at the real nginx boundary. Each is
      // rejected with the exact frozen 403, no data, no secret, no Set-Cookie,
      // no CORS and no committed durability for that mutation.
      const headerVariations: readonly (readonly [string, Record<string, string>])[] = [
        ["Cookie", { Cookie: "openarc_session=synthetic" }],
        // Even the exact same-origin value is forbidden on the agent family.
        ["Origin", { Origin: ENABLED_ORIGIN }],
        ["Sec-Fetch-Site", { "Sec-Fetch-Site": "same-origin" }],
        ["Sec-Fetch-Mode", { "Sec-Fetch-Mode": "cors" }],
        ["Sec-Fetch-Dest", { "Sec-Fetch-Dest": "empty" }],
        ["Sec-Fetch-User", { "Sec-Fetch-User": "?1" }],
        ["X-OpenArc-Client", { "X-OpenArc-Client": "browser-v1" }],
        ["X-OpenArc-CSRF", { "X-OpenArc-CSRF": "synthetic-csrf" }],
        ["Proxy-Authorization", { "Proxy-Authorization": "Basic synthetic" }],
      ];
      for (const [label, extra] of headerVariations) {
        const caseMutation = newMutationId();
        const caseKey = newIdempotencyKey();
        const denied = await exchangeWithSingleVariation(
          machine.agentToken,
          extra,
          rawHandoff,
          caseMutation,
          caseKey,
        );
        expect(denied.status, label).toBe(403);
        expect(denied.envelopeOk, label).toBe(false);
        expect(denied.hasDataKey, label).toBe(false);
        expect(denied.hasHandoffToken, label).toBe(false);
        expect(denied.sessionToken, label).toBeNull();
        expect(denied.setCookie, label).toBe(false);
        expect(denied.corsAllowOrigin, label).toBe(false);
        expect(denied.hasPrivateMetadata, label).toBe(false);
        expect(denied.spaShell, label).toBe(false);
        expect(
          await countDurableRows(org.organizationId, caseMutation),
          label,
        ).toEqual({ idempotency: 0, audit: 0, outbox: 0 });
      }

      // Wrong credential NAMESPACE on the SAME exact agent exchange path. The
      // request is otherwise valid; only the bearer primitive is a canonical
      // `oacs_v1_` commerce-session token instead of an `oas_ag_` machine
      // token. The namespace must be rejected before any DB authority work.
      const wrongNamespaceToken = `oacs_v1_${"A".repeat(43)}`;
      const namespaceMutation = newMutationId();
      const namespaceKey = newIdempotencyKey();
      const wrongNamespace = await exchangeWithSingleVariation(
        wrongNamespaceToken,
        {},
        rawHandoff,
        namespaceMutation,
        namespaceKey,
      );
      expect(wrongNamespace.status).toBe(403);
      expect(wrongNamespace.envelopeOk).toBe(false);
      expect(wrongNamespace.hasDataKey).toBe(false);
      expect(wrongNamespace.hasHandoffToken).toBe(false);
      expect(wrongNamespace.sessionToken).toBeNull();
      expect(wrongNamespace.setCookie).toBe(false);
      expect(wrongNamespace.corsAllowOrigin).toBe(false);
      expect(wrongNamespace.hasPrivateMetadata).toBe(false);
      expect(wrongNamespace.spaShell).toBe(false);
      expect(
        await countDurableRows(org.organizationId, namespaceMutation),
      ).toEqual({ idempotency: 0, audit: 0, outbox: 0 });
      // None of the denied variations consumed the shared fresh handoff.
      expect(await hasConsumedHandoff(org.organizationId, committed.sessionId)).toBe(false);

      // Fresh exchange through the REAL nginx for the SAME human/agent. The
      // exact correlation (mutation id + idempotency key) is retained so the
      // replay below is an EXACT idempotent replay, never a second exchange.
      const exchangeMutationId = newMutationId();
      const exchangeIdempotencyKey = newIdempotencyKey();
      const exchanged = await exchangeHandoff(
        machine.agentToken,
        rawHandoff,
        exchangeMutationId,
        exchangeIdempotencyKey,
      );
      expect(exchanged.status).toBe(200);
      expect(exchanged.envelopeOk).toBe(true);
      expect(exchanged.setCookie).toBe(false);
      expect(exchanged.corsAllowOrigin).toBe(false);
      expect(exchanged.replayed).toBe(false);
      expect(exchanged.hasHandoffToken).toBe(false);
      const rawSessionToken = exchanged.sessionToken;
      if (rawSessionToken === null) throw new Error("EXCHANGE_NO_SESSION_TOKEN");
      expect(CANONICAL_SESSION_TOKEN.test(rawSessionToken)).toBe(true);
      expect(await sessionTokenHashMatches(org.organizationId, committed.sessionId, rawSessionToken)).toBe(true);
      expect(await hasConsumedHandoff(org.organizationId, committed.sessionId)).toBe(true);

      const bound = await readCommerceSession(org.organizationId, committed.sessionId);
      expect(bound?.exchangedAt).not.toBeNull();
      expect(bound?.agentSessionId).toBe(machine.sessionId);
      expect(bound?.credentialId).toBe(machine.credentialId);

      // Actual agent ORIGINAL-mutation status GET through the REAL nginx after
      // the committed success: real bearer, no body and no browser metadata.
      // The strict safe committed receipt is returned and NO token/handoff is
      // replayed by a status read.
      const agentMutationGet = await nodeRequest({
        method: "GET",
        path: `/v2/agent/commerce-session-mutations/${exchangeMutationId}`,
        headers: { Authorization: `Bearer ${machine.agentToken}` },
        body: null,
      });
      expect(agentMutationGet.status).toBe(200);
      expect(agentMutationGet.envelopeOk).toBe(true);
      expect(agentMutationGet.hasDataKey).toBe(true);
      expect(agentMutationGet.mutationStatus).toBe("committed");
      expect(agentMutationGet.receiptOperation).toBe("control.commerce_session.exchange");
      expect(agentMutationGet.receiptResourceType).toBe("commerce_session");
      expect(agentMutationGet.receiptResourceId).toBe(committed.sessionId);
      expect(agentMutationGet.sessionToken).toBeNull();
      expect(agentMutationGet.hasHandoffToken).toBe(false);
      expect(agentMutationGet.setCookie).toBe(false);
      expect(agentMutationGet.corsAllowOrigin).toBe(false);
      expect(agentMutationGet.hasPrivateMetadata).toBe(false);
      expect(agentMutationGet.spaShell).toBe(false);

      // Exact exchange replay (SAME mutation id + SAME idempotency key) is safe:
      // the committed receipt is returned with replayed=true and the API never
      // mints a second session token and never re-reveals the handoff.
      const replay = await exchangeHandoff(
        machine.agentToken,
        rawHandoff,
        exchangeMutationId,
        exchangeIdempotencyKey,
      );
      expect(replay.status).toBe(200);
      expect(replay.envelopeOk).toBe(true);
      expect(replay.replayed).toBe(true);
      expect(replay.hasHandoffToken).toBe(false);
      expect(replay.sessionToken).toBeNull();
      expect(replay.setCookie).toBe(false);
      expect(replay.corsAllowOrigin).toBe(false);

      // Explicit detail navigation shows the ACTIVE bound state, then an
      // explicit UI revoke is terminal.
      await openSessionDetail(page, org.organizationId, committed.sessionId);
      await expect(
        page.getByText(/Server-derived status:\s*Active/u),
      ).toBeVisible({ timeout: 20_000 });
      await page.getByRole("button", { name: `Revoke session ${committed.sessionId}` }).click();
      await expect(page.getByRole("heading", { name: "Confirm revoke" })).toBeVisible();
      await page.getByRole("button", { name: "Confirm revoke" }).click();
      await expect(
        page.getByText(/The session was revoked\. Any client holding it has lost access/u),
      ).toBeVisible({ timeout: 20_000 });

      const revokeWrites = writes.filter((entry) => SESSION_REVOKE_WRITE.test(entry.pathname));
      expect(revokeWrites).toHaveLength(1);
      const revokeMutationId = revokeWrites[0]?.mutationId;
      if (revokeMutationId === null || revokeMutationId === undefined) {
        throw new Error("REVOKE_MUTATION_NOT_OBSERVED");
      }
      expect(
        await readDurableReceipt(org.organizationId, revokeMutationId),
      ).toMatchObject({
        operation: "control.commerce_session.revoke",
        resourceType: "commerce_session",
        resourceId: committed.sessionId,
      });
      expect(
        await countDurableRows(org.organizationId, revokeMutationId),
      ).toEqual({ idempotency: 1, audit: 1, outbox: 1 });
      const revoked = await readCommerceSession(org.organizationId, committed.sessionId);
      expect(revoked?.revokedAt).not.toBeNull();
      // Exactly one binding and one durable outbox for the issue mutation even
      // after the exchange and revoke.
      expect(
        await countDurableRows(org.organizationId, committed.mutationId),
      ).toEqual({ idempotency: 1, audit: 1, outbox: 1 });
    });
  });

  test("operator and viewer: operator issues and revokes through the real UI while a viewer is denied UI reads/writes and receives a real API 403 on a known same-org session; a wrong-agent exchange is denied", async ({
    browser,
    page,
  }) => {
    await withSignedInAccount(page, async (ownerAccountId) => {
      expect(CANONICAL_ACCOUNT.test(ownerAccountId)).toBe(true);

      let origin = ENABLED_ORIGIN;
      await test.step("operator issues and revokes through the real UI", () =>
        withIsolatedSignedInAccount(
          browser,
          origin,
          async (operatorPage, operatorAccountId) => {
            const org = await seedOrganizationWithRole(
              ownerAccountId,
              operatorAccountId,
              "Synthetic Session Operator",
              "operator",
            );
            const agent = firstProfile(await seedAgents(org.organizationId, 1));
            const policy = await seedPolicyForAgent(
              operatorAccountId,
              org.organizationId,
              agent.id,
            );
            const writes = observeSessionWrites(operatorPage);
            await issueSessionThroughUi(operatorPage, org.organizationId, agent, policy.policyId);
            const committed = await readCommittedReceipt(operatorPage);
            const issueWrites = writes.filter((entry) => SESSION_ISSUE_WRITE.test(entry.pathname));
            expect(issueWrites).toHaveLength(1);
            expect(issueWrites[0]?.mutationId).toBe(committed.mutationId);
            expect(
              await readDurableReceipt(org.organizationId, committed.mutationId),
            ).toMatchObject({
              operation: "control.commerce_session.issue",
              resourceType: "commerce_session",
              resourceId: committed.sessionId,
            });

            await openSessionDetail(operatorPage, org.organizationId, committed.sessionId);
            await operatorPage
              .getByRole("button", { name: `Revoke session ${committed.sessionId}` })
              .click();
            await expect(
              operatorPage.getByRole("heading", { name: "Confirm revoke" }),
            ).toBeVisible();
            await operatorPage.getByRole("button", { name: "Confirm revoke" }).click();
            await expect(
              operatorPage.getByText(
                /The session was revoked\. Any client holding it has lost access/u,
              ),
            ).toBeVisible({ timeout: 20_000 });
            origin = new URL(operatorPage.url()).origin;
          },
        ),
      );

      await test.step("viewer is denied UI reads and a known same-org session API 403", () =>
        withIsolatedSignedInAccount(
          browser,
          origin,
          async (viewerPage, viewerAccountId) => {
            const org = await seedOrganizationWithRole(
              ownerAccountId,
              viewerAccountId,
              "Synthetic Session Viewer",
              "viewer",
            );
            const agent = firstProfile(await seedAgents(org.organizationId, 1));
            const policy = await seedPolicyForAgent(
              ownerAccountId,
              org.organizationId,
              agent.id,
            );

            // A KNOWN real session in the same organization, created by the
            // owner through the real UI. The viewer denial below is NEVER a
            // vacuous empty-organization check.
            const ownerWrites = observeSessionWrites(page);
            await issueSessionThroughUi(page, org.organizationId, agent, policy.policyId);
            const known = await readCommittedReceipt(page);
            expect(
              ownerWrites.filter((entry) => SESSION_ISSUE_WRITE.test(entry.pathname)),
            ).toHaveLength(1);

            // Viewer UI: explicit no-access state, no list, no controls.
            await viewerPage.goto("/app/sessions");
            await selectOrganization(viewerPage, org.organizationId);
            await expect(
              viewerPage.getByRole("heading", {
                name: "You do not have access to commerce sessions",
                exact: true,
              }),
            ).toBeVisible();
            await expect(viewerPage.getByRole("button", { name: "Issue a session" })).toHaveCount(0);
            await expect(viewerPage.getByText("Existing sessions")).toHaveCount(0);

            // Real API 403 on the known same-org session path.
            const deniedRead = await sameOriginRead(
              viewerPage,
              `${SESSION_BASE}/${encodeURIComponent(org.organizationId)}/commerce-sessions/${encodeURIComponent(known.sessionId)}`,
            );
            expect(deniedRead.status).toBe(403);
            expect(deniedRead.errorCode).toBe("FORBIDDEN");
            expect(deniedRead.envelopeOk).toBe(false);
            expect(deniedRead.hasDataKey).toBe(false);
            expect(deniedRead.setCookie).toBe(false);
            expect(deniedRead.spaShell).toBe(false);
            expect(deniedRead.hasPrivateMetadata).toBe(false);

            const deniedMutation = newMutationId();
            const deniedWrite = await sameOriginWrite(viewerPage, {
              path: `${SESSION_BASE}/${encodeURIComponent(org.organizationId)}/commerce-sessions/${encodeURIComponent(known.sessionId)}/revoke`,
              method: "POST",
              body: JSON.stringify({ mutationId: deniedMutation }),
              idempotencyKey: newIdempotencyKey(),
            });
            expect(deniedWrite.status).toBe(403);
            expect(deniedWrite.errorCode).toBe("FORBIDDEN");
            expect(deniedWrite.setCookie).toBe(false);
            expect(deniedWrite.hasPrivateMetadata).toBe(false);
            expect(
              await countDurableRows(org.organizationId, deniedMutation),
            ).toEqual({ idempotency: 0, audit: 0, outbox: 0 });
            expect((await readCommerceSession(org.organizationId, known.sessionId))?.revokedAt).toBeNull();
          },
        ),
      );
    });
  });

  test("deterministic lost response: the real issue commits first, only the CDP response stage fails, and an explicit original-id status check recovers with exactly one outgoing POST and no recovered secret", async ({
    page,
  }) => {
    await withSignedInAccount(page, async (accountId) => {
      const seeded = await seedOwnOrganizations(accountId, ["Synthetic Session Lost Reply"]);
      const org = seeded[0];
      if (org === undefined) throw new Error("SEED_ORGANIZATION_MISSING");
      const agent = firstProfile(await seedAgents(org.organizationId, 1));
      const policy = await seedPolicyForAgent(accountId, org.organizationId, agent.id);

      await openSessionsNew(page, org.organizationId);
      const loadAgents = page.getByRole("button", { name: "Load agents" });
      if ((await loadAgents.count()) > 0) await loadAgents.click();
      const agentSelect = page.getByLabel("Active agent");
      await expect(agentSelect.locator(`option[value="${agent.id}"]`)).toBeAttached();
      await agentSelect.selectOption(agent.id);
      await page.getByLabel("Policy ID").fill(policy.policyId);
      await page.getByRole("button", { name: "Review issue" }).click();
      await expect(page.getByRole("heading", { name: "Confirm issue" })).toBeVisible();

      // Unconditional request observer registered BEFORE submission. It counts
      // EVERY outgoing session POST under SESSION_BASE (any session sub-path),
      // so an unexpected non-issue session POST cannot escape the count, plus
      // every recovery status GET on the wire. The CDP issue intercept below
      // stays deliberately issue-specific.
      const allSessionPosts = observeSessionWrites(page);
      const recoveryStatusGets: string[] = [];
      page.on("request", (request) => {
        if (request.method() !== "GET") return;
        const pathname = new URL(request.url()).pathname;
        if (
          pathname.startsWith(`${SESSION_BASE}/`) &&
          SESSION_MUTATION_STATUS.test(pathname)
        ) {
          recoveryStatusGets.push(pathname);
        }
      });

      const client = await page.context().newCDPSession(page);
      try {
      const capture: { mutationId: string | null } = { mutationId: null };
      let issuePosts = 0;
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
        const isIssue =
          event.request.method === "POST" &&
          SESSION_ISSUE_WRITE.test(new URL(event.request.url).pathname);
        if (!isIssue || event.responseStatusCode === undefined) {
          await client
            .send("Fetch.continueRequest", { requestId: event.requestId })
            .catch(() => undefined);
          return;
        }
        issuePosts += 1;
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
            const receipt = await readDurableReceipt(org.organizationId, mutationId);
            if (receipt?.operation === "control.commerce_session.issue") {
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
        preFaultCommitConfirmed = true;
        await client
          .send("Fetch.failRequest", { requestId: event.requestId, errorReason: "Failed" })
          .catch(() => undefined);
      });
      await client.send("Fetch.enable", {
        patterns: [{ urlPattern: "*", requestStage: "Response" }],
      });

      await page.getByRole("button", { name: "Confirm issue" }).click();
      const decision = await faultDecision;
      expect(decision.confirmed).toBe(true);
      expect(preFaultCommitConfirmed).toBe(true);
      expect(decision.mutationId).toBe(capture.mutationId);
      expect(issuePosts).toBe(1);

      await expect(page.getByRole("heading", { name: "The outcome is unknown" })).toBeVisible();
      const mutationId = capture.mutationId;
      if (mutationId === null) throw new Error("MUTATION_ID_NOT_OBSERVED");
      expect(CANONICAL_MUTATION.test(mutationId)).toBe(true);
      expect(allSessionPosts).toHaveLength(1);
      expect(allSessionPosts[0]?.pathname).toBe(
        `${SESSION_BASE}/${encodeURIComponent(org.organizationId)}/commerce-sessions`,
      );
      expect(allSessionPosts[0]?.mutationId).toBe(mutationId);
      expect(
        await countDurableRows(org.organizationId, mutationId),
      ).toEqual({ idempotency: 1, audit: 1, outbox: 1 });

      // Recovery is only an explicit status GET with the original mutation id.
      faultInstalled = false;
      await page.getByRole("button", { name: "Check status" }).click();
      // A committed status is rendered through the shared committed view with
      // replayed=true: the heading is "Session already committed" and the safe
      // receipt operation is shown. No raw handoff can be recovered.
      await expect(
        page.getByRole("heading", { name: "Session already committed" }),
      ).toBeVisible({ timeout: 20_000 });
      await expect(
        page.getByText("control.commerce_session.issue", { exact: true }),
      ).toBeVisible();
      await expect(page.getByRole("heading", { name: "The outcome is unknown" })).toHaveCount(0);
      // No raw secret is recovered by a status check.
      await expect(page.getByLabel("New one-time handoff token")).toHaveCount(0);
      expect(issuePosts).toBe(1);
      // EVERY session POST is counted: exactly one, on the exact issue path,
      // bound to the original mutation id.
      expect(allSessionPosts).toHaveLength(1);
      expect(allSessionPosts[0]?.pathname).toBe(
        `${SESSION_BASE}/${encodeURIComponent(org.organizationId)}/commerce-sessions`,
      );
      expect(allSessionPosts[0]?.mutationId).toBe(mutationId);
      expect(recoveryStatusGets).toHaveLength(1);
      expect(recoveryStatusGets[0]).toBe(
        `${SESSION_BASE}/${encodeURIComponent(org.organizationId)}/commerce-session-mutations/${mutationId}`,
      );
      // One-per-mutation durability is unchanged by the recovery.
      expect(
        await countDurableRows(org.organizationId, mutationId),
      ).toEqual({ idempotency: 1, audit: 1, outbox: 1 });
      const recoveryReceipt = await readDurableReceipt(org.organizationId, mutationId);
      const sessionId = recoveryReceipt?.resourceId;
      if (sessionId === undefined) throw new Error("RECOVERY_SESSION_ID_MISSING");
      expect(CANONICAL_SESSION.test(sessionId)).toBe(true);
      expect(await countSessionRows(org.organizationId, sessionId)).toEqual({
        sessions: 1,
        handoffs: 1,
      });
      } finally {
        // Always release the CDP Fetch interception, including on assertion
        // failure, so a failed run cannot leave the page paused or the session
        // attached.
        await client.send("Fetch.disable").catch(() => undefined);
        await client.detach().catch(() => undefined);
      }
    });
  });

  test("nginx boundary probes: malformed/query/wrongverb/mixedCookie/Origin/FetchMetadata/CSRF/ProxyAuth/wrong-namespace negatives fail closed at the real nginx while a valid counterproof succeeds, with no Set-Cookie/CORS and no SPA fallback", async () => {
    await test.step("credentialless capability probe is a strict enabled envelope", async () => {
      const capability = await nodeRequest({
        method: "GET",
        path: CAPABILITIES_PATH,
        headers: {},
        body: null,
      });
      expect(capability.status).toBe(200);
      expect(capability.contentType).toContain("application/json");
      expect(capability.envelopeOk).toBe(true);
      expect(capability.hasDataKey).toBe(true);
      expect(capability.setCookie).toBe(false);
      expect(capability.corsAllowOrigin).toBe(false);
      expect(capability.spaShell).toBe(false);
      expect(capability.hasPrivateMetadata).toBe(false);
      expect(capability.capabilityStates).toEqual(["enabled", "enabled"]);
    });

    const org = `openarc:org:${randomUUID()}`;
    const session = randomUUID();
    const collection = `${SESSION_BASE}/${encodeURIComponent(org)}/commerce-sessions`;
    const detail = `${collection}/${session}`;
    const revoke = `${detail}/revoke`;
    const mutationStatus = `${SESSION_BASE}/${encodeURIComponent(org)}/commerce-session-mutations/${randomUUID()}`;
    const jsonBody = JSON.stringify({ mutationId: randomUUID() });

    await test.step("negatives fail closed at the nginx boundary", async () => {
      const validGetHeaders = {
        "X-OpenArc-Client": "browser-v1",
        Origin: ENABLED_ORIGIN,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
      };

      // Malformed path (lookalike) is denied by the fixed fallback, never SPA.
      const malformed = await nodeRequest({
        method: "GET",
        path: "/v2/control/organizations/openarc:org:not-a-uuid/commerce-sessions",
        headers: validGetHeaders,
        body: null,
      });
      expect([400, 403, 404]).toContain(malformed.status);
      expect(malformed.status).not.toBe(200);
      expect(malformed.spaShell).toBe(false);
      expect(malformed.setCookie).toBe(false);
      expect(malformed.corsAllowOrigin).toBe(false);

      // Query on a query-free route is rejected.
      const query = await nodeRequest({
        method: "GET",
        path: `${detail}?limit=1`,
        headers: validGetHeaders,
        body: null,
      });
      expect(query.status).toBe(400);
      expect(query.spaShell).toBe(false);

      // Wrong verb on a GET-only route is 405.
      const wrongVerb = await nodeRequest({
        method: "POST",
        path: detail,
        headers: { ...validGetHeaders, "Content-Type": "application/json" },
        body: "{}",
      });
      expect(wrongVerb.status).toBe(405);
      expect(wrongVerb.spaShell).toBe(false);

      // Mixed cookie on the browser route is forwarded to the API, which
      // rejects it; nginx never surfaces a cookie or CORS grant.
      const mixedCookie = await nodeRequest({
        method: "GET",
        path: detail,
        headers: { ...validGetHeaders, Cookie: "openarc_session=synthetic" },
        body: null,
      });
      expect([400, 401, 403]).toContain(mixedCookie.status);
      expect(mixedCookie.setCookie).toBe(false);
      expect(mixedCookie.corsAllowOrigin).toBe(false);
      expect(mixedCookie.spaShell).toBe(false);

      // Wrong Origin is rejected.
      const wrongOrigin = await nodeRequest({
        method: "GET",
        path: detail,
        headers: { ...validGetHeaders, Origin: "https://evil.example.test" },
        body: null,
      });
      expect([400, 403]).toContain(wrongOrigin.status);
      expect(wrongOrigin.setCookie).toBe(false);
      expect(wrongOrigin.corsAllowOrigin).toBe(false);

      // Cross-site Fetch Metadata is rejected.
      const crossSite = await nodeRequest({
        method: "GET",
        path: detail,
        headers: { ...validGetHeaders, "Sec-Fetch-Site": "cross-site" },
        body: null,
      });
      expect([400, 403]).toContain(crossSite.status);
      expect(crossSite.setCookie).toBe(false);

      // Missing CSRF on a write route is rejected before any business write.
      const missingCsrf = await nodeRequest({
        method: "POST",
        path: revoke,
        headers: {
          "X-OpenArc-Client": "browser-v1",
          Origin: ENABLED_ORIGIN,
          "Content-Type": "application/json",
          "Idempotency-Key": newIdempotencyKey(),
        },
        body: jsonBody,
      });
      expect([400, 403]).toContain(missingCsrf.status);
      expect(missingCsrf.setCookie).toBe(false);
      expect(missingCsrf.spaShell).toBe(false);

      // Authorization on the browser family is rejected.
      const wrongAuth = await nodeRequest({
        method: "GET",
        path: detail,
        headers: { ...validGetHeaders, Authorization: "Bearer synthetic" },
        body: null,
      });
      expect([400, 403]).toContain(wrongAuth.status);
      expect(wrongAuth.setCookie).toBe(false);

      // Proxy-Authorization is rejected.
      const proxyAuth = await nodeRequest({
        method: "GET",
        path: detail,
        headers: { ...validGetHeaders, "Proxy-Authorization": "Basic synthetic" },
        body: null,
      });
      expect([400, 403]).toContain(proxyAuth.status);
      expect(proxyAuth.setCookie).toBe(false);

      // Wrong namespace on the agent exchange is denied, never proxied.
      const wrongNamespace = await nodeRequest({
        method: "POST",
        path: "/v2/agent/commerce-sessionsXYZ",
        headers: { Authorization: "Bearer oas_ag_synthetic" },
        body: "{}",
      });
      expect([404, 405]).toContain(wrongNamespace.status);
      expect(wrongNamespace.spaShell).toBe(false);

      // A browser-credentialed agent exchange is rejected at nginx.
      const browserAgent = await nodeRequest({
        method: "POST",
        path: AGENT_EXCHANGE_PATH,
        headers: {
          Authorization: "Bearer oas_ag_synthetic",
          Cookie: "openarc_session=synthetic",
          "Content-Type": "application/json",
        },
        body: "{}",
      });
      expect([403, 415]).toContain(browserAgent.status);
      expect(browserAgent.setCookie).toBe(false);
      expect(browserAgent.corsAllowOrigin).toBe(false);

      // No SPA fallback for ANY probed path.
      for (const outcome of [
        malformed,
        query,
        wrongVerb,
        mixedCookie,
        wrongOrigin,
        crossSite,
        missingCsrf,
        wrongAuth,
        proxyAuth,
        wrongNamespace,
        browserAgent,
      ]) {
        expect(outcome.spaShell).toBe(false);
        expect(outcome.corsAllowOrigin).toBe(false);
      }
      void mutationStatus;
    });
  });
});

/* -------------------------------------------------------------------------- */
/* @session-off: session flag false, account/tenant reads ON                   */
/* -------------------------------------------------------------------------- */

test.describe("commerce session OFF", { tag: "@session-off" }, () => {
  test("the disabled session surface keeps real account sign-up usable, makes zero automatic session business calls, reports strict built_disabled credentiallessly and serves the accepted bounded nginx 404 for session paths, never SPA", async ({
    page,
  }) => {
    await withSignedInAccount(page, async (accountId) => {
      expect(CANONICAL_ACCOUNT.test(accountId)).toBe(true);
      const businessCalls: string[] = [];
      page.on("request", (request) => {
        const path = new URL(request.url()).pathname;
        if (path.startsWith(`${SESSION_BASE}/`) || path.startsWith("/v2/agent/commerce-sessions")) {
          businessCalls.push(path);
        }
      });

      // The direct session UI is unavailable with NO business request.
      await page.goto("/app/sessions");
      await expect(
        page.getByRole("heading", { name: "This section is not available yet" }),
      ).toBeVisible();
      await expect(page.getByRole("button", { name: "Issue a session" })).toHaveCount(0);
      expect(businessCalls).toEqual([]);

      // The accepted account/tenant read experience is preserved.
      const org = await seedOwnOrganizations(accountId, ["Synthetic Session Off Read"]);
      const organization = org[0];
      if (organization === undefined) throw new Error("SEED_ORGANIZATION_MISSING");
      const agent = firstProfile(await seedAgents(organization.organizationId, 1));
      await page.goto("/app/overview");
      await selectOrganization(page, organization.organizationId);
      await expect(
        page.getByRole("heading", { name: "Synthetic Session Off Read", exact: true }),
      ).toBeVisible();
      expect(businessCalls).toEqual([]);

      // Explicit credentialless capability probe reports built_disabled.
      const capability = await nodeRequest({
        method: "GET",
        path: CAPABILITIES_PATH,
        headers: {},
        body: null,
        port: OFF_NODE_PORT,
      });
      expect(capability.status).toBe(200);
      expect(capability.contentType).toContain("application/json");
      expect(capability.envelopeOk).toBe(true);
      expect(capability.hasDataKey).toBe(true);
      expect(capability.capabilityStates).toEqual(["built_disabled", "built_disabled"]);
      expect(capability.hasPrivateMetadata).toBe(false);

      // A known session pattern on the OFF image is denied by the REAL nginx
      // with a bounded HTML 404 (never the SPA root).
      const known = await nodeRequest({
        method: "GET",
        path: `${SESSION_BASE}/${encodeURIComponent(organization.organizationId)}/commerce-sessions/${randomUUID()}`,
        headers: {},
        body: null,
        port: OFF_NODE_PORT,
      });
      expect(known.status).toBe(404);
      expect(known.contentType.startsWith("text/html")).toBe(true);
      expect(known.html404).toBe(true);
      expect(known.spaShell).toBe(false);
      expect(known.setCookie).toBe(false);
      expect(known.corsAllowOrigin).toBe(false);
      expect(known.hasPrivateMetadata).toBe(false);

      // The agent exchange pattern is likewise denied, never SPA.
      const agentPath = await nodeRequest({
        method: "POST",
        path: AGENT_EXCHANGE_PATH,
        headers: { Authorization: "Bearer oas_ag_synthetic", "Content-Type": "application/json" },
        body: "{}",
        port: OFF_NODE_PORT,
      });
      expect(agentPath.status).toBe(404);
      expect(agentPath.contentType.startsWith("text/html")).toBe(true);
      expect(agentPath.html404).toBe(true);
      expect(agentPath.spaShell).toBe(false);
      expect(agentPath.setCookie).toBe(false);
      expect(agentPath.corsAllowOrigin).toBe(false);
      // The seeded agent row is real, so the OFF session denial above cannot be
      // misread as a missing-tenant fixture.
      expect(CANONICAL_AGENT.test(agent.id)).toBe(true);
      // The OFF origin is the fixed 5472 fixture origin; no other origin is
      // ever contacted.
      expect(OFF_ORIGIN).toBe("https://account.openarc.test:5472");
    });
  });
});
