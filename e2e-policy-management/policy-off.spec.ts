import { expect, test, type Page } from "@playwright/test";

// Policy-management flag OFF.
//
// Same parent flags as the ON server (account access, tenant reads and the API
// boundary enabled) but the policy flag is false. The shell must make ZERO
// control-capability or policy requests, and the pre-existing workspace routes
// must be unchanged. These are honestly labelled UI contract tests with
// synthetic fixtures, never actual API/PG evidence.

const META = {
  schemaVersion: "openarc.api.v2",
  requestId: "018f47a2-3b4c-7def-8123-456789abcdef",
  buildSha: "0123456789abcdef0123456789abcdef01234567",
};

const UUID = "12345678-1234-4234-8123-123456789abc";
const ORG_A = `openarc:org:${UUID}`;
const ACCOUNT_A = `openarc:account:${UUID}`;
const CREATED = "2026-01-01T00:00:00.000Z";

function envelope(data: unknown): string {
  return JSON.stringify({ ok: true, data, meta: META });
}

function organization(organizationId: string) {
  return {
    schemaVersion: "openarc.organization.v1",
    organizationId,
    displayName: "Organization 0",
    createdAt: CREATED,
    updatedAt: CREATED,
  };
}

function context() {
  return {
    organization: organization(ORG_A),
    access: {
      schemaVersion: "openarc.organization-access.v1",
      organizationId: ORG_A,
      accountId: ACCOUNT_A,
      role: "owner",
      membershipStatus: "active",
      sessionExpiresAt: "2030-01-01T00:00:00.000Z",
    },
    network: "eip155:5042002",
  };
}

async function instrument(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const w = window as typeof window & { __policyPaths?: string[] };
    w.__policyPaths = [];
    const originalFetch = window.fetch.bind(window);
    window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      const value = String(input);
      if (
        value.includes("control-capabilities") ||
        value.includes("/v2/control/organizations")
      ) {
        w.__policyPaths?.push(`${init?.method ?? "GET"} ${value}`);
      }
      return originalFetch(input, init);
    };
  });
}

async function stubParents(page: Page): Promise<void> {
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
    await route.fulfill({ status: 500, contentType: "application/json", body: "{}" });
  });
  await page.route("**/v2/control/organizations/**", async (route) => {
    await route.fulfill({ status: 500, contentType: "application/json", body: "{}" });
  });
  await page.route("**/v1/operator/organizations?*", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope({ items: [organization(ORG_A)], nextCursor: null }) });
  });
  await page.route("**/v1/operator/organizations", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope({ items: [organization(ORG_A)], nextCursor: null }) });
  });
  await page.route("**/v1/operator/organizations/*/agents*", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope({ organizationId: ORG_A, items: [], nextCursor: null }) });
  });
  await page.route("**/v1/operator/organizations/*", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: envelope(context()) });
  });
}

async function open(page: Page, path: string): Promise<void> {
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

test("makes zero capability or policy requests on the policy roots route", async ({ page }) => {
  await instrument(page);
  await stubParents(page);
  await open(page, "/app/budgets");
  await expect(page.getByRole("heading", { name: "This section is not available yet" })).toBeVisible();
  const paths = await page.evaluate(() => (window as typeof window & { __policyPaths?: string[] }).__policyPaths ?? []);
  expect(paths).toEqual([]);
});

test("makes zero capability or policy requests on the policy new route", async ({ page }) => {
  await instrument(page);
  await stubParents(page);
  await open(page, "/app/budgets/new");
  await expect(page.getByRole("heading", { name: "This section is not available yet" })).toBeVisible();
  const paths = await page.evaluate(() => (window as typeof window & { __policyPaths?: string[] }).__policyPaths ?? []);
  expect(paths).toEqual([]);
});

test("makes zero capability or policy requests on a policy detail route", async ({ page }) => {
  await instrument(page);
  await stubParents(page);
  await open(page, `/app/budgets/${encodeURIComponent(`openarc:policy:${UUID}`)}`);
  await expect(page.getByRole("heading", { name: "This section is not available yet" })).toBeVisible();
  const paths = await page.evaluate(() => (window as typeof window & { __policyPaths?: string[] }).__policyPaths ?? []);
  expect(paths).toEqual([]);
});

test("preserves the pre-existing workspace routes", async ({ page }) => {
  await instrument(page);
  await stubParents(page);
  await open(page, "/app/provider");
  await expect(page.getByRole("heading", { name: "Provider" })).toBeVisible();
  const paths = await page.evaluate(() => (window as typeof window & { __policyPaths?: string[] }).__policyPaths ?? []);
  expect(paths).toEqual([]);
});
