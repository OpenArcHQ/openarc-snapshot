import { expect, test } from "@playwright/test";

/**
 * P04-06 — the browser purchase handoff fails closed.
 *
 * With the commerce-action flag absent (the default), opening a purchase
 * address must construct no purchase controller, make ZERO commerce or
 * capability requests, and render no review, amount or decision control. A
 * disabled deployment must never show a purchase surface at all.
 */

const ACTION_ID = "openarc:action:12345678-1234-4234-8123-123456789abc";

test("makes no purchase or capability request when commerce actions are off", async ({ page }) => {
  const commerceRequests: string[] = [];
  page.on("request", (request) => {
    // Only real API calls count. The dev server also serves module source over
    // `/@fs/...`, which is a bundler fetch and not a request to the commerce
    // surface, so the match is anchored to the `/v2/` API root.
    const { pathname } = new URL(request.url());
    if (pathname.startsWith("/v2/")) commerceRequests.push(pathname);
  });

  await page.goto(`/app/actions/${encodeURIComponent(ACTION_ID)}`);
  await page.waitForLoadState("networkidle");

  // No purchase surface and no decision control exists to be clicked.
  await expect(page.getByRole("heading", { name: /Review purchase/iu })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Approve purchase" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Reject purchase" })).toHaveCount(0);
  // Nothing was asked of the commerce surface, not even the public probe.
  expect(commerceRequests).toEqual([]);
});

test("never renders a payment outcome word on the disabled purchase address", async ({ page }) => {
  await page.goto(`/app/actions/${encodeURIComponent(ACTION_ID)}`);
  await page.waitForLoadState("networkidle");
  const body = (await page.locator("body").innerText()).toLowerCase();
  for (const forbidden of ["paid", "settled", "refunded", "released"]) {
    expect(body).not.toMatch(new RegExp(`\\b${forbidden}\\b`, "u"));
  }
});
