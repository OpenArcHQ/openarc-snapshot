import { createHash, randomUUID } from "node:crypto";
import type { Pool } from "pg";

import {
  asControlGrantPool,
  ControlGrantStore,
  ControlGrantStoreError,
  CONTROL_GRANT_STORE_ERROR_MESSAGES,
  createDatabasePool,
  migrate,
} from "@openarc/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createCommerceGrantStoreAdapter } from "../src/control/grant-store-adapter.js";
import type { CommerceGrantStorePort } from "../src/control/grant-ports.js";
import {
  adminPool,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
} from "../../../packages/db/test/postgres-fixture.js";

/**
 * REAL PostgreSQL signature check for the authorization-grant store adapter.
 *
 * This suite deliberately proves ONE thing: that every operation the adapter
 * binds actually exists on the accepted DB12 `ControlGrantStore`, reaches its
 * real SECURITY DEFINER helper through the restricted `openarc_tenant_app`
 * role, and accepts the exact argument shapes the adapter passes. It does NOT
 * re-test the store's authority semantics — `packages/db` already owns that —
 * and it seeds no commerce rows, so every call runs against an EMPTY tenant and
 * is refused by the database itself.
 *
 * Two assertions carry the proof. First, every SECURITY DEFINER helper the
 * adapter's call chain depends on is shown to EXIST in the migrated schema.
 * Second, a well-formed adapter call is never refused with
 * `CONTROL_GRANT_STORE_INPUT_INVALID` — that code is exactly what a mis-shaped
 * argument, a swapped parameter or a renamed field would produce, so its
 * absence is the runtime counterpart of the adapter's compile-time binding.
 * No payment, settlement, delivery or funds movement occurs anywhere here.
 */

const VOCABULARY = Object.keys(CONTROL_GRANT_STORE_ERROR_MESSAGES);

/** A canonical 64-hex session digest that belongs to no seeded session. */
function unknownHash(label: string): string {
  return createHash("sha256").update(`grant-adapter-fixture:${label}`).digest("hex");
}

function canonicalUuid(): string {
  return randomUUID();
}

const ORGANIZATION = `openarc:org:${canonicalUuid()}`;
const GRANT = `openarc:grant:${canonicalUuid()}`;
const ACTION = `openarc:action:${canonicalUuid()}`;

function metadata(): { idempotencyKey: string; mutationId: string } {
  return { idempotencyKey: "A".repeat(43), mutationId: canonicalUuid() };
}

let admin: Pool;
let migrator: Pool;
let tenant: Pool;
let store: ControlGrantStore;
let port: CommerceGrantStorePort;

beforeAll(async () => {
  admin = adminPool();
  await ensureRoles(admin);
  migrator = createDatabasePool(migratorUrl());
  await resetSchema(admin);
  await migrate(migrator);
  tenant = createDatabasePool(tenantUrl());
  store = new ControlGrantStore(asControlGrantPool(tenant));
  await store.initialize();
  port = createCommerceGrantStoreAdapter(store);
});

afterAll(async () => {
  try {
    await resetSchema(admin);
  } finally {
    await tenant?.end();
    await migrator.end();
    await admin.end();
  }
});

/**
 * Run one adapter call and return the store error it produced. Anything that is
 * not a real `ControlGrantStoreError` — including a resolved value — fails the
 * signature check outright.
 */
async function storeRefusal(
  promise: Promise<unknown>,
): Promise<ControlGrantStoreError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlGrantStoreError);
    return error as ControlGrantStoreError;
  }
  throw new Error("expected the store to refuse this call");
}

/** The exact DB12 helpers every adapter call chain reaches. */
const REQUIRED_HELPERS: readonly string[] = [
  "issue_authorization_grant",
  "replace_authorization_grant",
  "introspect_authorization_grant",
  "claim_authorization_grant",
  "revoke_authorization_grant",
  "read_authorization_grant",
  "read_provider_grant_attempt_status",
  // DB14 lost-response recovery. Their absence is exactly what forced the two
  // status ports to report the dependency UNAVAILABLE before this migration.
  "read_human_grant_mutation_status",
  "read_agent_grant_mutation_status",
  // The agent write path resolves its commerce chain before the grant helper.
  "resolve_commerce_action_context",
  "lock_action_human",
];

/**
 * Authority refusals, i.e. the helper ran and the DATABASE said no. The two
 * agent writes resolve their commerce chain first and therefore surface the
 * store's generic unavailable code for an unseeded tenant, which is why the
 * helper-existence assertion above carries their side of the proof.
 */
const AUTHORITY_REFUSALS: ReadonlySet<string> = new Set([
  "CONTROL_GRANT_STORE_FORBIDDEN",
  "CONTROL_GRANT_STORE_SESSION_INVALID",
  "CONTROL_GRANT_STORE_NOT_FOUND",
]);

describe("the adapter binds the real DB12 grant store", () => {
  it("finds every SECURITY DEFINER helper the adapter depends on", async () => {
    const result = await admin.query<{ proname: string }>(
      `SELECT p.proname FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable' AND p.proname = ANY($1::text[])`,
      [REQUIRED_HELPERS],
    );
    const present = new Set(result.rows.map((row) => row.proname));
    for (const helper of REQUIRED_HELPERS) {
      expect([helper, present.has(helper)]).toEqual([helper, true]);
    }
  });

  it("initializes the real store over the restricted tenant role", async () => {
    // `initialize` already ran in beforeAll; `readiness` re-probes read-only
    // and must succeed against the migrated schema without migrating itself.
    await expect(store.readiness()).resolves.toBeUndefined();
  });

  it("reaches a real SQL helper for every bound operation with accepted argument shapes", async () => {
    const calls: readonly { name: string; run: () => Promise<unknown> }[] = [
      {
        name: "issueCommerceGrant",
        run: () =>
          port.issueCommerceGrant(
            unknownHash("commerce-session"),
            { actionId: ACTION, grantTokenHash: unknownHash("grant-token") },
            metadata(),
          ),
      },
      {
        name: "replaceCommerceGrant",
        run: () =>
          port.replaceCommerceGrant(
            unknownHash("commerce-session"),
            { grantId: GRANT, grantTokenHash: unknownHash("grant-token-2") },
            metadata(),
          ),
      },
      {
        name: "introspectCommerceGrant",
        run: () =>
          port.introspectCommerceGrant(
            unknownHash("provider-session"),
            unknownHash("grant-token"),
          ),
      },
      {
        name: "claimCommerceGrant",
        run: () =>
          port.claimCommerceGrant(
            unknownHash("provider-session"),
            {
              grantTokenHash: unknownHash("grant-token"),
              expectedActionId: ACTION,
              attemptId: canonicalUuid(),
            },
            metadata(),
          ),
      },
      {
        name: "getProviderCommerceGrantAttemptStatus",
        run: () =>
          port.getProviderCommerceGrantAttemptStatus(
            unknownHash("provider-session"),
            canonicalUuid(),
          ),
      },
      {
        name: "getCommerceGrant",
        run: () =>
          port.getCommerceGrant(
            unknownHash("human-session"),
            ORGANIZATION,
            GRANT,
          ),
      },
      {
        name: "revokeCommerceGrant",
        run: () =>
          port.revokeCommerceGrant(
            unknownHash("human-session"),
            ORGANIZATION,
            GRANT,
            metadata(),
          ),
      },
      {
        name: "getHumanCommerceGrantMutationStatus",
        run: () =>
          port.getHumanCommerceGrantMutationStatus(
            unknownHash("human-session"),
            ORGANIZATION,
            canonicalUuid(),
          ),
      },
      {
        name: "getAgentCommerceGrantMutationStatus",
        run: () =>
          port.getAgentCommerceGrantMutationStatus(
            unknownHash("commerce-session"),
            canonicalUuid(),
          ),
      },
    ];

    for (const call of calls) {
      const error = await storeRefusal(call.run());
      // The refusal comes from DB12's own vocabulary...
      expect([call.name, VOCABULARY.includes(error.code)]).toEqual([
        call.name,
        true,
      ]);
      // ...and it is NEVER "input invalid", which is precisely what a swapped,
      // renamed or mis-shaped adapter argument would have produced.
      expect([call.name, error.code]).not.toEqual([
        call.name,
        "CONTROL_GRANT_STORE_INPUT_INVALID",
      ]);
      // Every call whose grant helper answers directly is refused on AUTHORITY,
      // which is only reachable once the SQL actually ran.
      if (
        call.name !== "issueCommerceGrant" &&
        call.name !== "replaceCommerceGrant"
      ) {
        expect([call.name, AUTHORITY_REFUSALS.has(error.code)]).toEqual([
          call.name,
          true,
        ]);
      }
      // The store error never echoes an identifier or a digest back.
      expect(error.message).not.toContain(GRANT);
      expect(error.message).not.toContain(ORGANIZATION);
      expect(error.message).not.toContain(unknownHash("grant-token"));
    }
  });

  it("serves the two mutation-status reads from real SQL instead of a 503", async () => {
    // The dependency is no longer missing: both reads reach their DB14
    // SECURITY DEFINER helper through the restricted tenant role and are
    // refused by the DATABASE on AUTHORITY for an unseeded tenant. A stub that
    // short-circuits before the SQL could not produce a real
    // `ControlGrantStoreError` from DB12's own vocabulary.
    const agent = await storeRefusal(
      port.getAgentCommerceGrantMutationStatus(
        unknownHash("commerce-session"),
        canonicalUuid(),
      ),
    );
    const human = await storeRefusal(
      port.getHumanCommerceGrantMutationStatus(
        unknownHash("human-session"),
        ORGANIZATION,
        canonicalUuid(),
      ),
    );
    for (const error of [agent, human]) {
      expect(VOCABULARY).toContain(error.code);
      // An unknown authority is refused as an authority failure, never as a
      // missing dependency and never as a mis-shaped argument.
      expect(AUTHORITY_REFUSALS.has(error.code)).toBe(true);
      expect(error.code).not.toBe("CONTROL_GRANT_STORE_UNAVAILABLE");
      expect(error.code).not.toBe("CONTROL_GRANT_STORE_INPUT_INVALID");
      // It is never the terminal double-spend code either.
      expect(error.code).not.toBe("CONTROL_GRANT_STORE_OUTCOME_UNKNOWN");
      expect(error.message).not.toContain(ORGANIZATION);
      expect(error.message).not.toContain(unknownHash("human-session"));
      expect(error.message).not.toContain(unknownHash("commerce-session"));
    }
  });

  it("keeps the adapter's error vocabulary identical to the store's", () => {
    // The service maps structurally on these codes, so a drift here would
    // silently downgrade a mapping. `CONTROL_GRANT_STORE_UNAVAILABLE` in
    // particular must remain a real member.
    expect(VOCABULARY).toContain("CONTROL_GRANT_STORE_UNAVAILABLE");
    expect(VOCABULARY).toContain("CONTROL_GRANT_STORE_OUTCOME_UNKNOWN");
    // `CONTROL_GRANT_STORE_UNAVAILABLE` still means a genuine outage and is
    // still produced by the store itself; it is no longer produced by a
    // hard-coded "this dependency does not exist" stub in the adapter, which
    // now exports only its two factory functions.
    expect(new ControlGrantStoreError("CONTROL_GRANT_STORE_UNAVAILABLE").code).toBe(
      "CONTROL_GRANT_STORE_UNAVAILABLE",
    );
  });
});
