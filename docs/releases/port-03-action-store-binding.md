# PORT-03 action store adapter

Accepted 2026-09-15 UTC. Binds the commerce-action service ports to the real
DB10 mutation store and DB11 read store.

`apps/api/src/control/action-store-adapter.ts` is deliberately thin and does
exactly three things: it renames methods, reshapes two results into the wrapper
shape the port declares, and converts the port's integer page limit back into
the canonical string the read store accepts. It performs no authority,
financial, transport or validation work of its own. Both store imports are
type-only and therefore erased, so the concrete stores stay injected and the
service remains testable with fakes.

Where the adapter echoes a caller-supplied organization — `getCommerceAction`
and `getCommerceExposure`, whose DB10 reads return bare metadata — it does so
only because the store validates the caller's current authority against that
exact organization and throws otherwise, the not-found path included, so a value
is echoed only after authority has already passed for it. The agent read and the
DB11 reads use the store's own organization verbatim. The service re-validates
every assembled shape against the accepted shared wire schemas.

The limit conversion renders only an integer in 1..50 and otherwise passes the
value through unchanged, so the read store's own validation rejects it with its
fixed error rather than the adapter inventing one or silently clamping a page
size.

Verified: `@openarc/api` typecheck, build and ESLint exit 0; the API unit suite
stays at 61 files / 1,110 tests.

## Remaining blocker for enabling the agent lane

`server.ts` still cannot complete the binding, and the reason is concrete:
the runtime requires a `CommerceSessionReadPort` exposing
`getCommerceSessionByHash(tokenHash)`, and **no such read exists in the database
layer**. `CommerceSessionStore.getCommerceSessionStatus` requires a *human*
session hash, organization and session id, so it cannot resolve a bearer.
Searching `0009_control_sessions.sql` confirms no SQL helper resolves a commerce
session from its bearer token hash into `CommerceControlSessionMetadata`;
`read_agent_commerce_session_mutation_status` takes a token hash but returns a
mutation receipt.

This needs a small new migration adding that read, sequenced **after** DB12's
`0012_authorization_grants.sql` to avoid a migration-number collision. Until
then the runtime correctly reports `built_disabled` and, with the flag on,
`createApp` fails startup rather than serving a family the capability manifest
advertises. The nine browser routes depend only on DB10/DB11 and are already
adapted; the three agent routes are what this read unblocks.
