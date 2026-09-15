# PORT-03 commerce-action notification handlers

Accepted 2026-09-15 UTC, based on `32c4f8d`. Adds the four notification-only
commerce-action outbox events to the worker's closed handler registry:
authorized, approved, rejected and cancelled.

Owned files: `apps/worker/src/handlers.ts`, `apps/worker/test/worker.test.ts`.

## Verification

Run in an isolated container against this revision: `@openarc/worker` unit tests
passed 47/47 (41 before the merge; one inventory test was widened in place and
six were added, none removed). Worker typecheck exited 0 and ESLint over both
owned files exited 0 with `--max-warnings=0`.

## Lead review

The diff is additive and confined to the two owned files. The closed union gains
exactly four tuples; the safe metadata keyset is unchanged, so no new field can
cross the handler boundary. The new `COMMERCE_ACTION_ID` pattern requires the
canonical lower-case `openarc:action:` prefix and a UUIDv4 with an absolute-end
anchor, matching the accepted DB10 outbox-store pattern byte for byte, so a
trailing newline, a suffix or a UUIDv1 is rejected rather than coerced. All four
tuples map to `consume`: there is no financial effect, no dynamic callback, no
user URL and no plugin handler, and the original event is never JSON-logged.

## Boundary and deferred evidence

These handlers are notification-only. Consumption from **actual action lifecycle
transactions** in PostgreSQL is deliberately NOT proven here and remains open
until DB10 is integrated; direct outbox inserts are not a substitute for that
end-to-end evidence. DB10 is not in this checkout yet, so migrations still end
at `0009_control_sessions.sql` and no commerce-action event can currently be
produced by a real lifecycle. Whole PORT-03 acceptance and publication remain
pending.
