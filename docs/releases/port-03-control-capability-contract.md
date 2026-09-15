# PORT-03 control capability contract

Accepted pure shared contract, September12, 2026, based on c9c9a28. Implementation
and tests were authored with DeepSeek V4.1 Flash through OpenCode CLI; lead and
independent review covered integration and contract boundaries.

Adds a separate browser-only `policy_management` capability family and exact
ten-route registry. The environment is Arc Testnet, `eip155:5042002`. It does not
modify either existing capability inventory, register an HTTP route, open a
database, authorize spending or enable a deployment flag.

Verification:22 focused tests,860 complete shared-package tests, shared build,
typecheck and lint passed. Strict whole-manifest validation covers family,
dependencies, exact route tuples, ordering, unknown fields and bounded shape.
Review caught shallow freezing of Zod-cloned manifest data; the final candidate
freezes every nested layer and mutation tests pass against the exported object.

Policy API/runtime, production proxy and UI remain separate acceptance steps.
This contract is not evidence that the financial engine or PORT-03 is complete.
