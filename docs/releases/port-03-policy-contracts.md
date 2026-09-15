# PORT03 policy contract foundation

September12, 2026. Component acceptance only; PORT03 and the whole port remain
incomplete. Implementation/tests authored through OpenCode Go
`opencode-go/deepseek-v4.1-flash`; lead planned and reviewed.

Strict policy content, immutable revision and stable root schemas now describe
exact Testnet ERC-20 USDC/6 limits, explicit fee ceiling, true rolling-window
configuration, intersected external provider/listing allowlists, approval shape
and optional policy expiry. Zero limits deny spending; empty allowlists do not
mean unrestricted access. Policy revisions cannot represent balance resets.

These are shape validators only: no SQL, HTTP, UI, hashing, new machine scope,
budget reservation, approval decision, grant, payment or execution was added.
Parsing a declared digest does not verify it. Existing read-only machine tokens
remain read-only. External wallet/network spending is outside these definitions.

Lead review reproduced a malformed approval threshold throwing from BigInt in a
continuing Zod refinement. The correction guards conversion with the accepted
integer validator. Direct and nested exponent/fraction/letters/overflow/newline
vectors now reject normally without throwing.

- Focused policy schema suite: **95 passed**.
- Complete shared suite: **706 passed**.
- Shared build, type checks and owned-file lint: **passed**.
- Independent malformed-threshold reproduction after the fix: **passed**.

Persistence, concurrency, authorization and real PostgreSQL policy evidence are
the next component. This report does not claim deployment or spending readiness.
