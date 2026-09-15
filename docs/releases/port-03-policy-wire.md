# PORT03 policy management wire contracts

September12, 2026. Pure shared DTO component, authored through exact OpenCode Go
`opencode-go/deepseek-v4.1-flash`. No database, API, UI, session, reservation,
approval, grant or payment is enabled by this packet.

Strict write bodies, read requests, metadata-only history pages, root/version
details, exact operation/resource receipts, mutation status and APIv2 envelopes
bind organization/policy/version/cursor identity without carrying credentials,
actor claims, raw signatures or private payloads. A parsed receipt is not current
authority; downstream services must revalidate principal and resource binding.

Review closed two boundary defects: status transitions now permit the final
revision (while append still requires room for a successor), and revision
resource IDs correctly accept10/100 and other values beginning with1. Strict
malformed-input rejection and non-throwing refinements remain intact.

- Focused wire tests: **132 passed**.
- Complete shared tests: **838 passed**.
- Shared type check, build and owned-file lint: **passed**.
- Independent bounded review and two-finding closure: **passed**.

This is not a PORT03 phase gate, deployed policy management or enforced budget.
