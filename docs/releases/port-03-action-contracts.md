# PORT-03 action / approval core contracts

September 12, 2026. Exact OpenCode CLI `opencode-go/deepseek-v4.1-flash`
implementation, source based on `4b57483`; separate read-only backend review
passed the bounded new module, test file and additive export.

Strict organization-protected action and approval metadata describes the next
database engine's stages, exact amount/fee/debit relationship, stable exposure
identity, requirement reference, pinned policy/listing versions and decision
metadata. UUIDv4 namespaces and monetary/version/digest boundaries are canonical
and absolute-end validated. Timestamp/state/nullability and separate-approver
relationships are checked as declared shape only.

Parsing never establishes current authority, requirement verification, consent,
reservation, grant or payment. `reserved_not_granted` explicitly cannot be
represented as paid or settled. No runtime/capability/routes or database writes
are introduced; public listings remain payment-unavailable.

All final checks exited 0: 39 focused tests, 1,104 complete shared tests across
36 files, shared build/typecheck and targeted ESLint. Existing tests unchanged.
Durable financial enforcement and whole-phase acceptance remain unfinished.
