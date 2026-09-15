# PORT-03 grant token primitives

September 12, 2026. Exact OpenCode CLI `opencode-go/deepseek-v4.1-flash`
implementation, reviewed by the lead. Source based on private `dcb222a`.

This bounded component adds only a canonical typed UUIDv4 grant ID, a distinct
`oag_v1_` 256-bit token grammar, CSPRNG generation and purpose-separated SHA-256
hashing (version1). It does not create an authoritative grant, reserve money,
claim an action, call a provider or persist/replay a raw token.

Malformed values are rejected before hashing. Crypto failures have a fixed,
non-echoing error surface. Generation clears its entropy buffer. Review corrected
a comment typo and replaced a misleading zeroing test with assertions against
the actual synthetic buffer returned to the module, on success and failure.

Final focused/static checks, all exit 0:

- 34 shared grammar tests.
- 33 API crypto tests.
- API/dependency build, API typecheck and targeted ESLint.

The full phase gate was not rerun for this isolated primitive. One-use grant
issuance, authenticated claim, replacement and durable exposure integration
remain separate unfinished PORT-03 work. No deployment or authority activation.
