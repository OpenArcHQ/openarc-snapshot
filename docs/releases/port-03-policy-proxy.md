# PORT-03 policy proxy acceptance checkpoint

September 12, 2026. Exact OpenCode `opencode-go/deepseek-v4.1-flash` authored
the default-off policy proxy and its deployment guards. Independent source
review passed. Nineteen focused guards and 153 combined deployment/CI guards
passed; focused lint and shared build passed (all exit 0).

The ten policy routes retain bounded methods, headers, body and encoded-path
handling. The two mixed GET/POST parents enforce 16 KiB before internal POST
dispatch while GET remains bodyless. Policy-only proxy installation does not
depend on unrelated tenant/machine/market flags. Credentialless capability and
deny-only fallbacks are installed without exposing business routes when off.

The source gate timeout increases from 25 to 40 minutes because the preceding
verified gate took 24m14s. Three existing exact timeout assertions were aligned
with that deliberate change; no assertions or gates were removed.

## Actual production image boundary checks

Source `50b765651386eb0e4d76b47beeeacebecf8b4b0c` built four real nginx images:
policy-only, policy-off, Arc plus policy, and no-API. All four entrypoint/template
startup and `nginx -t` checks passed. Fifty-six actual request boundary checks
passed across encoded route dispatch, unsupported methods, disabled/lookalike
paths, query restrictions, capability credentials, and 16 KiB body enforcement.

The isolated upstream was deliberately absent: forwarded requests returned 502,
while rejected requests returned their expected boundary status. This verifies
proxy dispatch/rejection, not successful API TLS or browser authentication.
Actual combined-image API/browser checks and full control-phase acceptance are
still pending. No deployment or financial enforcement is established here.
