# Writing an agent client for the OpenArc agent surfaces

The agent and headless surfaces refuse requests that look like they came from a
browser. This is deliberate: a browser-originated call must never reach a
surface that spends an agent's budget, and the check is part of the audience
separation between browser, agent and provider credentials.

## Node's global `fetch` cannot call these routes

Node's built-in `fetch` (undici) always sends `sec-fetch-mode: cors`. The agent
transport guard rejects that, so **every** call made with global `fetch` is
answered with `400 INVALID_REQUEST`, whatever the credential. `sec-fetch-*` is a
forbidden header name, so a caller cannot remove or override it.

The identical request made with `node:http` or `node:https` is accepted.

```js
// Refused with 400 INVALID_REQUEST, even with a valid commerce session.
await fetch(url, { method: "POST", headers: { authorization: `Bearer ${token}` } });
```

Write the request directly instead:

```js
import { request } from "node:https";
// or node:http for a loopback development stack
```

The reference implementations do exactly that: `tools/agent-harness` for the
buyer side and `tools/x402-reference-provider` for the seller side. Both send
only the headers the surface expects and never set a `sec-fetch-*` header.

## What the guard checks

Any of these headers present on an agent or headless route is refused with
`400 INVALID_REQUEST`, before the credential is even read:

`cookie`, `origin`, `x-openarc-client`, `x-openarc-csrf`, `sec-fetch-site`,
`sec-fetch-mode`, `sec-fetch-dest`, `sec-fetch-user`, `proxy-authorization`.

A duplicate of any critical header is refused the same way, and an
over-long request URL is refused before anything else.

The credential must then match the namespace that surface accepts, as a single
`Bearer` value:

| Surface | Accepted credential |
| --- | --- |
| Commerce session exchange | `oas_ag_…` machine credential |
| Buyer agent routes (actions, grants, payments) | `oacs_v1_…` commerce session |
| Provider routes (claim, introspect) | `oas_pr_…` provider credential |

The machine credential is valid **only** at the session exchange. It is not
accepted on any spending surface, which is the audience separation the guards
exist to enforce. Provider claim additionally carries the one-use grant secret
in the request body, never in a header.

A browser client uses the browser audience instead, with a cookie, an Origin, a
client marker and a CSRF token. Those routes expect no `Authorization` header:
the payment-terms route, for example, refuses any request that carries one.
