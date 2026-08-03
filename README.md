# auth-service

OIDC/PKCE login for Flect apps. It sits next to your app on the **same origin**
(mounted at `/v1/auth`), runs the OAuth code+PKCE dance against your identity
provider, and hands your app a signed **`oidc_token` cookie** it can verify to
identify the user. It owns **no database** and deals in **identity only** — orgs
and roles are an [org-service](../org-service) question, never carried in the
token. Durable identity lives in [iam-service](../iam-service); auth delegates to
it when present, or runs login-only.

## What it provides

- **Browser SSO** — `/login` → IdP → `/oidc/callback`, sets a same-site
  `oidc_token` (HS256 JWT) plus session cookies; `/logout` clears them (optional
  IdP single-sign-out with `?sso=1`).
- **CLI device flow** — `/start` → `/poll/:state` → `/approve`, so a terminal can
  obtain a token by approving in the browser.
- **Token minting** — `GET /token` returns the identity JWT (`{ sub, type }`) for
  a signed-in session.

## Two modes

auth discovers whether an IAM service is reachable and adapts:

| | **login-only** (no IAM) | **IAM-backed** (`IAM_SERVICE_URL` set) |
|---|---|---|
| identity | the OIDC `subject` *is* the id | iam-service (`/sync` → a stable user id) |
| orgs / roles | never here — resolve via org-service | never here — resolve via org-service |
| `oidc_token` claims | `{ sub: <oidc subject>, type }` | `{ sub: <iam user id>, type }` |
| needs a database | **no** | no (auth owns none) |

`IAM_SERVICE_URL` is **injected by a Flect service binding**, never typed by a
user. Absent it, auth is login-only — perfect for an app that just wants "who is
this user".

## The token contract (what downstream apps read)

On login, auth sets cookie **`oidc_token`** — an HS256 JWT signed with the shared
`JWT_SECRET`. Any app on the same origin verifies it with that secret and reads:

- `sub` — the user id (stable per user). Scope your data by this.
- `type` — `"human"`.

There is **no `org_id` claim** — an app that needs org context calls org-service.
This is the single integration seam: **share `JWT_SECRET`, read `oidc_token.sub`.**

## Dependencies

- An **OIDC identity provider** — `OIDC_ISSUER` + a **PKCE client** whose redirect
  URI is `${APP_PUBLIC_URL}/v1/auth/oidc/callback`.
- **A cache** resolved via `@baseworks/sdk` (`env.kv('CACHE')` → raw `ioredis`) —
  the only persistence, holding transient PKCE/CLI state. No database.
- Optionally **[iam-service](../iam-service)** for durable identity (`/sync`).

## Configuration (env / `[vars]`)

| var | required | purpose |
|---|---|---|
| `JWT_SECRET` | ✅ | signs/verifies the shared-realm JWT (`oidc_token`) |
| `OIDC_ISSUER` | ✅ | IdP base URL |
| `OIDC_CLIENT_ID` | ✅ | PKCE client id |
| `OIDC_CLIENT_SECRET` | — | set only for a confidential client (PKCE public if absent) |
| `OIDC_SCOPE` | — | default `openid profile email offline_access` |
| `APP_PUBLIC_URL` | — | app origin; **injected by the platform**, overridable |
| `OIDC_POST_LOGOUT_URL` | — | exact post-logout URI for `?sso=1` |
| `AUTH_KV_BINDING` | — | cache binding name, default `CACHE` |
| `IAM_SERVICE_URL` | — | **injected by a service binding**; enables IAM identity mode |
| `IAM_BASE_PATH` | — | path prefix if IAM is reached through a gateway (e.g. `/v1/iam`) |
| `KV_CACHE_URL` | — | cache URL (`redis://…`); injected by the platform in prod |

## Deploy (as a sibling in a Flect app)

```toml
[[apps]]
name   = "auth"
image  = "ghcr.io/dotlabshq/auth-service:0.4.0"
port   = 3000
expose = "/v1/auth"          # same origin as the app that owns the domain

[vars]
JWT_SECRET     = "<shared realm secret>"
OIDC_ISSUER    = "https://your-idp.example"
OIDC_CLIENT_ID = "<pkce client id>"
APP_PUBLIC_URL = "https://<app>-<shortid>.up.flect.run"

# auth shares the app's cache (binding CACHE) — no store of its own to declare.
```

See [AGENTS.md](./AGENTS.md) for the full integration playbook (PKCE setup,
turning on IAM, the cookie contract) and [examples/notes](../flect/examples/notes)
for a live login-only app.

## Endpoints

Mounted at root; through `expose="/v1/auth"` the gateway strips the prefix, so
publicly they live under `/v1/auth/*`.

- Browser: `GET /login`, `GET /oidc/callback`, `GET /session`, `GET /logout`, `GET /token`
- CLI: `GET /start`, `GET /poll/:state`, `POST /approve`, `GET /token/done`
- `GET /healthz` → `{ ok, service, iam }` (`iam` reflects the mode)

## Develop

```bash
pnpm dev        # tsx watch, reads .env.local
pnpm test       # 15 — routers over an in-memory KV
pnpm build      # vitest run && tsup → dist/index.js
just release-docker 0.2.0
```
