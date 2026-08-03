# AGENTS.md — auth-service

Operating manual for AI coding agents. Read this before wiring auth into a
project or changing this service. Companion: [README.md](./README.md).

## What this service is

A stateless OIDC/PKCE login service that runs **as a sibling of your app on the
same origin** (`/v1/auth`) and gives the app a verifiable `oidc_token` cookie
carrying **identity only** (`{ sub, type }`). It owns **no database**.

auth deals in identity, never orgs. A user has no org of their own — only
memberships — so org context is an **org-service** question, resolved by the app
when it needs one, never carried in the auth token. Durable identity lives in
[iam-service](../iam-service): when reachable, auth registers the login there
(`/sync`) to get a stable user id; otherwise it is **login-only** (the OIDC
subject is the identity).

## The one rule

**auth never persists user or org data.** If you find yourself adding a table,
a migration, or a `@baseworks/account`/`@baseworks/organization` import here, stop
— that belongs in iam-service. auth's only persistence is a cache (`env.kv`) for
transient PKCE/CLI state.

## Architecture in one paragraph

`createEnv()` (from `@baseworks/sdk`) resolves one cache binding — `env.kv('CACHE')`
returns a raw `ioredis` client for transient PKCE/CLI state (`KV_CACHE_URL`, no
substrate URLs in config, ADR-0004). On `/login` auth builds a PKCE auth URL; on
`/oidc/callback` it exchanges the code, then **resolves the platform identity**:
if `IAM_SERVICE_URL` is set it calls iam-service (`/sync` → user id), otherwise the
OIDC `subject` is the identity. It stores `{ userId }` in the session cookie and
sets the `oidc_token` JWT (HS256, `JWT_SECRET`, `{ sub, type }`). Downstream apps
verify that JWT and read `sub`. Files: `src/routes/oidc.ts` (browser),
`src/routes/cli.ts` (device flow), `src/lib/iam.ts` (IAM `/sync` client + mode
detection), `src/lib/cookies.ts` (cookie shapes), `src/index.ts` (wiring).

## How to integrate auth into a Flect app

Goal: give an app "sign in with our IdP" without a separate domain or a
cross-site cookie. Steps:

1. **Add auth as a sibling app** in the app's `flect.toml`, exposed on the same
   origin at `/v1/auth`:
   ```toml
   [[apps]]
   name   = "auth"
   image  = "ghcr.io/dotlabshq/auth-service:0.4.0"
   port   = 3000
   expose = "/v1/auth"
   ```
2. **Register a PKCE client** on the IdP with redirect URI
   `${APP_PUBLIC_URL}/v1/auth/oidc/callback`. You often need one deploy first to
   learn the generated `APP_PUBLIC_URL` (`https://<app>-<shortid>.up.flect.run`),
   then register the callback and set the id.
3. **Set `[vars]`** — `JWT_SECRET` (the shared realm secret, **same value the app
   uses to verify**), `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `APP_PUBLIC_URL`. auth
   shares the app's cache (binding `CACHE`), so declare no store for it.
4. **In the app, read the cookie.** Verify `oidc_token` (HS256, `JWT_SECRET`) and
   use `sub` as the user id:
   ```ts
   import { getCookie } from "hono/cookie"
   import { createHmac, timingSafeEqual } from "node:crypto"
   function userFrom(c): string | null {
     const t = getCookie(c, "oidc_token"); if (!t) return null
     const [h, p, s] = t.split("."); if (!h || !p || !s) return null
     const exp = createHmac("sha256", process.env.JWT_SECRET!).update(`${h}.${p}`).digest("base64url")
     if (!timingSafeEqual(Buffer.from(s), Buffer.from(exp))) return null
     const c2 = JSON.parse(Buffer.from(p, "base64url").toString())
     return c2.exp * 1000 > Date.now() ? c2.sub : null
   }
   ```
5. **Add login/logout links** — redirect to `/v1/auth/login?redirectTo=/` and
   `/v1/auth/logout?redirectTo=/`.

That is the whole login-only integration. `examples/notes` in the flect repo is a
working reference.

### Registering identities in IAM (identity mode)

Turn this on so logins map to a **stable, durable user id** (instead of the raw
OIDC subject) — e.g. so the same person keeps one id across IdP changes, and
other services can resolve them:

1. Deploy [iam-service](../iam-service) reachable from auth.
2. Bind it as a service so auth **discovers** it — the deployer injects
   `IAM_SERVICE_URL` (auth calls `POST /sync`). If IAM is reached through a
   gateway rather than a direct service binding, also set `IAM_BASE_PATH=/v1/iam`.

With IAM present, `oidc_token.sub` is the IAM user id and `/healthz` reports
`iam:true`. The token shape is unchanged (identity only). **Orgs are never
auth's job** — an app that needs org context calls org-service directly; there is
no `org_id` claim and no `/token-for-org`.

## Contracts you must not break

- **Shared-realm `JWT_SECRET`.** auth signs `oidc_token`; every consumer verifies
  with the same secret. Changing it invalidates all live sessions.
- **`oidc_token` claim shape** — `{ sub, type:"human" }`. Identity only; there is
  no `org_id` claim. An app that needs org context resolves membership via
  org-service — auth never scopes a token to an org.
- **Same origin.** auth must be `expose`d under the app's origin (`/v1/auth`) so
  the cookie is same-site. A separate subdomain reintroduces the cross-site
  cookie problem this design avoids.
- **IAM discovery, not configuration.** `IAM_SERVICE_URL` comes from a service
  binding; never hardcode a platform endpoint in `flect.toml` (ADR-0004).

## Depends on

- An OIDC IdP (issuer + PKCE client).
- `@baseworks/sdk` — `env.kv('CACHE')` resolves the cache (raw `ioredis`).
- Optionally iam-service (`IAM_SERVICE_URL`) for durable identity.

## Build / test / ship

```bash
pnpm test                    # 15 tests: CLI flow (/start /poll), /session, /token, login-only
pnpm build                   # runs tests, then tsup → dist/index.js
just release-docker <tag>    # build + push ghcr.io/dotlabshq/auth-service:<tag>
```

Tests wire the routers over an in-memory KV (`src/__tests__/setup.ts`) — no real
cache or IAM needed. `/token` and CLI `/approve` mint from the session cookie, so
IAM mode needs no mock (identity is already resolved into the session).
