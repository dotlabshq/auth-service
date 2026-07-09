# AGENTS.md — auth-service

Operating manual for AI coding agents. Read this before wiring auth into a
project or changing this service. Companion: [README.md](./README.md).

## What this service is

A stateless OIDC/PKCE login service that runs **as a sibling of your app on the
same origin** (`/v1/auth`) and gives the app a verifiable `oidc_token` cookie.
It owns **no database**. Identity + org data live in [iam-service](../iam-service);
auth either delegates to IAM or runs **login-only** (the OIDC subject is the
identity, no orgs). See ADR-006/007 in `../../docs/decisions`.

## The one rule

**auth never persists user or org data.** If you find yourself adding a table,
a migration, or a `@baseworks/account`/`@baseworks/organization` import here, stop
— that belongs in iam-service. auth's only persistence is a cache (`env.kv`) for
transient PKCE/CLI state.

## Architecture in one paragraph

`createEnv()` (from `@getflect/sdk`) resolves one cache binding through the broker
(`FLECT_TOKEN` + `FLECT_BROKER_URL`) — no substrate URLs, ADR-0004. On `/login`
auth builds a PKCE auth URL; on `/oidc/callback` it exchanges the code, then
**resolves the platform identity**: if `IAM_SERVICE_URL` is set it calls
iam-service (`/sync` → user id, `/me`|`/orgs` → org), otherwise the OIDC `subject`
is the identity. It stores `{ userId, orgId }` in the session cookie and sets the
`oidc_token` JWT (HS256, `JWT_SECRET`). Downstream apps verify that JWT and read
`sub`. Files: `src/routes/oidc.ts` (browser), `src/routes/cli.ts` (device flow),
`src/lib/iam.ts` (IAM client + mode detection), `src/lib/cookies.ts` (cookie
shapes), `src/index.ts` (wiring).

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

### Turning on user + org management (IAM mode)

Only when the app needs accounts/orgs/RBAC, not just "who is this user":

1. Deploy [iam-service](../iam-service) reachable from auth.
2. Bind it as a service so auth **discovers** it — the deployer injects
   `IAM_SERVICE_URL` (auth appends `/sync`, `/me`, `/orgs`). If IAM is reached
   through a gateway rather than a direct service binding, also set
   `IAM_BASE_PATH=/v1/iam`.
3. Optionally `CREATE_DEFAULT_ORG=true` to seed a default org on first login.

With IAM present, `oidc_token` gains `org_id`, `/token-for-org` works, and
`/healthz` reports `iam:true`. Nothing else in the app changes — it still just
reads `sub` (and `org_id` if it cares).

## Contracts you must not break

- **Shared-realm `JWT_SECRET`.** auth signs `oidc_token`; every consumer verifies
  with the same secret. Changing it invalidates all live sessions.
- **`oidc_token` claim shape** — `{ sub, org_id?, type:"human" }`. `org_id` is
  absent in login-only mode; consumers must treat it as optional.
- **Same origin.** auth must be `expose`d under the app's origin (`/v1/auth`) so
  the cookie is same-site. A separate subdomain reintroduces the cross-site
  cookie problem this design avoids.
- **IAM discovery, not configuration.** `IAM_SERVICE_URL` comes from a service
  binding; never hardcode a platform endpoint in `flect.toml` (ADR-0004).

## Depends on

- An OIDC IdP (issuer + PKCE client).
- `@getflect/sdk` — resolves the cache binding via the broker.
- Optionally iam-service (`IAM_SERVICE_URL`).

## Build / test / ship

```bash
pnpm test                    # 22 tests: CLI flow, /session, /token, token-for-org (login-only + IAM)
pnpm build                   # runs tests, then tsup → dist/index.js
just release-docker <tag>    # build + push ghcr.io/dotlabshq/auth-service:<tag>
```

Tests mock iam-service with `installIamMock` (see `src/__tests__/setup.ts`) — no
real IAM needed to cover IAM mode.
