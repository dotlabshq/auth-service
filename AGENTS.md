# AGENTS.md — auth-service

Operating manual for whoever changes this service. [README.md](./README.md) is
how to use it; [openapi.yaml](./openapi.yaml) is the contract; the workspace
[AGENTS.md](../../AGENTS.md) is the layer above both. The same session owns
[`@baseworks/auth`](../../packages/baseworks-auth) — the SDK side of the brick.

## What this service is

The realm's sign-in gate and its **only token issuer**. It signs a person in
(OIDC with PKCE, or a password in [dev mode](./README.md#dev-mode-a-password-instead-of-an-identity-provider)),
keeps the browser session, approves `bw login`, and mints identity tokens. It
owns **no database**: durable identity is iam-service's (`POST /sync` turns a
login into a stable user id), organisations are org-service's.

Where the line between the two repositories runs: **the service is the web-facing
side** — anything that signs someone in, holds a session or mints. **The package
is what consumers share** — `requireAuth`, the verifier, the CLI login commands.
A second place that signs people in is a bug, which is why the package's
Next.js session modules were removed in its 1.0.0.

## Two surfaces

**Pages under `/ui`, the API under `/api`, nothing published at the root.** A
gateway publishes the first two at `/auth` and `/v1/auth`. A page answers HTML or a redirect and never JSON; an API route
never draws a page. A route that would do both is two routes.

- A new screen: a function in `src/pages/` drawn with `layout()`, a route in
  `src/routes/pages.ts` sent with `respond()`, its sentences in
  `src/pages/strings.ts` in **every** language there. Nothing else.
- The frame, the stylesheet, branding, language/theme and the `returnTo` rule
  are `@baseworks/core/pages`, shared with org-service. Change the look there,
  never in a copy here.
- A new endpoint: under `/api`, in `openapi.yaml`, snake_case.
- **Never write `/auth` or `/v1/auth` in code.** Addresses the browser follows
  come from `publicUrls()` (`src/lib/urls.ts`), which reads configuration. The
  version in `/v1/auth` is the gateway's; a `/v2` must not need a change here.
- The root is not a surface. `/healthz` is there, and so is any route meant
  only for services on the same network: no gateway rule can reach it.

## Where things stand (2026-11-11)

- `main` = 2.2.0: pages in en/tr on the realm's shared frame
  (`@baseworks/core/pages`). (2.0.0 had the pages at the root and so published
  `/auth/healthz`; superseded, do not deploy). `1.x` = 1.1.0, the line every deployed product is still on;
  a fix for them goes there and is released as 1.1.x.
- Local realm: on 2.1. `Caddyfile`, `apps/console` and `apps/doubletap` rewrite
  `/v1/auth` to `/api` and `/auth` to `/ui`. `.env.local` pins
  `OIDC_REDIRECT_URI` to the pre-2.0 callback until the new one is registered
  with the provider.
- flect's local dev (`flect/justfile`) starts this same checkout on :3003; its
  broker (`AUTH_URL`) and dashboard rewrite have to name `/api`.
- Not deployed anywhere. Blocked on: flect broker with `expose` `{ path, to }`
  (clave #161), then each product's `flect.toml` and OIDC redirect URI.
- Not verified: a full round trip through a real identity provider on 2.0.
- Deliberately left alone: `/service-token`, `/exchange`, and what a
  `type: 'service'` token may skip. The operator will decide those separately
  (workspace ADR 0003 §5).
- Still to come, in 3.0: remove the deprecated navigations under `/api`.

## The rules

1. **auth never persists user or org data.** Its only state is the cache
   (`env.kv('CACHE')`) for short-lived PKCE/CLI handles. A table, a migration,
   or an org import here belongs in iam-service or org-service instead.
2. **A token says who, never where** (ADR-042 §1). `iss aud sub iat exp jti
   type`, nothing else. No `org_id`, no role, no endpoint that mints for an
   arbitrary subject — `/service-token` is the caller itself, `/exchange` is
   the same subject narrowed.
3. **Only this service signs.** ES256 with `AUTH_SIGNING_KEY`; everyone else
   verifies against `/.well-known/jwks.json`. `JWT_SECRET` is legacy HS256,
   accepted while set, and on its way out.
4. **Nothing the browser sends is believed unchecked.** The session cookie is
   HMAC-tagged and carries its own expiry; `returnTo` is a same-origin path or
   an origin the realm publishes (`APP_PUBLIC_URL`, `AUTH_RETURN_ORIGINS`);
   anything a page echoes goes through `escapeHtml`. Each of these was once a
   way to become someone else or to be sent somewhere else.
5. **Dev mode never reaches production.** `AUTH_DEV_MODE` with
   `NODE_ENV=production` stops the service at boot. Keep it that way.
6. **Snake_case on the wire** (ADR-043). The session *cookie* keeps its own
   camelCase shape: it is storage, and renaming it signs everyone out.

## Where things are

```
src/index.ts          boot: dev mode, the cache and its ping, listen
src/app.ts            createApp() — /ui, /api and the closed root; discovery
src/routes/pages.ts   PAGES  /login (page, dev form) /cli /cli/approve /cli/done
src/routes/oidc.ts    signinRouter: /login/sso /login/:idp /oidc/callback /logout
                        (pages; mounted again under /api, deprecated)
                      sessionRouter: API  /session /token /idps POST /logout
                      startSession() — the one place a sign-in becomes a session
src/routes/cli.ts     API  /start /poll/:state /approve — the `bw login` device
                      flow; approveCli() — the one place a terminal gets a token
src/routes/tokens.ts  API  /service-token /exchange
src/pages/layout.ts   view() (language, theme, brand), layout(), respond()
src/pages/strings.ts  every sentence the pages show, en and tr
src/pages/login.ts    the sign-in page       src/pages/cli.ts  the approval pages
src/lib/urls.ts       where the gateway publishes us — every public address
src/lib/brand.ts      what the pages look like: REALM_UI_*, AUTH_UI_* on top
src/lib/realm.ts      signing keys, issuer, audience, JWKS
src/lib/mint.ts       mintIdentityToken — every token goes through it
src/lib/cookies.ts    cookie names, the signed session codec
src/lib/return-to.ts  what returnTo may be
src/lib/dev.ts        dev mode: the account, the production refusal
src/lib/iam.ts        POST /sync client
```

## Contracts you must not break

- **What is published under `/v1/auth`.** Every caller outside reaches the API
  there; 2.0 moved the mount and changed none of those addresses. The
  deprecated navigations under `/api` stay until 3.0.
- **The token's claim set and the JWKS.** Every service in the realm verifies
  with `@baseworks/auth/hono`; a claim renamed here is an outage there.
- **`/start` → `/poll` semantics.** `bw` polls until `expires_in`; an unknown
  and an expired handle both answer `expired`.
- **`returnTo`** is the parameter name (`redirectTo` is still read). The
  console and doubletap send it.
- **The session key.** It is derived from `AUTH_SESSION_SECRET`, else
  `JWT_SECRET`, else `AUTH_SIGNING_KEY`. Changing the one in use signs every
  browser out.

## Build / test

```bash
pnpm test     # vitest; routers over an in-memory KV, no Redis, IdP or IAM needed
pnpm build    # tests, then tsup
```

Tests go through `createApp()` with real requests (`src/__tests__/setup.ts`),
asking for paths as the process sees them: `/ui/login`, `/api/session`.
`surfaces.test.ts` states the split itself.
A rule about what the service accepts is tested through the route, not only
through the helper — a helper tested alone is how `?returnTo=` went unread for
a whole release while `safeReturnTo` had full coverage.
