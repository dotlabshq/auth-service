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
src/index.ts          wiring: boot (dev mode, cache ping), discovery, routers
src/routes/oidc.ts    /login /oidc/callback /session /logout /token;
                      startSession() — the one place a sign-in becomes a session
src/routes/cli.ts     /start /poll/:state /approve — the `bw login` device flow
src/routes/tokens.ts  /service-token /exchange
src/lib/realm.ts      signing keys, issuer, audience, JWKS
src/lib/mint.ts       mintIdentityToken — every token goes through it
src/lib/cookies.ts    cookie names, the signed session codec
src/lib/return-to.ts  what returnTo may be
src/lib/dev.ts        dev mode: the account, the production refusal
src/lib/iam.ts        POST /sync client
src/pages/            the approval page and the dev sign-in form
```

## Contracts you must not break

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

Tests go through the routers with real requests (`src/__tests__/setup.ts`).
A rule about what the service accepts is tested through the route, not only
through the helper — a helper tested alone is how `?returnTo=` went unread for
a whole release while `safeReturnTo` had full coverage.
