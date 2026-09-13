# auth-service

The realm's sign-in gate and its **only token issuer**.

A realm is one deployment of this plane: one auth-service, one signing key pair,
and the services that trust it. A token issued here is accepted by every service
in that realm and by no other.

## What a token is

An identity token and nothing more:

```
iss  the realm's issuer URL        sub  the platform user id
aud  the realm's name              iat / exp
jti  unique, so revocation is possible later
type human | service | assistant
```

**Organisation and role are deliberately absent.** Membership changes while a
token lives, so a token carrying a role goes stale and lies. A service that needs
org context asks the org service and caches the answer briefly.

## Why only this service signs

With ES256 the private key never leaves auth-service. Everyone else verifies
using the public key from `/.well-known/jwks.json`, and therefore cannot mint
anything.

The shared HMAC secret this replaces gave every holder the power to *issue*
tokens, not just check them — and that power was being used: a product API in
this plane minted `{ sub: <another user>, type: 'user' }` to act on that user's
behalf. There is deliberately no endpoint here that mints a token for an
arbitrary subject. What replaced those uses is narrower:

| Need | Endpoint | Limit |
|---|---|---|
| A service acting as itself | `POST /service-token` | Subject is the authenticated client; it cannot be chosen |
| An assistant or CI job | `POST /exchange` | Same subject as the caller, one org, at most an hour |
| Acting as another user | — | Not offered. Grant the *service* the permission instead |

## Using it from your app

Add `@baseworks/auth` and let the middleware do the work. Your code never names
a key or an algorithm:

```ts
import { requireAuth } from '@baseworks/auth/hono'

app.use('*', requireAuth)
app.get('/things', (c) => {
  const { userId, tokenType } = c.get('auth')
})
```

```
AUTH_JWKS_URI=https://auth.example.com/v1/auth/.well-known/jwks.json
AUTH_ISSUER=https://auth.example.com
AUTH_AUDIENCE=example-realm
```

Set the issuer and audience in production. Without them, a token from any realm
whose key set you happen to fetch will verify.

Needing org context? Do **not** look for it in the token — it is not there, on
purpose. Ask the org service and cache the answer briefly.

### Signing in from a CLI

```ts
import { addAuthCommands } from '@baseworks/auth/cli'
import { createConfigManager } from '@baseworks/config'

const config = createConfigManager<{ token?: string }>('mycli', {}, {
  format: 'toml',
  scope: 'global',   // ~/.mycli/config.toml, 0600 — never inside a working tree
})

addAuthCommands(program, {
  cliName: 'mycli',
  authBase: () => 'https://auth.example.com/v1/auth',
  onToken:  (token) => config.patch({ token }),
  onLogout: () => config.patch({ token: undefined }),
  getToken: () => config.load().token,
  tokenOrigin: () => config.writePath,
})
```

```
$ mycli login
  Approve this sign-in in your browser:
  https://auth.example.com/v1/auth/token?state=dd6c62cb…
  Waiting for approval — the link is valid for 10m…
✓ Logged in.

$ mycli auth status
  user        01a05840-b6aa-7421-80d7-6eb192551584
  token type  human
  expires     2026-09-13 14:33 UTC (in 23h 57m)
```

### Getting a token for a service

For cron jobs, queue workers and anything else acting on its own behalf:

```bash
curl -sX POST https://auth.example.com/v1/auth/service-token \
  -H 'content-type: application/json' \
  -d '{"client_id":"billing","client_secret":"'"$BILLING_AUTH_SECRET"'"}'
```

The subject is the authenticated client and cannot be chosen. If you find
yourself wanting a token for a *user* from a backend, that is the thing this
service deliberately does not do — give the service its own identity and grant
that identity the permission it needs.

### Narrowing a token for an assistant or a CI job

```bash
curl -sX POST https://auth.example.com/v1/auth/exchange \
  -H "authorization: Bearer $USER_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"org_id":"org_1","scope":"read","expires_in":600}'
```

Same subject, one org, at most an hour. `org_id` is a restriction, not a grant:
the receiving service still checks membership, because auth knows nothing about
organisations.

## Configuration

| Variable | Meaning |
|---|---|
| `AUTH_SIGNING_KEY` | EC P-256 private key, PKCS#8 PEM **or base64 of it** |
| `AUTH_SIGNING_KID` | Override the derived key id; rarely needed |
| `AUTH_RETIRED_PUBLIC_KEYS` | SPKI PEMs still published during a rotation |
| `AUTH_ISSUER` | Expected `iss`; defaults to `APP_PUBLIC_URL` |
| `AUTH_AUDIENCE` | Realm name; defaults to the issuer's hostname |
| `AUTH_SERVICE_CLIENTS` | `name:secret,name:secret` for `/service-token` |
| `JWT_SECRET` | **Legacy.** HS256, accepted while set — see below |
| `OIDC_*`, `APP_PUBLIC_URL`, `IAM_SERVICE_URL`, `KV_CACHE_URL` | Unchanged |

Base64 is accepted for key material because environment variables, Kubernetes
Secrets and CI variables all mangle the newlines a PEM needs.

### Generating a key

```
pnpm --filter @dotlabshq/auth-service keygen
```

Prints a fresh pair to stdout and never to a file: a private key written to disk
gets committed, backed up and copied. The key id is derived from the key itself
(RFC 7638 thumbprint), so it is not something to keep in step by hand.

### Rotating

1. Generate a new pair.
2. Put the **old public** key in `AUTH_RETIRED_PUBLIC_KEYS` and the new private
   key in `AUTH_SIGNING_KEY`. Both are now published; new tokens use the new key.
3. After the longest token lifetime has passed, drop the retired key.

### Migrating off the shared secret

Order matters, and each step is safe on its own:

1. Deploy this service **without** `AUTH_SIGNING_KEY`. It keeps issuing HS256
   and behaves exactly as before.
2. Upgrade verifiers to `@baseworks/auth` 0.3.0 and give them `AUTH_JWKS_URI`.
   They accept both algorithms while `JWT_SECRET` is set.
3. Set `AUTH_SIGNING_KEY` here. New tokens are ES256; old ones keep verifying
   until they expire.
4. Move anything that was *minting* with the secret onto `/service-token`.
5. Remove `JWT_SECRET` everywhere. Only then is the issuing power actually gone.

## Endpoints

Full contract: [`openapi.yaml`](./openapi.yaml), also served at `/openapi.yaml`.

Routes live at the service root. Behind a gateway the realm is reached at
`/v1/auth/...`, with that prefix stripped before the request arrives.

| | |
|---|---|
| `GET /healthz` · `GET /.well-known/service` · `GET /.well-known/jwks.json` | Discovery, unauthenticated |
| `GET /login` · `/oidc/callback` · `/session` · `/logout` · `/token` | Browser sign-in |
| `GET /start` · `GET /poll/:state` · `POST /approve` | CLI device flow |
| `POST /service-token` · `POST /exchange` | Tokens that are not a browser login |

### The CLI flow, and the one mistake clients make

`/start` returns a handle and the URL to approve; poll `/poll/{state}` until it
answers `done`. Poll until exactly `expires_in` and no longer — a shorter client
timeout reports failure while the link still works. An unknown handle and an
expired one both answer `expired`, because from the client's side they mean the
same thing: nobody approved in time.

## Field naming

Bodies are `snake_case` (ADR-043), which the OAuth2 fields — `token_type`,
`expires_in`, `client_id` — already were; the plane had been mixing the two.

The **session cookie** keeps its own shape. It is storage, not a contract, and
renaming its keys would invalidate every session already in a browser — signing
everyone out to tidy up a field name.

## Known gaps

- **No revocation.** A token is valid until it expires; `/logout` clears cookies
  only. Every token carries a `jti` so a deny list can be added without a format
  change.
- **Login state lives in the cache.** With no `KV_CACHE_URL` the service falls
  back to an in-process cache, which is correct for one replica and wrong for
  several: `/start` and `/poll` would land on different pods and the flow would
  break. Bind a Redis cache before scaling out.

## Development

```
pnpm dev     # tsx watch, reads .env.local
pnpm test    # vitest
pnpm build   # tsup
```

Build the image from the monorepo root:

```
podman build -f projects/auth-service/Dockerfile.workspace -t auth-service:<tag> .
```

The standalone `Dockerfile` is deprecated: `npm ci` cannot resolve the
`workspace:*` dependencies this service now uses.
