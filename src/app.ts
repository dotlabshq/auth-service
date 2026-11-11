import { Hono } from 'hono'
import { logger } from 'hono/logger'
import { readFileSync } from 'node:fs'
import { serviceManifest } from '@baseworks/core/service'
import type { KvClient } from './db/client.js'
import type { DevLogin } from './lib/dev.js'
import { iamEnabled } from './lib/iam.js'
import { realm } from './lib/realm.js'
import { cliRouter } from './routes/cli.js'
import { sessionRouter, signinRouter } from './routes/oidc.js'
import { pagesRouter } from './routes/pages.js'
import { tokensRouter } from './routes/tokens.js'

// Read once at startup: the release is a build-time fact, and re-reading it per
// request would turn a manifest fetch into disk I/O.
const VERSION = (() => {
  try {
    return (JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as
      { version?: string }).version ?? '0.0.0'
  } catch {
    return '0.0.0'
  }
})()

export interface AppOptions {
  /** Set when dev mode is on. Decided once, at boot. */
  dev?: DevLogin | null
  kv: KvClient
  /** Request logging; off in tests. */
  log?: boolean
}

/**
 * The service, as two surfaces under one process:
 *
 *   /        pages — what a person sees: sign in, approve a terminal
 *   /api     the API — what a program calls: session, tokens, keys, discovery
 *
 * A gateway publishes the first at `/auth` and the second at `/v1/auth`,
 * replacing the prefix each time. The version in that second address is the
 * gateway's to choose; a `/v2/auth` can point at another deployment, or at
 * this same `/api`, without this service changing.
 *
 * `/healthz` is on neither: it is for the platform that runs the process and
 * is not published.
 */
export function createApp(opts: AppOptions) {
  const dev = opts.dev ?? null
  const app = new Hono()
  if (opts.log) app.use('*', logger())

  app.get('/healthz', (c) => c.json({
    ok: true, service: 'auth-service', iam: iamEnabled(), ...(dev ? { dev: true } : {}),
  }))

  const api = new Hono()

  // The contract itself. Served from the repo file so the document and the code
  // ship together and cannot drift apart between releases.
  api.get('/openapi.yaml', (c) => {
    try {
      const spec = readFileSync(new URL('../openapi.yaml', import.meta.url), 'utf8')
      return c.body(spec, 200, { 'content-type': 'application/yaml; charset=utf-8' })
    } catch {
      return c.json({ error: 'spec not bundled with this build' }, 404)
    }
  })

  // What this service is and what contract it speaks. Unauthenticated: it carries
  // no secrets, and its readers include the gateway and a CLI that has not signed
  // in yet (ADR-042 §8 in the zone9 repo).
  api.get('/.well-known/service', async (c) => {
    const r = await realm()
    return c.json(
      serviceManifest({
        name: 'auth',
        version: VERSION,
        // Bumped only when the HTTP surface breaks callers, not on every
        // release. 2.0 moved where the service mounts things; what a caller
        // outside reaches at `/v1/auth/...` did not change, so this did not.
        api_version: '1.0',
        openapi_url: '/openapi.yaml',
        capabilities: [
          // A client can tell a dev realm from a real one without guessing.
          dev ? 'dev-login' : 'oidc-login',
          'cli-device-flow',
          'service-token',
          'token-exchange',
          // A product can send people to this service's own sign-in page
          // rather than drawing one.
          'login-page',
          // Consumers branch on this: with no signing key the realm still issues
          // HS256 and there is nothing at the JWKS endpoint to verify against.
          ...(r.jwks ? ['jwks'] : []),
          ...(iamEnabled() ? ['iam-sync'] : []),
        ],
      }),
    )
  })

  // The realm's public keys. Unauthenticated on purpose: every verifier in the
  // realm — and the gateway — reads this, and it contains only public material.
  // Cached hard because the key changes about as often as the domain does; jose
  // refetches on its own when it meets a `kid` it does not know.
  api.get('/.well-known/jwks.json', async (c) => {
    const r = await realm()
    if (!r.jwks) {
      // No signing key: the realm is still on the shared HS256 secret. An empty
      // set is the honest answer — "this issuer publishes no verifiable keys" —
      // and it keeps verifiers from caching a 404 as if it were a key set.
      return c.json({ keys: [] }, 200, { 'cache-control': 'no-store' })
    }
    return c.json(r.jwks, 200, { 'cache-control': 'public, max-age=3600' })
  })

  const signin = signinRouter({ dev })
  api.route('/', sessionRouter({ dev, sso: signin.sso }))
  api.route('/', cliRouter(opts.kv))
  api.route('/', tokensRouter())
  // Deprecated: the sign-in navigations at their pre-2.0 addresses.
  api.route('/', signinRouter({ dev }))

  app.route('/api', api)
  app.route('/', pagesRouter({ dev, kv: opts.kv }))
  app.route('/', signin)

  app.onError((err, c) => {
    console.error(err)
    return c.json({ error: 'Internal server error' }, 500)
  })

  return app
}
