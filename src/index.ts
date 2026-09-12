import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { logger } from 'hono/logger'
import { createEnv } from '@baseworks/sdk'
import type { Redis } from 'ioredis'
import { kvAdapter, memoryKvAdapter } from './db/client.js'
import type { KvClient } from './db/client.js'
import { oidcRouter } from './routes/oidc.js'
import { cliRouter } from './routes/cli.js'
import { tokensRouter } from './routes/tokens.js'
import { iamEnabled } from './lib/iam.js'
import { realm } from './lib/realm.js'

const app = new Hono()
app.use('*', logger())
app.get('/healthz', (c) => c.json({ ok: true, service: 'auth-service', iam: iamEnabled() }))

// The realm's public keys. Unauthenticated on purpose: every verifier in the
// realm — and the gateway — reads this, and it contains only public material.
// Cached hard because the key changes about as often as the domain does; jose
// refetches on its own when it meets a `kid` it does not know.
app.get('/.well-known/jwks.json', async (c) => {
  const r = await realm()
  if (!r.jwks) {
    // No signing key: the realm is still on the shared HS256 secret. An empty
    // set is the honest answer — "this issuer publishes no verifiable keys" —
    // and it keeps verifiers from caching a 404 as if it were a key set.
    return c.json({ keys: [] }, 200, { 'cache-control': 'no-store' })
  }
  return c.json(r.jwks, 200, { 'cache-control': 'public, max-age=3600' })
})

// auth owns NO database — identity + org management belong to IAM (ADR-006/007).
// It resolves only a cache (OIDC/CLI transient state) through the broker
// (FLECT_TOKEN + FLECT_BROKER_URL); no substrate URLs in config (ADR-0004).
//
// The cache binding defaults to `CACHE`, so a bundled auth SHARES its host app's
// cache (bindings are scope-level; auth's keys are prefixed `auth:` and never
// collide). Override with AUTH_KV_BINDING for a dedicated cache.
//
// Identity/org: when IAM is reachable (IAM_SERVICE_URL, injected by a service
// binding) auth delegates to iam-service; otherwise it is login-only.
const kvBinding = process.env.AUTH_KV_BINDING ?? 'CACHE'
const env = createEnv()
// A CACHE binding is preferred (durable, shared across instances). When none is
// configured, auth degrades to an in-process cache rather than failing to boot:
// its only state is short-lived OIDC/CLI login state, correct for a single
// instance. Bind a `redis://` CACHE for multi-instance / restart-durable state.
let kv: KvClient
try {
  kv = kvAdapter(await env.kv<Redis>(kvBinding))
  console.log(`auth-service using CACHE binding "${kvBinding}"`)
} catch (err) {
  console.warn(
    `auth-service: no usable CACHE binding "${kvBinding}" (${(err as Error).message}) — ` +
      `falling back to in-memory KV (single-instance, non-durable)`,
  )
  kv = memoryKvAdapter()
}

app.route('/', oidcRouter())
app.route('/', cliRouter(kv))
app.route('/', tokensRouter())

app.onError((err, c) => {
  console.error(err)
  return c.json({ error: 'Internal server error' }, 500)
})

const port = parseInt(process.env['PORT'] ?? '3000')

serve({ fetch: app.fetch, port }, () => {
  console.log(`auth-service listening on :${port}`)
})
