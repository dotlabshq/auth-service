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
import { devBanner, devLogin } from './lib/dev.js'
import { serviceManifest } from '@baseworks/core/service'
import { readFileSync } from 'node:fs'

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

// Dev mode is decided once, at boot: the password is made up here and must stay
// the same for the life of the process. Throws under NODE_ENV=production.
const dev = devLogin()

const app = new Hono()
app.use('*', logger())
app.get('/healthz', (c) => c.json({
  ok: true, service: 'auth-service', iam: iamEnabled(), ...(dev ? { dev: true } : {}),
}))

// The contract itself. Served from the repo file so the document and the code
// ship together and cannot drift apart between releases.
app.get('/openapi.yaml', (c) => {
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
app.get('/.well-known/service', async (c) => {
  const r = await realm()
  return c.json(
    serviceManifest({
      name: 'auth',
      version: VERSION,
      // Bumped only when the HTTP surface breaks callers, not on every release.
      api_version: '1.0',
      openapi_url: '/openapi.yaml',
      capabilities: [
        // A client can tell a dev realm from a real one without guessing.
        dev ? 'dev-login' : 'oidc-login',
        'cli-device-flow',
        'service-token',
        'token-exchange',
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
/** Give a promise a deadline. A cache that cannot answer a ping in 2s is down. */
async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      p,
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`no answer in ${ms}ms`)), ms) }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

const kvBinding = process.env.AUTH_KV_BINDING ?? 'CACHE'
const env = createEnv()
// A CACHE binding is preferred (durable, shared across instances). When none is
// configured, auth degrades to an in-process cache rather than failing to boot:
// its only state is short-lived OIDC/CLI login state, correct for a single
// instance. Bind a `redis://` CACHE for multi-instance / restart-durable state.
let kv: KvClient
let redis: Redis | undefined
try {
  redis = await env.kv<Redis>(kvBinding)
  // Resolving the binding only builds a client: ioredis connects lazily, so a
  // cache that is configured but not running is still "resolved" here and only
  // fails on the first write — 28 seconds later, as a 500 on `/start`, with the
  // reason nowhere near the request. One ping at boot turns that into a warning
  // on the line above, before anyone has tried to sign in.
  //
  // Until the ping settles, keep the reason instead of letting ioredis print an
  // "Unhandled error event" per reconnect attempt: the warning below says it once.
  let lastError: Error | undefined
  const remember = (err: Error) => { lastError = err }
  redis.on('error', remember)
  await withTimeout(redis.ping(), 2000).catch((err: Error) => { throw lastError ?? err })
  redis.off('error', remember)
  kv = kvAdapter(redis)
  console.log(`auth-service using CACHE binding "${kvBinding}"`)
} catch (err) {
  console.warn(
    `auth-service: no usable CACHE binding "${kvBinding}" (${(err as Error).message}) — ` +
      `falling back to in-memory KV (single-instance, non-durable)`,
  )
  // Stop the client that failed the ping: left alone, ioredis keeps
  // reconnecting in the background for the life of the process, and a cache
  // this instance is not going to use is only noise in the log.
  redis?.disconnect()
  kv = memoryKvAdapter()
}

app.route('/', oidcRouter({ dev }))
app.route('/', cliRouter(kv))
app.route('/', tokensRouter())

app.onError((err, c) => {
  console.error(err)
  return c.json({ error: 'Internal server error' }, 500)
})

const port = parseInt(process.env['PORT'] ?? '3000')

serve({ fetch: app.fetch, port }, () => {
  console.log(`auth-service listening on :${port}`)
  if (dev) {
    const base = (process.env['APP_PUBLIC_URL'] ?? `http://localhost:${port}`).replace(/\/+$/, '')
    console.warn(devBanner(dev, `${base}/v1/auth/login`))
  }
})
