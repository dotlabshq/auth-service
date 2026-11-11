import { serve } from '@hono/node-server'
import { createEnv } from '@baseworks/sdk'
import type { Redis } from 'ioredis'
import { kvAdapter, memoryKvAdapter } from './db/client.js'
import type { KvClient } from './db/client.js'
import { devBanner, devLogin } from './lib/dev.js'
import { publicUrls } from './lib/urls.js'
import { createApp } from './app.js'

// Dev mode is decided once, at boot: the password is made up here and must stay
// the same for the life of the process. Throws under NODE_ENV=production.
const dev = devLogin()

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

const app = createApp({ dev, kv, log: true })

const port = parseInt(process.env['PORT'] ?? '3000')

serve({ fetch: app.fetch, port }, () => {
  console.log(`auth-service listening on :${port}`)
  if (dev) {
    const urls = publicUrls()
    console.warn(devBanner(dev, urls.origin ? urls.ui('/login') : `http://localhost:${port}/ui/login`))
  }
})
