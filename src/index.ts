import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { logger } from 'hono/logger'
import { createEnv } from '@getflect/sdk'
import type { Redis } from 'ioredis'
import { kvAdapter } from './db/client.js'
import { oidcRouter } from './routes/oidc.js'
import { cliRouter } from './routes/cli.js'
import { iamEnabled } from './lib/iam.js'

const app = new Hono()
app.use('*', logger())
app.get('/healthz', (c) => c.json({ ok: true, service: 'auth-service', iam: iamEnabled() }))

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
const kv = kvAdapter(await env.kv<Redis>(kvBinding))

app.route('/', oidcRouter())
app.route('/', cliRouter(kv))

app.onError((err, c) => {
  console.error(err)
  return c.json({ error: 'Internal server error' }, 500)
})

const port = parseInt(process.env['PORT'] ?? '3000')

serve({ fetch: app.fetch, port }, () => {
  console.log(`auth-service listening on :${port}`)
})
