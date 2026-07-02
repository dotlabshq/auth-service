import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { logger } from 'hono/logger'
import { createEnv } from '@dotlabshq/flect-sdk'
import { createDB } from './db/client.js'
import { oidcRouter } from './routes/oidc.js'
import { cliRouter } from './routes/cli.js'

const app = new Hono()
app.use('*', logger())
app.get('/healthz', (c) => c.json({ ok: true, service: 'auth-service' }))

const env = createEnv()
const db  = createDB(env.db('DB'))
const kv  = env.kv('KV')

app.route('/', oidcRouter(db))
app.route('/', cliRouter(db, kv))

app.onError((err, c) => {
  console.error(err)
  return c.json({ error: 'Internal server error' }, 500)
})

const port = parseInt(process.env['PORT'] ?? '3000')

serve({ fetch: app.fetch, port }, () => {
  console.log(`auth-service listening on :${port}`)
})
