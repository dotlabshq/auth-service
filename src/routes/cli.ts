import { Hono } from 'hono'
import { mintIdentityToken } from '../lib/mint.js'
import type { KvClient } from '../db/client.js'
import { parseSession } from '../lib/cookies.js'
import { donePage } from '../pages/token.js'

const KV_PFX          = 'auth:cli:'
const TTL             = 600
const IDENTITY_TTL    = 86400      // 24h

function stateKey(state: string) { return `${KV_PFX}${state}` }

function randomState(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

type CliStatus = { status: 'pending' } | { status: 'done'; token: string }

export function cliRouter(kv: KvClient) {
  const app = new Hono()

  // GET /start
  //
  // The URL handed back is where the person approves. By default that is this
  // service's own bare page; a realm with a console sets AUTH_CLI_APPROVE_URL
  // to that console's screen, which can say who is signing in and what the
  // token will be able to do. The state travels as a query parameter either
  // way, so the CLI does not know or care which one it got.
  app.get('/start', async (c) => {
    const state  = randomState()
    const base   = (process.env['APP_PUBLIC_URL'] ?? '').replace(/\/+$/, '')
    const approve = (process.env['AUTH_CLI_APPROVE_URL'] ?? `${base}/v1/auth/token`).replace(/\/+$/, '')
    await kv.set(stateKey(state), JSON.stringify({ status: 'pending' }), { ttl: TTL })
    return c.json({ state, url: `${approve}?state=${state}`, expires_in: TTL })
  })

  // GET /poll/:state
  app.get('/poll/:state', async (c) => {
    const raw = await kv.get(stateKey(c.req.param('state')))
    if (!raw) return c.json({ status: 'expired' })
    const data = JSON.parse(raw) as CliStatus
    if (data.status === 'done') {
      await kv.del(stateKey(c.req.param('state')))
      return c.json({ status: 'done', token: data.token })
    }
    return c.json({ status: data.status })
  })

  // GET /token/done
  app.get('/token/done', (c) => c.html(donePage()))

  // POST /approve — the person says yes → issues the identity JWT, writes it
  // to KV for the waiting CLI to collect.
  //
  // Two callers, two answers: a browser form posts and is redirected to a page
  // that says it worked, while a console screen posts JSON with fetch and wants
  // JSON back — following a redirect there would hand it a page of HTML.
  app.post('/approve', async (c) => {
    const session = parseSession(c)
    if (!session?.isAuthenticated) return c.json({ error: 'not_authenticated' }, 401)

    const { subject } = session

    const ct = c.req.header('content-type') ?? ''
    const wantsJson = ct.includes('application/json') || (c.req.header('accept') ?? '').includes('application/json')
    let state: string | undefined
    if (ct.includes('application/x-www-form-urlencoded') || ct.includes('multipart/form-data')) {
      state = (await c.req.formData()).get('state')?.toString()
    } else {
      state = ((await c.req.json().catch(() => ({}))) as { state?: string }).state
    }
    if (!state) return c.json({ error: 'state_required' }, 400)

    const raw = await kv.get(stateKey(state))
    if (!raw) return c.json({ error: 'expired_or_invalid' }, 404)

    const data = JSON.parse(raw) as CliStatus
    if (data.status !== 'pending') return c.json({ error: 'already_used' }, 409)

    // The identity was resolved at OIDC callback and carried in the session (the
    // IAM user id in IAM mode; the OIDC subject in login-only mode).
    const userId = session.userId ?? subject

    // Identity JWT — identity only. An app that needs org context resolves
    // membership via org-service; auth does not scope tokens to orgs.
    const token = await mintIdentityToken({ sub: userId, type: 'human', expiresInSeconds: IDENTITY_TTL })
    if (!token) return c.json({ error: 'realm has no signing key configured' }, 500)

    await kv.set(stateKey(state), JSON.stringify({ status: 'done', token }), { ttl: 60 })

    // The token itself is NOT returned: it belongs to the CLI that asked for it
    // and reaches it by polling. A page that could read it would be a page that
    // could hand it to anyone who got the person to open a link.
    if (wantsJson) return c.json({ ok: true })

    const base = (process.env['APP_PUBLIC_URL'] ?? '').replace(/\/+$/, '')
    return c.redirect(`${base}/v1/auth/token/done`)
  })

  return app
}
