import { Hono } from 'hono'
import { mintIdentityToken } from '../lib/mint.js'
import type { KvClient } from '../db/client.js'
import { parseSession, type OidcSession } from '../lib/cookies.js'
import { publicUrls } from '../lib/urls.js'

const KV_PFX          = 'auth:cli:'
const TTL             = 600
const IDENTITY_TTL    = 86400      // 24h

function stateKey(state: string) { return `${KV_PFX}${state}` }

function randomState(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

/** What `randomState` makes. Anything else in `?state=` is not one of ours. */
export function isCliState(state: string | undefined): state is string {
  return typeof state === 'string' && /^[0-9a-f]{32}$/.test(state)
}

type CliStatus = { status: 'pending' } | { status: 'done'; token: string }

/** Where a sign-in the CLI started stands: waiting, already approved, or gone. */
export async function cliRequest(kv: KvClient, state: string): Promise<'pending' | 'used' | 'expired'> {
  const raw = await kv.get(stateKey(state))
  if (!raw) return 'expired'
  return (JSON.parse(raw) as CliStatus).status === 'pending' ? 'pending' : 'used'
}

export type ApproveResult =
  | { ok: true }
  | { ok: false; error: 'expired_or_invalid' | 'already_used' | 'no_signing_key' }

/**
 * The person said yes: mint the identity token and leave it for the waiting
 * CLI to collect. Shared by the page's form and the JSON endpoint, so there is
 * one place a terminal is ever given a token.
 *
 * The token is NOT handed back to the caller: it belongs to the CLI that asked
 * for it and reaches it by polling. A page that could read it would be a page
 * that could hand it to anyone who got the person to open a link.
 */
export async function approveCli(kv: KvClient, session: OidcSession, state: string): Promise<ApproveResult> {
  const raw = await kv.get(stateKey(state))
  if (!raw) return { ok: false, error: 'expired_or_invalid' }

  const data = JSON.parse(raw) as CliStatus
  if (data.status !== 'pending') return { ok: false, error: 'already_used' }

  // The identity was resolved at OIDC callback and carried in the session (the
  // IAM user id in IAM mode; the OIDC subject in login-only mode).
  const userId = session.userId ?? session.subject

  // Identity JWT — identity only. An app that needs org context resolves
  // membership via org-service; auth does not scope tokens to orgs.
  const token = await mintIdentityToken({ sub: userId, type: 'human', expiresInSeconds: IDENTITY_TTL })
  if (!token) return { ok: false, error: 'no_signing_key' }

  await kv.set(stateKey(state), JSON.stringify({ status: 'done', token }), { ttl: 60 })
  return { ok: true }
}

/** The `bw login` device flow, as the CLI and a console's own approve screen call it. */
export function cliRouter(kv: KvClient) {
  const app = new Hono()

  // GET /start
  //
  // The URL handed back is where the person approves. By default that is this
  // service's own page; a realm with a console sets AUTH_CLI_APPROVE_URL to
  // that console's screen, which can say more about what the token will be
  // able to do. The state travels as a query parameter either way, so the CLI
  // does not know or care which one it got.
  app.get('/start', async (c) => {
    const state   = randomState()
    const approve = (process.env['AUTH_CLI_APPROVE_URL'] ?? publicUrls().ui('/cli')).replace(/\/+$/, '')
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

  // POST /approve — for a console that draws its own approve screen and posts
  // with fetch. This service's own page posts its form to `/cli/approve` on the
  // page surface instead; a form sent here (a page rendered before 2.0) is
  // still taken, and sent on to the page that says it worked.
  app.post('/approve', async (c) => {
    const session = parseSession(c)
    if (!session?.isAuthenticated) return c.json({ error: 'not_authenticated' }, 401)

    const ct = c.req.header('content-type') ?? ''
    const isForm = ct.includes('application/x-www-form-urlencoded') || ct.includes('multipart/form-data')
    const state = isForm
      ? (await c.req.formData()).get('state')?.toString()
      : ((await c.req.json().catch(() => ({}))) as { state?: string }).state
    if (!state) return c.json({ error: 'state_required' }, 400)

    const result = await approveCli(kv, session, state)
    if (!result.ok) {
      if (result.error === 'expired_or_invalid') return c.json({ error: result.error }, 404)
      if (result.error === 'already_used') return c.json({ error: result.error }, 409)
      return c.json({ error: 'realm has no signing key configured' }, 500)
    }

    const wantsJson = ct.includes('application/json') || (c.req.header('accept') ?? '').includes('application/json')
    return wantsJson || !isForm ? c.json({ ok: true }) : c.redirect(publicUrls().ui('/cli/done'))
  })

  // GET /token/done — deprecated: where the approve form landed before 2.0.
  app.get('/token/done', (c) => c.redirect(publicUrls().ui('/cli/done')))

  return app
}
