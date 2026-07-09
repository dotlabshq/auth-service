import { Hono } from 'hono'
import { signHs256Jwt, verifyHs256Jwt } from '@baseworks/auth/jwt'
import type { KvClient } from '../db/client.js'
import { parseSession } from '../lib/cookies.js'
import { iamEnabled, iamMembershipRole } from '../lib/iam.js'
import { donePage } from '../pages/token.js'

const KV_PFX          = 'auth:cli:'
const TTL             = 600
const IDENTITY_TTL    = 86400      // 24h
const ORG_TOKEN_TTL   = 14400     // 4h

function stateKey(state: string) { return `${KV_PFX}${state}` }

function randomState(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function jwtSecret(): string {
  const s = process.env['JWT_SECRET']
  if (!s) throw new Error('JWT_SECRET not set')
  return s
}

type CliStatus = { status: 'pending' } | { status: 'done'; token: string }

export function cliRouter(kv: KvClient) {
  const app = new Hono()

  // GET /start
  app.get('/start', async (c) => {
    const state  = randomState()
    const base   = (process.env['APP_PUBLIC_URL'] ?? '').replace(/\/+$/, '')
    await kv.set(stateKey(state), JSON.stringify({ status: 'pending' }), { ttl: TTL })
    return c.json({ state, url: `${base}/v1/auth/token?state=${state}`, expires_in: TTL })
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

  // POST /approve — browser form submit → issues identity JWT, writes to KV
  app.post('/approve', async (c) => {
    const session = parseSession(c)
    if (!session?.isAuthenticated) return c.json({ error: 'not_authenticated' }, 401)

    const { subject } = session

    const ct = c.req.header('content-type') ?? ''
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

    // Identity + org were resolved at OIDC callback and carried in the session
    // (IAM user id + org in IAM mode; the OIDC subject in login-only mode) — no
    // database lookup here.
    const userId = session.userId ?? subject

    // identity JWT with org_id so downstream services can resolve memberships
    const token = signHs256Jwt(
      { sub: userId, org_id: session.orgId, type: 'human' },
      jwtSecret(),
      IDENTITY_TTL,
    )

    await kv.set(stateKey(state), JSON.stringify({ status: 'done', token }), { ttl: 60 })

    const base = (process.env['APP_PUBLIC_URL'] ?? '').replace(/\/+$/, '')
    return c.redirect(`${base}/v1/auth/token/done`)
  })

  // POST /token-for-org — exchange identity JWT for org-scoped JWT
  app.post('/token-for-org', async (c) => {
    const bearer = c.req.header('authorization')?.replace(/^Bearer\s+/i, '')
    if (!bearer) return c.json({ error: 'missing_token' }, 401)

    const claims = verifyHs256Jwt(bearer, jwtSecret())
    if (!claims || claims['type'] !== 'human') return c.json({ error: 'invalid_token' }, 401)
    // identity token must not already be org-scoped
    if (claims['org_id']) return c.json({ error: 'already_org_scoped' }, 400)

    const { org_id } = await c.req.json() as { org_id?: string }
    if (!org_id) return c.json({ error: 'org_id_required' }, 400)

    const userId = claims['sub'] as string

    // Org selection only exists when IAM is present — login-only auth has no
    // orgs to scope to.
    if (!iamEnabled()) return c.json({ error: 'org_selection_unavailable' }, 400)

    // Verify membership through IAM (deny if the user has no role in the org).
    const role = await iamMembershipRole(userId, org_id)
    if (!role) return c.json({ error: 'not_a_member' }, 403)

    const orgToken = signHs256Jwt(
      { sub: userId, org_id, role, type: 'human' },
      jwtSecret(),
      ORG_TOKEN_TTL,
    )

    return c.json({ token: orgToken, expires_in: ORG_TOKEN_TTL })
  })

  return app
}
