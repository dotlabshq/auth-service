import { Hono } from 'hono'
import { getCookie } from 'hono/cookie'
import { createUserRepo } from '@baseworks/account'
import { parseJwtPayload, signHs256Jwt, verifyHs256Jwt } from '@baseworks/auth/jwt'
import type { KvClient } from '@dotlabshq/flect-sdk'
import type { DB } from '../db/client.js'
import { schema } from '../db/client.js'
import { COOKIE_ID_TOKEN } from '../lib/cookies.js'
import { tokenPage, donePage } from '../pages/token.js'

const KV_PFX          = 'auth:cli:'
const TTL             = 600
const IDENTITY_TTL    = 86400      // 24h
const ORG_TOKEN_TTL   = 14400     // 4h

function stateKey(state: string) { return `${KV_PFX}${state}` }

function appUrl(c: { req: { url: string; header(name: string): string | undefined } }): string {
  if (process.env['APP_PUBLIC_URL']) return process.env['APP_PUBLIC_URL'].replace(/\/+$/, '')
  const url  = new URL(c.req.url)
  const host = c.req.header('x-forwarded-host') ?? url.hostname
  const proto = c.req.header('x-forwarded-proto') ?? url.protocol.replace(':', '')
  return `${proto}://${host}`
}

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

export function cliRouter(db: DB, kv: KvClient) {
  const app      = new Hono()
  const userRepo = createUserRepo(db, schema)

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

  // GET /token — browser approve page
  app.get('/token', (c) => {
    const state = c.req.query('state')
    if (!state) return c.html('<p>Invalid link. No state found.</p>', 400)
    const idToken = getCookie(c, COOKIE_ID_TOKEN)
    if (!idToken) {
      const base = (process.env['APP_PUBLIC_URL'] ?? '').replace(/\/+$/, '')
      return c.redirect(`${base}/v1/auth/login?redirectTo=/v1/auth/token?state=${state}`)
    }
    return c.html(tokenPage(state))
  })

  // GET /token/done
  app.get('/token/done', (c) => c.html(donePage()))

  // POST /approve — browser form submit → issues identity JWT
  app.post('/approve', async (c) => {
    const idToken = getCookie(c, COOKIE_ID_TOKEN)
    if (!idToken) return c.json({ error: 'not_authenticated' }, 401)

    const payload = parseJwtPayload(idToken)
    if (!payload) return c.json({ error: 'invalid_token' }, 401)

    const subject = payload['sub'] as string | undefined
    const issuer  = (payload['iss'] as string | undefined) ?? ''
    if (!subject) return c.json({ error: 'missing_subject' }, 401)

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

    const user = await userRepo.findBySubject(issuer, subject)
    if (!user) return c.json({ error: 'user_not_found' }, 404)

    // identity JWT — no org, just who the user is
    const token = signHs256Jwt(
      { sub: user.id, type: 'human' },
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

    // verify membership
    const { eq, and } = await import('drizzle-orm')
    const rows = await db
      .select({ role: schema.orgMemberships.role })
      .from(schema.orgMemberships)
      .where(and(
        eq(schema.orgMemberships.userId, userId),
        eq(schema.orgMemberships.organizationId, org_id),
      ))
      .limit(1)

    if (!rows[0]) return c.json({ error: 'not_a_member' }, 403)

    const orgToken = signHs256Jwt(
      { sub: userId, org_id, role: rows[0].role, type: 'human' },
      jwtSecret(),
      ORG_TOKEN_TTL,
    )

    return c.json({ token: orgToken, expires_in: ORG_TOKEN_TTL })
  })

  return app
}
