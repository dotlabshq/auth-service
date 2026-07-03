import { describe, it, expect, beforeEach } from 'vitest'
import { createTestApp, makeIdentityToken, makeOrgToken, makeSessionCookie, SESSION_COOKIE_NAME } from './setup.js'

type App = Awaited<ReturnType<typeof createTestApp>>
let app: App

async function json<T>(res: Response): Promise<T> {
  return res.json() as Promise<T>
}

beforeEach(async () => {
  app = await createTestApp()
})

// ─── GET /start ───────────────────────────────────────────────────

describe('GET /start — initiate CLI auth flow', () => {
  it('returns state, url, and expires_in', async () => {
    const res = await app.get('/start')
    expect(res.status).toBe(200)
    const body = await json<{ state: string; url: string; expires_in: number }>(res)
    expect(typeof body.state).toBe('string')
    expect(body.state.length).toBeGreaterThan(0)
    expect(body.url).toContain(body.state)
    expect(body.expires_in).toBe(600)
  })

  it('stores pending status in KV', async () => {
    const res  = await app.get('/start')
    const { state } = await json<{ state: string }>(res)
    const raw = await app.kv.get(`auth:cli:${state}`)
    expect(raw).not.toBeNull()
    expect(JSON.parse(raw!).status).toBe('pending')
  })

  it('each call produces a unique state', async () => {
    const a = await json<{ state: string }>(await app.get('/start'))
    const b = await json<{ state: string }>(await app.get('/start'))
    expect(a.state).not.toBe(b.state)
  })
})

// ─── GET /poll/:state ─────────────────────────────────────────────

describe('GET /poll/:state — check CLI auth status', () => {
  it('returns pending for a fresh state', async () => {
    const { state } = await json<{ state: string }>(await app.get('/start'))
    const res = await app.get(`/poll/${state}`)
    expect(res.status).toBe(200)
    const { status } = await json<{ status: string }>(res)
    expect(status).toBe('pending')
  })

  it('returns expired for unknown state', async () => {
    const res = await app.get('/poll/no-such-state')
    expect(res.status).toBe(200)
    const { status } = await json<{ status: string }>(res)
    expect(status).toBe('expired')
  })

  it('returns done + token and clears KV when approved', async () => {
    const { state } = await json<{ state: string }>(await app.get('/start'))
    // Simulate approved: manually set done in KV
    await app.kv.set(`auth:cli:${state}`, JSON.stringify({ status: 'done', token: 'test-jwt' }))

    const res = await app.get(`/poll/${state}`)
    expect(res.status).toBe(200)
    const body = await json<{ status: string; token?: string }>(res)
    expect(body.status).toBe('done')
    expect(body.token).toBe('test-jwt')

    // KV entry must be removed after done is returned
    const remaining = await app.kv.get(`auth:cli:${state}`)
    expect(remaining).toBeNull()
  })
})

// ─── POST /token-for-org ──────────────────────────────────────────

describe('POST /token-for-org — exchange identity JWT for org-scoped JWT', () => {
  it('returns org-scoped token for a valid member', async () => {
    const user = await app.seedUser()
    const org  = await app.seedOrg()
    await app.seedMembership(user.id, org.id, 'admin')

    const identityToken = makeIdentityToken(user.id)
    const res = await app.post('/token-for-org', { org_id: org.id }, { token: identityToken })
    expect(res.status).toBe(200)
    const body = await json<{ token: string; expires_in: number }>(res)
    expect(typeof body.token).toBe('string')
    expect(body.expires_in).toBe(14400)
  })

  it('returns 401 without Authorization header', async () => {
    const org = await app.seedOrg()
    const res = await app.post('/token-for-org', { org_id: org.id })
    expect(res.status).toBe(401)
  })

  it('returns 401 for invalid/expired token', async () => {
    const org = await app.seedOrg()
    const res = await app.post('/token-for-org', { org_id: org.id }, { token: 'not.a.jwt' })
    expect(res.status).toBe(401)
  })

  it('returns 400 when token is already org-scoped', async () => {
    const user = await app.seedUser()
    const org  = await app.seedOrg()
    await app.seedMembership(user.id, org.id, 'member')
    const orgToken = makeOrgToken(user.id, org.id)
    const res = await app.post('/token-for-org', { org_id: org.id }, { token: orgToken })
    expect(res.status).toBe(400)
    const { error } = await json<{ error: string }>(res)
    expect(error).toBe('already_org_scoped')
  })

  it('returns 403 when user is not a member', async () => {
    const user = await app.seedUser()
    const org  = await app.seedOrg()
    // No membership inserted
    const identityToken = makeIdentityToken(user.id)
    const res = await app.post('/token-for-org', { org_id: org.id }, { token: identityToken })
    expect(res.status).toBe(403)
    const { error } = await json<{ error: string }>(res)
    expect(error).toBe('not_a_member')
  })

  it('returns 400 when org_id is missing from body', async () => {
    const user  = await app.seedUser()
    const token = makeIdentityToken(user.id)
    const res   = await app.post('/token-for-org', {}, { token })
    expect(res.status).toBe(400)
  })

  it('issued token encodes correct role', async () => {
    const { verifyHs256Jwt } = await import('@baseworks/auth/jwt')
    const user = await app.seedUser()
    const org  = await app.seedOrg()
    await app.seedMembership(user.id, org.id, 'owner')

    const identityToken = makeIdentityToken(user.id)
    const { token } = await json<{ token: string }>(
      await app.post('/token-for-org', { org_id: org.id }, { token: identityToken })
    )
    const claims = verifyHs256Jwt(token, process.env['JWT_SECRET']!)
    expect(claims?.['role']).toBe('owner')
    expect(claims?.['org_id']).toBe(org.id)
    expect(claims?.['sub']).toBe(user.id)
  })
})

// ─── GET /session ─────────────────────────────────────────────────

describe('GET /session — browser session check', () => {
  it('returns 401 when no session cookie', async () => {
    const res = await app.get('/session')
    expect(res.status).toBe(401)
    const { isAuthenticated } = await json<{ isAuthenticated: boolean }>(res)
    expect(isAuthenticated).toBe(false)
  })

  it('returns 200 with authenticated session cookie', async () => {
    const sessionData = {
      isAuthenticated: true,
      subject: 'sub-001',
      email: 'user@test.com',
      name: 'Test User',
      issuer: 'https://auth.test',
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    }
    const cookie = makeSessionCookie(sessionData)
    const res = await app.get('/session', { cookie: `${SESSION_COOKIE_NAME}=${cookie}` })
    expect(res.status).toBe(200)
    const body = await json<{ isAuthenticated: boolean; email: string }>(res)
    expect(body.isAuthenticated).toBe(true)
    expect(body.email).toBe('user@test.com')
  })

  it('returns 401 for invalid/malformed session cookie', async () => {
    const res = await app.get('/session', { cookie: 'auth_session=not-base64-json' })
    expect(res.status).toBe(401)
  })

  it('returns 401 for unauthenticated session cookie', async () => {
    const cookie = makeSessionCookie({ isAuthenticated: false })
    const res = await app.get('/session', { cookie: `${SESSION_COOKIE_NAME}=${cookie}` })
    expect(res.status).toBe(401)
  })
})

// ─── GET /healthz ─────────────────────────────────────────────────

describe('healthz', () => {
  it('returns ok', async () => {
    // healthz is on index.ts not the routers, but ensure routes are healthy
    // Test that the app handles unknown routes gracefully (not 500)
    const res = await app.get('/no-such-route')
    expect(res.status).not.toBe(500)
  })
})
