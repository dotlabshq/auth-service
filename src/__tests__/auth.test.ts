import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import {
  createTestApp, installIamMock,
  makeIdentityToken, makeOrgToken, makeSessionCookie, SESSION_COOKIE_NAME,
} from './setup.js'

type App = Awaited<ReturnType<typeof createTestApp>>
let app: App
let restoreFetch: (() => void) | undefined

async function json<T>(res: Response): Promise<T> {
  return res.json() as Promise<T>
}

beforeEach(async () => {
  app = await createTestApp()
})

afterEach(() => {
  restoreFetch?.()
  restoreFetch = undefined
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
    await app.kv.set(`auth:cli:${state}`, JSON.stringify({ status: 'done', token: 'test-jwt' }))

    const res = await app.get(`/poll/${state}`)
    expect(res.status).toBe(200)
    const body = await json<{ status: string; token?: string }>(res)
    expect(body.status).toBe('done')
    expect(body.token).toBe('test-jwt')

    const remaining = await app.kv.get(`auth:cli:${state}`)
    expect(remaining).toBeNull()
  })
})

// ─── POST /token-for-org (IAM mode) ───────────────────────────────

describe('POST /token-for-org — exchange identity JWT for org-scoped JWT (IAM mode)', () => {
  beforeEach(async () => { app = await createTestApp({ iam: true }) })

  it('returns org-scoped token for a valid member', async () => {
    restoreFetch = installIamMock({ 'user-1': [{ id: 'org-1', role: 'admin' }] })
    const res = await app.post('/token-for-org', { org_id: 'org-1' }, { token: makeIdentityToken('user-1') })
    expect(res.status).toBe(200)
    const body = await json<{ token: string; expires_in: number }>(res)
    expect(typeof body.token).toBe('string')
    expect(body.expires_in).toBe(14400)
  })

  it('returns 401 without Authorization header', async () => {
    const res = await app.post('/token-for-org', { org_id: 'org-1' })
    expect(res.status).toBe(401)
  })

  it('returns 401 for invalid/expired token', async () => {
    const res = await app.post('/token-for-org', { org_id: 'org-1' }, { token: 'not.a.jwt' })
    expect(res.status).toBe(401)
  })

  it('returns 400 when token is already org-scoped', async () => {
    const res = await app.post('/token-for-org', { org_id: 'org-1' }, { token: makeOrgToken('user-1', 'org-1') })
    expect(res.status).toBe(400)
    expect((await json<{ error: string }>(res)).error).toBe('already_org_scoped')
  })

  it('returns 403 when user is not a member', async () => {
    restoreFetch = installIamMock({ 'user-1': [] })
    const res = await app.post('/token-for-org', { org_id: 'org-1' }, { token: makeIdentityToken('user-1') })
    expect(res.status).toBe(403)
    expect((await json<{ error: string }>(res)).error).toBe('not_a_member')
  })

  it('returns 400 when org_id is missing from body', async () => {
    const res = await app.post('/token-for-org', {}, { token: makeIdentityToken('user-1') })
    expect(res.status).toBe(400)
  })

  it('issued token encodes the role IAM reports', async () => {
    const { verifyHs256Jwt } = await import('@baseworks/auth/jwt')
    restoreFetch = installIamMock({ 'user-1': [{ id: 'org-1', role: 'owner' }] })
    const { token } = await json<{ token: string }>(
      await app.post('/token-for-org', { org_id: 'org-1' }, { token: makeIdentityToken('user-1') }),
    )
    const claims = verifyHs256Jwt(token, process.env['JWT_SECRET']!)
    expect(claims?.['role']).toBe('owner')
    expect(claims?.['org_id']).toBe('org-1')
    expect(claims?.['sub']).toBe('user-1')
  })
})

// ─── POST /token-for-org (login-only mode) ────────────────────────

describe('POST /token-for-org — login-only mode has no orgs', () => {
  it('returns 400 org_selection_unavailable when IAM is absent', async () => {
    const res = await app.post('/token-for-org', { org_id: 'org-1' }, { token: makeIdentityToken('user-1') })
    expect(res.status).toBe(400)
    expect((await json<{ error: string }>(res)).error).toBe('org_selection_unavailable')
  })
})

// ─── GET /session ─────────────────────────────────────────────────

describe('GET /session — browser session check', () => {
  it('returns 401 when no session cookie', async () => {
    const res = await app.get('/session')
    expect(res.status).toBe(401)
    expect((await json<{ isAuthenticated: boolean }>(res)).isAuthenticated).toBe(false)
  })

  it('returns 200 with authenticated session cookie', async () => {
    const cookie = makeSessionCookie({
      isAuthenticated: true,
      subject: 'sub-001',
      email: 'user@test.com',
      name: 'Test User',
      issuer: 'https://auth.test',
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    })
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

// ─── GET /token (API flow) ────────────────────────────────────────

describe('GET /token — mints a JWT from the session (no database)', () => {
  it('login-only: token carries the OIDC subject as sub and no org_id', async () => {
    const { verifyHs256Jwt } = await import('@baseworks/auth/jwt')
    const cookie = makeSessionCookie({
      isAuthenticated: true,
      subject: 'sub-xyz', email: 'a@b.com', name: 'A', issuer: 'https://auth.test',
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      userId: 'sub-xyz',
    })
    const res = await app.get('/token', { cookie: `${SESSION_COOKIE_NAME}=${cookie}` })
    expect(res.status).toBe(200)
    const { token } = await json<{ token: string }>(res)
    const claims = verifyHs256Jwt(token, process.env['JWT_SECRET']!)
    expect(claims?.['sub']).toBe('sub-xyz')
    expect(claims?.['org_id']).toBeUndefined()
  })

  it('IAM mode: token carries the resolved userId + orgId from the session', async () => {
    const { verifyHs256Jwt } = await import('@baseworks/auth/jwt')
    const cookie = makeSessionCookie({
      isAuthenticated: true,
      subject: 'sub-xyz', email: 'a@b.com', name: 'A', issuer: 'https://auth.test',
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      userId: 'iam-user-1', orgId: 'iam-org-1',
    })
    const res = await app.get('/token', { cookie: `${SESSION_COOKIE_NAME}=${cookie}` })
    expect(res.status).toBe(200)
    const { token } = await json<{ token: string }>(res)
    const claims = verifyHs256Jwt(token, process.env['JWT_SECRET']!)
    expect(claims?.['sub']).toBe('iam-user-1')
    expect(claims?.['org_id']).toBe('iam-org-1')
  })

  it('returns 401 without a session', async () => {
    const res = await app.get('/token')
    expect(res.status).toBe(401)
  })
})

// ─── unknown routes ───────────────────────────────────────────────

describe('routing', () => {
  it('does not 500 on unknown routes', async () => {
    const res = await app.get('/no-such-route')
    expect(res.status).not.toBe(500)
  })
})
