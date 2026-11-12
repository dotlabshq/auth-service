/**
 * Audit lines (auth-service 2.5): one JSON object per line on stdout, written
 * by `audit()` in lib/audit.ts. Every event, ok and refused, the envelope, the
 * request facts, `AUTH_AUDIT=off`, and above all: no secret in any line.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { signHs256Jwt, verifyHs256Jwt } from '@baseworks/auth/jwt'
import { createApp } from '../app.js'
import { audit } from '../lib/audit.js'
import { encodeSession } from '../lib/cookies.js'
import { InMemoryKv, JWT_SECRET, SESSION_COOKIE_NAME, createTestApp } from './setup.js'

const saved = { ...process.env }
let lines: string[]
let realFetch: typeof fetch

/** What was written to stdout, one entry per line. */
const written = () => lines.join('').split('\n').filter(Boolean)
/** The audit lines among them: JSON objects that say `audit: 1`. */
const audited = () => written().flatMap((l) => { try { const o = JSON.parse(l); return o?.audit === 1 ? [o as Record<string, any>] : [] } catch { return [] } })
const last = () => audited().at(-1)!

beforeEach(() => {
  process.env = { ...saved, JWT_SECRET }
  delete process.env['AUTH_AUDIT']
  delete process.env['IAM_SERVICE_URL']
  lines = []
  vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: unknown) => { lines.push(String(chunk)); return true }) as never)
  realFetch = globalThis.fetch
})
afterEach(() => { vi.restoreAllMocks(); globalThis.fetch = realFetch; process.env = { ...saved } })

const session = (user_id = 'usr_1', extra: Record<string, unknown> = {}) =>
  encodeSession({ is_authenticated: true, subject: 'oidc-sub', email: 'ada@example.test', name: 'Ada', issuer: 'https://idp.test', expires_at: Math.floor(Date.now() / 1000) + 3600, user_id, ...extra } as never, { JWT_SECRET } as NodeJS.ProcessEnv)
const BASE = { audit: 1, service: 'auth-service' }
const common = (o: Record<string, any>) => {
  expect(o['ts']).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/)
  expect(typeof o['request_id']).toBe('string')
  expect(o['request_id'].length).toBeGreaterThanOrEqual(8)
  expect(o).toHaveProperty('ip')
  expect(o).toHaveProperty('user_agent')
  expect(['ok', 'refused']).toContain(o['outcome'])
  expect(o).toMatchObject(BASE)
}

describe('the line', () => {
  it('is one JSON object, newline-terminated, with the fixed fields and nothing else on the line', () => {
    audit('sign_out', { outcome: 'ok', request_id: 'req-12345678', ip: '10.0.0.1', user_agent: 'curl/8' })
    expect(lines.join('')).toMatch(/^\{.*\}\n$/)
    expect(written()).toHaveLength(1)
    const o = JSON.parse(written()[0]!)
    expect(Object.keys(o)).toEqual(['audit', 'ts', 'event', 'service', 'outcome', 'request_id', 'ip', 'user_agent'])
    expect(o).toMatchObject({ audit: 1, event: 'sign_out', service: 'auth-service', outcome: 'ok', request_id: 'req-12345678', ip: '10.0.0.1', user_agent: 'curl/8' })
  })

  it('a newline or control character in a value cannot make a second line', () => {
    audit('sign_in_refused', { outcome: 'refused', reason: 'x', request_id: 'req-12345678', ip: '1.2.3.4', user_agent: 'evil\n{"audit":1,"event":"sign_in","outcome":"ok"}\r\u0000' })
    expect(written()).toHaveLength(1)
    expect(JSON.parse(written()[0]!)['event']).toBe('sign_in_refused')
  })

  it('only the known fields are written: anything else passed is dropped', () => {
    audit('exchange', { outcome: 'ok', request_id: 'req-12345678', ip: '', user_agent: '', token: 'eyJhbGciOiJIUzI1NiJ9.abcdefgh.sig', password: 'hunter2', cookie: 'x' } as never)
    expect(Object.keys(JSON.parse(written()[0]!))).not.toEqual(expect.arrayContaining(['token', 'password', 'cookie']))
    expect(lines.join('')).not.toContain('hunter2')
  })

  it('a value that looks like a JWT or an API token is replaced even in an allowed field', () => {
    audit('exchange_key', { outcome: 'refused', reason: 'bwt_abcdefghijklmnop', request_id: 'req-12345678', ip: '', user_agent: 'eyJhbGciOiJIUzI1NiJ9.abcdefghij.sig', actor_id: 'bwt_abcdef' })
    const o = JSON.parse(written()[0]!)
    expect(o['reason']).toBe('[redacted]')
    expect(o['user_agent']).toBe('[redacted]')
    expect(o['actor_id']).toBe('bwt_abcdef') // a credential id, not enough to be a secret
  })

  it('AUTH_AUDIT=off writes nothing', async () => {
    process.env['AUTH_AUDIT'] = 'off'
    audit('sign_out', { outcome: 'ok', request_id: 'req-12345678', ip: '', user_agent: '' })
    const app = await createTestApp()
    await app.post('/api/logout', {})
    expect(written()).toEqual([])
  })
})

describe('sign_in and sign_out', () => {
  const idp = (over: Record<string, unknown> = {}) => {
    process.env['OIDC_ISSUER'] = 'https://idp.test'
    process.env['OIDC_CLIENT_ID'] = 'client'
    const idToken = signHs256Jwt({ sub: 'oidc-sub', type: 'human', email: 'ada@example.test', name: 'Ada', iss: 'https://idp.test', ...over } as never, 'idp-secret', 3600)
    globalThis.fetch = (async (url: string | URL | Request) => {
      if (String(url).startsWith('https://idp.test/oauth/v2/token')) {
        return new Response(JSON.stringify({ id_token: idToken, access_token: 'at-secret-value', refresh_token: 'rt-secret-value', expires_in: 3600 }), { status: 200 })
      }
      return new Response('{}', { status: 500 })
    }) as typeof fetch
    return idToken
  }
  const cb = (app: Awaited<ReturnType<typeof createTestApp>>, q = 'code=the-code', cookie = 'oidc_pkce_verifier=the-verifier; oidc_return_to=%2F') =>
    app.fetch(new Request(`http://localhost/ui/oidc/callback?${q}`, { headers: { cookie, 'user-agent': 'Mozilla/5.0 test', 'x-forwarded-for': '203.0.113.7, 10.0.0.1', 'x-request-id': 'req-from-the-edge' } }))

  it('the OIDC callback: sign_in ok, as the person, via session, from the ui', async () => {
    idp()
    const res = await cb(await createTestApp())
    expect(res.status).toBe(302)
    expect(audited()).toHaveLength(1)
    const o = last()
    common(o)
    expect(o).toEqual({
      ...BASE, ts: o['ts'], event: 'sign_in', outcome: 'ok', request_id: 'req-from-the-edge', ip: '203.0.113.7', user_agent: 'Mozilla/5.0 test',
      kind: 'human', actor: 'user:oidc-sub', actor_id: 'oidc-sub', via: 'session', client: 'ui',
    })
  })

  it('with iam answering 500, the sign-in goes on with the subject and says so', async () => {
    idp()
    const app = await createTestApp()
    process.env['IAM_SERVICE_URL'] = 'http://iam.test'
    const f = globalThis.fetch
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => String(url).startsWith('http://iam.test') ? new Response('{}', { status: 500 }) : f(url as never, init)) as typeof fetch
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await cb(app)
    expect(last()).toMatchObject({ event: 'sign_in', outcome: 'ok', actor: 'user:oidc-sub', degraded: 'iam_sync_failed' })
  })

  it.each([
    ['the provider says no', 'error=access_denied', 'oidc_pkce_verifier=v', 'oidc_denied'],
    ['no code', '', 'oidc_pkce_verifier=v', 'oidc_denied'],
    ['no PKCE verifier cookie', 'code=c', '', 'missing_verifier'],
  ])('sign_in_refused: %s', async (_n, q, cookie, reason) => {
    idp()
    const res = await cb(await createTestApp(), q, cookie)
    expect(res.status).toBe(302)
    const o = last()
    common(o)
    expect(o).toMatchObject({ event: 'sign_in_refused', outcome: 'refused', reason, client: 'ui' })
    expect(o).not.toHaveProperty('actor')
  })

  it('sign_in_refused: the token exchange failing, and an answer with no id_token', async () => {
    idp()
    const app = await createTestApp()
    globalThis.fetch = (async () => new Response('{}', { status: 400 })) as typeof fetch
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await cb(app)
    expect(last()).toMatchObject({ event: 'sign_in_refused', reason: 'token_exchange' })
    globalThis.fetch = (async () => new Response(JSON.stringify({ access_token: 'x' }), { status: 200 })) as typeof fetch
    await cb(app)
    expect(last()).toMatchObject({ event: 'sign_in_refused', reason: 'no_id_token' })
  })

  it('the dev login: ok signs in; a wrong password is refused and never written', async () => {
    const dev = { username: 'admin', password: 'correct horse', generated: false }
    const app = await createTestApp({ dev })
    const form = (p: string) => new URLSearchParams({ username: 'admin', password: p, returnTo: '/' }).toString()
    await app.postForm('/ui/login', form('wrong password'))
    expect(last()).toMatchObject({ event: 'sign_in_refused', outcome: 'refused', reason: 'bad_credentials', client: 'ui' })
    await app.postForm('/ui/login', form('correct horse'))
    expect(last()).toMatchObject({ event: 'sign_in', outcome: 'ok', actor: 'user:admin', via: 'session', kind: 'human' })
    expect(lines.join('')).not.toContain('wrong password')
    expect(lines.join('')).not.toContain('correct horse')
  })

  it('sign_out, GET and POST: the person when the cookie still says who, nobody when it does not', async () => {
    const app = await createTestApp()
    await app.get('/ui/logout', { cookie: `${SESSION_COOKIE_NAME}=${session('usr_9')}` })
    expect(last()).toMatchObject({ event: 'sign_out', outcome: 'ok', actor: 'user:usr_9', via: 'session', client: 'ui' })
    await app.post('/api/logout', {}, { cookie: `${SESSION_COOKIE_NAME}=${session('usr_8')}` })
    expect(last()).toMatchObject({ event: 'sign_out', actor: 'user:usr_8' })
    await app.get('/ui/logout')
    const o = last()
    expect(o).toMatchObject({ event: 'sign_out', outcome: 'ok' })
    expect(o).not.toHaveProperty('actor')
    expect(audited()).toHaveLength(3)
  })
})

describe('cli_approval', () => {
  it('approved from the page, and from the API', async () => {
    const app = await createTestApp()
    const cookie = `${SESSION_COOKIE_NAME}=${session('usr_1')}`
    const start = async () => ((await (await app.get('/api/start')).json()) as { state: string }).state
    const s1 = await start()
    expect((await app.postForm('/ui/cli/approve', `state=${s1}`, { cookie })).status).toBe(302)
    expect(last()).toMatchObject({ event: 'cli_approval', outcome: 'ok', actor: 'user:usr_1', via: 'session', client: 'ui' })
    const s2 = await start()
    expect((await app.post('/api/approve', { state: s2 }, { cookie })).status).toBe(200)
    expect(last()).toMatchObject({ event: 'cli_approval', outcome: 'ok', actor: 'user:usr_1', client: 'api' })
    expect(lines.join('')).not.toContain(s1)
    expect(lines.join('')).not.toContain(s2)
  })

  it('refused: used twice, expired, and nobody signed in', async () => {
    const app = await createTestApp()
    const cookie = `${SESSION_COOKIE_NAME}=${session('usr_1')}`
    const state = ((await (await app.get('/api/start')).json()) as { state: string }).state
    await app.post('/api/approve', { state }, { cookie })
    await app.post('/api/approve', { state }, { cookie })
    expect(last()).toMatchObject({ event: 'cli_approval', outcome: 'refused', reason: 'already_used', actor: 'user:usr_1' })
    await app.post('/api/approve', { state: 'x'.repeat(24) }, { cookie })
    expect(last()).toMatchObject({ event: 'cli_approval', outcome: 'refused', reason: 'expired_or_invalid' })
    await app.post('/api/approve', { state })
    const o = last()
    expect(o).toMatchObject({ event: 'cli_approval', outcome: 'refused', reason: 'not_authenticated' })
    expect(o).not.toHaveProperty('actor')
  })
})

describe('service_token', () => {
  const SECRET = 's3-service-client-secret-value'
  beforeEach(() => { process.env['AUTH_SERVICE_CLIENTS'] = `billing:${SECRET}` })
  const ask = (app: Awaited<ReturnType<typeof createTestApp>>, body: unknown) => app.post('/api/service-token', body)

  it('minted: the service as itself', async () => {
    const app = await createTestApp()
    expect((await ask(app, { client_id: 'billing', client_secret: SECRET })).status).toBe(200)
    const o = last()
    common(o)
    expect(o).toMatchObject({ event: 'service_token', outcome: 'ok', kind: 'service', actor: 'service:billing', actor_id: 'billing', via: 'client' })
  })

  it('refused: a wrong secret and an unknown id are the same line, with the id that was offered', async () => {
    const app = await createTestApp()
    expect((await ask(app, { client_id: 'billing', client_secret: 'wrong-guess-value' })).status).toBe(401)
    expect(last()).toMatchObject({ event: 'service_token', outcome: 'refused', reason: 'invalid_client', client_id: 'billing' })
    expect(last()).not.toHaveProperty('actor')
    expect((await ask(app, { client_id: 'nobody\nelse', client_secret: 'x' })).status).toBe(401)
    expect(last()).toMatchObject({ reason: 'invalid_client', client_id: 'nobody_else' })
    expect(lines.join('')).not.toContain('wrong-guess-value')
  })

  it('no clients configured is refused with its reason', async () => {
    delete process.env['AUTH_SERVICE_CLIENTS']
    expect((await ask(await createTestApp(), { client_id: 'billing', client_secret: 'x' })).status).toBe(503)
    expect(last()).toMatchObject({ event: 'service_token', outcome: 'refused', reason: 'no_clients_configured' })
  })
})

describe('exchange', () => {
  const human = () => signHs256Jwt({ sub: 'usr_1', type: 'human' } as never, JWT_SECRET, 600)
  it('a person narrows their own token: ok, as the person, with the organization they restricted it to', async () => {
    const app = await createTestApp()
    const res = await app.post('/api/exchange', { org_id: 'org-1', scope: 'read' }, { token: human() })
    expect(res.status).toBe(200)
    expect(last()).toMatchObject({ event: 'exchange', outcome: 'ok', kind: 'human', actor: 'user:usr_1', actor_id: 'usr_1', via: 'session', org_id: 'org-1' })
  })

  it('refused: no bearer, a bad token, a service token', async () => {
    const app = await createTestApp()
    await app.post('/api/exchange', {})
    expect(last()).toMatchObject({ event: 'exchange', outcome: 'refused', reason: 'no_bearer' })
    await app.post('/api/exchange', {}, { token: 'garbage' })
    expect(last()).toMatchObject({ outcome: 'refused', reason: 'invalid_token' })
    await app.post('/api/exchange', {}, { token: signHs256Jwt({ sub: 'billing', type: 'service' } as never, JWT_SECRET, 60) })
    expect(last()).toMatchObject({ outcome: 'refused', reason: 'not_human', kind: 'service', actor: 'service:billing' })
  })
})

describe('exchange_key', () => {
  const API = 'bwt_api-token-secret-that-must-never-be-logged'
  const withIam = (answer: () => Response) => {
    process.env['IAM_SERVICE_URL'] = 'http://iam.test'
    globalThis.fetch = (async (url: string | URL | Request) => String(url).startsWith('http://iam.test') ? answer() : new Response('{}', { status: 500 })) as typeof fetch
  }
  const exchange = (token: unknown) => createApp({ kv: new InMemoryKv() as never }).request('/api/exchange-key', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token }) })
  const principal = (p: Record<string, unknown>) => new Response(JSON.stringify({ principal: p }), { status: 200 })

  it('ok: the principal the realm token says, and its credential id, never the token', async () => {
    withIam(() => principal({ token_id: 'tok-a', type: 'agent', org_id: 'org-1', user_id: 'u1', scopes: ['read'], name: 'laptop', metadata: {}, expires_at: null, kind: 'agent', actor: 'agent:dev@ada', actor_id: 'agt-1', on_behalf_of: 'user:u1', access: ['read'] }))
    expect((await exchange(API)).status).toBe(200)
    const o = last()
    common(o)
    expect(o).toMatchObject({ event: 'exchange_key', outcome: 'ok', kind: 'agent', actor: 'agent:dev@ada', actor_id: 'agt-1', on_behalf_of: 'user:u1', via: 'token', credential_id: 'tok-a', org_id: 'org-1' })
    expect(lines.join('')).not.toContain(API)
    expect(lines.join('')).not.toContain('bwt_api')
  })

  it('ok for a machine: via key, the key id as credential', async () => {
    withIam(() => principal({ token_id: 'tok-m', type: 'machine', org_id: 'org-1', user_id: null, scopes: [], name: 'ci', metadata: {}, expires_at: null, kind: 'machine', actor: 'machine:ci@org-1', actor_id: 'tok-m', role: 'member' }))
    await exchange(API)
    expect(last()).toMatchObject({ event: 'exchange_key', outcome: 'ok', kind: 'machine', actor: 'machine:ci@org-1', via: 'key', credential_id: 'tok-m' })
  })

  it.each([
    ['not an API token', () => exchange('not-bwt'), null, 'not_an_api_token'],
    ['iam says no', () => exchange(API), () => new Response('{}', { status: 401 }), 'invalid_token'],
    ['iam is down', () => exchange(API), () => new Response('{}', { status: 503 }), 'iam_unavailable'],
    ['already past its end', () => exchange(API), () => principal({ token_id: 't', type: 'user', org_id: null, user_id: 'u', scopes: [], name: 'n', metadata: {}, expires_at: Date.now() - 1000, kind: 'human', actor: 'user:u', actor_id: 'u' }), 'expired'],
  ])('refused: %s', async (_n, run, iamAnswer, reason) => {
    if (iamAnswer) withIam(iamAnswer)
    await run()
    const o = last()
    common(o)
    expect(o).toMatchObject({ event: 'exchange_key', outcome: 'refused', reason })
    expect(o).not.toHaveProperty('actor')
    expect(o).not.toHaveProperty('credential_id')
    expect(lines.join('')).not.toContain('bwt_api')
  })

  it('no iam configured is refused as exchange_unavailable', async () => {
    delete process.env['IAM_SERVICE_URL']
    expect((await exchange(API)).status).toBe(503)
    expect(last()).toMatchObject({ event: 'exchange_key', outcome: 'refused', reason: 'exchange_unavailable' })
  })
})

describe('no secret in any line', () => {
  it('every route fed a known secret value: no stdout line contains it', async () => {
    const SECRETS = {
      apiToken: 'bwt_KNOWN-api-token-VALUE-0123456789',
      clientSecret: 'KNOWN-client-secret-VALUE-0123456789',
      code: 'KNOWN-oidc-code-VALUE-0123456789',
      verifier: 'KNOWN-pkce-verifier-VALUE-0123456789',
      password: 'KNOWN-password-VALUE-0123456789',
      idToken: '', accessToken: 'KNOWN-access-token-VALUE-0123456789', refreshToken: 'KNOWN-refresh-token-VALUE-0123456789',
      cliState: '',
    }
    process.env['AUTH_SERVICE_CLIENTS'] = `billing:${SECRETS.clientSecret}`
    process.env['OIDC_ISSUER'] = 'https://idp.test'
    process.env['OIDC_CLIENT_ID'] = 'client'
    process.env['IAM_SERVICE_URL'] = 'http://iam.test'
    SECRETS.idToken = signHs256Jwt({ sub: 'oidc-sub', type: 'human', email: 'ada@example.test', iss: 'https://idp.test' } as never, 'idp-secret', 3600)
    globalThis.fetch = (async (url: string | URL | Request) => {
      const u = String(url)
      if (u.startsWith('https://idp.test/oauth/v2/token')) return new Response(JSON.stringify({ id_token: SECRETS.idToken, access_token: SECRETS.accessToken, refresh_token: SECRETS.refreshToken, expires_in: 3600 }), { status: 200 })
      if (u.includes('/service-token')) return new Response('{}', { status: 401 })
      if (u.includes('/tokens/verify')) return new Response(JSON.stringify({ principal: { token_id: 'tok-1', type: 'user', org_id: null, user_id: 'u1', scopes: [], name: 'n', metadata: { api: SECRETS.apiToken }, expires_at: null, kind: 'human', actor: 'user:u1', actor_id: 'u1' } }), { status: 200 })
      return new Response('{}', { status: 500 })
    }) as typeof fetch
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(console, 'log').mockImplementation(() => {})

    const app = await createTestApp({ dev: { username: 'admin', password: SECRETS.password, generated: false } })
    // dev realm: the login form (wrong and right) and the routes around it
    await app.postForm('/ui/login', new URLSearchParams({ username: 'admin', password: `${SECRETS.password}x` }).toString())
    await app.postForm('/ui/login', new URLSearchParams({ username: 'admin', password: SECRETS.password, returnTo: '/' }).toString())
    // service tokens and exchanges
    await app.post('/api/service-token', { client_id: 'billing', client_secret: SECRETS.clientSecret })
    await app.post('/api/service-token', { client_id: 'billing', client_secret: `${SECRETS.clientSecret}-wrong` })
    await app.post('/api/exchange', { org_id: 'o' }, { token: signHs256Jwt({ sub: 'u', type: 'human' } as never, JWT_SECRET, 60) })
    await app.post('/api/exchange-key', { token: SECRETS.apiToken })
    await app.post('/api/exchange-key', { token: SECRETS.apiToken })
    // the CLI device flow
    const cookie = `${SESSION_COOKIE_NAME}=${session('usr_1')}`
    SECRETS.cliState = ((await (await app.get('/api/start')).json()) as { state: string }).state
    await app.post('/api/approve', { state: SECRETS.cliState }, { cookie })
    await app.get('/api/token', { cookie })
    await app.get('/ui/logout', { cookie })
    await app.post('/api/logout', {}, { cookie })
    // and the OIDC callback, in a realm that has an identity provider
    const oidc = await createTestApp()
    process.env['IAM_SERVICE_URL'] = 'http://iam.test'
    const headers = { cookie: `oidc_pkce_verifier=${SECRETS.verifier}; oidc_return_to=%2F` }
    await oidc.fetch(new Request(`http://localhost/ui/oidc/callback?code=${SECRETS.code}`, { headers }))
    await oidc.fetch(new Request(`http://localhost/ui/oidc/callback?code=${SECRETS.code}`, { headers: { cookie: '' } }))

    const out = lines.join('')
    expect(audited().length).toBeGreaterThan(8)
    for (const [name, secret] of Object.entries(SECRETS)) {
      expect(secret, `${name} is set`).not.toBe('')
      expect(out, name).not.toContain(secret)
    }
    // nor any part of the session cookie, the JWT the realm minted, or a bearer
    expect(out).not.toMatch(/eyJ[A-Za-z0-9_-]{8,}\./)
    expect(out).not.toMatch(/bwt_[A-Za-z0-9_-]{8,}/)
    expect(verifyHs256Jwt('x', 'y')).toBeNull()
  })
})
