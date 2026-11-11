/**
 * `POST /api/exchange-key` (auth-service 2.3.0, workspace ADR 0004 §7): an API
 * token for a realm token, only when iam says it is live, for at most five
 * minutes. iam is a stub here; the real one is in `exchange-key.iam.test.ts`.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { exportPKCS8, generateKeyPair, type JSONWebKeySet } from 'jose'
import { verifier } from '@baseworks/auth/identity'
import { parseJwtPayload, verifyHs256Jwt } from '@baseworks/auth/jwt'
import { principalOf } from '@baseworks/auth/principal'
import { createApp } from '../app.js'
import { resetRealm } from '../lib/realm.js'
import { InMemoryKv, JWT_SECRET } from './setup.js'

const ISSUER = 'https://auth.example.test'
const AUDIENCE = 'example-realm'
const SECRET = 'bwt_s3cr3t-api-token-value-that-must-never-leak'

type Call = { url: string; method: string; auth: string; body: unknown }
let calls: Call[]
let answer: () => Response | Promise<Response>
const saved = { ...process.env }

const verifyAnswer = (principal: Record<string, unknown>, status = 200) => new Response(JSON.stringify({ principal }), { status })
const HUMAN = { token_id: 'tok-h', type: 'user', org_id: null, user_id: 'u1', scopes: ['read'], name: 'laptop', metadata: { secret: 'x' }, expires_at: null, kind: 'human', actor: 'user:u1', actor_id: 'u1', access: ['read'] }
const AGENT = { token_id: 'tok-a', type: 'agent', org_id: 'org-1', user_id: 'u1', scopes: ['read', 'write'], name: 'laptop', metadata: {}, expires_at: null, kind: 'agent', actor: 'agent:dev@ada', actor_id: 'agt-1', on_behalf_of: 'user:u1', agent_id: 'agt-1', access: ['read', 'write'] }
const MACHINE = { token_id: 'tok-m', type: 'machine', org_id: 'org-1', user_id: null, scopes: ['read'], name: 'ci', metadata: { role: 'member', created_by: 'u9' }, expires_at: null, kind: 'machine', actor: 'machine:ci@org-1', actor_id: 'tok-m', role: 'member', created_by: 'u9', access: ['read'] }

function app() { return createApp({ kv: new InMemoryKv() as never }) }
const exchange = (token: unknown, headers: Record<string, string> = {}) =>
  app().request('/api/exchange-key', { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify({ token }) })

async function es256Env() {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true })
  process.env['AUTH_SIGNING_KEY'] = Buffer.from(await exportPKCS8(privateKey)).toString('base64')
  resetRealm()
}
const claimsOf = (token: string) => {
  const { iat, exp, jti, iss, aud, ...rest } = parseJwtPayload(token) as Record<string, unknown>
  return { rest, iat: iat as number, exp: exp as number, iss, aud, jti }
}

beforeEach(async () => {
  process.env = { ...saved }
  process.env['IAM_SERVICE_URL'] = 'http://iam.test'
  process.env['JWT_SECRET'] = JWT_SECRET
  process.env['AUTH_ISSUER'] = ISSUER
  process.env['AUTH_AUDIENCE'] = AUDIENCE
  delete process.env['AUTH_SIGNING_KEY']
  delete process.env['IAM_BASE_PATH']
  resetRealm()
  calls = []
  answer = () => verifyAnswer(HUMAN)
  vi.stubGlobal('fetch', async (url: string | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers)
    calls.push({ url: String(url), method: init?.method ?? 'GET', auth: headers.get('authorization') ?? '', body: init?.body ? JSON.parse(String(init.body)) : undefined })
    return answer()
  })
})
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); process.env = { ...saved }; resetRealm() })

describe('what is not an API token never reaches iam', () => {
  it.each([[''], ['abc'], ['BWT_abc'], [' bwt_abc'], ['Bearer bwt_abc'], ['eyJhbGciOiJIUzI1NiJ9.e30.x'], [null], [undefined], [5], [{}], [['bwt_a']]])('%j is 401 invalid_token', async (token) => {
    const res = await exchange(token)
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'invalid_token' })
    expect(calls).toEqual([])
  })

  it('no body, a body that is not JSON, and one that is not an object are the same 401', async () => {
    for (const init of [{}, { body: 'not json' }, { body: '[]' }, { body: 'null' }]) {
      const res = await app().request('/api/exchange-key', { method: 'POST', headers: { 'content-type': 'application/json' }, ...init })
      expect(res.status).toBe(401)
    }
    expect(calls).toEqual([])
  })

  it('the shape is checked before iam is configured: a non-token is 401 even with no iam', async () => {
    delete process.env['IAM_SERVICE_URL']
    expect((await exchange('nope')).status).toBe(401)
  })
})

describe('asking iam', () => {
  it('without IAM_SERVICE_URL there is no exchange: 503, and nothing is called', async () => {
    delete process.env['IAM_SERVICE_URL']
    const res = await exchange(SECRET)
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({ error: 'exchange_unavailable' })
    expect(calls).toEqual([])
  })

  it('POSTs the token to /_/tokens/verify on iam\'s own address, whatever IAM_BASE_PATH says', async () => {
    process.env['IAM_BASE_PATH'] = '/v1/iam'
    process.env['IAM_SERVICE_URL'] = 'http://iam.test///'
    await exchange(SECRET)
    expect(calls).toHaveLength(1)
    expect(calls[0]).toMatchObject({ url: 'http://iam.test/_/tokens/verify', method: 'POST', body: { token: SECRET } })
  })

  it('as a service of its own, for 60 seconds, named auth-service (or AUTH_SERVICE_NAME)', async () => {
    await exchange(SECRET)
    const claims = verifyHs256Jwt(calls[0]!.auth.replace('Bearer ', ''), JWT_SECRET)!
    expect(claims).toMatchObject({ sub: 'auth-service', type: 'service' })
    expect(claims.exp! - claims.iat!).toBe(60)
    process.env['AUTH_SERVICE_NAME'] = 'zone9-auth'
    await exchange(SECRET)
    expect(verifyHs256Jwt(calls[1]!.auth.replace('Bearer ', ''), JWT_SECRET)).toMatchObject({ sub: 'zone9-auth' })
  })

  it('the caller\'s Authorization header is not the credential and is never forwarded', async () => {
    await exchange(SECRET, { Authorization: 'Bearer some-other-token' })
    expect(calls[0]!.auth).not.toContain('some-other-token')
    expect(JSON.stringify(calls[0]!.body)).toBe(JSON.stringify({ token: SECRET }))
  })

  it('iam saying 401 is invalid_token: one answer for unknown, revoked, expired, suspended', async () => {
    answer = () => new Response(JSON.stringify({ error: 'invalid_token' }), { status: 401 })
    const res = await exchange(SECRET)
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'invalid_token' })
  })

  it.each([[403], [404], [500], [502], [503], [400], [429]])('iam answering %i is 502 iam_unavailable, never a token', async (status) => {
    answer = () => new Response('{}', { status })
    const res = await exchange(SECRET)
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({ error: 'iam_unavailable' })
  })

  it('iam unreachable is 502 iam_unavailable', async () => {
    vi.stubGlobal('fetch', async () => { throw new TypeError('fetch failed') })
    const res = await exchange(SECRET)
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({ error: 'iam_unavailable' })
  })

  it('iam answering 200 with something that is not a principal is 502, never a token', async () => {
    const bad: Array<[string, unknown]> = [
      ['not json', 'garbage'], ['empty object', {}], ['no principal', { ok: true }], ['principal null', { principal: null }],
      ['no kind', { principal: { ...HUMAN, kind: undefined } }], ['kind service', { principal: { ...HUMAN, kind: 'service' } }], ['kind robot', { principal: { ...HUMAN, kind: 'robot' } }],
      ['no actor', { principal: { ...HUMAN, actor: undefined } }], ['empty actor', { principal: { ...HUMAN, actor: '' } }],
      ['no actor_id', { principal: { ...HUMAN, actor_id: undefined } }], ['no token_id', { principal: { ...HUMAN, token_id: undefined } }],
      ['actor_id a number', { principal: { ...HUMAN, actor_id: 5 } }],
      ['agent with no on_behalf_of', { principal: { ...AGENT, on_behalf_of: undefined } }], ['agent with empty on_behalf_of', { principal: { ...AGENT, on_behalf_of: '' } }],
      ['machine with no role', { principal: { ...MACHINE, role: undefined } }], ['machine with no org', { principal: { ...MACHINE, org_id: null } }],
    ]
    for (const [name, body] of bad) {
      answer = () => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status: 200 })
      const res = await exchange(SECRET)
      expect(res.status, name).toBe(502)
      expect(await res.json(), name).toEqual({ error: 'iam_unavailable' })
    }
  })

  it('a realm that can sign nothing answers 500 and mints nothing', async () => {
    delete process.env['JWT_SECRET']
    resetRealm()
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    // iam is still asked; the answer is then a deployment mistake, not a token
    const res = await exchange(SECRET)
    expect([500, 502]).toContain(res.status)
    expect(await res.text()).not.toContain('eyJ')
  })
})

describe('what is minted', () => {
  it('a person: the exact claim set, and nothing from the rest of iam\'s answer', async () => {
    const res = await exchange(SECRET)
    expect(res.status).toBe(200)
    const body = await res.json() as { token: string; token_type: string; expires_in: number }
    expect(body).toEqual({ token: expect.any(String), token_type: 'bearer', expires_in: 300 })
    const c = claimsOf(body.token)
    expect(c.rest).toEqual({ sub: 'u1', type: 'assistant', kind: 'human', via: 'token', actor: 'user:u1', credential_id: 'tok-h', access: ['read'] })
    expect(JSON.stringify(c.rest)).not.toMatch(/laptop|metadata|scopes|secret|user_id|agent_id|created_by/)
  })

  it('a person with no access claim carries none, one with access [] carries []', async () => {
    answer = () => verifyAnswer({ ...HUMAN, access: undefined })
    expect(claimsOf(((await (await exchange(SECRET)).json()) as { token: string }).token).rest).not.toHaveProperty('access')
    answer = () => verifyAnswer({ ...HUMAN, access: [] })
    expect(claimsOf(((await (await exchange(SECRET)).json()) as { token: string }).token).rest).toHaveProperty('access', [])
  })

  it('a person\'s token bound to an organization carries org_id', async () => {
    answer = () => verifyAnswer({ ...HUMAN, org_id: 'org-9' })
    expect(claimsOf(((await (await exchange(SECRET)).json()) as { token: string }).token).rest).toMatchObject({ org_id: 'org-9' })
  })

  it('an agent: sub is the agent, on_behalf_of the person, via token, bound org kept', async () => {
    answer = () => verifyAnswer(AGENT)
    const { token } = (await (await exchange(SECRET)).json()) as { token: string }
    expect(claimsOf(token).rest).toEqual({
      sub: 'agt-1', type: 'assistant', kind: 'agent', via: 'token', actor: 'agent:dev@ada', credential_id: 'tok-a',
      on_behalf_of: 'user:u1', org_id: 'org-1', access: ['read', 'write'],
    })
  })

  it('an agent with no organization binding carries no org_id', async () => {
    answer = () => verifyAnswer({ ...AGENT, org_id: null })
    expect(claimsOf(((await (await exchange(SECRET)).json()) as { token: string }).token).rest).not.toHaveProperty('org_id')
  })

  it('a machine: sub is the key, via key, its role and organization', async () => {
    answer = () => verifyAnswer(MACHINE)
    const { token } = (await (await exchange(SECRET)).json()) as { token: string }
    expect(claimsOf(token).rest).toEqual({
      sub: 'tok-m', type: 'assistant', kind: 'machine', via: 'key', actor: 'machine:ci@org-1', credential_id: 'tok-m',
      role: 'member', org_id: 'org-1', access: ['read'],
    })
  })

  it('type is assistant for every kind, so an older verifier never reads it as a person who signed in', async () => {
    for (const p of [HUMAN, AGENT, MACHINE]) {
      answer = () => verifyAnswer(p)
      const { token } = (await (await exchange(SECRET)).json()) as { token: string }
      expect(claimsOf(token).rest['type']).toBe('assistant')
      const old = { ...(claimsOf(token).rest) }
      delete old['kind']; delete old['via']
      expect(principalOf(old).kind).toBe('agent')
      expect(principalOf(old).via).not.toBe('session')
    }
  })

  it('what auth\'s principalOf makes of it is the principal iam described', async () => {
    for (const [p, kind, via] of [[HUMAN, 'human', 'token'], [AGENT, 'agent', 'token'], [MACHINE, 'machine', 'key']] as const) {
      answer = () => verifyAnswer(p)
      const { token } = (await (await exchange(SECRET)).json()) as { token: string }
      const got = principalOf(claimsOf(token).rest)
      expect(got).toMatchObject({ kind, via, actor: p.actor, id: p.actor_id, credential_id: p.token_id })
      expect(got.via === 'session').toBe(false)
    }
  })
})

describe('how long it lives', () => {
  const ttl = async (expires_at: number | null | undefined) => {
    answer = () => verifyAnswer({ ...HUMAN, expires_at })
    const res = await exchange(SECRET)
    return res.status === 200 ? ((await res.json()) as { token: string; expires_in: number }) : res
  }

  it('five minutes when the API token never expires, or expires later', async () => {
    for (const at of [null, undefined, Date.now() + 3600_000, Date.now() + 301_000]) {
      const r = (await ttl(at)) as { token: string; expires_in: number }
      expect(r.expires_in, String(at)).toBe(300)
      const c = claimsOf(r.token)
      expect(c.exp - c.iat).toBe(300)
    }
  })

  it('never past the API token: min(300, seconds left)', async () => {
    for (const secs of [250, 100, 30, 5, 1]) {
      const r = (await ttl(Date.now() + secs * 1000 + 500)) as { token: string; expires_in: number }
      expect(r.expires_in, `${secs}s left`).toBe(secs)
      const c = claimsOf(r.token)
      expect(c.exp - c.iat).toBe(secs)
      expect(c.exp * 1000).toBeLessThanOrEqual(Date.now() + secs * 1000 + 1500)
    }
  })

  it('an API token with under a second left, or already past, is invalid and nothing is minted', async () => {
    for (const at of [Date.now() + 400, Date.now(), Date.now() - 1, Date.now() - 86_400_000]) {
      const r = (await ttl(at)) as Response
      expect(r.status, String(at)).toBe(401)
      expect(await r.json()).toEqual({ error: 'invalid_token' })
    }
  })
})

describe('both kinds of realm', () => {
  it('an ES256 realm signs with its key, and the published key set verifies it', async () => {
    await es256Env()
    answer = () => verifyAnswer(AGENT)
    const a = app()
    const { token } = (await (await a.request('/api/exchange-key', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: SECRET }) })).json()) as { token: string }
    const set = (await (await a.request('/api/.well-known/jwks.json')).json()) as JSONWebKeySet
    const claims = await verifier({ jwks: set, issuer: ISSUER, audience: AUDIENCE })(token)
    expect(claims).toMatchObject({ sub: 'agt-1', type: 'assistant', kind: 'agent', iss: ISSUER, aud: AUDIENCE })
    expect(JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString()).alg).toBe('ES256')
  })

  it('a realm still on the shared secret signs HS256 with the old claim shape: no iss or aud', async () => {
    const { token } = (await (await exchange(SECRET)).json()) as { token: string }
    expect(verifyHs256Jwt(token, JWT_SECRET)).toMatchObject({ sub: 'u1', type: 'assistant', kind: 'human' })
    const c = parseJwtPayload(token)!
    expect(c).not.toHaveProperty('iss')
    expect(c).not.toHaveProperty('aud')
  })

  it('a token from this realm is not accepted by another key', async () => {
    await es256Env()
    const { token } = (await (await exchange(SECRET)).json()) as { token: string }
    const other = await generateKeyPair('ES256', { extractable: true })
    const { exportJWK } = await import('jose')
    const jwk = { ...(await exportJWK(other.publicKey)), alg: 'ES256', kid: 'other' }
    expect(await verifier({ jwks: { keys: [jwk] }, issuer: ISSUER, audience: AUDIENCE })(token)).toBeNull()
  })
})

describe('nothing leaks, nothing is minted on a failure', () => {
  it('the API token is in no log line and no response, success or failure', async () => {
    const lines: string[] = []
    for (const m of ['log', 'warn', 'error', 'info', 'debug'] as const) vi.spyOn(console, m).mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')) })
    const bodies: string[] = []
    for (const a of [() => verifyAnswer(HUMAN), () => new Response('{}', { status: 401 }), () => new Response('{}', { status: 500 }), () => new Response('x', { status: 200 })]) {
      answer = a
      const res = await exchange(SECRET)
      bodies.push(await res.text())
    }
    vi.stubGlobal('fetch', async () => { throw new TypeError(`fetch failed for ${SECRET}`) })
    bodies.push(await (await exchange(SECRET)).text())
    for (const text of [...lines, ...bodies]) expect(text).not.toContain(SECRET)
    expect(bodies.filter((b) => b.includes('eyJ'))).toHaveLength(1)
  })

  it('a failure never has a token in its answer', async () => {
    for (const status of [401, 403, 500]) {
      answer = () => new Response('{}', { status })
      expect(await (await exchange(SECRET)).text()).not.toContain('"token"')
    }
  })

  it('/exchange and /service-token are as they were', async () => {
    process.env['AUTH_SERVICE_CLIENTS'] = 'svc:shh'
    const res = await app().request('/api/service-token', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_id: 'svc', client_secret: 'shh' }) })
    expect(res.status).toBe(200)
    expect((await app().request('/api/exchange', { method: 'POST' })).status).toBe(401)
  })

  it('the manifest says the service does this', async () => {
    const m = (await (await app().request('/api/.well-known/service')).json()) as { capabilities: string[] }
    expect(m.capabilities).toContain('api-token-exchange')
  })
})
