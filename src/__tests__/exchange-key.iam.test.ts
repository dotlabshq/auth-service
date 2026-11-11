/**
 * `/api/exchange-key` against the REAL iam-service, in-process over a real
 * foldbase: a person's API token, an agent's and an organization's key, each
 * created through iam's own routes, then exchanged.
 */
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomUUID } from 'node:crypto'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { FoldBase } from '../../../foldbase/clients/ts/dist/index.js'
// @ts-expect-error — plain ESM helper, no types
import { bootServer, signJwt } from '../../../foldbase/conformance/harness.mjs'
import { createApp as createIam, registerDefinitions as iamDefinitions } from '../../../iam-service/src/app.js'
import { signHs256Jwt, parseJwtPayload } from '@baseworks/auth/jwt'
import { principalOf } from '@baseworks/auth/principal'
import { createApp } from '../app.js'
import { resetRealm } from '../lib/realm.js'
import { InMemoryKv, JWT_SECRET } from './setup.js'

const here = dirname(fileURLToPath(import.meta.url))
const FB_SECRET = 'auth-exchange-foldbase-secret-32-chars!'
const saved = { ...process.env }

let fbBase = ''
let stop: () => Promise<void>
let iam: ReturnType<typeof createIam>
let user = ''

const session = (sub: string) => signHs256Jwt({ sub, type: 'human' }, JWT_SECRET, 3600)
const service = (sub: string) => signHs256Jwt({ sub, type: 'service' }, JWT_SECRET, 3600)
const send = (method: string, path: string, body: unknown, token: string) =>
  iam.fetch(new Request(`http://iam.test${path}`, { method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }))
const json = async (res: Response) => (await res.json()) as Record<string, any>
const exchange = (token: string) => createApp({ kv: new InMemoryKv() as never }).request('/api/exchange-key', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token }) })
const claimsOf = (jwt: string) => parseJwtPayload(jwt) as Record<string, any>

beforeAll(async () => {
  const es = await bootServer({ cmd: './bin/foldbase', dir: resolve(here, '../../../foldbase/go'), env: { FOLDBASE_AUTH: 'service-jwt', FOLDBASE_JWT_SECRET: FB_SECRET } })
  fbBase = es.base
  stop = es.stop
}, 30_000)
afterAll(async () => { await stop() })

beforeEach(async () => {
  process.env = { ...saved }
  process.env['JWT_SECRET'] = JWT_SECRET
  process.env['IAM_SERVICE_URL'] = 'http://iam.test'
  delete process.env['AUTH_SIGNING_KEY']
  delete process.env['IAM_BASE_PATH']
  resetRealm()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  const fb = new FoldBase({ baseUrl: fbBase, token: signJwt({ sub: 'iam-service', type: 'service' }, FB_SECRET), tenant: `t-${randomUUID()}` })
  await iamDefinitions(fb)
  // org-service as far as iam can tell: an admin everywhere, and the one question iam asks
  const org = {
    async orgs() { return [{ id: 'org-1', slug: 'acme', name: 'Acme' }] },
    async permissions() { return { app: 'iam', scope_id: 'org-1', role: 'admin', permissions: ['org_key.read', 'org_key.manage'] } },
    async register() { return true },
  }
  iam = createIam(fb, { org: org as never })
  vi.stubGlobal('fetch', async (url: string | URL | Request, init?: RequestInit) =>
    String(url).startsWith('http://iam.test') ? iam.fetch(new Request(url as string, init)) : fetch.call(globalThis, url as never, init))
  const synced = await send('POST', '/_/sync', { subject: `s-${randomUUID()}`, issuer: 'https://idp.test', email: 'ada@example.test' }, service('auth-service'))
  user = (await json(synced)).user.id
})
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); process.env = { ...saved }; resetRealm() })

describe('against the real iam', () => {
  it('a person\'s API token: a realm token that is the person, through a token, with what the token was limited to', async () => {
    const issued = await json(await send('POST', '/api/tokens', { name: 'laptop', scopes: ['read'] }, session(user)))
    const res = await exchange(issued.secret)
    expect(res.status).toBe(200)
    const body = await json(res)
    expect(body).toMatchObject({ token_type: 'bearer', expires_in: 300 })
    const c = claimsOf(body.token)
    expect(c).toMatchObject({ sub: user, type: 'assistant', kind: 'human', via: 'token', actor: `user:${user}`, credential_id: issued.token.id, access: ['read'] })
    expect(Object.keys(c).sort()).toEqual(['access', 'actor', 'credential_id', 'exp', 'iat', 'kind', 'sub', 'type', 'via'])
    expect(principalOf(c)).toMatchObject({ kind: 'human', via: 'token', access: ['read'] })
  })

  it('a person\'s token with a lifetime of 40 seconds is exchanged for no more than that', async () => {
    const issued = await json(await send('POST', '/api/tokens', { name: 'short', scopes: ['read', 'write'], expires_at: Date.now() + 40_500 }, session(user)))
    const body = await json(await exchange(issued.secret))
    expect(body.expires_in).toBeGreaterThanOrEqual(39)
    expect(body.expires_in).toBeLessThanOrEqual(40)
  })

  it('an agent\'s token: sub is the agent, on behalf of its person, named for its handle', async () => {
    const agent = (await json(await send('POST', '/api/agents', { name: 'dev' }, session(user)))).agent
    const issued = await json(await send('POST', `/api/agents/${agent.id}/tokens`, { name: 'laptop', access: 'write', org_id: 'org-1' }, session(user)))
    const body = await json(await exchange(issued.secret))
    const c = claimsOf(body.token)
    expect(c).toMatchObject({ sub: agent.id, type: 'assistant', kind: 'agent', via: 'token', actor: agent.actor, on_behalf_of: `user:${user}`, org_id: 'org-1', access: ['read', 'write'], credential_id: issued.token.id })
    expect(principalOf(c)).toMatchObject({ kind: 'agent', on_behalf_of: `user:${user}` })
  })

  it('suspend the agent and the exchange stops; resume and it works', async () => {
    const agent = (await json(await send('POST', '/api/agents', { name: 'dev' }, session(user)))).agent
    const issued = await json(await send('POST', `/api/agents/${agent.id}/tokens`, { name: 'laptop' }, session(user)))
    expect((await exchange(issued.secret)).status).toBe(200)
    await send('PATCH', `/api/agents/${agent.id}`, { state: 'suspended' }, session(user))
    const refused = await exchange(issued.secret)
    expect(refused.status).toBe(401)
    expect(await json(refused)).toEqual({ error: 'invalid_token' })
    await send('PATCH', `/api/agents/${agent.id}`, { state: 'active' }, session(user))
    expect((await exchange(issued.secret)).status).toBe(200)
    await send('DELETE', `/api/agents/${agent.id}`, undefined, session(user))
    expect((await exchange(issued.secret)).status).toBe(401)
  })

  it('an organization\'s key: sub is the key, via key, its role and organization, and read access', async () => {
    const issued = await json(await send('POST', '/api/orgs/acme/keys', { name: 'CI deploy', role: 'member', access: 'read' }, session(user)))
    expect(issued.token.type).toBe('machine')
    const body = await json(await exchange(issued.secret))
    const c = claimsOf(body.token)
    expect(c).toMatchObject({ sub: issued.token.id, type: 'assistant', kind: 'machine', via: 'key', actor: 'machine:CI_deploy@org-1', role: 'member', org_id: 'org-1', access: ['read'], credential_id: issued.token.id })
    expect(principalOf(c)).toMatchObject({ kind: 'machine', via: 'key', role: 'member', org_id: 'org-1' })
  })

  it('revoked, expired and unknown tokens are one answer: 401 invalid_token', async () => {
    const a = await json(await send('POST', '/api/tokens', { name: 'a' }, session(user)))
    const b = await json(await send('POST', '/api/tokens', { name: 'b', expires_at: Date.now() - 1000 }, session(user)))
    await send('DELETE', `/api/tokens/${a.token.id}`, undefined, session(user))
    for (const secret of [a.secret, b.secret, 'bwt_unknown', `${a.secret}x`]) {
      const res = await exchange(secret)
      expect(res.status, secret).toBe(401)
      expect(await json(res)).toEqual({ error: 'invalid_token' })
    }
  })
})
