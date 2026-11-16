/**
 * Role agents (auth-service 2.7.0): acting as another of the person's agents on the token exchange, `act` and `sid`
 * in the realm token, and the `agents` scope on consent. Against a REAL iam (0.11) over a real foldbase, as oauth.test.ts.
 */
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { FoldBase } from '../../../foldbase/clients/ts/dist/index.js'
// @ts-expect-error — plain ESM helper, no types
import { bootServer, signJwt } from '../../../foldbase/conformance/harness.mjs'
import { verifier } from '@baseworks/auth/identity'
import { parseJwtPayload } from '@baseworks/auth/jwt'
import { createApp as createAuth } from '../app.js'
import { createApp as createIam, registerDefinitions as iamDefinitions } from '../../../iam-service/src/app.js'
import { encodeSession } from '../lib/cookies.js'
import { mintIdentityToken } from '../lib/mint.js'
import { resetRealm, realm } from '../lib/realm.js'
import { setClientDocumentFetcher } from '../lib/oauth/clients.js'
import { InMemoryKv } from './setup.js'

const here = dirname(fileURLToPath(import.meta.url))
const FB_SECRET = 'auth-oauth-foldbase-secret-generated!'
const ORIGIN = 'http://auth.test'
/** The issuer carries the path it is published at, as behind the gateway (`https://host/v1/auth`). */
const ISSUER = `${ORIGIN}/api`
const AUDIENCE = 'oauth-realm'
const MCP = 'https://mcp.example.test/mcp'
const saved = { ...process.env }
const HTTPS_CB = 'https://app.example.test/cb'
const realFetch = globalThis.fetch

let fbStop: () => Promise<void>
let authApp: { fetch: (r: Request) => Response | Promise<Response> }
let iamApp: { fetch: (r: Request) => Response | Promise<Response> }
let lines: string[] = []
/** Lets a test change what iam answers on act-as, to prove auth does not trust it blindly. */
let actAsHook: ((a: Record<string, any>) => Record<string, any>) | null = null

const router = (async (input: string | URL | Request, init?: RequestInit) => {
  const req = new Request(input as never, init)
  const host = new URL(req.url).hostname
  if (host === 'auth.test') return authApp.fetch(req)
  if (host === 'iam.test') {
    const res = await iamApp.fetch(req)
    if (actAsHook && new URL(req.url).pathname.endsWith('/act-as') && res.status === 200) return Response.json(actAsHook(await res.json() as Record<string, any>))
    return res
  }
  return realFetch(input as never, init)
}) as typeof fetch

beforeAll(async () => {
  const pem = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
  const es = await bootServer({ cmd: './bin/foldbase', dir: resolve(here, '../../../foldbase/go'), env: { FOLDBASE_AUTH: 'service-jwt', FOLDBASE_JWT_SECRET: FB_SECRET } })
  fbStop = es.stop
  const fb = new FoldBase({ baseUrl: es.base, token: signJwt({ sub: 'oauth-test', type: 'service' }, FB_SECRET), tenant: `t-${randomBytes(4).toString('hex')}` })
  Object.assign(process.env, {
    AUTH_SIGNING_KEY: Buffer.from(pem).toString('base64'), AUTH_ISSUER: ISSUER, AUTH_AUDIENCE: AUDIENCE, APP_PUBLIC_URL: ORIGIN,
    AUTH_JWKS_URI: `${ISSUER}/.well-known/jwks.json`, AUTH_URL: ISSUER, IAM_SERVICE_URL: 'http://iam.test',
    AUTH_API_PATH: '/api', AUTH_UI_PATH: '/ui',
  })
  delete process.env['JWT_SECRET']
  await iamDefinitions(fb)
  iamApp = createIam(fb, { org: null })
  authApp = createAuth({ kv: new InMemoryKv() as never })
  vi.stubGlobal('fetch', router)
}, 60_000)
afterAll(async () => { vi.unstubAllGlobals(); process.env = { ...saved }; resetRealm(); await fbStop?.() })

beforeEach(() => {
  process.env['AUTH_MCP_RESOURCES'] = MCP
  delete process.env['AUTH_OAUTH_CLIENTS']
  delete process.env['AUTH_OAUTH_EXCHANGERS']
  process.env['AUTH_MCP_AGENTS_RESOURCES'] = MCP
  delete process.env['IAM_AGENTS_PER_USER']
  actAsHook = null
  delete process.env['AUTH_AUDIT']
  resetRealm()
  setClientDocumentFetcher(null)
  customDoc = false
  lines = []
  vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: unknown) => { lines.push(String(chunk)); return true }) as never)
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => { vi.restoreAllMocks(); setClientDocumentFetcher(null) })

const audited = () => lines.join('').split('\n').filter(Boolean).flatMap((l) => { try { const o = JSON.parse(l); return o?.audit === 1 ? [o as Record<string, any>] : [] } catch { return [] } })
const lastAudit = (event: string) => audited().filter((o) => o['event'] === event).at(-1)!

// ── people, clients, PKCE ─────────────────────────────────────────────────────

const serviceToken = async (name = 'auth-service') => (await mintIdentityToken({ sub: name, type: 'service', expires_in_seconds: 60 }))!
interface Person { id: string; handle: string; cookie: string }
let n = 0
async function person(name: string): Promise<Person> {
  const r = await iamApp.fetch(new Request('http://iam.test/_/sync', {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${await serviceToken()}` },
    body: JSON.stringify({ subject: `sub-${name}-${++n}`, issuer: 'https://idp.test', email: `${name}-${n}@example.test`, name }),
  }))
  const user = ((await r.json()) as { user: { id: string; handle: string } }).user
  const session = encodeSession({ is_authenticated: true, subject: 's', email: 'e@x.test', name, issuer: 'i', expires_at: Math.floor(Date.now() / 1000) + 3600, user_id: user.id } as never, process.env)
  return { id: user.id, handle: user.handle, cookie: `oidc_session=${session}` }
}

const CIMD = 'https://claude.example.test/oauth/claude-code-client-metadata'
const REDIRECT = 'http://localhost/callback'
let customDoc = false
function cimd(over: Record<string, unknown> = {}) {
  customDoc = Object.keys(over).length > 0
  setClientDocumentFetcher(async () => ({ json: { client_id: CIMD, client_name: 'Claude Code', redirect_uris: [REDIRECT, 'http://127.0.0.1/callback'], token_endpoint_auth_method: 'none', ...over }, headers: { 'cache-control': 'max-age=300' } }))
}
const pkce = () => { const verifier = randomBytes(32).toString('base64url'); return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') } }

const get = (path: string, cookie?: string, headers: Record<string, string> = {}) => authApp.fetch(new Request(`${ISSUER}${path}`, { headers: { ...(cookie ? { cookie } : {}), ...headers } }))
const form = (path: string, body: Record<string, string>, cookie?: string, headers: Record<string, string> = {}) =>
  authApp.fetch(new Request(`${ISSUER}${path}`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...(cookie ? { cookie } : {}), ...headers }, body: new URLSearchParams(body).toString() }))
const json = async <T = Record<string, any>>(res: Response) => (await res.json()) as T
const loc = (res: Response) => new URL(res.headers.get('location') ?? 'http://none.invalid/')

function authorizeUrl(over: Record<string, string | undefined> = {}, p = pkce()) {
  const params: Record<string, string> = {
    response_type: 'code', client_id: CIMD, redirect_uri: REDIRECT, code_challenge: p.challenge, code_challenge_method: 'S256', state: 'st-123', scope: 'read write', resource: MCP,
  }
  for (const [k, v] of Object.entries(over)) { if (v === undefined) delete params[k]; else params[k] = v }
  return { url: `/authorize?${new URLSearchParams(params).toString()}`, ...p }
}

/** Sign in, see the consent page, allow: returns the code and what the client keeps. */
async function consent(who: Person, over: Record<string, string | undefined> = {}, answer: Record<string, string> = { decision: 'approve', access: 'write' }) {
  if (!customDoc) cimd()
  const a = authorizeUrl(over)
  const page = await get(a.url, who.cookie)
  expect(page.status).toBe(200)
  const html = await page.text()
  const req = /name="req" value="([^"]+)"/.exec(html)![1]!
  // The choice of what the connection works as is required: a helper that approves says it.
  const body = answer['decision'] === 'approve' && !answer['default_agent'] && !answer['new_agent'] ? { ...answer, new_agent: 'claude-code' } : answer
  const res = await form('/authorize', { req, ...body }, who.cookie)
  return { ...a, html, res, redirect: loc(res), code: loc(res).searchParams.get('code') }
}
async function tokens(who: Person, over: Record<string, string | undefined> = {}, answer?: Record<string, string>): Promise<Record<string, any>> {
  const c = await consent(who, over, answer)
  const res = await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: over['redirect_uri'] ?? REDIRECT })
  expect(res.status).toBe(200)
  return { ...(await json<Record<string, any>>(res)), verifier: c.verifier }
}
const claims = (jwt: string) => parseJwtPayload(jwt) as Record<string, any>


const EX = 'urn:ietf:params:oauth:grant-type:token-exchange'
const exchange = async (subject: string, over: Record<string, string> = {}, bearer?: string | null) =>
  authApp.fetch(new Request(`${ISSUER}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...(bearer === null ? {} : { authorization: `Bearer ${bearer ?? await serviceToken('mcp')}` }) },
    body: new URLSearchParams({ grant_type: EX, subject_token: subject, subject_token_type: 'urn:ietf:params:oauth:token-type:access_token', ...over }).toString(),
  }))
const human = async (who: Person) => (await mintIdentityToken({ sub: who.id, type: 'human', expires_in_seconds: 60 }))!
const agentsOf = async (who: Person) => ((await (await iamApp.fetch(new Request('http://iam.test/api/agents', { headers: { authorization: `Bearer ${await human(who)}` } }))).json()) as { agents: Array<{ id: string; name: string; state: string }> }).agents
const names = async (who: Person) => (await agentsOf(who)).map((a) => a.name).sort()
const withAgents = { scope: 'read write agents' }

describe('discovery', () => {
  it('lists agents in scopes_supported only when some resource of the realm offers it', async () => {
    expect((await json(await get('/.well-known/oauth-authorization-server')))['scopes_supported']).toEqual(['read', 'write', 'offline_access', 'agents'])
    delete process.env['AUTH_MCP_AGENTS_RESOURCES']
    expect((await json(await get('/.well-known/oauth-authorization-server')))['scopes_supported']).toEqual(['read', 'write', 'offline_access'])
    process.env['AUTH_MCP_AGENTS_RESOURCES'] = 'https://not-a-resource.example.test/mcp'
    expect((await json(await get('/.well-known/oauth-authorization-server')))['scopes_supported']).toEqual(['read', 'write', 'offline_access'])
  })
})

describe('consent and the agents scope', () => {
  it('a client that sends no scope, on a resource that offers agents, is shown the line and the grant includes it', async () => {
    const who = await person('ada')
    const c = await consent(who, { scope: undefined })
    expect(c.html).toContain('work as any of your agents')
    const res = await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT })
    const t = await json(res)
    expect(t['scope']).toBe('read write agents')
    expect(lastAudit('oauth_authorize')).toMatchObject({ step: 'approved', scope: 'read write agents' })
    // the grant answers it on refresh too
    const r = await json(await form('/token', { grant_type: 'refresh_token', client_id: CIMD, refresh_token: t['refresh_token'] }))
    expect(r['scope']).toBe('read write agents offline_access')
    expect((await exchange(r['access_token'], { agent: 'software' })).status).toBe(200)
  })

  it('a client that asks only for read and write is not given agents, and an exchange with agent is refused insufficient_scope', async () => {
    const who = await person('ada')
    const c = await consent(who, { scope: 'read write' })
    expect(c.html).not.toContain('work as any of your agents')
    const t = await json(await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT }))
    expect(t['scope']).toBe('read write')
    expect(await names(who)).toEqual(['claude-code'])
    const res = await exchange(t['access_token'], { agent: 'software' })
    expect(res.status).toBe(403)
    expect(await json(res)).toMatchObject({ error: 'insufficient_scope', scope: 'agents' })
    expect(lastAudit('oauth_token')).toMatchObject({ outcome: 'refused', reason: 'insufficient_scope', agent: 'software' })
    expect(await names(who)).toEqual(['claude-code']) // nothing created
  })

  it('on a resource that does not offer agents the scope is left out, with or without being asked, and the consent page does not mention it', async () => {
    delete process.env['AUTH_MCP_AGENTS_RESOURCES']
    const who = await person('ada')
    for (const scope of [undefined, 'read write agents']) {
      const c = await consent(who, { scope })
      expect(c.html).not.toContain('work as any of your agents')
      const t = await json(await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT }))
      expect(t['scope']).toBe('read write')
    }
  })

  it('a form cannot add agents the client did not ask for', async () => {
    const who = await person('ada')
    const c = await consent(who, { scope: 'read write' }, { decision: 'approve', access: 'write', agents: 'on', scope: 'agents' })
    const t = await json(await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT }))
    expect(t['scope']).toBe('read write')
  })

  it('a person who agreed without agents is asked again when the client adds it (step-up), and then not again', async () => {
    const who = await person('ada')
    cimd({ redirect_uris: [HTTPS_CB] })
    await tokens(who, { redirect_uri: HTTPS_CB, scope: 'read write' })
    // same request: remembered, a code at once
    expect((await get(authorizeUrl({ redirect_uri: HTTPS_CB, scope: 'read write' }).url, who.cookie)).status).toBe(302)
    // adding agents: the page
    const asked = await get(authorizeUrl({ redirect_uri: HTTPS_CB, ...withAgents }).url, who.cookie)
    expect(asked.status).toBe(200)
    expect(await asked.text()).toContain('work as any of your agents')
    // having agreed to it, the same request is remembered
    const t = await tokens(who, { redirect_uri: HTTPS_CB, ...withAgents })
    expect(t['scope']).toBe('read write agents')
    const again = await get(authorizeUrl({ redirect_uri: HTTPS_CB, ...withAgents }).url, who.cookie)
    expect(again.status).toBe(302)
    expect(lastAudit('oauth_authorize')).toMatchObject({ step: 'approved_remembered', scope: 'read write agents' })
  })

  it('a read-only choice with agents keeps agents and read only', async () => {
    const who = await person('ada')
    const t = await tokens(who, withAgents, { decision: 'approve', access: 'read' })
    expect(t['scope']).toBe('read agents')
  })
})

describe('the picker: this connection works as', () => {
  const pick = async (who: Person, answer: Record<string, string>, over: Record<string, string | undefined> = {}) => {
    const c = await consent(who, over, { decision: 'approve', access: 'write', ...answer })
    return c
  }

  it('is on the consent page, with the person\'s active agents (never a connection) and a name field preselected with the client\'s name', async () => {
    const who = await person('ada')
    await tokens(who) // makes the connection agent `claude-code` and a default
    await exchange((await tokens(who, withAgents))['access_token'], { agent: 'software' }) // a role agent exists now
    cimd()
    const page = await (await get(authorizeUrl().url, who.cookie)).text()
    expect(page).toContain('This connection works as')
    expect(page).toContain('name="default_agent"')
    expect(page).toContain('<option value="software"')
    expect(page).not.toContain('<option value="claude-code"')
    expect(page).toContain('name="new_agent"')
  })

  it('first time: the name field holds the suggestion (the client\'s name), and Turkish is there too', async () => {
    const who = await person('ada')
    cimd()
    const page = await (await get(authorizeUrl().url, who.cookie)).text()
    expect(page).toMatch(/name="new_agent" value="claude-code"/)
    const tr = await (await get(authorizeUrl().url, `${who.cookie}; bw_lang=tr`)).text()
    expect(tr).toContain('Bu bağlantı şu ajan olarak çalışır')
  })

  it('a typed new name is created for the person and is what the connection works as', async () => {
    const who = await person('ada')
    const c = await pick(who, { new_agent: 'research' })
    expect(c.code).toBeTruthy()
    expect(lastAudit('oauth_authorize')).toMatchObject({ step: 'approved', default_agent: 'research' })
    const t = await json(await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT }))
    expect(lastAudit('oauth_token')).toMatchObject({ step: 'code_exchanged', default_agent: 'research' })
    const b = claims((await json(await exchange(t['access_token'])))['access_token'])
    expect(b['actor']).toBe(`agent:research@${who.handle}`)
    expect(await names(who)).toContain('research')
  })

  it('an existing agent chosen from the list is used, none is created', async () => {
    const who = await person('ada')
    await exchange((await tokens(who, withAgents))['access_token'], { agent: 'software' })
    const before = await names(who)
    const t = await tokens(who, undefined, { decision: 'approve', access: 'write', default_agent: 'software' })
    const b = claims((await json(await exchange(t['access_token'])))['access_token'])
    expect(b['actor']).toBe(`agent:software@${who.handle}`)
    expect(await names(who)).toEqual(before)
  })

  it('a typed name wins over the list', async () => {
    const who = await person('ada')
    await exchange((await tokens(who, withAgents))['access_token'], { agent: 'software' })
    const t = await tokens(who, undefined, { decision: 'approve', access: 'write', default_agent: 'software', new_agent: 'other' })
    expect(claims((await json(await exchange(t['access_token'])))['access_token'])['actor']).toBe(`agent:other@${who.handle}`)
  })

  it('the choice is required: a POST with neither field, or empty ones, is the 400 page with the request kept, and nothing is created', async () => {
    const who = await person('ada')
    cimd()
    const html = await (await get(authorizeUrl().url, who.cookie)).text()
    const req = /name="req" value="([^"]+)"/.exec(html)![1]!
    const before = await names(who)
    for (const body of [{}, { default_agent: '' }, { new_agent: '' }, { default_agent: '', new_agent: '   ' }]) {
      const res = await form('/authorize', { req, decision: 'approve', access: 'write', ...body }, who.cookie)
      expect(res.status, JSON.stringify(body)).toBe(400)
      expect(await res.text()).toContain('Choose which agent')
    }
    expect(await names(who)).toEqual(before)
    // the request is kept: choosing now works
    expect(loc(await form('/authorize', { req, decision: 'approve', access: 'write', new_agent: 'research' }, who.cookie)).searchParams.get('code')).toBeTruthy()
  })

  it('the name field is required in the form when there is no list to choose from, and a client\'s name may be the prefilled suggestion', async () => {
    const who = await person('ada')
    cimd()
    const page = await (await get(authorizeUrl().url, who.cookie)).text()
    expect(page).toMatch(/name="new_agent"[^>]* required/)
    expect(page).toMatch(/name="new_agent" value="claude-code"/)
  })

  it.each([['an upper-case name', 'Research'], ['a leading digit', '9x'], ['a space', 'my agent'], ['33 characters', 'a'.repeat(33)], ['an at sign', 'a@b']])('a new name with %s: a 400 page, the request is kept, nothing is created', async (_n, bad) => {
    const who = await person('ada')
    cimd()
    const a = authorizeUrl()
    const html = await (await get(a.url, who.cookie)).text()
    const req = /name="req" value="([^"]+)"/.exec(html)![1]!
    const before = await names(who)
    const res = await form('/authorize', { req, decision: 'approve', access: 'write', new_agent: bad }, who.cookie)
    expect(res.status).toBe(400)
    expect(await names(who)).toEqual(before)
    // back, and a good name: the same request still works
    const ok = await form('/authorize', { req, decision: 'approve', access: 'write', new_agent: 'research' }, who.cookie)
    expect(loc(ok).searchParams.get('code')).toBeTruthy()
  })

  it('a list value that is not one of the person\'s agents (another person\'s, or a connection) is a 400 page', async () => {
    const who = await person('ada'), other = await person('bob')
    await exchange((await tokens(other, withAgents))['access_token'], { agent: 'secret' })
    await tokens(who)
    for (const name of ['secret', 'claude-code']) {
      cimd()
      const html = await (await get(authorizeUrl().url, who.cookie)).text()
      const req = /name="req" value="([^"]+)"/.exec(html)![1]!
      expect((await form('/authorize', { req, decision: 'approve', access: 'write', default_agent: name }, who.cookie)).status, name).toBe(400)
    }
  })

  it('refusing stores nothing: no agent is created for a refused consent', async () => {
    const who = await person('ada')
    const c = await consent(who, {}, { decision: 'deny', new_agent: 'research' })
    expect(loc(c.res).searchParams.get('error')).toBe('access_denied')
    expect(await names(who)).not.toContain('research')
  })

  it('a remembered https grant with a chosen default is not asked again, and keeps its default agent', async () => {
    const who = await person('ada')
    cimd({ redirect_uris: [HTTPS_CB] })
    await tokens(who, { redirect_uri: HTTPS_CB }, { decision: 'approve', access: 'write', new_agent: 'research' })
    const again = await get(authorizeUrl({ redirect_uri: HTTPS_CB }).url, who.cookie)
    expect(again.status).toBe(302)
    expect(lastAudit('oauth_authorize')).toMatchObject({ step: 'approved_remembered', default_agent: 'research' })
  })

  describe('the default agent cannot work', () => {
    const state = async (who: Person, id: string, st: string) => iamApp.fetch(new Request(`http://iam.test/api/agents/${id}`, { method: 'PATCH', headers: { 'content-type': 'application/json', authorization: `Bearer ${await human(who)}` }, body: JSON.stringify({ state: st }) }))

    it('suspended: 400 invalid_target agent_inactive, the connection is not revoked, and agent= still works; resumed, it works again', async () => {
      const who = await person('ada')
      const t = await tokens(who, withAgents, { decision: 'approve', access: 'write', new_agent: 'software' })
      const role = (await agentsOf(who)).find((a) => a.name === 'software')!
      expect((await state(who, role.id, 'suspended')).status).toBe(200)
      const res = await exchange(t['access_token'])
      expect(res.status).toBe(400)
      expect(await json(res)).toMatchObject({ error: 'invalid_target', error_description: 'agent_inactive' })
      expect(lastAudit('oauth_token')).toMatchObject({ outcome: 'refused', reason: 'agent_inactive' })
      // another agent by name still works: the connection is alive
      expect(claims((await json(await exchange(t['access_token'], { agent: 'platform' })))['access_token'])['actor']).toBe(`agent:platform@${who.handle}`)
      expect((await state(who, role.id, 'active')).status).toBe(200)
      expect((await exchange(t['access_token'])).status).toBe(200)
    })

    it('removed: 400 invalid_target agent_removed', async () => {
      const who = await person('ada')
      const t = await tokens(who, undefined, { decision: 'approve', access: 'write', new_agent: 'software' })
      const role = (await agentsOf(who)).find((a) => a.name === 'software')!
      expect((await iamApp.fetch(new Request(`http://iam.test/api/agents/${role.id}`, { method: 'DELETE', headers: { authorization: `Bearer ${await human(who)}` } }))).status).toBe(200)
      const res = await exchange(t['access_token'])
      expect(res.status).toBe(400)
      expect(await json(res)).toMatchObject({ error: 'invalid_target', error_description: 'agent_removed' })
    })
  })

  it('agent= overrides the default: the token is for that agent, act present', async () => {
    const who = await person('ada')
    const t = await tokens(who, withAgents, { decision: 'approve', access: 'write', new_agent: 'software' })
    const b = claims((await json(await exchange(t['access_token'], { agent: 'platform' })))['access_token'])
    expect(b).toMatchObject({ actor: `agent:platform@${who.handle}`, act: { actor: `agent:claude-code@${who.handle}` } })
  })

  it('a default agent needs no agents scope: a read/write grant without it still works as its default', async () => {
    const who = await person('ada')
    const t = await tokens(who, { scope: 'read write' }, { decision: 'approve', access: 'write', new_agent: 'software' })
    expect(t['scope']).toBe('read write')
    expect(claims((await json(await exchange(t['access_token'])))['access_token'])['actor']).toBe(`agent:software@${who.handle}`)
    expect((await exchange(t['access_token'], { agent: 'platform' })).status).toBe(403)
  })
})

describe('/token exchange: agent and session', () => {
  async function connection(who: Person, over: Record<string, string | undefined> = {}, answer?: Record<string, string>): Promise<Record<string, any> & { c: Record<string, any> }> {
    const t = await tokens(who, over, answer)
    return { ...t, c: claims(t['access_token']) }
  }

  it('without agent the token is for the default agent chosen on the consent page, with the connection in act, always', async () => {
    const who = await person('ada')
    const t = await connection(who, withAgents, { decision: 'approve', access: 'write', new_agent: 'software' })
    const b = claims((await json(await exchange(t['access_token'])))['access_token'])
    const role = (await agentsOf(who)).find((a) => a.name === 'software')!
    expect(b).toMatchObject({ sub: role.id, actor: `agent:software@${who.handle}`, kind: 'agent', via: 'oauth', access: ['read', 'write'], act: { sub: t.c['sub'], actor: `agent:claude-code@${who.handle}` } })
    expect(b['sub']).not.toBe(b['act']['sub'])
    expect(b['sid']).toBeUndefined()
    expect(lastAudit('oauth_token')).toMatchObject({ step: 'exchanged', default_agent: 'software', actor: `agent:software@${who.handle}`, act: `agent:claude-code@${who.handle}` })
  })

  it('with session only, sid is in the token and the principal is the default agent', async () => {
    const who = await person('ada')
    const t = await connection(who, undefined, { decision: 'approve', access: 'write', new_agent: 'platform' })
    const b = claims((await json(await exchange(t['access_token'], { session: 'sess-ABC_123' })))['access_token'])
    expect(b).toMatchObject({ sid: 'sess-ABC_123', actor: `agent:platform@${who.handle}`, act: { sub: t.c['sub'] } })
  })

  it('a grant from before 0.12 (no default agent) works as the connection: sub = act.sub, act still present', async () => {
    const who = await person('ada')
    cimd()
    const made = await iamApp.fetch(new Request('http://iam.test/_/oauth/grants', {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${await serviceToken()}` },
      body: JSON.stringify({ user_id: who.id, client_id: CIMD, client_name: 'Claude Code', resource: MCP, org_id: null, access: ['read', 'write'] }),
    }))
    expect(made.status).toBe(201)
    const g = ((await made.json()) as { grant: { id: string; agent_id: string; actor: string } }).grant
    const access = (await mintIdentityToken({
      sub: g.agent_id, type: 'assistant', expires_in_seconds: 600, audience: MCP,
      claims: { kind: 'agent', via: 'oauth', actor: g.actor, on_behalf_of: `user:${who.id}`, credential_id: g.id, access: ['read', 'write'], client: 'mcp', client_id: CIMD },
    }))!
    const b = claims((await json(await exchange(access)))['access_token'])
    expect(b).toMatchObject({ sub: g.agent_id, actor: g.actor, act: { sub: g.agent_id, actor: g.actor } })
  })

  it('agent=software mints the realm token for the role agent, with act and sid, created on first use and found on the second', async () => {
    const who = await person('ada')
    const t = await connection(who, withAgents)
    const res = await exchange(t['access_token'], { agent: 'software', session: 'win-1' })
    expect(res.status).toBe(200)
    const body = await json(res)
    expect(body).toMatchObject({ token_type: 'Bearer', issued_token_type: 'urn:ietf:params:oauth:token-type:access_token' })
    expect(body['expires_in']).toBeLessThanOrEqual(300)
    const b = claims(body['access_token'])
    const role = (await agentsOf(who)).find((a) => a.name === 'software')!
    expect(role).toBeTruthy()
    expect(b).toMatchObject({
      aud: AUDIENCE, sub: role.id, type: 'assistant', kind: 'agent', via: 'oauth', actor: `agent:software@${who.handle}`, on_behalf_of: `user:${who.id}`,
      credential_id: t.c['credential_id'], act: { sub: t.c['sub'], actor: `agent:claude-code@${who.handle}` }, access: ['read', 'write'], client: 'mcp', client_id: CIMD, sid: 'win-1',
    })
    expect(b['exp']).toBeLessThanOrEqual(t.c['exp'])
    const r = await realm()
    expect(await verifier({ jwks: r.jwks!, issuer: ISSUER, audience: AUDIENCE })(body['access_token'])).not.toBeNull()
    const line = lastAudit('oauth_token')
    expect(line).toMatchObject({ step: 'exchanged', outcome: 'ok', agent: 'software', act: `agent:claude-code@${who.handle}`, session_id: 'win-1', actor: `agent:software@${who.handle}`, credential_id: t.c['credential_id'], on_behalf_of: `user:${who.id}` })
    // a second window, a second exchange: the same role agent, none created
    const again = claims((await json(await exchange(t['access_token'], { agent: 'software', session: 'win-2' })))['access_token'])
    expect(again['sub']).toBe(role.id)
    expect(again['sid']).toBe('win-2')
    expect(await names(who)).toEqual(['claude-code', 'software'])
  })

  it('the person can name the connection\'s own agent: acting as itself', async () => {
    const who = await person('ada')
    const t = await connection(who, withAgents)
    const b = claims((await json(await exchange(t['access_token'], { agent: 'claude-code' })))['access_token'])
    expect(b['sub']).toBe(t.c['sub'])
  })

  it('a role agent never has more access than the grant: a read grant gives read, whatever the role', async () => {
    const who = await person('ada')
    const t = await connection(who, withAgents, { decision: 'approve', access: 'read' })
    expect(t.c['access']).toEqual(['read'])
    const b = claims((await json(await exchange(t['access_token'], { agent: 'software' })))['access_token'])
    expect(b['access']).toEqual(['read'])
  })

  it('and if iam ever answered wider access than the grant\'s token has, the token keeps the narrower', async () => {
    const who = await person('ada')
    const t = await connection(who, withAgents, { decision: 'approve', access: 'read' })
    actAsHook = (a) => ({ ...a, access: ['read', 'write'] })
    const b = claims((await json(await exchange(t['access_token'], { agent: 'software' })))['access_token'])
    expect(b['access']).toEqual(['read'])
  })

  it('an answer from iam that does not match the subject token (another connection, person or organization) is refused, no token', async () => {
    const who = await person('ada')
    const t = await connection(who, withAgents)
    for (const bad of [{ connection: { id: 'someone-else', actor: 'agent:x@y' } }, { on_behalf_of: 'user:someone-else' }, { org_id: 'org-elsewhere' }]) {
      actAsHook = (a) => ({ ...a, ...bad })
      const res = await exchange(t['access_token'], { agent: 'software' })
      expect(res.status, JSON.stringify(bad)).toBe(400)
      const body = await json(res)
      expect(body['error']).toBe('invalid_grant')
      expect(body['access_token']).toBeUndefined()
    }
    actAsHook = (a) => { const { access: _x, ...rest } = a; return rest }
    expect((await exchange(t['access_token'], { agent: 'software' })).status).toBe(502)
  })

  describe('refusals, and none of them stores anything or mints anything', () => {
    const refused = async (who: Person, t: Record<string, any>, over: Record<string, string>, status: number, error: string, reason: string) => {
      const before = await agentsOf(who)
      const res = await exchange(t['access_token'], over)
      expect(res.status).toBe(status)
      const body = await json(res)
      expect(body['error']).toBe(error)
      expect(body['access_token']).toBeUndefined()
      expect(lastAudit('oauth_token')).toMatchObject({ outcome: 'refused', reason })
      expect(await agentsOf(who)).toEqual(before)
      return body
    }

    it.each([
      ['an upper-case name', 'Software'], ['an empty name', ''], ['a leading digit', '1abc'], ['a space', 'my agent'], ['an at sign (another person\'s agent)', 'software@bob'],
      ['33 characters', 'a'.repeat(33)], ['a slash', 'a/b'],
    ])('agent is %s: invalid_target', async (_n, agent) => {
      const who = await person('ada')
      const t = await connection(who, withAgents)
      await refused(who, t, { agent }, 400, 'invalid_target', 'agent_name_invalid')
    })

    it.each([
      ['empty', ''], ['65 characters', 'a'.repeat(65)], ['a space', 'a b'], ['non-ASCII', 'oturum-ş'], ['a control character', 'a\tb'],
    ])('session is %s: invalid_request, even without agent', async (_n, session) => {
      const who = await person('ada')
      const t = await connection(who, withAgents)
      await refused(who, t, { session }, 400, 'invalid_request', 'session_invalid')
      await refused(who, t, { session, agent: 'software' }, 400, 'invalid_request', 'session_invalid')
    })

    it('a session of 64 visible characters is accepted', async () => {
      const who = await person('ada')
      const t = await connection(who, withAgents)
      expect(claims((await json(await exchange(t['access_token'], { session: '~'.repeat(64) })))['access_token'])['sid']).toBe('~'.repeat(64))
    })

    it('a grant without the agents scope: 403 insufficient_scope naming agents, for any role', async () => {
      const who = await person('ada')
      const t = await connection(who, { scope: 'read write' })
      const body = await refused(who, t, { agent: 'software', session: 's1' }, 403, 'insufficient_scope', 'insufficient_scope')
      expect(body['scope']).toBe('agents')
      expect(lastAudit('oauth_token')).toMatchObject({ session_id: 's1', agent: 'software' })
    })

    it('a grant that was revoked: invalid_grant', async () => {
      const who = await person('ada')
      const t = await connection(who, withAgents)
      expect((await iamApp.fetch(new Request(`http://iam.test/api/agents/${t.c['sub']}/tokens/${t.c['credential_id']}`, { method: 'DELETE', headers: { authorization: `Bearer ${await human(who)}` } }))).status).toBe(200)
      await refused(who, t, { agent: 'software' }, 400, 'invalid_grant', 'grant_not_live_unknown')
    })

    it('a suspended role agent: invalid_target (and the connection\'s own suspension is the grant not being live)', async () => {
      const who = await person('ada')
      const t = await connection(who, withAgents)
      await exchange(t['access_token'], { agent: 'software' })
      const role = (await agentsOf(who)).find((a) => a.name === 'software')!
      const post = async (id: string, state: string) => iamApp.fetch(new Request(`http://iam.test/api/agents/${id}`, { method: 'PATCH', headers: { 'content-type': 'application/json', authorization: `Bearer ${await human(who)}` }, body: JSON.stringify({ state }) }))
      expect((await post(role.id, 'suspended')).status).toBe(200)
      await refused(who, t, { agent: 'software' }, 400, 'invalid_target', 'agent_inactive')
      expect((await post(role.id, 'active')).status).toBe(200)
      expect((await exchange(t['access_token'], { agent: 'software' })).status).toBe(200)
      expect((await post(t.c['sub'], 'suspended')).status).toBe(200)
      await refused(who, t, { agent: 'software' }, 400, 'invalid_grant', 'grant_not_live_agent_inactive')
    })

    it('a removed role agent is not created again by acting as it: invalid_target', async () => {
      const who = await person('ada')
      const t = await connection(who, withAgents)
      await exchange(t['access_token'], { agent: 'software' })
      const role = (await agentsOf(who)).find((a) => a.name === 'software')!
      expect((await iamApp.fetch(new Request(`http://iam.test/api/agents/${role.id}`, { method: 'DELETE', headers: { authorization: `Bearer ${await human(who)}` } }))).status).toBe(200)
      await refused(who, t, { agent: 'software' }, 400, 'invalid_target', 'agent_removed')
    })

    it('over the per-person limit: invalid_target', async () => {
      const who = await person('ada')
      const t = await connection(who, withAgents)
      process.env['IAM_AGENTS_PER_USER'] = '2'
      expect((await exchange(t['access_token'], { agent: 'one' })).status).toBe(200)
      await refused(who, t, { agent: 'two' }, 400, 'invalid_target', 'agent_limit')
      expect(await names(who)).toEqual(['claude-code', 'one'])
    })

    it('iam not answering: 502, never a token', async () => {
      const who = await person('ada')
      const t = await connection(who, withAgents)
      const saved = process.env['IAM_SERVICE_URL']
      process.env['IAM_SERVICE_URL'] = ''
      try {
        const res = await exchange(t['access_token'], { agent: 'software' })
        expect(res.status).toBe(502)
        expect((await json(res))['access_token']).toBeUndefined()
      } finally { process.env['IAM_SERVICE_URL'] = saved }
      expect(await names(who)).toEqual(['claude-code'])
    })

    it('only the exchangers: another service cannot send agent or session', async () => {
      const who = await person('ada')
      const t = await connection(who, withAgents)
      expect((await exchange(t['access_token'], { agent: 'software', session: 's' }, await serviceToken('billing'))).status).toBe(401)
      expect(await names(who)).toEqual(['claude-code'])
    })
  })
})
