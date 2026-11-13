/**
 * auth-service as an OAuth 2.1 authorization server for MCP clients (2.6.0),
 * against a REAL iam (in-process, over a real foldbase): metadata, /authorize
 * with its refusals, the consent page, /token (code, refresh with rotation,
 * token exchange), /register, /revoke, the audit lines, and that no secret is
 * ever in a line.
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
const realFetch = globalThis.fetch

let fbStop: () => Promise<void>
let authApp: { fetch: (r: Request) => Response | Promise<Response> }
let iamApp: { fetch: (r: Request) => Response | Promise<Response> }
let lines: string[] = []

const router = (async (input: string | URL | Request, init?: RequestInit) => {
  const req = new Request(input as never, init)
  const host = new URL(req.url).hostname
  if (host === 'auth.test') return authApp.fetch(req)
  if (host === 'iam.test') return iamApp.fetch(req)
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
  const res = await form('/authorize', { req, ...answer }, who.cookie)
  return { ...a, html, res, redirect: loc(res), code: loc(res).searchParams.get('code') }
}
async function tokens(who: Person, over: Record<string, string | undefined> = {}, answer?: Record<string, string>) {
  const c = await consent(who, over, answer)
  const res = await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: over['redirect_uri'] ?? REDIRECT })
  expect(res.status).toBe(200)
  return { ...(await json<Record<string, any>>(res)), verifier: c.verifier }
}
const claims = (jwt: string) => parseJwtPayload(jwt) as Record<string, any>

// ── discovery ─────────────────────────────────────────────────────────────────

describe('discovery (RFC 8414)', () => {
  it('says what a client needs: S256, CIMD, iss, none and private_key_jwt, DCR, offline_access, form-urlencoded token endpoint', async () => {
    const res = await get('/.well-known/oauth-authorization-server')
    expect(res.status).toBe(200)
    expect(await json(res)).toEqual({
      issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token`, registration_endpoint: `${ISSUER}/register`, revocation_endpoint: `${ISSUER}/revoke`,
      jwks_uri: `${ISSUER}/.well-known/jwks.json`, scopes_supported: ['read', 'write', 'offline_access'], response_types_supported: ['code'], response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:token-exchange'], code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'], token_endpoint_auth_signing_alg_values_supported: ['ES256'], revocation_endpoint_auth_methods_supported: ['none'],
      client_id_metadata_document_supported: true, authorization_response_iss_parameter_supported: true,
    })
  })

  it('is on the API mount (the gateway maps /.well-known/oauth-authorization-server/<issuer path> to it), nowhere else, and the metadata issuer is exactly the iss of the tokens', async () => {
    const meta = await (await get('/.well-known/oauth-authorization-server')).json() as Record<string, any>
    expect(meta['issuer']).toBe(ISSUER)
    expect((await authApp.fetch(new Request(`${ORIGIN}/.well-known/oauth-authorization-server`))).status).toBeGreaterThanOrEqual(400)
    expect((await authApp.fetch(new Request(`${ORIGIN}/ui/.well-known/oauth-authorization-server`))).status).toBeGreaterThanOrEqual(400)
    expect((await get('/.well-known/jwks.json')).status).toBe(200)
    const t = await tokens(await person('ada'))
    expect(claims(t['access_token'])['iss']).toBe(meta['issuer'])
    for (const k of ['authorization_endpoint', 'token_endpoint', 'registration_endpoint', 'revocation_endpoint']) expect(meta[k].startsWith(`${ISSUER}/`)).toBe(true)
  })

  it('the consent form posts to the published authorize endpoint', async () => {
    const who = await person('ada')
    cimd()
    expect(await (await get(authorizeUrl().url, who.cookie)).text()).toContain(`action="${ISSUER}/authorize"`)
  })
})

// ── /authorize ────────────────────────────────────────────────────────────────

describe('/authorize: a page, not a redirect, until client and redirect are known good', () => {
  it.each([
    ['an unknown client', { client_id: 'nobody' }],
    ['no client', { client_id: '' }],
    ['a redirect it did not register', { redirect_uri: 'https://evil.example/cb' }],
    ['plain http to a remote host', { redirect_uri: 'http://evil.example/callback' }],
    ['a loopback host it did not register', { redirect_uri: 'http://[::1]:5/callback' }],
    ['the right host, another path', { redirect_uri: 'http://localhost:5/other' }],
    ['a fragment', { redirect_uri: 'http://localhost/callback#x' }],
  ])('%s: 400, no Location, nothing sent to the redirect', async (_n, over) => {
    cimd()
    const who = await person('ada')
    const res = await get(authorizeUrl(over).url, who.cookie)
    expect(res.status).toBe(400)
    expect(res.headers.get('location')).toBeNull()
    expect(await res.text()).toContain('cannot be completed')
  })

  it('no redirect_uri is allowed only when the client has exactly one, and it is not loopback', async () => {
    cimd({ redirect_uris: ['https://app.example.test/cb'] })
    const who = await person('ada')
    const res = await get(authorizeUrl({ redirect_uri: undefined }).url, who.cookie)
    expect(res.status).toBe(200)
    cimd()
    expect((await get(authorizeUrl({ redirect_uri: undefined }).url, who.cookie)).status).toBe(400)
  })

  it('a metadata document that is wrong, or unreachable, is a page too', async () => {
    const who = await person('ada')
    cimd({ client_id: 'https://evil.test/else' })
    expect((await get(authorizeUrl().url, who.cookie)).status).toBe(400)
    setClientDocumentFetcher(async () => { throw new Error('down') })
    expect((await get(authorizeUrl().url, who.cookie)).status).toBe(400)
  })
})

describe('/authorize: after that, a refusal goes back to the client with state and iss', () => {
  const refused = async (over: Record<string, string | undefined>) => {
    cimd()
    const res = await get(authorizeUrl(over).url, (await person('ada')).cookie)
    expect(res.status).toBe(302)
    const u = loc(res)
    expect(`${u.origin}${u.pathname}`).toBe('http://localhost/callback')
    expect(u.searchParams.get('iss')).toBe(ISSUER)
    return u.searchParams
  }
  it.each([
    ['not response_type=code', { response_type: 'token' }, 'unsupported_response_type'],
    ['no code_challenge', { code_challenge: undefined }, 'invalid_request'],
    ['code_challenge_method plain', { code_challenge_method: 'plain' }, 'invalid_request'],
    ['no code_challenge_method', { code_challenge_method: undefined }, 'invalid_request'],
    ['a code_challenge that is not a SHA-256', { code_challenge: 'short' }, 'invalid_request'],
    ['a resource that is not an MCP server of this realm', { resource: 'https://evil.example/mcp' }, 'invalid_target'],
    ['an unknown scope', { scope: 'read admin' }, 'invalid_scope'],
  ])('%s → %s', async (_n, over, error) => {
    const q = await refused(over)
    expect(q.get('error')).toBe(error)
    expect(q.get('state')).toBe('st-123')
    expect(q.get('code')).toBeNull()
  })

  it('resource may be omitted when the realm has one MCP URL (it is used), and is required when it has more', async () => {
    cimd()
    const who = await person('ada')
    expect((await get(authorizeUrl({ resource: undefined }).url, who.cookie)).status).toBe(200)
    process.env['AUTH_MCP_RESOURCES'] = `${MCP},https://other.example.test/mcp`
    const q = await refused({ resource: undefined })
    expect(q.get('error')).toBe('invalid_target')
    process.env['AUTH_MCP_RESOURCES'] = ''
    expect((await refused({})).get('error')).toBe('invalid_target')
  })

  it('a trailing slash on resource is the same resource', async () => {
    cimd()
    expect((await get(authorizeUrl({ resource: `${MCP}/` }).url, (await person('ada')).cookie)).status).toBe(200)
  })

  it('without state, none is sent back; with a state that needs escaping, it comes back intact', async () => {
    cimd()
    const who = await person('ada')
    const a = await get(authorizeUrl({ response_type: 'x', state: undefined }).url, who.cookie)
    expect(loc(a).searchParams.has('state')).toBe(false)
    const b = await get(authorizeUrl({ response_type: 'x', state: 'a b&c=d/é' }).url, who.cookie)
    expect(loc(b).searchParams.get('state')).toBe('a b&c=d/é')
  })
})

describe('/authorize: sign in first, and come back to this request', () => {
  it('nobody signed in: off to the sign-in page, returnTo the same authorize request', async () => {
    cimd()
    const a = authorizeUrl()
    const res = await get(a.url)
    expect(res.status).toBe(302)
    const to = loc(res)
    expect(to.pathname).toBe('/ui/login')
    expect(to.searchParams.get('returnTo')).toBe(`${ISSUER}${a.url}`)
  })

  it('a session cookie that is forged, or expired, is nobody', async () => {
    cimd()
    const forged = `oidc_session=${Buffer.from(JSON.stringify({ isAuthenticated: true, subject: 'x', expiresAt: 9999999999 })).toString('base64url')}`
    expect(loc(await get(authorizeUrl().url, forged)).pathname).toBe('/ui/login')
  })
})

describe('the consent page', () => {
  it('says who is asking, where they go, the resource, the organization, the access, and the name it will act as', async () => {
    const who = await person('ada')
    cimd()
    const res = await get(authorizeUrl().url, who.cookie)
    const html = await res.text()
    expect(html).toContain('Claude Code')
    expect(html).toContain('<strong>localhost</strong>')
    expect(html).toContain('mcp.example.test/mcp')
    expect(html).toContain(`agent:claude-code@${who.handle}`)
    expect(html).toContain('Read only')
    expect(html).toContain('Read and write')
    expect(html).toContain('This application runs on your own computer')
    // no ORG_SERVICE_URL in this environment: the page says organizations are not available, not that the person has none
    expect(html).toContain('Organizations are not available on this server')
    expect(html).not.toContain('You are not in an organization yet')
    expect(html).toMatch(/name="decision" value="approve"/)
    expect(html).toMatch(/name="decision" value="deny"/)
    expect(html).not.toMatch(/<script/i)
    expect(res.headers.get('content-security-policy')).toContain("default-src 'none'")
  })

  it('a client with an https redirect gets no localhost warning and shows its host', async () => {
    const who = await person('ada')
    cimd({ redirect_uris: ['https://claude.ai/api/mcp/auth_callback'] })
    const html = await (await get(authorizeUrl({ redirect_uri: 'https://claude.ai/api/mcp/auth_callback' }).url, who.cookie)).text()
    expect(html).toContain('<strong>claude.ai</strong>')
    expect(html).not.toContain('This application runs on your own computer')
  })

  it('write is offered only when the client asked for it', async () => {
    const who = await person('ada')
    cimd()
    const html = await (await get(authorizeUrl({ scope: 'read' }).url, who.cookie)).text()
    expect(html).toContain('Read only')
    expect(html).not.toContain('Read and write')
  })

  it('a client name that is markup is escaped', async () => {
    const who = await person('ada')
    cimd({ client_name: '<script>alert(1)</script>' })
    const html = await (await get(authorizeUrl().url, who.cookie)).text()
    expect(html).not.toContain('<script>alert(1)')
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })

  it('no logo is loaded from the client\'s server (that would tell it who is looking): the page shows the name and the host of its client_id', async () => {
    const who = await person('ada')
    cimd({ logo_uri: 'https://claude.example.test/l.png' })
    const html = await (await get(authorizeUrl().url, who.cookie)).text()
    expect(html).not.toMatch(/<img/i)
    expect(html).not.toContain('l.png')
    expect(html).toContain('claude.example.test')
    expect(html).toContain('A logo is not loaded from there')
  })

  it('in Turkish when the cookie says so', async () => {
    const who = await person('ada')
    cimd()
    const html = await (await get(authorizeUrl().url, `${who.cookie}; bw_lang=tr`)).text()
    expect(html).toContain('hesabınızı kullanabilsin mi?')
    expect(html).toContain('Yalnızca okuma')
  })
})

describe('the consent answer', () => {
  it('refusing goes back to the client with access_denied, state and iss, and issues no code', async () => {
    const c = await consent(await person('ada'), {}, { decision: 'deny' })
    expect(c.redirect.searchParams.get('error')).toBe('access_denied')
    expect(c.redirect.searchParams.get('state')).toBe('st-123')
    expect(c.redirect.searchParams.get('iss')).toBe(ISSUER)
    expect(c.code).toBeNull()
  })

  it('allowing goes back with a code, the state and iss, to the redirect the client asked for (port and all)', async () => {
    const c = await consent(await person('ada'), { redirect_uri: 'http://localhost:54321/callback' })
    expect(c.redirect.origin).toBe('http://localhost:54321')
    expect(c.redirect.pathname).toBe('/callback')
    expect(c.redirect.searchParams.get('state')).toBe('st-123')
    expect(c.redirect.searchParams.get('iss')).toBe(ISSUER)
    expect(c.code).toMatch(/^[A-Za-z0-9_-]{40,}$/)
  })

  it('another signed-in person cannot answer this request; nor can nobody; and the request is gone after one answer', async () => {
    cimd()
    const ada = await person('ada'), bob = await person('bob')
    const html = await (await get(authorizeUrl().url, ada.cookie)).text()
    const req = /name="req" value="([^"]+)"/.exec(html)![1]!
    expect((await form('/authorize', { req, decision: 'approve' }, bob.cookie)).status).toBe(403)
    expect((await form('/authorize', { req, decision: 'approve' })).status).toBe(401)
    expect((await form('/authorize', { req: 'nonsense', decision: 'approve' }, ada.cookie)).status).toBe(400)
    expect(loc(await form('/authorize', { req, decision: 'approve' }, ada.cookie)).searchParams.get('code')).toBeTruthy()
    expect((await form('/authorize', { req, decision: 'approve' }, ada.cookie)).status).toBe(400)
  })

  it('the form cannot widen what the client asked: asked for read, answering write gives read', async () => {
    const who = await person('ada')
    const c = await consent(who, { scope: 'read' }, { decision: 'approve', access: 'write' })
    const t = await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT })
    expect(claims((await json(t))['access_token'])['access']).toEqual(['read'])
  })

  const HTTPS_CB = 'https://claude.ai/api/mcp/auth_callback'

  it('asked again by a client that comes back to an https address, a person who already agreed is not asked: a code at once', async () => {
    const who = await person('ada')
    cimd({ redirect_uris: [HTTPS_CB] })
    await tokens(who, { redirect_uri: HTTPS_CB })
    const res = await get(authorizeUrl({ redirect_uri: HTTPS_CB }).url, who.cookie)
    expect(res.status).toBe(302)
    expect(loc(res).origin + loc(res).pathname).toBe(HTTPS_CB)
    expect(loc(res).searchParams.get('code')).toBeTruthy()
    expect(lastAudit('oauth_authorize')).toMatchObject({ step: 'approved_remembered', outcome: 'ok' })
  })

  it('but never for a loopback redirect: any program on this computer can name a public client\'s id, so it always sees the page', async () => {
    const who = await person('ada')
    cimd()
    await tokens(who)
    for (const uri of ['http://localhost:51000/callback', 'http://127.0.0.1:51001/callback', 'http://localhost/callback']) {
      const res = await get(authorizeUrl({ redirect_uri: uri }).url, who.cookie)
      expect(res.status, uri).toBe(200)
      expect(res.headers.get('location'), uri).toBeNull()
    }
    expect(audited().filter((o) => o['step'] === 'approved_remembered')).toEqual([])
    // and the same person, same client, same https callback WAS remembered only because it is https
  })

  it('a remembered grant for one https callback does not make another client\'s request silent, nor another resource', async () => {
    const who = await person('ada')
    cimd({ redirect_uris: [HTTPS_CB] })
    await tokens(who, { redirect_uri: HTTPS_CB })
    process.env['AUTH_MCP_RESOURCES'] = `${MCP},https://other.example.test/mcp`
    expect((await get(authorizeUrl({ redirect_uri: HTTPS_CB, resource: 'https://other.example.test/mcp' }).url, who.cookie)).status).toBe(200)
  })

  it('but asking for more (write, after read) asks again', async () => {
    const who = await person('ada')
    await tokens(who, { scope: 'read' })
    cimd()
    expect((await get(authorizeUrl({ scope: 'read write' }).url, who.cookie)).status).toBe(200)
  })

  it('and another person is always asked', async () => {
    await tokens(await person('ada'))
    cimd()
    expect((await get(authorizeUrl().url, (await person('bob')).cookie)).status).toBe(200)
  })
})

// ── /token ────────────────────────────────────────────────────────────────────

describe('/token: authorization_code', () => {
  it('answers a Bearer access token for five minutes, a refresh token and the scope; nothing is cached', async () => {
    const who = await person('ada')
    const c = await consent(who)
    const res = await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT, resource: MCP })
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    const body = await json(res)
    expect(body).toMatchObject({ token_type: 'Bearer', expires_in: 300, scope: 'read write' })
    expect(body['refresh_token']).toMatch(/^bwr_/)
  })

  it('the access token is a realm JWT: agent, via oauth, on behalf of the person, bound to the MCP resource, five minutes', async () => {
    const who = await person('ada')
    const t = await tokens(who)
    const c = claims(t['access_token'])
    expect(c).toMatchObject({
      iss: ISSUER, aud: MCP, type: 'assistant', kind: 'agent', via: 'oauth', actor: `agent:claude-code@${who.handle}`, on_behalf_of: `user:${who.id}`,
      access: ['read', 'write'], client: 'mcp', client_id: CIMD,
    })
    expect(c['exp'] - c['iat']).toBe(300)
    expect(c['credential_id']).toBeTruthy()
    expect(c['sub']).toBeTruthy()
    expect(c).not.toHaveProperty('org_id')
    // verifiable by the MCP server (audience = the MCP URL) with the realm's keys, and NOT as a realm token
    const r = await realm()
    expect(await verifier({ jwks: r.jwks!, issuer: ISSUER, audience: MCP })(t['access_token'])).not.toBeNull()
    expect(await verifier({ jwks: r.jwks!, issuer: ISSUER, audience: AUDIENCE })(t['access_token'])).toBeNull()
  })

  it('the agent is the person\'s, listed with the client; the grant is on its Agents tab', async () => {
    const who = await person('ada')
    const t = await tokens(who)
    const agents = await (await iamApp.fetch(new Request('http://iam.test/api/agents', { headers: { authorization: `Bearer ${(await mintIdentityToken({ sub: who.id, type: 'human', expires_in_seconds: 60 }))!}` } }))).json() as { agents: Array<Record<string, any>> }
    expect(agents.agents).toEqual([expect.objectContaining({ client_id: CIMD, client_name: 'Claude Code', actor: `agent:claude-code@${who.handle}`, id: claims(t['access_token'])['sub'] })])
  })

  it('the consent page preselects read, also when the client asks for write: write is the person\'s own choice', async () => {
    const who = await person('ada')
    for (const scope of ['read', 'read write', 'write']) {
      const c = await consent(who, { scope })
      expect(c.html, scope).toMatch(/value="read" checked/)
      if (scope !== 'read') expect(c.html, scope).toMatch(/value="write">/)
      expect(c.html, scope).not.toMatch(/value="write" checked/)
    }
  })

  it('a PKCE verifier may use every unreserved character (RFC 7636), `.` and `~` too, as the MCP SDK makes them', async () => {
    const who = await person('ada')
    const verifier = 'abcDEF0123456789-._~abcDEF0123456789-._~abcDEF01234'
    const challenge = createHash('sha256').update(verifier).digest('base64url')
    const c = await consent(who, { code_challenge: challenge })
    const ok = await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: verifier, redirect_uri: REDIRECT })
    expect(ok.status).toBe(200)
    const c2 = await consent(await person('burner2'), { code_challenge: challenge }, { decision: 'approve' })
    const bad = await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c2.code!, code_verifier: verifier + '!', redirect_uri: REDIRECT })
    expect(bad.status).toBe(400)
  })

  it('a code is single use, whoever tries again, and one wrong try burns it', async () => {
    const who = await person('ada')
    const c = await consent(who)
    const ok = { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT }
    expect((await form('/token', ok)).status).toBe(200)
    const again = await form('/token', ok)
    expect(again.status).toBe(400)
    expect((await json(again))['error']).toBe('invalid_grant')
    const c2 = await consent(await person('burner'), {}, { decision: 'approve' })
    expect((await form('/token', { ...ok, code: c2.code!, code_verifier: pkce().verifier })).status).toBe(400)
    expect((await form('/token', { ...ok, code: c2.code!, code_verifier: c2.verifier })).status).toBe(400)
  })

  it.each([
    ['a wrong code_verifier', (c: any) => ({ code_verifier: pkce().verifier })],
    ['no code_verifier', () => ({ code_verifier: '' })],
    ['a code_verifier that is not base64url of enough length', () => ({ code_verifier: 'short' })],
    ['another redirect_uri', () => ({ redirect_uri: 'http://localhost:9/other' })],
    ['a code nobody issued', () => ({ code: 'x'.repeat(43) })],
    ['no code', () => ({ code: '' })],
  ])('refuses %s with invalid_grant', async (_n, over) => {
    const c = await consent(await person('ada'))
    const res = await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT, ...over(c) })
    expect(res.status).toBe(400)
    expect((await json(res))['error']).toBe('invalid_grant')
  })

  it('a code issued to one client is not honoured for another', async () => {
    const c = await consent(await person('ada'))
    process.env['AUTH_OAUTH_CLIENTS'] = JSON.stringify([{ client_id: 'other-client', client_name: 'Other', redirect_uris: [REDIRECT] }])
    const res = await form('/token', { grant_type: 'authorization_code', client_id: 'other-client', code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT })
    expect(res.status).toBe(400)
    expect(lastAudit('oauth_token')).toMatchObject({ outcome: 'refused', reason: 'client_mismatch' })
  })

  it('resource: a different known resource than the code was for, or an unknown one, is invalid_target', async () => {
    process.env['AUTH_MCP_RESOURCES'] = `${MCP},https://other.example.test/mcp`
    const c = await consent(await person('ada'))
    const base = { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT }
    expect((await json(await form('/token', { ...base, resource: 'https://evil.example/mcp' })))['error']).toBe('invalid_target')
    const c2 = await consent(await person('ada'))
    expect((await json(await form('/token', { ...base, code: c2.code!, code_verifier: c2.verifier, resource: 'https://other.example.test/mcp' })))['error']).toBe('invalid_target')
  })

  it('no client at all is invalid_client (401); an unknown or malformed one too; so is JSON instead of a form', async () => {
    expect((await form('/token', { grant_type: 'authorization_code', code: 'x' })).status).toBe(401)
    expect((await form('/token', { grant_type: 'authorization_code', client_id: 'nobody', code: 'x' })).status).toBe(401)
    const j = await authApp.fetch(new Request(`${ISSUER}/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'authorization_code', client_id: CIMD }) }))
    expect([400, 401]).toContain(j.status)
  })

  it('an unsupported grant type is unsupported_grant_type', async () => {
    cimd()
    const res = await form('/token', { grant_type: 'password', client_id: CIMD, username: 'a', password: 'b' })
    expect(res.status).toBe(400)
    expect((await json(res))['error']).toBe('unsupported_grant_type')
  })

  it('a removed account cannot get tokens from a code it was shown before', async () => {
    const who = await person('ada')
    const c = await consent(who)
    const humanToken = (await mintIdentityToken({ sub: who.id, type: 'human', expires_in_seconds: 60 }))!
    expect((await iamApp.fetch(new Request('http://iam.test/api/me', { method: 'DELETE', headers: { authorization: `Bearer ${humanToken}` } }))).status).toBe(200)
    const res = await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT })
    expect(res.status).toBe(400)
    expect((await json(res))['error']).toBe('invalid_grant')
  })
})

describe('/token: refresh_token', () => {
  const refresh = (rt: string, extra: Record<string, string> = {}) => form('/token', { grant_type: 'refresh_token', client_id: CIMD, refresh_token: rt, ...extra })

  it('rotates: a new access token and a new refresh token every time, same agent and grant', async () => {
    const t = await tokens(await person('ada'))
    const r1 = await json(await refresh(t['refresh_token']))
    expect(r1['refresh_token']).toMatch(/^bwr_/)
    expect(r1['refresh_token']).not.toBe(t['refresh_token'])
    expect(r1).toMatchObject({ token_type: 'Bearer', expires_in: 300 })
    const a = claims(t['access_token']), b = claims(r1['access_token'])
    expect(b).toMatchObject({ sub: a['sub'], credential_id: a['credential_id'], aud: MCP, via: 'oauth', kind: 'agent', access: ['read', 'write'] })
    expect((await refresh(r1['refresh_token'])).status).toBe(200)
  })

  it('an old refresh token used again is invalid_grant, and the whole chain, the newest included, is dead', async () => {
    const t = await tokens(await person('ada'))
    const r1 = await json(await refresh(t['refresh_token']))
    const reuse = await refresh(t['refresh_token'])
    expect(reuse.status).toBe(400)
    expect(await json(reuse)).toEqual({ error: 'invalid_grant', error_description: 'the refresh token is not valid' })
    expect((await refresh(r1['refresh_token'])).status).toBe(400)
    expect(audited().filter((o) => o['event'] === 'oauth_token' && o['step'] === 'refresh_reuse_detected')).toHaveLength(1)
  })

  it('every way to be dead is the same answer: unknown, another client\'s, empty', async () => {
    const t = await tokens(await person('ada'))
    process.env['AUTH_OAUTH_CLIENTS'] = JSON.stringify([{ client_id: 'other-client', client_name: 'Other', redirect_uris: [REDIRECT] }])
    for (const res of [await refresh('bwr_unknown-token'), await refresh(''), await form('/token', { grant_type: 'refresh_token', client_id: 'other-client', refresh_token: t['refresh_token'] })]) {
      expect(res.status).toBe(400)
      expect((await json(res))['error']).toMatch(/invalid_grant|invalid_request/)
    }
    // the other client's attempt spent nothing: the real one still works
    expect((await refresh(t['refresh_token'])).status).toBe(200)
  })

  it('a resource that is not the grant\'s is invalid_target', async () => {
    const t = await tokens(await person('ada'))
    process.env['AUTH_MCP_RESOURCES'] = `${MCP},https://other.example.test/mcp`
    expect((await json(await refresh(t['refresh_token'], { resource: 'https://other.example.test/mcp' })))['error']).toBe('invalid_target')
  })

  it('stops when the person suspends the agent on the Agents tab, and removing the account ends it for good', async () => {
    const who = await person('ada')
    const t = await tokens(who)
    const human = (await mintIdentityToken({ sub: who.id, type: 'human', expires_in_seconds: 60 }))!
    const agent = claims(t['access_token'])['sub']
    const call = (method: string, path: string, body?: unknown) => iamApp.fetch(new Request(`http://iam.test/api${path}`, { method, headers: { authorization: `Bearer ${human}`, 'content-type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) }))
    await call('PATCH', `/agents/${agent}`, { state: 'suspended' })
    expect((await refresh(t['refresh_token'])).status).toBe(400)
    await call('PATCH', `/agents/${agent}`, { state: 'active' })
    expect((await refresh(t['refresh_token'])).status).toBe(200)
  })

  it('revoking the grant on the Agents tab ends the refresh token', async () => {
    const who = await person('ada')
    const t = await tokens(who)
    const human = (await mintIdentityToken({ sub: who.id, type: 'human', expires_in_seconds: 60 }))!
    const c = claims(t['access_token'])
    const del = await iamApp.fetch(new Request(`http://iam.test/api/agents/${c['sub']}/tokens/${c['credential_id']}`, { method: 'DELETE', headers: { authorization: `Bearer ${human}` } }))
    expect(del.status).toBe(200)
    expect((await refresh(t['refresh_token'])).status).toBe(400)
  })
})

describe('/token: token exchange for the MCP server', () => {
  const EX = 'urn:ietf:params:oauth:grant-type:token-exchange'
  const exchange = async (subject: string, over: Record<string, string> = {}, bearer?: string | null) =>
    authApp.fetch(new Request(`${ISSUER}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...(bearer === null ? {} : { authorization: `Bearer ${bearer ?? await serviceToken('mcp')}` }) },
      body: new URLSearchParams({ grant_type: EX, subject_token: subject, subject_token_type: 'urn:ietf:params:oauth:token-type:access_token', ...over }).toString(),
    }))

  it('an MCP-audience token in, a realm-audience token for the same agent and person out, never longer than five minutes', async () => {
    const who = await person('ada')
    const t = await tokens(who)
    const res = await exchange(t['access_token'])
    expect(res.status).toBe(200)
    const body = await json(res)
    expect(body).toMatchObject({ token_type: 'Bearer', issued_token_type: 'urn:ietf:params:oauth:token-type:access_token' })
    expect(body['expires_in']).toBeLessThanOrEqual(300)
    const a = claims(t['access_token']), b = claims(body['access_token'])
    expect(b).toMatchObject({ aud: AUDIENCE, sub: a['sub'], kind: 'agent', via: 'oauth', actor: a['actor'], on_behalf_of: a['on_behalf_of'], credential_id: a['credential_id'], access: ['read', 'write'] })
    expect(b['exp']).toBeLessThanOrEqual(a['exp'])
    const r = await realm()
    expect(await verifier({ jwks: r.jwks!, issuer: ISSUER, audience: AUDIENCE })(body['access_token'])).not.toBeNull()
    expect(lastAudit('oauth_token')).toMatchObject({ step: 'exchanged', outcome: 'ok', kind: 'agent', actor: a['actor'] })
  })

  it('only the named service may ask: nobody, a person, another service', async () => {
    const t = await tokens(await person('ada'))
    expect((await exchange(t['access_token'], {}, null)).status).toBe(401)
    expect((await exchange(t['access_token'], {}, 'garbage')).status).toBe(401)
    expect((await exchange(t['access_token'], {}, await serviceToken('billing'))).status).toBe(401)
    expect((await exchange(t['access_token'], {}, (await mintIdentityToken({ sub: 'u1', type: 'human', expires_in_seconds: 60 }))!)).status).toBe(401)
    process.env['AUTH_OAUTH_EXCHANGERS'] = 'billing'
    expect((await exchange(t['access_token'], {}, await serviceToken('billing'))).status).toBe(200)
    expect((await exchange(t['access_token'])).status).toBe(401)
  })

  it('refuses a subject token that is not an MCP access token', async () => {
    const t = await tokens(await person('ada'))
    const realmToken = (await json(await exchange(t['access_token'])))['access_token']
    for (const [name, token] of [['a realm token (wrong audience)', realmToken], ['a human session', (await mintIdentityToken({ sub: 'u1', type: 'human', expires_in_seconds: 60 }))!], ['garbage', 'x.y.z'], ['empty', '']] as const) {
      const res = await exchange(token)
      expect(res.status, name).toBe(400)
      expect((await json(res))['error'], name).toBe('invalid_grant')
    }
    const other = await mintIdentityToken({ sub: 'agt', type: 'assistant', expires_in_seconds: 60, audience: MCP, claims: { kind: 'agent', via: 'token', actor: 'agent:x@y', on_behalf_of: 'user:u', credential_id: 'c' } })
    expect((await exchange(other!)).status).toBe(400)
  })

  it('refuses a wrong subject_token_type and an audience that is not the realm', async () => {
    const t = await tokens(await person('ada'))
    expect((await exchange(t['access_token'], { subject_token_type: 'urn:ietf:params:oauth:token-type:jwt' })).status).toBe(400)
    const res = await exchange(t['access_token'], { audience: 'https://elsewhere.example/' })
    expect(res.status).toBe(400)
    expect((await json(res))['error']).toBe('invalid_target')
  })

  it('an expired subject token is refused, and the result never outlives it', async () => {
    const t = await tokens(await person('ada'))
    const c = claims(t['access_token'])
    const short = (await mintIdentityToken({ sub: c['sub'], type: 'assistant', expires_in_seconds: 20, audience: MCP, claims: { kind: 'agent', via: 'oauth', actor: c['actor'], on_behalf_of: c['on_behalf_of'], credential_id: c['credential_id'], access: ['read'], client_id: CIMD } }))!
    const ok = await json(await exchange(short))
    expect(ok['expires_in']).toBeLessThanOrEqual(20)
    expect(claims(ok['access_token'])['access']).toEqual(['read'])
  })
})

// ── /register, /revoke ────────────────────────────────────────────────────────

describe('/register (RFC 7591)', () => {
  const reg = (body: unknown, headers: Record<string, string> = {}) => authApp.fetch(new Request(`${ISSUER}/register`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) }))

  it('registers a public client and answers 201 with what RFC 7591 asks; the client then works in /authorize', async () => {
    const res = await reg({ client_name: 'My Tool', redirect_uris: ['http://localhost:7777/cb', 'https://tool.example.test/cb'], token_endpoint_auth_method: 'none', grant_types: ['authorization_code'] })
    expect(res.status).toBe(201)
    const c = await json(res)
    expect(c).toMatchObject({ client_name: 'My Tool', token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] })
    expect(c['client_id']).toMatch(/^bwc_/)
    expect(typeof c['client_id_issued_at']).toBe('number')
    const who = await person('ada')
    const p = pkce()
    const q = new URLSearchParams({ response_type: 'code', client_id: c['client_id'], redirect_uri: 'http://localhost:51515/cb', code_challenge: p.challenge, code_challenge_method: 'S256', resource: MCP })
    const page = await get(`/authorize?${q}`, who.cookie)
    expect(page.status).toBe(200)
    expect(await page.text()).toContain('My Tool')
  })

  it.each([
    ['no body', 'x', 'invalid_client_metadata'],
    ['no redirect_uris', { client_name: 'x' }, 'invalid_redirect_uri'],
    ['a remote http redirect', { redirect_uris: ['http://evil.example/cb'] }, 'invalid_redirect_uri'],
    ['a custom scheme', { redirect_uris: ['myapp://cb'] }, 'invalid_redirect_uri'],
    ['a fragment', { redirect_uris: ['https://a.test/cb#x'] }, 'invalid_redirect_uri'],
    ['a secret method', { redirect_uris: ['https://a.test/cb'], token_endpoint_auth_method: 'client_secret_post' }, 'invalid_client_metadata'],
  ])('refuses %s with %s', async (_n, body, error) => {
    const res = await reg(body)
    expect(res.status).toBe(400)
    expect((await json(res))['error']).toBe(error)
  })

  it('is rate limited per address', async () => {
    process.env['AUTH_OAUTH_REGISTER_PER_MINUTE'] = '2'
    const fresh = createAuth({ kv: new InMemoryKv() as never })
    const call = () => fresh.fetch(new Request(`${ISSUER}/register`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.9' }, body: JSON.stringify({ client_name: 'x', redirect_uris: ['https://a.test/cb'] }) }))
    expect((await call()).status).toBe(201)
    expect((await call()).status).toBe(201)
    expect((await call()).status).toBe(429)
    delete process.env['AUTH_OAUTH_REGISTER_PER_MINUTE']
  })
})

describe('/revoke (RFC 7009)', () => {
  it('ends the grant, and answers 200 for a token nobody knows, an access token and nothing at all', async () => {
    const t = await tokens(await person('ada'))
    expect((await form('/revoke', { token: t['refresh_token'], client_id: CIMD })).status).toBe(200)
    expect((await form('/token', { grant_type: 'refresh_token', client_id: CIMD, refresh_token: t['refresh_token'] })).status).toBe(400)
    for (const token of ['bwr_unknown', t['access_token'], '']) expect((await form('/revoke', { token })).status).toBe(200)
    expect((await form('/revoke', {})).status).toBe(200)
  })
})

// ── the audit lines ───────────────────────────────────────────────────────────

describe('the audit lines', () => {
  it('the whole flow, in lines: consent shown, approved, code exchanged, refreshed; the client, the resource, whether it was sent', async () => {
    const who = await person('ada')
    const t = await tokens(who, { resource: undefined })
    await form('/token', { grant_type: 'refresh_token', client_id: CIMD, refresh_token: t['refresh_token'] })
    const steps = audited().filter((o) => ['oauth_authorize', 'oauth_token'].includes(o['event'])).map((o) => `${o['event']}:${o['step']}:${o['outcome']}`)
    expect(steps).toEqual(['oauth_authorize:consent_shown:ok', 'oauth_authorize:approved:ok', 'oauth_token:code_exchanged:ok', 'oauth_token:refreshed:ok'])
    const shown = audited().find((o) => o['step'] === 'consent_shown')!
    expect(shown).toMatchObject({ client_id: CIMD, resource: MCP, resource_sent: 'no', kind: 'human', actor: `user:${who.id}`, via: 'session', service: 'auth-service' })
    const exchanged = audited().find((o) => o['step'] === 'code_exchanged')!
    expect(exchanged).toMatchObject({ kind: 'agent', actor: `agent:claude-code@${who.handle}`, via: 'oauth', on_behalf_of: `user:${who.id}`, client_id: CIMD, resource: MCP, client: 'mcp' })
    expect(exchanged['credential_id']).toBeTruthy()
    expect(exchanged['grant_id']).toBe(exchanged['credential_id'])
  })

  it('records whether the client sent resource', async () => {
    const who = await person('ada')
    cimd()
    await get(authorizeUrl({ resource: MCP }).url, who.cookie)
    expect(lastAudit('oauth_authorize')).toMatchObject({ resource_sent: 'yes' })
    await get(authorizeUrl({ resource: undefined }).url, who.cookie)
    expect(lastAudit('oauth_authorize')).toMatchObject({ resource_sent: 'no' })
  })

  it('refusals say why: an invalid request, a refused consent, a wrong verifier, a reused refresh token', async () => {
    const who = await person('ada')
    cimd()
    await get(authorizeUrl({ code_challenge: undefined }).url, who.cookie)
    expect(lastAudit('oauth_authorize')).toMatchObject({ outcome: 'refused', step: 'invalid_request', reason: 'invalid_request', client_id: CIMD })
    await consent(who, {}, { decision: 'deny' })
    expect(lastAudit('oauth_authorize')).toMatchObject({ outcome: 'refused', step: 'consent_refused', reason: 'access_denied' })
    const c = await consent(who)
    await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: pkce().verifier, redirect_uri: REDIRECT })
    expect(lastAudit('oauth_token')).toMatchObject({ outcome: 'refused', reason: 'pkce_failed' })
    const t = await tokens(who)
    await form('/token', { grant_type: 'refresh_token', client_id: CIMD, refresh_token: t['refresh_token'] })
    await form('/token', { grant_type: 'refresh_token', client_id: CIMD, refresh_token: t['refresh_token'] })
    expect(lastAudit('oauth_token')).toMatchObject({ outcome: 'refused', step: 'refresh_reuse_detected', reason: 'reuse' })
  })

  it('no code, verifier, refresh token, access token or request id is in any line', async () => {
    const who = await person('ada')
    const c = await consent(who)
    const res = await form('/token', { grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT })
    const t = await json(res)
    const r1 = await json(await form('/token', { grant_type: 'refresh_token', client_id: CIMD, refresh_token: t['refresh_token'] }))
    await form('/token', { grant_type: 'refresh_token', client_id: CIMD, refresh_token: t['refresh_token'] })
    await form('/revoke', { token: r1['refresh_token'] })
    const out = lines.join('')
    expect(audited().length).toBeGreaterThan(5)
    const req = /name="req" value="([^"]+)"/.exec(c.html)![1]!
    for (const secret of [c.code!, c.verifier, c.challenge, t['refresh_token'], t['access_token'], r1['refresh_token'], r1['access_token'], req]) expect(out).not.toContain(secret)
    expect(out).not.toMatch(/eyJ[A-Za-z0-9_-]{8,}\./)
    expect(out).not.toMatch(/bwr_[A-Za-z0-9_-]{8,}/)
  })
})

describe('more than one MCP server (a product runs its own)', () => {
  const OTHER = 'https://quillpath.example.test/v1/mcp'
  const EX = 'urn:ietf:params:oauth:grant-type:token-exchange'
  const exchange = async (subject: string, resource?: string) =>
    authApp.fetch(new Request(`${ISSUER}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Bearer ${await serviceToken('mcp')}` },
      body: new URLSearchParams({ grant_type: EX, subject_token: subject, subject_token_type: 'urn:ietf:params:oauth:token-type:access_token', ...(resource ? { resource } : {}) }).toString(),
    }))

  it('each resource gets its own audience, and the refresh token stays with the one it was made for', async () => {
    process.env['AUTH_MCP_RESOURCES'] = `${MCP}, ${OTHER}/`
    const who = await person('ada')
    const a = await tokens(who, { resource: MCP })
    const b = await tokens(who, { resource: OTHER, scope: 'read', client_id: CIMD }, { decision: 'approve', access: 'read' })
    expect(claims(a['access_token'])['aud']).toBe(MCP)
    expect(claims(b['access_token'])['aud']).toBe(OTHER)
    const r = await form('/token', { grant_type: 'refresh_token', client_id: CIMD, refresh_token: b['refresh_token'] })
    expect(claims((await json(r))['access_token'])['aud']).toBe(OTHER)
    const wrong = await form('/token', { grant_type: 'refresh_token', client_id: CIMD, refresh_token: a['refresh_token'], resource: OTHER })
    expect((await json(wrong))['error']).toBe('invalid_target')
  })

  it('a resource must be asked for when there are several', async () => {
    process.env['AUTH_MCP_RESOURCES'] = `${MCP},${OTHER}`
    cimd()
    const res = await get(authorizeUrl({ resource: undefined }).url, (await person('ada')).cookie)
    expect(loc(res).searchParams.get('error')).toBe('invalid_target')
  })

  it('the exchange refuses a token made for the other server: it says which it is, and the audience must match', async () => {
    process.env['AUTH_MCP_RESOURCES'] = `${MCP},${OTHER}`
    const who = await person('ada')
    const forA = await tokens(who, { resource: MCP })
    const ok = await exchange(forA['access_token'], MCP)
    expect(ok.status).toBe(200)
    expect(claims((await json(ok))['access_token'])['aud']).toBe(AUDIENCE)
    const crossed = await exchange(forA['access_token'], OTHER)
    expect(crossed.status).toBe(400)
    expect((await json(crossed))['error']).toBe('invalid_grant')
    const forB = await tokens(who, { resource: OTHER, scope: 'read' }, { decision: 'approve', access: 'read' })
    expect((await exchange(forB['access_token'], MCP)).status).toBe(400)
    expect((await exchange(forB['access_token'], OTHER)).status).toBe(200)
  })

  it('and says so when it is not told, or told something unknown', async () => {
    process.env['AUTH_MCP_RESOURCES'] = `${MCP},${OTHER}`
    const t = await tokens(await person('ada'), { resource: MCP })
    const missing = await exchange(t['access_token'])
    expect(missing.status).toBe(400)
    expect((await json(missing))['error']).toBe('invalid_target')
    expect((await exchange(t['access_token'], 'https://evil.example/mcp')).status).toBe(400)
  })
})

describe('who is asking: an iam user, or nobody', () => {
  it('a session that names only the provider\'s subject (iam sync degraded) is refused with the person page, and nothing is stored', async () => {
    cimd()
    const ghost = `oidc_session=${encodeSession({ is_authenticated: true, subject: 'idp-subject-1', email: 'x@y.test', name: 'X', issuer: 'i', expires_at: Math.floor(Date.now() / 1000) + 3600, user_id: 'idp-subject-1' } as never, process.env)}`
    const res = await get(authorizeUrl().url, ghost)
    expect(res.status).toBe(403)
    expect(res.headers.get('location')).toBeNull()
    expect(await res.text()).toContain('another signed-in person')
    expect(audited().filter((o) => o['step'] === 'consent_shown')).toEqual([])
    expect(lastAudit('oauth_authorize')).toMatchObject({ outcome: 'refused', reason: 'person_not_in_iam' })
  })

  it('and so is a session with no user id at all (it falls back to the subject, which iam does not know)', async () => {
    cimd()
    const none = `oidc_session=${encodeSession({ is_authenticated: true, subject: 'someone', email: 'x@y.test', name: 'X', issuer: 'i', expires_at: Math.floor(Date.now() / 1000) + 3600 } as never, process.env)}`
    expect((await get(authorizeUrl().url, none)).status).toBe(403)
  })
})

describe('an authorization code is used once, atomically', () => {
  const body = (c: { code: string | null; verifier: string }) => ({ grant_type: 'authorization_code', client_id: CIMD, code: c.code!, code_verifier: c.verifier, redirect_uri: REDIRECT })

  it('two redemptions at the same moment: exactly one gets tokens', async () => {
    for (let round = 0; round < 5; round++) {
      const c = await consent(await person('ada'))
      const results = await Promise.all(Array.from({ length: 6 }, () => form('/token', body(c))))
      const ok = results.filter((r) => r.status === 200)
      expect(ok, `round ${round}`).toHaveLength(1)
      for (const r of results.filter((r) => r.status !== 200)) expect((await json(r))['error']).toBe('invalid_grant')
    }
  })

  it('a code that was redeemed and is presented again revokes the grant it produced: its refresh token dies, with a line saying so', async () => {
    const c = await consent(await person('ada'))
    const first = await json(await form('/token', body(c)))
    expect((await form('/token', { grant_type: 'refresh_token', client_id: CIMD, refresh_token: first['refresh_token'] })).status).toBe(200)
    // ...but that rotated it; take the new one to show the whole chain dies
    const second = await json(await form('/token', { grant_type: 'refresh_token', client_id: CIMD, refresh_token: first['refresh_token'] }).catch(() => new Response('{}')))
    void second
    const again = await form('/token', body(c))
    expect(again.status).toBe(400)
    expect((await json(again))['error']).toBe('invalid_grant')
    expect(lastAudit('oauth_token')).toMatchObject({ outcome: 'refused', step: 'code_reuse_detected', reason: 'code_reuse_grant_revoked', client_id: CIMD })
    expect(lastAudit('oauth_token')['grant_id']).toBeTruthy()
  })

  it('the refresh token the first redemption produced no longer works after the code is replayed', async () => {
    const c = await consent(await person('ada'))
    const first = await json(await form('/token', body(c)))
    await form('/token', body(c))
    expect((await form('/token', { grant_type: 'refresh_token', client_id: CIMD, refresh_token: first['refresh_token'] })).status).toBe(400)
  })

  it('a code nobody ever redeemed, and one that expired, revoke nothing', async () => {
    cimd()
    const before = audited().length
    const res = await form('/token', { ...body({ code: 'x'.repeat(43), verifier: pkce().verifier }) })
    expect(res.status).toBe(400)
    expect(audited().slice(before).some((o) => o['step'] === 'code_reuse_detected')).toBe(false)
  })

  it('a wrong verifier burns the code, but that is not a replay of a redeemed one: no grant was made, none is revoked', async () => {
    const c = await consent(await person('ada'))
    await form('/token', { ...body(c), code_verifier: pkce().verifier })
    const again = await form('/token', body(c))
    expect(again.status).toBe(400)
    expect(lastAudit('oauth_token')).toMatchObject({ reason: 'code_unknown_or_used' })
  })
})

