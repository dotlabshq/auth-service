import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestApp } from './setup.js'
import { parseIdps, idpScopes } from '../lib/idps.js'

type App = Awaited<ReturnType<typeof createTestApp>>
let app: App

const saved = { ...process.env }
beforeEach(async () => {
  process.env['OIDC_ISSUER'] = 'https://idp.test'
  process.env['OIDC_CLIENT_ID'] = 'client'
  process.env['OIDC_IDPS'] = 'google:111, GitHub:222'
  app = await createTestApp()
})
afterEach(() => { process.env = { ...saved } })

/** The authorize request /login sent the browser to. */
function authorize(res: Response): URL {
  return new URL(res.headers.get('location') ?? '')
}
const scopes = (u: URL) => (u.searchParams.get('scope') ?? '').split(' ')
const cookie = (res: Response, name: string) => res.headers.getSetCookie().some((c) => c.startsWith(`${name}=`) && !c.includes('Max-Age=0;'))

describe('sign in straight with a named IdP', () => {
  it('asks the provider to hand over to that IdP, past its own screens', async () => {
    const res = await app.get('/login/google?returnTo=%2Fentries')
    expect(res.status).toBe(302)
    const u = authorize(res)
    expect(u.origin + u.pathname).toBe('https://idp.test/oauth/v2/authorize')
    expect(scopes(u)).toContain('urn:zitadel:iam:org:idp:id:111')
    expect(scopes(u)).toContain('openid')
    // The IdP shows its own account chooser; asking the provider for one too
    // would put its screen back in front of the person.
    expect(u.searchParams.has('prompt')).toBe(false)
  })

  it('comes back through the same callback, with the same PKCE and return cookies', async () => {
    const res = await app.get('/login/github?returnTo=%2Fentries')
    const u = authorize(res)
    expect(u.searchParams.get('redirect_uri')).toBe('http://localhost/auth/oidc/callback')
    expect(u.searchParams.get('code_challenge_method')).toBe('S256')
    expect(scopes(u)).toContain('urn:zitadel:iam:org:idp:id:222')
    expect(cookie(res, 'oidc_pkce_verifier')).toBe(true)
    expect(cookie(res, 'oidc_return_to')).toBe(true)
  })

  it('still refuses a return address the realm does not publish', async () => {
    const res = await app.get(`/login/google?returnTo=${encodeURIComponent('https://evil.example')}`)
    const line = res.headers.getSetCookie().find((c) => c.startsWith('oidc_return_to='))!
    expect(decodeURIComponent(line.split(';')[0]!.slice('oidc_return_to='.length))).toBe('/')
  })

  it('pins the organization whose login settings apply, when one is configured', async () => {
    process.env['OIDC_ORG_ID'] = '999'
    expect(scopes(authorize(await app.get('/login/google')))).toContain('urn:zitadel:iam:org:id:999')
  })

  it('answers 404 for a name nobody configured, instead of the provider screen', async () => {
    const res = await app.get('/login/myspace')
    expect(res.status).toBe(404)
    expect(await res.json()).toMatchObject({ error: 'unknown_idp' })
  })

  it('keeps the provider\'s own sign-in beside them: the picker, no IdP hint', async () => {
    const u = authorize(await app.get('/login/sso'))
    expect(u.searchParams.get('prompt')).toBe('select_account')
    expect(scopes(u).some((s) => s.startsWith('urn:zitadel:iam:org:idp:id:'))).toBe(false)
  })
})

describe('GET /idps', () => {
  it('lists the names a login page can offer, never the provider ids', async () => {
    const res = await app.get('/api/idps')
    expect(res.status).toBe(200)
    const body = await res.json() as { idps: string[] }
    expect(body).toEqual({ idps: ['google', 'github'] })
    expect(JSON.stringify(body)).not.toContain('111')
  })

  it('is empty when none are configured', async () => {
    delete process.env['OIDC_IDPS']
    expect(await (await app.get('/api/idps')).json()).toEqual({ idps: [] })
  })
})

describe('dev mode', () => {
  it('lands every IdP button on the dev form: a laptop realm has no provider', async () => {
    const dev = await createTestApp({ dev: { username: 'admin', password: 'pw', generated: false } })
    const res = await dev.get('/login/google?returnTo=%2Fentries')
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe('http://localhost/auth/login?returnTo=%2Fentries')
  })
})

describe('OIDC_IDPS', () => {
  it('reads name:id pairs, case-insensitive names, and drops what it cannot read', () => {
    expect([...parseIdps(' google:1 ,Apple:2,broken,:3,bad name:4,github:')]).toEqual([['google', '1'], ['apple', '2']])
    expect(parseIdps(undefined).size).toBe(0)
  })

  it('adds the org scope only when there is an org', () => {
    expect(idpScopes('1')).toEqual(['urn:zitadel:iam:org:idp:id:1'])
    expect(idpScopes('1', '9')).toEqual(['urn:zitadel:iam:org:idp:id:1', 'urn:zitadel:iam:org:id:9'])
  })
})
