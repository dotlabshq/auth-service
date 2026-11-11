import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestApp, makeSessionCookie, SESSION_COOKIE_NAME } from './setup.js'
import { brand } from '../lib/brand.js'
import { publicUrls } from '../lib/urls.js'

/**
 * The rule these tests state: pages live under `/ui`, the API lives under
 * `/api`, neither is reachable through the other's mount, and the root is not
 * a surface at all. A gateway publishes `/ui` at `/auth` and `/api` at
 * `/v1/auth`; the service learns those two addresses from configuration and
 * writes them nowhere in its code.
 */

type App = Awaited<ReturnType<typeof createTestApp>>
let app: App

const saved = { ...process.env }
beforeEach(async () => {
  process.env['OIDC_ISSUER'] = 'https://idp.test'
  process.env['OIDC_CLIENT_ID'] = 'client'
  app = await createTestApp()
})
afterEach(() => { process.env = { ...saved } })

const session = () => `${SESSION_COOKIE_NAME}=${makeSessionCookie({
  isAuthenticated: true, subject: 'sub-1', userId: 'usr_1', email: 'ada@example.test', name: 'Ada', issuer: 'https://idp.test',
  expiresAt: Math.floor(Date.now() / 1000) + 3600,
})}`
const location = (res: Response) => res.headers.get('location')

describe('two surfaces and a closed root, one process', () => {
  it('answers the API only under /api', async () => {
    for (const path of ['/session', '/token', '/start', '/idps', '/poll/abc', '/.well-known/jwks.json', '/.well-known/service', '/openapi.yaml']) {
      expect((await app.get(path)).status, `root ${path}`).toBe(404)
      expect((await app.get(`/api${path}`)).status, `/api${path}`).not.toBe(404)
    }
    expect((await app.post('/service-token', {})).status).toBe(404)
    expect((await app.post('/exchange', {})).status).toBe(404)
    expect((await app.post('/approve', {})).status).toBe(404)
  })

  it('draws pages only under /ui', async () => {
    expect((await app.get('/ui/cli/done')).status).toBe(200)
    expect((await app.get('/api/cli/done')).status).toBe(404)
    expect((await app.get('/api/cli?state=' + 'a'.repeat(32))).status).toBe(404)
  })

  it('publishes nothing at the root: a gateway that strips a prefix to / reaches no page and no API', async () => {
    for (const path of ['/login', '/login/sso', '/oidc/callback', '/logout', '/cli', '/cli/done', '/']) {
      expect((await app.get(path)).status, `root ${path}`).toBe(404)
    }
  })

  it('keeps /healthz at the root, for the platform and the internal network only', async () => {
    const res = await app.get('/healthz')
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ ok: true, service: 'auth-service' })
    // Neither published mount carries it, so no gateway rule can expose it.
    expect((await app.get('/ui/healthz')).status).toBe(404)
    expect((await app.get('/api/healthz')).status).toBe(404)
  })
})

describe('GET /login is the sign-in page', () => {
  it('is a page, not a trip to the provider: nothing is started until a button is pressed', async () => {
    const res = await app.get('/ui/login?returnTo=%2Fentries')
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('text/html')
    expect(res.headers.getSetCookie()).toEqual([])
    const html = await res.text()
    expect(html).toContain('href="http://localhost/auth/login/sso?returnTo=%2Fentries"')
    expect(html).toContain('Continue')
  })

  it('offers a button per configured IdP, and the provider\'s own sign-in beside them', async () => {
    process.env['OIDC_IDPS'] = 'google:idp-id-google,okta:idp-id-okta'
    const html = await (await app.get('/ui/login?returnTo=%2Fentries')).text()
    expect(html).toContain('href="http://localhost/auth/login/google?returnTo=%2Fentries"')
    expect(html).toContain('Continue with Google')
    // A name the page has no mark for still gets its button.
    expect(html).toContain('href="http://localhost/auth/login/okta?returnTo=%2Fentries"')
    expect(html).toContain('Continue with Okta')
    expect(html).toContain('Other sign-in options')
    // Names only. The provider's ids are configuration, not something to publish.
    expect(html).not.toContain('idp-id-')
  })

  it('sends someone already signed in straight to where they were going', async () => {
    const res = await app.get('/ui/login?returnTo=%2Fentries', { cookie: session() })
    expect(res.status).toBe(302)
    expect(location(res)).toBe('/entries')
  })

  it('carries only a return address the realm publishes', async () => {
    const html = await (await app.get(`/ui/login?returnTo=${encodeURIComponent('https://evil.example')}`)).text()
    expect(html).not.toContain('evil.example')
    expect(html).toContain('/auth/login/sso?returnTo=%2F"')
  })

  it('says what went wrong in its own words, and never echoes the code', async () => {
    const denied = await (await app.get('/ui/login?error=oidc_denied')).text()
    expect(denied).toContain('cancelled or refused')

    const odd = await (await app.get(`/ui/login?error=${encodeURIComponent('<script>alert(1)</script>')}`)).text()
    expect(odd).not.toContain('<script>')
    expect(odd).not.toContain('alert(1)')
    expect(odd).toContain('Something went wrong')
  })

  it('cannot be framed, runs no script and is not cached', async () => {
    const res = await app.get('/ui/login')
    const csp = res.headers.get('content-security-policy') ?? ''
    expect(csp).toContain("frame-ancestors 'none'")
    expect(csp).toContain("default-src 'none'")
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(await res.text()).not.toContain('<script')
  })

  it('wears the product\'s name, and drops a link that is not one', async () => {
    process.env['AUTH_UI_NAME'] = 'clave <one>'
    process.env['AUTH_UI_TERMS_URL'] = '/terms'
    process.env['AUTH_UI_PRIVACY_URL'] = 'javascript:alert(1)'
    const html = await (await app.get('/ui/login')).text()
    expect(html).toContain('Sign in to clave &lt;one&gt;')
    expect(html).toContain('href="/terms"')
    expect(html).not.toContain('javascript:')
    expect(html).not.toContain('Privacy Policy')
  })
})

describe('the pages speak the person\'s language and wear their theme', () => {
  it('is Turkish when the product says so, and remembers it for the pages that follow', async () => {
    const res = await app.get('/ui/login?lang=tr&error=oidc_denied')
    const html = await res.text()
    expect(html).toContain('<html lang="tr"')
    expect(html).toContain('Giriş yap')
    expect(html).toContain('iptal edildi')
    // A sign-in leaves for the provider and comes back; the cookie is what is
    // still there afterwards.
    expect(res.headers.getSetCookie().some((c) => c.startsWith('bw_lang=tr;'))).toBe(true)

    const next = await (await app.get('/ui/cli/done', { cookie: 'bw_lang=tr' })).text()
    expect(next).toContain('İzin verildi')
  })

  it('falls back to the browser\'s language, then to English, and ignores one it does not have', async () => {
    const tr = await app.fetch(new Request('http://localhost/ui/login', { headers: { 'accept-language': 'tr-TR,tr;q=0.9,en;q=0.8' } }))
    expect(await tr.text()).toContain('<html lang="tr"')
    expect(await (await app.get('/ui/login')).text()).toContain('<html lang="en"')

    const odd = await app.get('/ui/login?lang=xx')
    expect(await odd.text()).toContain('<html lang="en"')
    expect(odd.headers.getSetCookie()).toEqual([])
  })

  it('follows the system theme unless told otherwise', async () => {
    expect(await (await app.get('/ui/login')).text()).toContain('<html lang="en">')
    const dark = await app.get('/ui/login?theme=dark')
    expect(await dark.text()).toContain('<html lang="en" data-theme="dark"')
    expect(dark.headers.getSetCookie().some((c) => c.startsWith('bw_theme=dark;'))).toBe(true)
  })

  it('takes the realm\'s branding, and this service\'s own where it is set', async () => {
    process.env['REALM_UI_NAME'] = 'quillpath'
    expect(await (await app.get('/ui/login')).text()).toContain('Sign in to quillpath')
    process.env['AUTH_UI_NAME'] = 'clave'
    expect(await (await app.get('/ui/login')).text()).toContain('Sign in to clave')
  })
})

describe('a failed sign-in comes back to the page', () => {
  it('with the reason, and still knowing where the person was headed', async () => {
    const res = await app.get('/ui/oidc/callback?error=access_denied', { cookie: 'oidc_return_to=%2Fentries' })
    expect(res.status).toBe(302)
    expect(location(res)).toBe('http://localhost/auth/login?returnTo=%2Fentries&error=oidc_denied')
  })

  it('whichever mount the provider came back through', async () => {
    // A realm whose OIDC app still lists the pre-2.0 redirect URI.
    const res = await app.get('/api/oidc/callback?code=x')
    expect(location(res)).toBe('http://localhost/auth/login?error=missing_verifier')
  })
})

describe('addresses from before 2.0 still work, under /api', () => {
  it('GET /api/login starts a sign-in, as /v1/auth/login always did', async () => {
    const res = await app.get('/api/login?returnTo=%2Fentries')
    expect(res.status).toBe(302)
    const u = new URL(location(res)!)
    expect(u.origin + u.pathname).toBe('https://idp.test/oauth/v2/authorize')
    expect(u.searchParams.get('prompt')).toBe('select_account')
    expect(u.searchParams.get('redirect_uri')).toBe('http://localhost/auth/oidc/callback')
  })

  it('GET /api/login/:idp goes straight to that IdP', async () => {
    process.env['OIDC_IDPS'] = 'google:111'
    const u = new URL(location(await app.get('/api/login/google'))!)
    expect(u.searchParams.get('scope')).toContain('urn:zitadel:iam:org:idp:id:111')
  })

  it('GET /api/logout signs out by navigation', async () => {
    const res = await app.get('/api/logout?returnTo=%2Flogin')
    expect(res.status).toBe(302)
    expect(location(res)).toBe('/login')
    expect(res.headers.getSetCookie().some((c) => c.startsWith(`${SESSION_COOKIE_NAME}=;`))).toBe(true)
  })

  it('a link an older CLI printed reaches the approve page', async () => {
    const state = 'a'.repeat(32)
    expect(location(await app.get(`/api/token?state=${state}`))).toBe(`http://localhost/auth/cli?state=${state}`)
    expect(location(await app.get('/api/token/done'))).toBe('http://localhost/auth/cli/done')
  })

  it('in dev mode they land on the form, which is the only way in', async () => {
    const dev = await createTestApp({ dev: { username: 'admin', password: 'pw', generated: false } })
    expect(location(await dev.get('/api/login?returnTo=%2Fentries'))).toBe('http://localhost/auth/login?returnTo=%2Fentries')
    const form = await (await dev.get('/ui/login?returnTo=%2Fentries')).text()
    expect(form).toContain('action="http://localhost/auth/login"')
  })
})

describe('approving a terminal, on the page', () => {
  const start = async () => (await (await app.get('/api/start')).json()) as { state: string; url: string }
  const poll = async (state: string) => ((await (await app.get(`/api/poll/${state}`)).json()) as { status: string }).status

  it('the CLI is handed the page\'s address', async () => {
    const { state, url } = await start()
    expect(url).toBe(`http://localhost/auth/cli?state=${state}`)
  })

  it('signs the person in first, then brings them back to the same request', async () => {
    const { state } = await start()
    const res = await app.get(`/ui/cli?state=${state}`)
    expect(res.status).toBe(302)
    expect(location(res)).toBe(`http://localhost/auth/login?returnTo=${encodeURIComponent(`/auth/cli?state=${state}`)}`)
  })

  it('says who is approving, and the button hands the waiting CLI its token', async () => {
    const { state } = await start()
    const page = await app.get(`/ui/cli?state=${state}`, { cookie: session() })
    expect(page.status).toBe(200)
    const html = await page.text()
    expect(html).toContain('ada@example.test')
    expect(html).toContain('action="http://localhost/auth/cli/approve"')

    const res = await app.postForm('/ui/cli/approve', `state=${state}`, { cookie: session() })
    expect(res.status).toBe(302)
    expect(location(res)).toBe('http://localhost/auth/cli/done')
    expect(await poll(state)).toBe('done')
  })

  it('does not approve without a session', async () => {
    const { state } = await start()
    const res = await app.postForm('/ui/cli/approve', `state=${state}`)
    expect(res.status).toBe(302)
    expect(location(res)).toContain('/auth/login?returnTo=')
    expect(await poll(state)).toBe('pending')
  })

  it('offers no button for a request that is gone, used, or not one of ours', async () => {
    const unknown = await app.get(`/ui/cli?state=${'b'.repeat(32)}`, { cookie: session() })
    expect(unknown.status).toBe(404)
    expect(await unknown.text()).not.toContain('<form')

    const { state } = await start()
    await app.postForm('/ui/cli/approve', `state=${state}`, { cookie: session() })
    const again = await app.get(`/ui/cli?state=${state}`, { cookie: session() })
    expect(again.status).toBe(409)
    expect(await again.text()).toContain('already approved')

    const odd = await app.get(`/ui/cli?state=${encodeURIComponent('"><script>')}`, { cookie: session() })
    expect(odd.status).toBe(400)
    expect(await odd.text()).not.toContain('<script>')
  })
})

describe('where the service is published is configuration', () => {
  it('defaults to the realm\'s layout: pages at /auth, the API at /v1/auth', () => {
    const u = publicUrls({ APP_PUBLIC_URL: 'https://example.com/' })
    expect(u.ui('/login')).toBe('https://example.com/auth/login')
    expect(u.api('/token')).toBe('https://example.com/v1/auth/token')
    expect(u.uiPath('/cli')).toBe('/auth/cli')
    expect(u.callback).toBe('https://example.com/auth/oidc/callback')
  })

  it('follows the gateway when it publishes somewhere else', () => {
    const u = publicUrls({ APP_PUBLIC_URL: 'https://example.com', AUTH_UI_PATH: 'id/', AUTH_API_PATH: '/v2/auth' })
    expect(u.ui('/login')).toBe('https://example.com/id/login')
    expect(u.api('/token')).toBe('https://example.com/v2/auth/token')
  })

  it('is the service\'s own layout when it runs alone on a port', () => {
    const u = publicUrls({ APP_PUBLIC_URL: 'http://localhost:3003', AUTH_UI_PATH: '/ui', AUTH_API_PATH: '/api' })
    expect(u.ui('/login')).toBe('http://localhost:3003/ui/login')
    expect(u.api('/token')).toBe('http://localhost:3003/api/token')
  })

  it('is root-relative with no origin configured', () => {
    expect(publicUrls({}).ui('/login')).toBe('/auth/login')
  })

  it('pins the redirect URI for a realm that has not registered the new one yet', async () => {
    const pinned = 'https://example.com/v1/auth/oidc/callback'
    expect(publicUrls({ APP_PUBLIC_URL: 'https://example.com', OIDC_REDIRECT_URI: pinned }).callback).toBe(pinned)

    process.env['OIDC_REDIRECT_URI'] = pinned
    const u = new URL(location(await app.get('/ui/login/sso'))!)
    expect(u.searchParams.get('redirect_uri')).toBe(pinned)
  })
})

describe('what the pages look like is configuration too', () => {
  it('reads a name, links and an accent, and drops what it cannot trust', () => {
    expect(brand({})).toEqual({ name: '', logoUrl: undefined, homeUrl: '/', termsUrl: undefined, privacyUrl: undefined, accent: undefined })
    const b = brand({
      AUTH_UI_NAME: ' clave ', AUTH_UI_LOGO_URL: 'https://cdn.example/logo.svg', AUTH_UI_HOME_URL: '//evil.example',
      AUTH_UI_TERMS_URL: 'data:text/html,x', AUTH_UI_ACCENT: 'red; background: url(x)',
    })
    expect(b.name).toBe('clave')
    expect(b.logoUrl).toBe('https://cdn.example/logo.svg')
    expect(b.homeUrl).toBe('/')
    expect(b.termsUrl).toBeUndefined()
    expect(b.accent).toBeUndefined()
    expect(brand({ AUTH_UI_ACCENT: '#0a7' }).accent).toBe('#0a7')
  })
})
