import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestApp, SESSION_COOKIE_NAME } from './setup.js'
import { DEV_ISSUER, devCredentialsMatch, devLogin, type DevLogin } from '../lib/dev.js'
import { cliApprovePage } from '../pages/cli.js'

const saved = { ...process.env }
afterEach(() => { process.env = { ...saved } })

describe('whether dev mode is on', () => {
  it('is off unless asked for', () => {
    expect(devLogin({} as NodeJS.ProcessEnv)).toBeNull()
    expect(devLogin({ AUTH_DEV_MODE: '0' } as NodeJS.ProcessEnv)).toBeNull()
  })

  it('refuses to exist under NODE_ENV=production', () => {
    expect(() => devLogin({ AUTH_DEV_MODE: '1', NODE_ENV: 'production' } as NodeJS.ProcessEnv)).toThrow(/production/)
  })

  it('is admin with a password made up at boot, unless one is fixed', () => {
    const a = devLogin({ AUTH_DEV_MODE: '1' } as NodeJS.ProcessEnv)!
    const b = devLogin({ AUTH_DEV_MODE: '1' } as NodeJS.ProcessEnv)!
    expect(a.username).toBe('admin')
    expect(a.generated).toBe(true)
    expect(a.password.length).toBeGreaterThanOrEqual(16)
    expect(a.password).not.toBe(b.password)

    const fixed = devLogin({ AUTH_DEV_MODE: 'true', AUTH_DEV_PASSWORD: 'pw', AUTH_DEV_USER: 'ada' } as NodeJS.ProcessEnv)!
    expect(fixed).toEqual({ username: 'ada', password: 'pw', generated: false })
  })

  it('matches only the exact pair', () => {
    const dev: DevLogin = { username: 'admin', password: 'secret', generated: false }
    expect(devCredentialsMatch(dev, 'admin', 'secret')).toBe(true)
    expect(devCredentialsMatch(dev, 'admin', 'secre')).toBe(false)
    expect(devCredentialsMatch(dev, 'root', 'secret')).toBe(false)
    expect(devCredentialsMatch(dev, 'admin', '')).toBe(false)
  })
})

describe('signing in with the dev account', () => {
  const dev: DevLogin = { username: 'admin', password: 'correct horse', generated: false }
  let app: Awaited<ReturnType<typeof createTestApp>>
  beforeEach(async () => { app = await createTestApp({ dev }) })

  const form = (f: Record<string, string>) => new URLSearchParams(f).toString()
  const cookieFrom = (res: Response) =>
    res.headers.getSetCookie().map((c) => c.split(';')[0]!).filter((c) => !c.endsWith('=')).join('; ')

  it('GET /login is a form, not a trip to the identity provider', async () => {
    const res = await app.get('/login?returnTo=%2Fentries')
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toContain('name="password"')
    expect(html).toContain('value="/entries"')
  })

  it('the right pair signs in for real: a session, a token, and back to where it was going', async () => {
    const res = await app.postForm('/login', form({ username: 'admin', password: 'correct horse', returnTo: '/entries' }))
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe('/entries')

    const cookie = cookieFrom(res)
    expect(cookie).toContain(`${SESSION_COOKIE_NAME}=`)
    expect(cookie).toContain('oidc_token=')

    const session = await (await app.get('/api/session', { cookie })).json() as Record<string, unknown>
    expect(session).toMatchObject({ is_authenticated: true, subject: 'admin', issuer: DEV_ISSUER, user_id: 'admin' })

    const token = await app.get('/api/token', { cookie })
    expect(token.status).toBe(200)
  })

  it('a dev session approves a waiting CLI like any other', async () => {
    const signedIn = await app.postForm('/login', form({ username: 'admin', password: 'correct horse' }))
    const { state } = await (await app.get('/api/start')).json() as { state: string }
    const res = await app.post('/api/approve', { state }, { cookie: cookieFrom(signedIn) })
    expect(res.status).toBe(200)
    expect(((await (await app.get(`/api/poll/${state}`)).json()) as { status: string }).status).toBe('done')
  })

  it('a wrong pair gets the form again, and no cookie', async () => {
    const res = await app.postForm('/login', form({ username: 'admin', password: 'wrong', returnTo: '/entries' }))
    expect(res.status).toBe(401)
    expect(res.headers.getSetCookie()).toEqual([])
    expect(await res.text()).toContain('do not match')
  })

  it('the return address is checked on the way out too', async () => {
    const res = await app.postForm('/login', form({ username: 'admin', password: 'correct horse', returnTo: 'https://evil.example' }))
    expect(res.headers.get('location')).toBe('/')
  })

  it('the OIDC callback is not a door into a dev realm', async () => {
    expect((await app.get('/oidc/callback?code=x')).status).toBe(404)
  })
})

describe('outside dev mode', () => {
  it('POST /login does not exist', async () => {
    const app = await createTestApp()
    const res = await app.postForm('/login', 'username=admin&password=anything')
    expect(res.status).toBe(404)
  })
})

describe('the approval page', () => {
  it('echoes the state it was given as text, never as markup', () => {
    const html = cliApprovePage({ state: '"><script>alert(1)</script>', who: '<b>ada</b>' })
    expect(html).not.toContain('<script>alert(1)')
    expect(html).toContain('&quot;&gt;&lt;script&gt;')
    expect(html).toContain('&lt;b&gt;ada&lt;/b&gt;')
  })
})
