import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestApp, makeSessionCookie, SESSION_COOKIE_NAME } from './setup.js'
import { sessionKey } from '../lib/cookies.js'

type App = Awaited<ReturnType<typeof createTestApp>>
let app: App

const saved = { ...process.env }
beforeEach(async () => {
  process.env['APP_PUBLIC_URL'] = 'http://localhost:8080'
  process.env['AUTH_RETURN_ORIGINS'] = 'http://doubletap.localhost:8080'
  process.env['OIDC_ISSUER'] = 'https://idp.test'
  process.env['OIDC_CLIENT_ID'] = 'client'
  app = await createTestApp()
})
afterEach(() => { process.env = { ...saved } })

/** The value /login stored for the callback to return to. */
function storedReturn(res: Response): string | undefined {
  const line = res.headers.getSetCookie().find((c) => c.startsWith('oidc_return_to='))
  return line ? decodeURIComponent(line.split(';')[0]!.slice('oidc_return_to='.length)) : undefined
}

describe('starting a sign-in remembers where the person was going', () => {
  it('reads ?returnTo=, the name the console, doubletap and openapi.yaml use', async () => {
    const res = await app.get('/ui/login/sso?returnTo=%2Fentries')
    expect(res.status).toBe(302)
    expect(storedReturn(res)).toBe('/entries')
  })

  it('keeps an absolute return to another surface this realm publishes', async () => {
    const res = await app.get(`/ui/login/sso?returnTo=${encodeURIComponent('http://doubletap.localhost:8080/bank')}`)
    expect(storedReturn(res)).toBe('http://doubletap.localhost:8080/bank')
  })

  it('still reads ?redirectTo= for links written against the old name', async () => {
    expect(storedReturn(await app.get('/ui/login/sso?redirectTo=%2Freports'))).toBe('/reports')
  })

  it('stores `/` for an origin the realm does not publish', async () => {
    expect(storedReturn(await app.get(`/ui/login/sso?returnTo=${encodeURIComponent('https://evil.example')}`))).toBe('/')
  })
})

describe('logout', () => {
  it('GET /logout returns to the page asked for, and nowhere else', async () => {
    const ok = await app.get('/ui/logout?returnTo=%2Flogin')
    expect(ok.status).toBe(302)
    expect(ok.headers.get('location')).toBe('/login')

    const evil = await app.get(`/ui/logout?returnTo=${encodeURIComponent('https://evil.example')}`)
    expect(evil.headers.get('location')).toBe('/')
  })

  it('POST /logout answers a fetch() with 204 and the cookies cleared', async () => {
    const res = await app.post('/api/logout', {})
    expect(res.status).toBe(204)
    const cleared = res.headers.getSetCookie()
    for (const name of [SESSION_COOKIE_NAME, 'oidc_token']) {
      expect(cleared.some((c) => c.startsWith(`${name}=;`) && c.includes('Max-Age=0'))).toBe(true)
    }
  })
})

describe('a session is only as long as the expiry signed inside it', () => {
  it('an expired session cookie is not a session, even with a valid tag', async () => {
    const expired = makeSessionCookie({
      isAuthenticated: true, subject: 's', userId: 'usr_1', email: 'a@b.test', name: 'A', issuer: 'i',
      expiresAt: Math.floor(Date.now() / 1000) - 1,
    })
    expect((await app.get('/api/session', { cookie: `${SESSION_COOKIE_NAME}=${expired}` })).status).toBe(401)
    expect((await app.get('/api/token', { cookie: `${SESSION_COOKIE_NAME}=${expired}` })).status).toBe(401)
  })
})

describe('the session key', () => {
  it('treats a variable left empty as unset, not as the key', () => {
    const withKey = sessionKey({ JWT_SECRET: '', AUTH_SIGNING_KEY: 'pem' } as NodeJS.ProcessEnv)
    expect(withKey).toEqual(sessionKey({ AUTH_SIGNING_KEY: 'pem' } as NodeJS.ProcessEnv))
    expect(sessionKey({ JWT_SECRET: '' } as NodeJS.ProcessEnv)).toBeNull()
  })
})
