/**
 * auth-service 2.4.0: names in code are snake_case. The session cookie is
 * storage, not a contract: it is written with the keys it has always had and
 * read in either spelling, so no browser is signed out by this release and a
 * rollback still reads what it wrote.
 */
import { createHmac } from 'node:crypto'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { beforeEach, describe, expect, it } from 'vitest'
import { verifyHs256Jwt } from '@baseworks/auth/jwt'
import { createTestApp, JWT_SECRET, SESSION_COOKIE_NAME } from './setup.js'
import { decodeSession, encodeSession, serializeSession, sessionKey } from '../lib/cookies.js'
import { mintIdentityToken } from '../lib/mint.js'

const env = { JWT_SECRET } as NodeJS.ProcessEnv
const SOON = () => Math.floor(Date.now() / 1000) + 3600

/** A cookie exactly as 2.3 and before wrote it: tagged, camelCase keys. */
function oldCookie(obj: Record<string, unknown>): string {
  const payload = Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url')
  return `${payload}.${createHmac('sha256', sessionKey(env)!).update(payload).digest('base64url')}`
}
const payloadOf = (cookie: string) => JSON.parse(Buffer.from(cookie.split('.')[0]!, 'base64url').toString('utf8')) as Record<string, unknown>

type App = Awaited<ReturnType<typeof createTestApp>>
let app: App
beforeEach(async () => { app = await createTestApp() })

describe('the session cookie', () => {
  const session = { is_authenticated: true, subject: 's', email: 'a@b.c', name: 'Ada', issuer: 'i', expires_at: SOON(), user_id: 'usr_1' }

  it('is written with the keys it has always had, so a rolled-back release reads it', () => {
    expect(payloadOf(encodeSession(session, env))).toEqual({
      isAuthenticated: true, subject: 's', email: 'a@b.c', name: 'Ada', issuer: 'i', expiresAt: session.expires_at, userId: 'usr_1',
    })
    const { user_id: _u, ...without } = session
    expect(Object.keys(payloadOf(encodeSession(without, env)))).not.toContain('userId')
  })

  it('a cookie written before 2.4.0 still decodes, into snake_case', () => {
    const decoded = decodeSession(oldCookie({ isAuthenticated: true, subject: 's', email: 'a@b.c', name: 'Ada', issuer: 'i', expiresAt: session.expires_at, userId: 'usr_1' }), env)
    expect(decoded).toEqual(session)
  })

  it('a cookie in snake_case decodes too, and one without a user id has none', () => {
    expect(decodeSession(oldCookie(session), env)).toEqual(session)
    const { user_id: _u, ...without } = session
    expect(decodeSession(oldCookie({ ...without }), env)).toEqual(without)
    expect(decodeSession(oldCookie({ isAuthenticated: true, subject: 's', email: 'a@b.c', name: 'Ada', issuer: 'i', expiresAt: 1 }), env)).toEqual({ ...without, expires_at: 1 })
  })

  it('both spellings in one cookie: the snake_case value is the one', () => {
    expect(decodeSession(oldCookie({ ...session, userId: 'old', user_id: 'new' }), env)?.user_id).toBe('new')
  })

  it('what is not an object is not a session', () => {
    for (const junk of [null, [], 'x', 5]) expect(decodeSession(oldCookie(junk as never), env)).toBeNull()
  })

  it('an old cookie signs a person in: /api/session answers, /api/token mints for the stored user id', async () => {
    const cookie = oldCookie({ isAuthenticated: true, subject: 'oidc-sub', email: 'a@b.c', name: 'Ada', issuer: 'https://idp', expiresAt: SOON(), userId: 'iam-user-7' })
    const s = await app.get('/api/session', { cookie: `${SESSION_COOKIE_NAME}=${cookie}` })
    expect(s.status).toBe(200)
    expect(await s.json()).toMatchObject({ is_authenticated: true, subject: 'oidc-sub', user_id: 'iam-user-7' })
    const t = await app.get('/api/token', { cookie: `${SESSION_COOKIE_NAME}=${cookie}` })
    expect(t.status).toBe(200)
    expect(verifyHs256Jwt(((await t.json()) as { token: string }).token, JWT_SECRET)?.['sub']).toBe('iam-user-7')
  })

  it('an expired old cookie is refused, as it was', async () => {
    const cookie = oldCookie({ isAuthenticated: true, subject: 's', email: '', name: '', issuer: '', expiresAt: 1, userId: 'u' })
    expect((await app.get('/api/session', { cookie: `${SESSION_COOKIE_NAME}=${cookie}` })).status).toBe(401)
  })

  it('serializeSession is the HTTP body: snake_case, as before', () => {
    expect(serializeSession(session)).toEqual({ is_authenticated: true, subject: 's', email: 'a@b.c', name: 'Ada', issuer: 'i', expires_at: session.expires_at, user_id: 'usr_1' })
  })
})

describe('minting', () => {
  it('takes expires_in_seconds', async () => {
    const token = (await mintIdentityToken({ sub: 'u', type: 'human', expires_in_seconds: 120 }))!
    const claims = verifyHs256Jwt(token, JWT_SECRET)!
    expect((claims.exp ?? 0) - (claims.iat ?? 0)).toBe(120)
    expect(claims.sub).toBe('u')
  })
})

// ── nothing in src still speaks the old names ────────────────────────────────

const here = dirname(fileURLToPath(import.meta.url))
const walk = (dir: string): string[] =>
  readdirSync(dir).flatMap((f) => {
    const p = join(dir, f)
    return statSync(p).isDirectory() ? (f === '__tests__' ? [] : walk(p)) : p.endsWith('.ts') ? [p] : []
  })

describe('the source is snake_case', () => {
  const OLDNAMES = /\.(userId|orgId|tokenType|requestId|realmToken|isAuthenticated|expiresAt|legacySecret|isProd|cookieDomain|returnOrigins|postLogoutUrl)\b|expiresInSeconds/
  it.each(walk(resolve(here, '..')).map((f) => [f.slice(resolve(here, '../..').length + 1), f] as const))('%s', (_n, f) => {
    // The session cookie's stored keys are spelled in lib/cookies.ts, in object literals and in strings: not read as properties.
    const hits = readFileSync(f, 'utf8').split('\n').map((l, i) => [i + 1, l] as const).filter(([, l]) => OLDNAMES.test(l))
    expect(hits).toEqual([])
  })
})
