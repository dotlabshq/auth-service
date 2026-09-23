import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import type { Context } from 'hono'
import { getCookie } from 'hono/cookie'

export const COOKIE_ID_TOKEN    = 'oidc_id_token'
export const COOKIE_SESSION     = 'oidc_session'
export const COOKIE_ACCESS      = 'oidc_access_token'
export const COOKIE_REFRESH     = 'oidc_refresh_token'
export const COOKIE_PKCE        = 'oidc_pkce_verifier'
export const COOKIE_RETURN_TO   = 'oidc_return_to'
export const COOKIE_PLATFORM_JWT = 'platform_jwt'

export const ALL_OIDC_COOKIES = [
  COOKIE_ID_TOKEN, COOKIE_SESSION, COOKIE_ACCESS, COOKIE_REFRESH,
]

export function cookieOpts(isProd: boolean, domain?: string) {
  const base = `HttpOnly; Path=/; SameSite=Lax${isProd ? '; Secure' : ''}`
  return domain ? `${base}; Domain=${domain}` : base
}

export function getIdToken(c: Context): string | undefined {
  return getCookie(c, COOKIE_ID_TOKEN)
}

export interface OidcSession {
  isAuthenticated: boolean
  subject: string
  email: string
  name: string
  issuer: string
  expiresAt: number
  /**
   * Resolved platform identity — the IAM user id in IAM mode, or the OIDC
   * subject in login-only mode. Stored here so `/token` and CLI `/approve` mint
   * JWTs without a database round-trip. auth carries NO org — a user has only
   * memberships, resolved by org-service when an app needs org context.
   */
  userId?: string
}

/**
 * The session as an HTTP body: `snake_case`, per ADR-043.
 *
 * The cookie itself keeps its own shape on purpose. It is storage, not a
 * contract, and renaming its keys would invalidate every session cookie already
 * in a browser — signing everyone out to tidy up a field name.
 */
export function serializeSession(s: OidcSession): Record<string, unknown> {
  return {
    is_authenticated: s.isAuthenticated,
    subject: s.subject,
    email: s.email,
    name: s.name,
    issuer: s.issuer,
    expires_at: s.expiresAt,
    ...(s.userId ? { user_id: s.userId } : {}),
  }
}

export function parseSession(c: Context): OidcSession | null {
  const raw = getCookie(c, COOKIE_SESSION)
  if (!raw) return null
  const parsed = decodeSession(raw)
  if (!parsed || !parsed.isAuthenticated) return null
  // The cookie's own Expires is advice to the browser; a client can keep
  // sending it. The signed expiry inside is the one that counts.
  if (!(parsed.expiresAt > Math.floor(Date.now() / 1000))) return null
  return parsed
}

/**
 * Session cookie codec: JSON → UTF-8 → base64url, then an HMAC tag.
 *
 * The tag is not decoration. `/token` and `/approve` mint a realm identity
 * token for whoever this cookie says you are, so an unauthenticated cookie is
 * an unauthenticated way to become any user: HttpOnly stops a script reading
 * it, and stops nothing at all about a request built by hand with the value an
 * attacker chose. Before the tag existed, a base64 blob naming any user id was
 * a valid session everywhere in the realm.
 *
 * NOT btoa()/atob(): those are Latin-1 only and throw InvalidCharacterError on any
 * code point above U+00FF. The session carries the IdP's display name, so a user
 * called "İsmail" (U+0130) got a 500 on /oidc/callback while everyone with an ASCII
 * name logged in fine (prod, 2026-09-08). Buffer with 'base64url' is UTF-8 safe and
 * already strips padding.
 *
 * Cookies issued before the tag are refused, so a realm that takes this change
 * signs everyone out once. That is the correct outcome: a session that cannot be
 * told apart from a forged one was never a session.
 */

/**
 * The key the session tag is computed with, derived from whatever the realm
 * already has. Derived rather than used directly, so the value that signs a
 * cookie is not byte-identical to the one that signs a token.
 *
 *   AUTH_SESSION_SECRET  when the cookie should have a key of its own
 *   JWT_SECRET           the legacy shared realm secret
 *   AUTH_SIGNING_KEY     an ES256-only realm, which has no shared secret at all
 *
 * Null means the realm can sign nothing — the same state in which it cannot
 * mint a token either, so browser sign-in is not available regardless.
 */
export function sessionKey(env: NodeJS.ProcessEnv = process.env): Buffer | null {
  // `||`, not `??`: a variable left empty in a .env file (`JWT_SECRET=`) is
  // unset, not a key. With `??` it shadowed AUTH_SIGNING_KEY and every
  // callback failed to sign its cookie. realm.ts reads it the same way.
  const material = env['AUTH_SESSION_SECRET'] || env['JWT_SECRET'] || env['AUTH_SIGNING_KEY']
  if (!material) return null
  return createHash('sha256').update(`baseworks.session\u0000${material}`).digest()
}

function tag(payload: string, key: Buffer): string {
  return createHmac('sha256', key).update(payload).digest('base64url')
}

export function encodeSession(session: OidcSession, env: NodeJS.ProcessEnv = process.env): string {
  const key = sessionKey(env)
  // A deployment with no key must fail loudly here rather than hand out a
  // cookie that nothing can verify.
  if (!key) throw new Error('cannot sign a session: set AUTH_SESSION_SECRET, JWT_SECRET or AUTH_SIGNING_KEY')
  const payload = Buffer.from(JSON.stringify(session), 'utf8').toString('base64url')
  return `${payload}.${tag(payload, key)}`
}

export function decodeSession(raw: string, env: NodeJS.ProcessEnv = process.env): OidcSession | null {
  const key = sessionKey(env)
  if (!key) return null

  const dot = raw.lastIndexOf('.')
  if (dot <= 0) return null                       // no tag: issued before this, or forged
  const payload = raw.slice(0, dot)
  const given = Buffer.from(raw.slice(dot + 1), 'base64url')
  const want = Buffer.from(tag(payload, key), 'base64url')
  // Compare in constant time, and only after the lengths match — timingSafeEqual
  // throws on a length mismatch, which would itself leak the length.
  if (given.length !== want.length || !timingSafeEqual(given, want)) return null

  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as OidcSession
  } catch {
    return null
  }
}
