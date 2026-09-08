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

export function parseSession(c: Context): OidcSession | null {
  const raw = getCookie(c, COOKIE_SESSION)
  if (!raw) return null
  const parsed = decodeSession(raw)
  if (!parsed || !parsed.isAuthenticated) return null
  return parsed
}

/**
 * Session cookie codec: JSON → UTF-8 → base64url.
 *
 * NOT btoa()/atob(): those are Latin-1 only and throw InvalidCharacterError on any
 * code point above U+00FF. The session carries the IdP's display name, so a user
 * called "İsmail" (U+0130) got a 500 on /oidc/callback while everyone with an ASCII
 * name logged in fine (prod, 2026-09-08). Buffer with 'base64url' is UTF-8 safe and
 * already strips padding; ASCII payloads encode to the identical string, so cookies
 * issued by the old code keep working.
 */
export function encodeSession(session: OidcSession): string {
  return Buffer.from(JSON.stringify(session), 'utf8').toString('base64url')
}

export function decodeSession(raw: string): OidcSession | null {
  try {
    return JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')) as OidcSession
  } catch {
    return null
  }
}
