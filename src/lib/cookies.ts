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
   * JWTs without a database round-trip.
   */
  userId?: string
  /** Resolved org id, when known (IAM mode with an org). Absent in login-only. */
  orgId?: string
}

export function parseSession(c: Context): OidcSession | null {
  const raw = getCookie(c, COOKIE_SESSION)
  if (!raw) return null
  try {
    const json = atob(raw.replace(/-/g, '+').replace(/_/g, '/'))
    const parsed = JSON.parse(json) as OidcSession
    if (!parsed.isAuthenticated) return null
    return parsed
  } catch {
    return null
  }
}

export function encodeSession(session: OidcSession): string {
  return btoa(JSON.stringify(session)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
