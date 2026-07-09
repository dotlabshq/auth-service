import { Hono } from 'hono'
import { getCookie } from 'hono/cookie'
import { generatePkce, buildOidcAuthUrl } from '@baseworks/auth/pkce'
import {
  cookieOpts, encodeSession, ALL_OIDC_COOKIES,
  COOKIE_PKCE, COOKIE_RETURN_TO, COOKIE_ID_TOKEN, COOKIE_SESSION, COOKIE_ACCESS, COOKIE_REFRESH,
  COOKIE_PLATFORM_JWT,
  parseSession,
} from '../lib/cookies.js'
import { signHs256Jwt } from '@baseworks/auth/jwt'
import { iamEnabled, iamSync, iamEnsureOrg } from '../lib/iam.js'
import { tokenPage } from '../pages/token.js'

/**
 * Decode a JWT's payload segment. No signature check: the id_token was just
 * fetched directly from the OIDC token endpoint over TLS during the code
 * exchange, so it is already trusted at this point.
 */
function parseJwtPayload(jwt: string): Record<string, unknown> | null {
  const seg = jwt.split('.')[1]
  if (!seg) return null
  try {
    const json = Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')
    return JSON.parse(json) as Record<string, unknown>
  } catch {
    return null
  }
}

function getConfig(env: Record<string, string | undefined>) {
  return {
    issuer:       (env['OIDC_ISSUER']  ?? '').replace(/\/+$/, ''),
    clientId:     env['OIDC_CLIENT_ID'] ?? '',
    clientSecret: env['OIDC_CLIENT_SECRET'],
    scope:        (env['OIDC_SCOPE'] ?? 'openid profile email offline_access').split(' '),
    appOrigin:    (env['APP_PUBLIC_URL'] ?? '').replace(/\/+$/, ''),
    appUrl:       `${(env['APP_PUBLIC_URL'] ?? '').replace(/\/+$/, '')}/v1/auth`,
    // Exact post-logout URL to hand the IdP (must match what's registered on
    // the OIDC app). Defaults to the app origin (no trailing slash).
    postLogoutUrl: (env['OIDC_POST_LOGOUT_URL'] ?? '').replace(/\/+$/, ''),
    cookieDomain: env['OIDC_COOKIE_DOMAIN'],
    isProd:       env['NODE_ENV'] === 'production',
  }
}

export function oidcRouter() {
  const app = new Hono()

  // GET /login
  app.get('/login', async (c) => {
    const cfg        = getConfig(process.env as Record<string, string | undefined>)
    const redirectTo = c.req.query('redirectTo') ?? '/'
    const pkce       = await generatePkce()

    const authUrl = buildOidcAuthUrl({
      issuer:      cfg.issuer,
      clientId:    cfg.clientId,
      redirectUri: `${cfg.appUrl}/oidc/callback`,
      challenge:   pkce.challenge,
      prompt:      'select_account',
      scopes:      cfg.scope,
    })

    const opts = cookieOpts(cfg.isProd, cfg.cookieDomain) + '; Max-Age=600'
    c.header('Set-Cookie', `${COOKIE_PKCE}=${pkce.verifier}; ${opts}`, { append: true })
    c.header('Set-Cookie', `${COOKIE_RETURN_TO}=${encodeURIComponent(redirectTo)}; ${opts}`, { append: true })
    return c.redirect(authUrl)
  })

  // GET /oidc/callback
  app.get('/oidc/callback', async (c) => {
    const cfg     = getConfig(process.env as Record<string, string | undefined>)
    const code    = c.req.query('code')
    const error   = c.req.query('error')

    if (error || !code) return c.redirect(`${cfg.appUrl}/login?error=oidc_denied`)

    const verifier = getCookie(c, COOKIE_PKCE)
    const returnTo = decodeURIComponent(getCookie(c, COOKIE_RETURN_TO) ?? '/')
    if (!verifier) return c.redirect(`${cfg.appUrl}/login?error=missing_verifier`)

    const body = new URLSearchParams({
      grant_type:    'authorization_code',
      code,
      redirect_uri:  `${cfg.appUrl}/oidc/callback`,
      client_id:     cfg.clientId,
      code_verifier: verifier,
    })
    if (cfg.clientSecret) body.set('client_secret', cfg.clientSecret)

    const tokenRes = await fetch(`${cfg.issuer}/oauth/v2/token`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    }).catch(() => null)

    if (!tokenRes?.ok) {
      console.error('[oidc/callback] token exchange failed', tokenRes?.status)
      return c.redirect(`${cfg.appUrl}/login?error=token_exchange`)
    }

    const data = await tokenRes.json() as {
      access_token?: string; id_token?: string; expires_in?: number; refresh_token?: string
    }
    if (!data.id_token) return c.redirect(`${cfg.appUrl}/login?error=no_id_token`)

    const payload   = parseJwtPayload(data.id_token) ?? {}
    const subject   = payload['sub'] as string | undefined
    const email     = payload['email'] as string | undefined
    const name      = payload['name'] as string | undefined
    const picture   = payload['picture'] as string | undefined
    const issuer    = payload['iss'] as string | undefined
    const expiresAt = (payload['exp'] as number | undefined) ?? Math.floor(Date.now() / 1000) + (data.expires_in ?? 3600)

    // Resolve the platform identity. With IAM present, delegate identity + org
    // to iam-service; without it, this is login-only — the OIDC subject IS the
    // identity and there is no org (auth owns no user/org data — ADR-006/007).
    let platformUserId = subject ?? ''
    let platformOrgId:  string | undefined

    if (subject && email && issuer && iamEnabled()) {
      const userId = await iamSync({ subject, issuer, email, name, picture })
      if (userId) {
        platformUserId = userId
        platformOrgId  = await iamEnsureOrg(userId, email)
      } else {
        console.error('[oidc] IAM sync failed; falling back to OIDC subject')
      }
    }

    const session = encodeSession({
      isAuthenticated: true,
      subject:  subject ?? '',
      email:    email   ?? '',
      name:     name    ?? '',
      issuer:   issuer  ?? '',
      expiresAt,
      userId:   platformUserId,
      orgId:    platformOrgId,
    })

    const expires  = new Date(expiresAt * 1000).toUTCString()
    const opts     = cookieOpts(cfg.isProd, cfg.cookieDomain)
    const clearOpt = `HttpOnly; Path=/; Max-Age=0${cfg.cookieDomain ? `; Domain=${cfg.cookieDomain}` : ''}`

    c.header('Set-Cookie', `${COOKIE_PKCE}=; ${clearOpt}`, { append: true })
    c.header('Set-Cookie', `${COOKIE_RETURN_TO}=; ${clearOpt}`, { append: true })
    c.header('Set-Cookie', `${COOKIE_ID_TOKEN}=${data.id_token}; ${opts}; Expires=${expires}`, { append: true })
    c.header('Set-Cookie', `${COOKIE_SESSION}=${session}; ${opts}; Expires=${expires}`, { append: true })

    // Platform JWT cookie — set on browser login so all services can read it
    // directly (same JWT the CLI gets via /v1/auth/token). `org_id` is omitted in
    // login-only mode; downstream apps that only need identity read `sub`.
    if (platformUserId) {
      const jwtSecret = process.env['JWT_SECRET']
      if (jwtSecret) {
        const platformTtl = expiresAt - Math.floor(Date.now() / 1000)
        const platformJwt = signHs256Jwt(
          { sub: platformUserId, org_id: platformOrgId, type: 'human' },
          jwtSecret,
          platformTtl,
        )
        c.header('Set-Cookie', `oidc_token=${platformJwt}; ${opts}; Expires=${expires}`, { append: true })
      }
    }

    if (data.access_token) {
      c.header('Set-Cookie', `${COOKIE_ACCESS}=${data.access_token}; ${opts}; Expires=${expires}`, { append: true })
    }
    if (data.refresh_token) {
      c.header('Set-Cookie', `${COOKIE_REFRESH}=${data.refresh_token}; ${opts}`, { append: true })
    }

    // returnTo is relative to the APP root (e.g. "/"), not to the auth service's
    // own base path — a root-relative Location resolves against the app origin.
    // Prefixing it with cfg.appUrl (which ends in /v1/auth) wrongly sent users
    // to /v1/auth/ instead of /.
    return c.redirect(returnTo)
  })

  // GET /session
  app.get('/session', (c) => {
    const raw = getCookie(c, COOKIE_SESSION)
    if (!raw) return c.json({ isAuthenticated: false }, 401)
    try {
      const pad    = raw.replace(/-/g, '+').replace(/_/g, '/')
      const rem    = pad.length % 4
      const parsed = JSON.parse(atob(rem ? pad + '='.repeat(4 - rem) : pad)) as { isAuthenticated: boolean }
      if (!parsed.isAuthenticated) return c.json({ isAuthenticated: false }, 401)
      return c.json(parsed)
    } catch {
      return c.json({ isAuthenticated: false }, 401)
    }
  })

  // GET /logout
  // Local logout by default: clears this app's cookies and returns to the app
  // root — no dependency on the IdP. Full single-sign-out (also ending the
  // Zitadel session) is opt-in with `?sso=1`, which requires the
  // post_logout_redirect_uri to be registered on the OIDC app.
  app.get('/logout', async (c) => {
    const cfg        = getConfig(process.env as Record<string, string | undefined>)
    const redirectTo = c.req.query('redirectTo') ?? '/'
    const sso        = c.req.query('sso') === '1'
    const idToken    = getCookie(c, COOKIE_ID_TOKEN)
    const domain     = cfg.cookieDomain ? `; Domain=${cfg.cookieDomain}` : ''
    const clear      = `HttpOnly; Path=/; Max-Age=0${domain}`

    // Clear every cookie this service issues — including the platform JWT
    // (`oidc_token`) that downstream services read to identify the user.
    const cookieNames = [...new Set([...ALL_OIDC_COOKIES, COOKIE_PLATFORM_JWT, COOKIE_PKCE, COOKIE_RETURN_TO, 'oidc_token'])]
    for (const name of cookieNames) {
      c.header('Set-Cookie', `${name}=; ${clear}`, { append: true })
    }

    if (sso) {
      try {
        const discovery = await fetch(`${cfg.issuer}/.well-known/openid-configuration`)
          .then((r) => r.json()) as { end_session_endpoint?: string }
        if (discovery.end_session_endpoint) {
          const endUrl = new URL(discovery.end_session_endpoint)
          // Absolute URL that must EXACTLY match a registered post-logout URI.
          // Precedence: ?redirectTo=<absolute> > OIDC_POST_LOGOUT_URL > app
          // origin (all without a trailing slash so "…/" mismatches don't bite).
          const post = redirectTo.startsWith('http')
            ? redirectTo.replace(/\/+$/, '')
            : (cfg.postLogoutUrl || cfg.appOrigin)
          endUrl.searchParams.set('post_logout_redirect_uri', post)
          if (idToken) endUrl.searchParams.set('id_token_hint', idToken)
          return c.redirect(endUrl.toString())
        }
      } catch { /* fall through to local logout */ }
    }

    // Local logout: back to the app root (root-relative resolves to the origin).
    return c.redirect(redirectTo)
  })

  // GET /token
  // - CLI flow  (state param present): session yoksa login'e redirect, varsa approve HTML göster
  // - API flow  (state param yoksa):   session yoksa 401, varsa JWT JSON döndür
  app.get('/token', async (c) => {
    const state   = c.req.query('state')
    const session = parseSession(c)
    const base    = (process.env['APP_PUBLIC_URL'] ?? '').replace(/\/+$/, '')

    if (!session?.isAuthenticated) {
      if (!state) return c.json({ error: 'not_authenticated' }, 401)
      // CLI flow: OIDC login'e yönlendir, state'i returnTo ile koru.
      // returnTo must include the /v1/auth base path — Traefik strips it before
      // this service sees the request, so a bare "/token" would 404 the app root.
      const redirectTo = `/v1/auth/token?state=${state}`
      return c.redirect(`${base}/v1/auth/login?redirectTo=${encodeURIComponent(redirectTo)}`)
    }

    // CLI flow: session var → approve sayfasını göster
    if (state) {
      return c.html(tokenPage(state))
    }

    // API flow: session var, state yok → direkt JWT döndür (web client).
    // Identity + org were resolved at callback and stored in the session, so no
    // database round-trip is needed here.
    const jwtSecret = process.env['JWT_SECRET']
    if (!jwtSecret) return c.json({ error: 'JWT_SECRET not configured' }, 500)

    const userId  = session.userId ?? session.subject
    const orgId   = session.orgId
    const ttl     = Math.max(session.expiresAt - Math.floor(Date.now() / 1000), 60)
    const expires = new Date(session.expiresAt * 1000).toUTCString()
    const cfg     = getConfig(process.env as Record<string, string | undefined>)

    const token = signHs256Jwt(
      { sub: userId, org_id: orgId, type: 'human' },
      jwtSecret,
      ttl,
    )

    const opts = cookieOpts(cfg.isProd, cfg.cookieDomain)
    c.header('Set-Cookie', `oidc_token=${token}; ${opts}; Expires=${expires}`, { append: true })

    return c.json({ token, token_type: 'bearer', expires_in: ttl })
  })

  return app
}
