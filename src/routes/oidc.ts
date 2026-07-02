import { Hono } from 'hono'
import { getCookie } from 'hono/cookie'
import { generatePkce, buildOidcAuthUrl } from '@baseworks/auth/pkce'
import { createUserRepo } from '@baseworks/account'
import {
  cookieOpts, encodeSession, ALL_OIDC_COOKIES,
  COOKIE_PKCE, COOKIE_RETURN_TO, COOKIE_ID_TOKEN, COOKIE_SESSION, COOKIE_ACCESS, COOKIE_REFRESH,
} from '../lib/cookies.js'
import { parseJwtPayload } from '@baseworks/auth/jwt'
import type { DB } from '../db/client.js'
import { schema } from '../db/client.js'

function getConfig(env: Record<string, string | undefined>) {
  return {
    issuer:       (env['OIDC_ISSUER']  ?? '').replace(/\/+$/, ''),
    clientId:     env['OIDC_CLIENT_ID'] ?? '',
    clientSecret: env['OIDC_CLIENT_SECRET'],
    scope:        (env['OIDC_SCOPE'] ?? 'openid profile email offline_access').split(' '),
    appUrl:       `${(env['APP_PUBLIC_URL'] ?? '').replace(/\/+$/, '')}/v1/auth`,
    cookieDomain: env['OIDC_COOKIE_DOMAIN'],
    isProd:       env['NODE_ENV'] === 'production',
  }
}

export function oidcRouter(db: DB) {
  const app      = new Hono()
  const userRepo = createUserRepo(db, schema)

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

    if (subject && email && issuer) {
      await userRepo.upsert({ subject, issuer, email, name, picture })
    }

    const session = encodeSession({
      isAuthenticated: true,
      subject:  subject ?? '',
      email:    email   ?? '',
      name:     name    ?? '',
      issuer:   issuer  ?? '',
      expiresAt,
    })

    const expires  = new Date(expiresAt * 1000).toUTCString()
    const opts     = cookieOpts(cfg.isProd, cfg.cookieDomain)
    const clearOpt = `HttpOnly; Path=/; Max-Age=0${cfg.cookieDomain ? `; Domain=${cfg.cookieDomain}` : ''}`

    c.header('Set-Cookie', `${COOKIE_PKCE}=; ${clearOpt}`, { append: true })
    c.header('Set-Cookie', `${COOKIE_RETURN_TO}=; ${clearOpt}`, { append: true })
    c.header('Set-Cookie', `${COOKIE_ID_TOKEN}=${data.id_token}; ${opts}; Expires=${expires}`, { append: true })
    c.header('Set-Cookie', `${COOKIE_SESSION}=${session}; ${opts}; Expires=${expires}`, { append: true })
    if (data.access_token) {
      c.header('Set-Cookie', `${COOKIE_ACCESS}=${data.access_token}; ${opts}; Expires=${expires}`, { append: true })
    }
    if (data.refresh_token) {
      c.header('Set-Cookie', `${COOKIE_REFRESH}=${data.refresh_token}; ${opts}`, { append: true })
    }

    const target = returnTo.startsWith('/') ? `${cfg.appUrl}${returnTo}` : returnTo
    return c.redirect(target)
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
  app.get('/logout', async (c) => {
    const cfg      = getConfig(process.env as Record<string, string | undefined>)
    const redirectTo = c.req.query('redirectTo') ?? '/'
    const idToken  = getCookie(c, COOKIE_ID_TOKEN)
    const domain   = cfg.cookieDomain ? `; Domain=${cfg.cookieDomain}` : ''
    const clear    = `HttpOnly; Path=/; Max-Age=0${domain}`

    for (const name of ALL_OIDC_COOKIES) {
      c.header('Set-Cookie', `${name}=; ${clear}`, { append: true })
    }

    try {
      const discovery = await fetch(`${cfg.issuer}/.well-known/openid-configuration`)
        .then((r) => r.json()) as { end_session_endpoint?: string }

      if (discovery.end_session_endpoint) {
        const endUrl = new URL(discovery.end_session_endpoint)
        const post   = redirectTo.startsWith('/') ? `${cfg.appUrl}${redirectTo}` : redirectTo
        endUrl.searchParams.set('post_logout_redirect_uri', post)
        if (idToken) endUrl.searchParams.set('id_token_hint', idToken)
        return c.redirect(endUrl.toString())
      }
    } catch { /* fall through */ }

    const target = redirectTo.startsWith('/') ? `${cfg.appUrl}${redirectTo}` : redirectTo
    return c.redirect(target)
  })

  return app
}
