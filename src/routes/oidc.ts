import { Hono, type Context } from 'hono'
import { getCookie } from 'hono/cookie'
import { generatePkce, buildOidcAuthUrl } from '@baseworks/auth/pkce'
import {
  cookieOpts, encodeSession, serializeSession, ALL_OIDC_COOKIES,
  COOKIE_PKCE, COOKIE_RETURN_TO, COOKIE_ID_TOKEN, COOKIE_SESSION, COOKIE_ACCESS, COOKIE_REFRESH,
  COOKIE_PLATFORM_JWT,
  parseSession,
} from '../lib/cookies.js'
import { mintIdentityToken } from '../lib/mint.js'
import { iamEnabled, iamSync } from '../lib/iam.js'
import { returnOrigins, safeReturnTo } from '../lib/return-to.js'
import type { DevLogin } from '../lib/dev.js'
import { publicUrls } from '../lib/urls.js'
import { idpScopes, parseIdps } from '../lib/idps.js'

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

export function getConfig(env: Record<string, string | undefined>) {
  return {
    issuer:       (env['OIDC_ISSUER']  ?? '').replace(/\/+$/, ''),
    clientId:     env['OIDC_CLIENT_ID'] ?? '',
    clientSecret: env['OIDC_CLIENT_SECRET'],
    scope:        (env['OIDC_SCOPE'] ?? 'openid profile email offline_access').split(' '),
    // Every address the browser is sent to — see lib/urls.ts.
    urls:         publicUrls(env),
    // Exact post-logout URL to hand the IdP (must match what's registered on
    // the OIDC app). Defaults to the app origin (no trailing slash).
    postLogoutUrl: (env['OIDC_POST_LOGOUT_URL'] ?? '').replace(/\/+$/, ''),
    cookieDomain: env['OIDC_COOKIE_DOMAIN'],
    // Where a sign-in or sign-out may send the browser afterwards. Anything
    // else lands on `/` — see lib/return-to.ts.
    returnOrigins: returnOrigins(env),
    isProd:       env['NODE_ENV'] === 'production',
    // Sign-in straight with a named IdP — see lib/idps.ts.
    idps:         parseIdps(env['OIDC_IDPS']),
    orgId:        (env['OIDC_ORG_ID'] ?? '').trim() || undefined,
  }
}

/**
 * The page to come back to, as the caller asked for it.
 *
 * `returnTo` is the name — it is what openapi.yaml publishes and what the
 * console and doubletap send. The code used to read `redirectTo`, so every
 * caller's value was ignored and everybody landed on `/`. `redirectTo` is
 * still read for links written against the old name.
 */
export function requestedReturn(c: { req: { query(name: string): string | undefined } }): string | undefined {
  return c.req.query('returnTo') ?? c.req.query('redirectTo')
}

/** decodeURIComponent, minus the URIError a hand-edited cookie can throw. */
function decodeCookieValue(v: string | undefined): string | undefined {
  if (v === undefined) return undefined
  try { return decodeURIComponent(v) } catch { return undefined }
}

/** Every cookie this service issues, expired. */
function clearAllCookies(c: { header(name: string, value: string, o?: { append?: boolean }): void }, cookieDomain?: string) {
  const clear = `HttpOnly; Path=/; Max-Age=0${cookieDomain ? `; Domain=${cookieDomain}` : ''}`
  // Including the platform JWT (`oidc_token`) that downstream services read to
  // identify the user.
  const names = [...new Set([...ALL_OIDC_COOKIES, COOKIE_PLATFORM_JWT, COOKIE_PKCE, COOKIE_RETURN_TO, 'oidc_token'])]
  for (const name of names) c.header('Set-Cookie', `${name}=; ${clear}`, { append: true })
}

/**
 * Sign the person in: resolve the platform identity, then set the signed
 * session cookie and the realm identity token. Shared by the OIDC callback and
 * the dev-mode form, so a dev sign-in is the real thing past this point.
 *
 * With IAM present the identity is registered with iam-service (`/sync`) to get
 * a stable user id; without it this is login-only — the subject IS the
 * identity. auth deals in NO org (a user has only memberships — an org-service
 * question).
 */
export async function startSession(
  c: { header(name: string, value: string, o?: { append?: boolean }): void },
  cfg: ReturnType<typeof getConfig>,
  id: { subject?: string; email?: string; name?: string; picture?: string; issuer?: string; expiresAt: number },
): Promise<void> {
  const { subject, email, name, picture, issuer, expiresAt } = id
  let platformUserId = subject ?? ''

  if (subject && email && issuer && iamEnabled()) {
    const userId = await iamSync({ subject, issuer, email, name, picture })
    if (userId) {
      platformUserId = userId
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
  })

  const expires  = new Date(expiresAt * 1000).toUTCString()
  const opts     = cookieOpts(cfg.isProd, cfg.cookieDomain)
  const clearOpt = `HttpOnly; Path=/; Max-Age=0${cfg.cookieDomain ? `; Domain=${cfg.cookieDomain}` : ''}`

  c.header('Set-Cookie', `${COOKIE_PKCE}=; ${clearOpt}`, { append: true })
  c.header('Set-Cookie', `${COOKIE_RETURN_TO}=; ${clearOpt}`, { append: true })
  c.header('Set-Cookie', `${COOKIE_SESSION}=${session}; ${opts}; Expires=${expires}`, { append: true })

  // Platform JWT cookie — set on browser login so all services can read it
  // directly (same JWT the CLI gets from `/api/token`). It carries identity
  // only (`{ sub, type }`); an app that needs org context resolves membership
  // via org-service.
  if (platformUserId) {
    const platformTtl = expiresAt - Math.floor(Date.now() / 1000)
    const platformJwt = await mintIdentityToken({
      sub: platformUserId, type: 'human', expiresInSeconds: platformTtl,
    })
    if (platformJwt) {
      c.header('Set-Cookie', `oidc_token=${platformJwt}; ${opts}; Expires=${expires}`, { append: true })
    }
  }
}

export interface OidcRouterOptions {
  /** Set when dev mode is on: there is no IdP, and sign-in is the password form. */
  dev?: DevLogin | null
}

type Config = ReturnType<typeof getConfig>

/** The sign-in page's address, carrying where to go afterwards and why it is shown. */
function loginPageUrl(cfg: Config, returnTo: string, error?: string): string {
  const q = new URLSearchParams()
  if (returnTo !== '/') q.set('returnTo', returnTo)
  if (error) q.set('error', error)
  const qs = q.toString()
  return cfg.urls.ui(`/login${qs ? `?${qs}` : ''}`)
}

/**
 * The navigations of a sign-in: off to the provider, back from it, and out.
 *
 * These are places a browser *goes*, so they belong to the page surface (the
 * service root, published at `/auth`). They are mounted a second time under
 * `/api` only so that links written before 2.0 — `/v1/auth/login/google`,
 * a `redirect_uri` still registered as `/v1/auth/oidc/callback`,
 * `/v1/auth/logout` — keep working. That second mount is deprecated.
 */
export function signinRouter(opts: OidcRouterOptions = {}) {
  const app = new Hono()
  const dev = opts.dev ?? null

  /**
   * Send the browser to the IdP with a fresh PKCE pair, remembering where to
   * come back to. `/login/sso` and `/login/:idp` differ only in what they ask for.
   */
  async function redirectToIdp(
    c: Context,
    cfg: Config,
    redirectTo: string,
    ask: { prompt?: 'select_account'; scopes: string[] },
  ) {
    // Dev mode has no IdP at all, so every way in lands on the same form — a
    // product's login buttons work on a laptop without a provider.
    if (dev) return c.redirect(loginPageUrl(cfg, redirectTo))

    const pkce    = await generatePkce()
    const authUrl = buildOidcAuthUrl({
      issuer:      cfg.issuer,
      clientId:    cfg.clientId,
      redirectUri: cfg.urls.callback,
      challenge:   pkce.challenge,
      ...(ask.prompt ? { prompt: ask.prompt } : {}),
      scopes:      ask.scopes,
    })

    const opts = cookieOpts(cfg.isProd, cfg.cookieDomain) + '; Max-Age=600'
    c.header('Set-Cookie', `${COOKIE_PKCE}=${pkce.verifier}; ${opts}`, { append: true })
    c.header('Set-Cookie', `${COOKIE_RETURN_TO}=${encodeURIComponent(redirectTo)}; ${opts}`, { append: true })
    return c.redirect(authUrl)
  }

  /** Sign in with whatever the realm's provider offers, on the provider's own screens. */
  const sso = async (c: Context) => {
    const cfg = getConfig(process.env as Record<string, string | undefined>)
    // Checked here rather than on the way back, so a poisoned value is never
    // stored in a cookie in the first place.
    const redirectTo = safeReturnTo(requestedReturn(c), cfg.returnOrigins)
    return redirectToIdp(c, cfg, redirectTo, { prompt: 'select_account', scopes: cfg.scope })
  }

  // GET /login/sso — the provider's own sign-in. Registered before `/login/:idp`,
  // so `sso` is not a name an IdP can be given in OIDC_IDPS.
  app.get('/login/sso', sso)

  // GET /login/:idp — straight to one IdP, past the provider's own screens.
  // No `prompt`: the IdP shows its own account chooser where it has one.
  app.get('/login/:idp', async (c) => {
    const cfg        = getConfig(process.env as Record<string, string | undefined>)
    const redirectTo = safeReturnTo(requestedReturn(c), cfg.returnOrigins)
    if (dev) return c.redirect(loginPageUrl(cfg, redirectTo))

    const idpId = cfg.idps.get(c.req.param('idp').toLowerCase())
    if (!idpId) return c.json({ error: 'unknown_idp', message: 'No such sign-in provider is configured' }, 404)

    return redirectToIdp(c, cfg, redirectTo, { scopes: [...cfg.scope, ...idpScopes(idpId, cfg.orgId)] })
  })

  // GET /oidc/callback
  app.get('/oidc/callback', async (c) => {
    // Dev mode has no IdP; nothing legitimate lands here.
    if (dev) return c.json({ error: 'not_found' }, 404)
    const cfg     = getConfig(process.env as Record<string, string | undefined>)
    const code    = c.req.query('code')
    const error   = c.req.query('error')

    // Again, because the cookie holding it is the client's: a browser that
    // arrives with one this service never wrote is still a browser to send
    // somewhere safe.
    const returnTo = safeReturnTo(decodeCookieValue(getCookie(c, COOKIE_RETURN_TO)), cfg.returnOrigins)

    // A failure goes back to the sign-in page, which says what happened and
    // offers the buttons again, still knowing where the person was headed.
    // (Before 2.0 it went to `/login`, which was itself a redirect to the
    // provider — a refusal looped straight back into another attempt.)
    const fail = (reason: string) => c.redirect(loginPageUrl(cfg, returnTo, reason))

    if (error || !code) return fail('oidc_denied')

    const verifier = getCookie(c, COOKIE_PKCE)
    if (!verifier) return fail('missing_verifier')

    const body = new URLSearchParams({
      grant_type:    'authorization_code',
      code,
      // The same address the authorize request carried, whichever mount the
      // provider came back through: the provider compares the two.
      redirect_uri:  cfg.urls.callback,
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
      return fail('token_exchange')
    }

    const data = await tokenRes.json() as {
      access_token?: string; id_token?: string; expires_in?: number; refresh_token?: string
    }
    if (!data.id_token) return fail('no_id_token')

    const payload   = parseJwtPayload(data.id_token) ?? {}
    const subject   = payload['sub'] as string | undefined
    const email     = payload['email'] as string | undefined
    const name      = payload['name'] as string | undefined
    const picture   = payload['picture'] as string | undefined
    const issuer    = payload['iss'] as string | undefined
    const expiresAt = (payload['exp'] as number | undefined) ?? Math.floor(Date.now() / 1000) + (data.expires_in ?? 3600)

    await startSession(c, cfg, { subject, email, name, picture, issuer, expiresAt })
    const expires = new Date(expiresAt * 1000).toUTCString()
    const opts    = cookieOpts(cfg.isProd, cfg.cookieDomain)
    c.header('Set-Cookie', `${COOKIE_ID_TOKEN}=${data.id_token}; ${opts}; Expires=${expires}`, { append: true })

    if (data.access_token) {
      c.header('Set-Cookie', `${COOKIE_ACCESS}=${data.access_token}; ${opts}; Expires=${expires}`, { append: true })
    }
    if (data.refresh_token) {
      c.header('Set-Cookie', `${COOKIE_REFRESH}=${data.refresh_token}; ${opts}`, { append: true })
    }

    // returnTo is relative to the APP root (e.g. "/"), not to wherever this
    // service is published — a root-relative Location resolves against the
    // app origin.
    return c.redirect(returnTo)
  })

  // GET /logout — a link or a navigation.
  // Local logout by default: clears this app's cookies and returns to the app
  // root — no dependency on the IdP. Full single-sign-out (also ending the
  // Zitadel session) is opt-in with `?sso=1`, which requires the
  // post_logout_redirect_uri to be registered on the OIDC app.
  app.get('/logout', async (c) => {
    const cfg        = getConfig(process.env as Record<string, string | undefined>)
    const redirectTo = safeReturnTo(requestedReturn(c), cfg.returnOrigins)
    const sso        = c.req.query('sso') === '1'
    const idToken    = getCookie(c, COOKIE_ID_TOKEN)

    clearAllCookies(c, cfg.cookieDomain)

    // There is no IdP session to end in dev mode.
    if (sso && !dev) {
      try {
        const discovery = await fetch(`${cfg.issuer}/.well-known/openid-configuration`)
          .then((r) => r.json()) as { end_session_endpoint?: string }
        if (discovery.end_session_endpoint) {
          const endUrl = new URL(discovery.end_session_endpoint)
          // Absolute URL that must EXACTLY match a registered post-logout URI.
          // Precedence: ?returnTo=<absolute> > OIDC_POST_LOGOUT_URL > app
          // origin (all without a trailing slash so "…/" mismatches don't bite).
          const post = redirectTo.startsWith('http')
            ? redirectTo.replace(/\/+$/, '')
            : (cfg.postLogoutUrl || cfg.urls.origin)
          endUrl.searchParams.set('post_logout_redirect_uri', post)
          if (idToken) endUrl.searchParams.set('id_token_hint', idToken)
          return c.redirect(endUrl.toString())
        }
      } catch { /* fall through to local logout */ }
    }

    // Local logout: back to the app root (root-relative resolves to the origin).
    return c.redirect(redirectTo)
  })

  // The `/api` mount adds one more route in front of these: before 2.0
  // `GET /login` was not a page but this redirect. See sessionRouter.
  return Object.assign(app, { sso })
}

/**
 * The session as other programs ask about it: is there one, a token for it,
 * end it. JSON in and out; nothing here draws a page.
 */
export function sessionRouter(opts: OidcRouterOptions & { sso: (c: Context) => Promise<Response> }) {
  const app = new Hono()

  // GET /login — deprecated. Until 2.0 this address (`/v1/auth/login`) started
  // a sign-in; consoles and products link to it. It still does exactly that.
  // The page a person should be sent to is the service root's `/login`.
  app.get('/login', opts.sso)

  // GET /idps — the names a product's login page can offer buttons for. Names
  // only: the provider's ids are configuration, not something to publish.
  app.get('/idps', (c) => {
    const cfg = getConfig(process.env as Record<string, string | undefined>)
    return c.json({ idps: [...cfg.idps.keys()] })
  })

  // GET /session
  app.get('/session', (c) => {
    const parsed = parseSession(c)
    if (!parsed) return c.json({ is_authenticated: false }, 401)
    return c.json(serializeSession(parsed))
  })

  // POST /logout — the local logout, for a page that signs out with fetch()
  // and draws its own next screen. A redirect would hand fetch() a page of
  // HTML it has no use for, so the answer is an empty 204 carrying the
  // cleared cookies.
  app.post('/logout', (c) => {
    const cfg = getConfig(process.env as Record<string, string | undefined>)
    clearAllCookies(c, cfg.cookieDomain)
    return c.body(null, 204)
  })

  // GET /token — the identity token for the session in the cookie.
  app.get('/token', async (c) => {
    const cfg = getConfig(process.env as Record<string, string | undefined>)

    // Deprecated: before 2.0 `…/token?state=` was the CLI's approve page. A
    // link an older `bw` printed still gets the person there.
    const state = c.req.query('state')
    if (state) return c.redirect(cfg.urls.ui(`/cli?state=${encodeURIComponent(state)}`))

    const session = parseSession(c)
    if (!session?.isAuthenticated) return c.json({ error: 'not_authenticated' }, 401)

    // The identity was resolved at callback and stored in the session, so no
    // round-trip is needed here.
    const userId  = session.userId ?? session.subject
    const ttl     = Math.max(session.expiresAt - Math.floor(Date.now() / 1000), 60)
    const expires = new Date(session.expiresAt * 1000).toUTCString()

    const token = await mintIdentityToken({ sub: userId, type: 'human', expiresInSeconds: ttl })
    if (!token) return c.json({ error: 'realm has no signing key configured' }, 500)

    const opts = cookieOpts(cfg.isProd, cfg.cookieDomain)
    c.header('Set-Cookie', `oidc_token=${token}; ${opts}; Expires=${expires}`, { append: true })

    return c.json({ token, token_type: 'bearer', expires_in: ttl })
  })

  return app
}
