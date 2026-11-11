import { Hono } from 'hono'
import type { KvClient } from '../db/client.js'
import { parseSession } from '../lib/cookies.js'
import { DEV_ISSUER, DEV_SESSION_SECONDS, devCredentialsMatch, type DevLogin } from '../lib/dev.js'
import { safeReturnTo } from '../lib/return-to.js'
import { cliApprovePage, cliDonePage, cliProblemPage } from '../pages/cli.js'
import { respond } from '../pages/layout.js'
import { loginPage } from '../pages/login.js'
import { approveCli, cliRequest, isCliState } from './cli.js'
import { getConfig, requestedReturn, startSession } from './oidc.js'

/** How long a wrong dev password waits before it is answered. */
export const FAILED_LOGIN_DELAY_MS = 400

/**
 * The pages: what a person sees. Mounted under `/ui`, which a gateway
 * publishes at `/auth` — so `/login` here is `/ui/login` in the process and
 * `https://…/auth/login` outside.
 *
 * A page never answers with JSON and an API route never draws a page; that is
 * the whole of the split between this router and the ones under `/api`. A new
 * screen goes here, drawn with `layout()` and sent with `respond()`.
 */
export function pagesRouter(opts: { dev?: DevLogin | null; kv: KvClient }) {
  const app = new Hono()
  const dev = opts.dev ?? null
  const { kv } = opts
  const env = () => process.env as Record<string, string | undefined>

  // GET /login — the sign-in page.
  app.get('/login', (c) => {
    const cfg      = getConfig(env())
    const returnTo = safeReturnTo(requestedReturn(c), cfg.returnOrigins)

    // Someone already signed in has nothing to do here; a link to the sign-in
    // page then works as a link to the place behind it.
    if (parseSession(c)?.isAuthenticated) return c.redirect(returnTo)

    if (dev) return respond(c, loginPage({ returnTo, idps: [], dev: {} }))
    return respond(c, loginPage({ returnTo, idps: [...cfg.idps.keys()], error: c.req.query('error') }))
  })

  // POST /login — dev mode only: the form above posts here.
  //
  // A wrong pair answers after a pause, so the form cannot be used to try
  // passwords at the speed of a loop. The password is random per boot anyway;
  // this is for the AUTH_DEV_PASSWORD someone chose.
  app.post('/login', async (c) => {
    if (!dev) return c.json({ error: 'not_found' }, 404)
    const cfg  = getConfig(env())
    const form = await c.req.parseBody()
    const username = typeof form['username'] === 'string' ? form['username'].trim() : ''
    const password = typeof form['password'] === 'string' ? form['password'] : ''
    const returnTo = safeReturnTo(typeof form['returnTo'] === 'string' ? form['returnTo'] : undefined, cfg.returnOrigins)

    if (!devCredentialsMatch(dev, username, password)) {
      await new Promise((r) => setTimeout(r, FAILED_LOGIN_DELAY_MS))
      return respond(c, loginPage({ returnTo, idps: [], dev: { failed: true, username } }), 401)
    }

    await startSession(c, cfg, {
      subject:   dev.username,
      issuer:    DEV_ISSUER,
      email:     `${dev.username}@dev.localhost`,
      name:      dev.username,
      expiresAt: Math.floor(Date.now() / 1000) + DEV_SESSION_SECONDS,
    })
    return c.redirect(returnTo)
  })

  // GET /cli?state= — where `bw login` sends a person to approve the terminal.
  app.get('/cli', async (c) => {
    const state = c.req.query('state')
    if (!isCliState(state)) return respond(c, cliProblemPage('missing'), 400)

    const session = parseSession(c)
    if (!session?.isAuthenticated) {
      // Sign in first, then come back to this page with the same request.
      const cfg  = getConfig(env())
      const back = cfg.urls.uiPath(`/cli?state=${state}`)
      return c.redirect(cfg.urls.ui(`/login?returnTo=${encodeURIComponent(back)}`))
    }

    // Asked before the button is offered: a link opened twice, or an hour
    // late, says so instead of showing a button that can only fail.
    const status = await cliRequest(kv, state)
    if (status !== 'pending') return respond(c, cliProblemPage(status), status === 'used' ? 409 : 404)

    return respond(c, cliApprovePage({ state, who: session.email || session.name || session.subject }))
  })

  // POST /cli/approve — the page's own button.
  app.post('/cli/approve', async (c) => {
    const cfg     = getConfig(env())
    const state   = (await c.req.parseBody())['state']
    if (typeof state !== 'string' || !isCliState(state)) return respond(c, cliProblemPage('missing'), 400)

    const session = parseSession(c)
    if (!session?.isAuthenticated) {
      const back = cfg.urls.uiPath(`/cli?state=${state}`)
      return c.redirect(cfg.urls.ui(`/login?returnTo=${encodeURIComponent(back)}`))
    }

    const result = await approveCli(kv, session, state)
    if (result.ok) return c.redirect(cfg.urls.ui('/cli/done'))
    if (result.error === 'no_signing_key') return c.json({ error: 'realm has no signing key configured' }, 500)
    return result.error === 'already_used'
      ? respond(c, cliProblemPage('used'), 409)
      : respond(c, cliProblemPage('expired'), 404)
  })

  // GET /cli/done
  app.get('/cli/done', (c) => respond(c, cliDonePage()))

  return app
}
