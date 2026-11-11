import { escapeHtml } from '../lib/html.js'
import { publicUrls } from '../lib/urls.js'
import { layout, type PageView } from './layout.js'
import { strings, type StringKey } from './strings.js'

/** The providers this page has a mark for. Any other name still gets a button. */
const PROVIDERS: Record<string, { label: string; icon: string }> = {
  google: {
    label: 'Google',
    icon: '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path fill="#4285F4" d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5a5.6 5.6 0 0 1-2.4 3.6v3h3.9c2.2-2.1 3.5-5.1 3.5-8.8z"/><path fill="#34A853" d="M12 24c3.2 0 6-1.1 7.9-2.9l-3.9-3c-1.1.7-2.4 1.2-4 1.2-3.1 0-5.7-2.1-6.6-4.9h-4v3.1A12 12 0 0 0 12 24z"/><path fill="#FBBC05" d="M5.4 14.4a7.2 7.2 0 0 1 0-4.6V6.7h-4a12 12 0 0 0 0 10.8l4-3.1z"/><path fill="#EA4335" d="M12 4.8c1.8 0 3.3.6 4.6 1.8l3.4-3.4A12 12 0 0 0 1.4 6.7l4 3.1C6.3 6.9 8.9 4.8 12 4.8z"/></svg>',
  },
  github: {
    label: 'GitHub',
    icon: '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="currentColor"><path d="M12 .5a11.5 11.5 0 0 0-3.6 22.4c.6.1.8-.3.8-.6v-2c-3.2.7-3.9-1.5-3.9-1.5-.5-1.3-1.3-1.7-1.3-1.7-1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1 1.8 2.8 1.3 3.4 1 .1-.8.4-1.3.8-1.6-2.6-.3-5.3-1.3-5.3-5.7 0-1.3.5-2.3 1.2-3.1-.1-.3-.5-1.5.1-3.1 0 0 1-.3 3.2 1.2a11 11 0 0 1 5.8 0c2.2-1.5 3.2-1.2 3.2-1.2.6 1.6.2 2.8.1 3.1.8.8 1.2 1.9 1.2 3.1 0 4.4-2.7 5.4-5.3 5.7.4.4.8 1.1.8 2.2v3.2c0 .3.2.7.8.6A11.5 11.5 0 0 0 12 .5z"/></svg>',
  },
  apple: {
    label: 'Apple',
    icon: '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="currentColor"><path d="M16.4 12.6c0-2.6 2.1-3.8 2.2-3.9a4.8 4.8 0 0 0-3.8-2c-1.6-.2-3.1.9-3.9.9-.8 0-2-.9-3.4-.9a5 5 0 0 0-4.2 2.6c-1.8 3.1-.5 7.7 1.3 10.2.9 1.2 1.9 2.6 3.2 2.5 1.3 0 1.8-.8 3.3-.8 1.6 0 2 .8 3.4.8 1.4 0 2.3-1.3 3.1-2.5a11 11 0 0 0 1.4-2.9 4.5 4.5 0 0 1-2.6-4zM13.9 5c.7-.8 1.2-2 1-3.1-1 0-2.2.7-2.9 1.5-.6.7-1.2 1.9-1 3 1.1.1 2.2-.6 2.9-1.4z"/></svg>',
  },
  microsoft: {
    label: 'Microsoft',
    icon: '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path fill="#F25022" d="M1 1h10.5v10.5H1z"/><path fill="#7FBA00" d="M12.5 1H23v10.5H12.5z"/><path fill="#00A4EF" d="M1 12.5h10.5V23H1z"/><path fill="#FFB900" d="M12.5 12.5H23V23H12.5z"/></svg>',
  },
}

/**
 * What went wrong on the way back from the provider, as the key of the
 * sentence that says so. The codes are the ones `/oidc/callback` redirects
 * here with; an unknown one gets `errUnknown` rather than being echoed.
 */
const ERRORS: Record<string, StringKey> = {
  oidc_denied: 'errDenied',
  missing_verifier: 'errSlow',
  token_exchange: 'errProvider',
  no_id_token: 'errProvider',
}

export interface LoginPageOptions {
  view: PageView
  /** Already checked by `safeReturnTo`. */
  returnTo: string
  /** Names from `OIDC_IDPS`, in the order configured. */
  idps: string[]
  /** An error code from the callback, as it arrived in `?error=`. */
  error?: string
  /** Dev mode: the page is a password form and there is no provider at all. */
  dev?: { failed?: boolean; username?: string }
}

/**
 * The sign-in page.
 *
 * One button per configured identity provider, each going straight to that
 * provider, and a quieter link for everything else the realm's OIDC provider
 * offers. With no provider named the page is a single "Continue" button. In
 * dev mode it is the password form.
 */
export function loginPage(opts: LoginPageOptions): string {
  const e = escapeHtml
  const urls = publicUrls()
  const t = strings(opts.view.lang)
  const name = opts.view.brand.name
  const q = `returnTo=${encodeURIComponent(opts.returnTo)}`
  const heading = name ? t('signInTo', { name }) : t('signIn')

  if (opts.dev) {
    return layout({
      title: t('signIn'),
      view: opts.view,
      body: `    <span class="tag">${t('devTag')}</span>
    <h1>${heading}</h1>
    <p>${t('devHint')}</p>
    ${opts.dev.failed ? `<p class="error" role="alert">${t('devMismatch')}</p>` : ''}
    <form class="stack" method="POST" action="${e(urls.ui('/login'))}">
      <input type="hidden" name="returnTo" value="${e(opts.returnTo)}">
      <label>${t('user')} <input type="text" name="username" autocomplete="username" value="${e(opts.dev.username ?? '')}" required></label>
      <label>${t('password')} <input type="password" name="password" autocomplete="current-password" required autofocus></label>
      <button class="btn primary" type="submit">${t('signIn')}</button>
    </form>`,
    })
  }

  const message = opts.error ? t(ERRORS[opts.error] ?? 'errUnknown') : ''
  const sso = e(urls.ui(`/login/sso?${q}`))
  const buttons = opts.idps.map((idp) => {
    const p = PROVIDERS[idp]
    const label = p?.label ?? idp.charAt(0).toUpperCase() + idp.slice(1)
    return `<a class="btn" href="${e(urls.ui(`/login/${encodeURIComponent(idp)}?${q}`))}">${p?.icon ?? ''}<span>${t('continueWith', { provider: label })}</span></a>`
  })

  return layout({
    title: t('signIn'),
    view: opts.view,
    body: `    <h1>${heading}</h1>
    ${message ? `<p class="error" role="alert">${message}</p>` : ''}
    <div class="stack">
      ${buttons.length ? buttons.join('\n      ') : `<a class="btn primary" href="${sso}">${t('continue')}</a>`}
    </div>
    ${buttons.length ? `<div class="or"><span>${t('or')}</span></div>
    <p class="quiet center"><a href="${sso}">${t('otherOptions')}</a></p>` : ''}`,
  })
}
