import { escapeHtml } from '../lib/html.js'
import { publicUrls } from '../lib/urls.js'
import { layout, type PageView } from './layout.js'
import { strings } from './strings.js'

/**
 * The consent page of the OAuth authorization server (workspace ADR 0006):
 * server-rendered, no script (the realm's pages are served with
 * `default-src 'none'`), English and Turkish. A person is asked once, with the
 * client's name, where they will be sent, the organization and the access.
 */
export interface ConsentView {
  view: PageView
  client_name: string
  logo_uri: string | null
  /** Host of the redirect URI the client asked for, shown in plain sight. */
  redirect_host: string
  /** Every registered redirect URI is on this computer: say so. */
  localhost_only: boolean
  resource: string
  /** The person's organizations; empty: none. */
  orgs: Array<{ id: string; slug: string; name: string }>
  /** Whether the client asked for `write`: otherwise only read is offered. */
  may_write: boolean
  /** `agent:<name>@<handle>`. */
  actor: string
  /** The id the form posts back, tying the answer to this request and this person. */
  req: string
}

export function consentPage(v: ConsentView): string {
  const e = escapeHtml
  const t = strings(v.view.lang)
  const product = v.view.brand.name
  const orgs = v.orgs.length
    ? `<label>${t('oauthOrg')} <select name="org_id" required>${v.orgs.map((o, i) => `<option value="${e(o.id)}"${i === 0 ? ' selected' : ''}>${e(o.name)}</option>`).join('')}</select></label>`
    : `<p class="quiet">${t('oauthNoOrg')}</p>`
  return layout({
    title: t('oauthTitle', { client: v.client_name }),
    view: v.view,
    body: `    ${v.logo_uri ? `<p><img src="${e(v.logo_uri)}" alt="" width="48" height="48"></p>` : ''}
    <h1>${t('oauthTitle', { client: v.client_name })}</h1>
    <p>${t('oauthIntro', { client: v.client_name, product })}</p>
    <p>${t('oauthRedirect', { host: v.redirect_host })}</p>
    ${v.localhost_only ? `<p class="error" role="alert">${t('oauthLocalhost')}</p>` : ''}
    <p class="quiet">${t('oauthResource', { resource: v.resource })}</p>
    <form class="stack" method="POST" action="${e(publicUrls().api('/authorize'))}">
      <input type="hidden" name="req" value="${e(v.req)}">
      ${orgs}
      <fieldset>
        <legend>${t('oauthAccess')}</legend>
        <label><input type="radio" name="access" value="read"${v.may_write ? '' : ' checked'}> ${t('oauthRead')}</label>
        ${v.may_write ? `<label><input type="radio" name="access" value="write" checked> ${t('oauthWrite')}</label>` : ''}
      </fieldset>
      <p>${t('oauthActs', { actor: v.actor })}</p>
      <button class="btn primary" type="submit" name="decision" value="approve">${t('oauthApprove')}</button>
      <button class="btn" type="submit" name="decision" value="deny">${t('oauthDeny')}</button>
    </form>`,
  })
}

/** A request that cannot be completed and cannot safely be sent back to the client (unknown client, redirect not registered). */
export function oauthProblemPage(view: PageView, problem: 'client' | 'redirect' | 'request' | 'expired' | 'person'): string {
  const t = strings(view.lang)
  const text = t(({ client: 'oauthBadClient', redirect: 'oauthBadRedirect', request: 'oauthBadRequest', expired: 'oauthExpired', person: 'oauthWrongPerson' } as const)[problem])
  return layout({
    title: t('oauthBad'),
    view,
    body: `    <h1>${t('oauthBad')}</h1>
    <p class="error" role="alert">${text}</p>
    <p class="quiet">${t('oauthBack')}</p>`,
  })
}
