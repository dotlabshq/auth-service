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
  /** The host of the client's id (a Client ID Metadata Document URL), shown beside its name; null for a registered client. */
  client_host: string | null
  /** Host of the redirect URI the client asked for, shown in plain sight. */
  redirect_host: string
  /** Every registered redirect URI is on this computer: say so. */
  localhost_only: boolean
  resource: string
  /** The person's organizations; empty: none. */
  orgs: Array<{ id: string; slug: string; name: string }>
  /** This server has no organization service configured: say so instead of "you are in none". */
  orgs_unavailable?: boolean
  /** Whether the client asked for `write`: otherwise only read is offered. */
  may_write: boolean
  /** Whether the grant will include the `agents` scope: it may work as any of the person's agents. */
  may_agents?: boolean
  /** The person's active agents (not connections), for "This connection works as". null: iam did not say; only the name field is offered. */
  agents?: Array<{ id: string; name: string }> | null
  /** Preselected: the agent this client last used, else the client's name. */
  suggested_agent?: string
  /** `agent:<name>@<handle>`. */
  actor: string
  /** The organization chosen last time, selected again. */
  remembered_org?: string | null
  /** The id the form posts back, tying the answer to this request and this person. */
  req: string
}

/** "This connection works as": the person's agents, or a new name. No script: a select and a text field. */
function picker(v: ConsentView, t: ReturnType<typeof strings>): string {
  const e = escapeHtml
  const list = v.agents ?? []
  const suggested = v.suggested_agent ?? ''
  const existing = list.some((a) => a.name === suggested)
  const options = list.length
    ? `<select name="default_agent">${list.map((a) => `<option value="${e(a.name)}"${a.name === suggested ? ' selected' : ''}>${e(a.name)}</option>`).join('')}<option value=""${existing ? '' : ' selected'}>${t('oauthAgentNew')}</option></select>`
    : ''
  return `<fieldset>
        <legend>${t('oauthWorksAs')}</legend>
        ${options}
        <label>${t('oauthAgentNewLabel')} <input type="text" name="new_agent" value="${existing ? '' : e(suggested)}" pattern="[a-z][a-z0-9\\-]{0,31}" maxlength="32" autocomplete="off" spellcheck="false"></label>
        <p class="quiet">${t('oauthWorksAsHint')}</p>
      </fieldset>`
}

export function consentPage(v: ConsentView): string {
  const e = escapeHtml
  const t = strings(v.view.lang)
  const product = v.view.brand.name
  const orgs = v.orgs.length
    ? `<label>${t('oauthOrg')} <select name="org_id" required>${v.orgs.map((o, i) => `<option value="${e(o.id)}"${(v.remembered_org ? o.id === v.remembered_org : i === 0) ? ' selected' : ''}>${e(o.name)}</option>`).join('')}</select></label>`
    : `<p class="quiet">${t(v.orgs_unavailable ? 'oauthOrgsUnavailable' : 'oauthNoOrg')}</p>`
  return layout({
    title: t('oauthTitle', { client: v.client_name }),
    view: v.view,
    body: `    <h1>${t('oauthTitle', { client: v.client_name })}</h1>
    ${v.client_host ? `<p class="quiet">${t('oauthClientHost', { host: v.client_host })}</p>` : ''}
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
      ${picker(v, t)}
      <p>${t('oauthActs', { actor: v.actor })}</p>
      ${v.may_agents ? `<p>${t('oauthAgents')}</p>` : ''}
      <button class="btn primary" type="submit" name="decision" value="approve">${t('oauthApprove')}</button>
      <button class="btn" type="submit" name="decision" value="deny">${t('oauthDeny')}</button>
    </form>`,
  })
}

/** A request that cannot be completed and cannot safely be sent back to the client (unknown client, redirect not registered). */
export function oauthProblemPage(view: PageView, problem: 'client' | 'redirect' | 'request' | 'expired' | 'person' | 'agent'): string {
  const t = strings(view.lang)
  const text = t(({ client: 'oauthBadClient', redirect: 'oauthBadRedirect', request: 'oauthBadRequest', expired: 'oauthExpired', person: 'oauthWrongPerson', agent: 'oauthBadAgent' } as const)[problem])
  return layout({
    title: t('oauthBad'),
    view,
    body: `    <h1>${t('oauthBad')}</h1>
    <p class="error" role="alert">${text}</p>
    <p class="quiet">${t('oauthBack')}</p>`,
  })
}
