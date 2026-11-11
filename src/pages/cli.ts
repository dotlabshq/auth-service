import { escapeHtml } from '../lib/html.js'
import { publicUrls } from '../lib/urls.js'
import { layout, type PageView } from './layout.js'
import { strings } from './strings.js'

/**
 * The page where a person approves a terminal's sign-in.
 *
 * `state` arrives in the query string. It is checked to be one of ours before
 * this is called and escaped here regardless: echoed raw, `?state="><script>…`
 * once ran script on the realm's origin — the origin the session cookie lives on.
 */
export function cliApprovePage(opts: { view: PageView; state: string; who: string }): string {
  const e = escapeHtml
  const t = strings(opts.view.lang)
  return layout({
    title: t('cliTitle'),
    view: opts.view,
    body: `    <h1>${t('cliTitle')}</h1>
    <p>${t('cliAsk', { who: opts.who })}</p>
    <form class="stack" method="POST" action="${e(publicUrls().ui('/cli/approve'))}">
      <input type="hidden" name="state" value="${e(opts.state)}">
      <button class="btn primary" type="submit">${t('approve')}</button>
    </form>
    <p class="quiet">${t('cliNotYou')}</p>`,
  })
}

export function cliDonePage(opts: { view: PageView }): string {
  const t = strings(opts.view.lang)
  return layout({
    title: t('cliDoneTitle'),
    view: opts.view,
    body: `    <h1>${t('cliDoneTitle')}</h1>
    <p>${t('cliDone')}</p>`,
  })
}

/** A request this page cannot do anything with: said plainly, with the way out. */
export function cliProblemPage(opts: { view: PageView; problem: 'missing' | 'expired' | 'used' }): string {
  const t = strings(opts.view.lang)
  const text = t(({ missing: 'cliMissing', expired: 'cliExpired', used: 'cliUsed' } as const)[opts.problem])
  return layout({
    title: t('cliTitle'),
    view: opts.view,
    body: `    <h1>${t('cliTitle')}</h1>
    <p class="error" role="alert">${text}</p>`,
  })
}
