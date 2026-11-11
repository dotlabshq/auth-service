import { escapeHtml } from '../lib/html.js'
import { publicUrls } from '../lib/urls.js'
import { layout } from './layout.js'

/**
 * The page where a person approves a terminal's sign-in.
 *
 * `state` arrives in the query string. It is checked to be one of ours before
 * this is called and escaped here regardless: echoed raw, `?state="><script>…`
 * once ran script on the realm's origin — the origin the session cookie lives on.
 */
export function cliApprovePage(opts: { state: string; who: string }): string {
  const e = escapeHtml
  return layout({
    title: 'Authorize the CLI',
    body: `    <h1>Authorize the CLI</h1>
    <p>A terminal is asking to sign in as <strong>${e(opts.who)}</strong>. Approve only if you started this yourself, just now.</p>
    <form class="stack" method="POST" action="${e(publicUrls().ui('/cli/approve'))}">
      <input type="hidden" name="state" value="${e(opts.state)}">
      <button class="btn primary" type="submit">Approve</button>
    </form>
    <p class="quiet">Not you? Close this tab and nothing happens.</p>`,
  })
}

export function cliDonePage(): string {
  return layout({
    title: 'Authorized',
    body: `    <h1>Authorized</h1>
    <p>Your terminal is signed in. You can close this tab.</p>`,
  })
}

/** A request this page cannot do anything with: said plainly, with the way out. */
export function cliProblemPage(problem: 'missing' | 'expired' | 'used'): string {
  const text = {
    missing: 'This link is incomplete. Run the login command again and open the link it prints.',
    expired: 'This sign-in request has expired or was never made. Run the login command again.',
    used: 'This sign-in request was already approved. If your terminal is not signed in, run the login command again.',
  }[problem]
  return layout({
    title: 'Authorize the CLI',
    body: `    <h1>Authorize the CLI</h1>
    <p class="error" role="alert">${escapeHtml(text)}</p>`,
  })
}
