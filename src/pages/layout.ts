import type { Context } from 'hono'
import { brand as readBrand, type Brand } from '../lib/brand.js'
import { escapeHtml } from '../lib/html.js'

/**
 * The frame every page of this service is drawn in: the product's name at the
 * top, one column of content, the legal links at the bottom.
 *
 * Plain HTML with the stylesheet inline. No script and nothing fetched from
 * elsewhere, which is what lets `respond()` send a policy that allows neither.
 * A new screen is a function that returns the `body` of this.
 */
export function layout(opts: { title: string; body: string; brand?: Brand }): string {
  const b = opts.brand ?? readBrand()
  const e = escapeHtml
  const mark = [
    b.logoUrl ? `<img src="${e(b.logoUrl)}" alt="" height="24">` : '',
    b.name ? `<span>${e(b.name)}</span>` : '',
  ].join('')
  const legal = [
    b.termsUrl ? `<a href="${e(b.termsUrl)}">Terms of Service</a>` : '',
    b.privacyUrl ? `<a href="${e(b.privacyUrl)}">Privacy Policy</a>` : '',
  ].filter(Boolean).join('<span aria-hidden="true">·</span>')

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex">
  <title>${e(b.name ? `${opts.title} · ${b.name}` : opts.title)}</title>
  <style>
    :root {
      --bg: #f6f6f4; --card: #fff; --ink: #16161a; --muted: #62626b; --line: #dcdcd6;
      --accent: ${b.accent ?? '#16161a'}; --on-accent: #fff; --danger: #b3261e; --warn-bg: #fff4e0; --warn-ink: #8a4b00;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #111114; --card: #1b1b20; --ink: #f1f1ee; --muted: #a3a3ad; --line: #33333b;
        --accent: ${b.accent ?? '#f1f1ee'}; --on-accent: ${b.accent ? '#fff' : '#111114'}; --danger: #ff8a80; --warn-bg: #3a2a10; --warn-ink: #ffd08a;
      }
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0 }
    body {
      min-height: 100vh; display: flex; flex-direction: column; align-items: center;
      font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
      background: var(--bg); color: var(--ink); padding: 24px 16px;
    }
    header { width: 100%; max-width: 380px; min-height: 28px }
    .brand { display: inline-flex; align-items: center; gap: 8px; font-weight: 650; font-size: 17px; color: inherit; text-decoration: none }
    main {
      width: 100%; max-width: 380px; margin: auto 0; padding: 32px 28px;
      background: var(--card); border: 1px solid var(--line); border-radius: 14px;
      display: flex; flex-direction: column; gap: 14px;
    }
    h1 { font-size: 22px; font-weight: 650; line-height: 1.25 }
    p { color: var(--muted); font-size: 14px }
    .stack { display: flex; flex-direction: column; gap: 10px; margin-top: 6px }
    .btn {
      display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%;
      padding: 11px 14px; font: inherit; font-weight: 600; font-size: 14px; text-decoration: none; cursor: pointer;
      color: var(--ink); background: var(--card); border: 1px solid var(--line); border-radius: 9px;
    }
    .btn:hover { border-color: var(--muted) }
    .btn.primary { color: var(--on-accent); background: var(--accent); border-color: var(--accent) }
    .btn.primary:hover { opacity: .9 }
    .btn:focus-visible, input:focus-visible, a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px }
    input[type=text], input[type=password] {
      width: 100%; padding: 10px 12px; font: inherit; font-size: 14px;
      color: var(--ink); background: var(--card); border: 1px solid var(--line); border-radius: 9px;
    }
    label { font-size: 13px; font-weight: 600; display: flex; flex-direction: column; gap: 5px }
    .or { display: flex; align-items: center; gap: 12px; color: var(--muted); font-size: 12px }
    .or::before, .or::after { content: ""; flex: 1; border-top: 1px solid var(--line) }
    .quiet { color: var(--muted); font-size: 13px; text-align: center }
    .quiet a, footer a { color: inherit }
    .error { color: var(--danger); font-size: 14px }
    .tag { align-self: flex-start; font-size: 11px; font-weight: 700; letter-spacing: .06em; color: var(--warn-ink); background: var(--warn-bg); padding: 3px 8px; border-radius: 999px }
    footer { width: 100%; max-width: 380px; min-height: 20px; display: flex; justify-content: center; gap: 8px; color: var(--muted); font-size: 12px }
  </style>
</head>
<body>
  <header>${mark ? `<a class="brand" href="${e(b.homeUrl)}">${mark}</a>` : ''}</header>
  <main>
${opts.body}
  </main>
  <footer>${legal}</footer>
</body>
</html>`
}

/**
 * Send a page. The headers are the same for every one of them:
 *
 *  · never framed — the approve page is one button, and a button that can be
 *    laid under someone else's page is a button they can be made to press;
 *  · no script, no outside resources — nothing a page echoes could run even if
 *    an escape were missed;
 *  · never cached — a page drawn for a signed-in person must not be shown to
 *    the next one from a proxy's memory.
 */
export function respond(c: Context, html: string, status: 200 | 400 | 401 | 404 | 409 | 500 = 200): Response {
  c.header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' https: data:; base-uri 'none'; frame-ancestors 'none'")
  c.header('X-Frame-Options', 'DENY')
  c.header('Referrer-Policy', 'same-origin')
  c.header('Cache-Control', 'no-store')
  return c.html(html, status)
}
