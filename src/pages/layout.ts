import type { Context } from 'hono'
import { getCookie } from 'hono/cookie'
import { layout as frame, pagePrefs, PAGE_HEADERS, type Brand, type Lang, type Theme } from '@baseworks/core/pages'
import { brand as readBrand } from '../lib/brand.js'

/** What a page needs to know about the request it is drawn for. */
export interface PageView {
  lang: Lang
  theme: Theme
  brand: Brand
}

/**
 * The language, theme and branding for this request. A `?lang=` or `?theme=`
 * on the link is remembered in a cookie on the host, so the pages after a
 * sign-in's trip to the provider and back are still in the person's language.
 */
export function view(c: Context): PageView {
  const prefs = pagePrefs({
    query: (name) => c.req.query(name),
    cookie: (name) => getCookie(c, name),
    acceptLanguage: c.req.header('accept-language'),
    secure: process.env['NODE_ENV'] === 'production',
  })
  for (const cookie of prefs.setCookies) c.header('Set-Cookie', cookie, { append: true })
  return { lang: prefs.lang, theme: prefs.theme, brand: readBrand() }
}

/**
 * The frame every page of this service is drawn in. It is the realm's frame
 * (`@baseworks/core/pages`), shared with org-service's pages, so sign-in and
 * what comes after it read as one system. A new screen is a function that
 * returns the `body` of this.
 */
export function layout(opts: { title: string; body: string; view: PageView }): string {
  return frame({
    title: opts.title,
    body: `    <div class="card"><div class="body">\n${opts.body}\n    </div></div>`,
    brand: opts.view.brand,
    lang: opts.view.lang,
    theme: opts.view.theme,
    width: 'narrow',
  })
}

/** Send a page, with the headers every page carries (no framing, no script, no cache). */
export function respond(c: Context, html: string, status: 200 | 400 | 401 | 404 | 409 | 500 = 200): Response {
  for (const [name, value] of Object.entries(PAGE_HEADERS)) c.header(name, value)
  return c.html(html, status)
}
