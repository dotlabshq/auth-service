/**
 * What the pages look like, from configuration.
 *
 * auth-service signs people in for whatever product the realm is, so the name
 * on the page is that product's, not this service's. Everything here is
 * optional: with nothing set the pages are plain and say "Sign in".
 *
 *   AUTH_UI_NAME          the product's name                 "clave"
 *   AUTH_UI_LOGO_URL      an image shown beside the name
 *   AUTH_UI_HOME_URL      where the name links to            default `/`
 *   AUTH_UI_TERMS_URL     Terms of Service
 *   AUTH_UI_PRIVACY_URL   Privacy Policy
 *   AUTH_UI_ACCENT        button colour, `#rgb` or `#rrggbb`
 *
 * A link is a path on this origin or an http(s) URL; anything else is dropped,
 * so a typo in configuration cannot put a `javascript:` URL on the sign-in page.
 */

export interface Brand {
  name: string
  logoUrl?: string
  homeUrl: string
  termsUrl?: string
  privacyUrl?: string
  accent?: string
}

function link(raw: string | undefined): string | undefined {
  const v = (raw ?? '').trim()
  if (!v) return undefined
  if (v.startsWith('/')) return v.startsWith('//') ? undefined : v
  try {
    const u = new URL(v)
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.toString() : undefined
  } catch {
    return undefined
  }
}

export function brand(env: Record<string, string | undefined> = process.env): Brand {
  const accent = (env['AUTH_UI_ACCENT'] ?? '').trim()
  return {
    name: (env['AUTH_UI_NAME'] ?? '').trim(),
    logoUrl: link(env['AUTH_UI_LOGO_URL']),
    homeUrl: link(env['AUTH_UI_HOME_URL']) ?? '/',
    termsUrl: link(env['AUTH_UI_TERMS_URL']),
    privacyUrl: link(env['AUTH_UI_PRIVACY_URL']),
    accent: /^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i.test(accent) ? accent : undefined,
  }
}
