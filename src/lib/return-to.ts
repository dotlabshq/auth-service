/**
 * Where a sign-in or sign-out is allowed to send the browser afterwards.
 *
 * `?returnTo=` is attacker-controllable and unauthenticated — anyone can hand
 * out `…/v1/auth/login?returnTo=https://evil.example`, and the victim arrives
 * there having just been through a real sign-in on a real domain. That is the
 * whole of an open redirect: no cookie leaks, and it still works as phishing.
 *
 * So two forms are allowed and nothing else:
 *
 *   · a path on whatever origin the browser is already on — `/entries`;
 *   · an absolute URL whose origin is one this realm publishes.
 *
 * The second exists because a realm can serve more than one surface: the
 * console on its origin and a product on its own. The callback lands on the one
 * origin registered with the OIDC provider, and the return hop is what gets the
 * person to the surface they started from.
 *
 * Anything else becomes `/` — refused quietly rather than with an error, because
 * a user who followed a poisoned link has done nothing they need to be told off
 * about, and the page they wanted was never real.
 */

/** The origins this realm will return to: `APP_PUBLIC_URL` plus any extras. */
export function returnOrigins(env: Record<string, string | undefined>): string[] {
  const out: string[] = []
  for (const raw of [env['APP_PUBLIC_URL'], ...(env['AUTH_RETURN_ORIGINS'] ?? '').split(',')]) {
    const v = (raw ?? '').trim()
    if (!v) continue
    try {
      out.push(new URL(v).origin)
    } catch {
      // A misconfigured origin is dropped rather than widening the allowlist.
    }
  }
  return [...new Set(out)]
}

/**
 * A `returnTo` that is safe to put in a `Location` header, or `/`.
 *
 * A path must start with a single `/`. `//evil.example` is protocol-relative
 * and a browser reads it as another origin; `/\evil.example` is normalised to
 * the same thing by several of them. Both look like paths and are not.
 */
export function safeReturnTo(raw: string | undefined, allowed: string[]): string {
  const value = (raw ?? '').trim()
  if (!value) return '/'

  if (value.startsWith('/')) {
    return value.length > 1 && (value[1] === '/' || value[1] === '\\') ? '/' : value
  }

  try {
    const url = new URL(value)
    if ((url.protocol === 'http:' || url.protocol === 'https:') && allowed.includes(url.origin)) {
      return url.toString()
    }
  } catch {
    // Not a URL at all — a bare word, a `javascript:` payload, whatever.
  }
  return '/'
}
