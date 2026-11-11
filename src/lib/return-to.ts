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

// The rule itself lives with the page frame, because org-service's pages need
// the same one: a second copy of an open-redirect check is a second place to
// get it wrong.
export { safeReturnTo } from '@baseworks/core/pages'
import { returnOrigins as realmReturnOrigins } from '@baseworks/core/pages'

/** The origins this realm will return to: `APP_PUBLIC_URL` plus `AUTH_RETURN_ORIGINS`. */
export function returnOrigins(env: Record<string, string | undefined>): string[] {
  return realmReturnOrigins(env, 'AUTH_RETURN_ORIGINS')
}
