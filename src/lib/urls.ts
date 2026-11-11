/**
 * Where the browser and other services reach this service.
 *
 * The service mounts its pages under `/ui` and its API under `/api`, and
 * knows nothing about where a gateway publishes either (ADR-042 §4). But a
 * redirect, a form action and the OIDC `redirect_uri` are addresses the
 * *browser* follows, so they have to be the published ones. Those come from
 * configuration and from nowhere else:
 *
 *   APP_PUBLIC_URL   the origin the browser is on          https://example.com
 *   AUTH_UI_PATH     where the gateway publishes `/ui`      default `/auth`
 *   AUTH_API_PATH    where the gateway publishes `/api`    default `/v1/auth`
 *
 * Run alone on a port, with no gateway in front: `AUTH_UI_PATH=/ui` and
 * `AUTH_API_PATH=/api`, and every address below is the service's own.
 *
 * With no `APP_PUBLIC_URL` the addresses are root-relative, which a browser
 * resolves against the origin it is already on.
 */

function prefix(raw: string | undefined, fallback: string): string {
  if (raw === undefined) return fallback
  const v = raw.trim().replace(/\/+$/, '')
  if (!v) return ''
  return v.startsWith('/') ? v : `/${v}`
}

export interface PublicUrls {
  /** The browser's origin, no trailing slash. Empty when not configured. */
  origin: string
  /** A page of this service as the browser reaches it: `ui('/login')`. */
  ui(path?: string): string
  /** The same, without the origin — what a `returnTo` may carry. */
  uiPath(path?: string): string
  /** An API endpoint as a caller outside reaches it: `api('/token')`. */
  api(path?: string): string
  /** The `redirect_uri` registered with the identity provider. */
  callback: string
}

export function publicUrls(env: Record<string, string | undefined> = process.env): PublicUrls {
  const origin = (env['APP_PUBLIC_URL'] ?? '').trim().replace(/\/+$/, '')
  const uiPrefix = prefix(env['AUTH_UI_PATH'], '/auth')
  const apiPrefix = prefix(env['AUTH_API_PATH'], '/v1/auth')
  const ui = (path = '') => `${origin}${uiPrefix}${path}`
  return {
    origin,
    ui,
    uiPath: (path = '') => `${uiPrefix}${path}`,
    api: (path = '') => `${origin}${apiPrefix}${path}`,
    // The provider compares this byte for byte with what is registered on the
    // OIDC app. OIDC_REDIRECT_URI pins it for a realm whose app still lists
    // the address it had before 2.0 (`…/v1/auth/oidc/callback`).
    callback: (env['OIDC_REDIRECT_URI'] ?? '').trim() || ui('/oidc/callback'),
  }
}
