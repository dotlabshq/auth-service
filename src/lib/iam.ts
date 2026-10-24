/**
 * Optional IAM delegation — identity only.
 *
 * When an `IAM_SERVICE_URL` is present — injected by a Flect service binding, so
 * the operator never types a URL — auth registers the OIDC identity with
 * iam-service (`POST /sync`) to get a stable platform user id. When it is absent,
 * auth is **login-only**: the OIDC subject IS the identity.
 *
 * auth does NOT deal in orgs, roles, or memberships — a user has no org of their
 * own, only memberships, so those are org-service questions. auth just resolves
 * "who is this user" and mints a `{ sub, type }` token.
 *
 * `iam-service` mounts `/sync` at the app root; a service binding resolves to
 * that root. When auth reaches IAM through a gateway (routes under `/v1/iam`),
 * set `IAM_BASE_PATH=/v1/iam`.
 */

import { mintIdentityToken } from './mint.js'

function iamBase(): string | null {
  const url = (process.env['IAM_SERVICE_URL'] ?? '').replace(/\/+$/, '')
  if (!url) return null
  const path = (process.env['IAM_BASE_PATH'] ?? '').replace(/\/+$/, '')
  return `${url}${path}`
}

export function iamEnabled(): boolean {
  return iamBase() !== null
}

export interface OidcIdentity {
  subject: string
  issuer: string
  email: string
  name?: string
  picture?: string
}

/**
 * The name auth signs its own service token with. iam accepts `/sync` only
 * from the services in its IAM_SYNC_CALLERS (default `auth-service`).
 */
const serviceName = () => process.env['AUTH_SERVICE_NAME'] ?? 'auth-service'

/**
 * Upsert the OIDC identity in IAM → the platform user id (or null on failure).
 *
 * Called with a short-lived service token auth signs for itself: iam no longer
 * takes an identity from just anyone, because whoever may call `/sync` decides
 * which email belongs to which account.
 */
export async function iamSync(id: OidcIdentity): Promise<string | null> {
  const base = iamBase()
  if (!base) return null
  const token = await mintIdentityToken({ sub: serviceName(), type: 'service', expiresInSeconds: 60 })
  if (!token) return null
  const res = await fetch(`${base}/sync`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify(id),
  }).catch(() => null)
  if (!res?.ok) return null
  const { user } = (await res.json().catch(() => ({}))) as { user?: { id?: string } }
  return user?.id ?? null
}
