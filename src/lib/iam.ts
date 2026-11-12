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
  const token = await mintIdentityToken({ sub: serviceName(), type: 'service', expires_in_seconds: 60 })
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

/** What iam says a verified API token stands for (`/_/tokens/verify`, workspace ADR 0004). */
export interface VerifiedPrincipal {
  token_id: string
  kind: 'human' | 'agent' | 'machine'
  actor: string
  actor_id: string
  org_id: string | null
  expires_at: number | null
  on_behalf_of?: string
  access?: Array<'read' | 'write'>
  role?: string
}

export type Verification =
  | { status: 'ok'; principal: VerifiedPrincipal }
  | { status: 'invalid'; reason?: 'unsupported_credential' }
  | { status: 'unavailable' }
  | { status: 'unconfigured' }

const text = (v: unknown): v is string => typeof v === 'string' && v.length > 0

/**
 * Ask iam whether an API token (`bwt_…`) is live and what it stands for.
 *
 * `/_` is on iam's own address: `IAM_BASE_PATH` belongs to the published API
 * and is not used here. One answer for every way a token can be dead (unknown,
 * revoked, expired, an agent suspended or removed): `invalid`. iam not
 * answering, answering 5xx, or answering something that is not a principal is
 * `unavailable`: never a reason to let a token through.
 *
 * A live token that cannot stand in the realm (an agent with no person behind
 * it, such as the old organization keys of type `agent`; a machine with no role
 * or organization) is the credential's fault, not iam's: `invalid`, reason
 * `unsupported_credential`, so the caller gets 401 and not a 502 that reads as
 * an outage.
 */
export async function iamVerify(apiToken: string): Promise<Verification> {
  const url = (process.env['IAM_SERVICE_URL'] ?? '').replace(/\/+$/, '')
  if (!url) return { status: 'unconfigured' }
  const service = await mintIdentityToken({ sub: serviceName(), type: 'service', expires_in_seconds: 60 })
  if (!service) return { status: 'unavailable' }
  const res = await fetch(`${url}/_/tokens/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${service}` },
    body: JSON.stringify({ token: apiToken }),
  }).catch(() => null)
  if (!res) return { status: 'unavailable' }
  if (res.status === 401) return { status: 'invalid' }
  if (!res.ok) return { status: 'unavailable' }
  const p = ((await res.json().catch(() => null)) as { principal?: Record<string, unknown> } | null)?.principal
  if (!p || !text(p['token_id']) || !text(p['actor']) || !text(p['actor_id'])) return { status: 'unavailable' }
  const kind = p['kind']
  if (kind !== 'human' && kind !== 'agent' && kind !== 'machine') return { status: 'unavailable' }
  const org_id = text(p['org_id']) ? p['org_id'] : null
  const expires_at = typeof p['expires_at'] === 'number' ? p['expires_at'] : null
  const access = Array.isArray(p['access']) ? (p['access'].filter((a) => a === 'read' || a === 'write') as Array<'read' | 'write'>) : undefined
  if (kind === 'agent' && !text(p['on_behalf_of'])) return { status: 'invalid', reason: 'unsupported_credential' }
  if (kind === 'machine' && (!text(p['role']) || !org_id)) return { status: 'invalid', reason: 'unsupported_credential' }
  return {
    status: 'ok',
    principal: {
      token_id: p['token_id'], kind, actor: p['actor'], actor_id: p['actor_id'], org_id, expires_at,
      ...(kind === 'agent' ? { on_behalf_of: p['on_behalf_of'] as string } : {}),
      ...(kind === 'machine' ? { role: p['role'] as string } : {}),
      ...(access ? { access } : {}),
    },
  }
}
