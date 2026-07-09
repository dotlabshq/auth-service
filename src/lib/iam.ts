import { signHs256Jwt } from '@baseworks/auth/jwt'

/**
 * Optional IAM delegation.
 *
 * When an `IAM_SERVICE_URL` is present — injected by a Flect service binding, so
 * the operator never types a URL — auth delegates identity + org management to
 * iam-service. When it is absent, auth is **login-only**: it mints a JWT straight
 * from the OIDC identity and owns no user/org data (and no database) at all.
 *
 * `iam-service` mounts its routes at the app root (`/sync`, `/me`, `/orgs`). A
 * service binding resolves to that root, so no path prefix is needed; when auth
 * reaches IAM through a gateway instead (routes under `/v1/iam`), set
 * `IAM_BASE_PATH=/v1/iam`.
 */

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

/** Upsert the OIDC identity in IAM → the platform user id (or null on failure). */
export async function iamSync(id: OidcIdentity): Promise<string | null> {
  const base = iamBase()
  if (!base) return null
  const res = await fetch(`${base}/sync`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(id),
  }).catch(() => null)
  if (!res?.ok) return null
  const { user } = (await res.json().catch(() => ({}))) as { user?: { id?: string } }
  return user?.id ?? null
}

/** A 60s token authenticating AS the synced user (IAM verifies it via JWT_SECRET). */
function bootstrapToken(userId: string): string | null {
  const secret = process.env['JWT_SECRET']
  if (!secret) return null
  return signHs256Jwt({ sub: userId, type: 'human' }, secret, 60)
}

/**
 * The user's current org id — read from IAM, creating a default org (with the
 * user as founding owner) when they have none and `CREATE_DEFAULT_ORG=true`.
 * Retries the slug with a numeric suffix so a second identity sharing an email
 * prefix doesn't collide on the unique org slug.
 */
export async function iamEnsureOrg(userId: string, emailOrName: string): Promise<string | undefined> {
  const base = iamBase()
  const token = bootstrapToken(userId)
  if (!base || !token) return undefined
  const auth = { Authorization: `Bearer ${token}` }

  const me = await fetch(`${base}/me`, { headers: auth }).catch(() => null)
  if (me?.ok) {
    const body = (await me.json().catch(() => ({}))) as { org?: { id?: string } | null }
    if (body.org?.id) return body.org.id
  }

  if (process.env['CREATE_DEFAULT_ORG'] !== 'true') return undefined

  const name = emailOrName.includes('@') ? emailOrName.split('@')[0]! : emailOrName
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'my-org'
  for (let i = 1; i <= 5; i++) {
    const res = await fetch(`${base}/orgs`, {
      method: 'POST',
      headers: { ...auth, 'content-type': 'application/json' },
      body: JSON.stringify({ name, slug: i === 1 ? slug : `${slug}-${i}` }),
    }).catch(() => null)
    if (res?.ok) {
      const { org } = (await res.json().catch(() => ({}))) as { org?: { id?: string } }
      return org?.id
    }
    // Only a slug collision is worth retrying; anything else is terminal.
    if (!res || (res.status !== 409 && res.status !== 500)) break
  }
  return undefined
}

/** The user's role in `orgId` (IAM mode) — verifies membership, or null. */
export async function iamMembershipRole(userId: string, orgId: string): Promise<string | null> {
  const base = iamBase()
  const token = bootstrapToken(userId)
  if (!base || !token) return null
  const res = await fetch(`${base}/orgs`, { headers: { Authorization: `Bearer ${token}` } }).catch(() => null)
  if (!res?.ok) return null
  const { orgs } = (await res.json().catch(() => ({}))) as { orgs?: Array<{ id?: string; role?: string }> }
  return orgs?.find((o) => o.id === orgId)?.role ?? null
}
