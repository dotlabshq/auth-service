/** What auth-service asks iam, for OAuth (`/_/oauth/*`, iam's internal routes; see iam's README). */
import { orgServiceUrl } from './config.js'
import { mintIdentityToken } from '../mint.js'

const serviceName = () => process.env['AUTH_SERVICE_NAME'] ?? 'auth-service'

export interface IamAnswer<T = Record<string, any>> { status: number; data: T }

/** One call, as the service. `status` 0: iam is not configured or did not answer. */
export async function iamOauth<T = Record<string, any>>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<IamAnswer<T>> {
  const base = (process.env['IAM_SERVICE_URL'] ?? '').replace(/\/+$/, '')
  if (!base) return { status: 0, data: {} as T }
  const token = await mintIdentityToken({ sub: serviceName(), type: 'service', expires_in_seconds: 60 })
  if (!token) return { status: 0, data: {} as T }
  const res = await fetch(`${base}/_/oauth${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }).catch(() => null)
  if (!res) return { status: 0, data: {} as T }
  return { status: res.status, data: ((await res.json().catch(() => ({}))) as T) }
}

export interface Membership { id: string; slug: string; name: string }

/** The organizations a person is in, asked of org-service as that person. None when org-service is not configured or does not answer. */
export async function membershipsOf(user_id: string): Promise<Membership[]> {
  const base = orgServiceUrl()
  if (!base) return []
  const token = await mintIdentityToken({ sub: user_id, type: 'human', expires_in_seconds: 60 })
  if (!token) return []
  const res = await fetch(`${base}/api/orgs`, { headers: { authorization: `Bearer ${token}` } }).catch(() => null)
  if (!res?.ok) return []
  const { orgs } = (await res.json().catch(() => ({}))) as { orgs?: Array<{ id?: unknown; slug?: unknown; name?: unknown }> }
  return (orgs ?? []).flatMap((o) => (typeof o.id === 'string' && typeof o.slug === 'string' ? [{ id: o.id, slug: o.slug, name: typeof o.name === 'string' ? o.name : o.slug }] : []))
}
