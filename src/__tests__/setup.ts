import { Hono } from 'hono'
import { signHs256Jwt } from '@baseworks/auth/jwt'
import { cliRouter } from '../routes/cli.js'
import { oidcRouter } from '../routes/oidc.js'

export const JWT_SECRET = 'test-secret-32-chars-long-enough!'
export const IAM_URL = 'http://iam.test'
export const SESSION_COOKIE_NAME = 'oidc_session'

// Simple in-memory KV that satisfies the KvClient interface used by cliRouter.
export class InMemoryKv {
  private store = new Map<string, string>()
  async get(key: string) { return this.store.get(key) ?? null }
  async set(key: string, value: string, _opts?: { ttl?: number }) { this.store.set(key, value); return this }
  async del(key: string) { this.store.delete(key); return this }
  _raw() { return this.store }
}

/** Identity JWT — no org_id, as issued right after OIDC approve. */
export function makeIdentityToken(userId: string) {
  return signHs256Jwt({ sub: userId, type: 'human' }, JWT_SECRET, 3600)
}

/** Org-scoped JWT — as issued by token-for-org. */
export function makeOrgToken(userId: string, orgId: string, role = 'member') {
  return signHs256Jwt({ sub: userId, org_id: orgId, role, type: 'human' }, JWT_SECRET, 3600)
}

/** Encode a session cookie value exactly as encodeSession() does in cookies.ts. */
export function makeSessionCookie(data: Record<string, unknown>) {
  return btoa(JSON.stringify(data)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Stand in for iam-service by intercepting global fetch to IAM_URL. `orgsByUser`
 * maps a caller's user id (read from the bootstrap token) to the orgs IAM reports
 * for them via `GET /orgs`. Returns a restore function.
 */
export function installIamMock(orgsByUser: Record<string, Array<{ id: string; role: string }>>) {
  const real = globalThis.fetch
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url.startsWith(IAM_URL)) {
      const authz = (init?.headers as Record<string, string> | undefined)?.['Authorization'] ?? ''
      const token = authz.replace(/^Bearer\s+/i, '')
      const seg = token.split('.')[1] ?? ''
      const payload = seg ? JSON.parse(Buffer.from(seg, 'base64url').toString()) as { sub?: string } : {}
      const userId = payload.sub ?? ''
      if (url.endsWith('/orgs') && (init?.method ?? 'GET') === 'GET') {
        return new Response(JSON.stringify({ orgs: orgsByUser[userId] ?? [] }), {
          status: 200, headers: { 'content-type': 'application/json' },
        })
      }
      return new Response('{}', { status: 404 })
    }
    return real(input as RequestInfo | URL, init)
  }) as typeof fetch
  return () => { globalThis.fetch = real }
}

export async function createTestApp(opts: { iam?: boolean } = {}) {
  process.env['JWT_SECRET'] = JWT_SECRET
  process.env['APP_PUBLIC_URL'] = 'http://localhost'
  if (opts.iam) process.env['IAM_SERVICE_URL'] = IAM_URL
  else delete process.env['IAM_SERVICE_URL']

  const kv = new InMemoryKv()

  const app = new Hono()
  app.route('/', oidcRouter())
  app.route('/', cliRouter(kv as never))

  function req(method: string, path: string, o: {
    body?: unknown
    token?: string
    cookie?: string
    contentType?: string
  } = {}) {
    const headers: Record<string, string> = {}
    if (o.token) headers['Authorization'] = `Bearer ${o.token}`
    if (o.body !== undefined) headers['Content-Type'] = o.contentType ?? 'application/json'
    if (o.cookie) headers['Cookie'] = o.cookie
    const init: RequestInit = { method, headers }
    if (o.body !== undefined) init.body = JSON.stringify(o.body)
    return app.fetch(new Request(`http://localhost${path}`, init))
  }

  return {
    kv,
    get:  (path: string, o?: Parameters<typeof req>[2]) => req('GET', path, o),
    post: (path: string, body: unknown, o?: Omit<Parameters<typeof req>[2], 'body'>) =>
      req('POST', path, { body, ...o }),
  }
}
