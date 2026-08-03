import { Hono } from 'hono'
import { cliRouter } from '../routes/cli.js'
import { oidcRouter } from '../routes/oidc.js'

export const JWT_SECRET = 'test-secret-32-chars-long-enough!'
export const SESSION_COOKIE_NAME = 'oidc_session'

// Simple in-memory KV that satisfies the KvClient interface used by cliRouter.
export class InMemoryKv {
  private store = new Map<string, string>()
  async get(key: string) { return this.store.get(key) ?? null }
  async set(key: string, value: string, _opts?: { ttl?: number }) { this.store.set(key, value); return this }
  async del(key: string) { this.store.delete(key); return this }
  _raw() { return this.store }
}

/** Encode a session cookie value exactly as encodeSession() does in cookies.ts. */
export function makeSessionCookie(data: Record<string, unknown>) {
  return btoa(JSON.stringify(data)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function createTestApp() {
  process.env['JWT_SECRET'] = JWT_SECRET
  process.env['APP_PUBLIC_URL'] = 'http://localhost'
  delete process.env['IAM_SERVICE_URL']

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
