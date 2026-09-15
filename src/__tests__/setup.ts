import { Hono } from 'hono'
import { encodeSession } from '../lib/cookies.js'
import { cliRouter } from '../routes/cli.js'
import { oidcRouter } from '../routes/oidc.js'

export const JWT_SECRET = 'test-secret-32-chars-long-enough!'
// Set at import time: a test may build a cookie before createTestApp() runs,
// and the cookie's tag has to be keyed the same way the service will key it.
process.env['JWT_SECRET'] = JWT_SECRET
export const SESSION_COOKIE_NAME = 'oidc_session'

// Simple in-memory KV that satisfies the KvClient interface used by cliRouter.
export class InMemoryKv {
  private store = new Map<string, string>()
  async get(key: string) { return this.store.get(key) ?? null }
  async set(key: string, value: string, _opts?: { ttl?: number }) { this.store.set(key, value); return this }
  async del(key: string) { this.store.delete(key); return this }
  _raw() { return this.store }
}

/**
 * A session cookie the service will accept: payload plus the HMAC tag, keyed
 * the way cookies.ts derives it from JWT_SECRET. A test that hand-rolled the
 * base64 would now be testing forgery, which is a different test (and there is
 * one).
 */
export function makeSessionCookie(data: Record<string, unknown>) {
  return encodeSession(data as never, { JWT_SECRET } as NodeJS.ProcessEnv)
}

/** The same payload with no tag — what an attacker can build unaided. */
export function makeForgedSessionCookie(data: Record<string, unknown>) {
  return Buffer.from(JSON.stringify(data), 'utf8').toString('base64url')
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
    /** Sent verbatim — for a form post, whose body is not JSON. */
    rawBody?: string
    token?: string
    cookie?: string
    contentType?: string
  } = {}) {
    const headers: Record<string, string> = {}
    if (o.token) headers['Authorization'] = `Bearer ${o.token}`
    if (o.body !== undefined) headers['Content-Type'] = o.contentType ?? 'application/json'
    if (o.cookie) headers['Cookie'] = o.cookie
    const init: RequestInit = { method, headers }
    if (o.rawBody !== undefined) {
      headers['Content-Type'] = o.contentType ?? 'application/x-www-form-urlencoded'
      init.body = o.rawBody
    } else if (o.body !== undefined) {
      init.body = JSON.stringify(o.body)
    }
    return app.fetch(new Request(`http://localhost${path}`, init))
  }

  return {
    kv,
    get:  (path: string, o?: Parameters<typeof req>[2]) => req('GET', path, o),
    post: (path: string, body: unknown, o?: Omit<Parameters<typeof req>[2], 'body'>) =>
      req('POST', path, { body, ...o }),
    postForm: (path: string, form: string, o?: Omit<Parameters<typeof req>[2], 'body' | 'rawBody'>) =>
      req('POST', path, { rawBody: form, ...o }),
  }
}
