/**
 * Tokens that are not a browser login: a service acting as itself, and a
 * narrowed token derived from a human's.
 *
 * These exist because ES256 takes minting away from everyone but this service.
 * Under the shared HS256 secret any service could sign whatever it liked — and
 * some did, including a product API minting `{ sub: <another user> }` to act on
 * that user's behalf. Removing the secret without replacing those two needs
 * would simply break them, so both are served here, deliberately narrower than
 * what the secret allowed:
 *
 *   /service-token  a service gets a token for ITSELF and nobody else
 *   /exchange       a human's token is narrowed, never widened
 *
 * Neither can produce a token for an arbitrary user. That door is now closed.
 */

import { Hono } from 'hono'
import { timingSafeEqual } from 'node:crypto'
import { verifier } from '@baseworks/auth/identity'
import { mintIdentityToken } from '../lib/mint.js'
import { realm } from '../lib/realm.js'

/** Ceiling for both kinds. Short by design: neither is meant to be carried around. */
const MAX_TTL = 3600
const DEFAULT_TTL = 3600

/**
 * `AUTH_SERVICE_CLIENTS=zone9-api:secret1,billing:secret2`
 *
 * One secret per service, so a leaked secret speaks for that service alone.
 * This is the whole improvement over the shared signing secret, which spoke for
 * everyone including users.
 */
function serviceClients(env: NodeJS.ProcessEnv): Map<string, string> {
  const raw = env['AUTH_SERVICE_CLIENTS'] ?? ''
  const out = new Map<string, string>()
  for (const entry of raw.split(',').map((s) => s.trim()).filter(Boolean)) {
    const at = entry.indexOf(':')
    if (at <= 0) continue
    out.set(entry.slice(0, at), entry.slice(at + 1))
  }
  return out
}

/** Constant-time compare; lengths differ often enough that a plain === leaks. */
function secretMatches(given: string, expected: string): boolean {
  const a = Buffer.from(given)
  const b = Buffer.from(expected)
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

function clampTtl(requested: unknown): number {
  const n = typeof requested === 'number' ? requested : DEFAULT_TTL
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_TTL
  return Math.min(Math.floor(n), MAX_TTL)
}

export function tokensRouter() {
  const app = new Hono()

  // POST /service-token — client credentials for a service's own identity.
  app.post('/service-token', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      client_id?: string
      client_secret?: string
      expires_in?: number
    }

    const clients = serviceClients(process.env)
    if (clients.size === 0) {
      return c.json({ error: 'no service clients configured' }, 503)
    }

    const id = body.client_id ?? ''
    const expected = clients.get(id)
    // Same answer whether the id is unknown or the secret is wrong: telling
    // them apart turns this endpoint into a list of which services exist.
    if (!id || !expected || !body.client_secret || !secretMatches(body.client_secret, expected)) {
      return c.json({ error: 'invalid_client' }, 401)
    }

    const expiresIn = clampTtl(body.expires_in)
    const token = await mintIdentityToken({ sub: id, type: 'service', expiresInSeconds: expiresIn })
    if (!token) return c.json({ error: 'realm has no signing key configured' }, 500)

    return c.json({ token, token_type: 'bearer', expires_in: expiresIn })
  })

  // POST /exchange — narrow the caller's own token.
  app.post('/exchange', async (c) => {
    const header = c.req.header('Authorization')
    if (!header?.startsWith('Bearer ')) return c.json({ error: 'unauthorized' }, 401)

    const r = await realm()
    const verify = verifier({
      ...(r.jwks ? { jwks: r.jwks } : {}),
      ...(r.issuer ? { issuer: r.issuer } : {}),
      ...(r.audience ? { audience: r.audience } : {}),
      ...(r.legacySecret ? { legacyHs256Secret: r.legacySecret } : {}),
    })

    const claims = await verify(header.slice(7))
    if (!claims?.sub) return c.json({ error: 'unauthorized' }, 401)

    // Only a human token may be narrowed. Allowing a service or an already
    // narrowed token to exchange would build chains that outlive and outreach
    // the sign-in they came from.
    if (claims.type !== 'human') {
      return c.json({ error: 'only a human token can be exchanged' }, 403)
    }

    const body = (await c.req.json().catch(() => ({}))) as {
      org_id?: string
      scope?: string
      expires_in?: number
    }

    const expiresIn = clampTtl(body.expires_in)
    const token = await mintIdentityToken({
      sub: claims.sub,
      type: 'assistant',
      expiresInSeconds: expiresIn,
      claims: {
        // `org_id` is a RESTRICTION, not a grant: it says "only this org".
        // Membership is still the consuming service's question to ask, because
        // auth deals in identity and knows nothing about orgs.
        ...(body.org_id ? { org_id: body.org_id } : {}),
        ...(body.scope ? { scope: body.scope } : {}),
      },
    })
    if (!token) return c.json({ error: 'realm has no signing key configured' }, 500)

    return c.json({ token, token_type: 'bearer', expires_in: expiresIn })
  })

  return app
}
