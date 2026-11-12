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
import { iamVerify } from '../lib/iam.js'
import { realm } from '../lib/realm.js'
import { audit, envelopeOf, request } from '../lib/audit.js'
import { principalOf } from '@baseworks/auth/principal'

/** Ceiling for both kinds. Short by design: neither is meant to be carried around. */
const MAX_TTL = 3600
const DEFAULT_TTL = 3600
/** What an API token is exchanged for lives this long at most: a revoked one works that long. */
const EXCHANGE_TTL = 300

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

    const req = request(c)
    const offered = typeof body.client_id === 'string' ? body.client_id.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64) : ''
    const clients = serviceClients(process.env)
    if (clients.size === 0) {
      audit('service_token', { ...req, outcome: 'refused', reason: 'no_clients_configured' })
      return c.json({ error: 'no service clients configured' }, 503)
    }

    const id = body.client_id ?? ''
    const expected = clients.get(id)
    // Same answer whether the id is unknown or the secret is wrong: telling
    // them apart turns this endpoint into a list of which services exist.
    if (!id || !expected || !body.client_secret || !secretMatches(body.client_secret, expected)) {
      audit('service_token', { ...req, outcome: 'refused', reason: 'invalid_client', ...(offered ? { client_id: offered } : {}) })
      return c.json({ error: 'invalid_client' }, 401)
    }

    const expiresIn = clampTtl(body.expires_in)
    const token = await mintIdentityToken({ sub: id, type: 'service', expires_in_seconds: expiresIn })
    if (!token) {
      audit('service_token', { ...req, outcome: 'refused', reason: 'no_signing_key', ...envelopeOf(principalOf({ sub: id, type: 'service' })) })
      return c.json({ error: 'realm has no signing key configured' }, 500)
    }

    audit('service_token', { ...req, outcome: 'ok', ...envelopeOf(principalOf({ sub: id, type: 'service' })) })
    return c.json({ token, token_type: 'bearer', expires_in: expiresIn })
  })

  // POST /exchange — narrow the caller's own token.
  app.post('/exchange', async (c) => {
    const req = request(c)
    const header = c.req.header('Authorization')
    if (!header?.startsWith('Bearer ')) {
      audit('exchange', { ...req, outcome: 'refused', reason: 'no_bearer' })
      return c.json({ error: 'unauthorized' }, 401)
    }

    const r = await realm()
    const verify = verifier({
      ...(r.jwks ? { jwks: r.jwks } : {}),
      ...(r.issuer ? { issuer: r.issuer } : {}),
      ...(r.audience ? { audience: r.audience } : {}),
      ...(r.legacy_secret ? { legacy_hs256_secret: r.legacy_secret } : {}),
    })

    const claims = await verify(header.slice(7))
    if (!claims?.sub) {
      audit('exchange', { ...req, outcome: 'refused', reason: 'invalid_token' })
      return c.json({ error: 'unauthorized' }, 401)
    }
    const caller = principalOf(claims)

    // Only a human token may be narrowed. Allowing a service or an already
    // narrowed token to exchange would build chains that outlive and outreach
    // the sign-in they came from.
    if (claims.type !== 'human') {
      audit('exchange', { ...req, outcome: 'refused', reason: 'not_human', ...envelopeOf(caller) })
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
      expires_in_seconds: expiresIn,
      claims: {
        // `org_id` is a RESTRICTION, not a grant: it says "only this org".
        // Membership is still the consuming service's question to ask, because
        // auth deals in identity and knows nothing about orgs.
        ...(body.org_id ? { org_id: body.org_id } : {}),
        ...(body.scope ? { scope: body.scope } : {}),
      },
    })
    if (!token) {
      audit('exchange', { ...req, outcome: 'refused', reason: 'no_signing_key', ...envelopeOf(caller) })
      return c.json({ error: 'realm has no signing key configured' }, 500)
    }

    // The person who narrowed their own token; `org_id` is the restriction they asked for.
    audit('exchange', { ...req, outcome: 'ok', ...envelopeOf(caller, undefined, typeof body.org_id === 'string' ? body.org_id : undefined) })
    return c.json({ token, token_type: 'bearer', expires_in: expiresIn })
  })

  /**
   * POST /exchange-key — an API token (`bwt_…`) for a realm token (workspace
   * ADR 0004 §7).
   *
   * The API token is long-lived, opaque and revocable: right for the outside,
   * wrong for passing between services. The first service that receives one
   * sends it here; iam says whether it is live and what it stands for; this
   * mints a realm token that lives at most five minutes (and never past the API
   * token) saying the same. Services go on verifying JWTs and learn nothing
   * about API tokens. The cost, said plainly: a revoked API token keeps working
   * for as long as a realm token minted before the revocation lives, up to five
   * minutes.
   *
   * No Authorization header: the token in the body is the credential. Every way
   * a token can be dead is one answer (`invalid_token`); nothing is minted
   * unless iam said yes.
   */
  app.post('/exchange-key', async (c) => {
    const req = request(c)
    const refuse = (reason: string) => audit('exchange_key', { ...req, outcome: 'refused', reason })
    const body = (await c.req.json().catch(() => null)) as { token?: unknown } | null
    const given = typeof body?.token === 'string' ? body.token : ''
    if (!given.startsWith('bwt_')) { refuse('not_an_api_token'); return c.json({ error: 'invalid_token' }, 401) }

    const verdict = await iamVerify(given)
    if (verdict.status === 'unconfigured') { refuse('exchange_unavailable'); return c.json({ error: 'exchange_unavailable' }, 503) }
    if (verdict.status === 'unavailable') { refuse('iam_unavailable'); return c.json({ error: 'iam_unavailable' }, 502) }
    if (verdict.status === 'invalid') { refuse(verdict.reason ?? 'invalid_token'); return c.json({ error: 'invalid_token' }, 401) }

    const p = verdict.principal
    const remaining = p.expires_at === null ? EXCHANGE_TTL : Math.floor((p.expires_at - Date.now()) / 1000)
    if (remaining < 1) { refuse('expired'); return c.json({ error: 'invalid_token' }, 401) }
    const expiresIn = Math.min(EXCHANGE_TTL, remaining)

    const token = await mintIdentityToken({
      sub: p.actor_id,
      // `assistant` for every kind: a verifier from before ADR 0004 must never
      // read this as a person who signed in.
      type: 'assistant',
      expires_in_seconds: expiresIn,
      claims: {
        kind: p.kind,
        via: p.kind === 'machine' ? 'key' : 'token',
        actor: p.actor,
        credential_id: p.token_id,
        ...(p.on_behalf_of ? { on_behalf_of: p.on_behalf_of } : {}),
        ...(p.role ? { role: p.role } : {}),
        ...(p.org_id ? { org_id: p.org_id } : {}),
        ...(p.access ? { access: p.access } : {}),
      },
    })
    if (!token) { refuse('no_signing_key'); return c.json({ error: 'realm has no signing key configured' }, 500) }

    // The principal the realm token says: the same claims, read the way every service reads them.
    const stands = principalOf({
      sub: p.actor_id, type: 'assistant', kind: p.kind, via: p.kind === 'machine' ? 'key' : 'token', actor: p.actor,
      credential_id: p.token_id, on_behalf_of: p.on_behalf_of, role: p.role, org_id: p.org_id, access: p.access,
    })
    audit('exchange_key', { ...req, outcome: 'ok', ...envelopeOf(stands) })
    return c.json({ token, token_type: 'bearer', expires_in: expiresIn })
  })

  return app
}
