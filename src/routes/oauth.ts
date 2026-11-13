/**
 * auth-service as an OAuth 2.1 authorization server for MCP clients (workspace
 * ADR 0006; MCP authorization specification 2026-07-28).
 *
 *   GET  /.well-known/oauth-authorization-server   RFC 8414 metadata
 *   GET  /authorize                                 checks, sign-in, consent, then a code
 *   POST /authorize                                 the consent form
 *   POST /token                                     authorization_code, refresh_token, token exchange
 *   POST /register                                  Dynamic Client Registration (RFC 7591)
 *   POST /revoke                                    RFC 7009
 *
 * They are on this service's API mount (published at `/v1/auth`), with absolute URLs in
 * the metadata. The issuer may carry that path (`AUTH_ISSUER=https://host/v1/auth`); the
 * gateway then maps `/.well-known/oauth-authorization-server/v1/auth` on the web host to
 * this service's `/api/.well-known/oauth-authorization-server` (RFC 8414 path insertion).
 *
 * A grant is an agent in iam; auth keeps only short-lived codes and the pending
 * consent in its KV. The access token is a realm JWT, `kind: agent`, `via: oauth`,
 * for five minutes, with the MCP server as its audience.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { Hono, type Context } from 'hono'
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose'
import { verifier } from '@baseworks/auth/identity'
import { principalOf } from '@baseworks/auth/principal'
import { kvTake, type KvClient } from '../db/client.js'
import { audit, envelopeOf, personEnvelope, request, type AuditFields } from '../lib/audit.js'
import { parseSession } from '../lib/cookies.js'
import { ACCESS_TOKEN_SECONDS, SCOPES, endpoints, exchangers, issuerUrl, knownResources } from '../lib/oauth/config.js'
import { iamOauth, membershipsOf } from '../lib/oauth/iam.js'
import { lookupClient, type OAuthClientInfo } from '../lib/oauth/clients.js'
import { isLoopbackRedirect, redirectAllowed, redirectMatches } from '../lib/oauth/redirect.js'
import { mintIdentityToken } from '../lib/mint.js'
import { realm } from '../lib/realm.js'
import { publicUrls } from '../lib/urls.js'
import { consentPage, oauthProblemPage } from '../pages/oauth.js'
import { respond, view } from '../pages/layout.js'

const CODE_TTL = 60
const REQ_TTL = 600
const B64URL = /^[A-Za-z0-9_-]{43,128}$/
const GRANT_CODE = 'authorization_code'
const GRANT_REFRESH = 'refresh_token'
const GRANT_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

const sha256b64 = (s: string) => createHash('sha256').update(s).digest('base64url')
const same = (a: string, b: string) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y) }
const random = (n = 32) => randomBytes(n).toString('base64url')
const noStore = (c: Context) => { c.header('Cache-Control', 'no-store'); c.header('Pragma', 'no-cache') }

/** The resource as it is compared: no trailing slash. */
const norm = (r: string) => r.replace(/\/+$/, '')

interface PendingRequest {
  user_id: string
  client_id: string
  redirect_uri: string
  state: string | null
  code_challenge: string
  resource: string
  scope: string[]
  resource_sent: boolean
}

interface CodeRecord {
  user_id: string
  client_id: string
  client_name: string
  redirect_uri: string
  code_challenge: string
  resource: string
  org_id: string | null
  access: Array<'read' | 'write'>
  scope: string
}

/** A rate limit that remembers nothing durable: per key, per minute. */
/** Where the client says it is, for the person to read: the host of its client_id when that is a URL. */
function clientHost(client: OAuthClientInfo): string | null {
  try { return client.client_id.startsWith('https://') ? new URL(client.client_id).host : null } catch { return null }
}

function limiter(max: number, windowMs = 60_000) {
  const seen = new Map<string, number[]>()
  return (key: string): boolean => {
    const now = Date.now()
    const list = (seen.get(key) ?? []).filter((t) => t > now - windowMs)
    if (list.length >= max) { seen.set(key, list); return false }
    list.push(now); seen.set(key, list)
    if (seen.size > 10_000) seen.clear()
    return true
  }
}

export function oauthRouter(kv: KvClient) {
  const app = new Hono()
  const registerLimit = limiter(Number(process.env['AUTH_OAUTH_REGISTER_PER_MINUTE'] ?? 10))

  const oauthError = (c: Context, status: 400 | 401 | 403 | 429 | 500 | 502 | 503, error: string, description?: string) => {
    noStore(c)
    return c.json({ error, ...(description ? { error_description: description } : {}) }, status)
  }

  // ── metadata ───────────────────────────────────────────────────────────────
  app.get('/.well-known/oauth-authorization-server', (c) => {
    const e = endpoints()
    return c.json({
      issuer: e.issuer,
      authorization_endpoint: e.authorization_endpoint,
      token_endpoint: e.token_endpoint,
      registration_endpoint: e.registration_endpoint,
      revocation_endpoint: e.revocation_endpoint,
      jwks_uri: e.jwks_uri,
      scopes_supported: [...SCOPES],
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: [GRANT_CODE, GRANT_REFRESH, GRANT_EXCHANGE],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
      token_endpoint_auth_signing_alg_values_supported: ['ES256'],
      revocation_endpoint_auth_methods_supported: ['none'],
      client_id_metadata_document_supported: true,
      authorization_response_iss_parameter_supported: true,
    }, 200, { 'cache-control': 'public, max-age=300' })
  })

  // ── /authorize ─────────────────────────────────────────────────────────────

  /** An error that goes back to the client (RFC 6749 §4.1.2.1), with `state` and `iss`. */
  const back = (redirect_uri: string, state: string | null, params: Record<string, string>) => {
    const u = new URL(redirect_uri)
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v)
    if (state !== null) u.searchParams.set('state', state)
    u.searchParams.set('iss', issuerUrl())
    return u.toString()
  }

  async function issueCode(c: Context, p: PendingRequest, client: OAuthClientInfo, org_id: string | null, access: Array<'read' | 'write'>, step: string): Promise<Response> {
    const code = random(32)
    const record: CodeRecord = {
      user_id: p.user_id, client_id: p.client_id, client_name: client.client_name, redirect_uri: p.redirect_uri,
      code_challenge: p.code_challenge, resource: p.resource, org_id, access, scope: [...access, ...(p.scope.includes('offline_access') ? ['offline_access'] : [])].join(' '),
    }
    await kv.set(`oauth:code:${code}`, JSON.stringify(record), { ttl: CODE_TTL })
    audit('oauth_authorize', { ...request(c), outcome: 'ok', step, client: 'ui', ...personEnvelope(p.user_id), client_id: p.client_id, resource: p.resource, resource_sent: p.resource_sent ? 'yes' : 'no', scope: record.scope, ...(org_id ? { org_id } : {}) })
    return c.redirect(back(p.redirect_uri, p.state, { code }))
  }

  app.get('/authorize', async (c) => {
    const q = c.req.query()
    const v = view(c)
    const req = request(c)
    const refuseShown = (reason: string, client_id?: string) =>
      audit('oauth_authorize', { ...req, outcome: 'refused', step: 'invalid_request', reason, client: 'ui', ...(client_id ? { client_id: client_id.slice(0, 200) } : {}) })

    // 1. Who is asking. Until the client and the redirect are known good, an error is a page, not a redirect.
    const looked = await lookupClient(q['client_id'] ?? '')
    if (!looked.ok) { refuseShown(`client_${looked.reason}`, q['client_id']); return respond(c, oauthProblemPage(v, 'client'), 400) }
    const client = looked.client
    let redirect_uri = q['redirect_uri'] ?? ''
    if (!redirect_uri) {
      const only = client.redirect_uris.filter((u) => !isLoopbackRedirect(u))
      if (client.redirect_uris.length === 1 && only.length === 1) redirect_uri = only[0]!
      else { refuseShown('redirect_missing', client.client_id); return respond(c, oauthProblemPage(v, 'redirect'), 400) }
    }
    if (!redirectMatches(client.redirect_uris, redirect_uri)) { refuseShown('redirect_mismatch', client.client_id); return respond(c, oauthProblemPage(v, 'redirect'), 400) }

    // 2. From here a refusal goes back to the client.
    const state = q['state'] ?? null
    const fail = (error: string, description: string) => {
      audit('oauth_authorize', { ...req, outcome: 'refused', step: 'invalid_request', reason: error, client: 'ui', client_id: client.client_id })
      return c.redirect(back(redirect_uri, state, { error, error_description: description }))
    }
    if (q['response_type'] !== 'code') return fail('unsupported_response_type', 'response_type must be code')
    const challenge = q['code_challenge'] ?? ''
    if (q['code_challenge_method'] !== 'S256' || !B64URL.test(challenge)) return fail('invalid_request', 'PKCE with code_challenge_method=S256 is required')

    const resources = knownResources()
    const sent = q['resource'] !== undefined && q['resource'] !== ''
    let resource: string
    if (sent) {
      resource = norm(q['resource']!)
      if (!resources.includes(resource)) return fail('invalid_target', 'resource is not an MCP server of this realm')
    } else if (resources.length === 1) {
      resource = resources[0]!
    } else {
      return fail('invalid_target', 'resource is required')
    }

    const asked = (q['scope'] ?? '').split(/\s+/).filter(Boolean)
    if (asked.some((s) => !(SCOPES as readonly string[]).includes(s))) return fail('invalid_scope', 'scopes are read, write and offline_access')
    const scope = asked.length ? asked : ['read']
    if (!scope.includes('read') && !scope.includes('write')) scope.push('read')

    // 3. Who is the person. Not signed in: sign in, and come back to this exact request.
    const session = parseSession(c)
    if (!session?.is_authenticated) {
      // Back to this exact request, at the address the browser knows it by.
      return c.redirect(publicUrls().ui(`/login?returnTo=${encodeURIComponent(`${publicUrls().api('/authorize')}${new URL(c.req.url).search}`)}`))
    }
    const user_id = session.user_id ?? session.subject
    const pending: PendingRequest = { user_id, client_id: client.client_id, redirect_uri, state, code_challenge: challenge, resource, scope, resource_sent: sent }
    const may_write = scope.includes('write')
    const access: Array<'read' | 'write'> = may_write ? ['read', 'write'] : ['read']

    // 4. Who is this, really: an iam user (a session left over from a degraded sign-in names only the provider's subject).
    const known = await iamOauth('POST', '/preview', { user_id, client_id: client.client_id, client_name: client.client_name })
    if (known.status !== 200) { refuseShown(known.status === 404 ? 'person_not_in_iam' : 'iam_unavailable', client.client_id); return respond(c, oauthProblemPage(v, 'person'), 403) }
    const actor = (known.data as { actor?: string }).actor!

    // 5. Asked before? Only a request that comes back to an https address is not asked again. A loopback
    //    redirect is a program on this computer, which anything can claim to be (RFC 8252 §8.6, OAuth 2.1 §7.5):
    //    it always sees the page, with what the person chose last time already selected.
    const orgs = await membershipsOf(user_id)
    const candidates: Array<string | null> = orgs.length ? orgs.map((o) => o.id) : [null]
    const found: Array<string | null> = []
    for (const org_id of candidates.slice(0, 20)) {
      const r = await iamOauth<{ grant: unknown }>('POST', '/grants/find', { user_id, client_id: client.client_id, resource, org_id, access })
      if (r.status === 200 && r.data.grant) found.push(org_id)
    }
    const remembered = found.length === 1 ? found[0]! : undefined
    if (found.length === 1 && !isLoopbackRedirect(redirect_uri)) return issueCode(c, pending, client, remembered ?? null, access, 'approved_remembered')

    // 6. Ask. The pending request is remembered under an id only this person's session can answer.
    const id = random(24)
    await kv.set(`oauth:req:${id}`, JSON.stringify(pending), { ttl: REQ_TTL })
    audit('oauth_authorize', { ...req, outcome: 'ok', step: 'consent_shown', client: 'ui', ...personEnvelope(user_id), client_id: client.client_id, resource, resource_sent: sent ? 'yes' : 'no', scope: scope.join(' ') })
    return respond(c, consentPage({
      view: v, client_name: client.client_name, client_host: clientHost(client), redirect_host: new URL(redirect_uri).host, remembered_org: remembered ?? null,
      localhost_only: client.redirect_uris.every(isLoopbackRedirect), resource, orgs, may_write, actor, req: id,
    }))
  })

  app.post('/authorize', async (c) => {
    const v = view(c)
    const req = request(c)
    const form = await c.req.parseBody()
    const field = (k: string) => (typeof form[k] === 'string' ? (form[k] as string) : '')
    const session = parseSession(c)
    if (!session?.is_authenticated) return respond(c, oauthProblemPage(v, 'person'), 401)
    const user_id = session.user_id ?? session.subject
    const raw = await kv.get(`oauth:req:${field('req')}`)
    if (!raw) return respond(c, oauthProblemPage(v, 'expired'), 400)
    const p = JSON.parse(raw) as PendingRequest
    if (p.user_id !== user_id) return respond(c, oauthProblemPage(v, 'person'), 403)
    await kv.del(`oauth:req:${field('req')}`)
    const looked = await lookupClient(p.client_id)
    if (!looked.ok) return respond(c, oauthProblemPage(v, 'client'), 400)

    if (field('decision') !== 'approve') {
      audit('oauth_authorize', { ...req, outcome: 'refused', step: 'consent_refused', reason: 'access_denied', client: 'ui', ...personEnvelope(user_id), client_id: p.client_id, resource: p.resource, resource_sent: p.resource_sent ? 'yes' : 'no' })
      return c.redirect(back(p.redirect_uri, p.state, { error: 'access_denied', error_description: 'the person refused' }))
    }
    const orgs = await membershipsOf(user_id)
    // An organization comes from the person's own memberships and nowhere else.
    let org_id: string | null = null
    if (orgs.length) {
      org_id = orgs.find((o) => o.id === field('org_id'))?.id ?? null
      if (!org_id) return respond(c, oauthProblemPage(v, 'request'), 400)
    }
    // Read unless write was asked for AND chosen: a form cannot widen what the client asked.
    const access: Array<'read' | 'write'> = field('access') === 'write' && p.scope.includes('write') ? ['read', 'write'] : ['read']
    return issueCode(c, p, looked.client, org_id, access, 'approved')
  })

  // ── /token ─────────────────────────────────────────────────────────────────

  /** Who is calling: a public client names itself; a client with keys proves it with a signed assertion. */
  async function authenticateClient(form: Record<string, unknown>): Promise<{ ok: true; client: OAuthClientInfo } | { ok: false }> {
    const str = (k: string) => (typeof form[k] === 'string' ? (form[k] as string) : '')
    let client_id = str('client_id')
    const assertion = str('client_assertion')
    if (assertion && str('client_assertion_type') === ASSERTION_TYPE) {
      // The assertion's `iss` and `sub` are the client id; read to find the key, verified below.
      try { const p = JSON.parse(Buffer.from(assertion.split('.')[1] ?? '', 'base64url').toString('utf8')) as { sub?: string }; client_id = p.sub ?? client_id } catch { return { ok: false } }
    }
    if (!client_id) return { ok: false }
    const looked = await lookupClient(client_id)
    if (!looked.ok) return { ok: false }
    const client = looked.client
    if (client.auth_method === 'private_key_jwt') {
      if (!assertion || !client.jwks) return { ok: false }
      try {
        await jwtVerify(assertion, createLocalJWKSet(client.jwks as JSONWebKeySet), { issuer: client.client_id, subject: client.client_id, audience: [endpoints().token_endpoint, issuerUrl()], algorithms: ['ES256'] })
      } catch { return { ok: false } }
    }
    return { ok: true, client }
  }

  /** A realm JWT for an agent acting for a person, with the MCP server (or the realm) as audience. */
  async function mintFor(g: { id: string; agent_id: string; actor: string; on_behalf_of: string; client_id: string; org_id: string | null; access: Array<'read' | 'write'> }, audience: string | undefined, seconds: number) {
    return mintIdentityToken({
      sub: g.agent_id, type: 'assistant', expires_in_seconds: seconds, ...(audience ? { audience } : {}),
      claims: {
        kind: 'agent', via: 'oauth', actor: g.actor, on_behalf_of: g.on_behalf_of, credential_id: g.id,
        access: g.access, client: 'mcp', client_id: g.client_id, ...(g.org_id ? { org_id: g.org_id } : {}),
      },
    })
  }

  const agentEnvelope = (g: { id: string; agent_id: string; actor: string; on_behalf_of: string; org_id: string | null; access: Array<'read' | 'write'> }): Partial<AuditFields> =>
    envelopeOf(principalOf({ sub: g.agent_id, type: 'assistant', kind: 'agent', via: 'oauth', actor: g.actor, on_behalf_of: g.on_behalf_of, credential_id: g.id, access: g.access, ...(g.org_id ? { org_id: g.org_id } : {}) }), 'mcp')

  app.post('/token', async (c) => {
    const req = request(c)
    const form = await c.req.parseBody() as Record<string, unknown>
    const str = (k: string) => (typeof form[k] === 'string' ? (form[k] as string) : '')
    const grant_type = str('grant_type')
    const refuse = (status: 400 | 401 | 403 | 502 | 503, error: string, reason: string, extra: Partial<AuditFields> = {}) => {
      audit('oauth_token', { ...req, outcome: 'refused', step: grant_type || 'none', reason, client: 'api', ...extra })
      return oauthError(c, status, error, reason)
    }
    const r = await realm()
    if (!r.signing) return oauthError(c, 500, 'server_error', 'the realm has no signing key; OAuth needs ES256')

    // Token exchange authenticates the calling service, not a client.
    if (grant_type === GRANT_EXCHANGE) return exchangeToken(c, form, req, refuse)

    const auth = await authenticateClient(form)
    if (!auth.ok) return refuse(401, 'invalid_client', 'client_authentication_failed')
    const client = auth.client
    const given = str('resource') ? norm(str('resource')) : ''
    if (given && !knownResources().includes(given)) return refuse(400, 'invalid_target', 'unknown_resource', { client_id: client.client_id })

    if (grant_type === GRANT_CODE) {
      const code = str('code')
      // Single use, and atomic: of two redemptions at once exactly one gets the record. Gone before anything
      // is checked, so a wrong verifier burns the code too.
      const raw = code ? await kvTake(kv, `oauth:code:${code}`) : null
      if (!raw) {
        // A code that WAS redeemed, presented again: somebody holds a copy. What it produced is revoked (OAuth 2.1 §4.1.3).
        const used = code ? await kv.get(`oauth:used:${sha256b64(code)}`) : null
        if (used) {
          await iamOauth('POST', `/grants/${encodeURIComponent(used)}/revoke`, {})
          return refuse(400, 'invalid_grant', 'code_reuse_grant_revoked', { client_id: client.client_id, grant_id: used, step: 'code_reuse_detected' })
        }
        return refuse(400, 'invalid_grant', 'code_unknown_or_used', { client_id: client.client_id })
      }
      const rec = JSON.parse(raw) as CodeRecord
      if (rec.client_id !== client.client_id) return refuse(400, 'invalid_grant', 'client_mismatch', { client_id: client.client_id })
      if (str('redirect_uri') && str('redirect_uri') !== rec.redirect_uri) return refuse(400, 'invalid_grant', 'redirect_mismatch', { client_id: client.client_id })
      const verifierStr = str('code_verifier')
      if (!B64URL.test(verifierStr) || !same(sha256b64(verifierStr), rec.code_challenge)) return refuse(400, 'invalid_grant', 'pkce_failed', { client_id: client.client_id })
      if (given && given !== rec.resource) return refuse(400, 'invalid_target', 'resource_mismatch', { client_id: client.client_id })

      const made = await iamOauth<{ grant?: any; refresh_token?: string; error?: string }>('POST', '/grants', {
        user_id: rec.user_id, client_id: rec.client_id, client_name: rec.client_name, resource: rec.resource, org_id: rec.org_id, access: rec.access,
      })
      if (made.status === 0 || made.status >= 500) return refuse(502, 'server_error', 'iam_unavailable', { client_id: client.client_id })
      if (made.status !== 201 || !made.data.grant || !made.data.refresh_token) return refuse(400, 'invalid_grant', `grant_${made.data.error ?? made.status}`, { client_id: client.client_id })
      const g = made.data.grant
      await kv.set(`oauth:used:${sha256b64(code)}`, g.id, { ttl: CODE_TTL })
      const token = await mintFor(g, rec.resource, ACCESS_TOKEN_SECONDS)
      if (!token) return oauthError(c, 500, 'server_error')
      audit('oauth_token', { ...req, outcome: 'ok', step: 'code_exchanged', ...agentEnvelope(g), client_id: client.client_id, resource: rec.resource, resource_sent: given ? 'yes' : 'no', grant_id: g.id, scope: rec.scope })
      noStore(c)
      return c.json({ access_token: token, token_type: 'Bearer', expires_in: ACCESS_TOKEN_SECONDS, refresh_token: made.data.refresh_token, scope: rec.scope })
    }

    if (grant_type === GRANT_REFRESH) {
      const refresh = str('refresh_token')
      if (!refresh) return refuse(400, 'invalid_request', 'refresh_token_missing', { client_id: client.client_id })
      const out = await iamOauth<{ grant?: any; refresh_token?: string; reason?: string }>('POST', '/refresh', { refresh_token: refresh, client_id: client.client_id })
      if (out.status === 0 || out.status >= 500) return refuse(502, 'server_error', 'iam_unavailable', { client_id: client.client_id })
      if (out.status !== 200 || !out.data.grant || !out.data.refresh_token) {
        const reuse = out.data.reason === 'reuse'
        audit('oauth_token', { ...req, outcome: 'refused', step: reuse ? 'refresh_reuse_detected' : 'refresh', reason: out.data.reason ?? 'invalid_grant', client: 'api', client_id: client.client_id })
        // Whatever the reason, the client is told one thing (RFC 6749 §5.2).
        return oauthError(c, 400, 'invalid_grant', 'the refresh token is not valid')
      }
      const g = out.data.grant
      if (given && given !== g.resource) return refuse(400, 'invalid_target', 'resource_mismatch', { client_id: client.client_id })
      const token = await mintFor(g, g.resource, ACCESS_TOKEN_SECONDS)
      if (!token) return oauthError(c, 500, 'server_error')
      audit('oauth_token', { ...req, outcome: 'ok', step: 'refreshed', ...agentEnvelope(g), client_id: client.client_id, resource: g.resource, resource_sent: given ? 'yes' : 'no', grant_id: g.id })
      noStore(c)
      return c.json({ access_token: token, token_type: 'Bearer', expires_in: ACCESS_TOKEN_SECONDS, refresh_token: out.data.refresh_token, scope: [...g.access, 'offline_access'].join(' ') })
    }

    return refuse(400, 'unsupported_grant_type', 'unsupported_grant_type', { client_id: client.client_id })
  })

  /**
   * RFC 8693, for the realm's MCP server: an access token whose audience is the
   * MCP server, in; a realm token for the same agent and person, five minutes at
   * most and never past the one it came from, out. The caller is a service
   * (`AUTH_OAUTH_EXCHANGERS`, default `mcp`) that presents its own service token.
   */
  async function exchangeToken(c: Context, form: Record<string, unknown>, req: ReturnType<typeof request>, refuse: (s: 400 | 401 | 403 | 502 | 503, e: string, r: string, x?: Partial<AuditFields>) => Response) {
    const str = (k: string) => (typeof form[k] === 'string' ? (form[k] as string) : '')
    const r = await realm()
    const bearer = (c.req.header('Authorization') ?? '').replace(/^Bearer\s+/i, '')
    const callerClaims = bearer ? await verifier({ ...(r.jwks ? { jwks: r.jwks } : {}), ...(r.issuer ? { issuer: r.issuer } : {}), ...(r.audience ? { audience: r.audience } : {}) })(bearer) : null
    if (!callerClaims || callerClaims.type !== 'service' || !exchangers().includes(String(callerClaims.sub))) return refuse(401, 'invalid_client', 'exchange_caller_refused')
    if (str('subject_token_type') !== ACCESS_TOKEN_TYPE) return refuse(400, 'invalid_request', 'subject_token_type')
    const target = str('audience') || (r.audience ?? '')
    if (target && target !== r.audience) return refuse(400, 'invalid_target', 'audience_is_the_realm_only')
    // The caller says which MCP server it is (`resource`): the token must have been made for that one
    // and no other. With a single known resource it may be left out.
    const known = knownResources()
    const named = str('resource') ? norm(str('resource')) : ''
    if (named && !known.includes(named)) return refuse(400, 'invalid_target', 'unknown_resource')
    if (!named && known.length > 1) return refuse(400, 'invalid_target', 'resource_required')
    const claims = known.length === 0 ? null : await verifier({ ...(r.jwks ? { jwks: r.jwks } : {}), issuer: r.issuer, audience: named || known[0]! })(str('subject_token'))
    if (!claims || claims['via'] !== 'oauth' || claims['kind'] !== 'agent' || typeof claims['credential_id'] !== 'string') return refuse(400, 'invalid_grant', 'subject_token_invalid')
    const remaining = Math.floor(((claims.exp ?? 0) * 1000 - Date.now()) / 1000)
    if (remaining < 1) return refuse(400, 'invalid_grant', 'subject_token_expired')
    const p = principalOf(claims)
    const token = await mintIdentityToken({
      sub: String(claims.sub), type: 'assistant', expires_in_seconds: Math.min(ACCESS_TOKEN_SECONDS, remaining),
      claims: {
        kind: 'agent', via: 'oauth', actor: p.actor, ...(p.on_behalf_of ? { on_behalf_of: p.on_behalf_of } : {}), credential_id: claims['credential_id'],
        ...(p.access ? { access: p.access } : {}), ...(p.org_id ? { org_id: p.org_id } : {}), client: 'mcp', ...(typeof claims['client_id'] === 'string' ? { client_id: claims['client_id'] } : {}),
      },
    })
    if (!token) return oauthError(c, 500, 'server_error')
    audit('oauth_token', { ...req, outcome: 'ok', step: 'exchanged', client: 'mcp', ...envelopeOf(p, 'mcp'), ...(typeof claims['client_id'] === 'string' ? { client_id: claims['client_id'] } : {}), grant_id: String(claims['credential_id']) })
    noStore(c)
    return c.json({ access_token: token, issued_token_type: ACCESS_TOKEN_TYPE, token_type: 'Bearer', expires_in: Math.min(ACCESS_TOKEN_SECONDS, remaining) })
  }

  // ── /register (RFC 7591) ───────────────────────────────────────────────────
  app.post('/register', async (c) => {
    const req = request(c)
    if (!registerLimit(req.ip || 'unknown')) return oauthError(c, 429, 'too_many_requests', 'slow down')
    const body = (await c.req.json().catch(() => null)) as Record<string, unknown> | null
    if (!body || typeof body !== 'object') return oauthError(c, 400, 'invalid_client_metadata', 'a JSON body is required')
    const uris = body['redirect_uris']
    if (!Array.isArray(uris) || uris.length === 0 || !uris.every((u) => typeof u === 'string')) return oauthError(c, 400, 'invalid_redirect_uri', 'redirect_uris is a list of strings')
    if (!(uris as string[]).every(redirectAllowed)) return oauthError(c, 400, 'invalid_redirect_uri', 'a redirect URI is https, or http on localhost, 127.0.0.1 or [::1], with no fragment')
    const method = typeof body['token_endpoint_auth_method'] === 'string' ? body['token_endpoint_auth_method'] : 'none'
    if (method !== 'none') return oauthError(c, 400, 'invalid_client_metadata', 'registered clients are public: token_endpoint_auth_method is none')
    const out = await iamOauth<{ client?: { client_id: string; client_name: string; redirect_uris: string[]; created_at: number }; error?: string }>('POST', '/clients', {
      client_name: typeof body['client_name'] === 'string' && body['client_name'].trim() ? body['client_name'] : 'Unnamed client',
      redirect_uris: uris, token_endpoint_auth_method: 'none', ...(typeof body['logo_uri'] === 'string' ? { logo_uri: body['logo_uri'] } : {}),
    })
    if (out.status === 429) return oauthError(c, 429, 'too_many_requests', 'too many registrations')
    if (out.status === 0 || out.status >= 500) return oauthError(c, 503, 'temporarily_unavailable', 'registration is not available')
    if (out.status !== 201 || !out.data.client) return oauthError(c, 400, String(out.data.error ?? '').startsWith('invalid_redirect') ? 'invalid_redirect_uri' : 'invalid_client_metadata')
    noStore(c)
    return c.json({
      client_id: out.data.client.client_id, client_name: out.data.client.client_name, redirect_uris: out.data.client.redirect_uris,
      token_endpoint_auth_method: 'none', grant_types: [GRANT_CODE, GRANT_REFRESH], response_types: ['code'],
      client_id_issued_at: Math.floor(out.data.client.created_at / 1000),
    }, 201)
  })

  // ── /revoke (RFC 7009) ─────────────────────────────────────────────────────
  app.post('/revoke', async (c) => {
    const form = await c.req.parseBody() as Record<string, unknown>
    const token = typeof form['token'] === 'string' ? form['token'] : ''
    // Always 200: the caller learns nothing about whether a token existed. An access token is short-lived and not revocable here.
    if (token.startsWith('bwr_')) {
      const out = await iamOauth<{ revoked?: boolean }>('POST', '/revoke', { token })
      audit('oauth_token', { ...request(c), outcome: 'ok', step: 'revoked', client: 'api', ...(out.data.revoked ? {} : { reason: 'nothing_to_revoke' }), ...(typeof form['client_id'] === 'string' ? { client_id: form['client_id'].slice(0, 200) } : {}) })
    }
    noStore(c)
    return c.body(null, 200)
  })

  return app
}
