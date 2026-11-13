/**
 * Which client is this? Three kinds, one answer:
 *
 *  · a **Client ID Metadata Document** — the `client_id` is an HTTPS URL; its
 *    document says who the client is and which redirect URIs it may use. Fetched
 *    through the SSRF guard, `client_id` in it must equal the URL, cached by its
 *    HTTP headers for at most an hour (the MCP specification's preferred way);
 *  · a **registered** client (`bwc_…`, Dynamic Client Registration), kept by iam;
 *  · a **pre-registered** client from configuration (`AUTH_OAUTH_CLIENTS`).
 */
import type { JSONWebKeySet } from 'jose'
import { staticClients } from './config.js'
import { iamOauth } from './iam.js'
import { redirectAllowed } from './redirect.js'
import { FetchRefused, fetchJsonGuarded, type JsonFetcher } from './ssrf.js'

export interface OAuthClientInfo {
  client_id: string
  client_name: string
  redirect_uris: string[]
  logo_uri: string | null
  kind: 'cimd' | 'registered' | 'static'
  /** `none` (public) unless the client has keys and says `private_key_jwt`. */
  auth_method: 'none' | 'private_key_jwt'
  jwks?: JSONWebKeySet
}

export type ClientLookup = { ok: true; client: OAuthClientInfo } | { ok: false; reason: 'unknown_client' | 'invalid_metadata' | 'unreachable' | 'blocked' | 'iam_unavailable' }

let fetcher: JsonFetcher = fetchJsonGuarded
/** Tests (and only tests) replace how a metadata document is fetched. */
export function setClientDocumentFetcher(f: JsonFetcher | null): void { fetcher = f ?? fetchJsonGuarded; cache.clear() }

const cache = new Map<string, { client: OAuthClientInfo; until: number }>()
const MAX_CACHE_MS = 3_600_000
const DEFAULT_CACHE_MS = 300_000

/** `Cache-Control: max-age=N` read, bounded to an hour; `no-store` and `no-cache` are not cached. */
function cacheMs(headers: Record<string, string>): number {
  const cc = (headers['cache-control'] ?? '').toLowerCase()
  if (/no-store|no-cache/.test(cc)) return 0
  const m = /max-age=(\d+)/.exec(cc)
  return Math.min(m ? Number(m[1]) * 1000 : DEFAULT_CACHE_MS, MAX_CACHE_MS)
}

function fromDocument(url: string, doc: unknown): OAuthClientInfo | null {
  if (!doc || typeof doc !== 'object') return null
  const d = doc as Record<string, unknown>
  if (d['client_id'] !== url) return null
  const uris = d['redirect_uris']
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > 20 || !uris.every((u) => typeof u === 'string' && redirectAllowed(u))) return null
  const name = typeof d['client_name'] === 'string' && d['client_name'].trim() ? d['client_name'].trim().slice(0, 120) : new URL(url).hostname
  const method = d['token_endpoint_auth_method']
  // A document can name no secret-based method: there is nobody to keep a secret.
  if (method !== undefined && method !== 'none' && method !== 'private_key_jwt') return null
  const jwks = d['jwks'] && typeof d['jwks'] === 'object' && Array.isArray((d['jwks'] as { keys?: unknown }).keys) ? (d['jwks'] as JSONWebKeySet) : undefined
  if (method === 'private_key_jwt' && !jwks) return null
  let logo: string | null = null
  if (typeof d['logo_uri'] === 'string') { try { const l = new URL(d['logo_uri']); if (l.protocol === 'https:') logo = l.toString().slice(0, 512) } catch { /* no logo */ } }
  return { client_id: url, client_name: name, redirect_uris: uris as string[], logo_uri: logo, kind: 'cimd', auth_method: method === 'private_key_jwt' ? 'private_key_jwt' : 'none', ...(jwks ? { jwks } : {}) }
}

export async function lookupClient(client_id: string): Promise<ClientLookup> {
  if (!client_id || client_id.length > 2048) return { ok: false, reason: 'unknown_client' }

  const pre = staticClients().find((c) => c.client_id === client_id)
  if (pre) {
    return { ok: true, client: { client_id, client_name: pre.client_name, redirect_uris: pre.redirect_uris.filter(redirectAllowed), logo_uri: null, kind: 'static', auth_method: pre.jwks ? 'private_key_jwt' : 'none', ...(pre.jwks ? { jwks: pre.jwks } : {}) } }
  }

  if (client_id.startsWith('bwc_')) {
    const r = await iamOauth<{ client?: { client_name: string; redirect_uris: string[]; logo_uri: string | null } }>('GET', `/clients/${encodeURIComponent(client_id)}`)
    if (r.status === 404) return { ok: false, reason: 'unknown_client' }
    if (r.status !== 200 || !r.data.client) return { ok: false, reason: 'iam_unavailable' }
    return { ok: true, client: { client_id, client_name: r.data.client.client_name, redirect_uris: r.data.client.redirect_uris, logo_uri: r.data.client.logo_uri, kind: 'registered', auth_method: 'none' } }
  }

  if (client_id.startsWith('https://')) {
    const hit = cache.get(client_id)
    if (hit && hit.until > Date.now()) return { ok: true, client: hit.client }
    try {
      const { json, headers } = await fetcher(client_id)
      const client = fromDocument(client_id, json)
      if (!client) return { ok: false, reason: 'invalid_metadata' }
      const ttl = cacheMs(headers)
      if (ttl > 0) { if (cache.size > 1000) cache.clear(); cache.set(client_id, { client, until: Date.now() + ttl }) }
      return { ok: true, client }
    } catch (e) {
      if (e instanceof FetchRefused) return { ok: false, reason: e.code === 'blocked_address' || e.code === 'bad_url' ? 'blocked' : 'unreachable' }
      return { ok: false, reason: 'unreachable' }
    }
  }
  return { ok: false, reason: 'unknown_client' }
}
