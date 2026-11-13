/**
 * What this realm's OAuth server is configured with. Read from the environment
 * on every call (tests change it; nothing here is cached).
 *
 *   AUTH_MCP_RESOURCES      comma-separated MCP server URLs this realm knows (RFC 8707 `resource`).
 *                           A manifest lookup replaces it later; a client that omits `resource`
 *                           gets the one URL when there is exactly one.
 *   AUTH_OAUTH_CLIENTS      JSON: pre-registered clients [{ client_id, client_name, redirect_uris, jwks? }]
 *   ORG_SERVICE_URL         org-service's own address, for the person's memberships on the consent page
 *   AUTH_OAUTH_EXCHANGERS   services that may exchange an MCP access token (default `mcp`)
 */
import type { JSONWebKeySet } from 'jose'
import { publicUrls } from '../urls.js'

export const SCOPES = ['read', 'write', 'offline_access'] as const
export type Scope = (typeof SCOPES)[number]

export const ACCESS_TOKEN_SECONDS = 300

/**
 * The issuer: exactly the `iss` of every token this realm mints (`AUTH_ISSUER`, else
 * `APP_PUBLIC_URL`; see lib/realm.ts). It may carry a path (`https://host/v1/auth`): then
 * its RFC 8414 metadata is at `https://host/.well-known/oauth-authorization-server/v1/auth`
 * (path insertion), which the gateway maps to this service's own
 * `/.well-known/oauth-authorization-server` under its API mount.
 */
export function issuerUrl(env: NodeJS.ProcessEnv = process.env): string {
  return (env['AUTH_ISSUER'] ?? env['APP_PUBLIC_URL'] ?? '').trim().replace(/\/+$/, '')
}

export function knownResources(env: NodeJS.ProcessEnv = process.env): string[] {
  return (env['AUTH_MCP_RESOURCES'] ?? '').split(',').map((s) => s.trim().replace(/\/+$/, '')).filter(Boolean)
}

/** org-service's address as given (no trailing slash or `/api`); empty when not configured. */
export function orgServiceUrl(env: NodeJS.ProcessEnv = process.env): string {
  return (env['ORG_SERVICE_URL'] ?? '').trim().replace(/\/+$/, '').replace(/\/api$/, '')
}

/** Things that make OAuth work badly, said once at boot. OAuth is in use when an MCP resource is configured. */
export function oauthWarnings(env: NodeJS.ProcessEnv = process.env): string[] {
  if (!knownResources(env).length) return []
  return orgServiceUrl(env) ? [] : ['OAuth is enabled (AUTH_MCP_RESOURCES is set) but ORG_SERVICE_URL is not: the consent page cannot offer organizations, and every grant will act without one. Set ORG_SERVICE_URL (on Flect: auth `calls` org).']
}

export interface StaticClient {
  client_id: string
  client_name: string
  redirect_uris: string[]
  jwks?: JSONWebKeySet
}

export function staticClients(env: NodeJS.ProcessEnv = process.env): StaticClient[] {
  try {
    const v = JSON.parse(env['AUTH_OAUTH_CLIENTS'] ?? '[]') as unknown
    return Array.isArray(v) ? (v as StaticClient[]).filter((c) => c && typeof c.client_id === 'string' && Array.isArray(c.redirect_uris)) : []
  } catch { return [] }
}

export const exchangers = (env: NodeJS.ProcessEnv = process.env): string[] =>
  (env['AUTH_OAUTH_EXCHANGERS'] ?? 'mcp').split(',').map((s) => s.trim()).filter(Boolean)

/** The endpoints as a client outside reaches them: absolute URLs under this service's published API prefix. */
export function endpoints(env: NodeJS.ProcessEnv = process.env) {
  const api = publicUrls(env as Record<string, string | undefined>).api
  return {
    issuer: issuerUrl(env),
    authorization_endpoint: api('/authorize'),
    token_endpoint: api('/token'),
    registration_endpoint: api('/register'),
    revocation_endpoint: api('/revoke'),
    jwks_uri: api('/.well-known/jwks.json'),
  }
}
