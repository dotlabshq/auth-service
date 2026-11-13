/**
 * What this realm's OAuth server is configured with. Read from the environment
 * on every call (tests change it; nothing here is cached).
 *
 *   AUTH_MCP_RESOURCES      comma-separated MCP server URLs this realm knows (RFC 8707 `resource`).
 *                           A manifest lookup replaces it later; a client that omits `resource`
 *                           gets the one URL when there is exactly one.
 *   AUTH_OAUTH_CLIENTS      JSON: pre-registered clients [{ client_id, client_name, redirect_uris, jwks? }]
 *   AUTH_OAUTH_ORIGIN       the issuer's origin when it is not AUTH_ISSUER / APP_PUBLIC_URL
 *   ORG_SERVICE_URL         org-service's own address, for the person's memberships on the consent page
 *   AUTH_OAUTH_EXCHANGERS   services that may exchange an MCP access token (default `mcp`)
 */
import type { JSONWebKeySet } from 'jose'
import { publicUrls } from '../urls.js'

export const SCOPES = ['read', 'write', 'offline_access'] as const
export type Scope = (typeof SCOPES)[number]

export const ACCESS_TOKEN_SECONDS = 300

export function issuerUrl(env: NodeJS.ProcessEnv = process.env): string {
  return (env['AUTH_OAUTH_ORIGIN'] ?? env['AUTH_ISSUER'] ?? env['APP_PUBLIC_URL'] ?? '').trim().replace(/\/+$/, '')
}

export function knownResources(env: NodeJS.ProcessEnv = process.env): string[] {
  return (env['AUTH_MCP_RESOURCES'] ?? '').split(',').map((s) => s.trim().replace(/\/+$/, '')).filter(Boolean)
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

/** The endpoints, as a client outside reaches them: at the issuer's root (the gateway must route them). */
export function endpoints(env: NodeJS.ProcessEnv = process.env) {
  const issuer = issuerUrl(env)
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    revocation_endpoint: `${issuer}/revoke`,
    jwks_uri: publicUrls(env as Record<string, string | undefined>).api('/.well-known/jwks.json'),
  }
}
