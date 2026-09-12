/**
 * The realm's signing identity: one key pair, one issuer, one audience.
 *
 * auth-service is the only issuer in a realm. Everyone else verifies with the
 * public key served at /.well-known/jwks.json and cannot mint anything — which
 * is the difference from the shared HMAC secret this replaces, where every
 * service holding the secret could also issue tokens, including tokens claiming
 * to be another user.
 *
 * Configuration (all optional; without a signing key the service keeps using
 * HS256 exactly as before, so this can be deployed before keys exist):
 *
 *   AUTH_SIGNING_KEY          EC P-256 private key, PKCS#8 PEM or base64 of it
 *   AUTH_SIGNING_KID          override the derived key id (rarely needed)
 *   AUTH_RETIRED_PUBLIC_KEYS  comma/newline separated SPKI PEMs, still published
 *   AUTH_ISSUER               defaults to APP_PUBLIC_URL
 *   AUTH_AUDIENCE             realm name; defaults to the issuer's hostname
 *   JWT_SECRET                legacy HS256 secret — used only while it is set
 *
 * Generate a key pair with:
 *   pnpm --filter @dotlabshq/auth-service keygen
 */

import { loadPublicKey, loadSigningKey, jwks, type SigningKey } from '@baseworks/auth/identity'
import type { JSONWebKeySet } from 'jose'

export interface Realm {
  signing?: SigningKey
  jwks?: JSONWebKeySet
  issuer: string
  audience: string
  /** HS256 secret, while the realm still has one. */
  legacySecret?: string
}

let cached: Realm | undefined

function splitKeys(raw: string): string[] {
  // PEM blocks contain newlines themselves, so only split on commas or on blank
  // lines between blocks — splitting on every newline would shred the PEM.
  return raw
    .split(/,|\n\s*\n/)
    .map((s) => s.trim())
    .filter(Boolean)
}

export async function realm(env: NodeJS.ProcessEnv = process.env): Promise<Realm> {
  if (cached) return cached

  const issuer = (env['AUTH_ISSUER'] ?? env['APP_PUBLIC_URL'] ?? '').replace(/\/+$/, '')
  const audience = env['AUTH_AUDIENCE'] ?? hostnameOf(issuer)
  const legacySecret = env['JWT_SECRET']

  const privateKey = env['AUTH_SIGNING_KEY']
  if (!privateKey) {
    // No key configured: HS256 only. Logged once at startup so an operator who
    // expected ES256 finds out here rather than from a puzzled verifier.
    console.warn(
      '[realm] AUTH_SIGNING_KEY not set — minting HS256 tokens with the shared secret. ' +
        'Every service holding that secret can also mint tokens; set a signing key to end that.',
    )
    cached = { issuer, audience, ...(legacySecret ? { legacySecret } : {}) }
    return cached
  }

  const signing = await loadSigningKey(privateKey, env['AUTH_SIGNING_KID'])
  const retired = await Promise.all(
    splitKeys(env['AUTH_RETIRED_PUBLIC_KEYS'] ?? '').map((pem) => loadPublicKey(pem)),
  )

  cached = {
    signing,
    jwks: jwks(signing, retired),
    issuer,
    audience,
    ...(legacySecret ? { legacySecret } : {}),
  }
  console.log(
    `[realm] signing ES256 as ${issuer} (aud ${audience}), kid ${signing.kid}` +
      (retired.length ? `, ${retired.length} retired key(s) still published` : ''),
  )
  return cached
}

function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname
  } catch {
    return url || 'realm'
  }
}

/** Tests reconfigure the environment between cases. */
export function resetRealm(): void {
  cached = undefined
}
