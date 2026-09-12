/**
 * Minting the realm's identity tokens, in one place.
 *
 * Three routes need a token — the OIDC callback (browser cookie), `/token`
 * (same JWT handed to a page) and `/approve` (CLI device flow) — and before
 * this they each reached for JWT_SECRET and called signHs256Jwt themselves.
 * One place means the claim set, the algorithm and the migration switch cannot
 * drift apart between them.
 */

import { mint as mintEs256, type IdentityType } from '@baseworks/auth/identity'
import { signHs256Jwt } from '@baseworks/auth/jwt'
import { realm } from './realm.js'

export interface MintInput {
  sub: string
  type: IdentityType
  expiresInSeconds: number
  /** Extra claims — a narrowed token's org and scope, for instance. */
  claims?: Record<string, unknown>
}

/**
 * Returns the signed token, or null when the realm has no way to sign at all
 * (neither a signing key nor a legacy secret). Callers answer 500 in that case:
 * it is a deployment mistake, not a user error.
 */
export async function mintIdentityToken(input: MintInput): Promise<string | null> {
  const r = await realm()

  if (r.signing) {
    return mintEs256(
      r.signing,
      { sub: input.sub, type: input.type, ...(input.claims ?? {}) },
      { issuer: r.issuer, audience: r.audience, expiresInSeconds: input.expiresInSeconds },
    )
  }

  if (r.legacySecret) {
    // Migration path. Deliberately keeps the old claim shape: a verifier still
    // running the previous release has never seen iss/aud and would reject a
    // token carrying them.
    return signHs256Jwt(
      { sub: input.sub, type: input.type, ...(input.claims ?? {}) },
      r.legacySecret,
      input.expiresInSeconds,
    )
  }

  return null
}
