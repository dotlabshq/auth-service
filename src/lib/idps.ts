/**
 * Sign-in straight with a named identity provider.
 *
 * A product's own login page offers "Continue with Google" and sends the
 * browser to `/login/google`. auth asks the OIDC provider to skip its own
 * screens and hand over to that IdP at once, through the provider's IdP hint
 * scope (`urn:zitadel:iam:org:idp:id:<id>`). The person never sees the
 * provider's login UI; the provider still owns the user, the session and the
 * account linking.
 *
 * `OIDC_IDPS="google:<idp id>,github:<idp id>"` — the name is what a product
 * puts in its URL and what `GET /idps` lists; the id is the provider's and is
 * never published. `OIDC_ORG_ID` optionally pins the organization whose login
 * settings apply (`urn:zitadel:iam:org:id:<id>`).
 */

const NAME = /^[a-z0-9][a-z0-9-]{0,31}$/

/** The configured IdPs, name → provider id. Malformed entries are left out. */
export function parseIdps(raw: string | undefined): Map<string, string> {
  const out = new Map<string, string>()
  for (const entry of (raw ?? '').split(',')) {
    const i = entry.indexOf(':')
    if (i < 0) continue
    const name = entry.slice(0, i).trim().toLowerCase()
    const id = entry.slice(i + 1).trim()
    if (NAME.test(name) && id) out.set(name, id)
  }
  return out
}

/** The extra scopes that send an authorize request straight to `idpId`. */
export function idpScopes(idpId: string, orgId?: string): string[] {
  return [
    `urn:zitadel:iam:org:idp:id:${idpId}`,
    ...(orgId ? [`urn:zitadel:iam:org:id:${orgId}`] : []),
  ]
}
