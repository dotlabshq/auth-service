/**
 * Print a fresh EC P-256 key pair for the realm.
 *
 *   pnpm --filter @dotlabshq/auth-service keygen
 *
 * Writes to stdout and never to a file: a private key that lands on disk gets
 * committed, backed up and copied. Paste the value straight into the secret
 * store. The base64 form is there because environment variables, Kubernetes
 * Secrets and CI variables all mangle the newlines a PEM needs.
 */
import { exportPKCS8, exportSPKI, generateKeyPair } from 'jose'
import { loadSigningKey } from '@baseworks/auth/identity'

const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true })
const pkcs8 = await exportPKCS8(privateKey)
const spki = await exportSPKI(publicKey)
const { kid } = await loadSigningKey(pkcs8)

const b64 = (s: string) => Buffer.from(s).toString('base64')

console.log(`# key id (derived, RFC 7638 thumbprint): ${kid}`)
console.log('#')
console.log('# auth-service — keep secret, set once:')
console.log(`AUTH_SIGNING_KEY=${b64(pkcs8)}`)
console.log('#')
console.log('# public half — publish as a retired key during the NEXT rotation:')
console.log(`AUTH_RETIRED_PUBLIC_KEYS=${b64(spki)}`)
console.log('#')
console.log('# Verifiers need no key material: they read /.well-known/jwks.json.')
