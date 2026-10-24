import { afterEach, describe, expect, it, vi } from 'vitest'
import { verifier } from '@baseworks/auth/identity'
import { JWT_SECRET } from './setup.js'
import { iamSync } from '../lib/iam.js'
import { resetRealm } from '../lib/realm.js'

afterEach(() => {
  vi.unstubAllGlobals()
  delete process.env['IAM_SERVICE_URL']
  delete process.env['AUTH_SERVICE_NAME']
  resetRealm()
})

/** iam's /sync as auth sees it: records the request, answers with a user id. */
function stubIam() {
  const seen: Array<{ url: string; authorization: string | null }> = []
  vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
    seen.push({ url, authorization: new Headers(init.headers).get('authorization') })
    return Response.json({ user: { id: 'usr_1' } })
  })
  return seen
}

describe('iamSync', () => {
  it('registers the identity with a service token auth signs for itself', async () => {
    process.env['IAM_SERVICE_URL'] = 'http://iam.test/'
    const seen = stubIam()

    expect(await iamSync({ subject: 's', issuer: 'https://idp.test', email: 'a@b.test' })).toBe('usr_1')
    expect(seen[0]!.url).toBe('http://iam.test/sync')

    const token = seen[0]!.authorization!.replace(/^Bearer /, '')
    const claims = await verifier({ legacyHs256Secret: JWT_SECRET })(token)
    expect(claims).toMatchObject({ sub: 'auth-service', type: 'service' })
    // Short-lived: it is used once, right now.
    expect((claims!.exp as number) - Math.floor(Date.now() / 1000)).toBeLessThanOrEqual(60)
  })

  it('signs as AUTH_SERVICE_NAME when the realm names auth differently', async () => {
    process.env['IAM_SERVICE_URL'] = 'http://iam.test'
    process.env['AUTH_SERVICE_NAME'] = 'zone9-auth'
    const seen = stubIam()
    await iamSync({ subject: 's', issuer: 'https://idp.test', email: 'a@b.test' })
    const claims = await verifier({ legacyHs256Secret: JWT_SECRET })(seen[0]!.authorization!.slice(7))
    expect(claims?.sub).toBe('zone9-auth')
  })
})
