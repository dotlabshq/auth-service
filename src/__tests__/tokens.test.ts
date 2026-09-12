import { Hono } from 'hono'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { exportPKCS8, generateKeyPair } from 'jose'
import { verifier } from '@baseworks/auth/identity'
import { tokensRouter } from '../routes/tokens.js'
import { realm, resetRealm } from '../lib/realm.js'

const ISSUER = 'https://auth.example.test'
const AUDIENCE = 'example-realm'

function app() {
  const a = new Hono()
  a.route('/', tokensRouter())
  return a
}

async function verifyToken(token: string) {
  const r = await realm()
  return verifier({ jwks: r.jwks!, issuer: ISSUER, audience: AUDIENCE })(token)
}

function post(a: Hono, path: string, body: unknown, token?: string) {
  return a.request(path, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  })
}

beforeEach(async () => {
  resetRealm()
  const { privateKey } = await generateKeyPair('ES256', { extractable: true })
  process.env['AUTH_SIGNING_KEY'] = Buffer.from(await exportPKCS8(privateKey)).toString('base64')
  process.env['AUTH_ISSUER'] = ISSUER
  process.env['AUTH_AUDIENCE'] = AUDIENCE
  process.env['AUTH_SERVICE_CLIENTS'] = 'zone9-api:s3cret-one,billing:s3cret-two'
  delete process.env['JWT_SECRET']
  resetRealm()
})

afterEach(() => {
  for (const k of ['AUTH_SIGNING_KEY', 'AUTH_ISSUER', 'AUTH_AUDIENCE', 'AUTH_SERVICE_CLIENTS']) {
    delete process.env[k]
  }
  resetRealm()
})

describe('POST /service-token', () => {
  it('issues a token for the calling service only', async () => {
    const res = await post(app(), '/service-token', { client_id: 'zone9-api', client_secret: 's3cret-one' })
    expect(res.status).toBe(200)

    const body = (await res.json()) as { token: string; expires_in: number }
    const claims = await verifyToken(body.token)

    expect(claims?.sub).toBe('zone9-api')
    expect(claims?.type).toBe('service')
    expect(body.expires_in).toBe(3600)
  })

  it('cannot be talked into issuing a token for a user', async () => {
    // The request shape simply has no way to name a subject; whatever extra a
    // caller sends, the subject is the authenticated client.
    const res = await post(app(), '/service-token', {
      client_id: 'zone9-api',
      client_secret: 's3cret-one',
      sub: 'usr_victim',
      type: 'human',
    })
    const { token } = (await res.json()) as { token: string }
    const claims = await verifyToken(token)

    expect(claims?.sub).toBe('zone9-api')
    expect(claims?.type).toBe('service')
  })

  it('answers the same for an unknown client and a wrong secret', async () => {
    const unknown = await post(app(), '/service-token', { client_id: 'ghost', client_secret: 'x' })
    const wrong = await post(app(), '/service-token', { client_id: 'zone9-api', client_secret: 'nope' })

    expect(unknown.status).toBe(401)
    expect(wrong.status).toBe(401)
    expect(await unknown.json()).toEqual(await wrong.json())
  })

  it('caps the lifetime', async () => {
    const res = await post(app(), '/service-token', {
      client_id: 'billing', client_secret: 's3cret-two', expires_in: 86400,
    })
    expect(((await res.json()) as { expires_in: number }).expires_in).toBe(3600)
  })
})

describe('POST /exchange', () => {
  async function humanToken(sub = 'usr_1'): Promise<string> {
    const { mintIdentityToken } = await import('../lib/mint.js')
    return (await mintIdentityToken({ sub, type: 'human', expiresInSeconds: 3600 }))!
  }

  it('narrows a human token to one org and a scope', async () => {
    const res = await post(app(), '/exchange', { org_id: 'org_1', scope: 'read', expires_in: 600 }, await humanToken())
    expect(res.status).toBe(200)

    const body = (await res.json()) as { token: string; expires_in: number }
    const claims = await verifyToken(body.token)

    expect(claims?.sub).toBe('usr_1')
    expect(claims?.type).toBe('assistant')
    expect(claims?.['org_id']).toBe('org_1')
    expect(claims?.['scope']).toBe('read')
    expect(body.expires_in).toBe(600)
  })

  it('keeps the subject: a caller cannot exchange into someone else', async () => {
    const res = await post(app(), '/exchange', { sub: 'usr_victim', org_id: 'org_1' }, await humanToken('usr_1'))
    const { token } = (await res.json()) as { token: string }
    expect((await verifyToken(token))?.sub).toBe('usr_1')
  })

  it('refuses to exchange a service token, so chains cannot be built', async () => {
    const issued = await post(app(), '/service-token', { client_id: 'zone9-api', client_secret: 's3cret-one' })
    const { token } = (await issued.json()) as { token: string }

    const res = await post(app(), '/exchange', { org_id: 'org_1' }, token)
    expect(res.status).toBe(403)
  })

  it('refuses to exchange a token from another realm', async () => {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true })
    const { loadSigningKey, mint } = await import('@baseworks/auth/identity')
    const foreign = await loadSigningKey(await exportPKCS8(privateKey))
    const token = await mint(foreign, { sub: 'usr_1', type: 'human' }, {
      issuer: ISSUER, audience: AUDIENCE, expiresInSeconds: 600,
    })

    expect((await post(app(), '/exchange', { org_id: 'org_1' }, token)).status).toBe(401)
  })

  it('rejects a missing token', async () => {
    expect((await post(app(), '/exchange', { org_id: 'org_1' })).status).toBe(401)
  })
})
