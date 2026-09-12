import { Hono } from 'hono'
import { beforeEach, afterEach, describe, expect, it } from 'vitest'
import { exportPKCS8, generateKeyPair, type JSONWebKeySet } from 'jose'
import { verifier } from '@baseworks/auth/identity'
import { cliRouter } from '../routes/cli.js'
import { oidcRouter } from '../routes/oidc.js'
import { resetRealm } from '../lib/realm.js'
import { InMemoryKv, JWT_SECRET, makeSessionCookie, SESSION_COOKIE_NAME } from './setup.js'

const ISSUER = 'https://auth.example.test'
const AUDIENCE = 'example-realm'

async function signingKeyEnv(): Promise<string> {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true })
  return Buffer.from(await exportPKCS8(privateKey)).toString('base64')
}

/** The two routes that mint tokens, mounted with the environment under test. */
function app() {
  const a = new Hono()
  a.route('/', oidcRouter())
  a.route('/', cliRouter(new InMemoryKv() as never))
  a.get('/.well-known/jwks.json', async (c) => {
    const { realm } = await import('../lib/realm.js')
    const r = await realm()
    return c.json(r.jwks ?? { keys: [] })
  })
  return a
}

/** Drive the CLI device flow to the point where a token is issued. */
async function approvedToken(a: Hono): Promise<string> {
  const start = (await (await a.request('/start')).json()) as { state: string }
  const session = makeSessionCookie({
    isAuthenticated: true, subject: 'oidc-sub', userId: 'usr_1',
    email: 'a@b.test', name: 'A', issuer: 'https://idp.test',
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
  })
  await a.request('/approve', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: `${SESSION_COOKIE_NAME}=${session}`,
    },
    body: `state=${start.state}`,
  })
  const done = (await (await a.request(`/poll/${start.state}`)).json()) as { token: string }
  return done.token
}

beforeEach(() => {
  resetRealm()
  process.env['APP_PUBLIC_URL'] = 'http://localhost'
  process.env['AUTH_ISSUER'] = ISSUER
  process.env['AUTH_AUDIENCE'] = AUDIENCE
  delete process.env['IAM_SERVICE_URL']
})

afterEach(() => {
  delete process.env['AUTH_SIGNING_KEY']
  delete process.env['AUTH_ISSUER']
  delete process.env['AUTH_AUDIENCE']
  resetRealm()
})

describe('with a signing key configured', () => {
  beforeEach(async () => {
    process.env['AUTH_SIGNING_KEY'] = await signingKeyEnv()
    process.env['JWT_SECRET'] = JWT_SECRET
    resetRealm()
  })

  it('publishes exactly one public key, without the private half', async () => {
    const res = await app().request('/.well-known/jwks.json')
    const body = (await res.json()) as JSONWebKeySet

    expect(body.keys).toHaveLength(1)
    expect(body.keys[0]?.alg).toBe('ES256')
    expect(body.keys[0]?.kid).toBeTruthy()
    expect(JSON.stringify(body)).not.toContain('"d"')
  })

  it('mints an ES256 token the published key set verifies', async () => {
    const a = app()
    const token = await approvedToken(a)
    const set = (await (await a.request('/.well-known/jwks.json')).json()) as JSONWebKeySet

    const claims = await verifier({ jwks: set, issuer: ISSUER, audience: AUDIENCE })(token)

    expect(claims?.sub).toBe('usr_1')
    expect(claims?.type).toBe('human')
    expect(claims?.jti).toBeTruthy()
  })

  it('does not mint HS256 even though the legacy secret is still set', async () => {
    const token = await approvedToken(app())
    const header = JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString()) as {
      alg: string
      kid?: string
    }

    // The whole point of the migration: once a key exists, the shared secret
    // stops being able to speak for the realm.
    expect(header.alg).toBe('ES256')
    expect(header.kid).toBeTruthy()
  })
})

describe('without a signing key', () => {
  beforeEach(() => {
    delete process.env['AUTH_SIGNING_KEY']
    process.env['JWT_SECRET'] = JWT_SECRET
    resetRealm()
  })

  it('keeps minting HS256, so the service can be deployed before keys exist', async () => {
    const token = await approvedToken(app())
    const header = JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString()) as {
      alg: string
    }
    expect(header.alg).toBe('HS256')
  })

  it('serves an empty key set rather than a 404', async () => {
    const res = await app().request('/.well-known/jwks.json')
    expect(res.status).toBe(200)
    expect(((await res.json()) as JSONWebKeySet).keys).toEqual([])
  })
})
