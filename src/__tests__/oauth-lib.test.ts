/**
 * The pieces under OAuth for MCP clients: which redirect URIs are allowed and how they
 * match, which addresses a server must never fetch, and how a client is told apart
 * (Client ID Metadata Document, registered, pre-registered).
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { redirectAllowed, redirectMatches, isLoopbackRedirect } from '../lib/oauth/redirect.js'
import { FetchRefused, fetchJsonGuarded, isBlockedAddress } from '../lib/oauth/ssrf.js'
import { lookupClient, setClientDocumentFetcher } from '../lib/oauth/clients.js'

const saved = { ...process.env }
afterEach(() => { process.env = { ...saved }; setClientDocumentFetcher(null) })

describe('redirect URIs', () => {
  it.each([
    ['https://app.example.test/cb', true], ['https://app.example.test:8443/cb?x=1', true],
    ['http://localhost/callback', true], ['http://localhost:54321/callback', true], ['http://127.0.0.1:8080/cb', true], ['http://[::1]:8080/cb', true],
    ['http://app.example.test/cb', false], ['http://localhost.evil.test/cb', false], ['http://127.0.0.1.evil.test/cb', false],
    ['https://app.example.test/cb#frag', false], ['https://user:pw@app.example.test/cb', false],
    ['myapp://cb', false], ['javascript:alert(1)', false], ['data:text/html,x', false], ['file:///etc/passwd', false],
    ['/relative', false], ['', false], ['https://' + 'a'.repeat(600) + '.test/', false],
  ])('%s allowed: %s', (uri, ok) => { expect(redirectAllowed(uri)).toBe(ok) })

  it('matches exactly: scheme, host, port, path and query', () => {
    const reg = ['https://app.example.test/cb', 'https://other.example.test:8443/x?y=1']
    expect(redirectMatches(reg, 'https://app.example.test/cb')).toBe(true)
    for (const bad of ['https://app.example.test/cb/', 'https://app.example.test/CB', 'https://app.example.test:444/cb', 'http://app.example.test/cb', 'https://app.example.test/cb?x=1', 'https://app.example.test.evil.test/cb', 'https://evil.test/cb', 'https://other.example.test:8443/x', 'https://other.example.test:8443/x?y=2']) {
      expect(redirectMatches(reg, bad), bad).toBe(false)
    }
    expect(redirectMatches(reg, 'https://other.example.test:8443/x?y=1')).toBe(true)
  })

  it('a registered loopback address matches the same host, path and query on any port (RFC 8252), and only that', () => {
    const reg = ['http://localhost/callback', 'http://127.0.0.1/callback']
    for (const ok of ['http://localhost/callback', 'http://localhost:1/callback', 'http://localhost:54321/callback', 'http://127.0.0.1:60001/callback']) expect(redirectMatches(reg, ok), ok).toBe(true)
    for (const bad of ['http://localhost/other', 'http://localhost:5/callback?x=1', 'http://[::1]:5/callback', 'https://localhost:5/callback', 'http://localhost.evil.test:5/callback', 'http://127.0.0.2:5/callback', 'http://localhost:5/callback/']) {
      expect(redirectMatches(reg, bad), bad).toBe(false)
    }
  })

  it('a non-loopback registration never gets the port exception, and an https registration is not matched by http on loopback', () => {
    expect(redirectMatches(['https://app.example.test/cb'], 'https://app.example.test:9/cb')).toBe(false)
    expect(redirectMatches(['https://localhost/cb'], 'http://localhost:9/cb')).toBe(false)
    expect(redirectMatches([], 'https://app.example.test/cb')).toBe(false)
    expect(redirectMatches(['http://localhost/cb'], 'http://localhost:9/cb#x')).toBe(false)
    expect(isLoopbackRedirect('http://localhost:9/cb')).toBe(true)
    expect(isLoopbackRedirect('https://localhost/cb')).toBe(false)
  })
})

describe('addresses a server must never fetch', () => {
  it.each([
    '127.0.0.1', '127.1.2.3', '0.0.0.0', '10.0.0.1', '10.255.255.255', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '169.254.0.1',
    '100.64.0.1', '100.127.255.255', '224.0.0.1', '255.255.255.255', '192.0.0.1', '192.0.2.1', '198.18.0.1', '198.51.100.1', '203.0.113.1',
    '::', '::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'febf::1', 'ff02::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '::ffff:169.254.169.254', '::ffff:7f00:1', '64:ff9b::1', '2001:db8::1', '[::1]', 'not-an-ip', '',
  ])('%s is blocked', (a) => { expect(isBlockedAddress(a)).toBe(true) })

  it.each(['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.15.0.1', '172.32.0.1', '100.63.255.255', '100.128.0.1', '169.253.0.1', '2606:4700:4700::1111', '2001:4860:4860::8888', '::ffff:8.8.8.8'])('%s is allowed', (a) => {
    expect(isBlockedAddress(a)).toBe(false)
  })

  const refused = (url: string) => fetchJsonGuarded(url).then(() => 'fetched', (e) => (e instanceof FetchRefused ? e.code : `other:${e}`))
  it('refuses a URL that is not plain https before any connection', async () => {
    for (const url of ['http://example.com/c.json', 'ftp://example.com/c.json', 'https://user:pw@example.com/c.json', 'https://example.com/c.json#x', 'not a url', 'file:///etc/passwd']) {
      expect(await refused(url), url).toBe('bad_url')
    }
  })

  it('refuses an IP literal in a blocked range without resolving anything', async () => {
    for (const url of ['https://127.0.0.1/c.json', 'https://10.1.2.3/c.json', 'https://169.254.169.254/latest/meta-data', 'https://[::1]/c.json', 'https://[fd00::1]/x', 'https://[::ffff:127.0.0.1]/x']) {
      expect(await refused(url), url).toBe('blocked_address')
    }
  })

  it('refuses a NAME that resolves to a blocked address, at connect time (the check is on the address the socket would use)', async () => {
    expect(await refused('https://localhost/c.json')).toBe('blocked_address')
    expect(await refused('https://localhost:8443/c.json')).toBe('blocked_address')
  })
})

describe('telling a client apart', () => {
  const URL_ = 'https://claude.example.test/oauth/client-metadata'
  const doc = (over: Record<string, unknown> = {}) => ({ client_id: URL_, client_name: 'Claude Example', redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'], token_endpoint_auth_method: 'none', ...over })
  const serve = (json: unknown, headers: Record<string, string> = {}) => {
    const calls: string[] = []
    setClientDocumentFetcher(async (u) => { calls.push(u); return { json, headers } })
    return calls
  }

  it('a metadata document: the name, the redirect URIs, public', async () => {
    serve(doc({ logo_uri: 'https://claude.example.test/logo.png' }))
    const r = await lookupClient(URL_)
    expect(r).toMatchObject({ ok: true, client: { client_id: URL_, client_name: 'Claude Example', kind: 'cimd', auth_method: 'none', logo_uri: 'https://claude.example.test/logo.png', redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'] } })
  })

  it.each([
    ['client_id that is not the URL', doc({ client_id: 'https://evil.test/x' })],
    ['no client_id', doc({ client_id: undefined })],
    ['no redirect_uris', doc({ redirect_uris: [] })],
    ['a redirect URI that is not allowed', doc({ redirect_uris: ['http://evil.test/cb'] })],
    ['a custom scheme', doc({ redirect_uris: ['myapp://cb'] })],
    ['a shared secret method', doc({ token_endpoint_auth_method: 'client_secret_basic' })],
    ['private_key_jwt with no keys', doc({ token_endpoint_auth_method: 'private_key_jwt' })],
    ['more than 20 redirect URIs', doc({ redirect_uris: Array.from({ length: 21 }, (_, i) => `https://a.test/${i}`) })],
    ['not an object', 'a string'],
    ['null', null],
  ])('refuses %s', async (_n, json) => {
    serve(json)
    expect(await lookupClient(URL_)).toEqual({ ok: false, reason: 'invalid_metadata' })
  })

  it('an http logo is dropped, a missing name falls back to the host, private_key_jwt with keys is accepted', async () => {
    serve(doc({ logo_uri: 'http://x.test/l.png', client_name: undefined, token_endpoint_auth_method: 'private_key_jwt', jwks: { keys: [] } }))
    expect(await lookupClient(URL_)).toMatchObject({ ok: true, client: { logo_uri: null, client_name: 'claude.example.test', auth_method: 'private_key_jwt' } })
  })

  it('is cached by Cache-Control, for at most an hour, and not at all for no-store', async () => {
    let calls = serve(doc(), { 'cache-control': 'max-age=60' })
    await lookupClient(URL_); await lookupClient(URL_)
    expect(calls).toHaveLength(1)
    calls = serve(doc(), { 'cache-control': 'no-store' })
    await lookupClient(URL_); await lookupClient(URL_)
    expect(calls).toHaveLength(2)
    calls = serve(doc(), { 'cache-control': 'max-age=99999999' })
    await lookupClient(URL_)
    await lookupClient(URL_)
    expect(calls).toHaveLength(1)
  })

  it('a fetch the guard refused is blocked; one that failed is unreachable; both are refusals', async () => {
    setClientDocumentFetcher(async () => { throw new FetchRefused('blocked_address') })
    expect(await lookupClient(URL_)).toEqual({ ok: false, reason: 'blocked' })
    setClientDocumentFetcher(async () => { throw new FetchRefused('timeout') })
    expect(await lookupClient(URL_)).toEqual({ ok: false, reason: 'unreachable' })
    setClientDocumentFetcher(async () => { throw new Error('boom') })
    expect(await lookupClient(URL_)).toEqual({ ok: false, reason: 'unreachable' })
  })

  it('a pre-registered client comes from configuration, and its redirect URIs are filtered', async () => {
    process.env['AUTH_OAUTH_CLIENTS'] = JSON.stringify([{ client_id: 'bw-cli', client_name: 'The CLI', redirect_uris: ['http://localhost/cb', 'http://evil.test/cb'] }])
    expect(await lookupClient('bw-cli')).toMatchObject({ ok: true, client: { client_name: 'The CLI', kind: 'static', redirect_uris: ['http://localhost/cb'], auth_method: 'none' } })
    process.env['AUTH_OAUTH_CLIENTS'] = 'not json'
    expect(await lookupClient('bw-cli')).toEqual({ ok: false, reason: 'unknown_client' })
  })

  it('anything else is unknown: empty, an http URL, a bare name, a huge id', async () => {
    for (const id of ['', 'http://x.test/c', 'nobody', 'x'.repeat(3000)]) expect(await lookupClient(id), id.slice(0, 20)).toEqual({ ok: false, reason: 'unknown_client' })
  })
})
