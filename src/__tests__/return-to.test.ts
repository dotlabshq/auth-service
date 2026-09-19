import { describe, it, expect } from 'vitest'
import { returnOrigins, safeReturnTo } from '../lib/return-to.js'

const allowed = ['http://localhost:8080', 'http://doubletap.localhost:8080']

describe('where a sign-in may send the browser afterwards', () => {
  it('keeps a path on the origin the browser is already on', () => {
    expect(safeReturnTo('/entries', allowed)).toBe('/entries')
    expect(safeReturnTo('/reports/trial-balance?from=2026-04-01', allowed)).toBe('/reports/trial-balance?from=2026-04-01')
  })

  it('keeps an absolute URL on an origin this realm publishes', () => {
    expect(safeReturnTo('http://doubletap.localhost:8080/bank', allowed)).toBe('http://doubletap.localhost:8080/bank')
  })

  it('refuses an origin this realm does not publish', () => {
    expect(safeReturnTo('https://evil.example/pay-me', allowed)).toBe('/')
    // The victim's own realm name, on somebody else's domain.
    expect(safeReturnTo('https://localhost:8080.evil.example', allowed)).toBe('/')
  })

  it('refuses what looks like a path and is another origin', () => {
    // Protocol-relative: a browser reads this as https://evil.example.
    expect(safeReturnTo('//evil.example', allowed)).toBe('/')
    // Several browsers normalise the backslash to a slash before resolving.
    expect(safeReturnTo('/\\evil.example', allowed)).toBe('/')
  })

  it('refuses a scheme that is not the web', () => {
    expect(safeReturnTo('javascript:alert(1)', allowed)).toBe('/')
    expect(safeReturnTo('data:text/html,<script>', allowed)).toBe('/')
  })

  it('falls back to the root when nothing was asked for', () => {
    expect(safeReturnTo(undefined, allowed)).toBe('/')
    expect(safeReturnTo('   ', allowed)).toBe('/')
  })
})

describe('the allowlist', () => {
  it('always holds the realm’s own origin, and drops a trailing path', () => {
    expect(returnOrigins({ APP_PUBLIC_URL: 'http://localhost:8080/' })).toEqual(['http://localhost:8080'])
  })

  it('takes the extras as a comma-separated list', () => {
    expect(returnOrigins({
      APP_PUBLIC_URL: 'http://localhost:8080',
      AUTH_RETURN_ORIGINS: 'http://doubletap.localhost:8080, http://localhost:8080',
    })).toEqual(['http://localhost:8080', 'http://doubletap.localhost:8080'])
  })

  it('drops a misconfigured entry rather than widening the list', () => {
    expect(returnOrigins({ APP_PUBLIC_URL: 'http://localhost:8080', AUTH_RETURN_ORIGINS: 'not a url' }))
      .toEqual(['http://localhost:8080'])
  })
})
