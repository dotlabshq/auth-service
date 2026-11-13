/**
 * Fetching a URL a stranger named, safely (a Client ID Metadata Document: the
 * client's `client_id` IS a URL it controls). The rules, each tested:
 *
 *  · `https` only, no credentials in the URL, a default port or 443-class, no redirect followed;
 *  · the address the connection goes to is checked **at connect time** (a
 *    custom `lookup`), so a name that resolved to a public address a moment ago
 *    and to 169.254.169.254 now (DNS rebinding) is refused;
 *  · private, loopback, link-local, unique-local, multicast, reserved and
 *    metadata ranges, IPv4 and IPv6 (and IPv4-mapped IPv6), are refused;
 *  · a time limit and a size limit; JSON only.
 */
import { lookup as dnsLookup } from 'node:dns'
import { request } from 'node:https'
import { isIP } from 'node:net'

export class FetchRefused extends Error {
  constructor(readonly code: 'bad_url' | 'blocked_address' | 'too_large' | 'timeout' | 'bad_status' | 'not_json' | 'network') {
    super(code)
    this.name = 'FetchRefused'
  }
}

/** True for an address a server must never fetch from on a stranger's say-so. */
export function isBlockedAddress(address: string): boolean {
  const ip = address.replace(/^\[|\]$/g, '').toLowerCase()
  const v = isIP(ip)
  if (v === 4) {
    const [a, b, c] = ip.split('.').map(Number) as [number, number, number, number]
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
      (a === 169 && b === 254) || // link-local, cloud metadata
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && c === 0) || (a === 192 && b === 0 && c === 2) ||
      (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113)
    )
  }
  if (v === 6) {
    if (ip === '::' || ip === '::1') return true
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip)
    if (mapped) return isBlockedAddress(mapped[1]!)
    const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(ip)
    if (hex) {
      const n = (parseInt(hex[1]!, 16) << 16) | parseInt(hex[2]!, 16)
      return isBlockedAddress(`${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`)
    }
    const first = parseInt(ip.split(':')[0] || '0', 16)
    return (
      (first & 0xfe00) === 0xfc00 || // unique local fc00::/7
      (first & 0xffc0) === 0xfe80 || // link-local fe80::/10
      (first & 0xff00) === 0xff00 || // multicast
      ip.startsWith('64:ff9b:') || ip.startsWith('2001:db8:') // NAT64, documentation
    )
  }
  return true // not an address at all: never connect to it
}

export interface FetchOptions { timeoutMs?: number; maxBytes?: number }

/** What a tests may replace: the real fetch is below. */
export type JsonFetcher = (url: string, opts?: FetchOptions) => Promise<{ json: unknown; headers: Record<string, string> }>

export const fetchJsonGuarded: JsonFetcher = (rawUrl, opts = {}) => {
  const timeoutMs = opts.timeoutMs ?? 5000
  const maxBytes = opts.maxBytes ?? 64 * 1024
  let url: URL
  try { url = new URL(rawUrl) } catch { return Promise.reject(new FetchRefused('bad_url')) }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) return Promise.reject(new FetchRefused('bad_url'))
  if (isIP(url.hostname.replace(/^\[|\]$/g, '')) && isBlockedAddress(url.hostname)) return Promise.reject(new FetchRefused('blocked_address'))

  return new Promise((resolve, reject) => {
    let settled = false
    const done = (fn: () => void) => { if (!settled) { settled = true; fn() } }
    const req = request(url, {
      method: 'GET',
      headers: { accept: 'application/json', 'user-agent': 'baseworks-auth-service/oauth-cimd' },
      timeout: timeoutMs,
      // The check that matters: on the address the socket is about to use.
      lookup: (hostname, options, cb) => {
        dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
          if (err) return cb(err, '', 4)
          const list = addresses as unknown as Array<{ address: string; family: number }>
          const bad = list.find((a) => isBlockedAddress(a.address))
          if (bad || list.length === 0) return cb(new FetchRefused('blocked_address') as never, '', 4)
          const first = list[0]!
          if ((options as { all?: boolean }).all) return (cb as unknown as (e: null, a: unknown) => void)(null, list)
          cb(null, first.address, first.family)
        })
      },
    }, (res) => {
      const status = res.statusCode ?? 0
      // A redirect is a second URL nobody checked: refused, not followed.
      if (status < 200 || status >= 300) { res.resume(); return done(() => reject(new FetchRefused('bad_status'))) }
      const chunks: Buffer[] = []
      let size = 0
      res.on('data', (b: Buffer) => {
        size += b.length
        if (size > maxBytes) { req.destroy(); return done(() => reject(new FetchRefused('too_large'))) }
        chunks.push(b)
      })
      res.on('end', () => {
        try {
          const json = JSON.parse(Buffer.concat(chunks).toString('utf8'))
          const headers: Record<string, string> = {}
          for (const [k, v] of Object.entries(res.headers)) if (typeof v === 'string') headers[k] = v
          done(() => resolve({ json, headers }))
        } catch { done(() => reject(new FetchRefused('not_json'))) }
      })
      res.on('error', () => done(() => reject(new FetchRefused('network'))))
    })
    req.on('timeout', () => { req.destroy(); done(() => reject(new FetchRefused('timeout'))) })
    req.on('error', (e) => done(() => reject(e instanceof FetchRefused ? e : (e as { code?: string }).code === 'ERR_BLOCKED' ? new FetchRefused('blocked_address') : new FetchRefused(/blocked_address/.test(String(e.message)) ? 'blocked_address' : 'network'))))
    req.end()
  })
}
