/** Redirect URIs (RFC 6749 §3.1.2, RFC 8252 §7.3, MCP authorization): HTTPS or loopback, matched exactly. */

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]'])

/** HTTPS, or http on a loopback host; no fragment, no credentials. */
export function redirectAllowed(raw: string): boolean {
  if (raw.length > 512) return false
  let u: URL
  try { u = new URL(raw) } catch { return false }
  if (u.hash || u.username || u.password) return false
  return u.protocol === 'https:' || (u.protocol === 'http:' && LOOPBACK.has(u.hostname))
}

export const isLoopbackRedirect = (raw: string): boolean => {
  try { const u = new URL(raw); return u.protocol === 'http:' && LOOPBACK.has(u.hostname) } catch { return false }
}

/**
 * Exact match against what the client registered, except that a registered
 * loopback address (`localhost`, `127.0.0.1`, `[::1]`) matches the same host,
 * path and query on any port: a native app picks its port at random (RFC 8252).
 * `localhost` does not match `127.0.0.1`: each is its own registration.
 */
export function redirectMatches(registered: readonly string[], given: string): boolean {
  if (!redirectAllowed(given)) return false
  for (const reg of registered) {
    if (reg === given) return true
    if (!isLoopbackRedirect(reg) || !isLoopbackRedirect(given)) continue
    const a = new URL(reg)
    const b = new URL(given)
    if (a.hostname === b.hostname && a.pathname === b.pathname && a.search === b.search) return true
  }
  return false
}
