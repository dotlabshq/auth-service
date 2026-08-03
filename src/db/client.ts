import type { Redis } from 'ioredis'

/**
 * The small KV surface the OIDC/CLI routes need. `@baseworks/sdk`'s `env.kv()`
 * hands back a raw ioredis instance, so `kvAdapter` re-exposes the get/set/del
 * shape the routers were written against (ioredis `set(k,v,'EX',s)` vs a
 * `set(k,v,{ttl})` wrapper).
 *
 * auth keeps no database — identity + org data live in IAM — so this file is the
 * whole persistence surface: a cache for OIDC PKCE state and CLI login states.
 */
export interface KvClient {
  get(key: string): Promise<string | null>
  set(key: string, value: string, opts?: { ttl?: number }): Promise<void>
  del(key: string): Promise<void>
}

export function kvAdapter(redis: Redis): KvClient {
  return {
    get: (key) => redis.get(key),
    set: async (key, value, opts) => {
      if (opts?.ttl) await redis.set(key, value, 'EX', opts.ttl)
      else await redis.set(key, value)
    },
    del: async (key) => {
      await redis.del(key)
    },
  }
}

/**
 * In-process fallback when no CACHE binding is configured. auth's whole
 * persistence surface is short-lived OIDC/CLI state, so a single-instance Map
 * with lazy TTL expiry is a correct (if non-shared, non-durable) substitute:
 * the plane boots and logs in without an external cache. Swap in a real
 * `redis://` CACHE binding for multi-instance / restart-durable state.
 *
 * `nowMs` is injected (Date.now() is unavailable in some sandboxes) and defaults
 * to the real clock at runtime.
 */
export function memoryKvAdapter(nowMs: () => number = () => Date.now()): KvClient {
  const store = new Map<string, { value: string; expiresAt: number | null }>()
  const live = (key: string) => {
    const e = store.get(key)
    if (!e) return null
    if (e.expiresAt !== null && e.expiresAt <= nowMs()) {
      store.delete(key)
      return null
    }
    return e
  }
  return {
    get: async (key) => live(key)?.value ?? null,
    set: async (key, value, opts) => {
      store.set(key, { value, expiresAt: opts?.ttl ? nowMs() + opts.ttl * 1000 : null })
    },
    del: async (key) => {
      store.delete(key)
    },
  }
}
