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
  /**
   * Read a key and remove it in one step: of two callers at once, one gets the value
   * and the other gets null (Redis GETDEL; the in-process store does it without yielding).
   * Anything that must be used once — an authorization code — is taken, never read then deleted.
   */
  take?(key: string): Promise<string | null>
}

/** `kv.take` where there is one; read-then-delete where there is not (not atomic: only for a KV that cannot do better). */
export async function kvTake(kv: KvClient, key: string): Promise<string | null> {
  if (kv.take) return kv.take(key)
  const v = await kv.get(key)
  if (v !== null) await kv.del(key)
  return v
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
    take: (key) => redis.getdel(key),
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
  const store = new Map<string, { value: string; expires_at: number | null }>()
  const live = (key: string) => {
    const e = store.get(key)
    if (!e) return null
    if (e.expires_at !== null && e.expires_at <= nowMs()) {
      store.delete(key)
      return null
    }
    return e
  }
  return {
    get: async (key) => live(key)?.value ?? null,
    set: async (key, value, opts) => {
      store.set(key, { value, expires_at: opts?.ttl ? nowMs() + opts.ttl * 1000 : null })
    },
    del: async (key) => {
      store.delete(key)
    },
    // No await between the read and the delete: nothing else runs in between.
    take: async (key) => {
      const v = live(key)?.value ?? null
      store.delete(key)
      return v
    },
  }
}
