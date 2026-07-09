import type { Redis } from 'ioredis'

/**
 * The small KV surface the OIDC/CLI routes need. With @getflect/sdk the resolved
 * cache client is a raw ioredis instance, so `kvAdapter` re-exposes the
 * get/set/del shape the routers were written against (ioredis `set(k,v,'EX',s)`
 * vs the old SDK's `set(k,v,{ttl})`).
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
