import { brand as realmBrand, type Brand } from '@baseworks/core/pages'

export type { Brand }

/**
 * What the pages look like. The realm's settings are `REALM_UI_*`, shared with
 * every service that serves pages (`@baseworks/core/pages`); `AUTH_UI_*`, the
 * names 2.0 shipped with, still win for this service when set.
 */
export function brand(env: Record<string, string | undefined> = process.env): Brand {
  return realmBrand(env, 'AUTH')
}
