import type { DbClient } from '@dotlabshq/flect-sdk'
import { drizzle } from 'drizzle-orm/libsql'
import type { Client } from '@libsql/client'
import * as accountSchema from '@baseworks/account/schema/sqlite'
import * as orgSchema from '@baseworks/organization/schema/sqlite'

export const schema = { ...accountSchema, ...orgSchema }
export type DB = ReturnType<typeof createDB>

export function createDB(dbClient: DbClient) {
  return drizzle(dbClient as unknown as Client, { schema })
}
