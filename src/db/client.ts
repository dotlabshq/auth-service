import type { LibSqlClient } from '@dotlabshq/flect-sdk'
import { drizzle } from 'drizzle-orm/libsql'
import * as accountSchema from '@baseworks/account/schema/sqlite'
import * as orgSchema from '@baseworks/organization/schema/sqlite'

export const schema = { ...accountSchema, ...orgSchema }
export type DB = ReturnType<typeof createDB>

export function createDB(dbClient: LibSqlClient) {
  // LibSqlClient implements the @libsql/client Client interface
  return drizzle(dbClient as never, { schema })
}
