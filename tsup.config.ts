import { defineConfig } from 'tsup'

export default defineConfig({
  entry:      ['src/index.ts'],
  format:     ['esm'],
  outDir:     'dist',
  dts:        false,
  noExternal: [
    '@baseworks/account',
    '@baseworks/auth',
    '@baseworks/crypto',
    '@baseworks/organization',
    '@baseworks/core',
    '@dotlabshq/flect-sdk',
    '@hono/node-server',
    'hono',
    '@hono/zod-validator',
    'zod',
    'drizzle-orm',
  ],
  external: ['@libsql/client', 'ioredis'],
})
