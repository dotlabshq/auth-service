import { defineConfig } from 'tsup'

export default defineConfig({
  entry:      ['src/index.ts'],
  format:     ['esm'],
  outDir:     'dist',
  dts:        false,
  noExternal: [
    '@baseworks/auth',
    '@baseworks/crypto',
    '@baseworks/core',
    '@getflect/sdk',
    '@hono/node-server',
    'hono',
    '@hono/zod-validator',
    'zod',
  ],
  external: ['@libsql/client', 'ioredis', 'libsodium-wrappers'],
})
