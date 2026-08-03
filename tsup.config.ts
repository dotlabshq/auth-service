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
    '@baseworks/sdk',
    '@baseworks/foldbase',
    '@baseworks/org',
    '@baseworks/iam',
    '@hono/node-server',
    'hono',
    '@hono/zod-validator',
    'zod',
  ],
  // ioredis is the raw KV driver @baseworks/sdk hands back (env.kv) — kept
  // external and installed at runtime, not bundled.
  external: ['ioredis', 'libsodium-wrappers'],
})
