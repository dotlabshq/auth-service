import { createClient } from '@libsql/client'
import { drizzle } from 'drizzle-orm/libsql'
import { Hono } from 'hono'
import * as accountSchema from '@baseworks/account/schema/sqlite'
import * as orgSchema from '@baseworks/organization/schema/sqlite'
import { cliRouter } from '../routes/cli.js'
import { oidcRouter } from '../routes/oidc.js'
import { signHs256Jwt } from '@baseworks/auth/jwt'
import { generateId, generateShortId } from '@baseworks/core'

const schema = { ...accountSchema, ...orgSchema }

export const JWT_SECRET = 'test-secret-32-chars-long-enough!'

// Tables used by auth-service CLI and OIDC routes
const MIGRATION_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY NOT NULL,
  subject TEXT NOT NULL,
  issuer TEXT NOT NULL,
  email TEXT NOT NULL,
  name TEXT,
  picture TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(subject, issuer)
);
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY NOT NULL,
  short_id TEXT NOT NULL UNIQUE,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  metadata TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS org_memberships (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(organization_id, user_id)
);
CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  short_id TEXT NOT NULL UNIQUE,
  slug TEXT NOT NULL,
  name TEXT NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(organization_id, slug)
);
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  short_id TEXT NOT NULL UNIQUE,
  slug TEXT NOT NULL,
  name TEXT NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0,
  metadata TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(workspace_id, slug)
);
CREATE TABLE IF NOT EXISTS environments (
  id TEXT PRIMARY KEY NOT NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  short_id TEXT NOT NULL UNIQUE,
  slug TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(project_id, slug)
);
`

// Simple in-memory KV that satisfies the KvClient interface used by cliRouter
export class InMemoryKv {
  private store = new Map<string, string>()
  async get(key: string) { return this.store.get(key) ?? null }
  async set(key: string, value: string, _opts?: { ttl?: number }) { this.store.set(key, value); return this }
  async del(key: string) { this.store.delete(key); return this }
  // expose raw store for test assertions
  _raw() { return this.store }
}

/** Identity JWT — no org_id, as issued right after OIDC approve */
export function makeIdentityToken(userId: string) {
  return signHs256Jwt({ sub: userId, type: 'human' }, JWT_SECRET, 3600)
}

/** Org-scoped JWT — as issued by token-for-org */
export function makeOrgToken(userId: string, orgId: string, role = 'member') {
  return signHs256Jwt({ sub: userId, org_id: orgId, role, type: 'human' }, JWT_SECRET, 3600)
}

/** Encode a session cookie value exactly as encodeSession() does in cookies.ts */
export function makeSessionCookie(data: Record<string, unknown>) {
  return btoa(JSON.stringify(data)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export const SESSION_COOKIE_NAME = 'oidc_session'

export async function createTestApp() {
  process.env['JWT_SECRET'] = JWT_SECRET
  process.env['APP_PUBLIC_URL'] = 'http://localhost'

  const client = createClient({ url: ':memory:' })
  const stmts = MIGRATION_SQL.split(';').map(s => s.trim()).filter(Boolean)
  for (const sql of stmts) await client.execute(sql)

  const db = drizzle(client as never, { schema })
  const kv = new InMemoryKv()

  const app = new Hono()
  app.route('/', oidcRouter(db))
  app.route('/', cliRouter(db, kv as never))

  function req(method: string, path: string, opts: {
    body?: unknown
    token?: string
    cookie?: string
    contentType?: string
  } = {}) {
    const headers: Record<string, string> = {}
    if (opts.token) headers['Authorization'] = `Bearer ${opts.token}`
    if (opts.body !== undefined) headers['Content-Type'] = opts.contentType ?? 'application/json'
    if (opts.cookie) headers['Cookie'] = opts.cookie
    const init: RequestInit = { method, headers }
    if (opts.body !== undefined) init.body = JSON.stringify(opts.body)
    return app.fetch(new Request(`http://localhost${path}`, init))
  }

  // Seed helpers
  async function seedUser(overrides: Partial<{
    id: string; subject: string; issuer: string; email: string; name: string
  }> = {}) {
    const now = Date.now()
    const user = {
      id:        overrides.id      ?? generateId(),
      subject:   overrides.subject ?? 'sub-001',
      issuer:    overrides.issuer  ?? 'https://auth.test',
      email:     overrides.email   ?? 'user@test.com',
      name:      overrides.name    ?? 'Test User',
      picture:   null,
      createdAt: now,
      updatedAt: now,
    }
    await db.insert(schema.users).values(user)
    return user
  }

  async function seedOrg(overrides: Partial<{ id: string; slug: string; name: string }> = {}) {
    const now = Date.now()
    const org = {
      id:        overrides.id   ?? generateId(),
      shortId:   generateShortId(),
      slug:      overrides.slug ?? 'test-org',
      name:      overrides.name ?? 'Test Org',
      metadata:  null,
      createdAt: now,
      updatedAt: now,
    }
    await db.insert(schema.organizations).values(org)
    return org
  }

  async function seedMembership(userId: string, orgId: string, role = 'member') {
    const now = Date.now()
    const mem = { id: generateId(), organizationId: orgId, userId, role, createdAt: now, updatedAt: now }
    await db.insert(schema.orgMemberships).values(mem)
    return mem
  }

  return {
    db,
    kv,
    get:  (path: string, opts?: Parameters<typeof req>[2]) => req('GET', path, opts),
    post: (path: string, body: unknown, opts?: Omit<Parameters<typeof req>[2], 'body'>) =>
      req('POST', path, { body, ...opts }),
    seedUser,
    seedOrg,
    seedMembership,
  }
}
