/**
 * Audit lines: one JSON object per line on stdout, nothing else on that line,
 * for the infra log collector (workspace ADR 0004 §6). auth-service has no
 * store of its own, so the log is where "who signed in, who was refused, which
 * credentials were exchanged" lives; retention is infra's.
 *
 * One function writes them, so the shape cannot drift between routes:
 *
 *     audit('sign_in', { ...request(c), outcome: 'ok', ...envelope })
 *
 * Every line has `audit: 1`, `ts`, `event`, `service`, `request_id`, `ip`,
 * `user_agent` and `outcome` (`ok` | `refused`), and the envelope fields known
 * at that point. A refusal adds `reason`, always from a fixed vocabulary, never
 * a message built from input.
 *
 * **What never goes in a line**: a token, key, code, cookie, secret, password or
 * PKCE verifier. Only the fields below are written (anything else passed is
 * dropped, not logged), and a value that looks like a JWT or an API token is
 * replaced even in an allowed field. A credential is named by its id.
 *
 *   AUTH_AUDIT=off   no lines (tests turn them on by default)
 */
import { randomUUID } from 'node:crypto'
import type { Context } from 'hono'
import { auditEnvelope, principalOf, type Principal } from '@baseworks/auth/principal'

export type AuditEvent =
  | 'sign_in' | 'sign_out' | 'sign_in_refused' | 'cli_approval' | 'exchange' | 'exchange_key' | 'service_token'

export interface AuditFields {
  outcome: 'ok' | 'refused'
  request_id: string
  ip: string
  user_agent: string
  reason?: string
  kind?: string
  actor?: string
  actor_id?: string
  on_behalf_of?: string
  via?: string
  credential_id?: string
  client?: string
  org_id?: string
  /** The email as the provider returned it, on a refused sign-in only. */
  email?: string
  /** The service client id that was offered, on a refused service token. Not a secret. */
  client_id?: string
  /** `iam_sync_failed`: the sign-in went on with the provider's subject. */
  degraded?: string
}

/** The only keys a line may have, in the order they are written. */
const KEYS = [
  'outcome', 'reason', 'request_id', 'ip', 'user_agent',
  'kind', 'actor', 'actor_id', 'on_behalf_of', 'via', 'credential_id', 'client', 'org_id',
  'email', 'client_id', 'degraded',
] as const

/** A value that is a credential wherever it appears: a JWT, or an API token with more than its id. */
const SECRET = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}|bwt_[A-Za-z0-9_-]{8,}/

const clean = (v: unknown, max: number): string | undefined => {
  if (typeof v !== 'string' || !v) return undefined
  // eslint-disable-next-line no-control-regex
  const s = v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max)
  if (!s) return undefined
  return SECRET.test(s) ? '[redacted]' : s
}

export function auditEnabled(): boolean {
  return process.env['AUTH_AUDIT'] !== 'off'
}

/** Write one audit line. Never throws: a log that fails must not fail a sign-in. */
export function audit(event: AuditEvent, fields: AuditFields): void {
  if (!auditEnabled()) return
  try {
    const line: Record<string, unknown> = {
      audit: 1, ts: new Date().toISOString(), event, service: 'auth-service',
    }
    for (const key of KEYS) {
      const v = clean((fields as unknown as Record<string, unknown>)[key], key === 'user_agent' ? 300 : 200)
      if (v !== undefined) line[key] = v
    }
    // `ip` and `user_agent` are always there, empty if the request had none.
    line['ip'] ??= ''
    line['user_agent'] ??= ''
    process.stdout.write(`${JSON.stringify(line)}\n`)
  } catch {
    /* an audit line is best effort: the request it describes has been answered */
  }
}

/** The part of a request every line carries. */
export function request(c: Context): Pick<AuditFields, 'request_id' | 'ip' | 'user_agent'> {
  const given = c.req.header('X-Request-Id')
  const request_id = given && /^[A-Za-z0-9._-]{8,128}$/.test(given) ? given : randomUUID()
  const forwarded = (c.req.header('x-forwarded-for') ?? '').split(',')[0]?.trim()
  const socket = (c.env as { incoming?: { socket?: { remoteAddress?: string } } } | undefined)?.incoming?.socket?.remoteAddress
  const ip = (forwarded && /^[0-9A-Fa-f:.]{2,45}$/.test(forwarded) ? forwarded : socket) ?? ''
  return { request_id, ip, user_agent: c.req.header('user-agent') ?? '' }
}

/** What a person signed in with a session is, in the ADR 0004 envelope. */
export function personEnvelope(user_id: string, client = 'ui'): Partial<AuditFields> {
  return envelopeOf(principalOf({ sub: user_id, type: 'human' }), client)
}

/** The envelope fields of a principal: who, how, for whom, through which credential. */
export function envelopeOf(p: Principal, client?: string, org_id?: string): Partial<AuditFields> {
  const e = auditEnvelope(p, { ...(org_id ? { org_id } : {}) })
  const { request_id: _r, ...rest } = e
  return { ...rest, ...(client ? { client } : {}) } as Partial<AuditFields>
}
