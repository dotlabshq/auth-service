import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

/**
 * Dev mode: sign in with a username and password instead of an identity
 * provider.
 *
 * A realm on a laptop should not need a Zitadel project, a registered PKCE
 * client and a callback URL before anyone can open the console. With
 * `AUTH_DEV_MODE=1`, `/login` shows a form instead of redirecting to the IdP,
 * and one account signs in there. Everything after the form is the ordinary
 * path: the same signed session cookie, the same identity token, the same IAM
 * `/sync` — so the console, `bw login` and every service behave exactly as they
 * will behind a real IdP.
 *
 * The password is random per boot and printed to the log, unless
 * `AUTH_DEV_PASSWORD` fixes it. The account is always the same identity
 * (`DEV_ISSUER` + the username), so with IAM present it resolves to the same
 * user id across restarts and keeps its org memberships.
 *
 * It refuses to start under `NODE_ENV=production`. A realm that can be entered
 * with a password in an env var is a realm with no identity provider, and that
 * must never be one flag away from production.
 */

/** The issuer recorded for a dev sign-in. Not a URL: nothing will ever fetch it. */
export const DEV_ISSUER = 'urn:baseworks:dev'

/** How long a dev session lasts. A working day; sign in again tomorrow. */
export const DEV_SESSION_SECONDS = 12 * 60 * 60

export interface DevLogin {
  username: string
  password: string
  /** True when the password was made up at boot rather than read from the env. */
  generated: boolean
}

function on(v: string | undefined): boolean {
  return ['1', 'true', 'yes', 'on'].includes((v ?? '').trim().toLowerCase())
}

/**
 * The dev account, or null when dev mode is off. Throws under production:
 * called at boot, so the service does not start rather than start open.
 */
export function devLogin(env: NodeJS.ProcessEnv = process.env): DevLogin | null {
  if (!on(env['AUTH_DEV_MODE'])) return null
  if (env['NODE_ENV'] === 'production') {
    throw new Error('AUTH_DEV_MODE is set under NODE_ENV=production — refusing to start with a password sign-in')
  }
  const username = (env['AUTH_DEV_USER'] || 'admin').trim()
  const fixed = env['AUTH_DEV_PASSWORD']
  return fixed
    ? { username, password: fixed, generated: false }
    : { username, password: randomBytes(12).toString('base64url'), generated: true }
}

/**
 * Whether the pair is the dev account. Both sides are hashed first so the
 * comparison is constant-time whatever the lengths — timingSafeEqual on the raw
 * strings would throw on a length mismatch, and that throw leaks the length.
 */
export function devCredentialsMatch(dev: DevLogin, username: string, password: string): boolean {
  const h = (s: string) => createHash('sha256').update(s, 'utf8').digest()
  const userOk = timingSafeEqual(h(username), h(dev.username))
  const passOk = timingSafeEqual(h(password), h(dev.password))
  return userOk && passOk
}

/** The boot banner: what to type, where it will be seen. */
export function devBanner(dev: DevLogin, loginUrl: string): string {
  const pw = dev.generated ? dev.password : '(AUTH_DEV_PASSWORD)'
  return [
    '',
    '  auth-service: DEV MODE — no identity provider, password sign-in',
    `    sign in at  ${loginUrl}`,
    `    user        ${dev.username}`,
    `    password    ${pw}`,
    '',
  ].join('\n')
}
