import { escapeHtml } from '../lib/html.js'

/**
 * The dev-mode sign-in form. Posts back to `/login` under the public prefix,
 * carrying the (already checked) return address with it.
 */
export function devLoginPage(opts: { returnTo: string; error?: boolean; username?: string }): string {
  const base = (process.env['APP_PUBLIC_URL'] ?? '').replace(/\/+$/, '')
  const action = `${base}/v1/auth/login`
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in (dev)</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0 }
    body {
      min-height: 100vh; display: flex; flex-direction: column;
      align-items: center; justify-content: center;
      font-family: system-ui, -apple-system, sans-serif;
      background: #fafafa; color: #111; gap: 16px; padding: 24px;
    }
    h1   { font-size: 22px; font-weight: 600 }
    p    { font-size: 14px; color: #555; max-width: 340px; text-align: center; line-height: 1.5 }
    form { display: flex; flex-direction: column; gap: 10px; width: 100%; max-width: 300px }
    input {
      padding: 10px 12px; font-size: 14px; border: 1px solid #ccc; border-radius: 8px; background: #fff;
    }
    button {
      margin-top: 4px; padding: 11px; font-size: 14px; font-weight: 600;
      background: #000; color: #fff; border: none; border-radius: 8px; cursor: pointer;
    }
    button:hover { background: #222 }
    .tag   { font-size: 11px; font-weight: 600; letter-spacing: .06em; color: #a15c00; background: #fff4e0; padding: 3px 8px; border-radius: 999px }
    .error { color: #b00020 }
  </style>
</head>
<body>
  <span class="tag">DEV MODE</span>
  <h1>Sign in</h1>
  <p>This realm has no identity provider. The password is in auth-service's log.</p>
  ${opts.error ? '<p class="error" role="alert">That user and password do not match.</p>' : ''}
  <form method="POST" action="${escapeHtml(action)}">
    <input type="hidden" name="returnTo" value="${escapeHtml(opts.returnTo)}">
    <input name="username" autocomplete="username" placeholder="User" value="${escapeHtml(opts.username ?? '')}" required>
    <input name="password" type="password" autocomplete="current-password" placeholder="Password" required autofocus>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>`
}
