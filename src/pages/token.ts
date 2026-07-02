export function tokenPage(state: string): string {
  const base = (process.env['APP_PUBLIC_URL'] ?? '').replace(/\/+$/, '')
  const approveUrl = `${base}/v1/auth/approve`
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize CLI Access</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0 }
    body {
      min-height: 100vh; display: flex; flex-direction: column;
      align-items: center; justify-content: center;
      font-family: system-ui, -apple-system, sans-serif;
      background: #fafafa; color: #111; gap: 16px; padding: 24px;
    }
    h1  { font-size: 22px; font-weight: 600 }
    p   { font-size: 14px; color: #555; max-width: 380px; text-align: center; line-height: 1.5 }
    button {
      margin-top: 8px; padding: 11px 32px; font-size: 14px; font-weight: 600;
      background: #000; color: #fff; border: none; border-radius: 8px; cursor: pointer;
    }
    button:hover { background: #222 }
  </style>
</head>
<body>
  <h1>Authorize CLI Access</h1>
  <p>A CLI session is requesting access to your account. Approving will allow your terminal to authenticate as you.</p>
  <form method="POST" action="${approveUrl}">
    <input type="hidden" name="state" value="${state}">
    <button type="submit">Approve</button>
  </form>
</body>
</html>`
}

export function donePage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorized</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0 }
    body {
      min-height: 100vh; display: flex; flex-direction: column;
      align-items: center; justify-content: center;
      font-family: system-ui, -apple-system, sans-serif;
      background: #fafafa; color: #111; gap: 12px; padding: 24px;
    }
    h1  { font-size: 22px; font-weight: 600 }
    p   { font-size: 14px; color: #555 }
  </style>
</head>
<body>
  <h1>&#10003; Authorized</h1>
  <p>You can close this tab. Your CLI session is now active.</p>
</body>
</html>`
}
