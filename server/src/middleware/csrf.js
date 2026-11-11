import { doubleCsrf } from 'csrf-csrf';

// Routes that run before a session exists, so there is nothing to protect yet.
const CSRF_EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

// Double-submit-cookie CSRF protection.
// The server puts an httpOnly CSRF cookie in the browser and hands the same token
// to our own client in a response body. The client echoes it back in the
// `x-csrf-token` header on every write. An attacker's page gets the cookie sent
// automatically, but it cannot read the token, so it cannot set the header -> 403.
export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read lazily so the secret can come from .env (or be set by tests at runtime).
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind each CSRF token to the logged-in session (the auth cookie).
  getSessionIdentifier: (req) => req.cookies?.token || '',
  // Plain name (not the default "__Host-" prefix) so it works over http://localhost.
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/'
  },
  // GET, HEAD and OPTIONS are "safe" and are not checked.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => CSRF_EXEMPT_PATHS.has(req.path)
});

// GET /api/csrf-token: give our own client a fresh token. Other sites can trigger
// this request, but CORS stops them from reading the response.
export function sendCsrfToken(req, res) {
  res.json({ csrfToken: generateCsrfToken(req, res, { overwrite: true }) });
}
