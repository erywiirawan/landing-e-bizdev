// Edge Middleware — basic-auth gate for the e-BizDev portal root.
// Runs on every request before Vercel serves the static site.
// Credentials come from env vars AUTH_USER / AUTH_PASS (set on Vercel).

export const config = {
  // Apply to every path under the root.
  matcher: '/:path*',
};

function unauthorized() {
  return new Response('Authentication required', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="e-BizDev Portal"',
      'Content-Type': 'text/plain; charset=utf-8',
    },
  });
}

export default function middleware(request) {
  const user = process.env.AUTH_USER;
  const pass = process.env.AUTH_PASS;

  // Misconfigured env -> block everything (fail closed).
  if (!user || !pass) {
    return unauthorized();
  }

  const auth = request.headers.get('authorization');
  if (!auth || !auth.startsWith('Basic ')) {
    return unauthorized();
  }

  let creds;
  try {
    creds = atob(auth.slice(6));
  } catch (e) {
    return unauthorized();
  }

  const idx = creds.indexOf(':');
  if (idx === -1) return unauthorized();

  const u = creds.slice(0, idx);
  const p = creds.slice(idx + 1);

  if (u === user && p === pass) {
    // Authenticated — continue to serve the static site.
    return;
  }

  return unauthorized();
}
