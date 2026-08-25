// Edge Middleware — login-page session gate untuk portal e-BizDev.
// - Tanpa sesi valid  -> redirect ke /login.html
// - POST /login        -> verifikasi kredensial, set cookie sesi (HMAC-signed)
// - /logout            -> hapus cookie
// Kredensial dari env: AUTH_USERS=user1:pass1,user2:pass2 (multi-user)
// Fallback: AUTH_USER + AUTH_PASS (single user)
// Secret signing dari env: AUTH_SECRET

export const config = {
  matcher: '/:path*',
};

const COOKIE_NAME = 'ebz_session';
const SESSION_MS = 30 * 24 * 60 * 60 * 1000; // 30 hari
const SESSION_SEC = SESSION_MS / 1000;

function getAllowedUsers() {
  const users = [];
  const multi = process.env.AUTH_USERS;
  if (multi) {
    for (const pair of multi.split(',')) {
      const i = pair.indexOf(':');
      if (i > 0) users.push([pair.slice(0, i).trim(), pair.slice(i + 1)]);
    }
  }
  if (!users.length && process.env.AUTH_USER && process.env.AUTH_PASS) {
    users.push([process.env.AUTH_USER, process.env.AUTH_PASS]);
  }
  return users;
}

async function sign(secret, msg) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function readSession(request) {
  const secret = process.env.AUTH_SECRET;
  if (!secret) return null;
  const cookies = request.headers.get('cookie') || '';
  const m = cookies.match(new RegExp('(?:^|;\\s*)' + COOKIE_NAME + '=([^;]+)'));
  if (!m) return null;

  let raw;
  try { raw = decodeURIComponent(m[1]); } catch (e) { return null; }
  const dot = raw.lastIndexOf('.');
  if (dot < 1) return null;
  const payload = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  if (sig !== await sign(secret, payload)) return null; // gak bisa dipalsu

  const bar = payload.indexOf('|');
  if (bar < 1) return null;
  const user = payload.slice(0, bar);
  const exp = Number(payload.slice(bar + 1));
  if (!Number.isFinite(exp) || Date.now() > exp) return null; // kadaluarsa

  // User harus masih terdaftar (kalau dicabut, sesi mati)
  if (!getAllowedUsers().some(([u]) => u === user)) return null;

  return user;
}

export default async function middleware(request) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const secret = process.env.AUTH_SECRET;

  // Konfigurasi belum lengkap -> fail closed
  if (!secret || getAllowedUsers().length === 0) {
    return new Response('Authentication not configured', { status: 503 });
  }

  // Logout — hapus cookie, balik ke halaman login
  if (path === '/logout') {
    return new Response(null, {
      status: 302,
      headers: {
        Location: '/login.html',
        'Set-Cookie': COOKIE_NAME + '=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax',
      },
    });
  }

  // Halaman login & submit form
  if (path === '/login' || path === '/login.html') {
    if (request.method === 'POST') {
      let user = '', pass = '';
      try {
        const form = await request.formData();
        user = String(form.get('username') || '');
        pass = String(form.get('password') || '');
      } catch (e) { /* body rusak -> anggap gagal */ }

      const ok = getAllowedUsers().some(([u, p]) => u === user && p === pass);
      if (!ok) {
        return Response.redirect(new URL('/login.html?error=1', url).toString(), 302);
      }

      const payload = user + '|' + (Date.now() + SESSION_MS);
      const value = encodeURIComponent(payload) + '.' + await sign(secret, payload);
      return new Response(null, {
        status: 302,
        headers: {
          Location: '/',
          'Set-Cookie': COOKIE_NAME + '=' + value +
            '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + SESSION_SEC,
        },
      });
    }

    const session = await readSession(request);
    if (session && request.method === 'GET') {
      // Sudah login -> langsung ke portal
      return Response.redirect(new URL('/', url).toString(), 302);
    }
    if (path === '/login') {
      // Rapikan ke URL file statis
      return Response.redirect(new URL('/login.html', url).toString(), 302);
    }
    return; // serve /login.html
  }

  // Semua path lain butuh sesi valid
  const session = await readSession(request);
  if (!session) {
    return Response.redirect(new URL('/login.html', url).toString(), 302);
  }

  return; // lanjut serve konten
}
