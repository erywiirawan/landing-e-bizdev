// POST /api/register — pengajuan akun baru (publik, tanpa sesi).
// Runtime Node klasik (req,res): body urlencoded, respons redirect 303.
// Password disimpan sebagai SHA-256(AUTH_SECRET|username|password) — bukan plaintext.

const crypto = require('crypto');

const EC_ID = 'ecfg_tl0wfh2s0xat2npteybpbaa9voyk';
const EC_TEAM = 'team_tjWQtc0HxCOkDm5m7JgFzVL1';
const MAX_PENDING = 50;

async function ecRequest(method, body) {
  const r = await fetch(
    'https://api.vercel.com/v1/edge-config/' + EC_ID + '/items?teamId=' + EC_TEAM,
    {
      method,
      headers: {
        Authorization: 'Bearer ' + process.env.VERCEL_API_TOKEN,
        'Content-Type': 'application/json',
      },
      body: body ? JSON.stringify(body) : undefined,
    }
  );
  if (!r.ok) throw new Error('edge-config ' + r.status);
  return r.json();
}

async function readState() {
  const items = await ecRequest('GET');
  let users = {}, pending = [];
  for (const it of items || []) {
    if (it.key === 'users' && it.value && typeof it.value === 'object') users = it.value;
    if (it.key === 'pending' && Array.isArray(it.value)) pending = it.value;
  }
  return { users, pending };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 1e5) req.destroy(); });
    req.on('end', () => resolve(new URLSearchParams(data)));
    req.on('error', reject);
  });
}

module.exports = async (req, res) => {
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || 'e-bizdev.my.id').split(',')[0].trim();
  const proto = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  const base = proto + '://' + host;
  const back = (q) => { res.statusCode = 303; res.setHeader('Location', base + '/register.html' + q); res.end(); };

  // GET /api/register -> rapikan ke halaman form
  if (req.method === 'GET') {
    res.statusCode = 302; res.setHeader('Location', base + '/register.html'); return res.end();
  }
  if (req.method !== 'POST') { res.statusCode = 405; return res.end('Method Not Allowed'); }

  const secret = process.env.AUTH_SECRET;
  if (!secret || !process.env.VERCEL_API_TOKEN) {
    res.statusCode = 503; return res.end('Authentication not configured');
  }

  let f;
  try {
    if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
      f = new URLSearchParams(req.body);
    } else {
      f = await readBody(req);
    }
  } catch (e) { return back('?error=invalid'); }

  const getv = (k) => String(f.get ? (f.get(k) || '') : (f[k] || ''));

  // Honeypot — bot isi field tersembunyi; pura-pura sukses
  if (getv('website') !== '') return back('?sent=1');

  const nama = getv('nama').trim();
  const u = getv('username').trim().toLowerCase();
  const p = getv('password');
  const p2 = getv('password2');

  if (nama.length < 2 || nama.length > 60) return back('?error=nama');
  if (!/^[a-z0-9._-]{3,20}$/.test(u)) return back('?error=username');
  if (p.length < 6 || p.length > 72) return back('?error=password');
  if (p !== p2) return back('?error=confirm');

  let state;
  try { state = await readState(); } catch (e) { return back('?error=server'); }
  if (state.users[u]) return back('?error=taken');
  if (state.pending.some((r) => r.u === u)) return back('?error=taken');
  if (state.pending.length >= MAX_PENDING) return back('?error=full');

  const h = crypto.createHash('sha256')
    .update(secret + '|' + u + '|' + p)
    .digest('hex');

  state.pending.push({
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
    nama, u, h,
    at: new Date().toISOString(),
  });

  try {
    await ecRequest('PATCH', {
      items: [{ operation: 'upsert', key: 'pending', value: state.pending }],
    });
  } catch (e) {
    return back('?error=server');
  }

  return back('?sent=1');
};
