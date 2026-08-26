// /api/admin — kelola pengajuan & akun portal (khusus admin).
// Runtime Node klasik (req,res).
// GET           -> JSON { pending: [...], users: [...] }
// POST (JSON)   -> { action: 'approve' | 'reject' | 'revoke', id?, username? }
// Auth: cookie sesi sama dengan middleware; hanya username di ADMIN_USERS (default: ery).

const crypto = require('crypto');

const EC_ID = 'ecfg_tl0wfh2s0xat2npteybpbaa9voyk';
const EC_TEAM = 'team_tjWQtc0HxCOkDm5m7JgFzVL1';
const COOKIE_NAME = 'ebz_session';

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

function signSync(secret, msg) {
  return crypto.createHmac('sha256', secret).update(msg).digest('hex');
}

function sessionUser(req, extraAllowed) {
  const secret = process.env.AUTH_SECRET;
  if (!secret) return null;
  const cookies = String(req.headers.cookie || '');
  const m = cookies.match(new RegExp('(?:^|;\\s*)' + COOKIE_NAME + '=([^;]+)'));
  if (!m) return null;
  let raw;
  try { raw = decodeURIComponent(m[1]); } catch (e) { return null; }
  const dot = raw.lastIndexOf('.');
  if (dot < 1) return null;
  const payload = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  const want = signSync(secret, payload);
  const a = Buffer.from(sig), b = Buffer.from(want);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const bar = payload.indexOf('|');
  if (bar < 1) return null;
  const user = payload.slice(0, bar);
  const exp = Number(payload.slice(bar + 1));
  if (!Number.isFinite(exp) || Date.now() > exp) return null;
  // env users dulu — kalau Edge Config bermasalah admin tetap bisa masuk
  const allowed = [...extraAllowed];
  const multi = process.env.AUTH_USERS;
  if (multi) for (const pair of multi.split(',')) {
    const i = pair.indexOf(':');
    if (i > 0) allowed.push(pair.slice(0, i).trim());
  }
  if (!allowed.includes(user)) return null;
  return user;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 1e5) req.destroy(); });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

module.exports = async (req, res) => {
  const sendJson = (code, obj) => {
    res.statusCode = code;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(obj));
  };

  if (!process.env.AUTH_SECRET || !process.env.VERCEL_API_TOKEN) {
    return sendJson(503, { error: 'not_configured' });
  }
  if (req.method !== 'GET' && req.method !== 'POST') {
    return sendJson(405, { error: 'method_not_allowed' });
  }

  // Anti-CSRF: POST harus JSON dengan origin cocok
  if (req.method === 'POST') {
    const ct = String(req.headers['content-type'] || '').toLowerCase();
    if (!ct.includes('application/json')) return sendJson(400, { error: 'bad_request' });
    const host = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
    const origin = req.headers.origin ? String(req.headers.origin) : '';
    if (origin && (() => { try { return new URL(origin).host !== host; } catch (e) { return true; } })()) {
      return sendJson(403, { error: 'forbidden' });
    }
  }

  // Daftar user yang dianggap valid utk verifikasi sesi
  let edgeAllowed = [];
  try {
    const st = await readState();
    edgeAllowed = Object.keys(st.users);
  } catch (e) { /* Edge Config gagal -> env users tetap oke */ }

  const user = sessionUser(req, edgeAllowed);
  if (!user) return sendJson(401, { error: 'unauthorized' });
  const admins = (process.env.ADMIN_USERS || 'ery').split(',').map((s) => s.trim().toLowerCase());
  if (!admins.includes(user.toLowerCase())) return sendJson(403, { error: 'forbidden' });

  let state;
  try { state = await readState(); } catch (e) { return sendJson(502, { error: 'edge_config' }); }

  if (req.method === 'GET') {
    const pending = state.pending
      .slice()
      .sort((a, b) => (a.at < b.at ? 1 : -1))
      .map((r) => ({ id: r.id, nama: r.nama, u: r.u, at: r.at }));
    const users = Object.entries(state.users)
      .map(([u, v]) => ({
        u,
        nama: v && typeof v === 'object' ? v.nama || '' : '',
        at: v && typeof v === 'object' ? v.at || '' : '',
      }))
      .sort((a, b) => a.u.localeCompare(b.u));
    return sendJson(200, { pending, users });
  }

  // POST actions
  let body;
  try {
    body = JSON.parse(req.body && typeof req.body === 'string'
      ? req.body
      : (await readBody(req)));
  } catch (e) { return sendJson(400, { error: 'bad_request' }); }
  const action = body.action;

  if (action === 'approve') {
    const idx = state.pending.findIndex((r) => r.id === body.id);
    if (idx < 0) return sendJson(404, { error: 'not_found' });
    const rec = state.pending[idx];
    state.users[rec.u] = { h: rec.h, nama: rec.nama, at: new Date().toISOString(), by: user };
    state.pending.splice(idx, 1);
  } else if (action === 'reject') {
    const idx = state.pending.findIndex((r) => r.id === body.id);
    if (idx < 0) return sendJson(404, { error: 'not_found' });
    state.pending.splice(idx, 1);
  } else if (action === 'revoke') {
    const u = String(body.username || '').toLowerCase();
    if (!state.users[u]) return sendJson(404, { error: 'not_found' });
    delete state.users[u];
  } else {
    return sendJson(400, { error: 'unknown_action' });
  }

  await ecRequest('PATCH', {
    items: [
      { operation: 'upsert', key: 'users', value: state.users },
      { operation: 'upsert', key: 'pending', value: state.pending },
    ],
  });

  return sendJson(200, { ok: true });
};
