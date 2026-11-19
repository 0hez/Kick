const http = require('http'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const { KICK_CLIENT_ID: ID, KICK_CLIENT_SECRET: SECRET, BASE_URL, SESSION_SECRET } = process.env;
const BASE = (BASE_URL || '').replace(/\/$/, '');
const KEY = crypto.createHash('sha256').update(SESSION_SECRET || 'change-me').digest();
const SCOPES = 'user:read channel:read chat:write';
const MONTH = 60 * 60 * 24 * 30;

const enc = o => {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const b = Buffer.concat([c.update(JSON.stringify(o)), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), b]).toString('base64url');
};
const dec = s => {
  try {
    const b = Buffer.from(s, 'base64url');
    const d = crypto.createDecipheriv('aes-256-gcm', KEY, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]));
  } catch { return null; }
};
const getCookies = req => Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(Boolean).map(c => {
  const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)];
}));
const setCookie = (res, name, val, age) => {
  const prev = res.getHeader('Set-Cookie') || [];
  res.setHeader('Set-Cookie', [...prev, `${name}=${val}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${age}`]);
};
const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const redirect = (res, url) => { res.writeHead(302, { Location: url }); res.end(); };
const readBody = req => new Promise(r => { let d = ''; req.on('data', c => { d += c; if (d.length > 5000) req.destroy(); }); req.on('end', () => r(d)); });

async function tokenReq(params) {
  const r = await fetch('https://id.kick.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: ID, client_secret: SECRET, ...params })
  });
  if (!r.ok) throw new Error('token ' + r.status);
  const j = await r.json();
  return { at: j.access_token, rt: j.refresh_token, exp: Date.now() + (j.expires_in - 60) * 1000 };
}

// Returns a valid access token, refreshing and re-saving the cookie when needed.
async function session(req, res) {
  const s = dec(getCookies(req).ks || '');
  if (!s) return null;
  if (Date.now() < s.exp) return s.at;
  try {
    const n = await tokenReq({ grant_type: 'refresh_token', refresh_token: s.rt });
    setCookie(res, 'ks', enc(n), MONTH);
    return n.at;
  } catch { return null; }
}
const kick = (at, url, opts = {}) => fetch('https://api.kick.com/public/v1' + url, {
  ...opts, headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' }
});

http.createServer(async (req, res) => {
  const u = new URL(req.url, BASE || 'http://localhost');
  try {
    if (u.pathname === '/auth/login') {
      const v = crypto.randomBytes(32).toString('base64url');
      const state = crypto.randomBytes(16).toString('base64url');
      const ch = crypto.createHash('sha256').update(v).digest('base64url');
      setCookie(res, 'pk', enc({ v, state }), 600);
      const q = new URLSearchParams({
        response_type: 'code', client_id: ID, redirect_uri: BASE + '/auth/callback',
        scope: SCOPES, code_challenge: ch, code_challenge_method: 'S256', state
      });
      return redirect(res, 'https://id.kick.com/oauth/authorize?' + q);
    }
    if (u.pathname === '/auth/callback') {
      const pk = dec(getCookies(req).pk || '');
      if (!pk || pk.state !== u.searchParams.get('state') || !u.searchParams.get('code')) return redirect(res, '/?login=failed');
      const t = await tokenReq({
        grant_type: 'authorization_code', code: u.searchParams.get('code'),
        redirect_uri: BASE + '/auth/callback', code_verifier: pk.v
      });
      setCookie(res, 'ks', enc(t), MONTH);
      setCookie(res, 'pk', '', 0);
      return redirect(res, '/');
    }
    if (u.pathname === '/auth/logout') {
      setCookie(res, 'ks', '', 0);
      return redirect(res, '/');
    }
    if (u.pathname === '/api/me') {
      const at = await session(req, res);
      if (!at) return json(res, 401, {});
      const r = await kick(at, '/users');
      if (!r.ok) return json(res, 401, {});
      const d = (await r.json()).data[0];
      return json(res, 200, { name: d.name, id: d.user_id });
    }
    if (u.pathname === '/api/channel') {
      const slug = u.searchParams.get('slug') || '';
      const out = {};
      const at = await session(req, res);
      if (at) {
        const r = await kick(at, '/channels?slug=' + encodeURIComponent(slug));
        if (r.ok) { const d = (await r.json()).data[0]; if (d) out.bid = d.broadcaster_user_id; }
      }
      try { // chatroom id comes from Kick's site API, which can be blocked; the page has a manual fallback
        const r = await fetch('https://kick.com/api/v2/channels/' + encodeURIComponent(slug), { headers: { 'User-Agent': 'Mozilla/5.0', Accept: 'application/json' } });
        if (r.ok) { const j = await r.json(); out.rid = j.chatroom && j.chatroom.id; out.bid = out.bid || j.user_id; }
      } catch {}
      return json(res, 200, out);
    }
    if (u.pathname === '/api/chat' && req.method === 'POST') {
      const at = await session(req, res);
      if (!at) return json(res, 401, {});
      const b = JSON.parse((await readBody(req)) || '{}');
      const content = String(b.content || '').slice(0, 500);
      if (!content || !b.broadcaster_user_id) return json(res, 400, {});
      const r = await kick(at, '/chat', { method: 'POST', body: JSON.stringify({ broadcaster_user_id: Number(b.broadcaster_user_id), content, type: 'user' }) });
      return json(res, r.status, {});
    }
    if (u.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(path.join(__dirname, 'index.html')));
    }
    res.writeHead(404); res.end();
  } catch (e) {
    console.error(e);
    json(res, 500, {});
  }
}).listen(process.env.PORT || 3000);
