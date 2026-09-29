const { Redis } = require('@upstash/redis');
const crypto = require('crypto');
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN,
});
const SECRET = process.env.AUTH_SECRET || 'change-me';
const STATUS = ['open', 'progress', 'resolved', 'closed'];
const now = () => Date.now();
const norm = (e) => String(e || '').trim().toLowerCase();
const sha = (x) => crypto.createHash('sha256').update(String(x)).digest();
const eq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const sign = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const cookie = (v, age) => `hd=${v}; HttpOnly; Path=/; SameSite=Lax; Secure; Max-Age=${age}`;
const log = (by, ticket, action) => redis.lpush('logs', { at: now(), by, ticket, action }).then(() => redis.ltrim('logs', 0, 1999));
const isAdmin = (req) => {
  const m = /(?:^|; )hd=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return false;
  const [p, s] = m[1].split('.');
  return !!p && !!s && s === sign(p) && JSON.parse(Buffer.from(p, 'base64url')).exp > now();
};
async function limit(req, key, max, sec) {
  const ip = String(req.headers['x-nf-client-connection-ip'] || req.headers['x-forwarded-for'] || 'x').split(',')[0].trim();
  const k = `rl:${key}:${ip}`, n = await redis.incr(k);
  if (n === 1) await redis.expire(k, sec);
  return n <= max;
}
const pubT = (t) => ({ id: t.id, title: t.title, desc: t.desc, priority: t.priority, category: t.category, status: t.status,
  byName: t.byName, assignee: t.assignee, createdAt: t.createdAt, notes: t.notes.filter((n) => !n.internal) });

const core = async (req, res) => {
  const send = (c, d) => res.status(c).json(d);
  try {
    const path = new URL(req.url, 'http://x').pathname.replace(/^\/(\.netlify\/functions\/api|api)\/?/, '').split('/').filter(Boolean);
    const [a, b] = path, body = req.body || {}, M = req.method;

    // ---------- PUBLIC (no login) ----------
    if (a === 'public') {
      if (b === 'submit') {
        if (!(await limit(req, 'submit', 10, 3600))) return send(429, { error: 'Too many tickets. Try again later.' });
        const name = String(body.name || '').trim().slice(0, 60), email = norm(body.email);
        const title = String(body.title || '').trim().slice(0, 120), desc = String(body.desc || '').trim().slice(0, 4000);
        if (!name || !email.includes('@') || !title || !desc) return send(400, { error: 'Name, valid email, title and description are required.' });
        const id = 'T-' + (await redis.incr('ticketseq')).toString().padStart(4, '0');
        const t = { id, title, desc, priority: ['Low', 'Medium', 'High', 'Urgent'].includes(body.priority) ? body.priority : 'Medium',
          category: String(body.category || 'General').slice(0, 30), status: 'open', by: email, byName: name, assignee: '', notes: [],
          history: [{ at: now(), by: name, action: 'Ticket created' }], createdAt: now() };
        await redis.set('ticket:' + id, t); await redis.lpush('tickets', id); await log(name, id, 'Created: ' + title);
        return send(200, { id });
      }
      if (['track', 'comment', 'status'].includes(b)) {
        if (!(await limit(req, 'track', 60, 900))) return send(429, { error: 'Too many requests.' });
        const t = await redis.get('ticket:' + String(body.id || '').trim().toUpperCase());
        if (!t || t.by !== norm(body.email)) return send(404, { error: 'No ticket found for that ID and email.' });
        let act;
        if (b === 'comment') {
          const text = String(body.text || '').trim().slice(0, 2000); if (!text) return send(400, { error: 'Write something first.' });
          if (t.status === 'closed') return send(400, { error: 'Ticket is closed.' });
          t.notes.push({ at: now(), by: t.byName, text }); act = 'Requester comment';
        } else if (b === 'status') {
          if (t.status !== 'resolved' || !['closed', 'open'].includes(body.status)) return send(403, { error: 'Not allowed.' });
          t.status = body.status; act = 'Requester set status → ' + body.status;
        }
        if (act) { t.history.push({ at: now(), by: t.byName, action: act }); await redis.set('ticket:' + t.id, t); await log(t.byName, t.id, act); }
        return send(200, pubT(t));
      }
      return send(404, { error: 'Not found.' });
    }

    // ---------- ADMIN LOGIN ----------
    if (a === 'auth') {
      if (b === 'logout') { res.setHeader('Set-Cookie', cookie('', 0)); return send(200, {}); }
      if (!(await limit(req, 'login', 10, 900))) return send(429, { error: 'Too many attempts. Wait 15 minutes.' });
      if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) return send(500, { error: 'Admin credentials are not configured.' });
      if (!eq(norm(body.email), norm(process.env.ADMIN_EMAIL)) || !eq(body.password || '', process.env.ADMIN_PASSWORD)) return send(401, { error: 'Incorrect email or password.' });
      const p = Buffer.from(JSON.stringify({ exp: now() + 7 * 864e5 })).toString('base64url');
      res.setHeader('Set-Cookie', cookie(p + '.' + sign(p), 604800));
      return send(200, { ok: true });
    }

    // ---------- ADMIN ONLY ----------
    if (!isAdmin(req)) return send(401, { error: 'Please sign in.' });
    if (a === 'me') return send(200, { ok: true });
    if (a === 'tickets') {
      if (!b) {
        const ids = await redis.lrange('tickets', 0, 299);
        return send(200, ids.length ? (await redis.mget(...ids.map((i) => 'ticket:' + i))).filter(Boolean) : []);
      }
      const t = await redis.get('ticket:' + b);
      if (!t) return send(404, { error: 'Ticket not found.' });
      let act;
      if (body.op === 'comment') {
        const text = String(body.text || '').trim().slice(0, 2000); if (!text) return send(400, { error: 'Write something first.' });
        t.notes.push({ at: now(), by: 'Support', text, internal: !!body.internal }); act = body.internal ? 'Internal note' : 'Reply to requester';
      } else if (body.op === 'status' && STATUS.includes(body.status)) { t.status = body.status; act = 'Status → ' + body.status; }
      else if (body.op === 'assign') {
        const team = await redis.smembers('team'), who = String(body.name || '');
        if (who && !team.includes(who)) return send(400, { error: 'Unknown team member.' });
        t.assignee = who; if (who && t.status === 'open') t.status = 'progress'; act = who ? 'Assigned to ' + who : 'Unassigned';
      } else return send(400, { error: 'Bad request.' });
      t.history.push({ at: now(), by: 'Admin', action: act });
      await redis.set('ticket:' + b, t); await log('Admin', b, act);
      return send(200, t);
    }
    if (a === 'logs') return send(200, await redis.lrange('logs', 0, 499));
    if (a === 'team') {
      if (M === 'GET') return send(200, await redis.smembers('team'));
      const name = String(body.name || '').trim().slice(0, 40); if (!name) return send(400, { error: 'Enter a name.' });
      if (b === 'remove') await redis.srem('team', name); else await redis.sadd('team', name);
      await log('Admin', '-', (b === 'remove' ? 'Removed' : 'Added') + ' team member ' + name);
      return send(200, await redis.smembers('team'));
    }
    return send(404, { error: 'Not found.' });
  } catch (e) { console.error(e); return send(500, { error: 'Server error.' }); }
};

exports.handler = async (event) => {
  let body = {};
  try { body = event.body ? JSON.parse(event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString() : event.body) : {}; } catch (e) {}
  const out = { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: '' };
  const res = {
    status(c) { out.statusCode = c; return res; },
    json(d) { out.body = JSON.stringify(d); return res; },
    setHeader(k, v) { out.headers[k] = v; },
  };
  await core({ url: event.path + (event.rawQuery ? '?' + event.rawQuery : ''), method: event.httpMethod, headers: event.headers || {}, body }, res);
  return out;
};
