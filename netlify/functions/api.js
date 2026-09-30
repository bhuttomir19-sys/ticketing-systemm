const { Redis } = require('@upstash/redis');
const crypto = require('crypto');
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN,
});
const SECRET = process.env.AUTH_SECRET || 'change-me';
const STATUS = ['open', 'progress', 'resolved', 'closed'];
const PAGE = 500, LOGPAGE = 2000;
const now = () => Date.now();
const norm = (e) => String(e || '').trim().toLowerCase();
const sha = (x) => crypto.createHash('sha256').update(String(x)).digest();
const eq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const sign = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const hash = (pw, salt = crypto.randomBytes(16).toString('hex')) => salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
const check = (pw, h) => eq(hash(pw, h.split(':')[0]), h);
const cookie = (v, age) => `hd=${v}; HttpOnly; Path=/; SameSite=Lax; Secure; Max-Age=${age}`;
const day = (t) => new Date(t).toISOString().slice(0, 10);
const log = async (by, ticket, action, team = '') => {
  const d = day(now());
  await redis.lpush('logs:' + d, { at: now(), by, ticket, action, team });
  await redis.sadd('logdays', d);
};
async function auth(req) {
  const m = /(?:^|; )hd=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const [p, s] = m[1].split('.');
  if (!p || !s || !eq(s, sign(p))) return null;
  const d = JSON.parse(Buffer.from(p, 'base64url'));
  if (d.exp < now()) return null;
  if (d.a) return process.env.ADMIN_EMAIL && eq(d.e, norm(process.env.ADMIN_EMAIL)) ? { role: 'admin', name: 'Admin', email: d.e, team: '' } : null;
  const u = await redis.get('user:' + d.e);
  return u ? { role: 'team', name: u.name, email: u.email, team: u.team } : null;
}
async function limit(req, key, max, sec) {
  const ip = String(req.headers['x-nf-client-connection-ip'] || req.headers['x-forwarded-for'] || 'x').split(',')[0].trim();
  const k = `rl:${key}:${ip}`, n = await redis.incr(k);
  if (n === 1) await redis.expire(k, sec);
  return n <= max;
}
const pubT = (t) => ({ id: t.id, title: t.title, desc: t.desc, status: t.status, byName: t.byName, assignee: t.assignee,
  createdAt: t.createdAt, notes: t.notes.filter((n) => !n.internal) });
const teamsList = async () => Object.values((await redis.hgetall('teams')) || {});
const usersList = async () => { const em = await redis.smembers('users'); return em.length ? (await redis.mget(...em.map((e) => 'user:' + e))).filter(Boolean) : []; };
const getMany = async (ids) => (ids.length ? (await redis.mget(...ids.map((i) => 'ticket:' + i))).filter(Boolean) : []);

const core = async (req, res) => {
  const send = (c, d) => res.status(c).json(d);
  try {
    const url = new URL(req.url, 'http://x'), q = url.searchParams;
    const path = url.pathname.replace(/^\/(\.netlify\/functions\/api|api)\/?/, '').split('/').filter(Boolean);
    const [a, b] = path, body = req.body || {}, M = req.method;

    if (a === 'public') {
      if (b === 'teams') return send(200, await teamsList());
      if (b === 'submit') {
        if (!(await limit(req, 'submit', 10, 3600))) return send(429, { error: 'Too many tickets. Try again later.' });
        const name = String(body.name || '').trim().slice(0, 60), dept = String(body.dept || '').trim().slice(0, 60);
        const title = String(body.title || '').trim().slice(0, 120), desc = String(body.desc || '').trim().slice(0, 4000);
        if (!name || !dept || !title || !desc) return send(400, { error: 'Name, department, title and description are required.' });
        const teams = await teamsList(), team = String(body.team || '');
        if (teams.length && !teams.some((t) => t.id === team)) return send(400, { error: 'Choose which team to send this to.' });
        const id = 'T-' + String(await redis.incr('ticketseq')).padStart(4, '0');
        const t = { id, title, desc, status: 'open', byName: name, dept, team: teams.length ? team : '', assignee: '', notes: [],
          history: [{ at: now(), by: name, action: 'Ticket created' }], createdAt: now() };
        await redis.set('ticket:' + id, t); await redis.lpush('tickets', id);
        if (t.team) await redis.lpush('tickets:' + t.team, id);
        await log(name, id, 'Created: ' + title, t.team);
        return send(200, { id });
      }
      if (['track', 'comment', 'status'].includes(b)) {
        if (!(await limit(req, 'track', 60, 900))) return send(429, { error: 'Too many requests.' });
        const t = await redis.get('ticket:' + String(body.id || '').trim().toUpperCase());
        if (!t) return send(404, { error: 'No ticket found with that ID.' });
        let act;
        if (b === 'comment') {
          const text = String(body.text || '').trim().slice(0, 2000); if (!text) return send(400, { error: 'Write something first.' });
          if (t.status === 'closed') return send(400, { error: 'Ticket is closed.' });
          t.notes.push({ at: now(), by: t.byName, text }); act = 'Requester comment';
        } else if (b === 'status') {
          if (t.status !== 'resolved' || !['closed', 'open'].includes(body.status)) return send(403, { error: 'Not allowed.' });
          t.status = body.status; act = 'Requester set status → ' + body.status;
        }
        if (act) { t.history.push({ at: now(), by: t.byName, action: act }); await redis.set('ticket:' + t.id, t); await log(t.byName, t.id, act, t.team); }
        return send(200, pubT(t));
      }
      return send(404, { error: 'Not found.' });
    }

    if (a === 'auth') {
      if (b === 'logout') { res.setHeader('Set-Cookie', cookie('', 0)); return send(200, {}); }
      if (!(await limit(req, 'login', 10, 900))) return send(429, { error: 'Too many attempts. Wait 15 minutes.' });
      const email = norm(body.email), pw = String(body.password || ''); let tok;
      if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD && eq(email, norm(process.env.ADMIN_EMAIL))) {
        if (!eq(pw, process.env.ADMIN_PASSWORD)) return send(401, { error: 'Incorrect email or password.' });
        tok = { e: email, a: 1 };
      } else {
        const u = await redis.get('user:' + email);
        if (!u || !check(pw, u.pw)) return send(401, { error: 'Incorrect email or password.' });
        tok = { e: email };
      }
      const p = Buffer.from(JSON.stringify({ ...tok, exp: now() + 7 * 864e5 })).toString('base64url');
      res.setHeader('Set-Cookie', cookie(p + '.' + sign(p), 604800));
      return send(200, { ok: true });
    }

    const me = await auth(req);
    if (!me) return send(401, { error: 'Please sign in.' });
    const admin = me.role === 'admin';
    if (a === 'me') return send(200, { role: me.role, name: me.name, team: me.team });

    if (a === 'tickets') {
      if (!b) {
        const off = Math.max(0, Number(q.get('offset')) || 0), key = admin ? 'tickets' : 'tickets:' + me.team;
        return send(200, await getMany(await redis.lrange(key, off, off + PAGE - 1)));
      }
      const t = await redis.get('ticket:' + b);
      if (!t || (!admin && t.team !== me.team)) return send(404, { error: 'Ticket not found.' });
      if (body.op === 'delete') {
        if (!admin) return send(403, { error: 'Only the admin can delete tickets.' });
        await redis.del('ticket:' + b); await redis.lrem('tickets', 0, b); if (t.team) await redis.lrem('tickets:' + t.team, 0, b);
        await log(me.name, b, 'Ticket deleted: ' + t.title, t.team);
        return send(200, { ok: true });
      }
      let act;
      if (body.op === 'comment') {
        const text = String(body.text || '').trim().slice(0, 2000); if (!text) return send(400, { error: 'Write something first.' });
        t.notes.push({ at: now(), by: me.name, text, internal: !!body.internal }); act = body.internal ? 'Internal note' : 'Reply to requester';
      } else if (body.op === 'status' && STATUS.includes(body.status)) { t.status = body.status; act = 'Status → ' + body.status; }
      else if (body.op === 'assign') {
        const who = String(body.name || '');
        const ok = !who || (admin && who === 'Admin') || (await usersList()).some((u) => u.team === t.team && u.name === who);
        if (!ok) return send(400, { error: 'Pick a member of this ticket\'s team.' });
        t.assignee = who; if (who && t.status === 'open') t.status = 'progress'; act = who ? 'Assigned to ' + who : 'Unassigned';
      } else if (body.op === 'move') {
        const to = await redis.hget('teams', String(body.team || ''));
        if (!to) return send(400, { error: 'Unknown team.' });
        if (t.team) await redis.lrem('tickets:' + t.team, 0, t.id);
        t.team = to.id; t.assignee = ''; await redis.lpush('tickets:' + to.id, t.id); act = 'Moved to team ' + to.name;
      } else return send(400, { error: 'Bad request.' });
      t.history.push({ at: now(), by: me.name, action: act });
      await redis.set('ticket:' + b, t); await log(me.name, b, act, t.team);
      if (!admin && t.team !== me.team) return send(200, { ...t, moved: true });
      return send(200, t);
    }

    if (a === 'logs') {
      const from = Number(b === 'delete' ? body.from : q.get('from')) || 0, to = Number(b === 'delete' ? body.to : q.get('to')) || now();
      let days = (await redis.smembers('logdays')).filter((d) => d >= day(from) && d <= day(to)).sort().reverse();
      if (b === 'delete') {
        if (!admin) return send(403, { error: 'Only the admin can delete logs.' });
        let n = 0;
        for (const d of days) { n += await redis.llen('logs:' + d); await redis.del('logs:' + d); await redis.srem('logdays', d); }
        await log(me.name, '-', `Deleted ${n} log entries (${days.length} days)`);
        return send(200, { deleted: n });
      }
      const before = q.get('before'); if (before) days = days.filter((d) => d < before);
      const out = []; let last = null;
      for (const d of days) {
        const rows = (await redis.lrange('logs:' + d, 0, -1)).filter((l) => l.at >= from && l.at <= to && (admin || l.team === me.team));
        out.push(...rows); last = d;
        if (out.length >= LOGPAGE) break;
      }
      return send(200, { logs: out, next: last && days.indexOf(last) < days.length - 1 ? last : null });
    }

    if (a === 'users') {
      if (M === 'GET') {
        const all = (await usersList()).map((u) => ({ name: u.name, email: u.email, team: u.team }));
        return send(200, admin ? all : all.filter((u) => u.team === me.team));
      }
      if (!admin) return send(403, { error: 'Admin only.' });
      const email = norm(body.email);
      if (b === 'delete') { await redis.del('user:' + email); await redis.srem('users', email); await log(me.name, '-', 'Deleted login ' + email); return send(200, { ok: true }); }
      const old = await redis.get('user:' + email), pw = String(body.password || '');
      if (!email.includes('@') || !String(body.name || '').trim() || !(await redis.hget('teams', String(body.team || '')))) return send(400, { error: 'Name, email and team are required.' });
      if ((!old && pw.length < 8) || (pw && pw.length < 8)) return send(400, { error: 'Password must be 8+ characters.' });
      await redis.set('user:' + email, { email, name: String(body.name).trim().slice(0, 60), team: body.team, pw: pw ? hash(pw) : old.pw });
      await redis.sadd('users', email); await log(me.name, '-', (old ? 'Updated' : 'Created') + ' login ' + email, body.team);
      return send(200, { ok: true });
    }

    if (a === 'teams') {
      if (!admin) return send(403, { error: 'Admin only.' });
      if (b === 'delete') {
        const id = String(body.id || '');
        if ((await redis.llen('tickets:' + id)) > 0 || (await usersList()).some((u) => u.team === id)) return send(400, { error: 'Move its tickets and delete its logins first.' });
        await redis.hdel('teams', id); await log(me.name, '-', 'Deleted team ' + id);
        return send(200, await teamsList());
      }
      const name = String(body.name || '').trim().slice(0, 40), id = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      if (!id) return send(400, { error: 'Enter a team name.' });
      await redis.hset('teams', { [id]: { id, name } }); await log(me.name, '-', 'Added team ' + name);
      return send(200, await teamsList());
    }
    return send(404, { error: 'Not found.' });
  } catch (e) { console.error(e); return send(500, { error: 'Server error.' }); }
};
exports.handler = async (event) => {
  let body = {};
  try { body = event.body ? JSON.parse(event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString() : event.body) : {}; } catch (e) {}
  const out = { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: '' };
  const res = { status(c) { out.statusCode = c; return res; }, json(d) { out.body = JSON.stringify(d); return res; }, setHeader(k, v) { out.headers[k] = v; } };
  await core({ url: event.path + (event.rawQuery ? '?' + event.rawQuery : ''), method: event.httpMethod, headers: event.headers || {}, body }, res);
  return out;
};
