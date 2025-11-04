// server.js — mcrm-mini (Invites + Accept + Server-Login, Resend + PostgreSQL)
// Node >= 18
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import { Resend } from 'resend';
import pkg from 'pg';
import bcrypt from 'bcryptjs';

const { Pool } = pkg;

/* ====== ENV ====== */
const {
  PORT = 10000,
  NODE_ENV = 'production',
  ALLOWED_ORIGINS = '',
  RESEND_API_KEY,
  EMAIL_FROM,
  EMAIL_REPLY_TO,
  ACCEPT_BASE_URL,          // z.B. https://invite.multi-session-crm.com/accept
  DOWNLOAD_BASE_URL,        // z.B. https://invite.multi-session-crm.com/download
  INVITE_SIGNING_SECRET,
  DATABASE_URL,
  RATE_LIMIT_MAX = '60',
  RATE_LIMIT_WINDOW = '60000'
} = process.env;

/* ====== Guards ====== */
function must(val, name) {
  if (!val || String(val).trim() === '') {
    console.error(`[ENV MISSING] ${name}`);
    process.exit(1);
  }
}
must(RESEND_API_KEY, 'RESEND_API_KEY');
must(EMAIL_FROM, 'EMAIL_FROM');
must(ACCEPT_BASE_URL, 'ACCEPT_BASE_URL');
must(DOWNLOAD_BASE_URL, 'DOWNLOAD_BASE_URL');
must(INVITE_SIGNING_SECRET, 'INVITE_SIGNING_SECRET');
must(DATABASE_URL, 'DATABASE_URL');

/* ====== Core ====== */
const app = express();
app.use(express.json({ limit: '1mb' }));

/* CORS (App + Landingpages) */
const allow = new Set(
  ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
);
app.use(cors({
  origin: (origin, cb) => {
    // Electron / curl / Postman
    if (!origin) return cb(null, true);
    if (allow.has(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS: ' + origin));
  },
  credentials: false,
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET','POST','OPTIONS'] // POST reicht auch für "remove"
}));

/* Rate-Limit (einfach, in-memory) */
const maxReq = parseInt(RATE_LIMIT_MAX, 10) || 60;
const winMs  = parseInt(RATE_LIMIT_WINDOW, 10) || 60000;
const ipHits = new Map();
app.use((req, res, next) => {
  const now = Date.now();
  const w = ipHits.get(req.ip) || [];
  const fresh = w.filter(t => now - t < winMs);
  fresh.push(now);
  ipHits.set(req.ip, fresh);
  if (fresh.length > maxReq) return res.status(429).json({ ok:false, error:'rate_limited' });
  next();
});

/* ===== Postgres ===== */
const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function ensureSchema() {
  const sql = `
    create extension if not exists pgcrypto;

    create table if not exists invites (
      id uuid primary key default gen_random_uuid(),
      workspace_id text not null,
      inviter_email text not null,
      invitee_email text not null,
      role text not null check (role in ('member','admin')),
      status text not null default 'pending' check (status in ('pending','accepted','cancelled')),
      token text not null unique,
      created_at timestamptz not null default now(),
      accepted_at timestamptz
    );

    create index if not exists idx_invites_invitee on invites (invitee_email);
    create index if not exists idx_invites_token on invites (token);

    create table if not exists users (
      id uuid primary key default gen_random_uuid(),
      workspace_id text not null,
      email text not null,
      role text not null check (role in ('member','admin','owner')),
      password_hash text not null,
      name text default 'User',
      status text not null default 'active' check (status in ('active','disabled')),
      created_at timestamptz not null default now(),
      unique (workspace_id, email)
    );
  `;
  await pool.query(sql);
}

/* ==== Token Utils (HMAC, stateless) ==== */
const resend = new Resend(RESEND_API_KEY);

function signToken(payloadObj) {
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  const sig = crypto.createHmac('sha256', INVITE_SIGNING_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function verifyToken(token) {
  const [payload, sig] = String(token || '').split('.');
  if (!payload || !sig) return null;
  const expect = crypto.createHmac('sha256', INVITE_SIGNING_SECRET).update(payload).digest('base64url');
  if (sig !== expect) return null;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); }
  catch { return null; }
}
function authFromHeader(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  return verifyToken(h.slice(7));
}

/* ===== Email HTML ===== */
function inviteHtml({ inviterEmail, role, acceptUrl, downloadUrl }) {
  const safeInviter = inviterEmail.replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const roleLabel = role === 'admin' ? 'Admin' : 'Member';
  return `
  <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px;background:#0f0f0f;color:#eee">
    <h2 style="margin:0 0 12px">You’re invited to Multi-Session CRM</h2>
    <p style="margin:0 0 10px">Hello! <b>${safeInviter}</b> has invited you to join their workspace as <b>${roleLabel}</b>.</p>
    <div style="height:14px"></div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <a href="${acceptUrl}" style="text-decoration:none;padding:12px 14px;border-radius:10px;background:#ff5c33;color:#fff;display:inline-block">Accept invitation</a>
      <a href="${downloadUrl}" style="text-decoration:none;padding:12px 14px;border-radius:10px;background:#222;color:#fff;display:inline-block">Download the app</a>
    </div>
    <div style="height:14px"></div>
    <p style="font-size:13px;color:#9aa0a6">If you didn’t expect this email, you can safely ignore it.</p>
  </div>`;
}

/* ===== Health ===== */
app.get('/health', (_req, res) => res.json({ ok:true, env: NODE_ENV }));

/* ===== AUTH: Owner-Signup ===== */
/** POST /api/auth/signup_owner
 * Body: { workspaceId, email, name, password }
 * Ergebnis: legt Owner-User an (falls nicht vorhanden) und gibt Session-Token zurück
 */
app.post('/api/auth/signup_owner', async (req, res) => {
  try {
    const { workspaceId, email, name, password } = req.body || {};
    if (!workspaceId || !email || !password) {
      return res.status(400).json({ ok:false, error:'missing_fields' });
    }
    const wsid = String(workspaceId).trim();
    const mail = String(email).toLowerCase().trim();

    const exists = await pool.query(
      'select id from users where workspace_id=$1 and email=$2',
      [wsid, mail]
    );
    if (exists.rowCount > 0) {
      return res.status(409).json({ ok:false, error:'owner_exists' });
    }

    const hash = await bcrypt.hash(password, 10);
    const ins = await pool.query(
      `insert into users (workspace_id,email,role,password_hash,name,status)
       values ($1,$2,'owner',$3,$4,'active')
       returning id, workspace_id, email, role, name, status, created_at`,
      [wsid, mail, hash, name || 'Owner']
    );

    const token = signToken({ workspaceId: wsid, email: mail, role: 'owner', iat: Date.now() });
    return res.json({ ok:true, token, user: ins.rows[0] });
  } catch (e) {
    console.error('POST /api/auth/signup_owner', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

/* ===== Auth: Login ===== */
/** POST /api/auth/login  { workspaceId, email, password } */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { workspaceId, email, password } = req.body || {};
    if (!workspaceId || !email || !password) {
      return res.status(400).json({ ok:false, error:'missing_fields' });
    }
    const q = await pool.query(
      `select * from users where workspace_id=$1 and email=$2`,
      [String(workspaceId), String(email).toLowerCase()]
    );
    const u = q.rows[0];
    if (!u) return res.status(401).json({ ok:false, error:'invalid_credentials' });

    // NEW: disabled blocken
    if (u.status !== 'active') {
      return res.status(403).json({ ok:false, error:'user_disabled' });
    }

    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ ok:false, error:'invalid_credentials' });

    const token = signToken({ workspaceId: u.workspace_id, email: u.email, role: u.role, iat: Date.now() });
    res.json({ ok:true, token, email: u.email, role: u.role, workspaceId: u.workspace_id, name: u.name });
  } catch (e) {
    console.error('POST /api/auth/login', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

/* ===== Session: /me ===== */
/** GET /api/me   (Authorization: Bearer <token>) */
app.get('/api/me', async (req, res) => {
  try {
    const sess = authFromHeader(req);
    if (!sess) return res.status(401).json({ ok:false, error:'no_or_bad_token' });

    const meQ = await pool.query(
      `select id,workspace_id,email,role,name,status,created_at
         from users
        where workspace_id=$1 and email=$2`,
      [sess.workspaceId, String(sess.email).toLowerCase()]
    );
    const me = meQ.rows[0] || null;

    const teamQ = await pool.query(
      `select id,email,role,name,status,created_at
         from users
        where workspace_id=$1
        order by (role='owner') desc, (role='admin') desc, email asc`,
      [sess.workspaceId]
    );

    res.json({
      ok: true,
      user: me,
      workspace: {
        id: sess.workspaceId,
        users: teamQ.rows
      }
    });
  } catch (e) {
    console.error('GET /api/me', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

/* ===== Invites: Create + Send ===== */
app.post('/api/invites', async (req, res) => {
  try {
    const maybe = authFromHeader(req);
    const body = req.body || {};

    const workspaceId = (maybe?.workspaceId) || body.workspaceId;
    const inviterEmail = (maybe?.email)       || body.inviterEmail;
    const inviteeEmail = body.inviteeEmail;
    const role = body.role === 'admin' ? 'admin' : 'member';

    if (!workspaceId || !inviterEmail || !inviteeEmail) {
      return res.status(400).json({ ok:false, error:'missing_fields' });
    }

    const tokenPayload = { workspaceId, inviteeEmail, role, iat: Date.now() };
    const token = signToken(tokenPayload);

    const q = `
      insert into invites (workspace_id, inviter_email, invitee_email, role, status, token)
      values ($1,$2,$3,$4,'pending',$5)
      returning id, token, created_at
    `;
    const { rows } = await pool.query(q, [
      String(workspaceId),
      String(inviterEmail).toLowerCase(),
      String(inviteeEmail).toLowerCase(),
      role,
      token
    ]);
    const row = rows[0];

    const acceptUrl = `${ACCEPT_BASE_URL}?token=${encodeURIComponent(token)}`;
    const downloadUrl = `${DOWNLOAD_BASE_URL}`;
    const html = inviteHtml({ inviterEmail, role, acceptUrl, downloadUrl });

    const sent = await resend.emails.send({
      from: EMAIL_FROM,
      to: inviteeEmail,
      subject: `You’re invited to Multi-Session CRM`,
      html,
      reply_to: EMAIL_REPLY_TO || undefined
    });
    if (sent?.error) {
      return res.status(500).json({ ok:false, error:'resend_error', details: sent.error });
    }

    return res.json({ ok:true, inviteId: row.id, token: row.token, acceptUrl, downloadUrl });
  } catch (e) {
    console.error('POST /api/invites', e);
    return res.status(500).json({ ok:false, error:'server_error' });
  }
});

/* ===== Invites: List / Resend / Cancel ===== */
app.get('/api/invites', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `select id, workspace_id, inviter_email, invitee_email, role, status, created_at, accepted_at
         from invites
        order by created_at desc
        limit 200`
    );
    res.json({ ok:true, invites: rows });
  } catch (e) {
    console.error('GET /api/invites', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

app.post('/api/invites/:id/resend', async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query(`select * from invites where id = $1`, [id]);
    if (!rows[0]) return res.status(404).json({ ok:false, error:'not_found' });
    const inv = rows[0];

    const acceptUrl = `${ACCEPT_BASE_URL}?token=${encodeURIComponent(inv.token)}`;
    const downloadUrl = `${DOWNLOAD_BASE_URL}`;
    const html = inviteHtml({ inviterEmail: inv.inviter_email, role: inv.role, acceptUrl, downloadUrl });

    const sent = await resend.emails.send({
      from: EMAIL_FROM,
      to: inv.invitee_email,
      subject: `Your invitation to Multi-Session CRM`,
      html,
      reply_to: EMAIL_REPLY_TO || undefined
    });
    if (sent?.error) return res.status(500).json({ ok:false, error:'resend_error', details: sent.error });

    res.json({ ok:true });
  } catch (e) {
    console.error('POST /api/invites/:id/resend', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

app.post('/api/invites/:id/cancel', async (req, res) => {
  try {
    const { id } = req.params;
    const { rowCount } = await pool.query(
      `update invites set status='cancelled' where id=$1 and status='pending'`,
      [id]
    );
    if (rowCount === 0) return res.status(404).json({ ok:false, error:'not_found_or_not_pending' });
    res.json({ ok:true });
  } catch (e) {
    console.error('POST /api/invites/:id/cancel', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

/* ===== Accept: Passwort setzen (API + Minimal-HTML) ===== */
app.post('/api/invites/accept', async (req, res) => {
  try {
    const { token, password, name } = req.body || {};
    if (!token || !password) return res.status(400).json({ ok:false, error:'missing_fields' });

    const payload = verifyToken(token);
    if (!payload) return res.status(400).json({ ok:false, error:'invalid_token' });

    const invQ = await pool.query(`select * from invites where token=$1`, [token]);
    const inv = invQ.rows[0];
    if (!inv) return res.status(404).json({ ok:false, error:'invite_not_found' });
    if (inv.status === 'cancelled') return res.status(400).json({ ok:false, error:'invite_cancelled' });

    const pwHash = await bcrypt.hash(password, 10);

    // NEW: Accept setzt/reaktiviert status='active'
    await pool.query(`
      insert into users (workspace_id, email, role, password_hash, name, status)
      values ($1,$2,$3,$4,$5,'active')
      on conflict (workspace_id, email)
      do update set role=excluded.role,
                    password_hash=excluded.password_hash,
                    name=excluded.name,
                    status='active'
    `, [
      inv.workspace_id,
      inv.invitee_email.toLowerCase(),
      inv.role,
      pwHash,
      name || inv.invitee_email.split('@')[0]
    ]);

    if (inv.status !== 'accepted') {
      await pool.query(`update invites set status='accepted', accepted_at=now() where token=$1`, [token]);
    }

    return res.json({ ok:true });
  } catch (e) {
    console.error('POST /api/invites/accept', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

app.get('/api/invites/accept-page', async (req, res) => {
  try {
    const { token } = req.query || {};
    if (!token) return res.status(400).send('missing token');
    const payload = verifyToken(token);
    if (!payload) return res.status(400).send('invalid token');

    res.type('html').send(`<!doctype html>
<html><head><meta charset="utf-8"><title>Accept Invitation</title></head>
<body style="font-family:system-ui;background:#0f0f0f;color:#eee;padding:24px">
  <h2>Accept invitation</h2>
  <p>Set your password to join the workspace.</p>
  <form id="f" style="display:grid;gap:10px;max-width:360px">
    <input type="password" id="pw" placeholder="New password" style="padding:10px;border-radius:8px;border:1px solid #333;background:#141414;color:#eee">
    <button type="submit" style="padding:10px;border-radius:8px;background:#ff5c33;color:#fff;border:0">Save password</button>
  </form>
  <div id="msg" style="margin-top:10px;color:#9aa0a6"></div>
  <script>
    const t = ${JSON.stringify(String(token))};
    document.getElementById('f').addEventListener('submit', async (e)=>{
      e.preventDefault();
      const pw = document.getElementById('pw').value;
      const r = await fetch('/api/invites/accept', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ token: t, password: pw })
      });
      const j = await r.json().catch(()=>null);
      const m = document.getElementById('msg');
      if(!j || !j.ok){ m.textContent = 'Error saving password.'; return; }
      m.textContent = 'Password saved. You can now download the app.';
      setTimeout(()=>{ window.location.href = ${JSON.stringify(DOWNLOAD_BASE_URL)}; }, 800);
    });
  </script>
</body></html>`);
  } catch (e) {
    console.error('GET /api/invites/accept-page', e);
    res.status(500).send('server error');
  }
});

/* ===== Team: aus DB listen & Member entfernen (disable) ===== */

// GET /api/team?workspaceId=ws-123
app.get('/api/team', async (req, res) => {
  try {
    const { workspaceId } = req.query || {};
    if (!workspaceId) return res.status(400).json({ ok:false, error:'missing_workspaceId' });

    const { rows } = await pool.query(
      `select email, role, name, status, created_at
         from users
        where workspace_id=$1
        order by (role='owner') desc, (role='admin') desc, email asc`,
      [String(workspaceId)]
    );

    res.json({ ok:true, users: rows });
  } catch (e) {
    console.error('GET /api/team', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

// POST /api/team/remove  { workspaceId, targetEmail }
app.post('/api/team/remove', async (req, res) => {
  try {
    const { workspaceId, targetEmail } = req.body || {};
    if (!workspaceId || !targetEmail) {
      return res.status(400).json({ ok:false, error:'missing_fields' });
    }

    const q = await pool.query(
      `select role, status from users where workspace_id=$1 and email=$2`,
      [String(workspaceId), String(targetEmail).toLowerCase()]
    );
    const found = q.rows[0];
    if (!found) return res.status(404).json({ ok:false, error:'user_not_found' });
    if (found.role === 'owner') return res.status(400).json({ ok:false, error:'cannot_remove_owner' });

    // Soft-Remove → status='disabled'
    await pool.query(
      `update users set status='disabled' where workspace_id=$1 and email=$2`,
      [String(workspaceId), String(targetEmail).toLowerCase()]
    );

    return res.json({ ok:true });
  } catch (e) {
    console.error('POST /api/team/remove', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

/* ===== Boot ===== */
await ensureSchema();
app.listen(PORT, () => {
  console.log(`[mcrm-mini] listening on ${PORT} (${NODE_ENV})`);
});
