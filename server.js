// server.js — mcrm-mini (Invite API + Email via Resend, Postgres persistence)
// Node 18+ recommended

import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';
import { Resend } from 'resend';
import pkg from 'pg';

const { Pool } = pkg;

/* ====== ENV ====== */
const {
  PORT = 10000,
  NODE_ENV = 'production',
  BASE_URL,                 
  ALLOWED_ORIGINS = '',
  RESEND_API_KEY,
  EMAIL_FROM,
  EMAIL_REPLY_TO,
  ACCEPT_BASE_URL,          
  DOWNLOAD_BASE_URL,        
  INVITE_SIGNING_SECRET,    
  DATABASE_URL,
  RATE_LIMIT_MAX = '30',
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

/* CORS */
const allow = new Set(
  ALLOWED_ORIGINS
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); 
    if (allow.has(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS: ' + origin));
  },
  credentials: false,
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET','POST','OPTIONS']
}));

/* Basic rate limit (in-memory) */
const maxReq = parseInt(RATE_LIMIT_MAX, 10) || 30;
const winMs = parseInt(RATE_LIMIT_WINDOW, 10) || 60000;
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

/* Postgres */
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
  `;
  await pool.query(sql);
}

/* Utils */
const resend = new Resend(RESEND_API_KEY);

function signToken(payloadObj) {
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  const sig = crypto.createHmac('sha256', INVITE_SIGNING_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function verifyToken(token) {
  const [payload, sig] = String(token).split('.');
  if (!payload || !sig) return null;
  const expect = crypto.createHmac('sha256', INVITE_SIGNING_SECRET).update(payload).digest('base64url');
  if (sig !== expect) return null;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); }
  catch { return null; }
}

/* Email HTML */
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

/* ==== API ==== */

app.post('/api/invites', async (req, res) => {
  try {
    const { workspaceId, inviterEmail, inviteeEmail, role } = req.body || {};
    if (!workspaceId || !inviterEmail || !inviteeEmail) {
      return res.status(400).json({ ok:false, error:'missing_fields' });
    }
    const finalRole = (role === 'admin') ? 'admin' : 'member';
    const tokenPayload = { workspaceId, inviteeEmail, role: finalRole, iat: Date.now() };
    const token = signToken(tokenPayload);

    const q = `
      insert into invites (workspace_id, inviter_email, invitee_email, role, status, token)
      values ($1,$2,$3,$4,'pending',$5)
      returning id, token, created_at
    `;
    const { rows } = await pool.query(q, [workspaceId, inviterEmail.toLowerCase(), inviteeEmail.toLowerCase(), finalRole, token]);
    const row = rows[0];

    const acceptUrl = `${ACCEPT_BASE_URL}?token=${encodeURIComponent(token)}`;
    const downloadUrl = `${DOWNLOAD_BASE_URL}`;
    const html = inviteHtml({ inviterEmail, role: finalRole, acceptUrl, downloadUrl });

    const emailPayload = {
      from: EMAIL_FROM,
      to: inviteeEmail,
      subject: `You’re invited to Multi-Session CRM`,
      html,
      reply_to: EMAIL_REPLY_TO || undefined
    };

    const sent = await resend.emails.send(emailPayload);
    if (sent?.error) {
      return res.status(500).json({ ok:false, error:'resend_error', details: sent.error });
    }

    return res.json({
      ok: true,
      inviteId: row.id,
      token: row.token,
      acceptUrl,
      downloadUrl
    });
  } catch (e) {
    console.error('POST /api/invites', e);
    return res.status(500).json({ ok:false, error:'server_error' });
  }
});

app.get('/api/invites', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `select id, workspace_id, inviter_email, invitee_email, role, status, created_at, accepted_at
       from invites order by created_at desc limit 200`
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
      `update invites set status='cancelled' where id=$1 and status='pending'`, [id]
    );
    if (rowCount === 0) return res.status(404).json({ ok:false, error:'not_found_or_not_pending' });
    res.json({ ok:true });
  } catch (e) {
    console.error('POST /api/invites/:id/cancel', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

app.get('/api/invites/accept', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).send('missing token');

    const payload = verifyToken(token);
    if (!payload) return res.status(400).send('invalid token');

    const { rows } = await pool.query(`select * from invites where token=$1`, [token]);
    if (!rows[0]) return res.status(404).send('invite not found');
    if (rows[0].status === 'cancelled') return res.status(400).send('invite cancelled');

    if (rows[0].status !== 'accepted') {
      await pool.query(`update invites set status='accepted', accepted_at=now() where token=$1`, [token]);
    }

    const redirect = `${ACCEPT_BASE_URL}?token=${encodeURIComponent(token)}&email=${encodeURIComponent(rows[0].invitee_email)}`;
    res.redirect(302, redirect);

  } catch (e) {
    console.error('GET /api/invites/accept', e);
    res.status(500).send('server error');
  }
});

/* Health */
app.get('/health', (_req, res) => res.json({ ok:true, env: NODE_ENV }));

/* Boot */
await ensureSchema();
app.listen(PORT, () => {
  console.log(`[mcrm-mini] listening on ${PORT} (${NODE_ENV})`);
});
