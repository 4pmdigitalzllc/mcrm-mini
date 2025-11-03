// server.js
// mcrm-mini: Invite-Mail-Versand (Resend) + PostgreSQL-Persistenz (auto schema)
// Requires: npm i express cors pg resend nanoid

import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import { Resend } from 'resend';
import { nanoid } from 'nanoid';
import pkg from 'pg';
const { Pool } = pkg;

/* ===== ENV ===== */
const {
  PORT = 3000,
  NODE_ENV = 'production',
  DATABASE_URL,
  RESEND_API_KEY,
  INVITE_SIGNING_SECRET,
  EMAIL_FROM,
  EMAIL_REPLY_TO,
  ACCEPT_BASE_URL,        // e.g. https://app.multi-session-crm.com/accept
  DOWNLOAD_BASE_URL,      // e.g. https://app.multi-session-crm.com/download
  APP_DEEPLINK_SCHEME,    // e.g. mcrm://
  ALLOWED_ORIGINS = ''
} = process.env;

if (!DATABASE_URL) throw new Error('DATABASE_URL missing');
if (!RESEND_API_KEY) throw new Error('RESEND_API_KEY missing');
if (!INVITE_SIGNING_SECRET) throw new Error('INVITE_SIGNING_SECRET missing');
if (!EMAIL_FROM) throw new Error('EMAIL_FROM missing');
if (!ACCEPT_BASE_URL) throw new Error('ACCEPT_BASE_URL missing');
if (!DOWNLOAD_BASE_URL) throw new Error('DOWNLOAD_BASE_URL missing');

const resend = new Resend(RESEND_API_KEY);
const pool = new Pool({ connectionString: DATABASE_URL });

/* ===== App ===== */
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

/* ===== CORS ===== */
const allowList = ALLOWED_ORIGINS
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowList.length === 0) return cb(null, true);
    return cb(null, allowList.includes(origin));
  },
  credentials: false
}));

/* ===== Helpers ===== */
function nowIso() { return new Date().toISOString(); }
function sha256Base64url(input) {
  return crypto.createHmac('sha256', INVITE_SIGNING_SECRET)
    .update(input)
    .digest('base64url');
}
function makeToken() {
  // opaque token -> not guessable
  return nanoid(48); // ~288 bits
}
function acceptUrlFromToken(token) {
  const url = new URL(ACCEPT_BASE_URL);
  url.searchParams.set('token', token);
  return url.toString();
}
function downloadUrl() {
  return DOWNLOAD_BASE_URL;
}
function appDeepLink(inviteId) {
  if (!APP_DEEPLINK_SCHEME) return null;
  // Example: mcrm://accept?inviteId=...
  return `${APP_DEEPLINK_SCHEME.replace(/:$/, '')}://accept?inviteId=${encodeURIComponent(inviteId)}`;
}

/* ===== DB: init schema ===== */
const SQL_INIT = `
CREATE TABLE IF NOT EXISTS invites (
  id               TEXT PRIMARY KEY,
  workspace_id     TEXT NOT NULL,
  email            TEXT NOT NULL,
  role             TEXT NOT NULL CHECK (role IN ('member','admin')),
  token_hash       TEXT NOT NULL,
  status           TEXT NOT NULL CHECK (status IN ('pending','accepted','cancelled')) DEFAULT 'pending',
  invited_by       TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at       TIMESTAMPTZ NOT NULL,
  accepted_at      TIMESTAMPTZ,
  last_sent_at     TIMESTAMPTZ,
  UNIQUE (workspace_id, email, status) WHERE status = 'pending'
);
CREATE INDEX IF NOT EXISTS idx_invites_workspace ON invites (workspace_id);
CREATE INDEX IF NOT EXISTS idx_invites_email ON invites (email);
`;

async function dbInit() {
  const c = await pool.connect();
  try { await c.query(SQL_INIT); }
  finally { c.release(); }
}
await dbInit();

/* ===== Email Template (EN only) ===== */
function inviteEmailHtml({ workspaceName, acceptLink, downloadLink, deeplink }) {
  const headline = `You’ve been invited to ${workspaceName}`;
  const sub = `Click “Accept invitation” to join the workspace. You can also download the app below.`;
  const buttonPrimary = `Accept invitation`;
  const buttonDownload = `Download app`;
  return `
  <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;padding:24px;background:#0f0f0f;color:#eee;">
    <div style="max-width:560px;margin:0 auto;background:#151515;border:1px solid #2a2a2a;border-radius:12px;padding:20px;">
      <h2 style="margin:0 0 6px;font-size:20px;color:#fff;">${headline}</h2>
      <p style="margin:8px 0 18px;color:#cfcfcf;">${sub}</p>

      <a href="${acceptLink}" style="display:inline-block;padding:12px 16px;background:#ff5c33;border-radius:10px;color:#fff;text-decoration:none;font-weight:600;">
        ${buttonPrimary}
      </a>
      <div style="height:10px"></div>
      <a href="${downloadLink}" style="display:inline-block;padding:10px 14px;background:#1d1d1d;border:1px solid #2a2a2a;border-radius:10px;color:#fff;text-decoration:none;">
        ${buttonDownload}
      </a>

      ${deeplink ? `
      <div style="margin-top:14px;color:#9aa0a6;font-size:12px;">
        If you already installed the app, you can also open it directly: <br/>
        <code style="color:#eee;background:#111;padding:2px 6px;border-radius:6px;">${deeplink}</code>
      </div>` : ''}

      <hr style="border:none;border-top:1px solid #2a2a2a;margin:18px 0;">
      <div style="color:#9aa0a6;font-size:12px;">
        If you did not expect this email, you can ignore it.
      </div>
    </div>
  </div>`;
}

/* ===== Invite repository (SQL) ===== */
async function createInvite({ workspaceId, email, role, invitedBy, ttlMinutes = 10080 /* 7 days */ }) {
  const id = 'inv_' + nanoid(16);
  const token = makeToken();
  const tokenHash = sha256Base64url(token);
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();

  const q = `
    INSERT INTO invites (id, workspace_id, email, role, token_hash, status, invited_by, expires_at, last_sent_at)
    VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,NOW())
    RETURNING id, workspace_id, email, role, status, invited_by, created_at, expires_at, last_sent_at
  `;
  const v = [id, workspaceId, email.toLowerCase(), role, tokenHash, invitedBy.toLowerCase(), expiresAt];
  const { rows } = await pool.query(q, v);
  return { record: rows[0], token };
}
async function listInvites({ workspaceId }) {
  const { rows } = await pool.query(
    `SELECT * FROM invites WHERE workspace_id=$1 ORDER BY created_at DESC LIMIT 200`,
    [workspaceId]
  );
  return rows;
}
async function findInviteById(id) {
  const { rows } = await pool.query(`SELECT * FROM invites WHERE id=$1`, [id]);
  return rows[0] || null;
}
async function findPendingByEmail(workspaceId, email) {
  const { rows } = await pool.query(
    `SELECT * FROM invites WHERE workspace_id=$1 AND email=$2 AND status='pending' ORDER BY created_at DESC LIMIT 1`,
    [workspaceId, email.toLowerCase()]
  );
  return rows[0] || null;
}
async function markCancelled(id) {
  await pool.query(`UPDATE invites SET status='cancelled' WHERE id=$1`, [id]);
}
async function markAccepted(id) {
  await pool.query(`UPDATE invites SET status='accepted', accepted_at=NOW() WHERE id=$1`, [id]);
}
async function updateLastSent(id) {
  await pool.query(`UPDATE invites SET last_sent_at=NOW() WHERE id=$1`, [id]);
}

/* ===== Mail send helper ===== */
async function sendInviteEmail({ to, workspaceName, acceptLink, downloadLink, deeplink }) {
  const html = inviteEmailHtml({ workspaceName, acceptLink, downloadLink, deeplink });
  const subject = `Invitation to ${workspaceName}`;
  const headers = {};
  // Optional: List-Unsubscribe (nicht benötigt bei Transaktionsmails)
  // headers['List-Unsubscribe'] = `<mailto:unsubscribe@multi-session-cm.com>, <https://multi-session-cm.com/unsubscribe>`;

  const payload = {
    from: EMAIL_FROM,
    to,
    subject,
    html,
    headers
  };
  if (EMAIL_REPLY_TO) payload.reply_to = EMAIL_REPLY_TO;

  const res = await resend.emails.send(payload);
  return res;
}

/* ===== Routes ===== */

// Healthcheck (Render needs this)
app.get('/health', (_req, res) => {
  res.status(200).json({ ok: true, ts: nowIso() });
});

// Create invite & send email
app.post('/api/invites', async (req, res) => {
  try {
    const { workspaceId, workspaceName, inviteeEmail, role = 'member', invitedBy } = req.body || {};
    if (!workspaceId || !inviteeEmail || !invitedBy) {
      return res.status(400).json({ ok: false, error: 'workspaceId, inviteeEmail, invitedBy required' });
    }
    if (!['member','admin'].includes(role)) {
      return res.status(400).json({ ok:false, error:'invalid role' });
    }

    // de-dupe: existing pending?
    const existing = await findPendingByEmail(workspaceId, inviteeEmail);
    if (existing) {
      return res.status(409).json({ ok:false, error:'invite_already_pending', inviteId: existing.id });
    }

    const { record, token } = await createInvite({
      workspaceId,
      email: inviteeEmail,
      role,
      invitedBy,
      ttlMinutes: 60 * 24 * 7 // 7 days
    });

    const acceptLink = acceptUrlFromToken(`${record.id}.${token}`);
    const deep = appDeepLink(record.id);
    await sendInviteEmail({
      to: inviteeEmail,
      workspaceName: workspaceName || 'Multi-Session CRM',
      acceptLink,
      downloadLink: downloadUrl(),
      deeplink: deep
    });
    await updateLastSent(record.id);

    res.json({ ok:true, inviteId: record.id, expiresAt: record.expires_at });
  } catch (e) {
    console.error('create invite error', e);
    res.status(500).json({ ok:false, error:'internal_error' });
  }
});

// List invites (by workspace)
app.get('/api/invites', async (req, res) => {
  try {
    const { workspaceId } = req.query;
    if (!workspaceId) return res.status(400).json({ ok:false, error:'workspaceId required' });
    const rows = await listInvites({ workspaceId });
    res.json({ ok:true, invites: rows });
  } catch (e) {
    console.error('list invites error', e);
    res.status(500).json({ ok:false, error:'internal_error' });
  }
});

// Resend invite
app.post('/api/invites/:id/resend', async (req, res) => {
  try {
    const id = req.params.id;
    const inv = await findInviteById(id);
    if (!inv) return res.status(404).json({ ok:false, error:'not_found' });
    if (inv.status !== 'pending') return res.status(400).json({ ok:false, error:'not_pending' });

    // build a fresh accept token while keeping the same invite id
    const token = makeToken();
    const newHash = sha256Base64url(token);
    // rotate token_hash (optional, but safer)
    await pool.query(`UPDATE invites SET token_hash=$1, expires_at=$2, last_sent_at=NOW() WHERE id=$3`,
      [newHash, new Date(Date.now()+7*24*60*60*1000).toISOString(), id]);

    const acceptLink = acceptUrlFromToken(`${id}.${token}`);
    const deep = appDeepLink(id);
    await sendInviteEmail({
      to: inv.email,
      workspaceName: 'Multi-Session CRM',
      acceptLink,
      downloadLink: downloadUrl(),
      deeplink: deep
    });
    res.json({ ok:true });
  } catch (e) {
    console.error('resend invite error', e);
    res.status(500).json({ ok:false, error:'internal_error' });
  }
});

// Cancel invite
app.post('/api/invites/:id/cancel', async (req, res) => {
  try {
    const id = req.params.id;
    const inv = await findInviteById(id);
    if (!inv) return res.status(404).json({ ok:false, error:'not_found' });
    if (inv.status !== 'pending') return res.status(400).json({ ok:false, error:'not_pending' });
    await markCancelled(id);
    res.json({ ok:true });
  } catch (e) {
    console.error('cancel invite error', e);
    res.status(500).json({ ok:false, error:'internal_error' });
  }
});

/* ===== (Optional) Token verify endpoint (für deine Accept-Landingpage)
   Frontend ruft z. B. /api/invites/verify?token=inv_xxx.SECRET
   Antwort: ok + invite info → Client weiß, dass „Accept“ angeboten werden kann.
===== */
app.get('/api/invites/verify', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token || typeof token !== 'string') return res.status(400).json({ ok:false, error:'token required' });

    const [id, secret] = token.split('.');
    if (!id || !secret) return res.status(400).json({ ok:false, error:'bad_token' });

    const inv = await findInviteById(id);
    if (!inv) return res.status(404).json({ ok:false, error:'not_found' });
    if (inv.status !== 'pending') return res.status(400).json({ ok:false, error:'not_pending' });

    const expected = sha256Base64url(secret);
    if (expected !== inv.token_hash) return res.status(400).json({ ok:false, error:'invalid_token' });

    if (new Date(inv.expires_at).getTime() < Date.now()) {
      return res.status(400).json({ ok:false, error:'expired' });
    }

    res.json({ ok:true, invite: {
      id: inv.id,
      workspaceId: inv.workspace_id,
      email: inv.email,
      role: inv.role,
      expiresAt: inv.expires_at
    }});
  } catch (e) {
    console.error('verify invite error', e);
    res.status(500).json({ ok:false, error:'internal_error' });
  }
});

/* ===== Server start ===== */
app.listen(PORT, () => {
  console.log(`[mcrm-mini] listening on :${PORT} (${NODE_ENV})`);
});
