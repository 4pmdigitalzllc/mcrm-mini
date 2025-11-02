import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { nanoid } from 'nanoid';
import { fetch } from 'undici';

const {
  PORT = 10000,
  NODE_ENV = 'production',
  BASE_URL = 'https://mcrm-mini.onrender.com',
  ACCEPT_URL = 'https://mcrm-mini.onrender.com/accept',   // später auf deine invite-Subdomain ändern
  RESEND_API_KEY,
  EMAIL_FROM = 'Multi-Session CRM <onboarding@resend.dev>', // bis Domain verifiziert ist
  EMAIL_REPLY_TO = '',
  INVITE_SIGNING_SECRET,
  INVITE_TOKEN_TTL = String(7 * 24 * 60 * 60), // 7 Tage (Sekunden)
  RATE_LIMIT_WINDOW = '60000', // 60s
  RATE_LIMIT_MAX = '30',
  ALLOWED_ORIGINS = '',
  CORS_ALLOW_HEADERS = 'Content-Type,Authorization'
} = process.env;

// ---------- CORS ----------
const allowlist = (ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin(origin, cb) {
    // Electron: origin ist meistens null → erlauben
    if (!origin) return cb(null, true);
    // normale Browser: nur Allowlist
    if (allowlist.some(o => origin === o || origin.endsWith(o))) return cb(null, true);
    return cb(new Error('Not allowed by CORS'), false);
  },
  credentials: true,
  allowedHeaders: CORS_ALLOW_HEADERS
};

// ---------- Mini In-Memory Store (nur für „jetzt sofort“) ----------
/*
  Für Produktion später auf Redis/Upstash umziehen.
  Struktur:
  pendingInvites = { [ownerEmail]: [{id,email,role,token,exp}] }
*/
const pendingInvites = Object.create(null);

// ---------- Helpers ----------
function signInvite(payload) {
  const ttlSec = Number(INVITE_TOKEN_TTL) || (7 * 24 * 60 * 60);
  return jwt.sign(payload, INVITE_SIGNING_SECRET, { expiresIn: ttlSec });
}
function verifyInvite(token) {
  return jwt.verify(token, INVITE_SIGNING_SECRET);
}

async function sendInviteEmail({ to, ownerName, ownerEmail, workspaceName, token }) {
  const url = `${ACCEPT_URL}?token=${encodeURIComponent(token)}`;

  const html = `
    <div style="font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;font-size:16px;line-height:1.5;color:#111">
      <h2 style="margin:0 0 12px">Einladung zu Multi-Session CRM</h2>
      <p><b>${ownerName || ownerEmail}</b> (${ownerEmail}) hat dich in seinen Workspace <b>${workspaceName || 'Workspace'}</b> eingeladen.</p>
      <p>Klicke auf den Button, um dein Passwort zu setzen und beizutreten:</p>
      <p>
        <a href="${url}" style="display:inline-block;padding:10px 16px;background:#111;color:#fff;border-radius:8px;text-decoration:none">
          Einladung annehmen
        </a>
      </p>
      <p style="font-size:13px;color:#666">Falls der Button nicht funktioniert: ${url}</p>
    </div>
  `;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: EMAIL_FROM,                    // aktuell onboarding@resend.dev
      to: [to],
      subject: 'Du wurdest eingeladen – Multi-Session CRM',
      html,
      reply_to: EMAIL_REPLY_TO || undefined
    })
  });

  if (!res.ok) {
    const txt = await res.text().catch(()=>'');
    throw new Error(`Resend failed ${res.status}: ${txt}`);
  }
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(cors(corsOptions));

// -------- Health --------
app.get('/health', (req, res) => res.json({ ok: true, time: Date.now() }));
app.get('/', (req,res)=> res.type('text').send('mcrm-mini live'));

// -------- Rate limiting (simple in-memory) --------
const hits = new Map();
app.use((req,res,next)=>{
  const win = Number(RATE_LIMIT_WINDOW) || 60000;
  const max = Number(RATE_LIMIT_MAX) || 30;
  const key = `${req.ip}:${Math.floor(Date.now()/win)}`;
  const c = (hits.get(key) || 0) + 1;
  hits.set(key, c);
  if (c > max) return res.status(429).json({ ok:false, error:'rate_limited' });
  next();
});

// ===== INVITES API =====

// Create invite (Owner/Admin)
app.post('/api/invites', async (req, res) => {
  try {
    const { ownerEmail, ownerName, workspaceName, inviteEmail, role = 'member' } = req.body || {};
    if (!ownerEmail || !inviteEmail) return res.status(400).json({ ok:false, error:'missing_fields' });

    const id = nanoid(12);
    const token = signInvite({ id, inviteEmail, role, ownerEmail, workspaceName });
    const exp = Date.now() + (Number(INVITE_TOKEN_TTL) || (7*24*60*60))*1000;

    pendingInvites[ownerEmail] ||= [];
    // block duplicate pending email
    if (pendingInvites[ownerEmail].some(i => i.inviteEmail.toLowerCase() === inviteEmail.toLowerCase())) {
      return res.status(409).json({ ok:false, error:'already_invited' });
    }
    pendingInvites[ownerEmail].push({ id, inviteEmail, role, token, exp });

    if (!RESEND_API_KEY) {
      // Dev Modus ohne Mail
      return res.json({ ok:true, id, token, acceptUrl: `${ACCEPT_URL}?token=${encodeURIComponent(token)}` });
    }

    await sendInviteEmail({ to: inviteEmail, ownerName, ownerEmail, workspaceName, token });
    res.json({ ok:true, id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, error:'send_failed' });
  }
});

// List pending invites (Owner/Admin)
app.get('/api/invites', (req, res) => {
  const ownerEmail = String(req.query.ownerEmail || '').toLowerCase();
  if (!ownerEmail) return res.status(400).json({ ok:false, error:'missing_owner' });
  const now = Date.now();
  const list = (pendingInvites[ownerEmail] || []).filter(i => i.exp > now).map(i => ({
    id:i.id, email:i.inviteEmail, role:i.role, status:'pending'
  }));
  res.json({ ok:true, invites:list });
});

// Cancel invite
app.delete('/api/invites/:id', (req,res)=>{
  const ownerEmail = String(req.query.ownerEmail || '').toLowerCase();
  const { id } = req.params;
  if (!ownerEmail || !id) return res.status(400).json({ ok:false, error:'missing' });
  pendingInvites[ownerEmail] = (pendingInvites[ownerEmail] || []).filter(i => i.id !== id);
  res.json({ ok:true });
});

// Resend invite
app.post('/api/invites/:id/resend', async (req,res)=>{
  try{
    const ownerEmail = String(req.body.ownerEmail || '').toLowerCase();
    const ownerName  = req.body.ownerName || ownerEmail;
    const workspaceName = req.body.workspaceName || 'Workspace';
    const list = pendingInvites[ownerEmail] || [];
    const item = list.find(i => i.id === req.params.id);
    if(!item) return res.status(404).json({ ok:false, error:'not_found' });

    await sendInviteEmail({
      to: item.inviteEmail,
      ownerName, ownerEmail, workspaceName,
      token: item.token
    });
    res.json({ ok:true });
  }catch(e){
    console.error(e);
    res.status(500).json({ ok:false, error:'send_failed' });
  }
});

// Accept endpoint (nur zum Testen – gibt Payload aus)
app.get('/accept', (req,res)=>{
  const { token } = req.query;
  if(!token) return res.status(400).type('text').send('Missing token');
  try{
    const payload = verifyInvite(String(token));
    res.type('html').send(`
      <h2>Invite ok ✅</h2>
      <pre>${JSON.stringify(payload, null, 2)}</pre>
      <p>Hier würdest du später das Passwort setzen & in den Workspace einloggen.</p>
    `);
  }catch(e){
    res.status(400).type('text').send('Invalid or expired token');
  }
});

app.listen(PORT, () => {
  console.log(`mcrm-mini listening on ${PORT}`);
  console.log(`=> Your service is live 🎉`);
  console.log(`=> Available at your primary URL ${BASE_URL}`);
});
