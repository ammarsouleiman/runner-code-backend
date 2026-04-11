'use strict';

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const path = require('path');
const { Readable } = require('stream');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');

require('dotenv').config({ path: path.join(__dirname, '.env') });

const app = express();
const PORT = process.env.PORT || 8080;

if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  console.error('\u274c FATAL: JWT_SECRET is not set in production');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-insecure-secret';

// ── Database setup ────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'database.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL,
    email        TEXT    UNIQUE NOT NULL,
    password_hash TEXT   NOT NULL,
    country      TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id         TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT    NOT NULL DEFAULT 'New Chat',
    model      TEXT    NOT NULL DEFAULT 'google/gemini-2.5-flash',
    messages   TEXT    NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS reactions (
    user_id         INTEGER NOT NULL,
    message_id      TEXT    NOT NULL,
    conversation_id TEXT    NOT NULL,
    reaction        TEXT    NOT NULL CHECK(reaction IN ('up', 'down')),
    PRIMARY KEY (user_id, message_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS message_media (
    message_id TEXT    NOT NULL,
    user_id    INTEGER NOT NULL,
    image_url  TEXT,
    image_urls TEXT,
    pdf_url    TEXT,
    PRIMARY KEY (message_id, user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`);

// ── Migrations ────────────────────────────────────────────────────────────────
try { db.exec('ALTER TABLE users ADD COLUMN google_id TEXT'); } catch {}

// ── Middleware ────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  'https://platform.runner-code.com',
  'http://localhost:5173',
  'http://localhost:3000',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:3000',
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: origin '${origin}' not allowed`));
  },
  credentials: true,
}));
app.use(cookieParser());
app.use(express.json({ limit: '20mb' }));

// ── Google OAuth client ─────────────────────────────────────────────────────
const googleClient = process.env.GOOGLE_CLIENT_ID
  ? new OAuth2Client(process.env.GOOGLE_CLIENT_ID)
  : null;

// ── Rate limiters ─────────────────────────────────────────────────────────────
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });
const chatLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });

// ── Allowed AI models ─────────────────────────────────────────────────────────
const ALLOWED_MODELS = new Set([
  'openai/gpt-4o', 'anthropic/claude-3.7-sonnet', 'openai/o1',
  'openai/gpt-4o-mini', 'anthropic/claude-3-5-haiku', 'google/gemini-2.5-flash',
  'meta-llama/llama-3.3-70b-instruct:free', 'qwen/qwen3-coder:free',
  'mistralai/mistral-small-3.1-24b-instruct:free', 'google/gemma-3-27b-it:free',
]);

// ── Security headers ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ── Cookie helpers ───────────────────────────────────────────────────────────
const COOKIE_NAME = 'rc_token';
const IS_PROD = process.env.NODE_ENV === 'production';

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: IS_PROD ? 'none' : 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    path: '/',
  });
}

function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: IS_PROD ? 'none' : 'lax',
    path: '/',
  });
}

// ── JWT Verification Middleware ───────────────────────────────────────────────
function verifyToken(req, res, next) {
  // HttpOnly cookie first (XSS-safe), then Bearer header as fallback
  const token = req.cookies[COOKIE_NAME] ||
    (req.headers['authorization']?.split(' ')[1]);

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// ── POST /api/auth/register ───────────────────────────────────────────────────
app.post('/api/auth/register', authLimiter, (req, res) => {
  const { name, email, password, country } = req.body;

  if (!name?.trim() || !email?.trim() || !password?.trim()) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normalizedEmail);
  if (existing) {
    return res.status(409).json({ error: 'Email is already registered' });
  }

  const passwordHash = bcrypt.hashSync(password, 10);

  const result = db
    .prepare('INSERT INTO users (name, email, password_hash, country) VALUES (?, ?, ?, ?)')
    .run(name.trim(), normalizedEmail, passwordHash, country?.trim() || null);

  const token = jwt.sign(
    { id: result.lastInsertRowid, name: name.trim(), email: normalizedEmail },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  console.log(`✅ New user registered (id=${result.lastInsertRowid})`);

  setAuthCookie(res, token);
  res.status(201).json({
    user: {
      id: result.lastInsertRowid,
      name: name.trim(),
      email: normalizedEmail,
      country: country?.trim() || null,
    },
  });
});

// ── POST /api/auth/login ──────────────────────────────────────────────────────
app.post('/api/auth/login', authLimiter, (req, res) => {
  const { email, password } = req.body;

  if (!email?.trim() || !password?.trim()) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail);

  // Google-only account — no password set
  if (user && user.password_hash === 'GOOGLE_AUTH') {
    return res.status(400).json({ error: 'This account uses Google Sign-In. Please use the "Sign in with Google" button.' });
  }

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = jwt.sign(
    { id: user.id, name: user.name, email: user.email },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  console.log(`✅ User logged in (id=${user.id})`);

  setAuthCookie(res, token);
  res.json({
    user: { id: user.id, name: user.name, email: user.email, country: user.country },
  });
});

// ── GET /api/auth/me ──────────────────────────────────────────────────────────
app.get('/api/auth/me', verifyToken, (req, res) => {
  const user = db
    .prepare('SELECT id, name, email, country, created_at FROM users WHERE id = ?')
    .get(req.user.id);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({ user });
});

// ── PATCH /api/auth/profile ──────────────────────────────────────────────────
// Used by Google sign-in users to set country + password after first login
app.patch('/api/auth/profile', verifyToken, (req, res) => {
  const { country, password } = req.body;
  if (!country?.trim()) return res.status(400).json({ error: 'Country is required' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const passwordHash = bcrypt.hashSync(password, 10);
  db.prepare('UPDATE users SET country = ?, password_hash = ? WHERE id = ?')
    .run(country.trim(), passwordHash, req.user.id);
  res.json({ country: country.trim() });
});

// ── POST /api/auth/complete-profile ──────────────────────────────────────────
// Second step for new Google users — creates account in DB after profile setup
app.post('/api/auth/complete-profile', authLimiter, (req, res) => {
  const { setupToken, country, password } = req.body;
  if (!setupToken || !country?.trim() || !password || password.length < 8) {
    return res.status(400).json({ error: 'setupToken, country, and password (min 8 chars) are required' });
  }

  let payload;
  try {
    payload = jwt.verify(setupToken, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Setup session expired. Please sign in with Google again.' });
  }

  if (!payload.setup) return res.status(401).json({ error: 'Invalid setup token' });

  const { googleId, email, name } = payload;

  // Guard: don't create duplicates if called twice
  let user = db.prepare('SELECT * FROM users WHERE google_id = ?').get(googleId);
  if (!user) {
    const emailExists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (emailExists) {
      return res.status(409).json({ error: 'This email is already registered.' });
    }
    const passwordHash = bcrypt.hashSync(password, 10);
    const result = db.prepare(
      'INSERT INTO users (name, email, password_hash, google_id, country) VALUES (?, ?, ?, ?, ?)'
    ).run(name, email, passwordHash, googleId, country.trim());
    user = db.prepare('SELECT id, name, email, country FROM users WHERE id = ?').get(result.lastInsertRowid);
    console.log(`✅ New Google user created (id=${user.id})`);
  }

  const token = jwt.sign(
    { id: user.id, name: user.name, email: user.email },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  setAuthCookie(res, token);
  res.json({ user: { id: user.id, name: user.name, email: user.email, country: user.country } });
});

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
app.post('/api/auth/logout', (req, res) => {
  clearAuthCookie(res);
  res.json({ message: 'Logged out successfully' });
});

// ── DELETE /api/auth/account ──────────────────────────────────────────────────
app.delete('/api/auth/account', verifyToken, (req, res) => {
  const user = db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(req.user.id);
  console.log(`🗑️  Account deleted (id=${user.id})`);
  res.json({ message: 'Account deleted successfully' });
});

// ── POST /api/auth/google ───────────────────────────────────────────────────
app.post('/api/auth/google', authLimiter, async (req, res) => {
  if (!googleClient) return res.status(503).json({ error: 'Google sign-in not configured' });

  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token is required' });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture, email_verified: googleEmailVerified } = payload;

    if (!googleEmailVerified) {
      return res.status(400).json({ error: 'Google account email is not verified' });
    }

    const normalizedEmail = email.toLowerCase();

    // 1. Look up by google_id first (returning user)
    let user = db.prepare('SELECT * FROM users WHERE google_id = ?').get(googleId);

    if (!user) {
      // 2. Check if email exists under a password-based account
      const emailUser = db.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail);
      if (emailUser) {
        return res.status(409).json({
          error: 'This email is already registered. Please sign in with your email and password instead.',
        });
      }

      // 3. New user — do NOT create in DB yet, return a setup token instead
      const displayName = name || normalizedEmail.split('@')[0];
      const setupToken = jwt.sign(
        { googleId, email: normalizedEmail, name: displayName, setup: true },
        JWT_SECRET,
        { expiresIn: '15m' }
      );
      console.log(`🔑 Google setup token issued`);
      return res.json({ needsSetup: true, setupToken });
    }

    const jwtToken = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    setAuthCookie(res, jwtToken);
    res.json({
      user: { id: user.id, name: user.name, email: user.email, country: user.country },
    });
  } catch (err) {
    console.error('Google auth error:', err.message);
    res.status(400).json({ error: 'Invalid Google token' });
  }
});

// ── POST /api/chat ────────────────────────────────────────────────────────────
// Proxy to OpenRouter — keeps API key server-side only
app.post('/api/chat', verifyToken, chatLimiter, async (req, res) => {
  const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY;
  if (!OPENROUTER_KEY) return res.status(503).json({ error: 'AI service not configured' });

  const { model } = req.body;
  if (model && !ALLOWED_MODELS.has(model)) {
    return res.status(400).json({ error: 'Model not allowed' });
  }

  try {
    const upstream = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENROUTER_KEY}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://platform.runner-code.com',
        'X-Title': 'Runner Code AI',
      },
      body: JSON.stringify(req.body),
    });

    const contentType = upstream.headers.get('content-type') || '';

    if (!upstream.ok) {
      const err = await upstream.json().catch(() => ({}));
      const status = upstream.status === 404 ? 502 : upstream.status;
      return res.status(status).json(err);
    }

    // Stream response directly to client
    // upstream.body is a Web API ReadableStream — convert to Node.js stream before piping
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'no-cache');
    Readable.fromWeb(upstream.body).pipe(res);
  } catch (err) {
    res.status(502).json({ error: 'Upstream AI error' });
  }
});

// ── GET /api/images ───────────────────────────────────────────────────────────
// Proxy to Pexels — keeps API key server-side only
app.get('/api/images', verifyToken, async (req, res) => {
  const PEXELS_KEY = process.env.PEXELS_API_KEY;
  if (!PEXELS_KEY) return res.status(503).json({ error: 'Image service not configured' });

  const { query, per_page = '6', page = '1' } = req.query;
  const safePerPage = Math.min(Math.max(parseInt(per_page, 10) || 6, 1), 20);
  const safePage = Math.max(parseInt(page, 10) || 1, 1);
  if (!query) return res.status(400).json({ error: 'query is required' });

  try {
    const upstream = await fetch(
      `https://api.pexels.com/v1/search?query=${encodeURIComponent(query)}&per_page=${safePerPage}&page=${safePage}`,
      { headers: { Authorization: PEXELS_KEY } }
    );
    const data = await upstream.json();
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: 'Upstream image error' });
  }
});

// ── GET /admin/users ──────────────────────────────────────────────────────────
// Protected with ADMIN_KEY env variable — returns all users as HTML table
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

app.get('/admin/users', (req, res) => {
  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey || req.query.key !== adminKey) {
    return res.status(401).send('Unauthorized');
  }
  const users = db.prepare('SELECT id, name, email, country, password_hash, google_id, created_at FROM users ORDER BY created_at DESC').all();
  const key = encodeURIComponent(req.query.key);
  const rows = users.map(u => {
    const hasRealPassword = u.password_hash && u.password_hash !== 'GOOGLE_AUTH' && u.password_hash.startsWith('$2');
    let authType;
    if (u.google_id && hasRealPassword) authType = '🔵 Google + 🔑 Password';
    else if (u.google_id)              authType = '🔵 Google only (no password)';
    else if (hasRealPassword)          authType = '🔑 Password';
    else                               authType = '⚠️ No auth';
    return `
    <tr>
      <td>${u.id}</td>
      <td>${escapeHtml(u.name)}</td>
      <td>${escapeHtml(u.email)}</td>
      <td>${escapeHtml(u.country || '—')}</td>
      <td>${authType}</td>
      <td>${escapeHtml(u.created_at || '—')}</td>
      <td>
        <button onclick="deleteUser(${u.id}, '${escapeHtml(u.name)}')" 
          style="background:#E31E24;color:#fff;border:none;padding:4px 10px;border-radius:6px;cursor:pointer;font-size:12px;"
        >Delete</button>
      </td>
    </tr>`;
  }).join('');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Runner Code — Admin</title>
  <style>
    body { font-family: sans-serif; background: #0f0f0f; color: #eee; padding: 32px; }
    h1 { color: #E31E24; margin-bottom: 4px; }
    p  { color: #888; margin-bottom: 24px; }
    table { width: 100%; border-collapse: collapse; }
    th { background: #1a1a1a; color: #E31E24; padding: 10px 14px; text-align: left; font-size: 13px; }
    td { padding: 10px 14px; border-bottom: 1px solid #222; font-size: 13px; vertical-align: middle; }
    tr:hover td { background: #1a1a1a; }
    .toast { position:fixed; bottom:24px; right:24px; background:#1a1a1a; border:1px solid #333; color:#eee; padding:12px 20px; border-radius:10px; font-size:14px; display:none; }
  </style>
</head>
<body>
  <h1>Runner Code — Admin</h1>
  <p>Total: <strong>${users.length}</strong> user${users.length !== 1 ? 's' : ''}</p>
  <table>
    <thead><tr><th>#</th><th>Name</th><th>Email</th><th>Country</th><th>Auth</th><th>Registered</th><th>Action</th></tr></thead>
    <tbody id="tbody">${rows}</tbody>
  </table>
  <div class="toast" id="toast"></div>
  <script>
    function showToast(msg, ok) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.style.display = 'block';
      t.style.borderColor = ok ? '#34A853' : '#E31E24';
      setTimeout(() => t.style.display = 'none', 3000);
    }
    function deleteUser(id, name) {
      if (!confirm('Delete account of ' + name + '? This cannot be undone.')) return;
      fetch('/admin/users/' + id + '?key=${key}', { method: 'DELETE' })
        .then(r => r.json())
        .then(d => {
          if (d.ok) {
            document.querySelector('tr[data-id="' + id + '"]')?.remove();
            showToast('✅ Deleted: ' + name, true);
            // Remove row by finding button's parent row
            document.querySelectorAll('tr').forEach(tr => {
              if (tr.innerHTML.includes('deleteUser(' + id + ',')) tr.remove();
            });
          } else { showToast('❌ ' + (d.error || 'Failed'), false); }
        })
        .catch(() => showToast('❌ Network error', false));
    }
  <\/script>
</body>
</html>`);
});

// ── DELETE /admin/users/:id ───────────────────────────────────────────────────
app.delete('/admin/users/:id', (req, res) => {
  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey || req.query.key !== adminKey) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid id' });
  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  console.log(`🗑️  Admin deleted user (id=${id})`);
  res.json({ ok: true });
});

// ── GET /api/conversations ──────────────────────────────────────────────────
app.get('/api/conversations', verifyToken, (req, res) => {
  const convs = db.prepare(
    'SELECT id, title, model, messages, created_at, updated_at FROM conversations WHERE user_id = ? ORDER BY updated_at DESC'
  ).all(req.user.id);
  res.json(convs.map(c => ({ ...c, messages: JSON.parse(c.messages) })));
});

// ── PUT /api/conversations/:id ────────────────────────────────────────────────
app.put('/api/conversations/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const { title, model, messages, created_at, updated_at } = req.body;
  if (!id || !Array.isArray(messages)) return res.status(400).json({ error: 'Missing fields' });

  // Strip base64 blobs before storing to keep conversations table lean
  const stripped = messages.map(m => ({
    ...m,
    imageUrl: undefined,
    imageUrls: undefined,
    pdfUrl: undefined,
  }));

  db.prepare(`
    INSERT INTO conversations (id, user_id, title, model, messages, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      title      = excluded.title,
      model      = excluded.model,
      messages   = excluded.messages,
      updated_at = excluded.updated_at
    WHERE conversations.user_id = ?
  `).run(
    id, req.user.id,
    title || 'New Chat',
    model || 'google/gemini-2.5-flash',
    JSON.stringify(stripped),
    created_at || Date.now(),
    updated_at || Date.now(),
    req.user.id
  );

  // Save media separately for any messages that have images/PDFs
  const mediaMessages = messages.filter(m => m.imageUrl || (Array.isArray(m.imageUrls) && m.imageUrls.length > 0) || m.pdfUrl);
  if (mediaMessages.length > 0) {
    const upsertMedia = db.prepare(`
      INSERT INTO message_media (message_id, user_id, image_url, image_urls, pdf_url)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(message_id, user_id) DO UPDATE SET
        image_url  = COALESCE(excluded.image_url,  message_media.image_url),
        image_urls = COALESCE(excluded.image_urls, message_media.image_urls),
        pdf_url    = COALESCE(excluded.pdf_url,    message_media.pdf_url)
    `);
    const insertMediaBatch = db.transaction((msgs) => {
      msgs.forEach(m => upsertMedia.run(
        m.id, req.user.id,
        m.imageUrl || null,
        m.imageUrls ? JSON.stringify(m.imageUrls) : null,
        m.pdfUrl || null
      ));
    });
    insertMediaBatch(mediaMessages);
  }

  res.json({ ok: true });
});

// ── DELETE /api/conversations/:id ─────────────────────────────────────────────
app.delete('/api/conversations/:id', verifyToken, (req, res) => {
  db.prepare('DELETE FROM conversations WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  db.prepare('DELETE FROM reactions WHERE conversation_id = ? AND user_id = ?').run(req.params.id, req.user.id);
  db.prepare('DELETE FROM message_media WHERE message_id IN (SELECT id FROM json_each(?)) AND user_id = ?').run(
    JSON.stringify([req.params.id]), req.user.id
  );
  // Simpler: delete all media rows for this user that belong to deleted conversation
  // Since we don’t store conversation_id in message_media, clean via orphan check:
  db.prepare(`
    DELETE FROM message_media
    WHERE user_id = ?
      AND message_id NOT IN (
        SELECT json_each.value
        FROM conversations, json_each(json_extract(conversations.messages, '$[*].id'))
        WHERE conversations.user_id = ?
      )
  `).run(req.user.id, req.user.id);
  res.json({ ok: true });
});

// ── GET /api/media/:conversationId ──────────────────────────────────────────────
app.get('/api/media/:conversationId', verifyToken, (req, res) => {
  const conv = db.prepare('SELECT messages FROM conversations WHERE id = ? AND user_id = ?')
    .get(req.params.conversationId, req.user.id);
  if (!conv) return res.status(404).json({ error: 'Not found' });

  const messages = JSON.parse(conv.messages);
  const messageIds = messages.map(m => m.id);
  if (messageIds.length === 0) return res.json({});

  const placeholders = messageIds.map(() => '?').join(',');
  const media = db.prepare(
    `SELECT message_id, image_url, image_urls, pdf_url FROM message_media
     WHERE user_id = ? AND message_id IN (${placeholders})`
  ).all(req.user.id, ...messageIds);

  const result = {};
  media.forEach(m => {
    result[m.message_id] = {
      ...(m.image_url  ? { imageUrl:  m.image_url }                    : {}),
      ...(m.image_urls ? { imageUrls: JSON.parse(m.image_urls) }       : {}),
      ...(m.pdf_url    ? { pdfUrl:    m.pdf_url }                      : {}),
    };
  });
  res.json(result);
});

// ── POST /api/reactions ───────────────────────────────────────────────────────
app.post('/api/reactions', verifyToken, (req, res) => {
  const { messageId, conversationId, reaction } = req.body;
  if (!messageId || !conversationId || !['up', 'down'].includes(reaction)) {
    return res.status(400).json({ error: 'Invalid reaction' });
  }
  db.prepare(`
    INSERT INTO reactions (user_id, message_id, conversation_id, reaction)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id, message_id) DO UPDATE SET reaction = excluded.reaction
  `).run(req.user.id, messageId, conversationId, reaction);
  res.json({ ok: true });
});

// ── DELETE /api/reactions/:messageId ─────────────────────────────────────────
app.delete('/api/reactions/:messageId', verifyToken, (req, res) => {
  db.prepare('DELETE FROM reactions WHERE user_id = ? AND message_id = ?')
    .run(req.user.id, req.params.messageId);
  res.json({ ok: true });
});

// ── GET /api/reactions/:conversationId ───────────────────────────────────────
app.get('/api/reactions/:conversationId', verifyToken, (req, res) => {
  const rows = db.prepare(
    'SELECT message_id, reaction FROM reactions WHERE user_id = ? AND conversation_id = ?'
  ).all(req.user.id, req.params.conversationId);
  res.json(rows);
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log('\n🚀 Runner Code Auth Server');
  console.log(`📡 Running on: http://0.0.0.0:${PORT}`);
  console.log(`💾 Database:   ${path.join(__dirname, 'database.db')}`);
  console.log('\n✅ Ready to accept connections\n');
});
