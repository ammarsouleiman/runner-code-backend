'use strict';

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const { Readable } = require('stream');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');

require('dotenv').config({ path: path.join(__dirname, '.env') });

const app = express();
app.set('trust proxy', 1); // Trust Railway's reverse proxy for accurate IP detection
app.disable('x-powered-by');
const PORT = process.env.PORT || 8080;

if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  console.error('\u274c FATAL: JWT_SECRET is not set in production');
  process.exit(1);
}
if (process.env.NODE_ENV === 'production' && process.env.JWT_SECRET.length < 32) {
  console.error('\u274c FATAL: JWT_SECRET must be at least 32 characters in production');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-insecure-secret';

// ── Database setup ────────────────────────────────────────────────────────────
// In production: use /app/data (Railway persistent volume)
// In development: use local __dirname
const DB_DIR = process.env.NODE_ENV === 'production'
  ? '/app/data'
  : __dirname;
const db = new Database(path.join(DB_DIR, 'database.db'));

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
  );

  CREATE TABLE IF NOT EXISTS contact_messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT    NOT NULL,
    subject    TEXT    NOT NULL,
    message    TEXT    NOT NULL,
    user_name  TEXT    NOT NULL,
    user_email TEXT    NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS projects (
    id           TEXT    PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    color        TEXT    NOT NULL DEFAULT '#e31e24',
    instructions TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
  );
`);

// ── Migrations ────────────────────────────────────────────────────────────────
db.pragma('foreign_keys = ON');
try { db.exec('ALTER TABLE users ADD COLUMN google_id TEXT'); } catch {}
try { db.exec("ALTER TABLE contact_messages ADD COLUMN user_id INTEGER"); } catch {}
try { db.exec("ALTER TABLE contact_messages ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'"); } catch {}
try { db.exec("ALTER TABLE users ADD COLUMN suspended INTEGER NOT NULL DEFAULT 0"); } catch {}
try { db.exec("ALTER TABLE contact_messages ADD COLUMN admin_reply TEXT"); } catch {}
try { db.exec("ALTER TABLE users ADD COLUMN preferences TEXT NOT NULL DEFAULT '{}'"); } catch {}
try { db.exec("ALTER TABLE contact_messages ADD COLUMN replied_at DATETIME"); } catch {}
try { db.exec("ALTER TABLE contact_messages ADD COLUMN seen_at DATETIME"); } catch {}
try { db.exec("ALTER TABLE conversations ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0"); } catch {}
try { db.exec("ALTER TABLE conversations ADD COLUMN draft TEXT NOT NULL DEFAULT ''"); } catch {}
// project_id is nullable on purpose — null means "no project / Recents".
try { db.exec("ALTER TABLE conversations ADD COLUMN project_id TEXT REFERENCES projects(id) ON DELETE SET NULL"); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_conversations_project ON conversations(user_id, project_id)"); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id, updated_at DESC)"); } catch {}

// ── Middleware ────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  'https://platform.runner-code.com',
  'https://api.runner-code.com',
  'https://runner-code-backend-production.up.railway.app',
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
  'openai/gpt-oss-20b:free', 'google/gemma-4-31b-it:free',
]);

// ── Security headers ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=(), usb=()');
  res.removeHeader('X-Powered-By');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
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
    domain: IS_PROD ? '.runner-code.com' : undefined,
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    path: '/',
  });
}

function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: IS_PROD ? 'none' : 'lax',
    domain: IS_PROD ? '.runner-code.com' : undefined,
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
    // Check user still exists in DB — catches admin-deleted accounts immediately
    const exists = db.prepare('SELECT id, suspended FROM users WHERE id = ?').get(decoded.id);
    if (!exists) return res.status(401).json({ error: 'Account no longer exists' });
    if (exists.suspended) return res.status(403).json({ error: 'Account suspended. Contact support.' });
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
function parsePreferences(raw) {
  try { return raw ? JSON.parse(raw) : {}; } catch { return {}; }
}

app.get('/api/auth/me', verifyToken, (req, res) => {
  const user = db
    .prepare('SELECT id, name, email, country, created_at, preferences FROM users WHERE id = ?')
    .get(req.user.id);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  user.preferences = parsePreferences(user.preferences);
  res.json({ user });
});

// ── PATCH /api/user/preferences ──────────────────────────────────────────────
// Merge-patch user preferences (theme, sidebarOpen, adaptiveThinking, ...)
app.patch('/api/user/preferences', verifyToken, (req, res) => {
  const updates = req.body && typeof req.body === 'object' ? req.body : {};

  const ALLOWED = {
    theme:            (v) => v === 'dark' || v === 'light',
    sidebarOpen:      (v) => typeof v === 'boolean',
    adaptiveThinking: (v) => typeof v === 'boolean',
  };

  const clean = {};
  for (const [k, v] of Object.entries(updates)) {
    if (ALLOWED[k] && ALLOWED[k](v)) clean[k] = v;
  }

  const row = db.prepare('SELECT preferences FROM users WHERE id = ?').get(req.user.id);
  if (!row) return res.status(404).json({ error: 'User not found' });

  const current = parsePreferences(row.preferences);
  const merged  = { ...current, ...clean };

  db.prepare('UPDATE users SET preferences = ? WHERE id = ?')
    .run(JSON.stringify(merged), req.user.id);

  res.json({ preferences: merged });
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
  // Cascade: remove related data
  try { db.prepare('DELETE FROM message_media WHERE user_id = ?').run(user.id); } catch {}
  try { db.prepare('DELETE FROM reactions WHERE user_id = ?').run(user.id); } catch {}
  try { db.prepare('DELETE FROM conversations WHERE user_id = ?').run(user.id); } catch {}
  try {
    db.prepare('DELETE FROM contact_messages WHERE user_id = ? OR (user_id IS NULL AND user_email = ?)').run(user.id, user.email);
  } catch {}
  db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
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

// ── Admin authentication ──────────────────────────────────────────────────────
// Protected with ADMIN_KEY env variable. Login via POST /admin/login sets an
// httpOnly cookie 'admin_session'. All admin endpoints require either that
// cookie OR a ?key=... query param (legacy).
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

const ADMIN_COOKIE = 'admin_session';
function isAdminAuthed(req) {
  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey) return false;
  return req.cookies[ADMIN_COOKIE] === adminKey || req.query.key === adminKey;
}
function requireAdmin(req, res, next) {
  if (!isAdminAuthed(req)) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// Shared inline SVG icons (Lucide-like)
function adminIcons() {
  const svg = (path, color = 'currentColor', size = 14) =>
    `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;flex-shrink:0;">${path}</svg>`;
  const ICONS = {
    bug:        '<path d="m8 2 1.88 1.88"/><path d="M14.12 3.88 16 2"/><path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6"/><path d="M12 20v-9"/>',
    lightbulb:  '<path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/>',
    wrench:     '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
    message:    '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    clock:      '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    check:      '<polyline points="20 6 9 17 4 12"/>',
    x:          '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    users:      '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    inbox:      '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
    google:     '<path d="M22 12c0-5.5-4.5-10-10-10S2 6.5 2 12s4.5 10 10 10c3 0 5.7-1.3 7.5-3.5"/><path d="M12 12h10"/>',
    key:        '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
    alert:      '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    trash:      '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
    logout:     '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
    dashboard:  '<rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/>',
    mail:       '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 5L2 7"/>',
    search:     '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    user:       '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    calendar:   '<rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>',
    globe:      '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    shield:     '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    reply:      '<polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/>',
    lock:       '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    unlock:     '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
    msgCircle:  '<path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>',
    send:       '<line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>',
    thumbUp:    '<path d="M7 10v12"/><path d="M15 5.88 14 10h5.83a2 2 0 0 1 1.92 2.56l-2.33 8A2 2 0 0 1 17.5 22H4a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h2.76a2 2 0 0 0 1.79-1.11L12 2h0a3.13 3.13 0 0 1 3 3.88Z"/>',
    thumbDown:  '<path d="M17 14V2"/><path d="M9 18.12 10 14H4.17a2 2 0 0 1-1.92-2.56l2.33-8A2 2 0 0 1 6.5 2H20a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-2.76a2 2 0 0 0-1.79 1.11L12 22h0a3.13 3.13 0 0 1-3-3.88Z"/>',
    star:       '<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
    refresh:    '<path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/>',
  };
  return { svg, ICONS };
}

// ── GET /admin ────────────────────────────────────────────────────────────────
// Login page (or redirect to /admin/dashboard if already logged in)
app.get('/admin', (req, res) => {
  if (isAdminAuthed(req)) return res.redirect('/admin/dashboard');
  const { svg, ICONS } = adminIcons();
  res.send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin · Runner Code</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:radial-gradient(ellipse at top,#1a0a0b 0%,#0a0a0a 50%);color:#eee;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .card{width:100%;max-width:420px;background:#131313;border:1px solid #262626;border-radius:24px;padding:40px 32px;box-shadow:0 20px 60px rgba(0,0,0,.5),0 0 0 1px rgba(227,30,36,.08)}
  .logo{width:64px;height:64px;border-radius:20px;background:linear-gradient(135deg,#E31E24,#8b1217);display:flex;align-items:center;justify-content:center;margin:0 auto 24px;box-shadow:0 10px 30px rgba(227,30,36,.3)}
  h1{font-size:22px;font-weight:800;text-align:center;margin-bottom:6px;letter-spacing:-.3px}
  .sub{color:#888;text-align:center;font-size:13px;margin-bottom:32px}
  label{display:block;font-size:11px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px}
  .input-wrap{position:relative;margin-bottom:20px}
  .input-icon{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:#666}
  input{width:100%;padding:14px 14px 14px 44px;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:12px;color:#eee;font-size:14px;outline:none;transition:all .2s;font-family:inherit}
  input:focus{border-color:#E31E24;box-shadow:0 0 0 3px rgba(227,30,36,.12)}
  button{width:100%;padding:14px;background:linear-gradient(135deg,#E31E24,#b3161b);color:#fff;border:none;border-radius:12px;font-size:14px;font-weight:700;cursor:pointer;transition:all .2s;letter-spacing:.3px;display:flex;align-items:center;justify-content:center;gap:8px}
  button:hover{transform:translateY(-1px);box-shadow:0 8px 20px rgba(227,30,36,.3)}
  button:active{transform:translateY(0)}
  button:disabled{opacity:.6;cursor:not-allowed;transform:none}
  .err{display:none;margin-top:16px;padding:12px;background:#ef444418;border:1px solid #ef444440;border-radius:10px;color:#ef4444;font-size:13px;text-align:center}
  .err.show{display:block}
  .footer{text-align:center;color:#555;font-size:11px;margin-top:28px}
</style></head><body>
  <form class="card" onsubmit="return login(event)">
    <div class="logo">${svg(ICONS.shield, '#fff', 32)}</div>
    <h1>Admin Access</h1>
    <p class="sub">Enter your admin key to continue</p>
    <label>Admin Key</label>
    <div class="input-wrap">
      <span class="input-icon">${svg(ICONS.key, '#666', 18)}</span>
      <input id="key" type="password" placeholder="Enter your admin key" autofocus autocomplete="current-password" required>
    </div>
    <button type="submit" id="btn">${svg(ICONS.shield, '#fff', 16)}<span>Sign In</span></button>
    <div class="err" id="err"></div>
    <div class="footer">Runner Code · Admin Panel</div>
  </form>
<script>
async function login(e){
  e.preventDefault();
  const btn=document.getElementById('btn');const err=document.getElementById('err');
  const key=document.getElementById('key').value.trim();
  if(!key)return;
  btn.disabled=true;btn.querySelector('span').textContent='Signing in…';err.classList.remove('show');
  try{
    const r=await fetch('/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key})});
    const d=await r.json();
    if(r.ok&&d.ok){location.href='/admin/dashboard';}
    else{err.textContent=d.error||'Invalid key';err.classList.add('show');btn.disabled=false;btn.querySelector('span').textContent='Sign In';}
  }catch{err.textContent='Network error';err.classList.add('show');btn.disabled=false;btn.querySelector('span').textContent='Sign In';}
  return false;
}
</script></body></html>`);
});

// ── POST /admin/login ─────────────────────────────────────────────────────────
app.post('/admin/login', (req, res) => {
  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey) return res.status(500).json({ error: 'Admin key not configured' });
  const provided = typeof req.body?.key === 'string' ? req.body.key : '';
  // Constant-time comparison to avoid leaking key length/prefix via timing.
  const a = Buffer.from(provided);
  const b = Buffer.from(adminKey);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Invalid admin key' });
  }
  res.cookie(ADMIN_COOKIE, adminKey, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 12 * 60 * 60 * 1000, // 12h
    path: '/',
  });
  res.json({ ok: true });
});

// ── POST /admin/logout ────────────────────────────────────────────────────────
app.post('/admin/logout', (req, res) => {
  res.clearCookie(ADMIN_COOKIE, { path: '/' });
  res.json({ ok: true });
});

// ── GET /admin/users ──────────────────────────────────────────────────────────
// Legacy: redirect old ?key=... URL to the new dashboard
app.get('/admin/users', (req, res) => {
  if (!isAdminAuthed(req)) return res.redirect('/admin');
  res.redirect('/admin/dashboard');
});

// ── GET /admin/dashboard ──────────────────────────────────────────────────────
app.get('/admin/dashboard', (req, res) => {
  if (!isAdminAuthed(req)) return res.redirect('/admin');
  const users = db.prepare('SELECT id, name, email, country, password_hash, google_id, suspended, created_at FROM users ORDER BY created_at DESC').all();
  const contacts = db.prepare('SELECT id, type, subject, message, user_name, user_email, user_id, status, admin_reply, replied_at, created_at FROM contact_messages ORDER BY created_at DESC').all();
  // Conversations summary for admin
  const allConvs = db.prepare(`
    SELECT c.id, c.user_id, c.title, c.model, c.created_at, c.updated_at,
           u.name AS user_name, u.email AS user_email,
           json_array_length(c.messages) AS message_count
    FROM conversations c
    LEFT JOIN users u ON u.id = c.user_id
    ORDER BY c.updated_at DESC
  `).all();
  const { svg, ICONS } = adminIcons();

  // Stats
  const pendingCount = contacts.filter(c => c.status === 'pending').length;
  const approvedCount = contacts.filter(c => c.status === 'approved').length;
  const rejectedCount = contacts.filter(c => c.status === 'rejected').length;
  const totalDecided = approvedCount + rejectedCount;
  const approvalRate = totalDecided ? Math.round((approvedCount / totalDecided) * 100) : 0;
  const totalContacts = contacts.length;
  const pct = (n) => totalContacts ? Math.round((n / totalContacts) * 100) : 0;

  // Type breakdown
  const typeCounts = {
    bug:        contacts.filter(c => c.type === 'bug').length,
    suggestion: contacts.filter(c => c.type === 'suggestion').length,
    request:    contacts.filter(c => c.type === 'request').length,
    other:      contacts.filter(c => c.type === 'other').length,
  };

  // Auth breakdown
  const hasRealPw = (u) => u.password_hash && u.password_hash !== 'GOOGLE_AUTH' && u.password_hash.startsWith('$2');
  const googleUsers = users.filter(u => u.google_id && !hasRealPw(u)).length;
  const pwOnlyUsers = users.filter(u => !u.google_id && hasRealPw(u)).length;
  const dualUsers   = users.filter(u => u.google_id && hasRealPw(u)).length;
  const googleTotal = users.filter(u => u.google_id).length;
  const suspendedCount = users.filter(u => u.suspended).length;
  const totalConvs = allConvs.length;
  const totalMsgsInConvs = allConvs.reduce((s, c) => s + (c.message_count || 0), 0);
  const repliedCount = contacts.filter(c => c.admin_reply && c.admin_reply.trim()).length;
  const unrepliedCount = totalContacts - repliedCount;

  // Country distribution (top 8)
  const countryMap = {};
  users.forEach(u => { const c = u.country || 'Unknown'; countryMap[c] = (countryMap[c] || 0) + 1; });
  const topCountries = Object.entries(countryMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  // AI Model usage
  const modelMap = {};
  allConvs.forEach(c => { const m = (c.model || '').split('/').pop() || 'Unknown'; modelMap[m] = (modelMap[m] || 0) + 1; });
  const topModels = Object.entries(modelMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  // Top active users (by conversations)
  const userConvMap = {};
  allConvs.forEach(c => { if (c.user_id) userConvMap[c.user_id] = (userConvMap[c.user_id] || 0) + 1; });
  const topActiveUsers = Object.entries(userConvMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([uid, count]) => {
      const u = users.find(u => u.id === Number(uid));
      return { name: u?.name || 'Unknown', email: u?.email || '—', count, msgs: allConvs.filter(c => c.user_id === Number(uid)).reduce((s, c) => s + (c.message_count || 0), 0) };
    });

  // DB file size
  let dbSizeStr = '—';
  try { const fs = require('fs'); const sz = fs.statSync(db.name).size; dbSizeStr = sz < 1048576 ? (sz / 1024).toFixed(1) + ' KB' : (sz / 1048576).toFixed(1) + ' MB'; } catch {}

  // Feedback / Reactions data
  const allReactions = db.prepare(`
    SELECT r.user_id, r.message_id, r.conversation_id, r.reaction,
           u.name AS user_name, u.email AS user_email,
           c.title AS conv_title
    FROM reactions r
    LEFT JOIN users u ON u.id = r.user_id
    LEFT JOIN conversations c ON c.id = r.conversation_id
    ORDER BY r.rowid DESC
  `).all();
  const totalReactions = allReactions.length;
  const thumbsUp = allReactions.filter(r => r.reaction === 'up').length;
  const thumbsDown = allReactions.filter(r => r.reaction === 'down').length;
  const satisfactionRate = totalReactions ? Math.round((thumbsUp / totalReactions) * 100) : 0;

  // Top feedback users
  const feedbackUserMap = {};
  allReactions.forEach(r => {
    if (!feedbackUserMap[r.user_id]) feedbackUserMap[r.user_id] = { name: r.user_name || 'Unknown', email: r.user_email || '—', up: 0, down: 0, total: 0 };
    feedbackUserMap[r.user_id][r.reaction === 'up' ? 'up' : 'down']++;
    feedbackUserMap[r.user_id].total++;
  });
  const topFeedbackUsers = Object.values(feedbackUserMap).sort((a, b) => b.total - a.total).slice(0, 8);

  // Feedback by conversation (top 10)
  const feedbackConvMap = {};
  allReactions.forEach(r => {
    const key = r.conversation_id;
    if (!feedbackConvMap[key]) feedbackConvMap[key] = { title: r.conv_title || 'Untitled', up: 0, down: 0, total: 0 };
    feedbackConvMap[key][r.reaction === 'up' ? 'up' : 'down']++;
    feedbackConvMap[key].total++;
  });
  const topFeedbackConvs = Object.entries(feedbackConvMap).sort((a, b) => b[1].total - a[1].total).slice(0, 10);

  // Recent feedback (last 15)
  const recentFeedback = allReactions.slice(0, 15);

  // Recent activity
  const recentContacts = [...contacts]
    .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime())
    .slice(0, 5);

  // Users in last 7 days
  const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const newUsers7d = users.filter(u => {
    const t = new Date(u.created_at || 0).getTime();
    return t && t >= weekAgo;
  }).length;
  const msgs7d = contacts.filter(c => {
    const t = new Date(c.created_at || 0).getTime();
    return t && t >= weekAgo;
  }).length;

  // Helpers
  const typeIcon = {
    bug:        svg(ICONS.bug,       '#ef4444'),
    suggestion: svg(ICONS.lightbulb, '#eab308'),
    request:    svg(ICONS.wrench,    '#3b82f6'),
    other:      svg(ICONS.message,   '#94a3b8'),
  };
  const typeColorDot = { bug: '#ef4444', suggestion: '#eab308', request: '#3b82f6', other: '#94a3b8' };
  const statusPill = (status) => {
    const map = {
      pending:  { bg: '#f59e0b22', c: '#f59e0b', ic: svg(ICONS.clock, '#f59e0b', 11), lbl: 'Pending' },
      approved: { bg: '#22c55e22', c: '#22c55e', ic: svg(ICONS.check, '#22c55e', 11), lbl: 'Approved' },
      rejected: { bg: '#ef444422', c: '#ef4444', ic: svg(ICONS.x,     '#ef4444', 11), lbl: 'Rejected' },
    }[status] || { bg: '#2a2a2a', c: '#888', ic: '', lbl: status };
    return `<span class="pill" style="background:${map.bg};color:${map.c};border:1px solid ${map.c}44;">${map.ic}${map.lbl}</span>`;
  };

  // Group messages by user (using user_id, fallback to email)
  const userMap = new Map(users.map(u => [u.id, u]));
  const emailMap = new Map(users.map(u => [u.email.toLowerCase(), u]));
  const groupedByUser = new Map();  // key -> { user, messages[] }
  for (const c of contacts) {
    const u = (c.user_id && userMap.get(c.user_id)) || emailMap.get((c.user_email || '').toLowerCase()) || null;
    const key = u ? `uid-${u.id}` : `email-${(c.user_email || 'unknown').toLowerCase()}`;
    if (!groupedByUser.has(key)) {
      groupedByUser.set(key, {
        user: u,
        fallbackName: c.user_name,
        fallbackEmail: c.user_email,
        messages: [],
      });
    }
    groupedByUser.get(key).messages.push(c);
  }
  // Sort: most recent activity first
  const userGroups = [...groupedByUser.values()].sort((a, b) => {
    const ta = Math.max(...a.messages.map(m => new Date(m.created_at).getTime() || 0));
    const tb = Math.max(...b.messages.map(m => new Date(m.created_at).getTime() || 0));
    return tb - ta;
  });

  // Orphan messages: user_id missing AND email doesn't match any existing user
  const userEmails = new Set(users.map(u => u.email.toLowerCase()));
  const orphanCount = contacts.filter(c => {
    const hasUser = c.user_id && userMap.has(c.user_id);
    const hasEmail = c.user_email && userEmails.has(c.user_email.toLowerCase());
    return !hasUser && !hasEmail;
  }).length;

  // Build user cards
  const userCards = userGroups.map(g => {
    const name = g.user ? g.user.name : g.fallbackName;
    const email = g.user ? g.user.email : g.fallbackEmail;
    const country = g.user?.country || null;
    const initials = String(name || '?').trim().split(/\s+/).map(p => p[0]).slice(0, 2).join('').toUpperCase() || '?';
    const pending = g.messages.filter(m => m.status === 'pending').length;
    const approved = g.messages.filter(m => m.status === 'approved').length;
    const rejected = g.messages.filter(m => m.status === 'rejected').length;
    const groupId = g.user ? `u${g.user.id}` : `e${encodeURIComponent(email)}`;

    const msgItems = g.messages.map(c => {
      const locked = c.status !== 'pending';
      const hasReply = c.admin_reply && c.admin_reply.trim();
      return `
      <div class="msg-item" id="crow-${c.id}" data-status="${escapeHtml(c.status)}" data-user="${escapeHtml(g.messages[0]?.user_name || name || '')}" data-email="${escapeHtml(g.messages[0]?.user_email || email || '')}">
        <div class="msg-top">
          <span class="type-dot" style="background:${typeColorDot[c.type] || '#94a3b8'}"></span>
          <span class="type-label msg-type">${typeIcon[c.type] || typeIcon.other}${escapeHtml(c.type)}</span>
          <span class="msg-date">${escapeHtml(c.created_at || '')}</span>
          <span id="cstatus-${c.id}" class="msg-status">${statusPill(c.status)}</span>
        </div>
        <div class="msg-subject">${escapeHtml(c.subject)}</div>
        <div class="msg-body">${escapeHtml(c.message)}</div>
        ${hasReply ? `
        <div class="admin-reply-box">
          <div class="admin-reply-head">${svg(ICONS.reply, '#8b5cf6', 12)}<span>Admin reply</span><span class="admin-reply-date">${escapeHtml(c.replied_at || '')}</span></div>
          <div class="admin-reply-text reply-text">${escapeHtml(c.admin_reply)}</div>
        </div>` : ''}
        <div class="msg-actions" id="cactions-${c.id}">
          ${locked
            ? `<span class="locked">${svg(ICONS.shield, '#555', 12)} Decision locked</span>
               <button class="btn btn-reply" onclick="toggleReplyBox(${c.id})">${svg(ICONS.reply, '#fff', 13)}${hasReply ? 'Edit reply' : 'Reply'}</button>`
            : `<button class="btn btn-reply" onclick="toggleReplyBox(${c.id})">${svg(ICONS.reply, '#fff', 13)}${hasReply ? 'Edit reply' : 'Reply'}</button>
               <span class="reply-hint">${svg(ICONS.shield, '#f59e0b', 12)} Reply will be sent together with Approve or Reject</span>`
          }
        </div>
        <div class="reply-form" id="replyForm-${c.id}" style="display:none">
          <textarea id="replyText-${c.id}" class="reply-textarea" placeholder="Write your reply to the user…" rows="3">${hasReply ? escapeHtml(c.admin_reply) : ''}</textarea>
          <div class="reply-form-actions">
            <button class="btn btn-sm" onclick="document.getElementById('replyForm-${c.id}').style.display='none'">Cancel</button>
            <button class="btn btn-sm btn-send" onclick="sendReply(${c.id})">${svg(ICONS.send, '#fff', 12)}Send reply</button>
          </div>
        </div>
      </div>`;
    }).join('');

    return `
    <div class="user-card" data-search="${escapeHtml((name + ' ' + email).toLowerCase())}">
      <div class="user-header" onclick="toggleUser('${groupId}')">
        <div class="avatar">${escapeHtml(initials)}</div>
        <div class="user-meta">
          <div class="user-name">${escapeHtml(name || 'Unknown')}${g.user ? '' : ' <span class="orphan">· deleted account</span>'}</div>
          <div class="user-email">${escapeHtml(email || '—')}${country ? ` · ${escapeHtml(country)}` : ''}</div>
        </div>
        <div class="user-counts">
          ${pending  ? `<span class="count count-pending">${svg(ICONS.clock, '#f59e0b', 11)}${pending}</span>` : ''}
          ${approved ? `<span class="count count-approved">${svg(ICONS.check, '#22c55e', 11)}${approved}</span>` : ''}
          ${rejected ? `<span class="count count-rejected">${svg(ICONS.x,     '#ef4444', 11)}${rejected}</span>` : ''}
          <span class="total">${g.messages.length} ${g.messages.length === 1 ? 'message' : 'messages'}</span>
        </div>
        <span class="chevron" id="chev-${groupId}">▾</span>
      </div>
      <div class="user-body" id="body-${groupId}">${msgItems}</div>
    </div>`;
  }).join('');

  // User list (all users)
  const userRows = users.map(u => {
    const hasRealPassword = u.password_hash && u.password_hash !== 'GOOGLE_AUTH' && u.password_hash.startsWith('$2');
    let authBadge;
    if (u.google_id && hasRealPassword) authBadge = `<span class="auth-pill auth-dual">${svg(ICONS.google, '#4285F4', 11)}+${svg(ICONS.key, '#eab308', 11)}</span>`;
    else if (u.google_id)              authBadge = `<span class="auth-pill auth-google">${svg(ICONS.google, '#4285F4', 11)}Google</span>`;
    else if (hasRealPassword)          authBadge = `<span class="auth-pill auth-pw">${svg(ICONS.key, '#eab308', 11)}Password</span>`;
    else                               authBadge = `<span class="auth-pill auth-none">${svg(ICONS.alert, '#f59e0b', 11)}None</span>`;
    const initials = String(u.name || '?').trim().split(/\s+/).map(p => p[0]).slice(0, 2).join('').toUpperCase() || '?';
    const userConvCount = allConvs.filter(c => c.user_id === u.id).length;
    return `
    <div class="user-row ${u.suspended ? 'user-suspended' : ''}" data-search="${escapeHtml((u.name + ' ' + u.email).toLowerCase())}">
      <div class="avatar avatar-sm">${escapeHtml(initials)}</div>
      <div class="urow-meta">
        <div class="urow-name">${escapeHtml(u.name)}${u.suspended ? ` <span class="suspend-badge">${svg(ICONS.lock, '#ef4444', 10)} Suspended</span>` : ''}</div>
        <div class="urow-email">${escapeHtml(u.email)}</div>
      </div>
      <div class="urow-info">
        <span class="info-item urow-country">${svg(ICONS.globe, '#666', 12)}${escapeHtml(u.country || '—')}</span>
        <span class="info-item">${svg(ICONS.msgCircle, '#666', 12)}${userConvCount} chats</span>
        <span class="info-item urow-date">${svg(ICONS.calendar, '#666', 12)}${escapeHtml(u.created_at || '—')}</span>
        <span class="urow-auth" style="display:none">${u.google_id && hasRealPassword ? 'Google+Password' : u.google_id ? 'Google' : hasRealPassword ? 'Password' : 'None'}</span>
        ${u.suspended ? '<span class="urow-suspended" style="display:none">1</span>' : ''}
        ${authBadge}
      </div>
      <div class="urow-actions">
        <button class="btn-icon ${u.suspended ? 'btn-unsuspend' : 'btn-suspend'}" onclick="toggleSuspend(${u.id}, '${escapeHtml(u.name).replace(/'/g,"\\'")}', ${u.suspended ? 'true' : 'false'})" title="${u.suspended ? 'Unsuspend' : 'Suspend'} user">
          ${u.suspended ? svg(ICONS.unlock, '#22c55e', 15) : svg(ICONS.lock, '#f59e0b', 15)}
        </button>
        <button class="btn-icon btn-danger" onclick="deleteUser(${u.id}, '${escapeHtml(u.name).replace(/'/g,"\\'")}', '${escapeHtml(u.email).replace(/'/g,"\\'")}')" title="Delete user">
          ${svg(ICONS.trash, '#ef4444', 15)}
        </button>
      </div>
    </div>`;
  }).join('');

  res.send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Dashboard · Runner Code</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  :root{--bg:#0a0a0a;--card:#141414;--card2:#1a1a1a;--border:#262626;--border-soft:#1f1f1f;--text:#e5e5e5;--muted:#888;--muted2:#555;--primary:#E31E24;--radius:16px}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;font-size:14px;line-height:1.5}
  .layout{display:grid;grid-template-columns:260px 1fr;min-height:100vh}
  /* Sidebar */
  .sidebar{background:#0d0d0d;border-right:1px solid var(--border);padding:24px 16px;display:flex;flex-direction:column;position:sticky;top:0;height:100vh}
  .brand{display:flex;align-items:center;gap:10px;padding:8px 12px 24px;border-bottom:1px solid var(--border-soft);margin-bottom:20px}
  .brand-logo{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,var(--primary),#8b1217);display:flex;align-items:center;justify-content:center}
  .brand-title{font-weight:800;font-size:14px;letter-spacing:-.2px}
  .brand-sub{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:2px;margin-top:2px}
  .nav{display:flex;flex-direction:column;gap:4px;flex:1}
  .nav-item{display:flex;align-items:center;gap:12px;padding:11px 12px;border-radius:10px;color:var(--muted);cursor:pointer;font-weight:600;font-size:13px;transition:all .15s;border:none;background:transparent;width:100%;text-align:left;font-family:inherit}
  .nav-item:hover{background:#1a1a1a;color:var(--text)}
  .nav-item.active{background:rgba(227,30,36,.1);color:var(--primary)}
  .nav-badge{margin-left:auto;background:#262626;color:var(--muted);padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700}
  .nav-item.active .nav-badge{background:rgba(227,30,36,.2);color:var(--primary)}
  .logout-btn{display:flex;align-items:center;gap:10px;padding:11px 12px;border-radius:10px;color:var(--muted);cursor:pointer;font-weight:600;font-size:13px;border:1px solid var(--border);background:transparent;font-family:inherit;transition:all .15s}
  .logout-btn:hover{background:#ef444418;border-color:#ef444440;color:#ef4444}
  /* Main */
  .main{padding:32px 40px;max-width:1400px}
  .page-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;gap:20px}
  .page-title{font-size:24px;font-weight:800;letter-spacing:-.5px}
  .page-sub{color:var(--muted);font-size:13px;margin-top:3px}
  .search-wrap{position:relative;width:280px}
  .search-icon{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--muted2)}
  .search-input{width:100%;padding:10px 12px 10px 38px;background:var(--card);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:13px;outline:none;font-family:inherit;transition:all .15s}
  .search-input:focus{border-color:var(--primary);background:var(--card2)}
  /* Stats */
  .stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:14px;margin-bottom:28px}
  .stat{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px}
  .stat-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1.5px;font-weight:700;margin-bottom:8px;display:flex;align-items:center;gap:8px}
  .stat-value{font-size:28px;font-weight:800;letter-spacing:-.8px}
  .stat-foot{font-size:11px;color:var(--muted2);margin-top:4px}
  .stat.s-pending .stat-value{color:#f59e0b}
  .stat.s-approved .stat-value{color:#22c55e}
  .stat.s-rejected .stat-value{color:#ef4444}
  .stat.s-users .stat-value{color:var(--primary)}
  .stat{transition:transform .15s ease, border-color .15s}
  .stat:hover{transform:translateY(-2px);border-color:#333}
  /* === Overview redesign === */
  /* Hero */
  .hero{position:relative;background:linear-gradient(135deg,#18181b 0%,#0f0f10 100%);border:1px solid var(--border);border-radius:20px;padding:32px;margin-bottom:24px;overflow:hidden;display:grid;grid-template-columns:1fr 280px;gap:32px;align-items:center}
  .hero-bg{position:absolute;inset:0;background:radial-gradient(circle at 85% 30%, rgba(227,30,36,.16) 0%, transparent 45%), radial-gradient(circle at 10% 100%, rgba(59,130,246,.08) 0%, transparent 40%);pointer-events:none}
  .hero-content{position:relative;z-index:1}
  .hero-badge{display:inline-flex;align-items:center;gap:7px;background:rgba(34,197,94,.1);color:#22c55e;font-size:11px;font-weight:700;padding:5px 12px;border-radius:12px;border:1px solid rgba(34,197,94,.25);text-transform:uppercase;letter-spacing:1px}
  .live-dot{width:6px;height:6px;border-radius:50%;background:#22c55e;box-shadow:0 0 0 0 rgba(34,197,94,.7);animation:pulse 2s infinite}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(34,197,94,.7)}70%{box-shadow:0 0 0 8px rgba(34,197,94,0)}100%{box-shadow:0 0 0 0 rgba(34,197,94,0)}}
  .hero-title{font-size:30px;font-weight:800;letter-spacing:-1px;margin:14px 0 6px;background:linear-gradient(135deg,#fff,#999);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
  .hero-sub{color:var(--muted);font-size:14px;margin-bottom:18px}
  .hero-meta{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:12px;flex-wrap:wrap}
  .hero-meta-item{display:inline-flex;align-items:center;gap:6px}
  .hero-meta-dot{width:3px;height:3px;border-radius:50%;background:var(--muted2)}
  .hero-kpi{position:relative;z-index:1;background:rgba(0,0,0,.35);border:1px solid var(--border-soft);border-radius:16px;padding:20px;backdrop-filter:blur(10px)}
  .kpi-label{color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px}
  .kpi-value{font-size:42px;font-weight:800;letter-spacing:-1.5px;margin-top:4px;background:linear-gradient(135deg,#22c55e,#4ade80);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
  .kpi-value span{font-size:20px;margin-left:2px}
  .kpi-bar{height:6px;background:rgba(255,255,255,.06);border-radius:6px;margin-top:10px;overflow:hidden}
  .kpi-bar-fill{height:100%;background:linear-gradient(90deg,#22c55e,#4ade80);border-radius:6px;transition:width .6s cubic-bezier(.2,.8,.2,1)}
  .kpi-foot{color:var(--muted2);font-size:11px;margin-top:8px}
  /* Stat grid */
  .stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:14px;margin-bottom:24px}
  .stat-card{position:relative;background:var(--card);border:1px solid var(--border);border-radius:16px;padding:18px;overflow:hidden;transition:transform .15s,border-color .15s}
  .stat-card:hover{transform:translateY(-3px);border-color:#333}
  .stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:16px 16px 0 0}
  .sc-users::before{background:linear-gradient(90deg,#E31E24,#8b1217)}
  .sc-msgs::before{background:linear-gradient(90deg,#8b5cf6,#6d28d9)}
  .sc-pending::before{background:linear-gradient(90deg,#f59e0b,#b45309)}
  .sc-approved::before{background:linear-gradient(90deg,#22c55e,#15803d)}
  .sc-rejected::before{background:linear-gradient(90deg,#ef4444,#b91c1c)}
  .sc-convs::before{background:linear-gradient(90deg,#06b6d4,#0891b2)}
  .sc-convs .sc-icon{background:linear-gradient(135deg,#06b6d4,#0891b2)}
  .sc-icon{width:40px;height:40px;border-radius:12px;display:flex;align-items:center;justify-content:center;margin-bottom:14px}
  .sc-users .sc-icon{background:linear-gradient(135deg,#E31E24,#8b1217)}
  .sc-msgs .sc-icon{background:linear-gradient(135deg,#8b5cf6,#6d28d9)}
  .sc-pending .sc-icon{background:linear-gradient(135deg,#f59e0b,#b45309)}
  .sc-approved .sc-icon{background:linear-gradient(135deg,#22c55e,#15803d)}
  .sc-rejected .sc-icon{background:linear-gradient(135deg,#ef4444,#b91c1c)}
  .sc-label{color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px}
  .sc-value{font-size:30px;font-weight:800;letter-spacing:-1px;margin-top:4px;color:var(--text)}
  .sc-delta{font-size:11px;font-weight:700;margin-top:8px;display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:8px}
  .sc-delta.up{color:#22c55e;background:rgba(34,197,94,.1)}
  .sc-delta.down{color:#ef4444;background:rgba(239,68,68,.1)}
  .sc-delta.neutral{color:var(--muted);background:rgba(255,255,255,.04)}
  /* Two-column grid */
  .grid-two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:24px}
  /* Panel */
  .panel{background:var(--card);border:1px solid var(--border);border-radius:16px;overflow:hidden}
  .panel-head{display:flex;align-items:center;justify-content:space-between;padding:18px 20px;border-bottom:1px solid var(--border-soft)}
  .panel-title{font-size:14px;font-weight:700;color:var(--text)}
  .panel-sub{font-size:11px;color:var(--muted);margin-top:2px}
  .panel-ico{opacity:.5}
  .panel-action{display:inline-flex;align-items:center;gap:6px;background:transparent;border:1px solid var(--border);color:var(--muted);font-size:12px;font-weight:700;padding:6px 12px;border-radius:8px;cursor:pointer;font-family:inherit;transition:all .15s}
  .panel-action:hover{border-color:var(--primary);color:var(--primary)}
  .panel-body{padding:16px 20px}
  .panel-note{color:var(--muted2);font-size:11px;margin-top:10px;padding-top:10px;border-top:1px dashed var(--border-soft);font-style:italic}
  /* Breakdown rows */
  .bd-row{display:grid;grid-template-columns:140px 1fr auto;gap:12px;align-items:center;padding:10px 0}
  .bd-row + .bd-row{border-top:1px solid var(--border-soft)}
  .bd-label{display:inline-flex;align-items:center;gap:8px;font-size:12px;font-weight:600;color:var(--text)}
  .bd-bar{height:8px;background:rgba(255,255,255,.04);border-radius:8px;overflow:hidden}
  .bd-fill{height:100%;border-radius:8px;transition:width .6s cubic-bezier(.2,.8,.2,1)}
  .bd-val{font-size:13px;font-weight:700;color:var(--text);min-width:60px;text-align:right}
  .bd-pct{color:var(--muted);font-weight:600;font-size:11px;margin-left:6px}
  /* Activity */
  .act-row{display:flex;align-items:center;gap:12px;padding:12px 0}
  .act-row + .act-row{border-top:1px solid var(--border-soft)}
  .act-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
  .act-main{flex:1;min-width:0}
  .act-title{font-size:13px;font-weight:700;color:var(--text);display:inline-flex;align-items:center;gap:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
  .act-title span{overflow:hidden;text-overflow:ellipsis}
  .act-meta{color:var(--muted);font-size:11px;margin-top:2px}
  .act-side{display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex-shrink:0}
  .act-time{color:var(--muted2);font-size:10px}
  .empty-inline{text-align:center;padding:28px;color:var(--muted2);font-size:12px}
  .empty-inline p{margin-top:8px}
  @media(max-width:1100px){
    .hero{grid-template-columns:1fr;padding:24px}
    .hero-kpi{max-width:320px}
    .grid-two{grid-template-columns:1fr}
  }
  /* Sections */
  .section{display:none}
  .section.active{display:block;animation:fadeIn .25s ease}
  @keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
  /* User card (messages grouped) */
  .user-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:12px;overflow:hidden;transition:border-color .15s}
  .user-card:hover{border-color:#333}
  .user-header{display:flex;align-items:center;gap:14px;padding:16px 20px;cursor:pointer;user-select:none}
  .user-header:hover{background:rgba(255,255,255,.02)}
  .avatar{width:42px;height:42px;border-radius:50%;background:linear-gradient(135deg,var(--primary),#8b1217);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:14px;letter-spacing:.5px;flex-shrink:0}
  .avatar-sm{width:36px;height:36px;font-size:12px}
  .user-meta{flex:1;min-width:0}
  .user-name{font-weight:700;font-size:14px}
  .user-name .orphan{color:var(--muted2);font-weight:400;font-size:11px;font-style:italic}
  .user-email{color:var(--muted);font-size:12px;margin-top:2px}
  .user-counts{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
  .count{display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:700;padding:3px 8px;border-radius:10px}
  .count-pending{background:#f59e0b22;color:#f59e0b}
  .count-approved{background:#22c55e22;color:#22c55e}
  .count-rejected{background:#ef444422;color:#ef4444}
  .total{color:var(--muted);font-size:11px;font-weight:600}
  .chevron{color:var(--muted2);font-size:14px;transition:transform .2s;margin-left:4px}
  .user-card.open .chevron{transform:rotate(180deg)}
  .user-body{display:none;padding:4px 20px 20px;border-top:1px solid var(--border-soft)}
  .user-card.open .user-body{display:block}
  /* Message item */
  .msg-item{background:#0f0f0f;border:1px solid var(--border-soft);border-radius:12px;padding:14px 16px;margin-top:12px}
  .msg-top{display:flex;align-items:center;gap:10px;font-size:11px;color:var(--muted);margin-bottom:8px;flex-wrap:wrap}
  .type-dot{width:6px;height:6px;border-radius:50%}
  .type-label{display:inline-flex;align-items:center;gap:5px;font-weight:700;text-transform:capitalize;color:var(--text);font-size:11px}
  .msg-date{margin-left:auto;color:var(--muted2);font-size:11px}
  .msg-subject{font-weight:700;font-size:14px;margin-bottom:6px;color:var(--text)}
  .msg-body{color:#bbb;font-size:13px;white-space:pre-wrap;word-break:break-word;line-height:1.55;padding:10px 12px;background:#0a0a0a;border-radius:8px;border:1px solid var(--border-soft);margin-bottom:10px}
  .msg-actions{display:flex;gap:8px;align-items:center}
  .pill{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:12px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
  .btn{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border:none;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;transition:all .15s;font-family:inherit}
  .btn-approve{background:#22c55e;color:#fff}
  .btn-approve:hover{background:#16a34a}
  .btn-reject{background:#ef4444;color:#fff}
  .btn-reject:hover{background:#dc2626}
  .locked{display:inline-flex;align-items:center;gap:6px;color:var(--muted2);font-size:11px;font-style:italic;padding:7px 2px}
  /* User row (Users tab) */
  .user-row{display:flex;align-items:center;gap:14px;padding:14px 18px;background:var(--card);border:1px solid var(--border);border-radius:12px;margin-bottom:8px;transition:all .15s}
  .user-row:hover{border-color:#333;background:var(--card2)}
  .urow-meta{flex:1;min-width:0}
  .urow-name{font-weight:700;font-size:13px}
  .urow-email{color:var(--muted);font-size:12px;margin-top:2px}
  .urow-info{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
  .info-item{display:inline-flex;align-items:center;gap:5px;color:var(--muted);font-size:11px}
  .auth-pill{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:10px;font-size:10px;font-weight:700;border:1px solid}
  .auth-google{background:#4285F418;color:#4285F4;border-color:#4285F440}
  .auth-pw{background:#eab30818;color:#eab308;border-color:#eab30840}
  .auth-dual{background:#22c55e18;color:#22c55e;border-color:#22c55e40}
  .auth-none{background:#f59e0b18;color:#f59e0b;border-color:#f59e0b40}
  .btn-icon{width:34px;height:34px;border-radius:8px;border:1px solid var(--border);background:transparent;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s}
  .btn-icon:hover{background:var(--card2)}
  .btn-danger:hover{background:#ef444418;border-color:#ef444440}
  .btn-suspend:hover{background:#f59e0b18;border-color:#f59e0b40}
  .btn-unsuspend:hover{background:#22c55e18;border-color:#22c55e40}
  .urow-actions{display:flex;gap:6px;flex-shrink:0}
  .user-suspended{opacity:.65;border-color:#ef444440}
  .user-suspended .avatar{background:linear-gradient(135deg,#555,#333)}
  .suspend-badge{display:inline-flex;align-items:center;gap:3px;font-size:9px;font-weight:700;color:#ef4444;text-transform:uppercase;letter-spacing:.5px;margin-left:4px;padding:1px 6px;background:#ef444412;border:1px solid #ef444430;border-radius:6px}
  /* Admin reply */
  .admin-reply-box{background:linear-gradient(135deg,#8b5cf612,#8b5cf606);border:1px solid #8b5cf630;border-radius:10px;padding:12px 14px;margin-bottom:10px}
  .admin-reply-head{display:flex;align-items:center;gap:6px;font-size:10px;font-weight:700;color:#8b5cf6;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
  .admin-reply-date{margin-left:auto;color:var(--muted2);font-weight:400;text-transform:none;letter-spacing:0}
  .admin-reply-text{color:#c4b5fd;font-size:12.5px;line-height:1.55;white-space:pre-wrap;word-break:break-word}
  /* Reply form */
  .reply-hint{display:inline-flex;align-items:center;gap:6px;color:#f59e0b;font-size:11px;font-weight:600;font-style:italic;padding:7px 2px}
  .reply-form{margin-top:10px;padding-top:10px;border-top:1px dashed var(--border-soft)}
  .reply-textarea{width:100%;padding:10px 12px;background:#0a0a0a;border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:13px;outline:none;font-family:inherit;resize:vertical;transition:border-color .15s;min-height:70px}
  .reply-textarea:focus{border-color:#8b5cf6}
  .reply-form-actions{display:flex;gap:8px;margin-top:8px;justify-content:flex-end}
  .btn-sm{padding:6px 12px;font-size:11px;border-radius:8px}
  .btn-reply{background:#8b5cf6;color:#fff}
  .btn-reply:hover{background:#7c3aed}
  .btn-send{background:linear-gradient(135deg,#8b5cf6,#6d28d9);color:#fff}
  .btn-send:hover{background:linear-gradient(135deg,#7c3aed,#5b21b6)}
  /* Conversation rows */
  .conv-row{display:flex;align-items:center;gap:14px;padding:14px 18px;background:var(--card);border:1px solid var(--border);border-radius:12px;margin-bottom:8px;transition:all .15s}
  .conv-row:hover{border-color:#333;background:var(--card2)}
  .conv-main{flex:1;min-width:0}
  .conv-title{font-weight:700;font-size:13px;display:inline-flex;align-items:center;gap:6px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}
  .conv-title span{overflow:hidden;text-overflow:ellipsis}
  .conv-meta{color:var(--muted);font-size:11px;margin-top:2px}
  .conv-info{display:flex;gap:12px;align-items:center;flex-wrap:wrap;flex-shrink:0}
  .conv-model{padding:2px 8px;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.25);border-radius:6px;color:#a78bfa;font-size:10px;font-weight:700}
  /* Quick actions */
  .quick-actions{display:flex;gap:10px;margin-bottom:24px;flex-wrap:wrap}
  .qa-btn{display:inline-flex;align-items:center;gap:8px;padding:10px 16px;background:var(--card);border:1px solid var(--border);border-radius:12px;color:var(--text);font-size:12px;font-weight:700;cursor:pointer;font-family:inherit;transition:all .15s}
  .qa-btn:hover{border-color:var(--primary);color:var(--primary);background:rgba(227,30,36,.05);transform:translateY(-1px)}
  .qa-count{background:#262626;color:var(--muted);padding:2px 7px;border-radius:8px;font-size:10px;font-weight:700;margin-left:2px}
  .qa-btn:hover .qa-count{background:rgba(227,30,36,.15);color:var(--primary)}
  /* Refresh button (inline with hero badge) */
  .hero-top{display:flex;align-items:center;justify-content:space-between;gap:12px}
  .refresh-btn{display:inline-flex;align-items:center;gap:6px;padding:5px 14px;background:rgba(255,255,255,.05);border:1px solid var(--border);border-radius:12px;color:var(--muted);font-size:11px;font-weight:700;cursor:pointer;font-family:inherit;transition:all .2s;letter-spacing:.3px}
  .refresh-btn:hover{border-color:var(--primary);color:#fff;background:rgba(227,30,36,.12);transform:translateY(-1px);box-shadow:0 4px 16px rgba(227,30,36,.15)}
  .refresh-btn:active{transform:scale(.97)}
  .refresh-btn .r-icon{display:inline-flex;transition:transform .3s}
  .refresh-btn.spinning .r-icon{animation:spin .6s linear infinite}
  @keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
  /* Top users */
  .top-user-row{display:flex;align-items:center;gap:10px;padding:10px 0}
  .top-user-row + .top-user-row{border-top:1px solid var(--border-soft)}
  .top-rank{color:var(--muted2);font-size:12px;font-weight:800;width:24px;text-align:center;flex-shrink:0}
  .top-meta{flex:1;min-width:0}
  .top-name{font-size:13px;font-weight:700;color:var(--text)}
  .top-email{font-size:11px;color:var(--muted);margin-top:1px}
  .top-stats{display:flex;gap:8px;flex-shrink:0}
  .top-stat{display:inline-flex;align-items:center;gap:4px;font-size:10px;font-weight:700;color:var(--muted);padding:2px 6px;border-radius:6px;background:rgba(255,255,255,.03)}
  /* System info */
  .sys-grid{display:grid;grid-template-columns:1fr 1fr;gap:0}
  .sys-item{padding:12px 0;border-bottom:1px solid var(--border-soft);display:flex;justify-content:space-between;align-items:center}
  .sys-item:nth-child(odd){padding-right:16px;border-right:1px solid var(--border-soft)}
  .sys-item:nth-child(even){padding-left:16px}
  .sys-item:nth-last-child(-n+2){border-bottom:none}
  .sys-label{display:inline-flex;align-items:center;gap:6px;color:var(--muted);font-size:11px;font-weight:600}
  .sys-value{font-size:14px;font-weight:800;color:var(--text)}
  /* Feedback section */
  .sc-feedback::before{background:linear-gradient(90deg,#f59e0b,#d97706)}
  .sc-feedback .sc-icon{background:linear-gradient(135deg,#f59e0b,#d97706)}
  .fb-hero{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:28px;margin-bottom:24px;display:grid;grid-template-columns:1fr 1fr;gap:28px;align-items:center}
  .fb-hero-main{text-align:center}
  .fb-rate{font-size:64px;font-weight:900;letter-spacing:-2px;background:linear-gradient(135deg,#22c55e,#4ade80);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
  .fb-rate span{font-size:28px;margin-left:2px}
  .fb-rate-label{color:var(--muted);font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;margin-top:4px}
  .fb-rate-bar{height:8px;background:rgba(255,255,255,.06);border-radius:8px;margin-top:14px;overflow:hidden;max-width:260px;margin-left:auto;margin-right:auto}
  .fb-rate-fill{height:100%;border-radius:8px;transition:width .6s cubic-bezier(.2,.8,.2,1)}
  .fb-summary{display:flex;gap:16px;justify-content:center;flex-wrap:wrap}
  .fb-stat{display:flex;align-items:center;gap:12px;padding:14px 18px;background:#0f0f0f;border:1px solid var(--border-soft);border-radius:14px;min-width:130px}
  .fb-stat-icon{width:40px;height:40px;border-radius:12px;display:flex;align-items:center;justify-content:center}
  .fb-up{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.25)}
  .fb-down{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.25)}
  .fb-total{background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.25)}
  .fb-stat-val{font-size:22px;font-weight:800;letter-spacing:-.5px;color:var(--text)}
  .fb-stat-lbl{font-size:11px;color:var(--muted);font-weight:600;margin-top:1px}
  .fb-user-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;gap:12px}
  .fb-user-row + .fb-user-row{border-top:1px solid var(--border-soft)}
  .fb-user-info{flex:1;min-width:0}
  .fb-user-name{font-size:13px;font-weight:700;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .fb-user-email{font-size:11px;color:var(--muted);margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .fb-user-reactions{display:flex;gap:6px;flex-shrink:0}
  .fb-pill{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:8px;font-size:11px;font-weight:700}
  .fb-pill-up{background:rgba(34,197,94,.1);color:#22c55e}
  .fb-pill-down{background:rgba(239,68,68,.1);color:#ef4444}
  .fb-pill-pct{background:rgba(255,255,255,.04);font-weight:800;font-size:10px}
  .fb-conv-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;gap:12px}
  .fb-conv-row + .fb-conv-row{border-top:1px solid var(--border-soft)}
  .fb-conv-title{flex:1;min-width:0;display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .fb-conv-title span{overflow:hidden;text-overflow:ellipsis}
  .fb-conv-stats{display:flex;gap:6px;flex-shrink:0}
  .fb-recent-row{display:flex;align-items:center;gap:12px;padding:10px 0}
  .fb-recent-row + .fb-recent-row{border-top:1px solid var(--border-soft)}
  .fb-react-icon{width:32px;height:32px;border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
  .fb-react-up{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.2)}
  .fb-react-down{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2)}
  .fb-recent-info{flex:1;min-width:0}
  .fb-recent-user{font-size:13px;font-weight:700;color:var(--text)}
  .fb-recent-email{font-weight:400;color:var(--muted);font-size:11px}
  .fb-recent-conv{font-size:11px;color:var(--muted2);margin-top:2px;display:inline-flex;align-items:center;gap:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}
  .fb-recent-badge{padding:3px 8px;border-radius:8px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;flex-shrink:0}
  .fb-badge-up{background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.2)}
  .fb-badge-down{background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.2)}
  /* Conversation viewer */
  .cv-overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);display:none;align-items:center;justify-content:center;z-index:250;padding:20px}
  .cv-overlay.show{display:flex;animation:fadeIn .18s ease}
  .cv-panel{background:var(--bg);border:1px solid var(--border);border-radius:20px;width:100%;max-width:720px;max-height:85vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 30px 80px rgba(0,0,0,.6);animation:modalIn .22s cubic-bezier(.2,.9,.3,1)}
  .cv-header{display:flex;align-items:center;gap:14px;padding:20px 24px;border-bottom:1px solid var(--border-soft);flex-shrink:0}
  .cv-header-info{flex:1;min-width:0}
  .cv-header-title{font-size:16px;font-weight:800;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .cv-header-meta{font-size:11px;color:var(--muted);margin-top:3px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
  .cv-close{width:36px;height:36px;border-radius:10px;border:1px solid var(--border);background:transparent;color:var(--muted);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;flex-shrink:0}
  .cv-close:hover{background:#ef444418;border-color:#ef444440;color:#ef4444}
  .cv-body{flex:1;overflow-y:auto;padding:16px 24px;display:flex;flex-direction:column;gap:12px}
  .cv-msg{display:flex;gap:10px;animation:fadeIn .2s ease}
  .cv-msg.cv-user{flex-direction:row-reverse}
  .cv-bubble{max-width:80%;padding:12px 16px;border-radius:16px;font-size:13px;line-height:1.6;word-break:break-word;white-space:pre-wrap}
  .cv-msg:not(.cv-user) .cv-bubble{background:var(--card);border:1px solid var(--border);border-top-left-radius:4px;color:var(--text)}
  .cv-msg.cv-user .cv-bubble{background:linear-gradient(135deg,var(--primary),#8b1217);color:#fff;border-top-right-radius:4px}
  .cv-avatar{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:800;flex-shrink:0}
  .cv-msg:not(.cv-user) .cv-avatar{background:linear-gradient(135deg,#1a1a2e,#16213e);color:#888;border:1px solid var(--border)}
  .cv-msg.cv-user .cv-avatar{background:linear-gradient(135deg,var(--primary),#8b1217);color:#fff}
  .cv-time{font-size:9px;color:var(--muted2);text-align:center;margin:4px 0}
  .cv-loading{text-align:center;padding:40px;color:var(--muted)}
  .cv-empty{text-align:center;padding:40px;color:var(--muted2)}
  .cv-count{font-size:11px;color:var(--muted);text-align:center;padding:8px;border-bottom:1px solid var(--border-soft);flex-shrink:0}
  @media(max-width:960px){
    .cv-panel{max-width:100%;max-height:90vh;border-radius:16px}
    .cv-header{padding:16px}
    .cv-body{padding:12px 16px}
    .cv-bubble{max-width:88%;font-size:12px}
  }
  /* Empty state */
  .empty{text-align:center;padding:60px 20px;color:var(--muted2);background:var(--card);border:1px dashed var(--border);border-radius:var(--radius)}
  .empty-icon{opacity:.3;margin-bottom:12px}
  /* Toast */
  .toast{position:fixed;bottom:24px;right:24px;background:var(--card);border:1px solid var(--border);padding:12px 18px;border-radius:10px;font-size:13px;display:none;box-shadow:0 10px 30px rgba(0,0,0,.5);z-index:100;max-width:320px}
  .toast.show{display:block;animation:slideIn .2s ease}
  @keyframes slideIn{from{transform:translateX(20px);opacity:0}to{transform:none;opacity:1}}
  /* Confirm Modal */
  .modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.72);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);display:none;align-items:center;justify-content:center;z-index:200;padding:20px}
  .modal-overlay.show{display:flex;animation:fadeIn .18s ease}
  .modal{background:linear-gradient(180deg,#161616,#101010);border:1px solid var(--border);border-radius:20px;padding:0;width:100%;max-width:440px;box-shadow:0 30px 80px rgba(0,0,0,.6), 0 0 0 1px rgba(255,255,255,.03);overflow:hidden;animation:modalIn .22s cubic-bezier(.2,.9,.3,1)}
  @keyframes modalIn{from{transform:scale(.94) translateY(8px);opacity:0}to{transform:none;opacity:1}}
  .modal-head{display:flex;align-items:center;gap:14px;padding:22px 24px 14px}
  .modal-icon{width:48px;height:48px;border-radius:14px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
  .modal-icon.v-danger{background:linear-gradient(135deg,#ef444422,#ef444408);border:1px solid #ef444433}
  .modal-icon.v-success{background:linear-gradient(135deg,#22c55e22,#22c55e08);border:1px solid #22c55e33}
  .modal-icon.v-warn{background:linear-gradient(135deg,#f59e0b22,#f59e0b08);border:1px solid #f59e0b33}
  .modal-title{font-size:17px;font-weight:800;letter-spacing:-.2px;color:var(--text)}
  .modal-sub{font-size:12px;color:var(--muted);margin-top:2px}
  .modal-body{padding:4px 24px 20px;color:#bbb;font-size:13px;line-height:1.6}
  .modal-target{display:flex;align-items:center;gap:10px;margin-top:14px;padding:12px 14px;background:#0a0a0a;border:1px solid var(--border-soft);border-radius:10px;font-size:12.5px}
  .modal-target .avatar{width:32px;height:32px;font-size:11px}
  .modal-target-name{font-weight:700;color:var(--text);font-size:13px}
  .modal-target-meta{color:var(--muted);font-size:11px;margin-top:1px}
  .modal-foot{display:flex;gap:10px;padding:16px 24px 20px;background:rgba(255,255,255,.015);border-top:1px solid var(--border-soft)}
  .modal-btn{flex:1;padding:11px 16px;border-radius:10px;font-size:13px;font-weight:700;cursor:pointer;border:1px solid var(--border);background:transparent;color:var(--text);font-family:inherit;transition:all .15s;display:inline-flex;align-items:center;justify-content:center;gap:6px}
  .modal-btn:hover{background:var(--card2);border-color:#333}
  .modal-btn.primary{border:none;color:#fff}
  .modal-btn.primary.v-danger{background:linear-gradient(135deg,#ef4444,#b91c1c)}
  .modal-btn.primary.v-danger:hover{background:linear-gradient(135deg,#dc2626,#991b1b);box-shadow:0 8px 20px -8px #ef4444}
  .modal-btn.primary.v-success{background:linear-gradient(135deg,#22c55e,#15803d)}
  .modal-btn.primary.v-success:hover{background:linear-gradient(135deg,#16a34a,#14532d);box-shadow:0 8px 20px -8px #22c55e}
  .modal-btn.primary.v-warn{background:linear-gradient(135deg,#f59e0b,#b45309)}
  .modal-btn.primary.v-warn:hover{background:linear-gradient(135deg,#d97706,#92400e);box-shadow:0 8px 20px -8px #f59e0b}
  .modal-btn:disabled{opacity:.6;cursor:not-allowed}
  /* Responsive */
  @media(max-width:960px){
    .layout{grid-template-columns:1fr;padding-bottom:64px}
    .sidebar{position:fixed;bottom:0;left:0;right:0;top:auto;height:auto;flex-direction:row;padding:0;gap:0;z-index:900;background:#0d0d0d;border-right:none;border-top:1px solid var(--border);box-shadow:0 -4px 20px rgba(0,0,0,.5)}
    .brand{display:none}
    .nav{flex-direction:row;flex:1;justify-content:space-around;gap:0}
    .nav-item{flex-direction:column;gap:3px;padding:8px 4px;font-size:10px;border-radius:0;justify-content:center;align-items:center;flex:1;min-width:0}
    .nav-item svg{width:18px;height:18px;flex-shrink:0}
    .nav-item span:not(.nav-badge){overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}
    .nav-item.active{background:rgba(227,30,36,.08)}
    .nav-badge{position:absolute;top:4px;right:50%;transform:translateX(calc(50% + 12px));font-size:8px;padding:1px 5px;min-width:16px;text-align:center}
    .nav-item{position:relative}
    .logout-btn{flex-direction:column;gap:3px;padding:8px 4px;font-size:10px;border:none;border-radius:0;justify-content:center;align-items:center;flex:0 0 auto;min-width:52px}
    .logout-btn span{font-size:10px}
    .logout-btn svg{width:18px;height:18px}
    .main{padding:16px}
    .hero{grid-template-columns:1fr;padding:20px;gap:20px}
    .hero-title{font-size:22px}
    .hero-sub{font-size:13px}
    .hero-kpi{max-width:100%}
    .kpi-value{font-size:32px}
    .stats-grid{grid-template-columns:repeat(2,1fr);gap:10px}
    .sc-value{font-size:24px}
    .sc-icon{width:32px;height:32px;border-radius:10px;margin-bottom:10px}
    .quick-actions{gap:6px}
    .qa-btn{padding:8px 10px;font-size:11px;gap:6px}
    .grid-two{grid-template-columns:1fr}
    .bd-row{grid-template-columns:100px 1fr auto;gap:8px}
    .bd-label{font-size:11px}
    .bd-val{font-size:12px;min-width:50px}
    .top-stats{flex-wrap:wrap;gap:4px}
    .sys-grid{grid-template-columns:1fr}
    .sys-item:nth-child(odd){padding-right:0;border-right:none}
    .sys-item:nth-child(even){padding-left:0}
    .user-row{flex-wrap:wrap}
    .urow-info{width:100%;order:3}
    .urow-actions{width:100%;order:4;justify-content:flex-end}
    .conv-row{flex-wrap:wrap;padding:12px 14px;gap:10px}
    .conv-row .avatar{display:none}
    .conv-main{width:100%;order:1}
    .conv-title{white-space:normal;display:flex}
    .conv-info{width:100%;order:2;gap:8px}
    .conv-row .btn-icon{order:3;margin-left:auto}
    .search-wrap{width:100%}
    .page-header{flex-direction:column;align-items:stretch}
    .page-title{font-size:20px}
    .panel-head{padding:14px 16px;flex-wrap:wrap;gap:8px}
    .panel-body{padding:14px 16px}
    .act-row{flex-wrap:wrap;gap:8px}
    .act-side{flex-direction:row;align-items:center;width:100%;justify-content:flex-start;gap:8px}
    .uc-head{flex-wrap:wrap;gap:8px}
    .uc-head .pill{font-size:9px;padding:2px 6px}
    .msg-item{flex-direction:column;gap:8px}
    .msg-content{min-width:0;width:100%}
    .msg-actions{width:100%}
    .msg-actions textarea{width:100%}
    .reply-form{gap:8px}
    .modal-box{max-width:92vw;margin:20px;padding:24px}
    .fb-hero{grid-template-columns:1fr;padding:20px;gap:20px}
    .fb-rate{font-size:48px}
    .fb-summary{flex-direction:column;gap:10px}
    .fb-stat{min-width:0;flex:1}
    .fb-user-row{flex-wrap:wrap}
    .fb-user-reactions{width:100%;justify-content:flex-start;margin-top:4px}
    .fb-conv-row{flex-wrap:wrap}
    .fb-conv-stats{width:100%;justify-content:flex-start;margin-top:4px}
    .fb-recent-row{flex-wrap:wrap;gap:8px}
    .fb-recent-badge{margin-left:auto}
  }
  @media(max-width:480px){
    .stats-grid{grid-template-columns:1fr}
    .hero{padding:16px;gap:14px}
    .hero-title{font-size:19px}
    .kpi-value{font-size:28px}
    .main{padding:12px}
    .nav-item{padding:6px 2px;font-size:9px}
    .nav-item svg{width:16px;height:16px}
    .nav-badge{font-size:7px;padding:0 4px;min-width:14px;top:2px}
    .logout-btn{min-width:44px;padding:6px 2px;font-size:9px}
    .qa-btn{flex:1;justify-content:center}
    .top-user-row{flex-wrap:wrap;gap:6px}
    .top-stats{width:100%;justify-content:flex-end}
  }
</style></head><body>
<div class="layout">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-logo">${svg(ICONS.shield, '#fff', 20)}</div>
      <div>
        <div class="brand-title">Runner Code</div>
        <div class="brand-sub">Admin</div>
      </div>
    </div>
    <nav class="nav">
      <button class="nav-item active" data-section="overview" onclick="showSection('overview',this)">
        ${svg(ICONS.dashboard, 'currentColor', 16)}<span>Overview</span>
      </button>
      <button class="nav-item" data-section="messages" onclick="showSection('messages',this)">
        ${svg(ICONS.inbox, 'currentColor', 16)}<span>Messages</span>
        <span class="nav-badge">${contacts.length}</span>
      </button>
      <button class="nav-item" data-section="users" onclick="showSection('users',this)">
        ${svg(ICONS.users, 'currentColor', 16)}<span>Users</span>
        <span class="nav-badge">${users.length}${suspendedCount ? `<span style="color:#ef4444;margin-left:3px">(${suspendedCount})</span>` : ''}</span>
      </button>
      <button class="nav-item" data-section="conversations" onclick="showSection('conversations',this)">
        ${svg(ICONS.msgCircle, 'currentColor', 16)}<span>Conversations</span>
        <span class="nav-badge">${totalConvs}</span>
      </button>
      <button class="nav-item" data-section="feedback" onclick="showSection('feedback',this)">
        ${svg(ICONS.thumbUp, 'currentColor', 16)}<span>Feedback</span>
        <span class="nav-badge">${totalReactions}</span>
      </button>
    </nav>
    <button class="logout-btn" onclick="logout()">
      ${svg(ICONS.logout, 'currentColor', 16)}<span>Sign out</span>
    </button>
  </aside>

  <main class="main">
    <!-- Overview -->
    <section class="section active" id="sec-overview">
      <!-- Hero -->
      <div class="hero">
        <div class="hero-bg"></div>
        <div class="hero-content">
          <div class="hero-top">
            <div class="hero-badge"><span class="live-dot"></span> Live dashboard</div>
            <button class="refresh-btn" onclick="refreshDashboard(this)">
              <span class="r-icon">${svg(ICONS.refresh, 'currentColor', 13)}</span>
              <span>Refresh</span>
            </button>
          </div>
          <h1 class="hero-title">Welcome back, Admin</h1>
          <p class="hero-sub">Here's what's happening across Runner Code today.</p>
          <div class="hero-meta">
            <span class="hero-meta-item">${svg(ICONS.calendar, 'currentColor', 13)}<span id="nowDate"></span></span>
            <span class="hero-meta-dot"></span>
            <span class="hero-meta-item">${svg(ICONS.shield, 'currentColor', 13)} Session secure</span>
          </div>
        </div>
        <div class="hero-kpi">
          <div class="kpi-label">Approval rate</div>
          <div class="kpi-value">${approvalRate}<span>%</span></div>
          <div class="kpi-bar"><div class="kpi-bar-fill" style="width:${approvalRate}%"></div></div>
          <div class="kpi-foot">${totalDecided} decision${totalDecided === 1 ? '' : 's'} so far</div>
        </div>
      </div>

      <!-- Stat grid -->
      <div class="stats-grid">
        <div class="stat-card sc-users">
          <div class="sc-icon">${svg(ICONS.users, '#fff', 20)}</div>
          <div class="sc-label">Total users</div>
          <div class="sc-value">${users.length}</div>
          <div class="sc-delta up">+${newUsers7d} this week</div>
        </div>
        <div class="stat-card sc-msgs">
          <div class="sc-icon">${svg(ICONS.inbox, '#fff', 20)}</div>
          <div class="sc-label">Support messages</div>
          <div class="sc-value">${totalContacts}</div>
          <div class="sc-delta up">+${msgs7d} this week</div>
        </div>
        <div class="stat-card sc-convs">
          <div class="sc-icon">${svg(ICONS.msgCircle, '#fff', 20)}</div>
          <div class="sc-label">Conversations</div>
          <div class="sc-value">${totalConvs}</div>
          <div class="sc-delta neutral">${totalMsgsInConvs} AI messages</div>
        </div>
        <div class="stat-card sc-pending">
          <div class="sc-icon">${svg(ICONS.clock, '#fff', 20)}</div>
          <div class="sc-label">Awaiting review</div>
          <div class="sc-value">${pendingCount}</div>
          <div class="sc-delta neutral">${unrepliedCount} unreplied</div>
        </div>
        <div class="stat-card sc-approved">
          <div class="sc-icon">${svg(ICONS.check, '#fff', 20)}</div>
          <div class="sc-label">Approved</div>
          <div class="sc-value">${approvedCount}</div>
          <div class="sc-delta up">${pct(approvedCount)}% of total</div>
        </div>
        <div class="stat-card sc-rejected">
          <div class="sc-icon">${svg(ICONS.x, '#fff', 20)}</div>
          <div class="sc-label">Rejected</div>
          <div class="sc-value">${rejectedCount}</div>
          <div class="sc-delta down">${pct(rejectedCount)}% of total</div>
        </div>
        <div class="stat-card sc-feedback">
          <div class="sc-icon">${svg(ICONS.thumbUp, '#fff', 20)}</div>
          <div class="sc-label">AI Feedback</div>
          <div class="sc-value">${totalReactions}</div>
          <div class="sc-delta ${satisfactionRate >= 50 ? 'up' : 'down'}">${satisfactionRate}% positive</div>
        </div>
      </div>

      <!-- Quick actions -->
      <div class="quick-actions">
        <button class="qa-btn" onclick="showSection('messages', document.querySelector('[data-section=messages]'))">${svg(ICONS.inbox, 'currentColor', 16)}<span>Review messages</span><span class="qa-count">${pendingCount}</span></button>
        <button class="qa-btn" onclick="showSection('users', document.querySelector('[data-section=users]'))">${svg(ICONS.users, 'currentColor', 16)}<span>Manage users</span><span class="qa-count">${users.length}</span></button>
        <button class="qa-btn" onclick="showSection('conversations', document.querySelector('[data-section=conversations]'))">${svg(ICONS.msgCircle, 'currentColor', 16)}<span>View conversations</span><span class="qa-count">${totalConvs}</span></button>
        <button class="qa-btn" onclick="exportCSV('users')">${svg(ICONS.dashboard, 'currentColor', 16)}<span>Export users CSV</span></button>
        <button class="qa-btn" onclick="exportCSV('messages')">${svg(ICONS.mail, 'currentColor', 16)}<span>Export messages CSV</span></button>
      </div>

      <!-- Two column: breakdowns + activity -->
      <div class="grid-two">
        <!-- Breakdown: message types -->
        <div class="panel">
          <div class="panel-head">
            <div>
              <div class="panel-title">Message types</div>
              <div class="panel-sub">Distribution by category</div>
            </div>
            <span class="panel-ico">${svg(ICONS.inbox, 'var(--muted)', 16)}</span>
          </div>
          <div class="panel-body">
            ${[
              { key: 'bug',        label: 'Bug reports',   color: '#ef4444', ic: svg(ICONS.bug, '#ef4444', 14) },
              { key: 'suggestion', label: 'Suggestions',   color: '#eab308', ic: svg(ICONS.lightbulb, '#eab308', 14) },
              { key: 'request',    label: 'Feature requests', color: '#3b82f6', ic: svg(ICONS.wrench, '#3b82f6', 14) },
              { key: 'other',      label: 'Other',          color: '#94a3b8', ic: svg(ICONS.message, '#94a3b8', 14) },
            ].map(t => {
              const n = typeCounts[t.key];
              const p = totalContacts ? Math.round((n / totalContacts) * 100) : 0;
              return `<div class="bd-row">
                <div class="bd-label">${t.ic}<span>${t.label}</span></div>
                <div class="bd-bar"><div class="bd-fill" style="width:${p}%;background:${t.color}"></div></div>
                <div class="bd-val">${n}<span class="bd-pct">${p}%</span></div>
              </div>`;
            }).join('')}
          </div>
        </div>

        <!-- Breakdown: auth methods -->
        <div class="panel">
          <div class="panel-head">
            <div>
              <div class="panel-title">Authentication</div>
              <div class="panel-sub">How users sign in</div>
            </div>
            <span class="panel-ico">${svg(ICONS.shield, 'var(--muted)', 16)}</span>
          </div>
          <div class="panel-body">
            ${[
              { label: 'Google only',     n: googleUsers, color: '#4285F4', ic: svg(ICONS.google, '#4285F4', 14) },
              { label: 'Password only',   n: pwOnlyUsers, color: '#eab308', ic: svg(ICONS.key, '#eab308', 14) },
              { label: 'Google + Password', n: dualUsers, color: '#22c55e', ic: svg(ICONS.shield, '#22c55e', 14) },
            ].map(t => {
              const p = users.length ? Math.round((t.n / users.length) * 100) : 0;
              return `<div class="bd-row">
                <div class="bd-label">${t.ic}<span>${t.label}</span></div>
                <div class="bd-bar"><div class="bd-fill" style="width:${p}%;background:${t.color}"></div></div>
                <div class="bd-val">${t.n}<span class="bd-pct">${p}%</span></div>
              </div>`;
            }).join('')}
            <div class="panel-note">${googleTotal} user${googleTotal === 1 ? '' : 's'} connected a Google account</div>
          </div>
        </div>
      </div>

      <!-- Row 2: Country + Models -->
      <div class="grid-two">
        <!-- Country distribution -->
        <div class="panel">
          <div class="panel-head">
            <div>
              <div class="panel-title">Countries</div>
              <div class="panel-sub">Top ${topCountries.length} user locations</div>
            </div>
            <span class="panel-ico">${svg(ICONS.globe, 'var(--muted)', 16)}</span>
          </div>
          <div class="panel-body">
            ${topCountries.length ? topCountries.map(([country, n]) => {
              const p = users.length ? Math.round((n / users.length) * 100) : 0;
              return `<div class="bd-row">
                <div class="bd-label">${svg(ICONS.globe, '#3b82f6', 14)}<span>${escapeHtml(country)}</span></div>
                <div class="bd-bar"><div class="bd-fill" style="width:${p}%;background:#3b82f6"></div></div>
                <div class="bd-val">${n}<span class="bd-pct">${p}%</span></div>
              </div>`;
            }).join('') : '<div class="empty-inline"><p>No data</p></div>'}
          </div>
        </div>

        <!-- Model usage -->
        <div class="panel">
          <div class="panel-head">
            <div>
              <div class="panel-title">AI Models</div>
              <div class="panel-sub">Most used models</div>
            </div>
            <span class="panel-ico">${svg(ICONS.msgCircle, 'var(--muted)', 16)}</span>
          </div>
          <div class="panel-body">
            ${topModels.length ? topModels.map(([model, n]) => {
              const p = totalConvs ? Math.round((n / totalConvs) * 100) : 0;
              return `<div class="bd-row">
                <div class="bd-label"><span class="conv-model" style="font-size:11px">${escapeHtml(model)}</span></div>
                <div class="bd-bar"><div class="bd-fill" style="width:${p}%;background:#8b5cf6"></div></div>
                <div class="bd-val">${n}<span class="bd-pct">${p}%</span></div>
              </div>`;
            }).join('') : '<div class="empty-inline"><p>No conversations yet</p></div>'}
          </div>
        </div>
      </div>

      <!-- Row 3: Top users + System info -->
      <div class="grid-two">
        <!-- Top active users -->
        <div class="panel">
          <div class="panel-head">
            <div>
              <div class="panel-title">Top users</div>
              <div class="panel-sub">Most active by conversations</div>
            </div>
            <span class="panel-ico">${svg(ICONS.users, 'var(--muted)', 16)}</span>
          </div>
          <div class="panel-body">
            ${topActiveUsers.length ? topActiveUsers.map((u, i) => {
              const initials = String(u.name || '?').trim().split(/\s+/).map(p => p[0]).slice(0, 2).join('').toUpperCase() || '?';
              return `<div class="top-user-row">
                <span class="top-rank">#${i + 1}</span>
                <div class="avatar avatar-sm">${escapeHtml(initials)}</div>
                <div class="top-meta">
                  <div class="top-name">${escapeHtml(u.name)}</div>
                  <div class="top-email">${escapeHtml(u.email)}</div>
                </div>
                <div class="top-stats">
                  <span class="top-stat">${svg(ICONS.msgCircle, '#8b5cf6', 11)}${u.count} chats</span>
                  <span class="top-stat">${svg(ICONS.message, '#3b82f6', 11)}${u.msgs} msgs</span>
                </div>
              </div>`;
            }).join('') : '<div class="empty-inline"><p>No users yet</p></div>'}
          </div>
        </div>

        <!-- System info -->
        <div class="panel">
          <div class="panel-head">
            <div>
              <div class="panel-title">System</div>
              <div class="panel-sub">Platform information</div>
            </div>
            <span class="panel-ico">${svg(ICONS.dashboard, 'var(--muted)', 16)}</span>
          </div>
          <div class="panel-body">
            <div class="sys-grid">
              <div class="sys-item">
                <div class="sys-label">${svg(ICONS.dashboard, '#666', 12)}Database</div>
                <div class="sys-value">${dbSizeStr}</div>
              </div>
              <div class="sys-item">
                <div class="sys-label">${svg(ICONS.users, '#666', 12)}Active users</div>
                <div class="sys-value">${users.length - suspendedCount}</div>
              </div>
              <div class="sys-item">
                <div class="sys-label">${svg(ICONS.lock, '#666', 12)}Suspended</div>
                <div class="sys-value" style="color:#ef4444">${suspendedCount}</div>
              </div>
              <div class="sys-item">
                <div class="sys-label">${svg(ICONS.msgCircle, '#666', 12)}AI messages</div>
                <div class="sys-value">${totalMsgsInConvs}</div>
              </div>
              <div class="sys-item">
                <div class="sys-label">${svg(ICONS.reply, '#666', 12)}Replied</div>
                <div class="sys-value" style="color:#8b5cf6">${repliedCount}/${totalContacts}</div>
              </div>
              <div class="sys-item">
                <div class="sys-label">${svg(ICONS.check, '#666', 12)}Response rate</div>
                <div class="sys-value" style="color:#22c55e">${totalContacts ? Math.round((repliedCount / totalContacts) * 100) : 0}%</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Recent activity -->
      <div class="panel">
        <div class="panel-head">
          <div>
            <div class="panel-title">Recent activity</div>
            <div class="panel-sub">Last ${recentContacts.length} message${recentContacts.length === 1 ? '' : 's'}</div>
          </div>
          <button class="panel-action" onclick="showSection('messages', document.querySelector('[data-section=messages]'))">View all ${svg(ICONS.inbox, 'currentColor', 12)}</button>
        </div>
        <div class="panel-body">
          ${recentContacts.length ? recentContacts.map(c => `
            <div class="act-row">
              <span class="act-dot" style="background:${typeColorDot[c.type] || '#94a3b8'}"></span>
              <div class="act-main">
                <div class="act-title">${typeIcon[c.type] || typeIcon.other}<span>${escapeHtml(c.subject || '(no subject)')}</span></div>
                <div class="act-meta">${escapeHtml(c.user_name || 'Unknown')} · ${escapeHtml(c.user_email || '—')}</div>
              </div>
              <div class="act-side">
                ${statusPill(c.status)}
                <span class="act-time">${escapeHtml(c.created_at || '')}</span>
              </div>
            </div>`).join('') : `<div class="empty-inline">${svg(ICONS.inbox, '#333', 32)}<p>No activity yet</p></div>`}
        </div>
      </div>
    </section>

    <!-- Messages (grouped by user) -->
    <section class="section" id="sec-messages">
      <div class="page-header">
        <div>
          <div class="page-title">Contact Messages</div>
          <div class="page-sub">${userGroups.length} user${userGroups.length === 1 ? '' : 's'} · ${contacts.length} message${contacts.length === 1 ? '' : 's'}${orphanCount ? ` · <span style="color:#f59e0b;font-weight:700">${orphanCount} orphan${orphanCount === 1 ? '' : 's'}</span>` : ''}</div>
        </div>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
          ${orphanCount ? `<button class="panel-action" style="border-color:#f59e0b55;color:#f59e0b" onclick="cleanupOrphans(${orphanCount})">${svg(ICONS.trash, '#f59e0b', 12)} Clean ${orphanCount} orphan${orphanCount === 1 ? '' : 's'}</button>` : ''}
          <div class="search-wrap">
            <span class="search-icon">${svg(ICONS.search, '#555', 15)}</span>
            <input class="search-input" id="msgSearch" placeholder="Search by name or email…" oninput="filterCards('msgSearch','.user-card')">
          </div>
        </div>
      </div>
      ${userCards || `<div class="empty">${svg(ICONS.inbox, '#333', 48)}<div class="empty-icon"></div><p>No messages yet</p></div>`}
    </section>

    <!-- Users -->
    <section class="section" id="sec-users">
      <div class="page-header">
        <div>
          <div class="page-title">Users</div>
          <div class="page-sub">${users.length} registered account${users.length === 1 ? '' : 's'}${suspendedCount ? ` · <span style="color:#ef4444;font-weight:700">${suspendedCount} suspended</span>` : ''}</div>
        </div>
        <div class="search-wrap">
          <span class="search-icon">${svg(ICONS.search, '#555', 15)}</span>
          <input class="search-input" id="userSearch" placeholder="Search users…" oninput="filterCards('userSearch','.user-row')">
        </div>
      </div>
      ${userRows || `<div class="empty"><p>No users yet</p></div>`}
    </section>

    <!-- Conversations -->
    <section class="section" id="sec-conversations">
      <div class="page-header">
        <div>
          <div class="page-title">Conversations</div>
          <div class="page-sub">${totalConvs} conversation${totalConvs === 1 ? '' : 's'} · ${totalMsgsInConvs} total messages</div>
        </div>
        <div class="search-wrap">
          <span class="search-icon">${svg(ICONS.search, '#555', 15)}</span>
          <input class="search-input" id="convSearch" placeholder="Search conversations…" oninput="filterCards('convSearch','.conv-row')">
        </div>
      </div>
      ${allConvs.length ? allConvs.map(c => {
        const cInitials = String(c.user_name || '?').trim().split(/\s+/).map(p => p[0]).slice(0, 2).join('').toUpperCase() || '?';
        const modelShort = (c.model || '').split('/').pop() || c.model || '—';
        const updatedDate = c.updated_at ? new Date(c.updated_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';
        return `
      <div class="conv-row" data-search="${escapeHtml(((c.user_name || '') + ' ' + (c.user_email || '') + ' ' + (c.title || '')).toLowerCase())}">
        <div class="avatar avatar-sm">${escapeHtml(cInitials)}</div>
        <div class="conv-main">
          <div class="conv-title">${svg(ICONS.msgCircle, 'var(--muted)', 12)}<span>${escapeHtml(c.title || 'Untitled')}</span></div>
          <div class="conv-meta">${escapeHtml(c.user_name || 'Unknown')} · ${escapeHtml(c.user_email || '—')}</div>
        </div>
        <div class="conv-info">
          <span class="info-item">${svg(ICONS.message, '#666', 12)}${c.message_count || 0} msgs</span>
          <span class="info-item conv-model">${escapeHtml(modelShort)}</span>
          <span class="info-item">${svg(ICONS.clock, '#666', 12)}${escapeHtml(updatedDate)}</span>
        </div>
        <div style="display:flex;gap:6px;flex-shrink:0">
          <button class="btn-icon" onclick="viewConv('${escapeHtml(c.id)}')" title="View messages" style="border-color:#8b5cf640">
            ${svg(ICONS.message, '#8b5cf6', 15)}
          </button>
          <button class="btn-icon btn-danger" onclick="deleteConv('${escapeHtml(c.id)}', '${escapeHtml(c.title || 'Untitled').replace(/'/g,"\\'")}')" title="Delete conversation">
            ${svg(ICONS.trash, '#ef4444', 15)}
          </button>
        </div>
      </div>`;
      }).join('') : `<div class="empty"><p>No conversations yet</p></div>`}
    </section>

    <!-- Feedback -->
    <section class="section" id="sec-feedback">
      <div class="page-header">
        <div>
          <div class="page-title">AI Feedback</div>
          <div class="page-sub">${totalReactions} reaction${totalReactions === 1 ? '' : 's'} · ${thumbsUp} positive · ${thumbsDown} negative</div>
        </div>
      </div>

      <!-- Satisfaction hero -->
      <div class="fb-hero">
        <div class="fb-hero-main">
          <div class="fb-rate">${satisfactionRate}<span>%</span></div>
          <div class="fb-rate-label">Satisfaction Rate</div>
          <div class="fb-rate-bar"><div class="fb-rate-fill" style="width:${satisfactionRate}%;background:${satisfactionRate >= 60 ? '#22c55e' : satisfactionRate >= 40 ? '#f59e0b' : '#ef4444'}"></div></div>
        </div>
        <div class="fb-summary">
          <div class="fb-stat">
            <div class="fb-stat-icon fb-up">${svg(ICONS.thumbUp, '#22c55e', 18)}</div>
            <div>
              <div class="fb-stat-val">${thumbsUp}</div>
              <div class="fb-stat-lbl">Positive</div>
            </div>
          </div>
          <div class="fb-stat">
            <div class="fb-stat-icon fb-down">${svg(ICONS.thumbDown, '#ef4444', 18)}</div>
            <div>
              <div class="fb-stat-val">${thumbsDown}</div>
              <div class="fb-stat-lbl">Negative</div>
            </div>
          </div>
          <div class="fb-stat">
            <div class="fb-stat-icon fb-total">${svg(ICONS.star, '#f59e0b', 18)}</div>
            <div>
              <div class="fb-stat-val">${totalReactions}</div>
              <div class="fb-stat-lbl">Total</div>
            </div>
          </div>
        </div>
      </div>

      <div class="grid-two">
        <!-- Feedback by user -->
        <div class="panel">
          <div class="panel-head">
            <div>
              <div class="panel-title">Feedback by user</div>
              <div class="panel-sub">Most active reviewers</div>
            </div>
            <span class="panel-ico">${svg(ICONS.users, 'var(--muted)', 16)}</span>
          </div>
          <div class="panel-body">
            ${topFeedbackUsers.length ? topFeedbackUsers.map(u => {
              const pctUp = u.total ? Math.round((u.up / u.total) * 100) : 0;
              return `<div class="fb-user-row">
                <div class="fb-user-info">
                  <div class="fb-user-name">${escapeHtml(u.name)}</div>
                  <div class="fb-user-email">${escapeHtml(u.email)}</div>
                </div>
                <div class="fb-user-reactions">
                  <span class="fb-pill fb-pill-up">${svg(ICONS.thumbUp, '#22c55e', 11)}${u.up}</span>
                  <span class="fb-pill fb-pill-down">${svg(ICONS.thumbDown, '#ef4444', 11)}${u.down}</span>
                  <span class="fb-pill fb-pill-pct" style="color:${pctUp >= 60 ? '#22c55e' : pctUp >= 40 ? '#f59e0b' : '#ef4444'}">${pctUp}%</span>
                </div>
              </div>`;
            }).join('') : '<div class="empty-inline"><p>No feedback yet</p></div>'}
          </div>
        </div>

        <!-- Feedback by conversation -->
        <div class="panel">
          <div class="panel-head">
            <div>
              <div class="panel-title">Feedback by conversation</div>
              <div class="panel-sub">Top rated chats</div>
            </div>
            <span class="panel-ico">${svg(ICONS.msgCircle, 'var(--muted)', 16)}</span>
          </div>
          <div class="panel-body">
            ${topFeedbackConvs.length ? topFeedbackConvs.map(([, c]) => {
              const pctUp = c.total ? Math.round((c.up / c.total) * 100) : 0;
              return `<div class="fb-conv-row">
                <div class="fb-conv-title">${svg(ICONS.msgCircle, 'var(--muted)', 12)}<span>${escapeHtml(c.title)}</span></div>
                <div class="fb-conv-stats">
                  <span class="fb-pill fb-pill-up">${svg(ICONS.thumbUp, '#22c55e', 11)}${c.up}</span>
                  <span class="fb-pill fb-pill-down">${svg(ICONS.thumbDown, '#ef4444', 11)}${c.down}</span>
                  <span class="fb-pill fb-pill-pct" style="color:${pctUp >= 60 ? '#22c55e' : pctUp >= 40 ? '#f59e0b' : '#ef4444'}">${pctUp}%</span>
                </div>
              </div>`;
            }).join('') : '<div class="empty-inline"><p>No feedback yet</p></div>'}
          </div>
        </div>
      </div>

      <!-- Recent feedback -->
      <div class="panel">
        <div class="panel-head">
          <div>
            <div class="panel-title">Recent feedback</div>
            <div class="panel-sub">Last ${recentFeedback.length} reaction${recentFeedback.length === 1 ? '' : 's'}</div>
          </div>
          <span class="panel-ico">${svg(ICONS.clock, 'var(--muted)', 16)}</span>
        </div>
        <div class="panel-body">
          ${recentFeedback.length ? recentFeedback.map(r => `
            <div class="fb-recent-row">
              <span class="fb-react-icon ${r.reaction === 'up' ? 'fb-react-up' : 'fb-react-down'}">${r.reaction === 'up' ? svg(ICONS.thumbUp, '#22c55e', 14) : svg(ICONS.thumbDown, '#ef4444', 14)}</span>
              <div class="fb-recent-info">
                <div class="fb-recent-user">${escapeHtml(r.user_name || 'Unknown')}<span class="fb-recent-email"> · ${escapeHtml(r.user_email || '—')}</span></div>
                <div class="fb-recent-conv">${svg(ICONS.msgCircle, 'var(--muted2)', 10)} ${escapeHtml(r.conv_title || 'Untitled')}</div>
              </div>
              <span class="fb-recent-badge ${r.reaction === 'up' ? 'fb-badge-up' : 'fb-badge-down'}">${r.reaction === 'up' ? 'Positive' : 'Negative'}</span>
            </div>`).join('') : `<div class="empty-inline">${svg(ICONS.thumbUp, '#333', 32)}<p>No feedback yet</p></div>`}
        </div>
      </div>
    </section>
  </main>
</div>

<div class="toast" id="toast"></div>

<!-- Conversation viewer -->
<div class="cv-overlay" id="cvOverlay" onclick="if(event.target===this)closeCv()">
  <div class="cv-panel">
    <div class="cv-header">
      <div class="cv-header-info">
        <div class="cv-header-title" id="cvTitle">Conversation</div>
        <div class="cv-header-meta" id="cvMeta"></div>
      </div>
      <button class="cv-close" onclick="closeCv()" title="Close">${svg(ICONS.x, 'currentColor', 16)}</button>
    </div>
    <div class="cv-count" id="cvCount"></div>
    <div class="cv-body" id="cvBody">
      <div class="cv-loading">Loading…</div>
    </div>
  </div>
</div>
<div class="modal-overlay" id="confirmModal" onclick="if(event.target===this)closeConfirm(false)">
  <div class="modal" role="dialog" aria-modal="true">
    <div class="modal-head">
      <div class="modal-icon" id="mIcon"></div>
      <div>
        <div class="modal-title" id="mTitle"></div>
        <div class="modal-sub" id="mSub"></div>
      </div>
    </div>
    <div class="modal-body">
      <div id="mMessage"></div>
      <div id="mTarget"></div>
    </div>
    <div class="modal-foot">
      <button class="modal-btn" id="mCancel" onclick="closeConfirm(false)">Cancel</button>
      <button class="modal-btn primary" id="mOk" onclick="closeConfirm(true)"></button>
    </div>
  </div>
</div>
<!-- Status picker modal (after reply) -->
<div class="modal-overlay" id="statusPicker" onclick="if(event.target===this)pickStatus('skip')">
  <div class="modal" role="dialog" aria-modal="true">
    <div class="modal-head">
      <div class="modal-icon v-success">${svg(ICONS.check, '#22c55e', 22)}</div>
      <div>
        <div class="modal-title">Reply sent successfully</div>
        <div class="modal-sub">Set a decision for this message</div>
      </div>
    </div>
    <div class="modal-body">
      <div>Your reply has been saved. Choose a status for this message now, or skip to decide later.</div>
    </div>
    <div class="modal-foot" style="gap:8px">
      <button class="modal-btn" onclick="pickStatus('skip')" style="flex:1">Skip for now</button>
      <button class="modal-btn primary v-danger" onclick="pickStatus('rejected')" style="flex:1">${svg(ICONS.x, '#fff', 14)} <span>Reject</span></button>
      <button class="modal-btn primary v-success" onclick="pickStatus('approved')" style="flex:1">${svg(ICONS.check, '#fff', 14)} <span>Approve</span></button>
    </div>
  </div>
</div>
<script>
  function showSection(id, btn){
    document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
    document.getElementById('sec-'+id).classList.add('active');
    document.querySelectorAll('.nav-item').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    sessionStorage.setItem('admin_section', id);
  }
  // Restore last active section on load
  (function(){
    const saved = sessionStorage.getItem('admin_section');
    if(saved && document.getElementById('sec-'+saved)){
      const btn = document.querySelector('.nav-item[data-section="'+saved+'"]');
      if(btn) showSection(saved, btn);
    }
  })();
  function toggleUser(id){
    const card = document.getElementById('body-'+id)?.closest('.user-card');
    if(card) card.classList.toggle('open');
  }
  function filterCards(inputId, selector){
    const q = document.getElementById(inputId).value.toLowerCase().trim();
    document.querySelectorAll(selector).forEach(el=>{
      const s = el.dataset.search || '';
      el.style.display = (!q || s.includes(q)) ? '' : 'none';
    });
  }
  function showToast(msg, ok){
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.style.borderColor = ok ? '#22c55e55' : '#ef444455';
    t.classList.add('show');
    setTimeout(()=>t.classList.remove('show'), 3000);
  }
  // Custom in-app confirm modal (replaces browser confirm)
  const ICONS_JS = {
    trash:  \`${svg(ICONS.trash,  '#ef4444', 22)}\`,
    check:  \`${svg(ICONS.check,  '#22c55e', 22)}\`,
    x:      \`${svg(ICONS.x,      '#ef4444', 22)}\`,
    alert:  \`${svg(ICONS.alert,  '#f59e0b', 22)}\`,
  };
  let _confirmResolve = null;
  function showConfirm(opts){
    return new Promise(resolve => {
      _confirmResolve = resolve;
      const v = opts.variant || 'danger';
      document.getElementById('mIcon').className = 'modal-icon v-' + v;
      document.getElementById('mIcon').innerHTML = ICONS_JS[opts.icon] || ICONS_JS.alert;
      document.getElementById('mTitle').textContent = opts.title || 'Are you sure?';
      document.getElementById('mSub').textContent = opts.subtitle || '';
      document.getElementById('mMessage').textContent = opts.message || '';
      document.getElementById('mTarget').innerHTML = opts.targetHtml || '';
      const ok = document.getElementById('mOk');
      ok.className = 'modal-btn primary v-' + v;
      ok.innerHTML = (ICONS_JS[opts.icon] ? ICONS_JS[opts.icon].replace(/width="22" height="22"/,'width="14" height="14"').replace(/stroke="#[a-f0-9]+"/i,'stroke="#fff"') : '') + '<span>' + (opts.confirmText || 'Confirm') + '</span>';
      document.getElementById('confirmModal').classList.add('show');
    });
  }
  function closeConfirm(result){
    document.getElementById('confirmModal').classList.remove('show');
    if(_confirmResolve){ _confirmResolve(result); _confirmResolve = null; }
  }
  document.addEventListener('keydown', e => {
    if(e.key === 'Escape' && document.getElementById('confirmModal').classList.contains('show')){
      closeConfirm(false);
    }
  });
  // Live date in hero
  (function updateNow(){
    const el = document.getElementById('nowDate');
    if(!el) return;
    const d = new Date();
    el.textContent = d.toLocaleDateString(undefined, { weekday:'long', year:'numeric', month:'long', day:'numeric' }) + ' · ' + d.toLocaleTimeString(undefined, { hour:'2-digit', minute:'2-digit' });
    setTimeout(updateNow, 30000);
  })();
  async function deleteUser(id, name, email){
    const initials = String(name||'?').trim().split(/\\s+/).map(p=>p[0]).slice(0,2).join('').toUpperCase() || '?';
    const targetHtml = '<div class="modal-target"><div class="avatar">' + initials + '</div><div><div class="modal-target-name">' + name + '</div><div class="modal-target-meta">' + (email||'') + '</div></div></div>';
    const ok = await showConfirm({
      variant:'danger', icon:'trash',
      title:'Delete account',
      subtitle:'This action cannot be undone',
      message:'All conversations, reactions and data for this user will be permanently removed.',
      targetHtml,
      confirmText:'Delete account',
    });
    if(!ok) return;
    fetch('/admin/users/'+id, { method:'DELETE', credentials:'include' })
      .then(r=>r.json()).then(d=>{
        if(d.ok){ showToast('Deleted: '+name, true); setTimeout(()=>location.reload(), 500); }
        else showToast(d.error || 'Failed', false);
      }).catch(()=>showToast('Network error', false));
  }
  async function setStatus(id, status){
    const cfg = status === 'approved'
      ? { variant:'success', icon:'check', title:'Approve message', confirmText:'Approve', message:'Approving this report will mark it as accepted. This decision is final and cannot be changed later.' }
      : { variant:'danger',  icon:'x',     title:'Reject message',  confirmText:'Reject',  message:'Rejecting this report will mark it as declined. This decision is final and cannot be changed later.' };
    const ok = await showConfirm({ ...cfg, subtitle:'Final decision' });
    if(!ok) return;
    fetch('/admin/contact/'+id+'/status', {
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      credentials:'include',
      body: JSON.stringify({ status })
    }).then(r=>r.json()).then(d=>{
      if(d.ok){ showToast('Status: ' + status, true); setTimeout(()=>location.reload(), 600); }
      else showToast(d.error || 'Failed', false);
    }).catch(()=>showToast('Network error', false));
  }
  function logout(){
    fetch('/admin/logout', { method:'POST', credentials:'include' })
      .then(()=>location.href='/admin');
  }
  async function cleanupOrphans(count){
    const ok = await showConfirm({
      variant:'warn', icon:'alert',
      title:'Clean orphan messages',
      subtitle:'Remove messages from deleted accounts',
      message:'This will permanently delete ' + count + ' message' + (count===1?'':'s') + ' that belong to users who no longer exist. This cannot be undone.',
      confirmText:'Clean ' + count,
    });
    if(!ok) return;
    fetch('/admin/contact/cleanup-orphans', { method:'POST', credentials:'include' })
      .then(r=>r.json()).then(d=>{
        if(d.ok){ showToast('Removed ' + d.removed + ' orphan message(s)', true); setTimeout(()=>location.reload(), 700); }
        else showToast(d.error || 'Failed', false);
      }).catch(()=>showToast('Network error', false));
  }
  async function toggleSuspend(id, name, isSuspended){
    const action = isSuspended ? 'unsuspend' : 'suspend';
    const cfg = isSuspended
      ? { variant:'success', icon:'check', title:'Unsuspend user', confirmText:'Unsuspend', message:'This user will be able to sign in and use the platform again.' }
      : { variant:'warn', icon:'alert', title:'Suspend user', confirmText:'Suspend', message:'This user will be immediately blocked from using the platform. They can be unsuspended later.' };
    const ok = await showConfirm({ ...cfg, subtitle: name });
    if(!ok) return;
    fetch('/admin/users/'+id+'/suspend', {
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      credentials:'include',
      body: JSON.stringify({ suspended: !isSuspended })
    }).then(r=>r.json()).then(d=>{
      if(d.ok){ showToast(name + ' ' + action + 'ed', true); setTimeout(()=>location.reload(), 500); }
      else showToast(d.error || 'Failed', false);
    }).catch(()=>showToast('Network error', false));
  }
  function toggleReplyBox(id){
    const el = document.getElementById('replyForm-'+id);
    if(el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
  }
  var _pickResolve = null;
  function showStatusPicker(){
    return new Promise(resolve => {
      _pickResolve = resolve;
      document.getElementById('statusPicker').classList.add('show');
    });
  }
  function pickStatus(val){
    document.getElementById('statusPicker').classList.remove('show');
    if(_pickResolve){ _pickResolve(val); _pickResolve = null; }
  }
  document.addEventListener('keydown', e => {
    if(e.key === 'Escape' && document.getElementById('statusPicker').classList.contains('show')){
      pickStatus('skip');
    }
  });
  async function sendReply(id){
    const text = document.getElementById('replyText-'+id)?.value?.trim();
    if(!text || text.length < 2){ showToast('Reply too short', false); return; }
    try {
      // If the report is still pending, ask the admin to make a decision first.
      // The reply is then dispatched together with the approve/reject so that
      // the user receives them at the same time.
      const row = document.getElementById('crow-'+id);
      const isPending = row?.dataset?.status === 'pending';
      if (isPending) {
        const choice = await showStatusPicker();
        if (choice !== 'approved' && choice !== 'rejected') {
          showToast('A decision (approve/reject) is required to send the reply', false);
          return;
        }
        const sr = await fetch('/admin/contact/'+id+'/status', {
          method:'PATCH', headers:{'Content-Type':'application/json'}, credentials:'include',
          body: JSON.stringify({ status: choice })
        });
        const sd = await sr.json();
        if(!sd.ok){ showToast(sd.error || 'Failed to update status', false); return; }
      }
      const r = await fetch('/admin/contact/'+id+'/reply', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        credentials:'include',
        body: JSON.stringify({ reply: text })
      });
      const d = await r.json();
      if(!d.ok){ showToast(d.error || 'Failed', false); return; }
      showToast(isPending ? 'Decision saved & reply sent' : 'Reply sent', true);
      setTimeout(()=>location.reload(), 500);
    } catch(e){ showToast('Network error', false); }
  }
  async function deleteConv(id, title){
    const ok = await showConfirm({
      variant:'danger', icon:'trash',
      title:'Delete conversation',
      subtitle:'This cannot be undone',
      message:'The conversation "' + title + '" and all its data will be permanently removed.',
      confirmText:'Delete',
    });
    if(!ok) return;
    fetch('/admin/conversations/'+encodeURIComponent(id), { method:'DELETE', credentials:'include' })
      .then(r=>r.json()).then(d=>{
        if(d.ok){ showToast('Conversation deleted', true); setTimeout(()=>location.reload(), 500); }
        else showToast(d.error || 'Failed', false);
      }).catch(()=>showToast('Network error', false));
  }
  function exportCSV(type){
    const rows = [];
    if(type === 'users'){
      rows.push(['Name','Email','Country','Auth','Suspended','Created'].join(','));
      document.querySelectorAll('.user-row').forEach(el => {
        const name = el.querySelector('.urow-name')?.textContent?.trim() || '';
        const email = el.querySelector('.urow-email')?.textContent?.trim() || '';
        const country = el.querySelector('.urow-country')?.textContent?.trim() || '';
        const auth = el.querySelector('.urow-auth')?.textContent?.trim()?.replace(/,/g,' ') || '';
        const suspended = el.querySelector('.urow-suspended') ? 'Yes' : 'No';
        const created = el.querySelector('.urow-date')?.textContent?.trim() || '';
        rows.push([name,email,country,auth,suspended,created].map(c=>'"'+c.replace(/"/g,'""')+'"').join(','));
      });
    } else {
      rows.push(['Subject','Type','Status','User','Email','Reply','Created'].join(','));
      document.querySelectorAll('.msg-item').forEach(el => {
        const subject = el.querySelector('.msg-subject')?.textContent?.trim() || '';
        const mtype = el.querySelector('.msg-type')?.textContent?.trim() || '';
        const status = el.querySelector('.pill')?.textContent?.trim() || '';
        const user = el.getAttribute('data-user') || '';
        const email = el.getAttribute('data-email') || '';
        const reply = el.querySelector('.reply-text')?.textContent?.trim() || '';
        const created = el.querySelector('.msg-date')?.textContent?.trim() || '';
        rows.push([subject,mtype,status,user,email,reply,created].map(c=>'"'+c.replace(/"/g,'""')+'"').join(','));
      });
    }
    if(rows.length <= 1){ showToast('No data to export', false); return; }
    const blob = new Blob([rows.join('\\n')], { type:'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = type + '_export_' + new Date().toISOString().slice(0,10) + '.csv';
    a.click();
    showToast('CSV exported (' + (rows.length-1) + ' rows)', true);
  }

  // ── Conversation viewer ──
  async function viewConv(id){
    const overlay = document.getElementById('cvOverlay');
    const body = document.getElementById('cvBody');
    const title = document.getElementById('cvTitle');
    const meta = document.getElementById('cvMeta');
    const count = document.getElementById('cvCount');
    body.innerHTML = '<div class="cv-loading">Loading…</div>';
    title.textContent = 'Loading…';
    meta.innerHTML = '';
    count.textContent = '';
    overlay.classList.add('show');
    try {
      const r = await fetch('/admin/conversations/'+encodeURIComponent(id)+'/messages', { credentials:'include' });
      const d = await r.json();
      if(!r.ok){ body.innerHTML = '<div class="cv-empty">'+( d.error || 'Failed to load')+'</div>'; return; }
      title.textContent = d.title || 'Untitled';
      const model = (d.model||'').split('/').pop() || d.model || '—';
      meta.innerHTML = d.user_name + ' · ' + d.user_email + ' · <span class="conv-model">'+model+'</span>';
      count.textContent = d.messages.length + ' message' + (d.messages.length === 1 ? '' : 's');
      if(!d.messages.length){ body.innerHTML = '<div class="cv-empty">No messages</div>'; return; }
      let html = '';
      d.messages.forEach((m,i) => {
        const isUser = m.role === 'user';
        const t = m.timestamp ? new Date(m.timestamp).toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'}) : '';
        if(i > 0 && t) html += '<div class="cv-time">' + t + '</div>';
        const content = m.content.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        const label = isUser ? 'U' : 'AI';
        html += '<div class="cv-msg ' + (isUser ? 'cv-user' : '') + '">' +
          '<div class="cv-avatar">' + label + '</div>' +
          '<div class="cv-bubble">' + content + '</div>' +
        '</div>';
      });
      body.innerHTML = html;
      body.scrollTop = body.scrollHeight;
    } catch(e){
      body.innerHTML = '<div class="cv-empty">Network error</div>';
    }
  }
  function closeCv(){
    document.getElementById('cvOverlay').classList.remove('show');
  }
  document.addEventListener('keydown', e => {
    if(e.key === 'Escape' && document.getElementById('cvOverlay').classList.contains('show')){
      closeCv();
    }
  });

  // ── Tab title with pending count ──
  const pendingN = ${pendingCount};
  if(pendingN > 0) document.title = '(' + pendingN + ') Admin Dashboard · Runner Code';

  // ── Manual refresh ──
  function refreshDashboard(btn){
    btn.classList.add('spinning');
    const active = document.querySelector('.nav-item.active');
    if(active) sessionStorage.setItem('admin_section', active.dataset.section);
    setTimeout(()=>location.reload(), 400);
  }
</script>
</body></html>`);
});

// ── POST /api/contact ────────────────────────────────────────────────────────
app.post('/api/contact', verifyToken, (req, res) => {
  const { type, subject, message } = req.body;
  const allowedTypes = ['bug', 'suggestion', 'request', 'other'];
  if (!type || !allowedTypes.includes(type)) return res.status(400).json({ error: 'Invalid type' });
  if (!subject || typeof subject !== 'string' || subject.trim().length < 2) return res.status(400).json({ error: 'Subject too short' });
  if (!message || typeof message !== 'string' || message.trim().length < 10) return res.status(400).json({ error: 'Message too short' });
  try {
    db.prepare(
      'INSERT INTO contact_messages (type, subject, message, user_name, user_email, user_id, status) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(
      type,
      subject.trim().slice(0, 200),
      message.trim().slice(0, 3000),
      String(req.user.name || 'Unknown').slice(0, 100),
      String(req.user.email || 'Unknown').slice(0, 200),
      req.user.id,
      'pending'
    );
    console.log(`📩 Contact message received: [${type}] ${subject.trim()} from ${req.user.email}`);
    res.json({ ok: true });
  } catch (err) {
    console.error('Contact insert error:', err.message);
    res.status(500).json({ error: 'Failed to save message' });
  }
});

// ── GET /api/contact/my ───────────────────────────────────────────────────────
app.get('/api/contact/my', verifyToken, (req, res) => {
  try {
    // Match by user_id (new reports) OR by email as fallback (old reports before migration)
    const rows = db.prepare(
      `SELECT id, type, subject, status, admin_reply, replied_at, seen_at, created_at FROM contact_messages
       WHERE user_id = ? OR (user_id IS NULL AND user_email = ?)
       ORDER BY created_at DESC`
    ).all(req.user.id, req.user.email);
    res.json(rows);
  } catch (err) {
    console.error('GET /api/contact/my error:', err.message);
    res.status(500).json({ error: 'Failed to load' });
  }
});

// ── GET /api/notifications/count — number of unread admin replies ──────────
app.get('/api/notifications/count', verifyToken, (req, res) => {
  try {
    const row = db.prepare(
      `SELECT COUNT(*) AS count FROM contact_messages
       WHERE (user_id = ? OR (user_id IS NULL AND user_email = ?))
         AND admin_reply IS NOT NULL AND seen_at IS NULL`
    ).get(req.user.id, req.user.email);
    res.json({ count: row?.count || 0 });
  } catch (err) {
    console.error('GET /api/notifications/count error:', err.message);
    res.status(500).json({ error: 'Failed to load' });
  }
});

// ── POST /api/notifications/mark-seen — mark all unread replies as seen ────
app.post('/api/notifications/mark-seen', verifyToken, (req, res) => {
  try {
    db.prepare(
      `UPDATE contact_messages SET seen_at = CURRENT_TIMESTAMP
       WHERE (user_id = ? OR (user_id IS NULL AND user_email = ?))
         AND admin_reply IS NOT NULL AND seen_at IS NULL`
    ).run(req.user.id, req.user.email);
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/notifications/mark-seen error:', err.message);
    res.status(500).json({ error: 'Failed to update' });
  }
});

// ── DELETE /admin/users/:id ───────────────────────────────────────────────────
app.delete('/admin/users/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid id' });
  const user = db.prepare('SELECT id, email FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    db.prepare('DELETE FROM message_media WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM reactions WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM conversations WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM contact_messages WHERE user_id = ? OR (user_id IS NULL AND user_email = ?)').run(id, user.email);
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    console.log(`🗑️  Admin deleted user (id=${id})`);
    res.json({ ok: true });
  } catch (err) {
    console.error('Admin delete error:', err.message, err.stack);
    res.status(500).json({ error: err.message || 'Failed to delete user' });
  }
});

// ── PATCH /admin/contact/:id/status ─────────────────────────────────────────
app.patch('/admin/contact/:id/status', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { status } = req.body;
  if (!id) return res.status(400).json({ error: 'Invalid id' });
  if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    const current = db.prepare('SELECT status FROM contact_messages WHERE id = ?').get(id);
    if (!current) return res.status(404).json({ error: 'Message not found' });
    if (current.status !== 'pending') {
      return res.status(409).json({ error: `Already ${current.status} — decision is final` });
    }
    db.prepare('UPDATE contact_messages SET status = ? WHERE id = ?').run(status, id);
    res.json({ ok: true, status });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to update' });
  }
});

// ── POST /admin/contact/cleanup-orphans ─────────────────────────────────────
// Deletes contact_messages whose owner no longer exists in users table.
// A message is orphan when BOTH:
//   - user_id is NULL or points to a non-existent user, AND
//   - user_email does not match any existing user's email
app.post('/admin/contact/cleanup-orphans', requireAdmin, (req, res) => {
  try {
    const before = db.prepare('SELECT COUNT(*) AS n FROM contact_messages').get().n;
    const info = db.prepare(`
      DELETE FROM contact_messages
      WHERE (user_id IS NULL OR user_id NOT IN (SELECT id FROM users))
        AND (user_email IS NULL OR LOWER(user_email) NOT IN (SELECT LOWER(email) FROM users))
    `).run();
    const after = db.prepare('SELECT COUNT(*) AS n FROM contact_messages').get().n;
    console.log(`🧹 Admin cleaned ${info.changes} orphan contact message(s) (${before} → ${after})`);
    res.json({ ok: true, removed: info.changes, before, after });
  } catch (err) {
    console.error('Cleanup orphans error:', err.message);
    res.status(500).json({ error: err.message || 'Failed to cleanup' });
  }
});

// ── PATCH /admin/users/:id/suspend ─────────────────────────────────────────
app.patch('/admin/users/:id/suspend', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { suspended } = req.body; // true or false
  if (!id) return res.status(400).json({ error: 'Invalid id' });
  if (typeof suspended !== 'boolean') return res.status(400).json({ error: 'suspended must be boolean' });
  const user = db.prepare('SELECT id, name FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.prepare('UPDATE users SET suspended = ? WHERE id = ?').run(suspended ? 1 : 0, id);
  console.log(`${suspended ? '🔒' : '🔓'} Admin ${suspended ? 'suspended' : 'unsuspended'} user (id=${id}, name=${user.name})`);
  res.json({ ok: true, suspended });
});

// ── POST /admin/contact/:id/reply ───────────────────────────────────────────
app.post('/admin/contact/:id/reply', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { reply } = req.body;
  if (!id) return res.status(400).json({ error: 'Invalid id' });
  if (!reply || typeof reply !== 'string' || reply.trim().length < 2) return res.status(400).json({ error: 'Reply too short' });
  const msg = db.prepare('SELECT id, status FROM contact_messages WHERE id = ?').get(id);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  // Replies are only permitted after the report has been reviewed
  // (i.e. marked as approved or rejected). Pending reports cannot receive a reply.
  if (msg.status !== 'approved' && msg.status !== 'rejected') {
    return res.status(400).json({ error: 'Report must be approved or rejected before replying' });
  }
  db.prepare('UPDATE contact_messages SET admin_reply = ?, replied_at = CURRENT_TIMESTAMP, seen_at = NULL WHERE id = ?')
    .run(reply.trim().slice(0, 3000), id);
  console.log(`💬 Admin replied to contact message #${id}`);
  res.json({ ok: true });
});

// ── GET /admin/conversations ─────────────────────────────────────────────────
// Lists all conversations for admin (summary only — no message bodies)
app.get('/admin/conversations', requireAdmin, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT c.id, c.user_id, c.title, c.model, c.created_at, c.updated_at,
             u.name AS user_name, u.email AS user_email,
             json_array_length(c.messages) AS message_count
      FROM conversations c
      LEFT JOIN users u ON u.id = c.user_id
      ORDER BY c.updated_at DESC
    `).all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /admin/conversations/:id ──────────────────────────────────────────
app.delete('/admin/conversations/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ error: 'Invalid id' });
  try {
    const conv = db.prepare('SELECT user_id FROM conversations WHERE id = ?').get(id);
    if (!conv) return res.status(404).json({ error: 'Not found' });
    db.prepare('DELETE FROM reactions WHERE conversation_id = ?').run(id);
    db.prepare('DELETE FROM conversations WHERE id = ?').run(id);
    console.log(`🗑️ Admin deleted conversation (id=${id})`);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/conversations/:id/messages ─────────────────────────────────────
app.get('/admin/conversations/:id/messages', requireAdmin, (req, res) => {
  const { id } = req.params;
  try {
    const conv = db.prepare('SELECT id, title, model, messages, created_at, updated_at, user_id FROM conversations WHERE id = ?').get(id);
    if (!conv) return res.status(404).json({ error: 'Not found' });
    const user = conv.user_id ? db.prepare('SELECT name, email FROM users WHERE id = ?').get(conv.user_id) : null;
    const messages = JSON.parse(conv.messages || '[]');
    res.json({
      id: conv.id,
      title: conv.title,
      model: conv.model,
      user_name: user?.name || 'Unknown',
      user_email: user?.email || '—',
      created_at: conv.created_at,
      updated_at: conv.updated_at,
      messages: messages.map(m => ({ role: m.role, content: m.content, timestamp: m.timestamp })),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/conversations ──────────────────────────────────────────────────
app.get('/api/conversations', verifyToken, (req, res) => {
  const convs = db.prepare(
    'SELECT id, title, model, messages, pinned, draft, project_id, created_at, updated_at FROM conversations WHERE user_id = ? ORDER BY pinned DESC, updated_at DESC'
  ).all(req.user.id);
  res.json(convs.map(c => ({
    ...c,
    pinned: !!c.pinned,
    projectId: c.project_id || null,
    messages: JSON.parse(c.messages),
  })));
});

// ── PUT /api/conversations/:id ────────────────────────────────────────────────
app.put('/api/conversations/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const { title, model, messages, pinned, draft, projectId, project_id, created_at, updated_at } = req.body;
  if (!id || !Array.isArray(messages)) return res.status(400).json({ error: 'Missing fields' });

  // Strip base64 blobs before storing to keep conversations table lean
  const stripped = messages.map(m => ({
    ...m,
    imageUrl: undefined,
    imageUrls: undefined,
    pdfUrl: undefined,
  }));

  // Validate project ownership if a projectId is supplied so users can't
  // attach their conversation to a project owned by someone else.
  const rawProjectId = projectId !== undefined ? projectId : project_id;
  let resolvedProjectId = null;
  if (rawProjectId) {
    const owned = db.prepare('SELECT 1 FROM projects WHERE id = ? AND user_id = ?').get(rawProjectId, req.user.id);
    if (owned) resolvedProjectId = rawProjectId;
  }

  db.prepare(`
    INSERT INTO conversations (id, user_id, title, model, messages, pinned, draft, project_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      title      = excluded.title,
      model      = excluded.model,
      messages   = excluded.messages,
      pinned     = excluded.pinned,
      draft      = excluded.draft,
      project_id = excluded.project_id,
      updated_at = excluded.updated_at
    WHERE conversations.user_id = ?
  `).run(
    id, req.user.id,
    title || 'New Chat',
    model || 'google/gemini-2.5-flash',
    JSON.stringify(stripped),
    pinned ? 1 : 0,
    typeof draft === 'string' ? draft : '',
    resolvedProjectId,
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

// ─── Projects (Claude-style folders with shared instructions) ───────────────
function mapProjectRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    color: row.color,
    instructions: row.instructions,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

app.get('/api/projects', verifyToken, (req, res) => {
  const rows = db.prepare(
    'SELECT id, name, color, instructions, created_at, updated_at FROM projects WHERE user_id = ? ORDER BY updated_at DESC'
  ).all(req.user.id);
  res.json(rows.map(mapProjectRow));
});

app.post('/api/projects', verifyToken, (req, res) => {
  const { id, name, color, instructions } = req.body || {};
  if (!id || typeof id !== 'string') return res.status(400).json({ error: 'Missing id' });
  const trimmedName = (typeof name === 'string' ? name.trim() : '') || 'New Project';
  if (trimmedName.length > 100) return res.status(400).json({ error: 'Name too long' });
  const safeColor = (typeof color === 'string' && /^#[0-9a-fA-F]{6}$/.test(color)) ? color : '#e31e24';
  const safeInstructions = typeof instructions === 'string' ? instructions.slice(0, 20000) : '';
  const now = Date.now();
  try {
    db.prepare(`
      INSERT INTO projects (id, user_id, name, color, instructions, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, req.user.id, trimmedName, safeColor, safeInstructions, now, now);
  } catch (err) {
    return res.status(409).json({ error: 'Project id already exists' });
  }
  res.json({
    id, name: trimmedName, color: safeColor, instructions: safeInstructions,
    createdAt: now, updatedAt: now,
  });
});

app.put('/api/projects/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const row = db.prepare('SELECT id, name, color, instructions FROM projects WHERE id = ? AND user_id = ?')
    .get(id, req.user.id);
  if (!row) return res.status(404).json({ error: 'Not found' });

  const { name, color, instructions } = req.body || {};
  const nextName = (typeof name === 'string' && name.trim()) ? name.trim().slice(0, 100) : row.name;
  const nextColor = (typeof color === 'string' && /^#[0-9a-fA-F]{6}$/.test(color)) ? color : row.color;
  const nextInstructions = typeof instructions === 'string' ? instructions.slice(0, 20000) : row.instructions;
  const now = Date.now();

  db.prepare(`
    UPDATE projects SET name = ?, color = ?, instructions = ?, updated_at = ?
    WHERE id = ? AND user_id = ?
  `).run(nextName, nextColor, nextInstructions, now, id, req.user.id);

  res.json({
    id, name: nextName, color: nextColor, instructions: nextInstructions,
    updatedAt: now,
  });
});

app.delete('/api/projects/:id', verifyToken, (req, res) => {
  // Explicitly cascade: delete all conversations belonging to this project,
  // then the project itself. (Existing FK was ON DELETE SET NULL.)
  const tx = db.transaction((projectId, userId) => {
    db.prepare('DELETE FROM conversations WHERE project_id = ? AND user_id = ?').run(projectId, userId);
    return db.prepare('DELETE FROM projects WHERE id = ? AND user_id = ?').run(projectId, userId);
  });
  const info = tx(req.params.id, req.user.id);
  if (info.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── GET /api/media/:conversationId ──────────────────────────────────────────────
app.get('/api/media/:conversationId', verifyToken, (req, res) => {
  const conv = db.prepare('SELECT messages FROM conversations WHERE id = ? AND user_id = ?')
    .get(req.params.conversationId, req.user.id);
  // Newly-created conversations may not be persisted yet; return empty media
  // instead of 404 so the client doesn't log spurious errors.
  if (!conv) return res.json({});

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

// ── 404 fallback for unknown /api/* routes ───────────────────────────────────
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ── Global error handler ─────────────────────────────────────────────────────
// Prevents stack traces and internal error details from leaking to clients.
app.use((err, req, res, _next) => {
  if (err && typeof err.message === 'string' && err.message.startsWith('CORS:')) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  if (err?.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body too large' });
  }
  console.error('[unhandled]', err?.message || err);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log('\n🚀 Runner Code Auth Server');
  console.log(`📡 Running on: http://0.0.0.0:${PORT}`);
  console.log(`💾 Database:   ${path.join(DB_DIR, 'database.db')}`);
  console.log('\n✅ Ready to accept connections\n');
});
