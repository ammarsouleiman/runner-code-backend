'use strict';

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '.env') });

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'runner-code-secret-key-change-me';

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
  )
`);

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
app.use(express.json());

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ── JWT Verification Middleware ───────────────────────────────────────────────
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

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
app.post('/api/auth/register', (req, res) => {
  const { name, email, password, country } = req.body;

  if (!name?.trim() || !email?.trim() || !password?.trim()) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
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

  console.log(`✅ New user registered: ${name.trim()} (${normalizedEmail})`);

  res.status(201).json({
    token,
    user: {
      id: result.lastInsertRowid,
      name: name.trim(),
      email: normalizedEmail,
      country: country?.trim() || null,
    },
  });
});

// ── POST /api/auth/login ──────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email?.trim() || !password?.trim()) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = jwt.sign(
    { id: user.id, name: user.name, email: user.email },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  console.log(`✅ User logged in: ${user.name} (${user.email})`);

  res.json({
    token,
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

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
// Stateless JWT — client simply discards the token
app.post('/api/auth/logout', (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// ── DELETE /api/auth/account ──────────────────────────────────────────────────
app.delete('/api/auth/account', verifyToken, (req, res) => {
  const user = db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(req.user.id);
  console.log(`🗑️  Account deleted: ${user.name} (${user.email})`);
  res.json({ message: 'Account deleted successfully' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log('\n🚀 Runner Code Auth Server');
  console.log(`📡 Running on: http://0.0.0.0:${PORT}`);
  console.log(`💾 Database:   ${path.join(__dirname, 'database.db')}`);
  console.log('\n✅ Ready to accept connections\n');
});
