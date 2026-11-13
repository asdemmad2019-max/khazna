// قاعدة بيانات حقيقية SQLite
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const dbPath = process.env.DATABASE_URL && process.env.DATABASE_URL.startsWith('file:')
  ? process.env.DATABASE_URL.replace('file:', '')
  : path.join(__dirname, 'data', 'khazna.db');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'مستثمر',
  created_at TEXT NOT NULL,
  last_login TEXT
);
CREATE TABLE IF NOT EXISTS plans (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, icon TEXT DEFAULT '💎',
  desc TEXT DEFAULT '', tag TEXT DEFAULT '', ord INTEGER DEFAULT 1,
  active INTEGER DEFAULT 1, level INTEGER DEFAULT 50
);
CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, email TEXT NOT NULL,
  plan TEXT NOT NULL, amount TEXT DEFAULT '', type TEXT DEFAULT 'plan',
  status TEXT DEFAULT 'قيد المراجعة', created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT DEFAULT '',
  text TEXT NOT NULL, category TEXT DEFAULT 'استفسار عام', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ads (id TEXT PRIMARY KEY, title TEXT NOT NULL, text TEXT DEFAULT '', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sections (id TEXT PRIMARY KEY, icon TEXT DEFAULT '✨', title TEXT NOT NULL, text TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, by_user TEXT DEFAULT 'نظام', created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_orders_email ON orders(email);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
`);

function getSetting(k, def){ const r=db.prepare('SELECT value FROM settings WHERE key=?').get(k); return r?JSON.parse(r.value):def; }
function setSetting(k, v){ db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k, JSON.stringify(v)); }
function log(action, by){ db.prepare('INSERT INTO logs(action,by_user,created_at) VALUES(?,?,?)').run(action, by||'نظام', new Date().toISOString()); }
module.exports = { db, getSetting, setSetting, log };
