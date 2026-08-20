import 'dotenv/config';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { db, createSession, deleteSession, getUserBySession } from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const SESSION_COOKIE = 'tuffos_session';
const FRONTEND_ROOT = path.resolve(__dirname, '..');

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '32kb' }));
app.use(cookieParser());

function setSessionCookie(res, sessionId, expiresAt) {
  res.cookie(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    expires: new Date(expiresAt),
    path: '/'
  });
}

function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE, { httpOnly: true, sameSite: 'lax', path: '/' });
}

function auth(req, res, next) {
  const user = getUserBySession(req.cookies[SESSION_COOKIE]);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  req.user = user;
  next();
}

function validateUsername(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9._]{2,15}$/.test(value.trim());
}

function discordConfigured() {
  return Boolean(process.env.DISCORD_CLIENT_ID && process.env.DISCORD_CLIENT_SECRET && process.env.DISCORD_REDIRECT_URI);
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'tuffos-api', version: '0.2.0' });
});

app.get('/api/auth/me', (req, res) => {
  const user = getUserBySession(req.cookies[SESSION_COOKIE]);
  res.json({ authenticated: Boolean(user), user: user || null });
});

app.post('/api/auth/username', (req, res) => {
  const username = String(req.body?.username || '').trim();
  if (!validateUsername(username)) {
    return res.status(400).json({ error: 'Username must be 2–15 characters and use only letters, numbers, dots or underscores.' });
  }

  let user = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username);
  if (!user) {
    const result = db.prepare(`
      INSERT INTO users (username, avatar_url, auth_provider)
      VALUES (?, ?, 'username')
    `).run(username, '/files/images/user.png');
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
  }

  const session = createSession(user.id);
  setSessionCookie(res, session.id, session.expiresAt);
  res.json({ authenticated: true, user: getUserBySession(session.id) });
});

app.get('/api/auth/discord', (_req, res) => {
  if (!discordConfigured()) {
    return res.status(503).json({ error: 'Discord authentication is not configured on this server yet.' });
  }

  const state = crypto.randomBytes(24).toString('hex');
  res.cookie('tuffos_oauth_state', state, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 10 * 60 * 1000,
    path: '/'
  });

  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    redirect_uri: process.env.DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify',
    state
  });

  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

app.get('/api/auth/discord/callback', async (req, res) => {
  if (!discordConfigured()) return res.status(503).send('Discord authentication is not configured.');
  if (!req.query.code || req.query.state !== req.cookies.tuffos_oauth_state) {
    return res.status(400).send('Invalid Discord authentication state.');
  }

  try {
    const tokenResponse = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: String(req.query.code),
        redirect_uri: process.env.DISCORD_REDIRECT_URI
      })
    });

    if (!tokenResponse.ok) throw new Error('Discord token exchange failed.');
    const token = await tokenResponse.json();

    const profileResponse = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: `Bearer ${token.access_token}` }
    });
    if (!profileResponse.ok) throw new Error('Discord profile lookup failed.');

    const profile = await profileResponse.json();
    const avatarUrl = profile.avatar
      ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png?size=256`
      : `https://cdn.discordapp.com/embed/avatars/${Number(BigInt(profile.id) % 5n)}.png`;

    const username = String(profile.username || profile.global_name || `discord_${profile.id}`).slice(0, 15);
    const safeUsername = /^[a-zA-Z0-9._]{2,15}$/.test(username) ? username : `user_${profile.id}`.slice(0, 15);

    let user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(profile.id);
    if (user) {
      db.prepare(`UPDATE users SET username = ?, avatar_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
        .run(safeUsername, avatarUrl, user.id);
    } else {
      let uniqueUsername = safeUsername;
      let suffix = 1;
      while (db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE').get(uniqueUsername)) {
        const suffixText = String(suffix++);
        uniqueUsername = `${safeUsername.slice(0, Math.max(2, 15 - suffixText.length))}${suffixText}`;
      }
      const result = db.prepare(`
        INSERT INTO users (username, avatar_url, auth_provider, discord_id)
        VALUES (?, ?, 'discord', ?)
      `).run(uniqueUsername, avatarUrl, profile.id);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
    }

    const session = createSession(user.id);
    setSessionCookie(res, session.id, session.expiresAt);
    res.clearCookie('tuffos_oauth_state', { httpOnly: true, sameSite: 'lax', path: '/' });
    res.redirect('/home/');
  } catch (error) {
    console.error(error);
    res.status(502).send('Discord authentication could not be completed.');
  }
});

app.post('/api/auth/logout', (req, res) => {
  const sessionId = req.cookies[SESSION_COOKIE];
  if (sessionId) deleteSession(sessionId);
  clearSessionCookie(res);
  res.json({ authenticated: false });
});

app.get('/api/users', auth, (req, res) => {
  const query = String(req.query.q || '').trim();
  const users = query
    ? db.prepare(`SELECT id, username, avatar_url, auth_provider FROM users WHERE id != ? AND username LIKE ? COLLATE NOCASE ORDER BY username LIMIT 25`).all(req.user.id, `%${query}%`)
    : db.prepare(`SELECT id, username, avatar_url, auth_provider FROM users WHERE id != ? ORDER BY created_at DESC LIMIT 25`).all(req.user.id);
  res.json({ users });
});

app.get('/api/tabs', auth, (req, res) => {
  const tabs = db.prepare('SELECT id, title, url, position FROM tabs WHERE user_id = ? ORDER BY position, id').all(req.user.id);
  res.json({ tabs });
});

app.post('/api/tabs', auth, (req, res) => {
  const title = String(req.body?.title || 'New Tab').slice(0, 120);
  const url = String(req.body?.url || 'about:blank').slice(0, 2048);
  const position = Number.isInteger(req.body?.position) ? req.body.position : 0;
  const result = db.prepare('INSERT INTO tabs (user_id, title, url, position) VALUES (?, ?, ?, ?)').run(req.user.id, title, url, position);
  res.status(201).json({ id: result.lastInsertRowid, title, url, position });
});

app.get('/api/favourites', auth, (req, res) => {
  res.json({ favourites: db.prepare('SELECT id, title, url FROM favourites WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id) });
});

app.post('/api/favourites', auth, (req, res) => {
  const title = String(req.body?.title || 'Untitled').slice(0, 120);
  const url = String(req.body?.url || '').slice(0, 2048);
  if (!url) return res.status(400).json({ error: 'A URL is required.' });
  db.prepare('INSERT OR IGNORE INTO favourites (user_id, title, url) VALUES (?, ?, ?)').run(req.user.id, title, url);
  res.status(201).json({ ok: true });
});

app.use(express.static(FRONTEND_ROOT, { index: 'index.html' }));

app.listen(PORT, () => {
  console.log(`TuffOS running on http://localhost:${PORT}`);
});
