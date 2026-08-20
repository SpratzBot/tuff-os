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
  res.cookie(SESSION_COOKIE, sessionId, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', expires: new Date(expiresAt), path: '/' });
}
function clearSessionCookie(res) { res.clearCookie(SESSION_COOKIE, { httpOnly: true, sameSite: 'lax', path: '/' }); }
function auth(req, res, next) {
  const user = getUserBySession(req.cookies[SESSION_COOKIE]);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  req.user = user;
  next();
}
function validateUsername(value) { return typeof value === 'string' && /^[a-zA-Z0-9._]{2,15}$/.test(value.trim()); }
function discordConfigured() { return Boolean(process.env.DISCORD_CLIENT_ID && process.env.DISCORD_CLIENT_SECRET && process.env.DISCORD_REDIRECT_URI); }
function userIsMember(conversationId, userId) { return Boolean(db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?').get(conversationId, userId)); }

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'tuffos-api', version: '0.2.0' }));
app.get('/api/auth/me', (req, res) => { const user = getUserBySession(req.cookies[SESSION_COOKIE]); res.json({ authenticated: Boolean(user), user: user || null }); });

app.post('/api/auth/username', (req, res) => {
  const username = String(req.body?.username || '').trim();
  if (!validateUsername(username)) return res.status(400).json({ error: 'Username must be 2–15 characters and use only letters, numbers, dots or underscores.' });
  let user = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username);
  if (!user) {
    const result = db.prepare(`INSERT INTO users (username, avatar_url, auth_provider) VALUES (?, ?, 'username')`).run(username, '/files/images/user.png');
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
  }
  const session = createSession(user.id);
  setSessionCookie(res, session.id, session.expiresAt);
  res.json({ authenticated: true, user: getUserBySession(session.id) });
});

app.get('/api/auth/discord', (_req, res) => {
  if (!discordConfigured()) return res.status(503).json({ error: 'Discord authentication is not configured on this server yet.' });
  const state = crypto.randomBytes(24).toString('hex');
  res.cookie('tuffos_oauth_state', state, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 10 * 60 * 1000, path: '/' });
  const params = new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID, redirect_uri: process.env.DISCORD_REDIRECT_URI, response_type: 'code', scope: 'identify', state });
  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

app.get('/api/auth/discord/callback', async (req, res) => {
  if (!discordConfigured()) return res.status(503).send('Discord authentication is not configured.');
  if (!req.query.code || req.query.state !== req.cookies.tuffos_oauth_state) return res.status(400).send('Invalid Discord authentication state.');
  try {
    const tokenResponse = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID, client_secret: process.env.DISCORD_CLIENT_SECRET, grant_type: 'authorization_code', code: String(req.query.code), redirect_uri: process.env.DISCORD_REDIRECT_URI })
    });
    if (!tokenResponse.ok) throw new Error('Discord token exchange failed.');
    const token = await tokenResponse.json();
    const profileResponse = await fetch('https://discord.com/api/v10/users/@me', { headers: { Authorization: `Bearer ${token.access_token}` } });
    if (!profileResponse.ok) throw new Error('Discord profile lookup failed.');
    const profile = await profileResponse.json();
    const avatarUrl = profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png?size=256` : `https://cdn.discordapp.com/embed/avatars/${Number(BigInt(profile.id) % 5n)}.png`;
    const rawUsername = String(profile.username || profile.global_name || `discord_${profile.id}`);
    const safeUsername = /^[a-zA-Z0-9._]{2,15}$/.test(rawUsername) ? rawUsername : `user_${profile.id}`.slice(0, 15);
    let user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(profile.id);
    if (user) {
      db.prepare(`UPDATE users SET username = ?, avatar_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(safeUsername, avatarUrl, user.id);
    } else {
      let uniqueUsername = safeUsername; let suffix = 1;
      while (db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE').get(uniqueUsername)) {
        const suffixText = String(suffix++); uniqueUsername = `${safeUsername.slice(0, Math.max(2, 15 - suffixText.length))}${suffixText}`;
      }
      const result = db.prepare(`INSERT INTO users (username, avatar_url, auth_provider, discord_id) VALUES (?, ?, 'discord', ?)`).run(uniqueUsername, avatarUrl, profile.id);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
    }
    const session = createSession(user.id);
    setSessionCookie(res, session.id, session.expiresAt);
    res.clearCookie('tuffos_oauth_state', { httpOnly: true, sameSite: 'lax', path: '/' });
    res.redirect('/home/');
  } catch (error) { console.error(error); res.status(502).send('Discord authentication could not be completed.'); }
});

app.post('/api/auth/logout', (req, res) => { const sessionId = req.cookies[SESSION_COOKIE]; if (sessionId) deleteSession(sessionId); clearSessionCookie(res); res.json({ authenticated: false }); });

app.get('/api/users', auth, (req, res) => {
  const query = String(req.query.q || '').trim();
  const users = query
    ? db.prepare(`SELECT id, username, avatar_url, auth_provider FROM users WHERE id != ? AND username LIKE ? COLLATE NOCASE ORDER BY username LIMIT 25`).all(req.user.id, `%${query}%`)
    : db.prepare(`SELECT id, username, avatar_url, auth_provider FROM users WHERE id != ? ORDER BY created_at DESC LIMIT 25`).all(req.user.id);
  res.json({ users });
});

app.post('/api/conversations', auth, (req, res) => {
  const targetId = Number(req.body?.userId);
  if (!Number.isInteger(targetId) || targetId === req.user.id) return res.status(400).json({ error: 'A different user is required.' });
  if (!db.prepare('SELECT id FROM users WHERE id = ?').get(targetId)) return res.status(404).json({ error: 'User not found.' });
  const existing = db.prepare(`SELECT c.id FROM conversations c JOIN conversation_members a ON a.conversation_id = c.id AND a.user_id = ? JOIN conversation_members b ON b.conversation_id = c.id AND b.user_id = ? WHERE (SELECT COUNT(*) FROM conversation_members m WHERE m.conversation_id = c.id) = 2 LIMIT 1`).get(req.user.id, targetId);
  if (existing) return res.json({ conversationId: existing.id });
  const transaction = db.transaction(() => {
    const conversation = db.prepare('INSERT INTO conversations DEFAULT VALUES').run();
    db.prepare('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?), (?, ?)').run(conversation.lastInsertRowid, req.user.id, conversation.lastInsertRowid, targetId);
    return conversation.lastInsertRowid;
  });
  res.status(201).json({ conversationId: transaction() });
});

app.get('/api/conversations', auth, (req, res) => {
  const conversations = db.prepare(`SELECT c.id, MAX(m.created_at) AS last_message_at, u.id AS other_user_id, u.username AS other_username, u.avatar_url AS other_avatar_url FROM conversations c JOIN conversation_members me ON me.conversation_id = c.id AND me.user_id = ? JOIN conversation_members other ON other.conversation_id = c.id AND other.user_id != ? JOIN users u ON u.id = other.user_id LEFT JOIN messages m ON m.conversation_id = c.id GROUP BY c.id ORDER BY last_message_at DESC, c.id DESC`).all(req.user.id, req.user.id);
  res.json({ conversations });
});

app.get('/api/conversations/:id/messages', auth, (req, res) => {
  const conversationId = Number(req.params.id);
  if (!Number.isInteger(conversationId) || !userIsMember(conversationId, req.user.id)) return res.status(404).json({ error: 'Conversation not found.' });
  const messages = db.prepare(`SELECT m.id, m.sender_id, m.body, m.created_at, u.username, u.avatar_url FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.conversation_id = ? ORDER BY m.id ASC LIMIT 200`).all(conversationId);
  res.json({ messages });
});

app.post('/api/conversations/:id/messages', auth, (req, res) => {
  const conversationId = Number(req.params.id); const body = String(req.body?.body || '').trim();
  if (!Number.isInteger(conversationId) || !userIsMember(conversationId, req.user.id)) return res.status(404).json({ error: 'Conversation not found.' });
  if (!body || body.length > 4000) return res.status(400).json({ error: 'Message must be between 1 and 4000 characters.' });
  const result = db.prepare('INSERT INTO messages (conversation_id, sender_id, body) VALUES (?, ?, ?)').run(conversationId, req.user.id, body);
  const message = db.prepare(`SELECT m.id, m.sender_id, m.body, m.created_at, u.username, u.avatar_url FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.id = ?`).get(result.lastInsertRowid);
  res.status(201).json({ message });
});

app.get('/api/tabs', auth, (req, res) => res.json({ tabs: db.prepare('SELECT id, title, url, position FROM tabs WHERE user_id = ? ORDER BY position, id').all(req.user.id) }));
app.post('/api/tabs', auth, (req, res) => {
  const title = String(req.body?.title || 'New Tab').slice(0, 120); const url = String(req.body?.url || 'about:blank').slice(0, 2048); const position = Number.isInteger(req.body?.position) ? req.body.position : 0;
  const result = db.prepare('INSERT INTO tabs (user_id, title, url, position) VALUES (?, ?, ?, ?)').run(req.user.id, title, url, position);
  res.status(201).json({ id: result.lastInsertRowid, title, url, position });
});
app.get('/api/favourites', auth, (req, res) => res.json({ favourites: db.prepare('SELECT id, title, url FROM favourites WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id) }));
app.post('/api/favourites', auth, (req, res) => {
  const title = String(req.body?.title || 'Untitled').slice(0, 120); const url = String(req.body?.url || '').slice(0, 2048);
  if (!url) return res.status(400).json({ error: 'A URL is required.' });
  db.prepare('INSERT OR IGNORE INTO favourites (user_id, title, url) VALUES (?, ?, ?)').run(req.user.id, title, url);
  res.status(201).json({ ok: true });
});

app.use(express.static(FRONTEND_ROOT, { index: 'index.html' }));
app.listen(PORT, () => console.log(`TuffOS running on http://localhost:${PORT}`));
