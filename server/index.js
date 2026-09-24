import { pbkdf2, timingSafeEqual, randomBytes, createHash } from 'node:crypto';
import { promisify } from 'node:util';

const derive = promisify(pbkdf2);
const SESSION_SECONDS = 60 * 60 * 24 * 7;
const COOKIE = '__Host-cr_session';
const SUBJECTS = new Set(['Maths', 'Science', 'Computer Science', 'English', 'History', 'Languages', 'Other']);
const hash = value => createHash('sha256').update(value).digest('hex');
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const json = (body, status = 200, headers = {}) => Response.json(body, { status, headers });

function secure(response, api) {
  const result = new Response(response.body, response);
  result.headers.set('X-Content-Type-Options', 'nosniff');
  result.headers.set('X-Frame-Options', 'DENY');
  result.headers.set('Referrer-Policy', 'no-referrer');
  result.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  result.headers.set('Strict-Transport-Security', 'max-age=31536000');
  result.headers.set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'none'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  if (api) result.headers.set('Cache-Control', 'no-store');
  return result;
}

// Read with a hard byte cap, even when Content-Length is absent or incorrect.
async function body(request) {
  if (request.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json') throw new HttpError(415, 'Use application/json.');
  const max = 128 * 1024;
  if (Number(request.headers.get('Content-Length')) > max) throw new HttpError(413, 'Request is too large.');
  if (!request.body) throw new HttpError(400, 'A JSON object is required.');
  const reader = request.body.getReader();
  const chunks = []; let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) { await reader.cancel(); throw new HttpError(413, 'Request is too large.'); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try {
    const value = JSON.parse(new TextDecoder().decode(bytes));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error();
    return value;
  } catch { throw new HttpError(400, 'Invalid JSON object.'); }
}
function text(value, min, max, label) {
  if (typeof value !== 'string' || value.trim().length < min || value.trim().length > max) throw new HttpError(400, `${label} must contain ${min}–${max} characters.`);
  return value.trim();
}
function token(request) {
  const match = request.headers.get('Cookie')?.match(/(?:^|;\s*)__Host-cr_session=([a-f0-9]{64})(?:;|$)/);
  return match?.[1];
}
function cookie(value, age = SESSION_SECONDS) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
}
async function account(request, env) {
  const value = token(request);
  if (!value) throw new HttpError(401, 'Sign in to continue.');
  const user = await env.DB.prepare('SELECT u.id, u.username, u.muted FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires > ?').bind(hash(value), Date.now()).first();
  if (!user) throw new HttpError(401, 'Your session has expired. Sign in again.');
  return user;
}
async function rate(env, key, limit, seconds) {
  const now = Date.now();
  const row = await env.DB.prepare(`INSERT INTO rate_limits (key, count, expires) VALUES (?, 1, ?)
    ON CONFLICT(key) DO UPDATE SET count = CASE WHEN rate_limits.expires <= ? THEN 1 ELSE rate_limits.count + 1 END,
    expires = CASE WHEN rate_limits.expires <= ? THEN excluded.expires ELSE rate_limits.expires END
    RETURNING count`).bind(hash(key), now + seconds * 1000, now, now).first();
  if (row.count > limit) throw new HttpError(429, 'Too many requests. Please wait before trying again.');
}
async function newSession(request, env, user) {
  const raw = randomBytes(32).toString('hex');
  const old = token(request);
  const statements = [env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires) VALUES (?, ?, ?)').bind(hash(raw), user.id, Date.now() + SESSION_SECONDS * 1000)];
  if (old) statements.push(env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(hash(old)));
  await env.DB.batch(statements);
  return json({ user: { id: user.id, username: user.username } }, 200, { 'Set-Cookie': cookie(raw) });
}

async function api(request, env, url) {
  const path = url.pathname, method = request.method;
  // Require a browser same-origin JSON request for every mutation, including login/logout.
  if (!['GET', 'HEAD'].includes(method)) {
    if (request.headers.get('Origin') !== url.origin || request.headers.get('Sec-Fetch-Site') === 'cross-site') throw new HttpError(403, 'Cross-origin requests are not allowed.');
  }
  const ip = request.headers.get('CF-Connecting-IP') || 'local';
  if (path === '/api/auth/me' && method === 'GET') {
    try { const user = await account(request, env); return json({ user: { id: user.id, username: user.username } }); }
    catch (error) { if (error.status === 401) return json({ user: null }); throw error; }
  }
  if (['/api/auth/register', '/api/auth/login'].includes(path) && method === 'POST') {
    await rate(env, `auth-ip:${ip}`, 15, 900);
    const data = await body(request);
    const username = text(data.username, 3, 24, 'Username');
    if (!/^[a-zA-Z0-9_]+$/.test(username)) throw new HttpError(400, 'Use letters, numbers and underscores in your username.');
    if (typeof data.password !== 'string' || data.password.length < 12 || data.password.length > 128) throw new HttpError(400, 'Use a password between 12 and 128 characters.');
    await rate(env, `auth-user:${username.toLowerCase()}`, 10, 900);
    if (path.endsWith('register')) {
      const salt = randomBytes(16).toString('hex');
      const passwordHash = (await derive(data.password, salt, 600000, 32, 'sha256')).toString('hex');
      const user = { id: crypto.randomUUID(), username };
      const result = await env.DB.prepare('INSERT INTO users (id, username, password_hash, salt, created) VALUES (?, ?, ?, ?, ?) ON CONFLICT(username) DO NOTHING').bind(user.id, username, passwordHash, salt, Date.now()).run();
      if (!result.meta.changes) throw new HttpError(409, 'That username is unavailable.');
      return newSession(request, env, user);
    }
    const user = await env.DB.prepare('SELECT id, username, password_hash, salt FROM users WHERE username = ?').bind(username).first();
    // Derive even for an unknown account to avoid a cheap username timing oracle.
    const candidate = await derive(data.password, user?.salt || '00000000000000000000000000000000', 600000, 32, 'sha256');
    if (!timingSafeEqual(candidate, Buffer.from(user?.password_hash || '0'.repeat(64), 'hex')) || !user) throw new HttpError(401, 'Incorrect username or password.');
    return newSession(request, env, user);
  }
  if (path === '/api/auth/logout' && method === 'POST') {
    const raw = token(request);
    if (raw) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(hash(raw)).run();
    return json({ ok: true }, 200, { 'Set-Cookie': cookie('', 0) });
  }
  if (path === '/api/sets' && method === 'GET') {
    const offset = Number(url.searchParams.get('offset') || 0);
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > 100000) throw new HttpError(400, 'Invalid page offset.');
    const { results } = await env.DB.prepare('SELECT s.id, s.user_id AS ownerId, s.name, s.subject, s.cards, s.created, u.username AS author FROM study_sets s JOIN users u ON u.id=s.user_id ORDER BY s.created DESC, s.id DESC LIMIT 50 OFFSET ?').bind(offset).all();
    return json(results.map(s => ({ ...s, cards: JSON.parse(s.cards) })));
  }
  if (path === '/api/sets' && method === 'POST') {
    const user = await account(request, env);
    if (user.muted) throw new HttpError(403, 'Publishing is disabled for this account.');
    await rate(env, `sets:${user.id}`, 10, 3600);
    const data = await body(request);
    const name = text(data.name, 1, 120, 'Set title');
    if (!SUBJECTS.has(data.subject)) throw new HttpError(400, 'Choose a valid subject.');
    if (!Array.isArray(data.cards) || !data.cards.length || data.cards.length > 100) throw new HttpError(400, 'A set needs 1–100 cards.');
    const cards = data.cards.map(c => ({ front: text(c?.front, 1, 2000, 'Question'), back: text(c?.back, 1, 4000, 'Answer') }));
    const set = { id: crypto.randomUUID(), ownerId: user.id, name, subject: data.subject, cards, created: Date.now(), author: user.username };
    await env.DB.prepare('INSERT INTO study_sets (id, user_id, name, subject, cards, created) VALUES (?, ?, ?, ?, ?, ?)').bind(set.id, user.id, name, set.subject, JSON.stringify(cards), set.created).run();
    return json(set, 201);
  }
  if (/^\/api\/sets\/[^/]+$/.test(path) && method === 'DELETE') {
    const user = await account(request, env);
    const result = await env.DB.prepare('DELETE FROM study_sets WHERE id = ? AND user_id = ?').bind(path.split('/').pop(), user.id).run();
    if (!result.meta.changes) throw new HttpError(404, 'Set not found or not owned by you.');
    return json({ ok: true });
  }
  if (path === '/api/chat' && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT m.id, m.text, m.created AS time, u.username AS author FROM messages m JOIN users u ON u.id=m.user_id ORDER BY m.created DESC, m.id DESC LIMIT 100').all();
    return json(results.reverse());
  }
  if (path === '/api/chat' && method === 'POST') {
    const user = await account(request, env);
    if (user.muted) throw new HttpError(403, 'Chat is disabled for this account.');
    await rate(env, `chat:${user.id}`, 15, 60);
    const data = await body(request);
    const message = { id: crypto.randomUUID(), author: user.username, text: text(data.text, 1, 2000, 'Message'), time: Date.now() };
    await env.DB.prepare('INSERT INTO messages (id, user_id, text, created) VALUES (?, ?, ?, ?)').bind(message.id, user.id, message.text, message.time).run();
    return json(message, 201);
  }
  throw new HttpError(404, 'Endpoint not found.');
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const isApi = url.pathname.startsWith('/api/');
    try {
      const response = isApi ? await api(request, env, url) : await env.ASSETS.fetch(request);
      return secure(response, isApi);
    } catch (error) {
      if (!(error instanceof HttpError)) console.error(JSON.stringify({ event: 'request_failed', path: url.pathname, requestId: request.headers.get('cf-ray') }));
      return secure(json({ error: error instanceof HttpError ? error.message : 'Something went wrong. Please try again.' }, error.status || 500, error.status === 429 ? { 'Retry-After': '900' } : {}), true);
    }
  },
  async scheduled(_event, env) {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE expires <= ?').bind(Date.now()),
      env.DB.prepare('DELETE FROM rate_limits WHERE expires <= ?').bind(Date.now()),
      env.DB.prepare('DELETE FROM messages WHERE created < ?').bind(Date.now() - 30 * 86400000)
    ]);
  }
};
