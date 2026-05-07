const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { argon2id, argon2Verify } = require('hash-wasm');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : __dirname;
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
const DATA_FILE = path.join(DATA_DIR, 'chat.json');
const SECRET_FILE = path.join(DATA_DIR, '.jwt-secret');
const ATTACHMENTS_DIR = path.join(DATA_DIR, 'attachments');
if (!fs.existsSync(ATTACHMENTS_DIR)) fs.mkdirSync(ATTACHMENTS_DIR, { recursive: true, mode: 0o700 });
const CORS_ORIGINS = process.env.NODE_ENV === 'production'
  ? [
      'https://chat.niiix.net',
      'capacitor://localhost'
    ]
  : [
      'https://localhost',
      'capacitor://localhost',
      'http://localhost',
      /^http:\/\/localhost(:\d+)?$/
    ];
const JWT_ROTATION_DAYS = parseInt(process.env.JWT_ROTATION_DAYS || '30', 10);
const JWT_ROTATION_SECS = JWT_ROTATION_DAYS * 24 * 60 * 60;
function loadOrInitJwtSecrets() {
  const ts = () => Math.floor(Date.now() / 1000);
  let rec = null;
  if (fs.existsSync(SECRET_FILE)) {
    try {
      const raw = fs.readFileSync(SECRET_FILE, 'utf8').trim();
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        rec = parsed;
      }
      else if (typeof parsed === 'string') {
        rec = { current: { secret: parsed, createdAt: ts() }, previous: null };
      }
    } catch { rec = null; }
  }
  if (!rec || typeof rec.current?.secret !== 'string') {
    rec = {
      current: { secret: crypto.randomBytes(64).toString('hex'), createdAt: ts() },
      previous: null
    };
  }
  const age = ts() - (rec.current.createdAt || 0);
  if (age > JWT_ROTATION_SECS) {
    rec.previous = rec.current;
    rec.current = { secret: crypto.randomBytes(64).toString('hex'), createdAt: ts() };
    console.log('[jwt] rotated signing secret');
  }
  fs.writeFileSync(SECRET_FILE, JSON.stringify(rec), { mode: 0o600 });
  return rec;
}
let jwtSecrets = loadOrInitJwtSecrets();
const JWT_CURRENT  = () => jwtSecrets.current.secret;
const JWT_PREVIOUS = () => jwtSecrets.previous?.secret || null;
const store = (() => {
  const initial = {
    users: [], groups: [], messages: [], contactRequests: [],
    tokenBlocklist: [], loginFailures: {}, attachments: [],
    nextUserId: 1, nextGroupId: 1, nextMessageId: 1, nextRequestId: 1
  };
  let data;
  if (fs.existsSync(DATA_FILE)) {
    try {
      data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      data.groups = data.groups || [];
      data.nextGroupId = data.nextGroupId || 1;
      data.contactRequests = data.contactRequests || [];
      data.nextRequestId = data.nextRequestId || 1;
      data.tokenBlocklist = data.tokenBlocklist || [];
      data.loginFailures = data.loginFailures || {};
      data.attachments = data.attachments || [];
      for (const g of data.groups) g.adminIds = g.adminIds || [];
      for (const u of data.users) {
        u.contactIds = u.contactIds || [];
        u.hiddenMessageIds = u.hiddenMessageIds || [];
      }
    } catch { data = initial; }
  } else {
    data = initial;
  }
  let flushPromise = null;
  let flushQueued = false;
  async function flush() {
    if (flushPromise) { flushQueued = true; return flushPromise; }
    const doFlush = async () => {
      try {
        const tmp = DATA_FILE + '.tmp';
        await fs.promises.writeFile(tmp, JSON.stringify(data), { mode: 0o600 });
        await fs.promises.rename(tmp, DATA_FILE);
      } catch (e) { console.error('persist fail:', e); }
      flushPromise = null;
      if (flushQueued) { flushQueued = false; return flush(); }
    };
    flushPromise = doFlush();
    return flushPromise;
  }
  return { get data() { return data; }, save: flush };
})();
const findUserByName = (n) => {
  const lo = n.toLowerCase();
  return store.data.users.find(u => u.username.toLowerCase() === lo);
};
const findUserById = (id) => store.data.users.find(u => u.id === id);
const findGroupById = (id) => store.data.groups.find(g => g.id === id);
const isGroupMember = (groupId, userId) => {
  const g = findGroupById(groupId);
  return g && g.memberIds.includes(userId);
};
const now = () => Math.floor(Date.now() / 1000);
function logErr(e) {
  if (process.env.NODE_ENV === 'production') {
    console.error('error:', e?.message || String(e));
  } else {
    console.error(e);
  }
}
const userSockets = new Map();
function emitToUser(userId, event, payload) {
  if (typeof io === 'undefined') return;
  const set = userSockets.get(userId);
  if (!set) return;
  for (const sid of set) io.to(sid).emit(event, payload);
}
const app = express();
app.set('trust proxy', process.env.TRUST_PROXY === '0' ? false : 1);
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') return next();
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  });
}
app.use(helmet({
  hsts: process.env.NODE_ENV === 'production'
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net", "'wasm-unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "ws:", "wss:"],
      imgSrc: ["'self'", "data:", "blob:", "https://i.ytimg.com", "https://i9.ytimg.com"],
      mediaSrc: ["'self'", "blob:"],
      frameSrc: ["'self'", "https://www.youtube-nocookie.com"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(cors({ origin: CORS_ORIGINS, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  message: { error: 'Too many attempts, slow down.' }
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, max: 120,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => String(req.user?.id || req.ip),
  message: { error: 'Too many requests, slow down.' }
});
const messageLimiter = rateLimit({
  windowMs: 60 * 1000, max: 60,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => String(req.user?.id || req.ip),
  message: { error: 'Message fetch rate limit exceeded.' }
});
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  let payload;
  const secrets = [JWT_CURRENT(), JWT_PREVIOUS()].filter(Boolean);
  for (const secret of secrets) {
    try { payload = jwt.verify(token, secret); break; } catch {  }
  }
  if (!payload) return res.status(401).json({ error: 'Invalid token' });
  if (payload.jti && store.data.tokenBlocklist.some(b => b.jti === payload.jti)) {
    return res.status(401).json({ error: 'Token revoked' });
  }
  req.user = payload;
  next();
}
function signSessionToken(user) {
  const jti = crypto.randomBytes(16).toString('hex');
  return jwt.sign(
    { id: user.id, username: user.username, jti },
    JWT_CURRENT(),
    { expiresIn: '7d' }
  );
}
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { username, password, publicKey } = req.body || {};
    if (!username || !password || !publicKey)
      return res.status(400).json({ error: 'Missing fields' });
    if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username))
      return res.status(400).json({ error: 'Username: 3-32 chars, letters/numbers/_-' });
    if (typeof password !== 'string' || password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 chars' });
    if (typeof publicKey !== 'string' || publicKey.length < 80 || publicKey.length > 120)
      return res.status(400).json({ error: 'Invalid public key' });
    try {
      const raw = Buffer.from(publicKey.replace(/-/g,'+').replace(/_/g,'/'), 'base64');
      if (raw.length !== 64)
        return res.status(400).json({ error: 'Public key must be 64 bytes (Ed25519 + X25519)' });
    } catch {
      return res.status(400).json({ error: 'Public key is not valid base64' });
    }
    if (findUserByName(username))
      return res.status(409).json({ error: 'Username taken' });
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await argon2id({
      password, salt,
      iterations: 3, memorySize: 65536, parallelism: 4, hashLength: 32,
      outputType: 'encoded'
    });
    const id = store.data.nextUserId++;
    store.data.users.push({
      id, username, passwordHash, publicKey,
      contactIds: [],
      hiddenMessageIds: [],
      createdAt: now()
    });
    await store.save();
    const token = signSessionToken({ id, username });
    res.json({ token, id, username, publicKey });
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
    const lockKey = (username || '').toLowerCase();
    const lock = store.data.loginFailures[lockKey];
    const t = now();
    if (lock && lock.lockedUntil && lock.lockedUntil > t) {
      const wait = Math.ceil((lock.lockedUntil - t) / 60);
      return res.status(429).json({ error: `Too many failed attempts. Try again in ~${wait}min` });
    }
    const user = findUserByName(username);
    const dummyHash = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG';
    const valid = user
      ? await argon2Verify({ password, hash: user.passwordHash })
      : await argon2Verify({ password: 'dummy', hash: dummyHash }).catch(() => false);
    if (!user || !valid) {
      const rec = store.data.loginFailures[lockKey] || { fails: 0, lockedUntil: 0 };
      rec.fails++;
      if (rec.fails >= 10) {
        rec.lockedUntil = t + 15 * 60;
        rec.fails = 0;
      }
      store.data.loginFailures[lockKey] = rec;
      await store.save();
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    delete store.data.loginFailures[lockKey];
    await store.save();
    const token = signSessionToken(user);
    res.json({
      token, id: user.id, username: user.username,
      publicKey: user.publicKey
    });
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
app.get('/api/me', auth, (req, res) => {
  const u = findUserById(req.user.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json({ id: u.id, username: u.username, publicKey: u.publicKey });
});
app.post('/api/logout', auth, async (req, res) => {
  if (req.user.jti) {
    store.data.tokenBlocklist.push({
      jti: req.user.jti,
      exp: req.user.exp || (now() + 7 * 24 * 60 * 60)
    });
    await store.save();
  }
  res.json({ ok: true });
});
function knownUserIds(meId) {
  const me = findUserById(meId);
  if (!me) return new Set();
  const ids = new Set(me.contactIds || []);
  for (const g of store.data.groups) {
    if (!g.memberIds.includes(meId)) continue;
    for (const m of g.memberIds) if (m !== meId) ids.add(m);
  }
  for (const r of store.data.contactRequests) {
    if (r.fromUserId === meId) ids.add(r.toUserId);
    if (r.toUserId === meId) ids.add(r.fromUserId);
  }
  return ids;
}
app.get('/api/users', auth, (req, res) => {
  const q = (req.query.q || '').toString().toLowerCase();
  const meId = req.user.id;
  const known = knownUserIds(meId);
  let rows = store.data.users.filter(u => known.has(u.id));
  if (q) rows = rows.filter(u => u.username.toLowerCase().includes(q));
  rows.sort((a, b) => a.username.localeCompare(b.username));
  res.json(rows.slice(0, 200).map(u => ({
    id: u.id, username: u.username, publicKey: u.publicKey
  })));
});
const fingerprintLimiter = rateLimit({
  windowMs: 60 * 1000, max: 15,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many lookups, slow down.' }
});
async function getFingerprintFor(user) {
  if (user._fp) return user._fp;
  try {
    return null;
  } catch { return null; }
}
function fingerprintFor(user) {
  try {
    const raw = Buffer.from(
      user.publicKey.replace(/-/g, '+').replace(/_/g, '/'), 'base64'
    );
    if (raw.length !== 64) return null;
    const signPub = raw.slice(0, 32); 
    const hash = crypto.createHash('sha256').update(signPub).digest('hex').toUpperCase();
    return hash;
  } catch { return null; }
}
app.get('/api/users/by-fingerprint', auth, fingerprintLimiter, async (req, res) => {
  try {
    const raw = (req.query.fp || '').toString().toUpperCase().replace(/[\s:]/g, '');
    if (!/^[0-9A-F]{64}$/.test(raw))
      return res.status(400).json({ error: 'Fingerprint must be 64 hex chars' });
    for (const u of store.data.users) {
      if (u.id === req.user.id) continue;
      const fp = fingerprintFor(u);
      if (fp === raw) {
        return res.json({ id: u.id, username: u.username, publicKey: u.publicKey, fingerprint: fp });
      }
    }
    res.status(404).json({ error: 'No user with that fingerprint' });
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
function projectRequest(r) {
  const from = findUserById(r.fromUserId);
  const to = findUserById(r.toUserId);
  return {
    id: r.id,
    from: from ? { id: from.id, username: from.username, publicKey: from.publicKey } : null,
    to: to ? { id: to.id, username: to.username, publicKey: to.publicKey } : null,
    createdAt: r.createdAt
  };
}
app.get('/api/contacts/requests', auth, (req, res) => {
  const meId = req.user.id;
  const incoming = store.data.contactRequests
    .filter(r => r.toUserId === meId)
    .map(projectRequest);
  const outgoing = store.data.contactRequests
    .filter(r => r.fromUserId === meId)
    .map(projectRequest);
  res.json({ incoming, outgoing });
});
app.post('/api/contacts/requests', auth, async (req, res) => {
  try {
    const meId = req.user.id;
    const targetId = Number(req.body?.userId);
    if (!Number.isInteger(targetId)) return res.status(400).json({ error: 'Bad user id' });
    if (targetId === meId) return res.status(400).json({ error: 'Cannot add yourself' });
    const me = findUserById(meId);
    const target = findUserById(targetId);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if ((me.contactIds || []).includes(targetId))
      return res.status(409).json({ error: 'Already in your contacts' });
    const existing = store.data.contactRequests.find(
      r => r.fromUserId === meId && r.toUserId === targetId
    );
    if (existing) return res.status(409).json({ error: 'Request already pending' });
    const reverse = store.data.contactRequests.find(
      r => r.fromUserId === targetId && r.toUserId === meId
    );
    if (reverse) {
      const meRec = findUserById(meId);
      meRec.contactIds = meRec.contactIds || [];
      target.contactIds = target.contactIds || [];
      if (!meRec.contactIds.includes(targetId)) meRec.contactIds.push(targetId);
      if (!target.contactIds.includes(meId)) target.contactIds.push(meId);
      store.data.contactRequests = store.data.contactRequests.filter(r => r !== reverse);
      await store.save();
      const meBrief = { id: meRec.id, username: meRec.username, publicKey: meRec.publicKey };
      const tBrief = { id: target.id, username: target.username, publicKey: target.publicKey };
      emitToUser(meId, 'contact-added', tBrief);
      emitToUser(targetId, 'contact-added', meBrief);
      return res.json({ accepted: true, contact: tBrief });
    }
    const r = {
      id: store.data.nextRequestId++,
      fromUserId: meId,
      toUserId: targetId,
      createdAt: now()
    };
    store.data.contactRequests.push(r);
    await store.save();
    emitToUser(targetId, 'contact-request', projectRequest(r));
    res.json({ pending: true, request: projectRequest(r) });
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
app.post('/api/contacts/requests/:id/accept', auth, async (req, res) => {
  try {
    const meId = req.user.id;
    const rid = parseInt(req.params.id, 10);
    const idx = store.data.contactRequests.findIndex(r => r.id === rid);
    if (idx < 0) return res.status(404).json({ error: 'Request not found' });
    const r = store.data.contactRequests[idx];
    if (r.toUserId !== meId) return res.status(403).json({ error: 'Not your request' });
    const me = findUserById(meId);
    const from = findUserById(r.fromUserId);
    if (!from) {
      store.data.contactRequests.splice(idx, 1);
      await store.save();
      return res.status(404).json({ error: 'Sender no longer exists' });
    }
    me.contactIds = me.contactIds || [];
    from.contactIds = from.contactIds || [];
    if (!me.contactIds.includes(from.id)) me.contactIds.push(from.id);
    if (!from.contactIds.includes(me.id)) from.contactIds.push(me.id);
    store.data.contactRequests.splice(idx, 1);
    await store.save();
    const meBrief = { id: me.id, username: me.username, publicKey: me.publicKey };
    const fromBrief = { id: from.id, username: from.username, publicKey: from.publicKey };
    emitToUser(meId, 'contact-added', fromBrief);
    emitToUser(from.id, 'contact-added', meBrief);
    res.json({ contact: fromBrief });
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
app.post('/api/contacts/requests/:id/reject', auth, async (req, res) => {
  try {
    const meId = req.user.id;
    const rid = parseInt(req.params.id, 10);
    const idx = store.data.contactRequests.findIndex(r => r.id === rid);
    if (idx < 0) return res.status(404).json({ error: 'Request not found' });
    const r = store.data.contactRequests[idx];
    if (r.toUserId !== meId && r.fromUserId !== meId)
      return res.status(403).json({ error: 'Not your request' });
    store.data.contactRequests.splice(idx, 1);
    await store.save();
    res.json({ ok: true });
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
app.delete('/api/contacts/:userId', auth, async (req, res) => {
  try {
    const meId = req.user.id;
    const targetId = parseInt(req.params.userId, 10);
    const me = findUserById(meId);
    const them = findUserById(targetId);
    me.contactIds = (me.contactIds || []).filter(id => id !== targetId);
    if (them) them.contactIds = (them.contactIds || []).filter(id => id !== meId);
    await store.save();
    if (them) emitToUser(targetId, 'contact-removed', { userId: meId });
    res.json({ ok: true });
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
function projectGroup(g) {
  return {
    id: g.id,
    name: g.name,
    creatorId: g.creatorId,
    adminIds: g.adminIds || [],
    members: g.memberIds.map(mid => {
      const m = findUserById(mid);
      return m ? { id: m.id, username: m.username, publicKey: m.publicKey } : null;
    }).filter(Boolean),
    createdAt: g.createdAt
  };
}
const canManageMembers = (g, userId) =>
  g.creatorId === userId || (g.adminIds || []).includes(userId);
const canPromote = (g, userId) => g.creatorId === userId;
app.get('/api/groups', auth, (req, res) => {
  const meId = req.user.id;
  const myGroups = store.data.groups.filter(g => g.memberIds.includes(meId));
  res.json(myGroups.map(projectGroup));
});
app.post('/api/groups', auth, async (req, res) => {
  try {
    const { name, memberIds } = req.body || {};
    if (typeof name !== 'string' || name.trim().length < 1 || name.length > 64)
      return res.status(400).json({ error: 'Name must be 1-64 chars' });
    if (!Array.isArray(memberIds) || memberIds.length < 1)
      return res.status(400).json({ error: 'Need at least 1 other member' });
    if (memberIds.length > 50)
      return res.status(400).json({ error: 'Group too large (max 50 members)' });
    const meId = req.user.id;
    const uniqueIds = [...new Set([meId, ...memberIds.map(Number)])];
    for (const id of uniqueIds) {
      if (!findUserById(id)) return res.status(400).json({ error: `Unknown user: ${id}` });
    }
    const group = {
      id: store.data.nextGroupId++,
      name: name.trim(),
      creatorId: meId,
      adminIds: [],
      memberIds: uniqueIds,
      createdAt: now()
    };
    store.data.groups.push(group);
    await store.save();
    const payload = projectGroup(group);
    for (const mid of uniqueIds) {
      const sockets = userSockets.get(mid);
      if (sockets) for (const sid of sockets) io.to(sid).emit('group-created', payload);
    }
    res.json(payload);
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
function broadcastGroupUpdate(group, recipientIds, eventName = 'group-updated') {
  const payload = projectGroup(group);
  for (const mid of recipientIds) {
    const sockets = userSockets.get(mid);
    if (sockets) for (const sid of sockets) io.to(sid).emit(eventName, payload);
  }
}
app.post('/api/groups/:id/members', auth, async (req, res) => {
  try {
    const gid = parseInt(req.params.id, 10);
    const meId = req.user.id;
    const g = findGroupById(gid);
    if (!g) return res.status(404).json({ error: 'Group not found' });
    if (!canManageMembers(g, meId))
      return res.status(403).json({ error: 'Only creator or admins can add members' });
    const { memberIds } = req.body || {};
    if (!Array.isArray(memberIds) || memberIds.length < 1)
      return res.status(400).json({ error: 'No members supplied' });
    if (g.memberIds.length + memberIds.length > 50)
      return res.status(400).json({ error: 'Group would exceed 50 members' });
    const newIds = [];
    for (const raw of memberIds) {
      const id = Number(raw);
      if (!Number.isInteger(id)) return res.status(400).json({ error: 'Bad member id' });
      if (!findUserById(id)) return res.status(400).json({ error: `Unknown user: ${id}` });
      if (g.memberIds.includes(id)) continue; 
      newIds.push(id);
    }
    if (newIds.length === 0) return res.status(400).json({ error: 'All listed users are already members' });
    const audience = [...new Set([...g.memberIds, ...newIds])];
    g.memberIds = audience;
    await store.save();
    broadcastGroupUpdate(g, audience);
    res.json(projectGroup(g));
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
app.delete('/api/groups/:id/members/:userId', auth, async (req, res) => {
  try {
    const gid = parseInt(req.params.id, 10);
    const targetId = parseInt(req.params.userId, 10);
    const meId = req.user.id;
    const g = findGroupById(gid);
    if (!g) return res.status(404).json({ error: 'Group not found' });
    if (!g.memberIds.includes(targetId))
      return res.status(404).json({ error: 'User is not a member' });
    if (targetId === g.creatorId)
      return res.status(403).json({ error: 'Cannot remove the group creator' });
    if (targetId !== meId && !canManageMembers(g, meId))
      return res.status(403).json({ error: 'Only creator or admins can remove others' });
    if (targetId !== meId && (g.adminIds || []).includes(targetId) && g.creatorId !== meId)
      return res.status(403).json({ error: 'Only creator can remove an admin' });
    const audience = [...g.memberIds];
    g.memberIds = g.memberIds.filter(id => id !== targetId);
    g.adminIds = (g.adminIds || []).filter(id => id !== targetId);
    await store.save();
    broadcastGroupUpdate(g, audience);
    res.json(projectGroup(g));
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
app.post('/api/groups/:id/admins', auth, async (req, res) => {
  try {
    const gid = parseInt(req.params.id, 10);
    const { userId } = req.body || {};
    const targetId = Number(userId);
    const meId = req.user.id;
    const g = findGroupById(gid);
    if (!g) return res.status(404).json({ error: 'Group not found' });
    if (!canPromote(g, meId))
      return res.status(403).json({ error: 'Only the creator can promote members' });
    if (!Number.isInteger(targetId)) return res.status(400).json({ error: 'Bad user id' });
    if (!g.memberIds.includes(targetId))
      return res.status(400).json({ error: 'User is not a member' });
    if (targetId === g.creatorId)
      return res.status(400).json({ error: 'Creator is implicitly admin' });
    g.adminIds = g.adminIds || [];
    if (g.adminIds.includes(targetId))
      return res.status(400).json({ error: 'Already an admin' });
    g.adminIds.push(targetId);
    await store.save();
    broadcastGroupUpdate(g, g.memberIds);
    res.json(projectGroup(g));
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
app.delete('/api/groups/:id/admins/:userId', auth, async (req, res) => {
  try {
    const gid = parseInt(req.params.id, 10);
    const targetId = parseInt(req.params.userId, 10);
    const meId = req.user.id;
    const g = findGroupById(gid);
    if (!g) return res.status(404).json({ error: 'Group not found' });
    if (!canPromote(g, meId))
      return res.status(403).json({ error: 'Only the creator can demote admins' });
    if (!(g.adminIds || []).includes(targetId))
      return res.status(400).json({ error: 'User is not an admin' });
    g.adminIds = g.adminIds.filter(id => id !== targetId);
    await store.save();
    broadcastGroupUpdate(g, g.memberIds);
    res.json(projectGroup(g));
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
function projectMessageFor(m, userId) {
  const slot = m.ciphertexts.find(c => c.recipientId === userId);
  if (!slot) return null;
  let attachment = null;
  if (m.attachment) {
    if (m.attachment.expired) {
      attachment = {
        attachmentId: m.attachment.attachmentId,
        filename: m.attachment.filename,
        mime: m.attachment.mime,
        size: m.attachment.size,
        expired: true
      };
    } else {
      const keySlot = m.attachment.keyCiphertexts.find(k => k.recipientId === userId);
      if (keySlot) {
        const att = store.data.attachments.find(a => a.id === m.attachment.attachmentId);
        attachment = {
          attachmentId: m.attachment.attachmentId,
          filename: m.attachment.filename,
          mime: m.attachment.mime,
          size: m.attachment.size,
          keyCiphertext: keySlot.ciphertext,
          expiresAt: att?.expiresAt || null,
          firstViewedAt: att?.firstViewedAt || null
        };
      }
    }
  }
  return {
    id: m.id,
    senderId: m.senderId,
    conv: m.conv,
    ciphertext: slot.ciphertext,
    createdAt: m.createdAt,
    deleteAt: m.deleteAt || null,
    attachment
  };
}
app.get('/api/messages/dm/:userId', auth, messageLimiter, (req, res) => {
  const otherId = parseInt(req.params.userId, 10);
  if (!Number.isInteger(otherId)) return res.status(400).json({ error: 'Bad id' });
  const meId = req.user.id;
  const me = findUserById(meId);
  const hidden = new Set(me?.hiddenMessageIds || []);
  const t = now();
  const out = store.data.messages
    .filter(m => {
      if (m.deleteAt && m.deleteAt <= t) return false;
      if (hidden.has(m.id)) return false;
      if (m.senderId === meId && m.conv === `u:${otherId}`) return true;
      if (m.senderId === otherId && m.conv === `u:${meId}`) return true;
      return false;
    })
    .sort((a, b) => a.createdAt - b.createdAt || a.id - b.id)
    .map(m => projectMessageFor(m, meId))
    .filter(Boolean);
  res.json(out);
});
app.get('/api/messages/group/:groupId', auth, messageLimiter, (req, res) => {
  const gid = parseInt(req.params.groupId, 10);
  if (!Number.isInteger(gid)) return res.status(400).json({ error: 'Bad id' });
  const meId = req.user.id;
  if (!isGroupMember(gid, meId)) return res.status(403).json({ error: 'Not a member' });
  const me = findUserById(meId);
  const hidden = new Set(me?.hiddenMessageIds || []);
  const t = now();
  const out = store.data.messages
    .filter(m => m.conv === `g:${gid}` && (!m.deleteAt || m.deleteAt > t) && !hidden.has(m.id))
    .sort((a, b) => a.createdAt - b.createdAt || a.id - b.id)
    .map(m => projectMessageFor(m, meId))
    .filter(Boolean);
  res.json(out);
});
app.delete('/api/messages/dm/:userId', auth, async (req, res) => {
  try {
    const meId = req.user.id;
    const otherId = parseInt(req.params.userId, 10);
    const mode = (req.query.mode || 'for-me').toString();
    if (!Number.isInteger(otherId)) return res.status(400).json({ error: 'Bad id' });
    if (!['for-me', 'for-everyone'].includes(mode))
      return res.status(400).json({ error: 'Bad mode' });
    const me = findUserById(meId);
    const matchingIds = [];
    const matchingFromMe = [];
    for (const m of store.data.messages) {
      const isMine = m.senderId === meId && m.conv === `u:${otherId}`;
      const isTheirs = m.senderId === otherId && m.conv === `u:${meId}`;
      if (isMine || isTheirs) matchingIds.push(m.id);
      if (isMine) matchingFromMe.push(m.id);
    }
    if (mode === 'for-me') {
      me.hiddenMessageIds = [...new Set([...(me.hiddenMessageIds || []), ...matchingIds])];
      await store.save();
      emitToUser(meId, 'messages-hidden', { conv: `u:${otherId}`, messageIds: matchingIds });
      return res.json({ hidden: matchingIds.length });
    }
    const idSet = new Set(matchingFromMe);
    store.data.messages = store.data.messages.filter(m => !idSet.has(m.id));
    await store.save();
    const event = { messageIds: matchingFromMe, conv: `u:${otherId}` };
    emitToUser(meId, 'messages-deleted-bulk', event);
    emitToUser(otherId, 'messages-deleted-bulk', { ...event, conv: `u:${meId}` });
    res.json({ deleted: matchingFromMe.length });
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
app.delete('/api/groups/:id', auth, async (req, res) => {
  try {
    const gid = parseInt(req.params.id, 10);
    const meId = req.user.id;
    const g = findGroupById(gid);
    if (!g) return res.status(404).json({ error: 'Group not found' });
    if (g.creatorId !== meId)
      return res.status(403).json({ error: 'Only the creator can delete the group' });
    const memberIds = [...g.memberIds];
    store.data.messages = store.data.messages.filter(m => m.conv !== `g:${gid}`);
    store.data.groups = store.data.groups.filter(x => x.id !== gid);
    await store.save();
    for (const mid of memberIds) emitToUser(mid, 'group-deleted', { groupId: gid });
    res.json({ ok: true });
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
const ATTACHMENT_MAX = 100 * 1024 * 1024; 
const ACCOUNT_QUOTA = 1024 * 1024 * 1024; 
const ATTACHMENT_VIEWED_TTL = 2 * 24 * 60 * 60;   
const ATTACHMENT_UNVIEWED_TTL = 7 * 24 * 60 * 60; 
const uploadLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many uploads, slow down.' }
});
function userTotalUploadedBytes(userId) {
  return store.data.attachments
    .filter(a => a.ownerId === userId)
    .reduce((sum, a) => sum + (a.size || 0), 0);
}
const ALLOWED_MIME_TYPES = new Set([
  'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
  'video/mp4', 'video/webm', 'video/ogg',
  'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm',
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/plain', 'text/csv',
  'application/zip', 'application/x-zip-compressed',
  'application/octet-stream'
]);
function sanitizeFilename(raw) {
  const base = path.basename(String(raw || 'file').replace(/\0/g, ''));
  return base.slice(0, 255) || 'file';
}
app.post('/api/attachments',
  auth,
  uploadLimiter,
  express.raw({ type: 'application/octet-stream', limit: ATTACHMENT_MAX + 1024 }),
  async (req, res) => {
    try {
      const meId = req.user.id;
      const { filename, mime } = req.query;
      const buf = req.body;
      if (!Buffer.isBuffer(buf) || buf.length === 0)
        return res.status(400).json({ error: 'Empty body' });
      if (buf.length > ATTACHMENT_MAX)
        return res.status(413).json({ error: `File too big (max ${Math.round(ATTACHMENT_MAX/1024/1024)} MB)` });
      const safeFilename = sanitizeFilename(filename);
      const safeMime = (mime || 'application/octet-stream').toString().slice(0, 128).toLowerCase();
      if (!ALLOWED_MIME_TYPES.has(safeMime)) {
        return res.status(415).json({ error: `File type not allowed: ${safeMime}` });
      }
      const used = userTotalUploadedBytes(meId);
      if (used + buf.length > ACCOUNT_QUOTA) {
        return res.status(413).json({
          error: `Account quota exceeded (${Math.round(ACCOUNT_QUOTA/1024/1024)} MB total)`
        });
      }
      const id = crypto.randomBytes(16).toString('hex');
      await fs.promises.writeFile(path.join(ATTACHMENTS_DIR, `${id}.bin`), buf, { mode: 0o600 });
      const t = now();
      const rec = {
        id,
        ownerId: meId,
        filename: safeFilename,
        mime: safeMime,
        size: buf.length,
        refs: [], 
        createdAt: t,
        expiresAt: t + ATTACHMENT_UNVIEWED_TTL,
        firstViewedAt: null,
        viewedBy: []  
      };
      store.data.attachments.push(rec);
      await store.save();
      res.json({ id, filename: safeFilename, mime: safeMime, size: buf.length });
    } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
  }
);
app.get('/api/attachments/:id', auth, async (req, res) => {
  try {
    const id = req.params.id;
    if (!/^[0-9a-f]{32}$/.test(id)) return res.status(400).json({ error: 'Bad id' });
    const meId = req.user.id;
    const att = store.data.attachments.find(a => a.id === id);
    if (!att) return res.status(404).json({ error: 'Not found' });
    let allowed = att.ownerId === meId;
    if (!allowed) {
      for (const msgId of att.refs) {
        const m = store.data.messages.find(x => x.id === msgId);
        if (!m) continue;
        if (m.ciphertexts.some(c => c.recipientId === meId)) { allowed = true; break; }
      }
    }
    if (!allowed) return res.status(403).json({ error: 'Not authorized for this attachment' });
    const file = path.join(ATTACHMENTS_DIR, `${id}.bin`);
    if (!fs.existsSync(file)) return res.status(404).json({ error: 'Blob missing' });
    const isOwnerView = att.ownerId === meId;
    if (!isOwnerView) {
      att.viewedBy = att.viewedBy || [];
      if (!att.viewedBy.includes(meId)) att.viewedBy.push(meId);
      if (!att.firstViewedAt) {
        att.firstViewedAt = now();
        const newExpiry = att.firstViewedAt + ATTACHMENT_VIEWED_TTL;
        att.expiresAt = Math.min(att.expiresAt || newExpiry, newExpiry);
      }
      store.save();
    }
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Filename', encodeURIComponent(att.filename));
    res.setHeader('X-Mime', att.mime);
    res.setHeader('Content-Length', att.size);
    fs.createReadStream(file).pipe(res);
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
app.delete('/api/account', auth, async (req, res) => {
  try {
    const meId = req.user.id;
    const me = findUserById(meId);
    if (!me) return res.status(404).json({ error: 'Account not found' });
    const affectedUserIds = new Set();
    const myGroups = store.data.groups.filter(g => g.memberIds.includes(meId));
    for (const g of myGroups) for (const mid of g.memberIds) if (mid !== meId) affectedUserIds.add(mid);
    for (const m of store.data.messages) {
      if (m.senderId === meId && m.conv.startsWith('u:')) affectedUserIds.add(parseInt(m.conv.slice(2), 10));
      if (m.conv === `u:${meId}`) affectedUserIds.add(m.senderId);
    }
    for (const u of store.data.users) {
      if (u.id === meId) continue;
      if ((u.contactIds || []).includes(meId)) affectedUserIds.add(u.id);
    }
    for (const g of myGroups) {
      g.memberIds = g.memberIds.filter(id => id !== meId);
      g.adminIds = (g.adminIds || []).filter(id => id !== meId);
      if (g.creatorId === meId) {
        const newCreator = (g.adminIds[0]) || g.memberIds[0];
        if (newCreator) {
          g.creatorId = newCreator;
          g.adminIds = g.adminIds.filter(id => id !== newCreator);
        } else {
          store.data.messages = store.data.messages.filter(m => m.conv !== `g:${g.id}`);
          store.data.groups = store.data.groups.filter(x => x.id !== g.id);
        }
      }
    }
    store.data.messages = store.data.messages.filter(m => m.senderId !== meId);
    for (const m of store.data.messages) {
      m.ciphertexts = m.ciphertexts.filter(c => c.recipientId !== meId);
    }
    for (const u of store.data.users) {
      u.contactIds = (u.contactIds || []).filter(id => id !== meId);
    }
    store.data.contactRequests = store.data.contactRequests.filter(
      r => r.fromUserId !== meId && r.toUserId !== meId
    );
    store.data.users = store.data.users.filter(u => u.id !== meId);
    await store.save();
    for (const aid of affectedUserIds) emitToUser(aid, 'account-deleted', { userId: meId });
    const sockets = userSockets.get(meId);
    if (sockets) for (const sid of sockets) io.sockets.sockets.get(sid)?.disconnect(true);
    res.json({ ok: true });
  } catch (e) { logErr(e); res.status(500).json({ error: 'Server error' }); }
});
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 4e6,
  cors: { origin: CORS_ORIGINS, credentials: true }
});
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('No token'));
  let payload;
  const secrets = [JWT_CURRENT(), JWT_PREVIOUS()].filter(Boolean);
  for (const secret of secrets) {
    try { payload = jwt.verify(token, secret); break; } catch {  }
  }
  if (!payload) return next(new Error('Invalid token'));
  if (payload.jti && store.data.tokenBlocklist.some(b => b.jti === payload.jti))
    return next(new Error('Token revoked'));
  if (!findUserById(payload.id)) return next(new Error('Account not found'));
  socket.user = payload;
  next();
});
io.on('connection', (socket) => {
  const userId = socket.user.id;
  if (!userSockets.has(userId)) userSockets.set(userId, new Set());
  userSockets.get(userId).add(socket.id);
  if (userSockets.get(userId).size > 4) {
    const oldest = [...userSockets.get(userId)][0];
    if (oldest && oldest !== socket.id) {
      io.sockets.sockets.get(oldest)?.disconnect(true);
    }
  }
  const sendTimestamps = [];
  function checkSendRate() {
    const t = Date.now();
    const cutoff = t - 10_000;
    while (sendTimestamps.length && sendTimestamps[0] < cutoff) sendTimestamps.shift();
    if (sendTimestamps.length >= 20) return false;
    sendTimestamps.push(t);
    return true;
  }
  const meKnown = knownUserIds(userId);
  for (const otherId of meKnown) {
    if (!userSockets.has(otherId)) continue;
    for (const sid of userSockets.get(otherId)) {
      io.to(sid).emit('presence', { userId, online: true });
    }
  }
  const visibleOnline = [...userSockets.keys()].filter(id => meKnown.has(id) || id === userId);
  socket.emit('presence-list', visibleOnline);
  socket.on('send-message', async (data, ack) => {
    if (!checkSendRate()) return ack?.({ ok: false, error: 'Slow down — too many messages' });
    try {
      const { conv, ciphertexts, deleteAt, attachment } = data || {};
      if (typeof conv !== 'string' || !/^(u|g):\d+$/.test(conv))
        return ack?.({ ok: false, error: 'Bad conv' });
      if (!Array.isArray(ciphertexts) || ciphertexts.length === 0 || ciphertexts.length > 60)
        return ack?.({ ok: false, error: 'Bad ciphertexts' });
      for (const c of ciphertexts) {
        if (!Number.isInteger(c.recipientId)) return ack?.({ ok: false, error: 'Bad recipientId' });
        if (typeof c.ciphertext !== 'string' || c.ciphertext.length > 500_000) return ack?.({ ok: false, error: 'Bad ciphertext' });
        if (!/^[A-Za-z0-9_-]+$/.test(c.ciphertext)) return ack?.({ ok: false, error: 'Bad ciphertext encoding' });
      }
      if (deleteAt != null) {
        if (!Number.isInteger(deleteAt) || deleteAt <= now() || deleteAt > now() + 60 * 60 * 24 * 30)
          return ack?.({ ok: false, error: 'Bad deleteAt' });
      }
      const senderInCiphertexts = ciphertexts.some(c => c.recipientId === userId);
      if (!senderInCiphertexts)
        return ack?.({ ok: false, error: 'Sender must be among recipients' });
      let attRec = null;
      if (attachment) {
        if (typeof attachment.attachmentId !== 'string' ||
            !/^[0-9a-f]{32}$/.test(attachment.attachmentId))
          return ack?.({ ok: false, error: 'Bad attachment id' });
        attRec = store.data.attachments.find(a => a.id === attachment.attachmentId);
        if (!attRec) return ack?.({ ok: false, error: 'Attachment not found' });
        if (attRec.ownerId !== userId)
          return ack?.({ ok: false, error: 'Attachment not yours' });
        if (!Array.isArray(attachment.keyCiphertexts) ||
            attachment.keyCiphertexts.length !== ciphertexts.length)
          return ack?.({ ok: false, error: 'Attachment key bundle size mismatch' });
        for (const k of attachment.keyCiphertexts) {
          if (!Number.isInteger(k.recipientId)) return ack?.({ ok: false, error: 'Bad keyCiphertext recipientId' });
          if (typeof k.ciphertext !== 'string' || k.ciphertext.length > 100_000)
            return ack?.({ ok: false, error: 'Bad keyCiphertext' });
          if (!/^[A-Za-z0-9_-]+$/.test(k.ciphertext))
            return ack?.({ ok: false, error: 'Bad keyCiphertext encoding' });
        }
        const ctSet = new Set(ciphertexts.map(c => c.recipientId));
        const keySet = new Set(attachment.keyCiphertexts.map(k => k.recipientId));
        if (ctSet.size !== keySet.size || [...ctSet].some(r => !keySet.has(r)))
          return ack?.({ ok: false, error: 'Attachment key recipients mismatch' });
      }
      let expectedRecipients;
      if (conv.startsWith('u:')) {
        const otherId = parseInt(conv.slice(2), 10);
        if (!findUserById(otherId)) return ack?.({ ok: false, error: 'Unknown user' });
        expectedRecipients = new Set([userId, otherId]);
      } else {
        const gid = parseInt(conv.slice(2), 10);
        const g = findGroupById(gid);
        if (!g || !g.memberIds.includes(userId))
          return ack?.({ ok: false, error: 'Not a group member' });
        expectedRecipients = new Set(g.memberIds);
      }
      const got = new Set(ciphertexts.map(c => c.recipientId));
      if (got.size !== expectedRecipients.size || [...got].some(r => !expectedRecipients.has(r)))
        return ack?.({ ok: false, error: 'Recipient set mismatch' });
      const msg = {
        id: store.data.nextMessageId++,
        senderId: userId,
        conv,
        ciphertexts,
        createdAt: now(),
        deleteAt: deleteAt || null,
        attachment: attRec ? {
          attachmentId: attRec.id,
          filename: attRec.filename,
          mime: attRec.mime,
          size: attRec.size,
          keyCiphertexts: attachment.keyCiphertexts
        } : null
      };
      store.data.messages.push(msg);
      if (attRec) {
        attRec.refs = attRec.refs || [];
        if (!attRec.refs.includes(msg.id)) attRec.refs.push(msg.id);
      }
      store.save();
      for (const r of expectedRecipients) {
        const sockets = userSockets.get(r);
        if (!sockets) continue;
        const projection = projectMessageFor(msg, r);
        for (const sid of sockets) {
          if (r === userId && sid === socket.id) continue;
          io.to(sid).emit('new-message', projection);
        }
      }
      ack?.({ ok: true, message: projectMessageFor(msg, userId) });
    } catch (e) {
      logErr(e);
      ack?.({ ok: false, error: 'Server error' });
    }
  });
  socket.on('delete-message', async (data, ack) => {
    if (!checkSendRate()) return ack?.({ ok: false, error: 'Slow down' });
    try {
      const { messageId } = data || {};
      if (!Number.isInteger(messageId)) return ack?.({ ok: false, error: 'Bad id' });
      const idx = store.data.messages.findIndex(m => m.id === messageId);
      if (idx < 0) return ack?.({ ok: false, error: 'Not found' });
      const msg = store.data.messages[idx];
      if (msg.senderId !== userId) return ack?.({ ok: false, error: 'Not your message' });
      const recipients = new Set(msg.ciphertexts.map(c => c.recipientId));
      const conv = msg.conv;
      store.data.messages.splice(idx, 1);
      store.save();
      for (const r of recipients) {
        const sockets = userSockets.get(r);
        if (!sockets) continue;
        for (const sid of sockets) {
          io.to(sid).emit('message-deleted', { messageId, conv });
        }
      }
      ack?.({ ok: true });
    } catch (e) {
      logErr(e);
      ack?.({ ok: false, error: 'Server error' });
    }
  });
  socket.on('disconnect', () => {
    const set = userSockets.get(userId);
    if (set) {
      set.delete(socket.id);
      if (set.size === 0) {
        userSockets.delete(userId);
        const known = knownUserIds(userId);
        for (const otherId of known) {
          const otherSockets = userSockets.get(otherId);
          if (!otherSockets) continue;
          for (const sid of otherSockets) {
            io.to(sid).emit('presence', { userId, online: false });
          }
        }
      }
    }
  });
});
const MESSAGE_MAX_AGE_DAYS = parseInt(process.env.MESSAGE_MAX_AGE_DAYS || '90', 10);
const MESSAGE_MAX_AGE_SECS = MESSAGE_MAX_AGE_DAYS > 0 ? MESSAGE_MAX_AGE_DAYS * 24 * 60 * 60 : Infinity;
const BLOCKLIST_MAX = 10_000;
setInterval(async () => {
  const t = now();
  let dirty = false;
  const expired = [];
  store.data.messages = store.data.messages.filter(m => {
    if (m.deleteAt && m.deleteAt <= t) { expired.push(m); return false; }
    if (MESSAGE_MAX_AGE_SECS !== Infinity && (t - m.createdAt) > MESSAGE_MAX_AGE_SECS) {
      expired.push(m); return false;
    }
    return true;
  });
  if (expired.length) dirty = true;
  const timeExpiredAtts = [];
  store.data.attachments = store.data.attachments.filter(a => {
    if (a.expiresAt && a.expiresAt <= t) { timeExpiredAtts.push(a); return false; }
    return true;
  });
  if (timeExpiredAtts.length) {
    dirty = true;
    for (const a of timeExpiredAtts) {
      const file = path.join(ATTACHMENTS_DIR, `${a.id}.bin`);
      try { await fs.promises.unlink(file); } catch {}
    }
    const expiredAttIds = new Set(timeExpiredAtts.map(a => a.id));
    for (const m of store.data.messages) {
      if (m.attachment && expiredAttIds.has(m.attachment.attachmentId)) {
        m.attachment.expired = true;
        m.attachment.keyCiphertexts = []; 
      }
    }
  }
  const liveMsgIds = new Set(store.data.messages.map(m => m.id));
  const aliveAttachments = [];
  const orphanAttachments = [];
  for (const a of store.data.attachments) {
    a.refs = (a.refs || []).filter(id => liveMsgIds.has(id));
    if (a.refs.length === 0) orphanAttachments.push(a);
    else aliveAttachments.push(a);
  }
  if (orphanAttachments.length) {
    store.data.attachments = aliveAttachments;
    dirty = true;
    for (const a of orphanAttachments) {
      const file = path.join(ATTACHMENTS_DIR, `${a.id}.bin`);
      try { await fs.promises.unlink(file); } catch {}
    }
  }
  const beforeBL = store.data.tokenBlocklist.length;
  store.data.tokenBlocklist = store.data.tokenBlocklist.filter(b => b.exp > t);
  if (store.data.tokenBlocklist.length > BLOCKLIST_MAX) {
    store.data.tokenBlocklist = store.data.tokenBlocklist.slice(-BLOCKLIST_MAX);
  }
  if (store.data.tokenBlocklist.length !== beforeBL) dirty = true;
  for (const k of Object.keys(store.data.loginFailures)) {
    const r = store.data.loginFailures[k];
    if (r.lockedUntil && r.lockedUntil <= t) {
      delete store.data.loginFailures[k];
      dirty = true;
    }
  }
  if (dirty) await store.save();
  for (const m of expired) {
    const recipients = new Set(m.ciphertexts.map(c => c.recipientId));
    for (const r of recipients) {
      const sockets = userSockets.get(r);
      if (!sockets) continue;
      for (const sid of sockets) {
        io.to(sid).emit('message-deleted', { messageId: m.id, conv: m.conv, expired: true });
      }
    }
  }
  if (timeExpiredAtts.length) {
    const expiredAttIds = new Set(timeExpiredAtts.map(a => a.id));
    for (const m of store.data.messages) {
      if (!m.attachment || !expiredAttIds.has(m.attachment.attachmentId)) continue;
      const recipients = new Set(m.ciphertexts.map(c => c.recipientId));
      for (const r of recipients) {
        const sockets = userSockets.get(r);
        if (!sockets) continue;
        for (const sid of sockets) {
          io.to(sid).emit('attachment-expired', {
            messageId: m.id,
            conv: m.conv,
            attachmentId: m.attachment.attachmentId
          });
        }
      }
    }
  }
  if (expired.length) console.log(`swept ${expired.length} expired message(s)`);
  if (orphanAttachments.length) console.log(`swept ${orphanAttachments.length} orphan attachment(s)`);
  if (timeExpiredAtts.length) console.log(`swept ${timeExpiredAtts.length} time-expired attachment(s)`);
}, 60_000);

// ── Integrity endpoint ────────────────────────────────────────────────────────
// Returns SHA-256 hashes of all public JS/HTML files so users can verify
// the app hasn't been tampered with server-side. Compare against your
// published hashes.txt on GitHub Pages.
const PUBLIC_DIR = path.join(__dirname, 'public');
const INTEGRITY_FILES = [
  'index.html',
  'app.js',
  'crypto.js',
  'guide.js',
  'vendor-sodium.js',
];
async function hashFile(filePath) {
  const buf = await fs.promises.readFile(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}
app.get('/api/integrity', async (req, res) => {
  try {
    const results = [];
    for (const name of INTEGRITY_FILES) {
      const full = path.join(PUBLIC_DIR, name);
      try {
        const hash = await hashFile(full);
        results.push({ name, hash, ok: true });
      } catch {
        results.push({ name, hash: null, ok: false });
      }
    }
    const generated = new Date().toISOString();

    // Accept: application/json → return raw JSON (for scripts/tools)
    if ((req.headers.accept || '').includes('application/json')) {
      const obj = {};
      results.forEach(r => { obj[r.name] = r.hash; });
      return res.json({ generated, files: obj });
    }

    // Otherwise → return styled HTML page
    const rows = results.map(r => {
      const hashDisplay = r.ok
        ? `<span class="hash">${r.hash.slice(0,32)}<br>${r.hash.slice(32)}</span>`
        : `<span class="missing">FILE MISSING</span>`;
      const badge = r.ok
        ? `<span class="badge ok">✓</span>`
        : `<span class="badge err">✗</span>`;
      return `
        <div class="row">
          <div class="row-top">${badge}<span class="fname">${r.name}</span></div>
          <div class="row-hash">${hashDisplay}</div>
        </div>`;
    }).join('');

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>niix chat — integrity</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --green:  #0aff9e;
      --pink:   #ff0a6c;
      --bg:     #080b0f;
      --bg2:    #0d1117;
      --bg3:    #111820;
      --border: #1a2530;
      --dim:    #3a4a5a;
      --white:  #e8f0f8;
      --cyan:   #00d4ff;
      --red:    #ff3333;
    }
    body {
      background: var(--bg);
      color: var(--white);
      font-family: 'JetBrains Mono', ui-monospace, monospace;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem 1rem;
    }
    .wrap {
      width: 100%;
      max-width: 640px;
    }
    .header {
      margin-bottom: 2rem;
    }
    .header .diamond { color: var(--pink); }
    .title {
      font-size: 0.7rem;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--green);
      margin-bottom: 0.4rem;
    }
    .subtitle {
      font-size: 0.62rem;
      color: var(--dim);
      letter-spacing: 0.08em;
      line-height: 1.7;
    }
    .subtitle a {
      color: var(--cyan);
      text-decoration: none;
    }
    .subtitle a:hover { text-decoration: underline; }
    .generated {
      font-size: 0.58rem;
      color: var(--dim);
      margin-top: 0.4rem;
      letter-spacing: 0.06em;
    }
    .divider {
      border: none;
      border-top: 1px solid var(--border);
      margin: 1.2rem 0;
    }
    .row {
      padding: 0.9rem 0;
      border-bottom: 1px solid var(--border);
    }
    .row:last-child { border-bottom: none; }
    .row-top {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      margin-bottom: 0.4rem;
    }
    .badge {
      font-size: 0.6rem;
      font-weight: 700;
      padding: 0.1rem 0.35rem;
      border: 1px solid;
      letter-spacing: 0.05em;
    }
    .badge.ok  { color: var(--green); border-color: var(--green); }
    .badge.err { color: var(--red);   border-color: var(--red); }
    .fname {
      font-size: 0.72rem;
      color: var(--white);
      letter-spacing: 0.06em;
    }
    .row-hash { padding-left: 2.1rem; }
    .hash {
      font-size: 0.6rem;
      color: var(--cyan);
      letter-spacing: 0.04em;
      font-family: 'JetBrains Mono', monospace;
      line-height: 1.8;
      word-break: break-all;
    }
    .missing {
      font-size: 0.6rem;
      color: var(--red);
      letter-spacing: 0.1em;
    }
    .footer {
      margin-top: 2rem;
      font-size: 0.58rem;
      color: var(--dim);
      letter-spacing: 0.08em;
      line-height: 1.9;
    }
    .footer .diamond { color: var(--pink); }
    .back {
      display: inline-block;
      margin-top: 1.5rem;
      font-size: 0.65rem;
      color: var(--pink);
      text-decoration: none;
      border: 1px solid var(--pink);
      padding: 0.28rem 0.7rem;
      letter-spacing: 0.1em;
      transition: all 0.2s;
    }
    .back:hover { background: var(--pink); color: var(--bg); }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <div class="title"><span class="diamond">◈</span> integrity verification</div>
      <div class="subtitle">
        SHA-256 hashes of all public files served by this instance.<br>
        Compare against the signed <a href="/integrity/hashes.txt" target="_blank" rel="noopener">published hashes.txt</a> to verify nothing has been tampered with. <a href="/integrity/signing-key.pub" target="_blank" rel="noopener">public key</a>
      </div>
      <div class="generated">generated: ${generated}</div>
    </div>
    <hr class="divider"/>
    ${rows}
    <hr class="divider"/>
    <div class="footer">
      <span class="diamond">◈</span> hashes are SHA-256 · 64 hex chars · compare the full string<br>
      <span class="diamond">◈</span> if any hash differs from the published list, do not use this instance
    </div>
    <a class="back" href="/">[ ← back ]</a>
  </div>
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (e) { logErr(e); res.status(500).send('Server error'); }
});

server.listen(PORT, () => {
  console.log(`\n  NiiX Chat v2 running → http://localhost:${PORT}\n`);
});