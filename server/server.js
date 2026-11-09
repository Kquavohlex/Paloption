require('dotenv').config();
const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt'), jwt = require('jsonwebtoken'), { Pool } = require('pg');

const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 32) { console.error('JWT_SECRET (32+ chars) is required'); process.exit(1); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false });

const PAYOUT = 0.85, DURATIONS = [30, 60, 120, 300], SYMBOLS = ['BTCUSDT', 'ETHUSDT', 'BNBUSDT'];
const DEMO_START = 10000, MIN_STAKE = 1, MAX_STAKE = 1000;

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false })); // inline script in public/index.html; tighten with nonces before launch
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public'));

// ---- price feed (server-side only; Binance public ticker) ----
const cache = {};
async function price(sym) {
  const c = cache[sym];
  if (c && Date.now() - c.t < 900) return c.p;
  const r = await fetch('https://api.binance.com/api/v3/ticker/price?symbol=' + sym);
  if (!r.ok) throw new Error('price feed unavailable');
  const p = Number((await r.json()).price);
  if (!Number.isFinite(p)) throw new Error('bad price');
  cache[sym] = { p, t: Date.now() };
  return p;
}

// ---- ledger helper: atomic balance change + ledger row ----
async function adjust(c, uid, delta, type, ref) {
  const r = await c.query(
    "UPDATE wallets SET balance = balance + $2 WHERE user_id=$1 AND kind='demo' AND balance + $2 >= 0 RETURNING balance",
    [uid, delta]);
  if (!r.rowCount) throw Object.assign(new Error('Insufficient balance'), { status: 400 });
  await c.query("INSERT INTO transactions (user_id,type,amount,balance_after,ref) VALUES ($1,$2,$3,$4,$5)",
    [uid, type, delta, r.rows[0].balance, ref]);
  return r.rows[0].balance;
}
async function tx(fn) {
  const c = await pool.connect();
  try { await c.query('BEGIN'); const out = await fn(c); await c.query('COMMIT'); return out; }
  catch (e) { await c.query('ROLLBACK'); throw e; }
  finally { c.release(); }
}

// ---- auth ----
const wrap = fn => (req, res) => fn(req, res).catch(e => {
  if (!e.status) console.error(e);
  res.status(e.status || 500).json({ error: e.status ? e.message : 'Server error' });
});
const bad = m => Object.assign(new Error(m), { status: 400 });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
const sign = u => jwt.sign({ uid: u.id }, SECRET, { expiresIn: '7d' });

async function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    const { uid } = jwt.verify(t, SECRET);
    const u = (await pool.query('SELECT id,name,email,status FROM users WHERE id=$1', [uid])).rows[0];
    if (!u || u.status !== 'active') throw 0;
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Please sign in' }); }
}

app.post('/api/register', authLimiter, wrap(async (req, res) => {
  const { name, email, password } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 2 || name.length > 80) throw bad('Enter your full name');
  if (typeof email !== 'string' || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 120) throw bad('Enter a valid email');
  if (typeof password !== 'string' || password.length < 8 || password.length > 72) throw bad('Password must be 8–72 characters');
  const hash = await bcrypt.hash(password, 12);
  try {
    const u = await tx(async c => {
      const r = await c.query('INSERT INTO users (email,name,password_hash) VALUES ($1,$2,$3) RETURNING id,name,email',
        [email.toLowerCase().trim(), name.trim(), hash]);
      await c.query("INSERT INTO wallets (user_id,kind,balance) VALUES ($1,'live',0),($1,'demo',0)", [r.rows[0].id]);
      await adjust(c, r.rows[0].id, DEMO_START, 'demo_grant', 'signup');
      return r.rows[0];
    });
    res.json({ token: sign(u), user: u });
  } catch (e) {
    if (e.code === '23505') throw bad('That email is already registered');
    throw e;
  }
}));

app.post('/api/login', authLimiter, wrap(async (req, res) => {
  const { email, password } = req.body || {};
  const u = typeof email === 'string' ? (await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()])).rows[0] : null;
  const ok = u && typeof password === 'string' && await bcrypt.compare(password, u.password_hash);
  if (!ok || u.status !== 'active') throw Object.assign(new Error('Incorrect email or password'), { status: 401 });
  res.json({ token: sign(u), user: { id: u.id, name: u.name, email: u.email } });
}));

// ---- app API ----
let tk = { t: 0, d: null };
app.get('/api/ticker', rateLimit({ windowMs: 60000, max: 60 }), wrap(async (_req, res) => {
  if (!tk.d || Date.now() - tk.t > 4000) {
    const r = await fetch('https://api.binance.com/api/v3/ticker/24hr?symbols=' + encodeURIComponent(JSON.stringify(SYMBOLS)));
    if (!r.ok) throw new Error('feed');
    tk = { t: Date.now(), d: (await r.json()).map(x => ({ symbol: x.symbol, price: Number(x.lastPrice), change: Number(x.priceChangePercent) })) };
  }
  res.json({ items: tk.d });
}));
app.get('/api/config', (_req, res) => res.json({ symbols: SYMBOLS, durations: DURATIONS, payout: PAYOUT, minStake: MIN_STAKE, maxStake: MAX_STAKE }));
app.get('/api/me', auth, wrap(async (req, res) => {
  const b = (await pool.query("SELECT balance FROM wallets WHERE user_id=$1 AND kind='demo'", [req.user.id])).rows[0];
  res.json({ user: req.user, demoBalance: Number(b.balance) });
}));
app.get('/api/price/:sym', auth, wrap(async (req, res) => {
  if (!SYMBOLS.includes(req.params.sym)) throw bad('Unsupported asset');
  res.json({ symbol: req.params.sym, price: await price(req.params.sym), t: Date.now() });
}));

app.post('/api/trades', auth, wrap(async (req, res) => {
  const { symbol, direction, duration } = req.body || {};
  const stake = Math.round(Number(req.body && req.body.stake) * 100) / 100;
  if (!SYMBOLS.includes(symbol)) throw bad('Unsupported asset');
  if (!['up', 'down'].includes(direction)) throw bad('Choose Up or Down');
  if (!DURATIONS.includes(duration)) throw bad('Unsupported duration');
  if (!(stake >= MIN_STAKE && stake <= MAX_STAKE)) throw bad(`Stake must be $${MIN_STAKE}–$${MAX_STAKE}`);
  const entry = await price(symbol);
  const out = await tx(async c => {
    const t = (await c.query(
      "INSERT INTO trades (user_id,symbol,direction,stake,duration_s,entry_price,expires_at) VALUES ($1,$2,$3,$4,$5,$6, now() + ($5 || ' seconds')::interval) RETURNING *",
      [req.user.id, symbol, direction, stake, duration, entry])).rows[0];
    const bal = await adjust(c, req.user.id, -stake, 'trade_open', 'trade:' + t.id);
    return { trade: t, demoBalance: Number(bal) };
  });
  res.json(out);
}));

app.get('/api/trades', auth, wrap(async (req, res) => {
  const r = await pool.query('SELECT * FROM trades WHERE user_id=$1 ORDER BY id DESC LIMIT 50', [req.user.id]);
  const b = (await pool.query("SELECT balance FROM wallets WHERE user_id=$1 AND kind='demo'", [req.user.id])).rows[0];
  res.json({ trades: r.rows, demoBalance: Number(b.balance) });
}));
app.get('/api/ledger', auth, wrap(async (req, res) => {
  res.json({ rows: (await pool.query('SELECT type,amount,balance_after,ref,created_at FROM transactions WHERE user_id=$1 ORDER BY id DESC LIMIT 50', [req.user.id])).rows });
}));
app.post('/api/demo/reset', auth, wrap(async (req, res) => {
  const bal = await tx(async c => {
    const open = await c.query("SELECT 1 FROM trades WHERE user_id=$1 AND status='open'", [req.user.id]);
    if (open.rowCount) throw bad('Wait for open trades to settle');
    const cur = Number((await c.query("SELECT balance FROM wallets WHERE user_id=$1 AND kind='demo' FOR UPDATE", [req.user.id])).rows[0].balance);
    return adjust(c, req.user.id, DEMO_START - cur, 'demo_reset', 'user');
  });
  res.json({ demoBalance: Number(bal) });
}));

// ---- settlement: runs server-side against the live feed ----
let settling = false;
async function settle() {
  if (settling) return; settling = true;
  try {
    await tx(async c => {
      const { rows } = await c.query("SELECT * FROM trades WHERE status='open' AND expires_at <= now() ORDER BY id LIMIT 20 FOR UPDATE SKIP LOCKED");
      for (const t of rows) {
        const exit = await price(t.symbol), entry = Number(t.entry_price), stake = Number(t.stake);
        const moved = exit > entry ? 'up' : exit < entry ? 'down' : 'tie';
        let outcome, pnl, credit;
        if (moved === 'tie') { outcome = 'tie'; pnl = 0; credit = stake; }
        else if (moved === t.direction) { outcome = 'win'; pnl = Math.round(stake * PAYOUT * 100) / 100; credit = stake + pnl; }
        else { outcome = 'loss'; pnl = -stake; credit = 0; }
        if (credit > 0) await adjust(c, t.user_id, credit, 'trade_settle', 'trade:' + t.id);
        await c.query("UPDATE trades SET status='settled', exit_price=$2, outcome=$3, pnl=$4, settled_at=now() WHERE id=$1", [t.id, exit, outcome, pnl]);
      }
    });
  } catch (e) { console.error('settle:', e.message); }
  finally { settling = false; }
}
setInterval(settle, 1000);

app.listen(process.env.PORT || 3000, () => console.log('listening'));
