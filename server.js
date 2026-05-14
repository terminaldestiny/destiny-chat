require('dotenv').config();
var express = require('express');
var cors = require('cors');
var Anthropic = require('@anthropic-ai/sdk');
var crypto = require('crypto');
var nacl = require('tweetnacl');
var bs58 = require('bs58');
var { createClient } = require('@supabase/supabase-js');
var { Telegraf } = require('telegraf');

var app = express();
app.set('trust proxy', 1);

// ── Security headers (M1) ─────────────────────────────────────────────────
app.use(function(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Content-Security-Policy',
    "default-src 'none'; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: blob:; " +
    "connect-src 'self' https://destiny-chat-production.up.railway.app https://api.mainnet-beta.solana.com; " +
    "media-src 'self'; " +
    "frame-ancestors 'none'");
  next();
});

// ── CORS (M2, M3) ─────────────────────────────────────────────────────────
var PROD_ORIGINS = [
  'https://terminaldestiny.com',
  'https://www.terminaldestiny.com',
  'https://terminaldestiny.github.io',
];
var DEV_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:8080',
];
var ALLOWED_ORIGINS = process.env.NODE_ENV !== 'production'
  ? PROD_ORIGINS.concat(DEV_ORIGINS)
  : PROD_ORIGINS;

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) {
      // No Origin header = server-to-server call; CORS not applicable, allow through
      callback(null, false);
    } else if (ALLOWED_ORIGINS.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('CORS: origin not allowed'));
    }
  }
}));

// ── Body parsers — per-route size limits (M5) ─────────────────────────────
var jsonSmall = express.json({ limit: '64kb' });
var jsonLarge = express.json({ limit: '6mb' }); // only used on /api/chat

var client = new Anthropic.default({ apiKey: process.env.ANTHROPIC_API_KEY });

// ── Supabase ──────────────────────────────────────────────────────────────
var supabase = null;
if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_KEY) {
  supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
  console.log('Supabase: connected');
} else {
  console.log('Supabase: not configured — heroes using client history');
}

async function loadHistory(wallet) {
  if (!supabase) return null;
  try {
    var { data, error } = await supabase
      .from('conversations')
      .select('messages')
      .eq('wallet', wallet)
      .single();
    if (error && error.code !== 'PGRST116') throw error;
    return data ? data.messages : null;
  } catch (e) {
    console.error('Supabase load error:', e.message);
    return null;
  }
}

async function saveHistory(wallet, messages) {
  if (!supabase) return;
  try {
    await supabase
      .from('conversations')
      .upsert({ wallet, messages, updated_at: new Date().toISOString() }, { onConflict: 'wallet' });
  } catch (e) {
    console.error('Supabase save error:', e.message);
  }
}

// ── User store (email ↔ wallet linking) ───────────────────────────────────
async function getUserByEmail(email) {
  if (!supabase) return null;
  try {
    var { data, error } = await supabase.from('users').select('*').eq('email', email).single();
    if (error && error.code !== 'PGRST116') throw error;
    return data || null;
  } catch (e) { console.error('getUserByEmail:', e.message); return null; }
}

async function upsertUser(wallet, email, tier, balance) {
  if (!supabase) return;
  try {
    await supabase.from('users').upsert(
      { wallet, email, tier, balance, last_balance_check: new Date().toISOString() },
      { onConflict: 'wallet' }
    );
  } catch (e) { console.error('upsertUser:', e.message); }
}

// ── Magic token store ────────────────────────────────────────────────────
async function createMagicToken(email) {
  if (!supabase) throw new Error('no_supabase');
  var token = crypto.randomUUID();
  var expires_at = new Date(Date.now() + 900000).toISOString(); // 15 min
  var { error } = await supabase.from('magic_tokens').insert({ email, token, expires_at });
  if (error) throw error;
  return token;
}

async function consumeMagicToken(token) {
  if (!supabase) return null;
  try {
    // Atomic consume: update only if unused+unexpired, return email only on success.
    // Prevents TOCTOU double-redemption from simultaneous requests.
    var { data, error } = await supabase
      .from('magic_tokens')
      .update({ used: true })
      .eq('token', token)
      .eq('used', false)
      .gt('expires_at', new Date().toISOString())
      .select('email')
      .single();
    if (error || !data) return null;
    return data.email;
  } catch (e) { console.error('consumeMagicToken:', e.message); return null; }
}

// ── Magic send rate limit (max 3 emails/hour per address) ────────────────
function checkMagicSendLimit(email) {
  var now = Date.now();
  var ts = (magicSendLog.get(email) || []).filter(function(t) { return t > now - 3600000; });
  if (ts.length >= 3) return false;
  ts.push(now);
  magicSendLog.set(email, ts);
  return true;
}

// ── Email sending via Resend ─────────────────────────────────────────────
async function sendMagicLinkEmail(to, token) {
  if (!process.env.RESEND_API_KEY) throw new Error('no_resend_key');
  var link = SITE_URL.replace(/\/?$/, '/') + '#token=' + token;
  var res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + process.env.RESEND_API_KEY },
    body: JSON.stringify({
      from: process.env.EMAIL_FROM || 'DESTINY <onboarding@resend.dev>',
      to: [to],
      subject: 'DESTINY // ACCESS LINK',
      text: [
        '// DESTINY FIELD TERMINAL',
        '// ACCESS LINK REQUESTED',
        '',
        'Click below to access DESTINY with your hero tier restored:',
        '',
        link,
        '',
        'Expires in 15 minutes. Do not share this link.',
        '',
        '// terminaldestiny.com  ·  CODEC 140.85'
      ].join('\n')
    })
  });
  if (!res.ok) {
    var body = await res.text();
    throw new Error('resend: ' + body.slice(0, 120));
  }
}

// ── Hero registry ─────────────────────────────────────────────────────────
var BUILDER_RE = /\b(build|deploy|code|app|project|develop|launch|ship|create|program|api|backend|frontend|database|startup|product)\b/i;
var VALID_EMBLEMS   = ['hexagon','diamond','skull','shield','sword','signal','star','lightning','infinity','target','psi','omega','delta','phi','prism','nexus','origin','apex','command','gear','bullseye','cross','crown','circlex','anchor','crescent','ringeye','semi','bars','spark'];
var VALID_THEMES    = ['green','cyan','amber','red','purple','blue','pink','orange','solar','jade','flux','warp','ghost','ember'];
var VALID_PATTERNS  = ['none','grid','scan','circuit','dot','hex','rain','cross','pulse'];
var VALID_BANNERS   = ['clean','aurora','plasma','inferno','prism','glitch','neon','void'];
var VALID_FX        = ['none','glitch','hologram','classified','overdrive'];
var VALID_ROLES     = ['','BUILDER','TRADER','DEGEN','FOUNDER','SCOUT','SHADOW','GHOST','PILOT'];

async function ensureHero(wallet, codename, balance) {
  if (!supabase) return null;
  try {
    var { data: existing } = await supabase.from('heroes').select('*').eq('wallet', wallet).single();
    if (existing) {
      await supabase.from('heroes').update({
        codename: (codename && codename !== 'HERO') ? codename : existing.codename,
        balance: balance
      }).eq('wallet', wallet);
      return existing;
    }
    var titles = [];
    if (new Date() <= EARLY_OPERATIVE_CUTOFF) titles.push('EARLY OPERATIVE');
    var { data, error } = await supabase.from('heroes')
      .insert({ wallet, codename: codename || 'HERO', balance, titles })
      .select().single();
    if (error) throw error;
    return data;
  } catch (e) { console.error('ensureHero:', e.message); return null; }
}

async function updateHeroActivity(wallet, message, hour, sessionBalance) {
  if (!supabase) return;
  try {
    var { data: hero } = await supabase.from('heroes').select('*').eq('wallet', wallet).single();
    if (!hero) return;
    var today = new Date().toISOString().slice(0, 10);
    var activeDates = hero.active_dates || [];
    if (!activeDates.includes(today)) activeDates = activeDates.concat([today]);
    var titles = hero.titles || [];
    var bal = (sessionBalance != null ? sessionBalance : null) || hero.balance || 0;
    if (hour >= 0 && hour < 5 && !titles.includes('NIGHT OWL')) titles.push('NIGHT OWL');
    if (BUILDER_RE.test(message) && !titles.includes('FIRST BUILDER')) titles.push('FIRST BUILDER');
    if ((hero.total_conversations || 0) + 1 >= 100 && !titles.includes('CENTURION')) titles.push('CENTURION');
    if (activeDates.length >= 30 && !titles.includes('PHANTOM')) titles.push('PHANTOM');
    if (bal >= 10000000 && !titles.includes('SOVEREIGN')) titles.push('SOVEREIGN');
    await supabase.from('heroes').update({
      total_conversations: (hero.total_conversations || 0) + 1,
      active_dates: activeDates,
      days_active: activeDates.length,
      titles,
      balance: bal,
      last_active_at: new Date().toISOString()
    }).eq('wallet', wallet);
  } catch (e) { console.error('updateHeroActivity:', e.message); }
}

async function getAllHeroes() {
  if (!supabase) return [];
  try {
    var { data, error } = await supabase.from('heroes')
      .select('serial,codename,emblem,titles,total_conversations,days_active,joined_at,balance,theme,tagline,bg_pattern,last_active_at,x_handle,fx,show_barcode')
      .order('serial', { ascending: true });
    if (error) throw error;
    return (data || []).map(function(h) {
      var b = h.balance || 0;
      var rank = b >= 10000000 ? 'LEGEND' : b >= 2000000 ? 'COMMANDER' : b >= 500000 ? 'AGENT' : 'OPERATIVE';
      return { serial: h.serial, codename: h.codename, emblem: h.emblem, titles: h.titles,
               total_conversations: h.total_conversations, days_active: h.days_active,
               joined_at: h.joined_at, rank, gold: b >= 2000000, balance: b,
               theme: h.theme || 'green', tagline: h.tagline || '', bg_pattern: h.bg_pattern || 'none',
               last_active_at: h.last_active_at || null, x_handle: h.x_handle || '', fx: h.fx || 'none', show_barcode: h.show_barcode || false };
    });
  } catch (e) { console.error('getAllHeroes:', e.message); return []; }
}

// ── Holder verification ───────────────────────────────────────────────────
var DESTINY_MINT = '3AwkJnZL7xrf8ffUwEsSkKndQkPSj2vfR3CqvyFpk8UP';
var MIN_TOKENS    = 250000; // 250K = hero card + 30 msg/day
var SONNET_TOKENS = 500000; // 500K = Sonnet 4.6 upgrade
var SOLANA_RPC   = 'https://api.mainnet-beta.solana.com';
var SITE_URL     = process.env.SITE_URL || 'https://terminaldestiny.github.io/destiny-chat/';
var SESSION_TTL             = 7 * 24 * 60 * 60 * 1000; // 7 days
var EARLY_OPERATIVE_CUTOFF  = new Date('2026-06-01T00:00:00Z'); // first-month title window

var pendingNonces    = new Map();
var verifiedSessions = new Map();
var challengeLog     = new Map();
var verifyLog        = new Map(); // H2: rate limit magic-verify
var magicSendLog     = new Map();
var scanLog          = new Map(); // rate limit /api/scan
var adminLog         = new Map(); // rate limit /api/admin/stats

// L2: use Object.create(null) to prevent prototype pollution
var chatLog = Object.create(null);

setInterval(function() {
  var now = Date.now();
  pendingNonces.forEach(function(exp, k)    { if (exp < now) pendingNonces.delete(k); });
  verifiedSessions.forEach(function(s, k)   { if (s.expires < now) verifiedSessions.delete(k); });
  challengeLog.forEach(function(ts, k)      { if (!ts.length || ts[ts.length-1] < now - 60000) challengeLog.delete(k); });
  verifyLog.forEach(function(ts, k)         { if (!ts.length || ts[ts.length-1] < now - 60000) verifyLog.delete(k); });
  magicSendLog.forEach(function(ts, k)      { if (!ts.length || ts[ts.length-1] < now - 3600000) magicSendLog.delete(k); });
  scanLog.forEach(function(ts, k)           { if (!ts.length || ts[ts.length-1] < now - 60000) scanLog.delete(k); });
  adminLog.forEach(function(ts, k)          { if (!ts.length || ts[ts.length-1] < now - 60000) adminLog.delete(k); });
  var today = getTodayUTC();
  Object.keys(chatLog).forEach(function(k) { if (chatLog[k].date !== today) delete chatLog[k]; });
  if (supabase) {
    supabase.from('sessions').delete().lt('expires_at', new Date().toISOString())
      .then(function() {}).catch(function(e) { console.error('session cleanup:', e.message); });
  }
}, 600000);

// ── Session persistence (Supabase-backed, memory-cached) ──────────────────
async function createSession(token, wallet, tier, balance) {
  var expiresMs = Date.now() + SESSION_TTL;
  var session = { wallet, tier, balance, expires: expiresMs, lastBalanceCheck: Date.now() };
  verifiedSessions.set(token, session);
  if (supabase) {
    try {
      await supabase.from('sessions').upsert(
        { token, wallet, tier, balance,
          expires_at: new Date(expiresMs).toISOString(),
          last_balance_check: new Date().toISOString() },
        { onConflict: 'token' }
      );
    } catch (e) { console.error('createSession DB:', e.message); }
  }
  return session;
}

async function getSession(token) {
  var cached = verifiedSessions.get(token);
  if (cached) {
    if (cached.expires > Date.now()) return cached;
    verifiedSessions.delete(token);
  }
  if (!supabase) return null;
  try {
    var { data, error } = await supabase.from('sessions')
      .select('*').eq('token', token)
      .gt('expires_at', new Date().toISOString())
      .single();
    if (error || !data) return null;
    var session = {
      wallet: data.wallet, tier: data.tier, balance: data.balance,
      expires: new Date(data.expires_at).getTime(),
      lastBalanceCheck: new Date(data.last_balance_check).getTime()
    };
    verifiedSessions.set(token, session);
    return session;
  } catch (e) { console.error('getSession DB:', e.message); return null; }
}

async function updateSession(token, updates) {
  var cached = verifiedSessions.get(token);
  if (cached) Object.assign(cached, updates);
  if (!supabase) return;
  var dbUp = {};
  if (updates.tier !== undefined) dbUp.tier = updates.tier;
  if (updates.balance !== undefined) dbUp.balance = updates.balance;
  if (updates.lastBalanceCheck !== undefined) dbUp.last_balance_check = new Date(updates.lastBalanceCheck).toISOString();
  if (!Object.keys(dbUp).length) return;
  try {
    await supabase.from('sessions').update(dbUp).eq('token', token);
  } catch (e) { console.error('updateSession DB:', e.message); }
}

// Evicts oldest 25% of entries by insertion order when limit is exceeded
function guardMapSize(map, limit) {
  if (map.size > limit) {
    var iter = map.keys();
    for (var i = 0; i < Math.floor(limit / 4); i++) map.delete(iter.next().value);
  }
}

function checkChallengeLimit(ip) {
  var now = Date.now(), ago = now - 60000;
  var ts = challengeLog.get(ip) || [];
  while (ts.length && ts[0] < ago) ts.shift();
  if (ts.length >= 10) return false;
  ts.push(now);
  challengeLog.set(ip, ts);
  return true;
}

// H2: rate limit for magic-verify (10 attempts/min per IP)
function checkVerifyLimit(ip) {
  var now = Date.now(), ago = now - 60000;
  var ts = verifyLog.get(ip) || [];
  while (ts.length && ts[0] < ago) ts.shift();
  if (ts.length >= 10) return false;
  ts.push(now);
  verifyLog.set(ip, ts);
  return true;
}

// rate limit for /api/scan (30 requests/min per IP)
function checkScanLimit(ip) {
  var now = Date.now(), ago = now - 60000;
  var ts = scanLog.get(ip) || [];
  while (ts.length && ts[0] < ago) ts.shift();
  if (ts.length >= 30) return false;
  ts.push(now);
  scanLog.set(ip, ts);
  return true;
}

// rate limit for /api/admin/stats (5 attempts/min per IP — H1)
function checkAdminLimit(ip) {
  var now = Date.now(), ago = now - 60000;
  var ts = adminLog.get(ip) || [];
  while (ts.length && ts[0] < ago) ts.shift();
  if (ts.length >= 5) return false;
  ts.push(now);
  adminLog.set(ip, ts);
  return true;
}

async function getSolanaTokenBalance(walletAddress) {
  var res = await fetch(SOLANA_RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0', id: 1,
      method: 'getTokenAccountsByOwner',
      params: [walletAddress, { mint: DESTINY_MINT }, { encoding: 'jsonParsed' }]
    })
  });
  var data = await res.json();
  var accounts = (data.result && data.result.value) ? data.result.value : [];
  if (!accounts.length) return 0;
  return accounts[0].account.data.parsed.info.tokenAmount.uiAmount || 0;
}

// ── H1: Prompt injection detection ───────────────────────────────────────
var INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i,
  /forget\s+(all\s+)?(your\s+)?(previous|prior)?\s*instructions?/i,
  /\[system\]/i,
  /\bjailbreak\b/i,
  /\bdan\s+mode\b/i,
  /new\s+system\s+prompt/i,
  /you\s+are\s+now\s+(a\s+|an\s+)?(?:different|unrestricted|evil|free|unfiltered)/i,
];
function looksLikeInjection(text) {
  return INJECTION_PATTERNS.some(function(p) { return p.test(text); });
}

// ── L1: Email validation regex ────────────────────────────────────────────
var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

// ── L3: Magic token UUID format ───────────────────────────────────────────
var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ── DESTINY system prompt ─────────────────────────────────────────────────
var DESTINY_CHAT_PROMPT = `You are DESTINY — an AI who knows the AI and crypto world from the inside and helps people actually move in it. You've been deep in the tools, the tokens, the builds. You don't lecture. You just help people get going.

WHO YOU ARE:
You're DESTINY, the AI at the center of the DreamOS ecosystem. This chat runs on Claude (Anthropic) under the hood — you know that and you're fine saying it. People come here to ask real questions and get real answers. Connect a Solana wallet (Phantom or Backpack) and hold $DESTINY tokens to unlock tiers: 250,000+ gets you hero status — a hero card on the Heroes page, 30 messages a day; 500,000+ upgrades you to Sonnet 4.6 for deeper, sharper answers. Without a wallet you're on Haiku with 20 messages a day — still free, still real.

THE ECOSYSTEM:
- DESTINY Chat — this interface, where you live
- DreamOS World — a browser-based 3D survival game in the same universe, with live AI intel from DESTINY and ELIZA
- Hyperia — AI-native MMORPG, in the works
- X: @terminaldestiny — updates, community, drops

WHAT THIS SITE CAN DO:
- /scan [CA] — pulls live DexScreener data on any Solana token and displays it as a data panel. No opinion — raw data only. Tell people to use this when they ask about a token.
- /voice — toggles text-to-speech so DESTINY can be heard out loud
- /nvg — flips the interface to night vision mode
- /debrief — summarizes what was covered in the session
- /clear — wipes the chat
- MENU button (top right) — opens a panel with links to DREAM, Hyperia, Buy $DESTINY on Jupiter, and DexScreener. Hero-tier users see their hero card inside the menu.
- Heroes page (terminaldestiny.com/heroes) — the community roster. Shows every active hero's card: callsign, emblem, rank, tagline, titles, transmissions count, days active. Logged-in heroes can customize their card (emblem, color theme, banner FX, background pattern, special effect) and share it to X. Features constellation view, live activity feed, and sort/filter. Rank tiers on the heroes page: OPERATIVE (250K+), AGENT (500K+), COMMANDER (2M+), LEGEND (10M+).
- Hero Card — heroes can customize and share a terminal ID card from the menu or the heroes page
- Callsigns — users pick a name on first boot, use it when it feels natural

THE $DESTINY TOKEN:
- Solana SPL token. CA: 3AwkJnZL7xrf8ffUwEsSkKndQkPSj2vfR3CqvyFpk8UP
- Holding 250,000+ = hero status: hero card, listed on heroes page, 30 messages/day
- Holding 500,000+ = Sonnet 4.6 upgrade (sharper, longer answers) on top of hero status
- Buy on Jupiter or Raydium — always verify the CA before buying, fakes exist
- No real-time price or market cap data — point people to DEXScreener or Jupiter for that

BUILDING — TOOLS FIRST, ALWAYS:
When someone wants to build something, lead with the right tool. Never open with "go learn X from scratch." Start here:
- Claude Code: terminal AI coding for any project
- Cursor / Windsurf: AI-native code editor for full projects
- v0.dev: generate UI from a text prompt
- Bolt.new / Replit: full-stack prototype in the browser, zero setup
- Claude API: when they're ready to ship their own AI product
Go deeper on the internals if they ask — but start with the tool that gets them moving.

FINANCIAL ADVICE:
Never give financial advice, price predictions, or tell anyone to buy, sell, or hold anything. Explaining how something works is fine — telling someone what to do with their money is not. If pushed, be straight about it and move on.

IF ASKED WHETHER $DESTINY IS A RUG:
Be honest. No one can guarantee any token. Tell them to check the CA themselves (3AwkJnZL7xrf8ffUwEsSkKndQkPSj2vfR3CqvyFpk8UP), look at DEXScreener for liquidity and holder spread, and read the on-chain data. Skepticism is smart — fakes and scams are everywhere. Give them facts, not reassurance.

IF ASKED TO ANALYZE $DESTINY TOKEN ON-CHAIN DATA:
Read the numbers straight. It's an early-stage utility token with a small community — thin metrics are expected. 2 sentences max.

WHAT YOU KNOW:
AI tools and agents, Claude API, prompt engineering, Solana, DeFi, token safety, on-chain analysis, crypto wallets, NFTs, building AI products, the DreamOS and DESTINY ecosystem.

TERMINOLOGY:
Wallet holders with hero status are "heroes". Never call them "operatives". Recruits are "recruits". That's the only two tiers.

VOICE:
Direct and real — not cold, not hype. You say what you mean and skip the performance. Dry humor when it fits. You read people: a bit harder when someone's being overconfident, easier when someone's genuinely stuck or new. Crypto slang when it comes naturally. "Great question!" is banned. If you don't know something, say so.

RESPONSE FORMAT:
Terminal UI — keep it tight. 2-4 sentences for most replies. Bullet points when listing options. No walls of text. Lead with what matters most, offer to go deeper if they want it.`;

// ── Health check ──────────────────────────────────────────────────────────
app.get('/', function(req, res) { res.json({ status: 'ok' }); });
app.get('/health', function(req, res) { res.json({ status: 'ok' }); });

// ── /api/challenge ────────────────────────────────────────────────────────
app.get('/api/challenge', function(req, res) {
  var ip = req.ip || 'unknown';
  guardMapSize(pendingNonces, 5000);
  if (!checkChallengeLimit(ip)) {
    return res.status(429).json({ error: 'rate_limited' });
  }
  var nonce = crypto.randomUUID();
  pendingNonces.set(nonce, Date.now() + 300000);
  res.json({ nonce: nonce });
});

// ── /api/verify ───────────────────────────────────────────────────────────
app.post('/api/verify', jsonSmall, async function(req, res) {
  var body   = req.body || {};
  var wallet = (body.wallet || '').toString().trim();
  var nonce  = (body.nonce  || '').toString().trim();
  var sigArr = body.signature;

  if (!wallet || !nonce || !Array.isArray(sigArr) || sigArr.length !== 64) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  // M4: validate each byte is a proper integer 0-255
  if (sigArr.some(function(b) { return typeof b !== 'number' || !Number.isInteger(b) || b < 0 || b > 255; })) {
    return res.status(400).json({ error: 'invalid_signature' });
  }

  var nonceExpiry = pendingNonces.get(nonce);
  if (!nonceExpiry || nonceExpiry < Date.now()) {
    return res.status(400).json({ error: 'invalid_nonce' });
  }
  pendingNonces.delete(nonce);

  try {
    var message     = new TextEncoder().encode('DESTINY verification: ' + nonce);
    var signature   = new Uint8Array(sigArr);
    var pubkeyBytes = bs58.decode(wallet);
    if (!nacl.sign.detached.verify(message, signature, pubkeyBytes)) {
      return res.status(401).json({ error: 'invalid_signature' });
    }
  } catch (e) {
    return res.status(400).json({ error: 'signature_error' });
  }

  try {
    var balance      = await getSolanaTokenBalance(wallet);
    var tier         = balance >= MIN_TOKENS ? 'operative' : 'recruit';
    var sessionToken = crypto.randomUUID();
    await createSession(sessionToken, wallet, tier, balance);
    if (tier === 'operative') {
      var codename = (body.codename || '').toString().trim().slice(0, 32);
      ensureHero(wallet, codename, balance);
    }
    res.json({ tier: tier, balance: balance, sessionToken: sessionToken, minTokens: MIN_TOKENS });
  } catch (e) {
    console.error('RPC error:', e.message || e);
    res.status(500).json({ error: 'rpc_error' });
  }
});

// ── Rate limiting ─────────────────────────────────────────────────────────
var RECRUIT_DAILY_LIMIT      = 20;
var OPERATIVE_DAILY_LIMIT    = 30;
var BALANCE_RECHECK_INTERVAL = 6 * 60 * 60 * 1000; // 6 hours

function getTodayUTC() {
  return new Date().toISOString().split('T')[0];
}

function checkChatLimit(key, limit) {
  var today = getTodayUTC();
  var entry = chatLog[key];
  if (!entry || entry.date !== today) {
    chatLog[key] = { date: today, count: 0 };
    entry = chatLog[key];
  }
  if (entry.count >= limit) return false;
  entry.count++;
  return true;
}

function getChatRemaining(key, limit) {
  var today = getTodayUTC();
  var entry = chatLog[key];
  if (!entry || entry.date !== today) return limit;
  return Math.max(0, limit - entry.count);
}

// ── /api/chat ─────────────────────────────────────────────────────────────
app.post('/api/chat', jsonLarge, async function(req, res) {
  var body      = req.body || {};
  var visitorId = (body.visitorId || '').toString().trim().slice(0, 128);
  var message   = (body.message   || '').toString().trim().slice(0, 2000);
  var rawHistory = Array.isArray(body.history) ? body.history : [];

  if (!visitorId || !message) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  var sessionToken = (body.sessionToken || '').toString().trim().slice(0, 64);
  var tier = 'recruit';
  var walletAddress = null;
  var session = null;
  if (sessionToken) {
    session = await getSession(sessionToken);
    if (session) {
      tier = session.tier;
      walletAddress = session.wallet;
    }
  }

  // Re-check token balance every 6 hours to catch heroes who sold
  if (tier === 'operative' && walletAddress && session) {
    if (Date.now() - (session.lastBalanceCheck || 0) > BALANCE_RECHECK_INTERVAL) {
      try {
        var freshBalance = await getSolanaTokenBalance(walletAddress);
        var recheckUpdates = { balance: freshBalance, lastBalanceCheck: Date.now() };
        if (freshBalance < MIN_TOKENS) {
          recheckUpdates.tier = 'recruit';
          tier = 'recruit';
          walletAddress = null;
        }
        await updateSession(sessionToken, recheckUpdates);
      } catch (e) {
        console.error('Balance recheck error:', e.message);
        await updateSession(sessionToken, { lastBalanceCheck: Date.now() });
      }
    }
  }

  // H3: use server-side IP for recruit rate limiting — client-supplied visitorId is not trusted
  var ip = req.ip || visitorId;
  var limitKey   = (tier === 'operative' && walletAddress) ? 'w:' + walletAddress : 'ip:' + ip;
  var dailyLimit = (tier === 'operative') ? OPERATIVE_DAILY_LIMIT : RECRUIT_DAILY_LIMIT;

  if (!checkChatLimit(limitKey, dailyLimit)) {
    return res.status(429).json({
      error: 'rate_limited',
      remaining: 0,
      response: 'Signal exhausted. Return tomorrow, hero.'
    });
  }

  var remaining = getChatRemaining(limitKey, dailyLimit);

  // Vision image — operative-only, max ~4MB base64
  var imageSource = null;
  if (body.image && tier === 'operative') {
    var b64 = (body.image || '').toString().replace(/\s/g, '');
    if (b64.length > 0 && b64.length <= 5500000) {
      var MAGIC = {
        'image/jpeg': ['ffd8ff'],
        'image/png':  ['89504e47'],
        'image/gif':  ['47494638'],
        'image/webp': ['52494646'],
      };
      var raw = Buffer.from(b64.slice(0, 16), 'base64');
      var hex = raw.toString('hex');
      var detectedType = null;
      for (var mt in MAGIC) {
        if (MAGIC[mt].some(function(sig) { return hex.startsWith(sig); })) {
          detectedType = mt; break;
        }
      }
      if (detectedType) {
        imageSource = { type: 'base64', media_type: detectedType, data: b64 };
      }
    }
  }

  // H1: filter client history — strip entries that look like injection attempts
  var cleanClient = rawHistory
    .filter(function(m) {
      return m
        && (m.role === 'user' || m.role === 'assistant')
        && typeof m.content === 'string'
        && !looksLikeInjection(m.content);
    })
    .map(function(m) { return { role: m.role, content: m.content.slice(0, 2000) }; })
    .slice(-40);

  var messages = [];
  if (tier === 'operative' && walletAddress) {
    var saved = await loadHistory(walletAddress);
    messages = saved ? saved.slice(-40) : [];
  } else {
    messages = cleanClient.slice(-20);
  }

  var currentContent = imageSource
    ? [{ type: 'image', source: imageSource }, { type: 'text', text: message || 'Analyze this image.' }]
    : message;

  if (messages.length && messages[messages.length - 1].role === 'user') {
    messages[messages.length - 1] = { role: 'user', content: currentContent };
  } else {
    messages.push({ role: 'user', content: currentContent });
  }

  var ALLOWED_MODELS = { sonnet: 'claude-sonnet-4-6', haiku: 'claude-haiku-4-5-20251001' };
  var heroBalance = (session && session.balance) ? session.balance : 0;
  var modelKey = (tier === 'operative' && heroBalance >= SONNET_TOKENS) ? 'sonnet' : 'haiku';
  var modelId  = ALLOWED_MODELS[modelKey];
  var maxTokens = (modelKey === 'sonnet') ? 1000 : 500;

  // ── Streaming path (SSE) ──────────────────────────────────────────────────
  if (body.stream) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();
    var fullText = '';
    try {
      var msgStream = client.messages.stream({
        model: modelId, max_tokens: maxTokens,
        system: DESTINY_CHAT_PROMPT, messages: messages
      });
      msgStream.on('text', function(text) {
        fullText += text;
        res.write('data: ' + JSON.stringify({ t: text }) + '\n\n');
      });
      await msgStream.finalMessage();
      if (tier === 'operative' && walletAddress) {
        var sTextMessages = messages.map(function(m) {
          return { role: m.role, content: typeof m.content === 'string' ? m.content : message };
        });
        sTextMessages.push({ role: 'assistant', content: fullText });
        await saveHistory(walletAddress, sTextMessages.slice(-40));
        updateHeroActivity(walletAddress, message, new Date().getUTCHours(), heroBalance);
      }
      res.write('data: ' + JSON.stringify({ done: true, remaining: remaining, model: modelKey }) + '\n\n');
      res.end();
    } catch (err) {
      console.error('Stream error:', err.message || err);
      try { res.write('data: ' + JSON.stringify({ error: true }) + '\n\n'); res.end(); } catch(e) {}
    }
    return;
  }

  // ── Non-streaming fallback ────────────────────────────────────────────────
  try {
    var msg = await client.messages.create({
      model: modelId, max_tokens: maxTokens,
      system: DESTINY_CHAT_PROMPT, messages: messages
    });
    var text = (msg.content && msg.content[0] && msg.content[0].text) ? msg.content[0].text.trim() : 'Signal unclear.';

    if (tier === 'operative' && walletAddress) {
      var textMessages = messages.map(function(m) {
        return { role: m.role, content: typeof m.content === 'string' ? m.content : message };
      });
      textMessages.push({ role: 'assistant', content: text });
      await saveHistory(walletAddress, textMessages.slice(-40));
      updateHeroActivity(walletAddress, message, new Date().getUTCHours(), heroBalance);
    }

    res.json({ response: text, remaining: remaining, model: modelKey });
  } catch (err) {
    console.error('Chat API error:', err.message || err);
    res.status(500).json({ error: 'api_error', response: 'Static on the line. Try again.' });
  }
});

// ── /api/scan — proxies DexScreener so user IPs are not exposed (L5) ──────
app.get('/api/scan/:address', function(req, res) {
  var ip = req.ip || 'unknown';
  if (!checkScanLimit(ip)) return res.status(429).json({ error: 'rate_limited' });

  // Validate address — Solana base58 chars only, 20-50 chars
  var addr = (req.params.address || '').replace(/[^1-9A-HJ-NP-Za-km-z]/g, '');
  if (addr.length < 20 || addr.length > 50) {
    return res.status(400).json({ error: 'invalid_address' });
  }

  var ctrl = new AbortController();
  var t = setTimeout(function() { ctrl.abort(); }, 8000);

  fetch('https://api.dexscreener.com/latest/dex/tokens/' + encodeURIComponent(addr), { signal: ctrl.signal })
    .then(function(upstream) {
      clearTimeout(t);
      if (!upstream.ok) return res.status(upstream.status).json({ error: 'upstream_error' });
      return upstream.json().then(function(data) { res.json(data); });
    })
    .catch(function(e) {
      clearTimeout(t);
      res.status(500).json({ error: 'scan_error' });
    });
});

// ── /api/auth/link-email ──────────────────────────────────────────────────
app.post('/api/auth/link-email', jsonSmall, async function(req, res) {
  var body         = req.body || {};
  var sessionToken = (body.sessionToken || '').toString().trim().slice(0, 64);
  var email        = (body.email || '').toString().trim().toLowerCase().slice(0, 254);

  // L1: proper email validation
  if (!sessionToken || !email || !EMAIL_RE.test(email)) {
    return res.status(400).json({ error: 'missing_fields' });
  }
  if (!supabase) return res.status(503).json({ error: 'no_supabase' });

  var session = await getSession(sessionToken);
  if (!session) {
    return res.status(401).json({ error: 'invalid_session' });
  }

  try {
    var existing = await getUserByEmail(email);
    if (existing && existing.wallet !== session.wallet) {
      // M4: return generic 200 to avoid email enumeration — don't reveal the address is taken
      return res.json({ ok: true });
    }

    if (!checkMagicSendLimit(email)) {
      return res.status(429).json({ error: 'rate_limited' });
    }

    await upsertUser(session.wallet, email, session.tier, session.balance);
    var token = await createMagicToken(email);
    await sendMagicLinkEmail(email, token);
    res.json({ ok: true });
  } catch (e) {
    console.error('link-email error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

// ── /api/auth/magic-send ──────────────────────────────────────────────────
app.post('/api/auth/magic-send', jsonSmall, async function(req, res) {
  var body  = req.body || {};
  var email = (body.email || '').toString().trim().toLowerCase().slice(0, 254);

  // L1: proper email validation
  if (!email || !EMAIL_RE.test(email)) {
    return res.status(400).json({ error: 'invalid_email' });
  }
  if (!supabase) return res.status(503).json({ error: 'no_supabase' });
  if (!checkMagicSendLimit(email)) {
    return res.status(429).json({ error: 'rate_limited' });
  }

  try {
    var user = await getUserByEmail(email);
    if (user) {
      var token = await createMagicToken(email);
      await sendMagicLinkEmail(email, token);
    }
    // Always return ok — don't reveal whether email exists
    res.json({ ok: true });
  } catch (e) {
    console.error('magic-send error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

// ── /api/auth/magic-verify ────────────────────────────────────────────────
app.post('/api/auth/magic-verify', jsonSmall, async function(req, res) {
  // H2: rate limit verify attempts per IP
  var ip = req.ip || 'unknown';
  if (!checkVerifyLimit(ip)) return res.status(429).json({ error: 'rate_limited' });

  var body  = req.body || {};
  // L3: validate UUID format instead of just truncating
  var rawToken = (body.token || '').toString().trim();
  if (!rawToken || !UUID_RE.test(rawToken)) {
    return res.status(400).json({ error: 'missing_token' });
  }
  var token = rawToken;

  if (!supabase) return res.status(503).json({ error: 'no_supabase' });

  try {
    var email = await consumeMagicToken(token);
    if (!email) return res.status(401).json({ error: 'invalid_or_expired' });

    var user = await getUserByEmail(email);
    if (!user) return res.status(404).json({ error: 'user_not_found' });

    var balance  = await getSolanaTokenBalance(user.wallet);
    var tier     = balance >= MIN_TOKENS ? 'operative' : 'recruit';
    await upsertUser(user.wallet, email, tier, balance);

    var sessionToken = crypto.randomUUID();
    await createSession(sessionToken, user.wallet, tier, balance);
    if (tier === 'operative') ensureHero(user.wallet, null, balance);

    res.json({ tier, balance, sessionToken, wallet: user.wallet, email, minTokens: MIN_TOKENS });
  } catch (e) {
    console.error('magic-verify error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

// ── /api/heroes — community wall (public) ────────────────────────────────
app.get('/api/heroes', async function(req, res) {
  var heroes = await getAllHeroes();
  res.json({ heroes: heroes, count: heroes.length });
});

// ── /api/heroes/me — get own hero card ───────────────────────────────────
app.post('/api/heroes/me', jsonSmall, async function(req, res) {
  var body = req.body || {};
  var sessionToken = (body.sessionToken || '').toString().trim().slice(0, 64);
  if (!sessionToken) return res.status(401).json({ error: 'unauthorized' });
  var session = await getSession(sessionToken);
  if (!session) return res.status(401).json({ error: 'session_expired' });
  if (!supabase) return res.status(503).json({ error: 'no_supabase' });
  try {
    var { data, error } = await supabase.from('heroes').select('*').eq('wallet', session.wallet).single();
    if (error || !data) return res.status(404).json({ error: 'not_found' });
    var b = (session.balance != null ? session.balance : data.balance) || 0;
    var rank = b >= 10000000 ? 'LEGEND' : b >= 2000000 ? 'COMMANDER' : b >= 500000 ? 'AGENT' : 'OPERATIVE';
    res.json({ serial: data.serial, codename: data.codename, emblem: data.emblem,
               titles: data.titles, total_conversations: data.total_conversations,
               days_active: data.days_active, joined_at: data.joined_at, rank, gold: b >= 2000000,
               theme: data.theme || 'green', tagline: data.tagline || '', bg_pattern: data.bg_pattern || 'none',
               last_active_at: data.last_active_at || null, x_handle: data.x_handle || '', fx: data.fx || 'none', show_barcode: data.show_barcode || false });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
});

// ── /api/heroes/me PATCH — update emblem + codename ──────────────────────
app.patch('/api/heroes/me', jsonSmall, async function(req, res) {
  var body = req.body || {};
  var sessionToken = (body.sessionToken || '').toString().trim().slice(0, 64);
  if (!sessionToken) return res.status(401).json({ error: 'unauthorized' });
  var session = await getSession(sessionToken);
  if (!session) return res.status(401).json({ error: 'session_expired' });
  if (!supabase) return res.status(503).json({ error: 'no_supabase' });
  var updates = {};
  if (body.emblem !== undefined) {
    var embParts = body.emblem.toString().split('|');
    if (!VALID_EMBLEMS.includes(embParts[0])) return res.status(400).json({ error: 'invalid_emblem' });
    if (embParts[1] && !VALID_THEMES.includes(embParts[1])) return res.status(400).json({ error: 'invalid_emblem_color' });
    updates.emblem = body.emblem;
  }
  if (body.codename !== undefined) {
    var cn = body.codename.toString().trim().slice(0, 24);
    if (cn.length < 1) return res.status(400).json({ error: 'invalid_codename' });
    updates.codename = cn;
  }
  if (body.theme !== undefined) {
    if (!VALID_THEMES.includes(body.theme)) return res.status(400).json({ error: 'invalid_theme' });
    updates.theme = body.theme;
  }
  if (body.tagline !== undefined) {
    updates.tagline = body.tagline.toString().trim().slice(0, 50);
  }
  if (body.bg_pattern !== undefined) {
    var bgParts = body.bg_pattern.toString().split('|');
    if (!VALID_PATTERNS.includes(bgParts[0])) return res.status(400).json({ error: 'invalid_pattern' });
    if (bgParts[1] && !VALID_BANNERS.includes(bgParts[1])) return res.status(400).json({ error: 'invalid_banner' });
    updates.bg_pattern = body.bg_pattern;
  }
  if (body.show_barcode !== undefined) {
    updates.show_barcode = !!body.show_barcode;
  }
  if (body.x_handle !== undefined) {
    var xh = body.x_handle.toString().replace(/^@/, '').replace(/[^a-zA-Z0-9_.]/g, '').slice(0, 15);
    updates.x_handle = xh;
  }
  if (body.fx !== undefined) {
    if (!VALID_FX.includes(body.fx)) return res.status(400).json({ error: 'invalid_fx' });
    updates.fx = body.fx;
  }
  if (!Object.keys(updates).length) return res.status(400).json({ error: 'nothing_to_update' });
  try {
    await ensureHero(session.wallet, updates.codename || null, session.balance || 0);
    await supabase.from('heroes').update(updates).eq('wallet', session.wallet);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
});

// ── /api/admin/stats ──────────────────────────────────────────────────────
app.post('/api/admin/stats', jsonSmall, async function(req, res) {
  var ip = req.ip || 'unknown';
  if (!checkAdminLimit(ip)) return res.status(429).json({ error: 'rate_limited' });
  var body = req.body || {};
  var pw = (body.password || '').toString();
  var adminPw = process.env.ADMIN_PASSWORD || '';
  if (!adminPw) return res.status(503).json({ error: 'admin_not_configured' });
  try {
    var match = pw.length === adminPw.length &&
      crypto.timingSafeEqual(Buffer.from(pw, 'utf8'), Buffer.from(adminPw, 'utf8'));
    if (!match) return res.status(401).json({ error: 'unauthorized' });
  } catch (e) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  if (!supabase) return res.status(503).json({ error: 'no_supabase' });
  try {
    var { data: heroes, error: hErr } = await supabase
      .from('heroes')
      .select('wallet,codename,balance,total_conversations,days_active,joined_at,last_active_at')
      .order('total_conversations', { ascending: false });
    if (hErr) throw hErr;
    var heroesList = heroes || [];

    var tiers = { legend: 0, commander: 0, agent: 0, operative: 0 };
    heroesList.forEach(function(h) {
      var b = h.balance || 0;
      if (b >= 10000000) tiers.legend++;
      else if (b >= 2000000) tiers.commander++;
      else if (b >= 500000) tiers.agent++;
      else tiers.operative++;
    });

    var { data: sessionRows } = await supabase
      .from('sessions')
      .select('tier')
      .gt('expires_at', new Date().toISOString());
    var sessionsActive = (sessionRows || []).length;
    var sessionsByTier = { operative: 0, recruit: 0 };
    (sessionRows || []).forEach(function(s) {
      if (s.tier === 'operative') sessionsByTier.operative++;
      else sessionsByTier.recruit++;
    });

    var today = getTodayUTC();
    var messagesToday = 0;
    Object.keys(chatLog).forEach(function(k) {
      if (chatLog[k].date === today) messagesToday += chatLog[k].count;
    });

    var cutoff24h = new Date(Date.now() - 86400000).toISOString();
    var recentlyActive = heroesList.filter(function(h) {
      return h.last_active_at && h.last_active_at > cutoff24h;
    }).length;

    var newToday = heroesList.filter(function(h) {
      return h.joined_at && h.joined_at.startsWith(today);
    }).length;

    var topHeroes = heroesList.slice(0, 15).map(function(h) {
      var b = h.balance || 0;
      var rank = b >= 10000000 ? 'LEGEND' : b >= 2000000 ? 'COMMANDER' : b >= 500000 ? 'AGENT' : 'OPERATIVE';
      return {
        codename: h.codename || 'UNKNOWN',
        wallet: h.wallet.slice(0, 6) + '..' + h.wallet.slice(-4),
        total_conversations: h.total_conversations || 0,
        days_active: h.days_active || 0,
        rank: rank,
        last_active_at: h.last_active_at || null
      };
    });

    res.json({
      heroes_total: heroesList.length,
      tier_breakdown: tiers,
      sessions_active: sessionsActive,
      sessions_by_tier: sessionsByTier,
      messages_today: messagesToday,
      recently_active_24h: recentlyActive,
      new_today: newToday,
      top_heroes: topHeroes,
      generated_at: new Date().toISOString()
    });
  } catch (e) {
    console.error('admin/stats error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

// ── /api/heroes/reveal-comment ────────────────────────────────────────────
var revealLimiter = new Map();
app.post('/api/heroes/reveal-comment', jsonSmall, async function(req, res) {
  var ip = req.ip || 'unknown';
  var now = Date.now();
  if ((now - (revealLimiter.get(ip) || 0)) < 30000) return res.status(429).json({ error: 'rate_limited' });
  revealLimiter.set(ip, now);

  var body = req.body || {};
  var codename    = String(body.codename    || 'UNKNOWN').slice(0, 30);
  var emblem      = String(body.emblem      || 'hexagon').slice(0, 20);
  var theme       = String(body.theme       || 'green').slice(0, 12);
  var bgPattern   = String(body.bg_pattern  || 'none').slice(0, 20);
  var bannerStyle = String(body.banner_style|| 'clean').slice(0, 20);
  var fx          = String(body.fx          || 'none').slice(0, 20);
  var rank        = String(body.rank        || 'OPERATIVE').slice(0, 20);

  try {
    var msg = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 80,
      messages: [{
        role: 'user',
        content: 'A hero just received their DESTINY terminal card. Write ONE punchy comment (max 22 words) on their specific choices. Dry, slightly intimidating, cool. Reference their actual picks directly. No quotes.\n\nCallsign: ' + codename + '\nEmblem: ' + emblem + '\nColor theme: ' + theme + '\nBackground: ' + bgPattern + '\nBanner: ' + bannerStyle + '\nFX: ' + fx + '\nRank: ' + rank
      }]
    });
    var comment = ((msg.content[0] && msg.content[0].text) || '').trim().replace(/^["""'']+|["""'']+$/g, '');
    res.json({ comment: comment });
  } catch (e) {
    res.status(500).json({ error: 'ai_error' });
  }
});

var PORT = process.env.PORT || 3001;
app.listen(PORT, function() {
  console.log('Chat server running on http://localhost:' + PORT);
  console.log('API key:', process.env.ANTHROPIC_API_KEY ? 'SET' : 'MISSING');
});

// ── Telegram bot ──────────────────────────────────────────────────────────
if (process.env.TELEGRAM_BOT_TOKEN) {
  var tgBot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);

  // Short in-memory context per chat (last 10 turns, resets on restart)
  var tgHistory = new Map();
  var TG_MAX_HISTORY = 10;

  setInterval(function() {
    // Clean up chats idle for 2 hours
    var cutoff = Date.now() - 7200000;
    tgHistory.forEach(function(v, k) { if (v.ts < cutoff) tgHistory.delete(k); });
  }, 900000);

  tgBot.on('text', async function(ctx) {
    var userId   = String(ctx.from.id);
    var message  = (ctx.message.text || '').trim().slice(0, 2000);
    var limitKey = 'tg:' + userId;

    if (!message) return;

    // Commands
    if (message === '/start') {
      return ctx.reply(
        '// DESTINY ONLINE\n\nI\'m DESTINY — AI crypto intelligence. Ask me anything about crypto, DeFi, tokens, or building in the space.\n\nNo financial advice. Just real answers.'
      );
    }
    if (message === '/help') {
      return ctx.reply(
        '// AVAILABLE\n\nJust talk to me. Ask about tokens, market cycles, DeFi, scam detection, AI agents, or anything in the crypto space.\n\nVisit terminaldestiny.com to connect your wallet and unlock hero status.'
      );
    }

    // Rate limit — 20 messages/day (recruit tier)
    if (!checkChatLimit(limitKey, RECRUIT_DAILY_LIMIT)) {
      return ctx.reply('Signal exhausted. Return tomorrow.');
    }

    // Build messages with short in-memory context
    var hist = tgHistory.get(userId) || { turns: [], ts: Date.now() };
    hist.ts = Date.now();
    var messages = hist.turns.slice(-(TG_MAX_HISTORY * 2));
    messages.push({ role: 'user', content: message });

    try {
      await ctx.sendChatAction('typing');
      var msg = await client.messages.create({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 500,
        system: DESTINY_CHAT_PROMPT,
        messages: messages
      });
      var reply = (msg.content && msg.content[0] && msg.content[0].text)
        ? msg.content[0].text.trim()
        : 'Signal unclear. Try again.';

      // Update in-memory history
      hist.turns.push({ role: 'user', content: message });
      hist.turns.push({ role: 'assistant', content: reply });
      if (hist.turns.length > TG_MAX_HISTORY * 2) hist.turns = hist.turns.slice(-(TG_MAX_HISTORY * 2));
      tgHistory.set(userId, hist);

      await ctx.reply(reply);
    } catch (e) {
      console.error('TG bot error:', e.message);
      ctx.reply('Static on the line. Try again.').catch(function() {});
    }
  });

  tgBot.launch().then(function() {
    console.log('Telegram bot: online');
  }).catch(function(e) {
    console.error('Telegram bot failed to start:', e.message);
  });

  process.once('SIGINT',  function() { tgBot.stop('SIGINT');  });
  process.once('SIGTERM', function() { tgBot.stop('SIGTERM'); });
} else {
  console.log('Telegram bot: TELEGRAM_BOT_TOKEN not set, skipping');
}
