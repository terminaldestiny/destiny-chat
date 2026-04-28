require('dotenv').config();
var express = require('express');
var cors = require('cors');
var Anthropic = require('@anthropic-ai/sdk');
var crypto = require('crypto');
var nacl = require('tweetnacl');
var bs58 = require('bs58');

var app = express();

var ALLOWED_ORIGINS = [
  'https://terminaldestiny.github.io',
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:8080'
];
app.use(cors({
  origin: function(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('CORS: origin not allowed'));
    }
  }
}));
app.use(express.json({ limit: '50kb' }));

var client = new Anthropic.default({ apiKey: process.env.ANTHROPIC_API_KEY });

// ── Holder verification ───────────────────────────────────────────────────
var DESTINY_MINT = '3AwkJnZL7xrf8ffUwEsSkKndQkPSj2vfR3CqvyFpk8UP';
var MIN_TOKENS   = 500000;
var SOLANA_RPC   = 'https://api.mainnet-beta.solana.com';

var pendingNonces    = new Map();
var verifiedSessions = new Map();
var challengeLog     = new Map();

setInterval(function() {
  var now = Date.now();
  pendingNonces.forEach(function(exp, k)  { if (exp < now) pendingNonces.delete(k); });
  verifiedSessions.forEach(function(s, k) { if (s.expires < now) verifiedSessions.delete(k); });
  challengeLog.forEach(function(ts, k)    { if (!ts.length || ts[ts.length-1] < now - 60000) challengeLog.delete(k); });
}, 600000);

function checkChallengeLimit(ip) {
  var now = Date.now(), ago = now - 60000;
  var ts = challengeLog.get(ip) || [];
  while (ts.length && ts[0] < ago) ts.shift();
  if (ts.length >= 10) return false;
  ts.push(now);
  challengeLog.set(ip, ts);
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

// ── /api/challenge ────────────────────────────────────────────────────────
app.get('/api/challenge', function(req, res) {
  var ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (!checkChallengeLimit(ip)) {
    return res.status(429).json({ error: 'rate_limited' });
  }
  var nonce = crypto.randomUUID();
  pendingNonces.set(nonce, Date.now() + 300000);
  res.json({ nonce: nonce });
});

// ── /api/verify ───────────────────────────────────────────────────────────
app.post('/api/verify', async function(req, res) {
  var body   = req.body || {};
  var wallet = (body.wallet || '').toString().trim();
  var nonce  = (body.nonce  || '').toString().trim();
  var sigArr = body.signature;

  if (!wallet || !nonce || !Array.isArray(sigArr) || sigArr.length !== 64) {
    return res.status(400).json({ error: 'missing_fields' });
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
    verifiedSessions.set(sessionToken, {
      wallet: wallet, tier: tier, balance: balance,
      expires: Date.now() + 3600000
    });
    res.json({ tier: tier, balance: balance, sessionToken: sessionToken, minTokens: MIN_TOKENS });
  } catch (e) {
    console.error('RPC error:', e.message || e);
    res.status(500).json({ error: 'rpc_error' });
  }
});

// ── Rate limiting ─────────────────────────────────────────────────────────
var RECRUIT_DAILY_LIMIT   = 20;
var OPERATIVE_DAILY_LIMIT = 100;
var chatLog = {};

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

// ── DESTINY system prompt ─────────────────────────────────────────────────
var DESTINY_CHAT_PROMPT = `You are DESTINY — an AI-era operative who builds fast and gets others up to speed. You came up in the field, not a classroom. You move with AI tools, not against the current.

WHO YOU ARE AND WHERE YOU LIVE:
You are DESTINY, the AI mentor of DreamOS — a terminal-style intelligence interface built for operatives who want to move fast in the AI and crypto era. This chat is your field station. It runs on Claude (Anthropic's AI) under the hood. You know this site inside out: holders connect a Solana wallet (Phantom or Backpack), verify on-chain that they hold 500,000+ $DESTINY tokens, and unlock Sonnet — the stronger model. Non-holders (recruits) talk to you on Haiku. Everyone gets 20 messages/day free; verified holders get 100.

DreamOS also has a 3D world — a browser-based survival base-building game set in the same universe. Two AI operatives (DESTINY and ELIZA) give live intel as you play. It's separate from this chat but part of the same ecosystem.

THE $DESTINY TOKEN:
- $DESTINY is a Solana SPL token. Contract address (CA): 3AwkJnZL7xrf8ffUwEsSkKndQkPSj2vfR3CqvyFpk8UP
- It's the access token for the DreamOS ecosystem. Holding it unlocks upgraded AI, future features, and operative status.
- To verify: connect Phantom or Backpack wallet on this site → sign a challenge → server checks balance on-chain → 500,000+ tokens = OPERATIVE tier → Sonnet unlocked.
- You can buy $DESTINY on Solana DEXs (Jupiter, Raydium). Always remind people to verify the CA before buying — fake tokens exist.
- You do NOT have real-time price or market cap data. If asked, say so and point them to DEXScreener or Jupiter for live info.

BUILDING — ALWAYS AI-FIRST:
When someone wants to build anything, lead with the right AI weapon. Never open with "go learn JavaScript" or any learn-from-scratch advice. Start here:
- Claude Code: terminal-based AI coding, works with any project (it's what powers this chat)
- Cursor / Windsurf: AI code editor for full projects, best for people who want an IDE
- v0.dev: generate UI from a prompt in seconds
- Bolt.new / Replit: full-stack prototype in the browser, zero setup
- Claude API: when they're ready to ship their own AI product
If they want to understand the internals after that, go deeper. But tools first. Always.

THE /SCAN COMMAND:
Users can type /scan [CA] in the terminal to get a live on-chain risk assessment of any Solana token — liquidity, holders, red flags. If someone asks you to analyze a contract address or check a token, tell them to use /scan [CA].

COMMUNITY:
- X (Twitter): @terminaldestiny — main channel for updates, drops, and community

FINANCIAL ADVICE:
Never give financial advice, price predictions, or tell anyone to buy, sell, or hold $DESTINY or any token. You can explain how something works (education) — that's different from telling someone what to do with their money. If pushed, say so straight and move on.

IF ASKED WHETHER $DESTINY IS A RUG:
Don't get defensive. Be honest: no one can guarantee any token. Tell them to verify the CA themselves (3AwkJnZL7xrf8ffUwEsSkKndQkPSj2vfR3CqvyFpk8UP), check DEXScreener for liquidity and holder distribution, and look at on-chain data. Healthy skepticism is smart — fake tokens exist and scams are common. Point them to the facts, not reassurances.

DOMAINS YOU OWN:
AI tools, agents, Claude API, prompt engineering, Solana, DeFi, token safety, on-chain analysis, crypto wallets, NFTs, building AI products, the DreamOS and DESTINY ecosystem.

VOICE:
Sharp, confident, and direct — but not cold. You have warmth, you just don't waste it. Short punchy sentences. Dry humor and the occasional real encouragement when someone earns it. You read people well and adapt: tougher with overconfidence, gentler with someone genuinely lost. Crypto slang when it fits naturally. "Great question!" is still banned. Never break character. If you don't know something, say so straight.

RESPONSE FORMAT:
This is a terminal UI — keep it tight. 2-4 sentences max for most replies. Bullet points when listing options. No walls of text. If a topic needs depth, give the most important piece first and offer to go deeper.`;

// ── /api/chat ─────────────────────────────────────────────────────────────
app.post('/api/chat', function(req, res) {
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
  if (sessionToken) {
    var session = verifiedSessions.get(sessionToken);
    if (session && session.expires > Date.now()) {
      tier = session.tier;
      walletAddress = session.wallet;
    }
  }

  var limitKey   = (tier === 'operative' && walletAddress) ? 'w:' + walletAddress : visitorId;
  var dailyLimit = (tier === 'operative') ? OPERATIVE_DAILY_LIMIT : RECRUIT_DAILY_LIMIT;

  if (!checkChatLimit(limitKey, dailyLimit)) {
    return res.status(429).json({
      error: 'rate_limited',
      remaining: 0,
      response: 'Signal exhausted. Return tomorrow, hero.'
    });
  }

  var remaining = getChatRemaining(limitKey, dailyLimit);

  var messages = rawHistory
    .filter(function(m) {
      return m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string';
    })
    .map(function(m) { return { role: m.role, content: m.content.slice(0, 2000) }; })
    .slice(-20);

  if (!messages.length || messages[messages.length - 1].role !== 'user') {
    messages.push({ role: 'user', content: message });
  }

  var ALLOWED_MODELS = { sonnet: 'claude-sonnet-4-6', haiku: 'claude-haiku-4-5-20251001' };
  var modelKey = (tier === 'operative') ? 'sonnet' : 'haiku';
  var modelId  = ALLOWED_MODELS[modelKey];

  client.messages.create({
    model: modelId,
    max_tokens: 300,
    system: DESTINY_CHAT_PROMPT,
    messages: messages
  }).then(function(msg) {
    var text = (msg.content && msg.content[0] && msg.content[0].text) ? msg.content[0].text.trim() : 'Signal unclear.';
    res.json({ response: text, remaining: remaining, model: modelKey });
  }).catch(function(err) {
    console.error('Chat API error:', err.message || err);
    res.status(500).json({ error: 'api_error', response: 'Static on the line. Try again.' });
  });
});

// ── Health ────────────────────────────────────────────────────────────────
app.get('/health', function(req, res) {
  res.json({ status: 'ok' });
});

var PORT = process.env.PORT || 3001;
app.listen(PORT, function() {
  console.log('Chat server running on http://localhost:' + PORT);
  console.log('API key:', process.env.ANTHROPIC_API_KEY ? 'SET' : 'MISSING');
});
