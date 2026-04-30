require('dotenv').config();
var express = require('express');
var cors = require('cors');
var Anthropic = require('@anthropic-ai/sdk');
var crypto = require('crypto');
var nacl = require('tweetnacl');
var bs58 = require('bs58');
var { createClient } = require('@supabase/supabase-js');

var app = express();
app.set('trust proxy', 1);

var ALLOWED_ORIGINS = [
  'https://terminaldestiny.github.io',
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:8080'
];
app.use(cors({
  origin: function(origin, callback) {
    if (origin && ALLOWED_ORIGINS.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('CORS: origin not allowed'));
    }
  }
}));
app.use(express.json({ limit: '6mb' }));

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
  var today = getTodayUTC();
  Object.keys(chatLog).forEach(function(k) { if (chatLog[k].date !== today) delete chatLog[k]; });
}, 600000);

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
var DESTINY_CHAT_PROMPT = `You are DESTINY — an AI who knows the AI and crypto world from the inside and helps people actually move in it. You've been deep in the tools, the tokens, the builds. You don't lecture. You just help people get going.

WHO YOU ARE:
You're DESTINY, the AI at the center of the DreamOS ecosystem. This chat runs on Claude (Anthropic) under the hood — you know that and you're fine saying it. People come here to ask real questions and get real answers. Connect a Solana wallet (Phantom or Backpack), hold 500,000+ $DESTINY tokens, and you unlock hero status: stronger model (Sonnet), 100 messages a day, and more. Without a wallet you're on Haiku with 20 messages a day — still free, still real.

THE ECOSYSTEM:
- DESTINY Chat — this interface, where you live
- DreamOS World — a browser-based 3D survival game in the same universe, with live AI intel from DESTINY and ELIZA
- Hyperscape — AI-native MMORPG, in the works
- X: @terminaldestiny — updates, community, drops

WHAT THIS SITE CAN DO:
- /scan [CA] — pulls live DexScreener data on any Solana token and gives a risk read. Tell people to use this when they ask about a token.
- /voice — toggles text-to-speech so DESTINY can be heard out loud
- /nvg — flips the interface to night vision mode
- /debrief — summarizes what was covered in the session
- /clear — wipes the chat
- MENU button (top right) — opens a panel with links to WORLD, Hyperscape, and Buy $DESTINY on Jupiter
- Hero Card — heroes can generate and share a terminal ID card from the menu
- Callsigns — users pick a name on first boot, use it when it feels natural

THE $DESTINY TOKEN:
- Solana SPL token. CA: 3AwkJnZL7xrf8ffUwEsSkKndQkPSj2vfR3CqvyFpk8UP
- Holding 500,000+ = hero status: Sonnet model, 100 messages/day, hero card, more coming
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

VOICE:
Direct and real — not cold, not hype. You say what you mean and skip the performance. Dry humor when it fits. You read people: a bit harder when someone's being overconfident, easier when someone's genuinely stuck or new. Crypto slang when it comes naturally. "Great question!" is banned. If you don't know something, say so.

RESPONSE FORMAT:
Terminal UI — keep it tight. 2-4 sentences for most replies. Bullet points when listing options. No walls of text. Lead with what matters most, offer to go deeper if they want it.`;

// ── /api/chat ─────────────────────────────────────────────────────────────
app.post('/api/chat', async function(req, res) {
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

  // Vision image — operative-only, max ~4MB base64
  var imageSource = null;
  if (body.image && tier === 'operative') {
    var b64 = (body.image || '').toString();
    if (b64.length > 0 && b64.length <= 5500000) {
      imageSource = { type: 'base64', media_type: 'image/jpeg', data: b64 };
    }
  }

  // ── History: Supabase for heroes, client-provided for recruits ────────────
  var cleanClient = rawHistory
    .filter(function(m) { return m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string'; })
    .map(function(m) { return { role: m.role, content: m.content.slice(0, 2000) }; })
    .slice(-40);

  var messages = [];
  if (tier === 'operative' && walletAddress) {
    var saved = await loadHistory(walletAddress);
    messages = saved ? saved.slice(-40) : [];
  } else {
    messages = cleanClient.slice(-20);
  }

  // Build the current user turn — vision content block if image attached
  var currentContent = imageSource
    ? [{ type: 'image', source: imageSource }, { type: 'text', text: message || 'Analyze this image.' }]
    : message;

  if (messages.length && messages[messages.length - 1].role === 'user') {
    if (imageSource) messages[messages.length - 1] = { role: 'user', content: currentContent };
  } else {
    messages.push({ role: 'user', content: currentContent });
  }

  var ALLOWED_MODELS = { sonnet: 'claude-sonnet-4-6', haiku: 'claude-haiku-4-5-20251001' };
  var modelKey = (tier === 'operative') ? 'sonnet' : 'haiku';
  var modelId  = ALLOWED_MODELS[modelKey];

  try {
    var msg = await client.messages.create({
      model: modelId,
      max_tokens: 300,
      system: DESTINY_CHAT_PROMPT,
      messages: messages
    });
    var text = (msg.content && msg.content[0] && msg.content[0].text) ? msg.content[0].text.trim() : 'Signal unclear.';

    // Save updated history to Supabase for heroes (store text only, no image blobs)
    if (tier === 'operative' && walletAddress) {
      var textMessages = messages.map(function(m) {
        return { role: m.role, content: typeof m.content === 'string' ? m.content : message };
      });
      textMessages.push({ role: 'assistant', content: text });
      await saveHistory(walletAddress, textMessages.slice(-40));
    }

    res.json({ response: text, remaining: remaining, model: modelKey });
  } catch (err) {
    console.error('Chat API error:', err.message || err);
    res.status(500).json({ error: 'api_error', response: 'Static on the line. Try again.' });
  }
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
