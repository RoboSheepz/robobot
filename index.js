require('dotenv').config();
const tmi = require('tmi.js');
const { validateToken, attachDebug, sendAndLog } = require('./troubleshoot');
const db = require('./db');
const https = require('https');
const os = require('os');
const fs = require('fs');
const path = require('path');
const http = require('http');
// Global message queue settings
const MESSAGE_INTERVAL_MS = Number(process.env.MESSAGE_INTERVAL_MS || 1100);

// Banphrase API configuration
const BANPHRASE_API_URL = process.env.BANPHRASE_API_URL || 'https://pajlada.pajbot.com/api/v1/banphrases/test';

// Helper function to check message against banphrase API
async function checkBanphrase(message) {
  return new Promise((resolve) => {
    try {
      const postData = JSON.stringify({ message: String(message) });
      const url = new URL(BANPHRASE_API_URL);
      
      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        },
        timeout: 3000
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data || '{}');
            // API returns { banned: true/false, ... }
            resolve({ banned: !!parsed.banned, response: parsed });
          } catch (e) {
            console.error('Banphrase API parse error:', e);
            resolve({ banned: false, error: e });
          }
        });
      });

      req.on('error', (err) => {
        console.error('Banphrase API request error:', err);
        resolve({ banned: false, error: err });
      });

      req.on('timeout', () => {
        req.destroy();
        console.error('Banphrase API timeout');
        resolve({ banned: false, error: new Error('timeout') });
      });

      req.write(postData);
      req.end();
    } catch (e) {
      console.error('Banphrase check error:', e);
      resolve({ banned: false, error: e });
    }
  });
}

// Global send queue
const sendQueue = [];
let sendProcessing = false;

// Wrapper that records outgoing messages so echoed messages can be detected
function sendAndRecord(channel, text) {
  const now = Date.now();
  lastOutgoing = String(text);
  lastOutgoingTs = now;
  recentOutgoing.set(String(text), now);
  // prune old entries
  for (const [k, ts] of recentOutgoing) {
    if ((now - ts) > 60000) recentOutgoing.delete(k);
  }
  return sendAndLog(client, channel, text);
}

function enqueueSend(channel, text) {
  return new Promise((resolve, reject) => {
    sendQueue.push({ channel, text, resolve, reject });
    if (!sendProcessing) processSendQueue();
  });
}

async function processSendQueue() {
  if (sendProcessing) return;
  sendProcessing = true;
  while (sendQueue.length) {
    const item = sendQueue.shift();
    try {
      // Check message against banphrase API
      const banResult = await checkBanphrase(item.text);
      let messageToSend = item.text;
      
      if (banResult.banned) {
        console.log(`Message blocked by banphrase API: "${item.text}"`);
        messageToSend = '[banphrased]';
      }
      
      // record outgoing message immediately so echoes can be detected
      const now = Date.now();
      lastOutgoing = String(messageToSend);
      lastOutgoingTs = now;
      recentOutgoing.set(String(messageToSend), now);
      for (const [k, ts] of recentOutgoing) {
        if ((now - ts) > 60000) recentOutgoing.delete(k);
      }
      await sendAndLog(client, item.channel, messageToSend);
      item.resolve();
    } catch (err) {
      item.reject(err);
    }
    await new Promise(r => setTimeout(r, MESSAGE_INTERVAL_MS));
  }
  sendProcessing = false;
}

// Convenience wrapper used throughout: queue the send
function queueSend(channel, text) {
  return enqueueSend(channel, text);
}

const opts = {
  options: { debug: true },
  identity: {
    username: process.env.TWITCH_USERNAME,
    password: process.env.TWITCH_OAUTH
  },
  channels: []
};

const client = new tmi.Client(opts);

// Log configured identity and channel for debugging
console.log(`Configured identity: ${opts.identity.username}`);
console.log(`Configured channels: none (loaded from DB)`);

// Track last outgoing message to avoid replying to our own echoed messages
let lastOutgoing = null;
let lastOutgoingTs = 0;
// recent outgoing messages to recognize echoes (message -> ts)
const recentOutgoing = new Map();

// Per-user, per-command cooldowns (ms). Default 5000ms (5s). Can be overridden via env COMMAND_COOLDOWN_MS
const COMMAND_COOLDOWN_MS = Number(process.env.COMMAND_COOLDOWN_MS || 5000);
// Map key: `${userIdOrName}:${command}` -> last run timestamp (ms)
const commandCooldowns = new Map();

// Per-channel recent users (LRU of unique usernames). Map channelKey -> array of usernames (most recent first)
const recentUsers = new Map();

// In-memory caches loaded from DB at startup
let adminsCache = new Set();
let channelsCache = new Map();
let helixClientId = null;

// In-memory set of banned user IDs (populated from DB at startup)
let bannedUsersCache = new Set();
// Ban/unban helpers (DB and cache)
async function banUser(uid) {
  if (!uid) return;
  try {
    await db.addBannedUser(uid);
    bannedUsersCache.add(String(uid));
  } catch (e) {
    console.error('Failed to ban user:', e);
  }
}

async function unbanUser(uid) {
  if (!uid) return;
  try {
    await db.removeBannedUser(uid);
    bannedUsersCache.delete(String(uid));
  } catch (e) {
    console.error('Failed to unban user:', e);
  }
}

// OpenRouter LLM configuration
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'gpt-4o-mini';
const OPENROUTER_URL = process.env.OPENROUTER_URL || 'https://api.openrouter.ai/v1/chat/completions';
// Optional system prompt / extra context to include with every LLM call
let LLM_SYSTEM_PROMPT = process.env.LLM_SYSTEM_PROMPT || 'You are to play the role of a concise assistant in a Twitch chat.'; // CHANGED: let
// Optional character card (JanitorAI PNG format)
let LLM_CHARACTER_CARD = process.env.LLM_CHARACTER_CARD || null; // CHANGED: let
let characterCardData = null;
// LLM context budgeting (tokens)
const LLM_CONTEXT_TOKENS = Number(process.env.LLM_CONTEXT_TOKENS || 8192);
const LLM_RESPONSE_TOKEN_BUFFER = Number(process.env.LLM_RESPONSE_TOKEN_BUFFER || 8192);

// Token estimation helpers (tries tiktoken; falls back to chars/4)
let tkEncoder = null;
function tryInitTokenizer() {
  if (tkEncoder !== null) return;
  try {
    // Lazy load tokenizer if available
    const { encoding_for_model } = require('@dqbd/tiktoken');
    // Use cl100k_base-compatible model name for approximation
    tkEncoder = encoding_for_model('gpt-4o-mini');
  } catch (e) {
    tkEncoder = false; // mark unavailable
  }
}

function estimateTokensForText(text) {
  const s = String(text || '');
  if (!s) return 0;
  tryInitTokenizer();
  try {
    if (tkEncoder) {
      const tokens = tkEncoder.encode(s);
      return tokens.length;
    }
  } catch (_) {}
  // Fallback heuristic: ~4 chars per token
  return Math.ceil(s.length / 4);
}

function estimateMessagesTokens(messages) {
  if (!Array.isArray(messages)) return 0;
  let total = 0;
  for (const m of messages) {
    total += estimateTokensForText(m && m.content ? m.content : '');
    // add small overhead per message for roles/formatting
    total += 4;
  }
  return total;
}

// Helper function to extract character data from PNG file (JanitorAI format)
function loadCharacterCard(filePath) {
  try {
    if (!filePath) return null;
    const fullPath = path.isAbsolute(filePath) ? filePath : path.join(__dirname, filePath);
    if (!fs.existsSync(fullPath)) {
      console.warn(`Character card file not found: ${fullPath}`);
      return null;
    }
    const buffer = fs.readFileSync(fullPath);
    // PNG files start with specific signature
    if (buffer.length < 8 || buffer.toString('hex', 0, 8) !== '89504e470d0a1a0a') {
      console.warn('Invalid PNG file format for character card');
      return null;
    }
    // Parse PNG chunks to find tEXt/zTXt chunks containing character data
    let offset = 8; // Skip PNG signature
    while (offset < buffer.length) {
      if (offset + 8 > buffer.length) break;
      const chunkLength = buffer.readUInt32BE(offset);
      const chunkType = buffer.toString('ascii', offset + 4, offset + 8);
      offset += 8;
      if (offset + chunkLength > buffer.length) break;
      // Look for tEXt chunk with 'chara' key (common in character cards)
      if (chunkType === 'tEXt') {
        const chunkData = buffer.slice(offset, offset + chunkLength);
        const nullIndex = chunkData.indexOf(0);
        if (nullIndex !== -1) {
          const keyword = chunkData.toString('latin1', 0, nullIndex);
          if (keyword === 'chara' || keyword === 'character' || keyword === 'card') {
            const textData = chunkData.toString('utf8', nullIndex + 1);
            try {
              // Try to parse as base64-encoded JSON
              const decoded = Buffer.from(textData, 'base64').toString('utf8');
              const parsed = JSON.parse(decoded);
              console.log('Successfully loaded character card data');
              return parsed;
            } catch (e) {
              // Maybe it's already JSON
              try {
                const parsed = JSON.parse(textData);
                console.log('Successfully loaded character card data');
                return parsed;
              } catch (e2) {
                console.warn('Failed to parse character card data:', e2);
              }
            }
          }
        }
      }
      offset += chunkLength + 4; // +4 for CRC
    }
    console.warn('No character data found in PNG file');
    return null;
  } catch (e) {
    console.error('Error loading character card:', e);
    return null;
  }
}

// NEW: download a PNG to data/char and return saved path
async function downloadPNG(urlStr, destDir) {
  return new Promise((resolve, reject) => {
    try {
      const u = new URL(urlStr);
      const mod = u.protocol === 'https:' ? https : http;
      fs.mkdirSync(destDir, { recursive: true });
      const filename = `char-${Date.now()}.png`;
      const outPath = path.join(destDir, filename);
      const file = fs.createWriteStream(outPath);
      const req = mod.get(u, (res) => {
        if (res.statusCode !== 200) {
          file.close(); fs.unlink(outPath, () => {});
          return reject(new Error(`HTTP ${res.statusCode}`));
        }
        const ct = String(res.headers['content-type'] || '');
        if (!ct.includes('image/png')) {
          // allow octet-stream with .png name
          if (!ct.includes('application/octet-stream')) {
            file.close(); fs.unlink(outPath, () => {});
            return reject(new Error(`Invalid content-type: ${ct}`));
          }
        }
        res.pipe(file);
        file.on('finish', () => file.close(() => resolve(outPath)));
      });
      req.on('error', (err) => {
        try { file.close(); fs.unlink(outPath, () => {}); } catch (_) {}
        reject(err);
      });
    } catch (e) { reject(e); }
  });
}

// Per-user conversation memory (array of {role, content}) to include previous Q/A
const userConversations = new Map();
const USER_CONV_LIMIT = Number(process.env.USER_CONV_LIMIT || 10);
// Per-channel chat history (array of {user, text, ts}); used by askchat
const channelChatHistory = new Map();
const CHAT_HISTORY_LIMIT = Number(process.env.CHAT_HISTORY_LIMIT || 20000); // messages
const CHAT_HISTORY_MAX_CHARS = Number(process.env.CHAT_HISTORY_MAX_CHARS || 400000);

// token validation moved to `troubleshoot.js` (imported above)

client.on('message', async (channel, tags, message, self) => {
  // Always log inbound messages for debugging
  const time = new Date().toISOString();
  const username = tags['display-name'] || tags.username;
  // console.log(`[${time}] ${channel} <${username}>: ${message} (self=${self})`);
  

  // If this message is an echo of our own outgoing message, ignore it to avoid loops.
  const msg = String(message || '').trim();
  if (self && tags && String(tags.username).toLowerCase() === String(opts.identity.username).toLowerCase()) {
    const now = Date.now();
    // check recent outgoing set first
    if (recentOutgoing.has(msg) && (now - recentOutgoing.get(msg) < 5000)) {
      console.log(`[${time}] Ignoring echoed outgoing message (recent): ${msg}`);
      return;
    }
    if (lastOutgoing && msg === lastOutgoing && (now - lastOutgoingTs) < 5000) {
      console.log(`[${time}] Ignoring echoed outgoing message: ${msg}`);
      return;
    }
    // If it's from our own account but not matching our last outgoing message, continue processing.
  }

  if (!msg) return;

  // Determine channel key (without leading '#') and channel config for this channel
  const channelKey = channel && channel.startsWith('#') ? channel.slice(1) : (channel || '');
  const chanCfg = channelsCache.get(channelKey) || { prefix: '!', require_admin: false };
  const prefix = chanCfg.prefix || '!';

  // Update recent users LRU (unique) for this channel and persist all chat messages
  try {
    const loginRaw = (tags && (tags.username || '')) || String(username || '');
    const login = String(loginRaw).toLowerCase().trim();
    if (login) {
      const arr = recentUsers.get(channelKey) || [];
      const idx = arr.indexOf(login);
      if (idx !== -1) arr.splice(idx, 1);
      arr.unshift(login);
      if (arr.length > 100) arr.length = 100;
      recentUsers.set(channelKey, arr);
    }
    // Persist every chat message to DB
    try {
      await db.addChatMessage(channelKey, login, String(message || ''), Date.now());
    } catch (e) {
      console.error('Failed persisting chat message to DB:', e);
    }
    // Also update in-memory channelChatHistory for fast access (optional)
    try {
      const hist = channelChatHistory.get(channelKey) || [];
      hist.push({ user: login, text: String(message || ''), ts: Date.now() });
      if (hist.length > CHAT_HISTORY_LIMIT) hist.splice(0, hist.length - CHAT_HISTORY_LIMIT);
      channelChatHistory.set(channelKey, hist);
    } catch (e) {
      console.error('Failed updating channelChatHistory:', e);
    }
  } catch (e) {
    console.error('Failed updating recentUsers or persisting chat:', e);
  }

    // If the first word mentions the bot by username, call the `ask` command.
    try {
      const botName = String(process.env.TWITCH_USERNAME || opts.identity.username || '').toLowerCase();
      if (botName) {
        const words = msg.split(/\s+/);
        if (words.length > 1) {
          let first = words[0] || '';
          if (first.startsWith('@')) first = first.slice(1);
          // strip trailing punctuation , . ; :
          first = first.replace(/[\,\.\;\:]+$/g, '');
          if (first.toLowerCase() === botName) {
            const remainder = words.slice(1).join(' ').trim();
            if (remainder) {
              // Check if user is banned before processing
              const mentionUserId = String(tags['user-id'] || tags['userId'] || '');
              if (mentionUserId && bannedUsersCache.has(String(mentionUserId))) {
                // Silently ignore banned users
                return;
              }
              // parse optional model flag
              const parsed = extractModelFlag(remainder);
              const prompt = (parsed.rest || '').trim();
              const modelOverride = parsed.model || null;
              if (prompt) {
                const userKey = String((tags && (tags['user-id'] || tags['userId'] || tags.username || tags['display-name'])) || username || 'anonymous');
                await handleLLMRequest({
                  channel,
                  userKey,
                  prompt,
                  modelOverride,
                  channelKey,
                  username,
                  tags,
                  time,
                  source: 'mention',
                });
              }
              return;
            }
          }
        }
      }
    } catch (e) {
      console.error('Bot mention detection error:', e);
    }

  // Helper command as required by pajlada Bot guidelines
  if (msg.startsWith(`!${process.env.TWITCH_USERNAME}`)) {
    queueSend(channel, `Hi I'm a lidl clank-slop bot by @RoboSheepz. Ping me at the beginning of your message to chat or ${prefix}help for more.`).catch(()=>{});
  }

  // Only treat messages that start with the configured prefix as commands
  if (!msg.startsWith(prefix)) return;

  console.log(`[${time}] Command received from ${username}: ${msg}`);

  // Normalize command and arguments (strip prefix)
  const withoutPrefix = msg.slice(prefix.length).trim();
  const parts = withoutPrefix.split(/\s+/);
  const command = parts[0].toLowerCase();

  const userId = String(tags['user-id'] || tags['userId'] || '');
  const isAdmin = adminsCache.has(userId);

  // Block banned users from all commands
  try {
    if (userId && bannedUsersCache.has(String(userId))) {
      queueSend(channel, `You are banned from using bot commands.`).catch(()=>{});
      return;
    }
  } catch (e) {
    console.error('Banned user check error:', e);
  }

  // Enforce per-user, per-command cooldown
  try {
    const nowMs = Date.now();
    const userKey = userId || String((tags && (tags.username || tags['display-name'])) || username || 'anonymous');
    const cooldownKey = `${userKey}:${command}`;
    const last = commandCooldowns.get(cooldownKey) || 0;
    if ((nowMs - last) < COMMAND_COOLDOWN_MS) {
      const wait = Math.ceil((COMMAND_COOLDOWN_MS - (nowMs - last)) / 1000);
      console.log(`[${time}] Cooldown: user ${userKey} attempted '${command}' — wait ${wait}s`);
      return;
    }
    // record this invocation
    commandCooldowns.set(cooldownKey, nowMs);
  } catch (e) {
    // if anything goes wrong, don't block command execution
    console.error('Cooldown check error:', e);
  }
  // Admin-only: ban a user from all commands
  // Usage: <prefix>ban <username|uid>
  if (command === 'ban') {
    if (!isAdmin) {
      queueSend(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const target = parts[1];
    if (!target) {
      queueSend(channel, `Usage: ${prefix}ban <username|uid>`).catch(()=>{});
      return;
    }
    const uid = await resolveToUid(target);
    if (!uid) {
      queueSend(channel, `Could not resolve '${target}' to a Twitch account`).catch(()=>{});
      return;
    }
    await banUser(uid);
    queueSend(channel, `User ${uid} has been banned from all bot commands.`).catch(()=>{});
    return;
  }

  // Admin-only: unban a user
  // Usage: <prefix>unban <username|uid>
  if (command === 'unban') {
    if (!isAdmin) {
      queueSend(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const target = parts[1];
    if (!target) {
      queueSend(channel, `Usage: ${prefix}unban <username|uid>`).catch(()=>{});
      return;
    }
    const uid = await resolveToUid(target);
    if (!uid) {
      queueSend(channel, `Could not resolve '${target}' to a Twitch account`).catch(()=>{});
      return;
    }
    await unbanUser(uid);
    queueSend(channel, `User ${uid} has been unbanned.`).catch(()=>{});
    return;
  }

  // Admin-only: make the bot say something
  // Usage: <prefix>say <message>
  if (command === 'say') {
    if (!isAdmin) {
      queueSend(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    let text = withoutPrefix.slice(command.length).trim();
    let targetChannel = channel;
    
    // Check for --channel flag
    const channelMatch = text.match(/^--channel\s+([^\s]+)\s+(.+)$/);
    if (channelMatch) {
      const specifiedChannel = channelMatch[1];
      text = channelMatch[2];
      // Normalize channel name (add # if not present)
      targetChannel = specifiedChannel.startsWith('#') ? specifiedChannel : `#${specifiedChannel}`;
    }
    
    if (!text) {
      queueSend(channel, `Usage: ${prefix}say [--channel <channel>] <message>`).catch(()=>{});
      return;
    }
    queueSend(targetChannel, text).catch(()=>{});
    return;
  }

  // Admin-only: set LLM system prompt
  if (command === 'setprompt') {
    if (!isAdmin) {
      queueSend(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const newPrompt = withoutPrefix.slice(command.length).trim();
    if (!newPrompt) {
      queueSend(channel, `Usage: ${prefix}setprompt <text>`).catch(()=>{});
      return;
    }
    try {
      await db.setLLMSystemPrompt(newPrompt);
      LLM_SYSTEM_PROMPT = newPrompt;
      queueSend(channel, `LLM prompt updated.`).catch(()=>{});
    } catch (e) {
      console.error('Failed to set LLM prompt:', e);
      queueSend(channel, `Failed to update prompt.`).catch(()=>{});
    }
    return;
  }

  // Admin-only: add character by PNG URL
  if (command === 'addchar') {
    if (!isAdmin) {
      queueSend(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const raw = withoutPrefix.slice(command.length).trim();
    const first = extractFirstTokenPreservingQuotes(raw);
    const url = first.token;
    if (!url) {
      queueSend(channel, `Usage: ${prefix}addchar <png-url>`).catch(()=>{});
      return;
    }
    try {
      const saved = await downloadPNG(url, path.join(__dirname, 'data', 'char'));
      const rel = path.relative(__dirname, saved).replace(/\\/g, '/');
      await db.setCharacterCardPath(rel);
      LLM_CHARACTER_CARD = rel;
      characterCardData = loadCharacterCard(LLM_CHARACTER_CARD);
      const label = (characterCardData && (characterCardData.name || characterCardData.character || 'Character')) || path.basename(saved);
      queueSend(channel, `Character set: ${label}`).catch(()=>{});
    } catch (e) {
      console.error('addchar error:', e);
      queueSend(channel, `Failed to add character: ${e && e.message ? e.message : 'error'}`).catch(()=>{});
    }
    return;
  }

  // Enforce per-channel admin requirement: if channel requires admin for all commands, block non-admins
  try {
    if (chanCfg && chanCfg.require_admin && !isAdmin) {
      console.log(`[${time}] Channel ${channelKey} requires admin for all commands; rejecting ${username} for '${command}'`);
      return;
    }
  } catch (e) {
    console.error('Channel auth enforcement error:', e);
  }

  // Helper: fetch user info from Helix by login or id. Returns parsed user obj or null.
  function fetchHelixUser({ login, id }) {
    return new Promise((resolve, reject) => {
      if (!helixClientId) return resolve(null);
      const token = String(process.env.TWITCH_OAUTH || '').replace(/^oauth:/i, '');
      const params = login ? `login=${encodeURIComponent(login)}` : `id=${encodeURIComponent(id)}`;
      const options = {
        hostname: 'api.twitch.tv',
        path: `/helix/users?${params}`,
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Client-Id': helixClientId
        }
      };
      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data || '{}');
            if (parsed && Array.isArray(parsed.data) && parsed.data.length) return resolve(parsed.data[0]);
            return resolve(null);
          } catch (e) { return resolve(null); }
        });
      });
      req.on('error', (err) => resolve(null));
      req.end();
    });
  }

  // Helper: call OpenRouter using the official SDK and stream results
  // callOpenRouter accepts either a prompt string or an array of messages [{role,content},...]
  // and an optional model override string as second argument
  async function callOpenRouter(input, modelOverride) {
    if (!OPENROUTER_API_KEY) return { error: { message: 'No OPENROUTER_API_KEY configured' } };
    let OpenRouter;
    try {
      OpenRouter = require('@openrouter/sdk').OpenRouter;
    } catch (e) {
      return { error: { message: 'Missing @openrouter/sdk. Install with: npm install @openrouter/sdk' } };
    }

    // Timeout wrapper - 30 seconds
    const timeoutPromise = new Promise((resolve) => {
      setTimeout(() => {
        resolve({ error: { message: 'LLM timed out.', timeout: true } });
      }, 30000);
    });

    const llmPromise = (async () => {
      try {
        const or = new OpenRouter({ apiKey: OPENROUTER_API_KEY });
        const messages = Array.isArray(input) ? input.map(m => ({ role: m.role, content: String(m.content) })) : [{ role: 'user', content: String(input) }];
        const stream = await or.chat.send({
          model: modelOverride || OPENROUTER_MODEL,
          messages,
          stream: true,
          streamOptions: { includeUsage: true }
        });

        let response = '';
        let usage = null;
        for await (const chunk of stream) {
          const content = chunk.choices && chunk.choices[0] && (chunk.choices[0].delta?.content || chunk.choices[0].message?.content || chunk.choices[0].text);
          if (content) response += content;
          if (chunk.usage) usage = chunk.usage;
        }

        return { text: String(response), usage };
      } catch (err) {
        // Build a structured error object with common fields
        try {
          const errObj = {
            message: err && (err.message || String(err)) || 'Unknown error',
            name: err && err.name || undefined,
            code: err && (err.code || err.status || err.statusCode) || undefined,
            status: err && (err.status || err.statusCode || (err.response && err.response.status)) || undefined,
          };
          // try to extract a small body/info if present
          try {
            const info = err && (err.response && (err.response.data || err.response.body) || err.body || err.raw);
            if (info) {
              const s = typeof info === 'string' ? info : JSON.stringify(info);
              errObj.info = s.length > 500 ? (s.slice(0, 500) + '...') : s;
            }
          } catch (e) { /* ignore */ }
          return { error: errObj };
        } catch (e2) {
          return { error: { message: String(err) } };
        }
      }
    })();

    // Race between LLM response and timeout
    return Promise.race([llmPromise, timeoutPromise]);
  }

  // Helper: format AI error object/string into a concise single-line message
  function formatAIError(err) {
    if (!err) return 'Unknown error';
    if (typeof err === 'string') return err;
    try {
      const parts = [];
      if (err.message) parts.push(err.message);
      if (err.name && err.name !== 'Error') parts.push(`(${err.name})`);
      if (err.code) parts.push(`[code:${err.code}]`);
      if (err.status) parts.push(`[status:${err.status}]`);
      if (err.info) parts.push(`info:${err.info.slice(0,200)}`);
      const out = parts.join(' ').trim();
      return out || JSON.stringify(err).slice(0,300);
    } catch (e) {
      return String(err);
    }
  }

  // Helper: collect system statistics (cpu %, memory usage, uptime, os info)
  async function getSystemStats() {
    function cpuTimes() {
      const cpus = os.cpus();
      let idle = 0, total = 0;
      for (const cpu of cpus) {
        for (const t in cpu.times) total += cpu.times[t];
        idle += cpu.times.idle;
      }
      return { idle, total };
    }

    const start = cpuTimes();
    // sample after short delay
    await new Promise(r => setTimeout(r, 120));
    const end = cpuTimes();
    const idleDelta = end.idle - start.idle;
    const totalDelta = end.total - start.total;
    const cpuPercent = totalDelta > 0 ? Math.max(0, Math.min(100, Math.round((1 - idleDelta / totalDelta) * 100))) : 0;

    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const memPercent = totalMem > 0 ? Math.round((usedMem / totalMem) * 100) : 0;

    const uptimeSec = os.uptime();
    const uptimeHours = Math.floor(uptimeSec / 3600);
    const uptimeMins = Math.floor((uptimeSec % 3600) / 60);
    const uptimeSecs = Math.floor(uptimeSec % 60);
    const uptimeStr = `${uptimeHours}h ${uptimeMins}m ${uptimeSecs}s`;

    const platform = os.platform();
    const release = os.release();

    return {
      cpuPercent,
      usedMem,
      totalMem,
      memPercent,
      uptimeStr,
      platform,
      release
    };
  }

  // Resolve an argument to a UID. Accepts a numeric uid or a username; returns uid or null.
  async function resolveToUid(arg) {
    if (!arg) return null;
    if (/^\d+$/.test(arg)) {
      // numeric - verify exists
      const u = await fetchHelixUser({ id: arg });
      return u ? String(u.id) : null;
    }
    // username
    const login = arg.replace(/^#/, '').toLowerCase();
    const u = await fetchHelixUser({ login });
    return u ? String(u.id) : null;
  }

  // Helper to send multi-part messages limited to 200 chars each
  function sendSplit(client, channel, lines) {
    const max = 152;
    const chunks = [];
    // build chunks first
    for (const line of lines) {
      if (line.length <= max) {
        // try to merge into last chunk if possible
        const last = chunks.length ? chunks[chunks.length - 1] : null;
        if (last && (last.length + 1 + line.length) <= max) {
          chunks[chunks.length - 1] = last + '\n' + line;
        } else {
          chunks.push(line);
        }
      } else {
        // split long line into max-sized pieces
        for (let i = 0; i < line.length; i += max) {
          chunks.push(line.slice(i, i + max));
        }
      }
    }

    // append '...' to non-final messages
    const sends = chunks.map((text, idx) => {
      const out = (idx < chunks.length - 1) ? (text + '...') : text;
      return queueSend(channel, out);
    });
    return Promise.all(sends);
  }

  // Helper to extract the first token from a string preserving quoted tokens
  function extractFirstTokenPreservingQuotes(s) {
    if (!s) return { token: null, rest: '' };
    let str = String(s).trim();
    if (!str) return { token: null, rest: '' };
    const firstChar = str[0];
    if (firstChar === '"' || firstChar === "'") {
      const quote = firstChar;
      let i = 1;
      let token = '';
      while (i < str.length) {
        const ch = str[i];
        if (ch === quote) { i++; break; }
        if (ch === '\\' && i + 1 < str.length) { token += str[i+1]; i += 2; continue; }
        token += ch; i++;
      }
      const rest = str.slice(i).trim();
      return { token, rest };
    }
    // unquoted - first whitespace-separated token
    const m = str.match(/^(\S+)(?:\s+([\s\S]*))?$/);
    if (!m) return { token: str, rest: '' };
    return { token: m[1], rest: (m[2] || '').trim() };
  }

  


    // Helper: extract a leading --model flag from a prompt string.
    // Returns { model: string|null, rest: string }
    function extractModelFlag(s) {
      if (!s) return { model: null, rest: '' };
      const str = String(s).trim();
      if (!str) return { model: null, rest: '' };
      // Patterns: --model=value, --model "value", --model 'value', --model value
      // Also support short form: -m=value or -m "value" or -m value
      let m = str.match(/^(?:--model|-m)=(?:"([^"]+)"|'([^']+)'|([^\s]+))(?:\s+([\s\S]*))?$/);
      if (m) return { model: m[1] || m[2] || m[3] || null, rest: (m[4] || '').trim() };
      m = str.match(/^(?:--model|-m)\s+(?:"([^"]+)"|'([^']+)'|([^\s]+))(?:\s+([\s\S]*))?$/);
      if (m) return { model: m[1] || m[2] || m[3] || null, rest: (m[4] || '').trim() };
      return { model: null, rest: str };
    }
  // sendAndRecord is defined at module top-level to be available to the send queue

  if (command === 'ping') {
    // Compute response time using tmi timestamp if available
    const nowMs = Date.now();
    let latency = 'unknown';
    try {
      const sentTs = Number(tags && (tags['tmi-sent-ts'] || tags['tmi-sent-ts']));
      if (Number.isFinite(sentTs)) latency = String(nowMs - sentTs);
      else latency = String(nowMs - Date.now());
    } catch (e) {
      latency = 'unknown';
    }

    try {
      const stats = await getSystemStats();
      const usedMB = Math.round(stats.usedMem / 1024 / 1024);
      const totalMB = Math.round(stats.totalMem / 1024 / 1024);
      const reply = `Pong! MrDestructoid ${latency}ms | CPU: ${stats.cpuPercent}% | Mem: ${usedMB}MB/${totalMB}MB (${stats.memPercent}%) | Uptime: ${stats.uptimeStr} | OS: ${stats.platform} ${stats.release}`;
      sendAndRecord(channel, reply).catch(err => console.error(`[${time}] Error sending ping reply:`, err));
    } catch (e) {
      const reply = `Pong! MrDestructoid ${latency}ms`;
      sendAndRecord(channel, reply).catch(err => console.error(`[${time}] Error sending ping reply:`, err));
    }
  }
  
  // Admin-only: join a new channel and optionally set its prefix
  // Usage: <prefix>join <channelName> [prefix]
  if (command === 'join') {
    if (!isAdmin) {
      queueSend(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    // parse target and optional prefix (prefix may be quoted to include spaces)
    const remainderAfterCommand = withoutPrefix.slice(command.length).trim();
    const first = extractFirstTokenPreservingQuotes(remainderAfterCommand);
    const target = first.token;
    if (!target) {
      queueSend(channel, `Usage: ${prefix}join <channelName> [prefix]`);
      return;
    }
    const afterTarget = first.rest || '';
    const second = extractFirstTokenPreservingQuotes(afterTarget);
    let requestedPrefix = '!';
    let requestedRequireAdmin = false;
    if (second.token) {
      // if the provided token is exactly 'admin' and there is no further text, treat it as flag
      if (String(second.token).toLowerCase() === 'admin' && (!second.rest || !second.rest.trim())) {
        requestedPrefix = '!';
        requestedRequireAdmin = true;
      } else {
        requestedPrefix = second.token;
        const remainingFlags = (second.rest || '').split(/\s+/).map(p => String(p || '').toLowerCase()).filter(Boolean);
        if (remainingFlags.includes('admin')) requestedRequireAdmin = true;
      }
    } else {
      // no second token; check if afterTarget contains 'admin' as bare word
      const maybeFlags = (afterTarget || '').split(/\s+/).map(p => String(p || '').toLowerCase()).filter(Boolean);
      if (maybeFlags.includes('admin')) requestedRequireAdmin = true;
    }
    // normalize channel name
    const normalized = target.startsWith('#') ? target.slice(1) : target;
    const joinChannel = `#${normalized}`;
    client.join(joinChannel)
      .then(async () => {
        try {
          await db.addChannel(normalized, requestedPrefix, requestedRequireAdmin);
          channelsCache.set(normalized, { prefix: requestedPrefix, require_admin: requestedRequireAdmin });
        } catch (e) {
          console.error('DB addChannel error:', e);
        }
        queueSend(channel, `Joined ${joinChannel} with prefix '${requestedPrefix}'${requestedRequireAdmin ? ' (admin-only)' : ''}`)
          .catch(()=>{});
      })
      .catch(err => {
        console.error('Error joining channel:', err);
        queueSend(channel, `Failed to join ${joinChannel}: ${err && err.message ? err.message : err}`)
          .catch(()=>{});
      });
  }

  if (command === 'addadmin') {
    if (!isAdmin) {
      queueSend(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const target = parts[1];
    if (!target) {
      queueSend(channel, `Usage: ${prefix}addadmin <username|uid>`).catch(()=>{});
      return;
    }
    const uid = await resolveToUid(target);
    if (!uid) {
      queueSend(channel, `Could not resolve '${target}' to a Twitch account`).catch(()=>{});
      return;
    }
    db.addAdmin(uid).then(() => {
      adminsCache.add(String(uid));
      queueSend(channel, `Added admin uid ${uid}`).catch(()=>{});
    }).catch(err => {
      console.error('Error adding admin:', err);
      queueSend(channel, `Failed to add admin: ${err && err.message ? err.message : err}`).catch(()=>{});
    });
  }

  if (command === 'rmadmin') {
    if (!isAdmin) {
      queueSend(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const target = parts[1];
    if (!target) {
      queueSend(channel, `Usage: ${prefix}rmadmin <username|uid>`).catch(()=>{});
      return;
    }
    const uid = await resolveToUid(target);
    if (!uid) {
      queueSend(channel, `Could not resolve '${target}' to a Twitch account`).catch(()=>{});
      return;
    }
    db.removeAdmin(uid).then(() => {
      adminsCache.delete(String(uid));
      queueSend(channel, `Removed admin uid ${uid}`).catch(()=>{});
    }).catch(err => {
      console.error('Error removing admin:', err);
      queueSend(channel, `Failed to remove admin: ${err && err.message ? err.message : err}`).catch(()=>{});
    });
  }

  if (command === 'help') {
    // Build help lines with prefix and auth level
    const cmdLines = [];
    const pfx = prefix;
    // default auth per-command
    const defaultAuth = {
      ping: 'user',
      uid: 'user',
      join: 'admin',
      setprefix: 'admin',
      leave: 'admin',
      addadmin: 'admin',
      rmadmin: 'admin',
      massping: 'admin',
      ask: 'user',
      askchat: 'user',
      askclear: 'user',
      lockdown: 'admin',
      setprompt: 'admin',      // NEW
      addchar: 'admin'         // NEW
    };

    // if channel enforces admin for all commands, override default
    const effectiveAuth = (cmd) => (chanCfg && chanCfg.require_admin) ? 'admin' : (defaultAuth[cmd] || 'user');

    cmdLines.push(`${pfx}ping - ping the bot (${effectiveAuth('ping')})`);
    cmdLines.push(`${pfx}uid <uid/user> - return Twitch user or UID (${effectiveAuth('uid')})`);
    cmdLines.push(`${pfx}join <channel> [prefix] [admin] - Join channel and set prefix (${effectiveAuth('join')})`);
    cmdLines.push(`${pfx}setprefix <prefix> - Set this channel's prefix (${effectiveAuth('setprefix')})`);
    cmdLines.push(`${pfx}leave <channel> - Leave channel (${effectiveAuth('leave')})`);
    cmdLines.push(`${pfx}addadmin <uid/user> - Add a user as admin (${effectiveAuth('addadmin')})`);
    cmdLines.push(`${pfx}rmadmin <uid/user> - Remove a user from admins (${effectiveAuth('rmadmin')})`);
    cmdLines.push(`${pfx}massping - send single message of recent users (${effectiveAuth('massping')})`);
    cmdLines.push(`${pfx}ask [--model MODEL] <question> - ask with recent channel chat as context (${effectiveAuth('ask')})`);
    cmdLines.push(`${pfx}askclear [username|uid] - clear your (or admin: another user's) AI conversation memory (${effectiveAuth('askclear')})`);
    cmdLines.push(`${pfx}lockdown [on|off|toggle] - restrict all bot commands to admins in this channel (${effectiveAuth('lockdown')})`);
    cmdLines.push(`${pfx}ban <username|uid> - Ban user from all bot commands (admin)`);
    cmdLines.push(`${pfx}unban <username|uid> - Unban user (admin)`);
    cmdLines.push(`${pfx}say [--channel <channel>] <message> - Make the bot say something (admin)`);
    cmdLines.push(`${pfx}setprompt <text> - Update the system prompt used for AI (admin)`); // NEW
    cmdLines.push(`${pfx}addchar <png-url> - Download a PNG character card and set active (admin)`); // NEW
    sendSplit(client, channel, cmdLines).catch(err => console.error('Help send error:', err));
  }

  if (command === 'uid') {
    const arg = parts[1];
    if (!arg) {
      queueSend(channel, `Usage: ${prefix}uid <username|uid>`).catch(()=>{});
      return;
    }
    // determine if numeric
    let info = null;
    if (/^\d+$/.test(arg)) {
      info = await fetchHelixUser({ id: arg });
    } else {
      info = await fetchHelixUser({ login: arg.replace(/^#/, '').toLowerCase() });
    }
    if (!info) {
      queueSend(channel, `No Twitch account found for '${arg}'`).catch(()=>{});
      return;
    }
    // Attempt to detect ban status: Helix doesn't expose global ban easily; if user exists, report active
    const status = 'active';
    sendSplit(client, channel, [`Username: ${info.login}`, `Display: ${info.display_name}`, `UID: ${info.id}`, `Created: ${info.created_at}`, `Status: ${status}`]).catch(()=>{});
  }

  

  // Ask LLM including recent channel chat history as context: <prefix>ask <prompt>
  if (command === 'ask' || command === 'ai') {
    const raw = withoutPrefix.slice(command.length).trim();
    const parsed = extractModelFlag(raw);
    const prompt = (parsed.rest || '').trim();
    const modelOverride = parsed.model || null;
    if (!prompt) {
      queueSend(channel, `Usage: ${prefix}ask [--model MODEL] <your question>`).catch(()=>{});
      return;
    }
    const userKey = userId || String((tags && (tags.username || tags['display-name'])) || username || 'anonymous');
    await handleLLMRequest({
      channel,
      userKey,
      prompt,
      modelOverride,
      channelKey,
      username,
      tags,
      time,
      source: 'ask',
    });
    return;
  }

  // Clear conversation memory: askclear [username|uid]
  if (command === 'askclear') {
    const raw = withoutPrefix.slice(command.length).trim();
    const first = extractFirstTokenPreservingQuotes(raw || '');
    const target = first.token || null;
    // If no target provided, allow user to clear their own memory
    const callerKey = userId || String((tags && (tags.username || tags['display-name'])) || username || 'anonymous');
    if (!target) {
      userConversations.delete(callerKey);
      queueSend(channel, `Cleared your conversation memory.`).catch(()=>{});
      return;
    }
    // target provided -> must be admin to clear others
    if (!isAdmin) {
      queueSend(channel, `You are not authorized to clear another user's memory.`).catch(()=>{});
      return;
    }
    // (No LLM call here, just admin logic)
  }
  // Helper to handle LLM requests for ask, mention, etc. (per-channel context only)
  async function handleLLMRequest({ channel, userKey, prompt, modelOverride, channelKey, username, tags, time, source }) {
    try {
      if (!prompt) return;
      const msgs = [];
      if (LLM_SYSTEM_PROMPT) msgs.push({ role: 'system', content: LLM_SYSTEM_PROMPT });
      
      // Add character card data if available
      if (characterCardData) {
        let cardContent = '';
        if (characterCardData.name) cardContent += `Character: ${characterCardData.name}\n`;
        if (characterCardData.description) cardContent += `Description: ${characterCardData.description}\n`;
        if (characterCardData.personality) cardContent += `Personality: ${characterCardData.personality}\n`;
        if (characterCardData.scenario) cardContent += `Scenario: ${characterCardData.scenario}\n`;
        if (characterCardData.first_mes) cardContent += `First Message: ${characterCardData.first_mes}\n`;
        if (characterCardData.mes_example) cardContent += `Example Messages: ${characterCardData.mes_example}\n`;
        if (cardContent) {
          msgs.push({ role: 'system', content: cardContent.trim() });
        }
      }

      // Only include per-channel context (no per-user conversation)
      // Budget history by model token window
      let baseUserMsg = { role: 'user', content: prompt };
      // Estimate tokens for fixed parts (system + card + user prompt)
      const baseTokens = estimateMessagesTokens([...msgs, baseUserMsg]);
      const maxContext = Math.max(LLM_CONTEXT_TOKENS, 1024);
      const availableForHistory = Math.max(0, maxContext - LLM_RESPONSE_TOKEN_BUFFER - baseTokens);

      // Retrieve recent chat history from DB (persistent) without char trimming
      let histRows = [];
      try {
        histRows = await db.getRecentChatMessages(channelKey, CHAT_HISTORY_LIMIT, 0);
      } catch (e) {
        console.error('Failed to fetch persistent chat history:', e);
      }

      if (histRows && histRows.length && availableForHistory > 0) {
        // Build from oldest to newest until token budget is exhausted
        let histText = '';
        let histTokens = 0;
        for (let i = histRows.length - 1; i >= 0; i--) {
          const entry = histRows[i];
          const line = `${entry.user}: ${entry.text}\n`;
          const lineTokens = estimateTokensForText(line);
          if ((histTokens + lineTokens) > availableForHistory) break;
          histTokens += lineTokens;
          histText += line;
        }
        if (histText) msgs.push({ role: 'system', content: `Recent channel messages:\n${histText}` });
      }

      msgs.push(baseUserMsg);

      // Log the entire messages array sent to LLM
      console.log(`LLM REQUEST (${source || 'unknown'}, all prompt/context):`, JSON.stringify(msgs, null, 2));

      const resp = await callOpenRouter(msgs, modelOverride);
      if (resp.error) {
        console.error('OpenRouter error:', resp.error);
        const msg = formatAIError(resp.error);
        queueSend(channel, `AI error: ${msg}`).catch(()=>{});
        return;
      }
      const out = (resp.text || '').trim();
      if (!out) {
        queueSend(channel, `AI returned no text`).catch(()=>{});
        return;
      }

      // Check if response is too long
      if (out.length > 2000) {
        queueSend(channel, `LLM sent a long response.`).catch(()=>{});
        return;
      }

      await sendSplit(client, channel, [out]);
    } catch (e) {
      console.error('LLM request handler error:', e);
      queueSend(channel, `AI request failed`).catch(()=>{});
    }
  }
  // Admin-only: set prefix for current channel
  // Usage: <prefix>setprefix <newPrefix>
  if (command === 'setprefix') {
    if (!isAdmin) {
      queueSend(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const newPrefix = parts[1];
    if (!newPrefix) {
      sendAndRecord(channel, `Usage: ${prefix}setprefix <newPrefix>`).catch(()=>{});
      return;
    }
    // update DB and cache for this channel
    const normalized = channelKey;
    const existing = channelsCache.get(normalized) || { prefix: newPrefix, require_admin: false };
    db.addChannel(normalized, newPrefix, existing.require_admin)
      .then(() => {
        // preserve existing require_admin setting when only updating prefix
        channelsCache.set(normalized, { prefix: newPrefix, require_admin: existing.require_admin });
        sendAndRecord(channel, `Prefix for ${normalized} set to '${newPrefix}'`).catch(()=>{});
      })
      .catch(err => {
        console.error('Error setting prefix:', err);
        sendAndRecord(channel, `Failed to set prefix: ${err && err.message ? err.message : err}`).catch(()=>{});
      });
  }

  // Admin-only: lockdown - restrict all bot commands to admins in this channel
  // Usage: <prefix>lockdown [on|off|toggle]
  if (command === 'lockdown') {
    if (!isAdmin) {
      queueSend(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const arg = (parts[1] || 'toggle').toLowerCase();
    const normalized = channelKey;
    const existing = channelsCache.get(normalized) || { prefix: prefix, require_admin: false };
    let newRequire;
    if (['on', 'enable', 'true', '1'].includes(arg)) newRequire = true;
    else if (['off', 'disable', 'false', '0'].includes(arg)) newRequire = false;
    else if (arg === 'toggle') newRequire = !existing.require_admin;
    else {
      queueSend(channel, `Usage: ${prefix}lockdown [on|off|toggle]`).catch(()=>{});
      return;
    }

    db.addChannel(normalized, existing.prefix || prefix, newRequire)
      .then(() => {
        channelsCache.set(normalized, { prefix: existing.prefix || prefix, require_admin: newRequire });
        queueSend(channel, `Lockdown ${newRequire ? 'enabled' : 'disabled'} for #${normalized}`).catch(()=>{});
      })
      .catch(err => {
        console.error('Error setting lockdown:', err);
        queueSend(channel, `Failed to set lockdown: ${err && err.message ? err.message : err}`).catch(()=>{});
      });
    return;
  }

  // Admin-only: leave a channel
  // Usage: <prefix>leave <channelName>
  if (command === 'leave') {
    if (!isAdmin) {
      sendAndRecord(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const target = parts[1];
    if (!target) {
      sendAndRecord(channel, `Usage: ${prefix}leave <channelName>`).catch(()=>{});
      return;
    }
    const normalized = target.startsWith('#') ? target.slice(1) : target;
    const leaveChannel = `#${normalized}`;
    client.part(leaveChannel)
      .then(async () => {
        try {
          await db.removeChannel(normalized);
          channelsCache.delete(normalized);
        } catch (e) {
          console.error('DB removeChannel error:', e);
        }
        sendAndRecord(channel, `Left ${leaveChannel}`)
          .catch(()=>{});
      })
      .catch(err => {
        console.error('Error leaving channel:', err);
        sendAndRecord(channel, `Failed to leave ${leaveChannel}: ${err && err.message ? err.message : err}`)
          .catch(()=>{});
      });
  }
});

// Attach debug handlers moved to troubleshoot.js
attachDebug(client, opts);
// Validate token, init DB, load caches, then connect
// Add DB helpers for banned users if not present
// db.addBannedUser(uid), db.removeBannedUser(uid), db.loadBannedUsers()

(async () => {
  // CHANGED: load from DB after init
  try {
    const info = await validateToken(process.env.TWITCH_OAUTH);
    console.log(`Token belongs to login: ${info.login || 'unknown'}`);
    console.log(`Token scopes: ${Array.isArray(info.scopes) ? info.scopes.join(', ') : info.scopes || 'none'}`);
    helixClientId = info.client_id || null;
  } catch (err) {
    console.warn('Token validation failed:', err && err.body ? JSON.stringify(err.body) : err.message || err);
  }

  try {
    await db.init();
    await db.ensureLLMDefaultsFromEnv(); // NEW
    adminsCache = await db.loadAdmins();
    channelsCache = await db.loadChannels();
    if (db.loadBannedUsers) {
      bannedUsersCache = new Set(await db.loadBannedUsers());
    } else {
      bannedUsersCache = new Set();
    }
    // Load persisted LLM settings
    try {
      const dbPrompt = await db.getLLMSystemPrompt();
      if (dbPrompt) LLM_SYSTEM_PROMPT = dbPrompt;
      const dbCardPath = await db.getCharacterCardPath();
      if (dbCardPath) LLM_CHARACTER_CARD = dbCardPath;
    } catch (e) {
      console.error('Failed to load LLM settings from DB:', e);
    }

    // Load character card if specified (from DB or .env)
    if (LLM_CHARACTER_CARD) {
      characterCardData = loadCharacterCard(LLM_CHARACTER_CARD);
      if (characterCardData) {
        console.log(`Loaded character card: ${characterCardData.name || 'Unknown'}`);
      }
    }

    console.log(`Loaded admins: ${Array.from(adminsCache).join(', ')}`);
    console.log(`Loaded channels: ${Array.from(channelsCache.keys()).join(', ')}`);
    console.log(`Loaded banned users: ${Array.from(bannedUsersCache).join(', ')}`);
  } catch (err) {
    console.error('DB init/load error:', err);
  }

  try {
    await client.connect();
    // join channels from DB cache
    for (const ch of channelsCache.keys()) {
      const joinChannel = `#${ch}`;
      client.join(joinChannel).then(() => {
        console.log(`Joined configured channel ${joinChannel}`);
      }).catch(err => {
        console.error(`Failed to join configured channel ${joinChannel}:`, err);
      });
    }
  } catch (err) {
    console.error('Connection error:', err);
  }
})();
