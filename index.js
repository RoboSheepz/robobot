require('dotenv').config();
const tmi = require('tmi.js');
const { validateToken, attachDebug, sendAndLog } = require('./troubleshoot');
const db = require('./db');
const https = require('https');
const os = require('os');
// Global message queue settings
const MESSAGE_INTERVAL_MS = Number(process.env.MESSAGE_INTERVAL_MS || 1100);

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
      // record outgoing message immediately so echoes can be detected
      const now = Date.now();
      lastOutgoing = String(item.text);
      lastOutgoingTs = now;
      recentOutgoing.set(String(item.text), now);
      for (const [k, ts] of recentOutgoing) {
        if ((now - ts) > 60000) recentOutgoing.delete(k);
      }
      await sendAndLog(client, item.channel, item.text);
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

// token validation moved to `troubleshoot.js` (imported above)

client.on('message', async (channel, tags, message, self) => {
  // Always log inbound messages for debugging
  const time = new Date().toISOString();
  const username = tags['display-name'] || tags.username;
  console.log(`[${time}] ${channel} <${username}>: ${message} (self=${self})`);
  

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

  // Update recent users LRU (unique) for this channel
  try {
    const loginRaw = (tags && (tags.username || '')) || String(username || '');
    const login = String(loginRaw).toLowerCase().trim();
    // Exclude bot accounts (any username containing 'bot')
    if (login && !login.includes('bot')) {
      const arr = recentUsers.get(channelKey) || [];
      const idx = arr.indexOf(login);
      if (idx !== -1) arr.splice(idx, 1);
      arr.unshift(login);
      if (arr.length > 100) arr.length = 100;
      recentUsers.set(channelKey, arr);
    }
  } catch (e) {
    console.error('Failed updating recentUsers:', e);
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
    const max = 200;
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
      massping: 'admin'
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

  // Admin-only: massping - send a single (<=500 char) message listing most recent usernames for this channel
  if (command === 'massping') {
    if (!isAdmin) {
      queueSend(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    try {
      const arr = recentUsers.get(channelKey) || [];
      if (!arr.length) {
        queueSend(channel, `No recent users to massping.`).catch(()=>{});
        return;
      }
      // Build a single message up to 500 characters containing @user mentions (most recent first)
      const maxLen = 500;
      let msgParts = [];
      let curLen = 0;
      for (const u of arr) {
        const mention = `@${u}`;
        const addition = (msgParts.length ? ' ' : '') + mention;
        if ((curLen + addition.length) > maxLen) break;
        msgParts.push(mention);
        curLen += addition.length;
      }
      const out = msgParts.join(' ');
      if (!out) {
        queueSend(channel, `No recent users fit into a ${maxLen} char message.`).catch(()=>{});
        return;
      }
      // Send as a single message (not split)
      queueSend(channel, out).catch(err => console.error(`[${time}] Error sending massping:`, err));
    } catch (e) {
      console.error('massping error:', e);
      queueSend(channel, `Failed to build massping message.`).catch(()=>{});
    }
    return;
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
(async () => {
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
    adminsCache = await db.loadAdmins();
    channelsCache = await db.loadChannels();
    console.log(`Loaded admins: ${Array.from(adminsCache).join(', ')}`);
    console.log(`Loaded channels: ${Array.from(channelsCache.keys()).join(', ')}`);
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
