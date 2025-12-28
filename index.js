require('dotenv').config();
const tmi = require('tmi.js');
const { validateToken, attachDebug, sendAndLog } = require('./troubleshoot');
const db = require('./db');
const https = require('https');
const os = require('os');

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

  // Determine channel key (without leading '#') and prefix for this channel
  const channelKey = channel && channel.startsWith('#') ? channel.slice(1) : (channel || '');
  const prefix = channelsCache.has(channelKey) ? channelsCache.get(channelKey) : '!';

  // Only treat messages that start with the configured prefix as commands
  if (!msg.startsWith(prefix)) return;

  console.log(`[${time}] Command received from ${username}: ${msg}`);

  // Normalize command and arguments (strip prefix)
  const withoutPrefix = msg.slice(prefix.length).trim();
  const parts = withoutPrefix.split(/\s+/);
  const command = parts[0].toLowerCase();

  const userId = String(tags['user-id'] || tags['userId'] || '');
  const isAdmin = adminsCache.has(userId);

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
      return sendAndRecord(channel, out);
    });
    return Promise.all(sends);
  }

  // Wrapper that records outgoing messages so echoed messages can be detected
  function sendAndRecord(channel, text) {
    // record immediately so we can detect echoes reliably
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
      sendAndRecord(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const target = parts[1];
    if (!target) {
      sendAndRecord(channel, `Usage: ${prefix}join <channelName> [prefix]`);
      return;
    }
    const requestedPrefix = parts[2] || '!';
    // normalize channel name
    const normalized = target.startsWith('#') ? target.slice(1) : target;
    const joinChannel = `#${normalized}`;
    client.join(joinChannel)
      .then(async () => {
        try {
          await db.addChannel(normalized, requestedPrefix);
          channelsCache.set(normalized, requestedPrefix);
        } catch (e) {
          console.error('DB addChannel error:', e);
        }
        sendAndRecord(channel, `Joined ${joinChannel} with prefix '${requestedPrefix}'`)
          .catch(()=>{});
      })
      .catch(err => {
        console.error('Error joining channel:', err);
        sendAndRecord(channel, `Failed to join ${joinChannel}: ${err && err.message ? err.message : err}`)
          .catch(()=>{});
      });
  }

  if (command === 'addadmin') {
    if (!isAdmin) {
      sendAndRecord(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const target = parts[1];
    if (!target) {
      sendAndRecord(channel, `Usage: ${prefix}addadmin <username|uid>`).catch(()=>{});
      return;
    }
    const uid = await resolveToUid(target);
    if (!uid) {
      sendAndRecord(channel, `Could not resolve '${target}' to a Twitch account`).catch(()=>{});
      return;
    }
    db.addAdmin(uid).then(() => {
      adminsCache.add(String(uid));
      sendAndRecord(channel, `Added admin uid ${uid}`).catch(()=>{});
    }).catch(err => {
      console.error('Error adding admin:', err);
      sendAndRecord(channel, `Failed to add admin: ${err && err.message ? err.message : err}`).catch(()=>{});
    });
  }

  if (command === 'rmadmin') {
    if (!isAdmin) {
      sendAndRecord(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const target = parts[1];
    if (!target) {
      sendAndRecord(channel, `Usage: ${prefix}rmadmin <username|uid>`).catch(()=>{});
      return;
    }
    const uid = await resolveToUid(target);
    if (!uid) {
      sendAndRecord(channel, `Could not resolve '${target}' to a Twitch account`).catch(()=>{});
      return;
    }
    db.removeAdmin(uid).then(() => {
      adminsCache.delete(String(uid));
      sendAndRecord(channel, `Removed admin uid ${uid}`).catch(()=>{});
    }).catch(err => {
      console.error('Error removing admin:', err);
      sendAndRecord(channel, `Failed to remove admin: ${err && err.message ? err.message : err}`).catch(()=>{});
    });
  }

  if (command === 'help') {
    // Build help lines with prefix and auth level
    const cmdLines = [];
    const pfx = prefix;
    cmdLines.push(`${pfx}ping - Pong! MrDestructoid <response time>ms (user)`);
    cmdLines.push(`${pfx}join <channel> [prefix] - Join channel and set prefix (admin)`);
    cmdLines.push(`${pfx}setprefix <prefix> - Set this channel's prefix (admin)`);
    cmdLines.push(`${pfx}leavechannel <channel> - Leave channel and remove from DB (admin)`);
    cmdLines.push(`${pfx}addadmin <uid> - Add a Twitch UID as admin (admin)`);
    cmdLines.push(`${pfx}rmadmin <uid> - Remove a Twitch UID from admins (admin)`);
    sendSplit(client, channel, cmdLines).catch(err => console.error('Help send error:', err));
  }

  if (command === 'uid') {
    const arg = parts[1];
    if (!arg) {
      sendAndRecord(channel, `Usage: ${prefix}uid <username|uid>`).catch(()=>{});
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
      sendAndRecord(channel, `No Twitch account found for '${arg}'`).catch(()=>{});
      return;
    }
    // Attempt to detect ban status: Helix doesn't expose global ban easily; if user exists, report active
    const status = 'active';
    sendSplit(client, channel, [`Username: ${info.login}`, `Display: ${info.display_name}`, `UID: ${info.id}`, `Created: ${info.created_at}`, `Status: ${status}`]).catch(()=>{});
  }
  
  // Admin-only: set prefix for current channel
  // Usage: <prefix>setprefix <newPrefix>
  if (command === 'setprefix') {
    if (!isAdmin) {
      sendAndRecord(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const newPrefix = parts[1];
    if (!newPrefix) {
      sendAndRecord(channel, `Usage: ${prefix}setprefix <newPrefix>`).catch(()=>{});
      return;
    }
    // update DB and cache for this channel
    const normalized = channelKey;
    db.addChannel(normalized, newPrefix)
      .then(() => {
        channelsCache.set(normalized, newPrefix);
        sendAndRecord(channel, `Prefix for ${normalized} set to '${newPrefix}'`).catch(()=>{});
      })
      .catch(err => {
        console.error('Error setting prefix:', err);
        sendAndRecord(channel, `Failed to set prefix: ${err && err.message ? err.message : err}`).catch(()=>{});
      });
  }

  // Admin-only: leave a channel
  // Usage: <prefix>leavechannel <channelName>
  if (command === 'leavechannel') {
    if (!isAdmin) {
      sendAndRecord(channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const target = parts[1];
    if (!target) {
      sendAndRecord(channel, `Usage: ${prefix}leavechannel <channelName>`).catch(()=>{});
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
