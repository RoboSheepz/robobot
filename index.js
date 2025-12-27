require('dotenv').config();
const tmi = require('tmi.js');
const { validateToken, attachDebug, sendAndLog } = require('./troubleshoot');
const db = require('./db');

const opts = {
  options: { debug: true },
  identity: {
    username: process.env.TWITCH_USERNAME,
    password: process.env.TWITCH_OAUTH
  },
  channels: [ process.env.TWITCH_CHANNEL ]
};

const client = new tmi.Client(opts);

// Log configured identity and channel for debugging
console.log(`Configured identity: ${opts.identity.username}`);
console.log(`Configured channels: ${opts.channels.join(', ')}`);

// Track last outgoing message to avoid replying to our own echoed messages
let lastOutgoing = null;
let lastOutgoingTs = 0;

// In-memory caches loaded from DB at startup
let adminsCache = new Set();
let channelsCache = new Map();

// token validation moved to `troubleshoot.js` (imported above)

client.on('message', (channel, tags, message, self) => {
  // Always log inbound messages for debugging
  const time = new Date().toISOString();
  const username = tags['display-name'] || tags.username;
  console.log(`[${time}] ${channel} <${username}>: ${message} (self=${self})`);
  console.log(`[${time}] tags: ${JSON.stringify(tags)} | message-type=${tags['message-type']}`);

  // If this message is an echo of our own outgoing message, ignore it to avoid loops.
  const msg = String(message || '').trim();
  if (self && tags && String(tags.username).toLowerCase() === String(opts.identity.username).toLowerCase()) {
    const now = Date.now();
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

  if (command === 'hello') {
    const reply = `Hello, ${username}!`;
    sendAndLog(client, channel, reply)
      .then(() => {
        console.log(`[${time}] Replied to ${username} for ${command}`);
        lastOutgoing = reply;
        lastOutgoingTs = Date.now();
      })
      .catch(err => console.error(`[${time}] Error sending message:`, err));
  }

  if (command === 'sendtest') {
    const reply = `Test message ${Date.now()} from ${opts.identity.username}`;
    console.log(`[${time}] Sending test message: ${reply}`);
    sendAndLog(client, channel, reply)
      .then(() => {
        console.log(`[${time}] Sent test message`);
        lastOutgoing = reply;
        lastOutgoingTs = Date.now();
      })
      .catch(err => console.error(`[${time}] Error sending test message:`, err));
  }
  
  // Admin-only: join a new channel and optionally set its prefix
  // Usage: <prefix>join <channelName> [prefix]
  if (command === 'join') {
    if (!isAdmin) {
      sendAndLog(client, channel, `You are not authorized to run this command.`).catch(()=>{});
      return;
    }
    const target = parts[1];
    if (!target) {
      sendAndLog(client, channel, `Usage: ${prefix}join <channelName> [prefix]`);
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
        sendAndLog(client, channel, `Joined ${joinChannel} with prefix '${requestedPrefix}'`)
          .catch(()=>{});
      })
      .catch(err => {
        console.error('Error joining channel:', err);
        sendAndLog(client, channel, `Failed to join ${joinChannel}: ${err && err.message ? err.message : err}`)
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

  client.connect().catch(err => {
    console.error('Connection error:', err);
  });
})();
