require('dotenv').config();
const tmi = require('tmi.js');
const https = require('https');

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

// Validate token with Twitch so we can confirm which login the OAuth token belongs to
function validateToken(token) {
  return new Promise((resolve, reject) => {
    if (!token) return reject(new Error('No token provided'));
    const trimmed = String(token).replace(/^oauth:/i, '');
    const options = {
      method: 'GET',
      headers: {
        Authorization: `OAuth ${trimmed}`
      }
    };
    const req = https.request('https://id.twitch.tv/oauth2/validate', options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data || '{}');
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed);
          } else {
            const err = new Error(`Validate failed ${res.statusCode}`);
            err.body = parsed;
            reject(err);
          }
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on('error', (err) => reject(err));
    req.end();
  });
}

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
    // This handles cases where the account is the broadcaster and messages may appear with self=true.
  }

  if (!msg) return;
  if (!msg) return;

  // Log commands (messages that start with '!')
  if (msg.startsWith('!')) {
    console.log(`[${time}] Command received from ${username}: ${msg}`);
  }

  // Normalize command and arguments
  const parts = msg.split(/\s+/);
  const command = parts[0].toLowerCase();

  if (command === '!hello') {
    const reply = `Hello, ${username}!`;
    sendAndLog(channel, reply)
      .then(() => {
        console.log(`[${time}] Replied to ${username} for ${command}`);
        lastOutgoing = reply;
        lastOutgoingTs = Date.now();
      })
      .catch(err => console.error(`[${time}] Error sending message:`, err));
  }
  
  if (command === '!sendtest') {
    const reply = `Test message ${Date.now()} from ${opts.identity.username}`;
    console.log(`[${time}] Sending test message: ${reply}`);
    sendAndLog(channel, reply)
      .then(() => {
        console.log(`[${time}] Sent test message`);
        lastOutgoing = reply;
        lastOutgoingTs = Date.now();
      })
      .catch(err => console.error(`[${time}] Error sending test message:`, err));
  }
});

// Helper to log the raw PRIVMSG line we intend to send, then send via tmi
function sendAndLog(channel, text) {
  try {
    const rawLine = `PRIVMSG ${channel} :${text}`;
    const time = new Date().toISOString();
    console.log(`[${time}] OUTGOING: ${rawLine}`);
  } catch (e) {
    console.log('Failed to stringify outgoing message');
  }
  return client.say(channel, text);
}

client.on('connected', (addr, port) => {
  console.log(`Connected to ${addr}:${port}`);
});

// Log raw IRC messages from the server for low-level debugging
client.on('raw', (message) => {
  try {
    const time = new Date().toISOString();
    console.log(`[${time}] RAW:`, message);
  } catch (e) {
    console.log('RAW (unserializable)');
  }
});

// Listen for NOTICE messages from Twitch which often indicate why a message was rejected
client.on('notice', (channel, msgid, message) => {
  const time = new Date().toISOString();
  console.warn(`[${time}] NOTICE ${msgid} on ${channel}: ${message}`);
});

client.on('disconnected', (reason) => {
  console.warn('Disconnected:', reason);
});

client.on('reconnect', () => {
  console.log('Reconnecting...');
});

// Validate token then connect. We won't print the token itself.
(async () => {
  try {
    const info = await validateToken(process.env.TWITCH_OAUTH);
    console.log(`Token belongs to login: ${info.login || 'unknown'}`);
    console.log(`Token scopes: ${Array.isArray(info.scopes) ? info.scopes.join(', ') : info.scopes || 'none'}`);
  } catch (err) {
    console.warn('Token validation failed:', err && err.body ? JSON.stringify(err.body) : err.message || err);
  }

  client.connect().catch(err => {
    console.error('Connection error:', err);
  });
})();
