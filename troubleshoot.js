const https = require('https');

function isoNow() {
  return new Date().toISOString();
}

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

function attachDebug(client, opts = {}) {
  // connected
  client.on('connected', (addr, port) => {
    console.log(`Connected to ${addr}:${port}`);
  });

  // raw IRC messages for low-level debugging
  client.on('raw', (message) => {
    try {
      console.log(`[${isoNow()}] RAW:`, message);
    } catch (e) {
      console.log('RAW (unserializable)');
    }
  });

  // NOTICE messages from Twitch
  client.on('notice', (channel, msgid, message) => {
    console.warn(`[${isoNow()}] NOTICE ${msgid} on ${channel}: ${message}`);
  });

  client.on('disconnected', (reason) => {
    console.warn('Disconnected:', reason);
  });

  client.on('reconnect', () => {
    console.log('Reconnecting...');
  });

  // Optionally log configured identity for debugging if opts object provided
  if (opts.identity) {
    try {
      console.log(`Configured identity: ${opts.identity.username}`);
    } catch (e) { /* ignore */ }
  }
}

function sendAndLog(client, channel, text) {
  try {
    const rawLine = `PRIVMSG ${channel} :${text}`;
    console.log(`[${isoNow()}] OUTGOING: ${rawLine}`);
  } catch (e) {
    console.log('Failed to stringify outgoing message');
  }
  return client.say(channel, text);
}

module.exports = {
  validateToken,
  attachDebug,
  sendAndLog
};