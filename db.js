const path = require('path');
require('dotenv').config();
const sqlite3 = require('sqlite3').verbose();
const DB_PATH = path.join(__dirname, 'robobot.db');

function openDb() {
  return new sqlite3.Database(DB_PATH);
}

function init() {
  return new Promise((resolve, reject) => {
    const db = openDb();
    const defaultAdmin = process.env.DEFAULT_ADMIN_UID;
    const defaultChannel = process.env.DEFAULT_CHANNEL;
    const defaultPrefix = process.env.DEFAULT_PREFIX || '!';

    db.serialize(() => {
      db.run(`CREATE TABLE IF NOT EXISTS admins (
        uid TEXT PRIMARY KEY
      );`);
      db.run(`CREATE TABLE IF NOT EXISTS channels (
        channel TEXT PRIMARY KEY,
        prefix TEXT
      );`);
      // Create chat_history table for persistent message logging
      db.run(`CREATE TABLE IF NOT EXISTS chat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel TEXT,
        user TEXT,
        text TEXT,
        ts INTEGER
      );`);
      // Create banned_users table for persistent bans
      db.run(`CREATE TABLE IF NOT EXISTS banned_users (
        uid TEXT PRIMARY KEY
      );`);

      // NEW: settings kv store
      db.run(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
      );`);

      // NEW: online_mode settings per channel (whether bot lockdowns when streamer is online)
      db.run(`CREATE TABLE IF NOT EXISTS online_mode (
        channel TEXT PRIMARY KEY,
        enabled INTEGER DEFAULT 1
      );`);

      // Migrate/add require_admin column if missing, then perform default inserts and close inside callback
      db.all(`PRAGMA table_info(channels)`, [], (err, cols) => {
        if (err) {
          // close and resolve/reject accordingly
          db.close(() => reject(err));
          return;
        }
        const hasRequire = Array.isArray(cols) && cols.some(c => c && c.name === 'require_admin');
        const doAfterMigration = () => {
          // Ensure initial admin and default channel if configured via environment
          if (defaultAdmin) {
            db.run(`INSERT OR IGNORE INTO admins(uid) VALUES(?)`, [String(defaultAdmin)]);
          }
          if (defaultChannel) {
            const defaultRequireAdmin = (String(process.env.DEFAULT_CHANNEL_ADMIN || '').toLowerCase() === '1' || String(process.env.DEFAULT_CHANNEL_ADMIN || '').toLowerCase() === 'true') ? 1 : 0;
            db.run(`INSERT OR IGNORE INTO channels(channel, prefix) VALUES(?,?)`, [String(defaultChannel), String(defaultPrefix)], function() {
              // attempt to update require_admin if column exists
              db.run(`UPDATE channels SET require_admin = ? WHERE channel = ?`, [defaultRequireAdmin, String(defaultChannel)]);
            });
          }
          db.close((err) => err ? reject(err) : resolve());
        };

        if (!hasRequire) {
          db.run(`ALTER TABLE channels ADD COLUMN require_admin INTEGER DEFAULT 0`, [], (alterErr) => {
            if (alterErr) console.error('Failed to add require_admin column:', alterErr && alterErr.message ? alterErr.message : alterErr);
            doAfterMigration();
          });
        } else {
          doAfterMigration();
        }
      });
    });
  });
}

// Add a user to the banned_users table
function addBannedUser(uid) {
  return new Promise((resolve, reject) => {
    const db = openDb();
    db.run(`INSERT OR IGNORE INTO banned_users(uid) VALUES(?)`, [String(uid)], function(err) {
      db.close();
      if (err) return reject(err);
      resolve();
    });
  });
}

// Remove a user from the banned_users table
function removeBannedUser(uid) {
  return new Promise((resolve, reject) => {
    const db = openDb();
    db.run(`DELETE FROM banned_users WHERE uid = ?`, [String(uid)], function(err) {
      db.close();
      if (err) return reject(err);
      resolve();
    });
  });
}

// Load all banned user IDs as an array of strings
function loadBannedUsers() {
  return new Promise((resolve, reject) => {
    const db = openDb();
    db.all(`SELECT uid FROM banned_users`, [], (err, rows) => {
      db.close();
      if (err) return reject(err);
      resolve(rows.map(r => String(r.uid)));
    });
  });
}

function loadAdmins() {
  return new Promise((resolve, reject) => {
    const db = openDb();
    db.all(`SELECT uid FROM admins`, [], (err, rows) => {
      db.close();
      if (err) return reject(err);
      const set = new Set(rows.map(r => String(r.uid)));
      resolve(set);
    });
  });
}

function loadChannels() {
  return new Promise((resolve, reject) => {
    const db = openDb();
    db.all(`SELECT channel, prefix, require_admin FROM channels`, [], (err, rows) => {
      db.close();
      if (err) return reject(err);
      const map = new Map(rows.map(r => [String(r.channel), { prefix: r.prefix || '!', require_admin: !!r.require_admin }]));
      resolve(map);
    });
  });
}

function addChannel(channel, prefix, requireAdmin) {
  return new Promise((resolve, reject) => {
    const db = openDb();
    const req = requireAdmin ? 1 : 0;
    db.run(`INSERT OR REPLACE INTO channels(channel, prefix, require_admin) VALUES(?,?,?)`, [channel, prefix, req], function(err) {
      db.close();
      if (err) return reject(err);
      resolve();
    });
  });
}

function removeChannel(channel) {
  return new Promise((resolve, reject) => {
    const db = openDb();
    db.run(`DELETE FROM channels WHERE channel = ?`, [channel], function(err) {
      db.close();
      if (err) return reject(err);
      resolve();
    });
  });
}

function addAdmin(uid) {
  return new Promise((resolve, reject) => {
    const db = openDb();
    db.run(`INSERT OR IGNORE INTO admins(uid) VALUES(?)`, [String(uid)], function(err) {
      db.close();
      if (err) return reject(err);
      resolve();
    });
  });
}

function removeAdmin(uid) {
  return new Promise((resolve, reject) => {
    const db = openDb();
    db.run(`DELETE FROM admins WHERE uid = ?`, [String(uid)], function(err) {
      db.close();
      if (err) return reject(err);
      resolve();
    });
  });
}

function isAdminUid(uid) {
  return new Promise((resolve, reject) => {
    const db = openDb();
    db.get(`SELECT uid FROM admins WHERE uid = ?`, [String(uid)], (err, row) => {
      db.close();
      if (err) return reject(err);
      resolve(!!row);
    });
  });
}

// NEW: generic settings helpers
function getSetting(key) {
  return new Promise((resolve, reject) => {
    const db = openDb();
    db.get(`SELECT value FROM settings WHERE key = ?`, [String(key)], (err, row) => {
      db.close();
      if (err) return reject(err);
      resolve(row ? String(row.value) : null);
    });
  });
}

function setSetting(key, value) {
  return new Promise((resolve, reject) => {
    const db = openDb();
    db.run(`INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)`, [String(key), String(value)], function(err) {
      db.close();
      if (err) return reject(err);
      resolve();
    });
  });
}

// NEW: specific LLM settings
function getLLMSystemPrompt() { return getSetting('llm_system_prompt'); }
function setLLMSystemPrompt(prompt) { return setSetting('llm_system_prompt', prompt); }
function getCharacterCardPath() { return getSetting('llm_character_card_path'); }
function setCharacterCardPath(p) { return setSetting('llm_character_card_path', p); }

// NEW: on startup, populate settings from .env if not set
function ensureLLMDefaultsFromEnv() {
  return new Promise(async (resolve, reject) => {
    try {
      const curPrompt = await getLLMSystemPrompt();
      const curCard = await getCharacterCardPath();
      if (!curPrompt && process.env.LLM_SYSTEM_PROMPT) {
        await setLLMSystemPrompt(String(process.env.LLM_SYSTEM_PROMPT));
      }
      if (!curCard && process.env.LLM_CHARACTER_CARD) {
        await setCharacterCardPath(String(process.env.LLM_CHARACTER_CARD));
      }
      resolve();
    } catch (e) {
      reject(e);
    }
  });
}

module.exports = {
  init,
  loadAdmins,
  loadChannels,
  addChannel,
  removeChannel,
  isAdminUid,
  addAdmin,
  removeAdmin,
  addBannedUser,
  removeBannedUser,
  loadBannedUsers,
  // Add chat message to persistent history
  addChatMessage: function(channel, user, text, ts) {
    return new Promise((resolve, reject) => {
      const db = openDb();
      db.run(`INSERT INTO chat_history(channel, user, text, ts) VALUES(?,?,?,?)`, [channel, user, text, ts], function(err) {
        db.close();
        if (err) return reject(err);
        resolve();
      });
    });
  },

  // Get recent chat messages for a channel, most recent first
  getRecentChatMessages: function(channel, limit, maxChars) {
    return new Promise((resolve, reject) => {
      const db = openDb();
      db.all(`SELECT user, text, ts FROM chat_history WHERE channel = ? ORDER BY ts DESC LIMIT ?`, [channel, limit], (err, rows) => {
        db.close();
        if (err) return reject(err);
        // Optionally trim to maxChars
        if (maxChars && maxChars > 0) {
          let acc = '';
          const out = [];
          for (const row of rows) {
            const line = `${row.user}: ${row.text}\n`;
            if ((acc.length + line.length) > maxChars) break;
            acc = line + acc;
            out.push(row);
          }
          resolve(out);
        } else {
          resolve(rows);
        }
      });
    });
  },

  // Prune old chat messages for a channel, keeping only the most recent N
  pruneChatHistory: function(channel, keepLimit) {
    return new Promise((resolve, reject) => {
      const db = openDb();
      db.run(`DELETE FROM chat_history WHERE id NOT IN (SELECT id FROM chat_history WHERE channel = ? ORDER BY ts DESC LIMIT ?) AND channel = ?`, [channel, keepLimit, channel], function(err) {
        db.close();
        if (err) return reject(err);
        resolve();
      });
    });
  },

  // NEW: exported LLM helpers
  getSetting,
  setSetting,
  getLLMSystemPrompt,
  setLLMSystemPrompt,
  getCharacterCardPath,
  setCharacterCardPath,
  ensureLLMDefaultsFromEnv,

  // NEW: online mode helpers
  getOnlineModeEnabled: function(channel) {
    return new Promise((resolve, reject) => {
      const db = openDb();
      db.get(`SELECT enabled FROM online_mode WHERE channel = ?`, [channel], (err, row) => {
        db.close();
        if (err) return reject(err);
        // Default to true (1) if not set
        resolve(row ? !!row.enabled : true);
      });
    });
  },

  setOnlineModeEnabled: function(channel, enabled) {
    return new Promise((resolve, reject) => {
      const db = openDb();
      const val = enabled ? 1 : 0;
      db.run(`INSERT OR REPLACE INTO online_mode(channel, enabled) VALUES(?, ?)`, [channel, val], function(err) {
        db.close();
        if (err) return reject(err);
        resolve();
      });
    });
  },

  toggleOnlineMode: function(channel) {
    return new Promise(async (resolve, reject) => {
      try {
        const db = openDb();
        db.get(`SELECT enabled FROM online_mode WHERE channel = ?`, [channel], async (err, row) => {
          if (err) {
            db.close();
            return reject(err);
          }
          const current = row ? !!row.enabled : true;
          const newValue = !current;
          
          db.run(`INSERT OR REPLACE INTO online_mode(channel, enabled) VALUES(?, ?)`, [channel, newValue ? 1 : 0], function(err2) {
            db.close();
            if (err2) return reject(err2);
            resolve(newValue);
          });
        });
      } catch (e) {
        reject(e);
      }
    });
  }
};
