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

module.exports = {
  init,
  loadAdmins,
  loadChannels,
  addChannel,
  removeChannel,
  isAdminUid,
  addAdmin,
  removeAdmin
};
