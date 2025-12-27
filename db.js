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
    db.serialize(() => {
      db.run(`CREATE TABLE IF NOT EXISTS admins (
        uid TEXT PRIMARY KEY
      );`);

      db.run(`CREATE TABLE IF NOT EXISTS channels (
        channel TEXT PRIMARY KEY,
        prefix TEXT
      );`);

      // Ensure initial admin and default channel if configured via environment
      const defaultAdmin = process.env.DEFAULT_ADMIN_UID;
      const defaultChannel = process.env.DEFAULT_CHANNEL;
      const defaultPrefix = process.env.DEFAULT_PREFIX || '!';
      if (defaultAdmin) {
        db.run(`INSERT OR IGNORE INTO admins(uid) VALUES(?)`, [String(defaultAdmin)]);
      }
      if (defaultChannel) {
        db.run(`INSERT OR IGNORE INTO channels(channel, prefix) VALUES(?,?)`, [String(defaultChannel), String(defaultPrefix)]);
      }

      db.close((err) => err ? reject(err) : resolve());
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
    db.all(`SELECT channel, prefix FROM channels`, [], (err, rows) => {
      db.close();
      if (err) return reject(err);
      const map = new Map(rows.map(r => [String(r.channel), r.prefix || '!']));
      resolve(map);
    });
  });
}

function addChannel(channel, prefix) {
  return new Promise((resolve, reject) => {
    const db = openDb();
    db.run(`INSERT OR REPLACE INTO channels(channel, prefix) VALUES(?,?)`, [channel, prefix], function(err) {
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
