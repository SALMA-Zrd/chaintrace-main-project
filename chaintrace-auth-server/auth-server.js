/**
 * ChainTrace — Auth Server v2.0
 * ─────────────────────────────
 * Port    : 3001
 * DB      : SQLite (chaintrace.db)
 * Sécurité: bcrypt + JWT
 *
 * INSTALLATION:
 *   npm install express better-sqlite3 bcryptjs jsonwebtoken cors
 *
 * LANCEMENT:
 *   node auth-server.js
 */

'use strict';

const express    = require('express');
const Database   = require('better-sqlite3');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const path       = require('path');
const fs         = require('fs');

const app        = express();
const PORT       = 3001;
const DB_PATH    = path.join(__dirname, 'chaintrace.db');
const JWT_SECRET = process.env.JWT_SECRET || 'chaintrace-nist-secret-key-2026';
const JWT_EXPIRY = '24h';
const SALT       = 10;

const VALID_ROLES = ['Admin', 'Maker', 'Transporter', 'Receiver', 'Assembler', 'Employer'];

app.use(cors());
app.use(express.json());

// ════════════════════════════════════════════════
// BASE DE DONNÉES SQLITE
// ════════════════════════════════════════════════

const db = new Database(DB_PATH);

// Activer les clés étrangères et le mode WAL (performance)
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Créer les tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    supplierID  TEXT     UNIQUE NOT NULL,
    name        TEXT     NOT NULL,
    email       TEXT     UNIQUE,
    company     TEXT     DEFAULT '',
    role        TEXT     NOT NULL,
    password    TEXT     NOT NULL,
    is_active   INTEGER  DEFAULT 1,
    created_at  TEXT     DEFAULT (datetime('now')),
    last_login  TEXT
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token        TEXT    PRIMARY KEY,
    supplier_id  TEXT    NOT NULL,
    created_at   TEXT    DEFAULT (datetime('now')),
    expires_at   TEXT    NOT NULL,
    FOREIGN KEY (supplier_id) REFERENCES users(supplierID) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    supplier_id TEXT,
    action      TEXT    NOT NULL,
    details     TEXT,
    ip          TEXT,
    created_at  TEXT    DEFAULT (datetime('now'))
  );
`);

// ════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════

function writeAudit(supplierID, action, details = '', ip = '') {
  db.prepare(`
    INSERT INTO audit_log (supplier_id, action, details, ip)
    VALUES (?, ?, ?, ?)
  `).run(supplierID || 'anonymous', action, details, ip);
}

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || '';
}

// ════════════════════════════════════════════════
// MIDDLEWARE JWT
// ════════════════════════════════════════════════

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token manquant ou invalide' });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token expiré ou invalide. Reconnectez-vous.' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'Admin') {
    return res.status(403).json({ error: 'Accès réservé aux administrateurs' });
  }
  next();
}

// ════════════════════════════════════════════════
// ROUTES PUBLIQUES
// ════════════════════════════════════════════════

/**
 * POST /auth/register
 * Créer un nouveau compte fournisseur
 */
app.post('/auth/register', async (req, res) => {
  const { supplierID, name, email, company, role, password } = req.body;

  // Validation des champs obligatoires
  if (!supplierID || !name || !role || !password) {
    return res.status(400).json({
      error: 'Les champs supplierID, name, role et password sont obligatoires'
    });
  }

  // Validation du rôle
  if (!VALID_ROLES.includes(role)) {
    return res.status(400).json({
      error: `Rôle invalide. Valeurs acceptées : ${VALID_ROLES.join(', ')}`
    });
  }

  // Validation du mot de passe
  if (password.length < 6) {
    return res.status(400).json({ error: 'Mot de passe minimum 6 caractères' });
  }

  // Validation de l'identifiant (pas d'espaces, caractères spéciaux limités)
  if (!/^[a-zA-Z0-9_\-\.]+$/.test(supplierID)) {
    return res.status(400).json({
      error: 'L\'identifiant ne peut contenir que des lettres, chiffres, _ - .'
    });
  }

  // Vérifier unicité
  const existing = db.prepare('SELECT id FROM users WHERE supplierID = ?').get(supplierID);
  if (existing) {
    return res.status(409).json({ error: `L'identifiant "${supplierID}" est déjà utilisé` });
  }

  if (email) {
    const emailExists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (emailExists) {
      return res.status(409).json({ error: 'Cette adresse email est déjà associée à un compte' });
    }
  }

  try {
    const hashed = await bcrypt.hash(password, SALT);

    const result = db.prepare(`
      INSERT INTO users (supplierID, name, email, company, role, password)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(supplierID, name, email || null, company || '', role, hashed);

    writeAudit(supplierID, 'REGISTER', `Nouveau compte créé - Rôle: ${role}`, getClientIP(req));

    console.log(`[AUTH] ✅ Nouveau compte: ${supplierID} (${role})`);

    res.status(201).json({
      success: true,
      message: `Compte "${supplierID}" créé avec succès`,
      user: { id: result.lastInsertRowid, supplierID, name, role }
    });

  } catch (err) {
    console.error('[AUTH] Erreur register:', err.message);
    res.status(500).json({ error: 'Erreur interne lors de la création du compte' });
  }
});

/**
 * POST /auth/login
 * Connexion et génération du JWT
 */
app.post('/auth/login', async (req, res) => {
  const { supplierID, password } = req.body;

  if (!supplierID || !password) {
    return res.status(400).json({ error: 'supplierID et password sont requis' });
  }

  const user = db.prepare('SELECT * FROM users WHERE supplierID = ?').get(supplierID);

  // Message générique pour éviter l'énumération de comptes
  if (!user) {
    writeAudit(supplierID, 'LOGIN_FAILED', 'Compte inexistant', getClientIP(req));
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }

  if (!user.is_active) {
    writeAudit(supplierID, 'LOGIN_BLOCKED', 'Compte désactivé', getClientIP(req));
    return res.status(403).json({ error: 'Compte désactivé. Contactez l\'administrateur.' });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    writeAudit(supplierID, 'LOGIN_FAILED', 'Mauvais mot de passe', getClientIP(req));
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }

  // Mettre à jour last_login
  db.prepare("UPDATE users SET last_login = datetime('now') WHERE supplierID = ?").run(supplierID);

  // Générer le JWT
  const payload = {
    supplierID: user.supplierID,
    name:       user.name,
    role:       user.role,
    email:      user.email,
  };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });

  // Enregistrer la session
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  db.prepare(`
    INSERT OR REPLACE INTO sessions (token, supplier_id, expires_at)
    VALUES (?, ?, ?)
  `).run(token, supplierID, expiresAt);

  writeAudit(supplierID, 'LOGIN_SUCCESS', `Connexion depuis ${getClientIP(req)}`, getClientIP(req));
  console.log(`[AUTH] ✅ Connexion: ${supplierID} (${user.role})`);

  res.json({
    success: true,
    token,
    user: {
      supplierID: user.supplierID,
      name:       user.name,
      email:      user.email || '',
      company:    user.company || '',
      role:       user.role,
      createdAt:  user.created_at,
      lastLogin:  user.last_login,
    }
  });
});

// ════════════════════════════════════════════════
// ROUTES PROTÉGÉES (JWT requis)
// ════════════════════════════════════════════════

/**
 * GET /auth/me
 * Profil de l'utilisateur connecté
 */
app.get('/auth/me', requireAuth, (req, res) => {
  const user = db.prepare(`
    SELECT supplierID, name, email, company, role, is_active, created_at, last_login
    FROM users WHERE supplierID = ?
  `).get(req.user.supplierID);

  if (!user) return res.status(404).json({ error: 'Compte introuvable' });
  res.json(user);
});

/**
 * PUT /auth/me/password
 * Modifier son propre mot de passe
 */
app.put('/auth/me/password', requireAuth, async (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'oldPassword et newPassword sont requis' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Nouveau mot de passe minimum 6 caractères' });
  }
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'Les mots de passe ne correspondent pas' });
  }

  const user = db.prepare('SELECT * FROM users WHERE supplierID = ?').get(req.user.supplierID);
  const valid = await bcrypt.compare(oldPassword, user.password);

  if (!valid) {
    return res.status(401).json({ error: 'Ancien mot de passe incorrect' });
  }

  const hashed = await bcrypt.hash(newPassword, SALT);
  db.prepare('UPDATE users SET password = ? WHERE supplierID = ?').run(hashed, req.user.supplierID);
  writeAudit(req.user.supplierID, 'PASSWORD_CHANGED', '', getClientIP(req));

  res.json({ success: true, message: 'Mot de passe mis à jour avec succès' });
});

/**
 * POST /auth/logout
 * Révoquer le token courant
 */
app.post('/auth/logout', requireAuth, (req, res) => {
  const token = req.headers.authorization?.slice(7);
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  writeAudit(req.user.supplierID, 'LOGOUT', '', getClientIP(req));
  res.json({ success: true, message: 'Déconnexion réussie' });
});

// ════════════════════════════════════════════════
// ROUTES ADMIN UNIQUEMENT
// ════════════════════════════════════════════════

/**
 * GET /auth/users
 * Liste tous les comptes
 */
app.get('/auth/users', requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT supplierID, name, email, company, role, is_active, created_at, last_login
    FROM users ORDER BY created_at DESC
  `).all();

  res.json({ users, total: users.length });
});

/**
 * PATCH /auth/users/:supplierID/toggle
 * Activer / désactiver un compte
 */
app.patch('/auth/users/:supplierID/toggle', requireAuth, requireAdmin, (req, res) => {
  const { supplierID } = req.params;

  if (supplierID === req.user.supplierID) {
    return res.status(400).json({ error: 'Vous ne pouvez pas désactiver votre propre compte' });
  }

  const user = db.prepare('SELECT is_active FROM users WHERE supplierID = ?').get(supplierID);
  if (!user) return res.status(404).json({ error: 'Compte introuvable' });

  const newStatus = user.is_active ? 0 : 1;
  db.prepare('UPDATE users SET is_active = ? WHERE supplierID = ?').run(newStatus, supplierID);

  writeAudit(req.user.supplierID, newStatus ? 'USER_ACTIVATED' : 'USER_DEACTIVATED', supplierID, getClientIP(req));

  res.json({
    success: true,
    supplierID,
    is_active: newStatus === 1,
    message: `Compte ${newStatus ? 'activé' : 'désactivé'}`
  });
});

/**
 * DELETE /auth/users/:supplierID
 * Supprimer définitivement un compte
 */
app.delete('/auth/users/:supplierID', requireAuth, requireAdmin, (req, res) => {
  const { supplierID } = req.params;

  if (supplierID === req.user.supplierID) {
    return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte' });
  }

  const result = db.prepare('DELETE FROM users WHERE supplierID = ?').run(supplierID);
  if (result.changes === 0) return res.status(404).json({ error: 'Compte introuvable' });

  writeAudit(req.user.supplierID, 'USER_DELETED', supplierID, getClientIP(req));
  res.json({ success: true, message: `Compte "${supplierID}" supprimé définitivement` });
});

/**
 * PATCH /auth/users/:supplierID/reset-password
 * Réinitialiser le mot de passe d'un utilisateur (admin)
 */
app.patch('/auth/users/:supplierID/reset-password', requireAuth, requireAdmin, async (req, res) => {
  const { supplierID } = req.params;
  const { newPassword } = req.body;

  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'newPassword minimum 6 caractères requis' });
  }

  const user = db.prepare('SELECT id FROM users WHERE supplierID = ?').get(supplierID);
  if (!user) return res.status(404).json({ error: 'Compte introuvable' });

  const hashed = await bcrypt.hash(newPassword, SALT);
  db.prepare('UPDATE users SET password = ? WHERE supplierID = ?').run(hashed, supplierID);
  writeAudit(req.user.supplierID, 'PASSWORD_RESET', `Reset pour ${supplierID}`, getClientIP(req));

  res.json({ success: true, message: `Mot de passe de "${supplierID}" réinitialisé` });
});

/**
 * GET /auth/audit
 * Historique des actions (admin)
 */
app.get('/auth/audit', requireAuth, requireAdmin, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const logs = db.prepare(`
    SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?
  `).all(limit);
  res.json({ logs, total: logs.length });
});

/**
 * PATCH /auth/users/:supplierID/role
 * Changer le rôle d'un utilisateur (admin)
 */
app.patch('/auth/users/:supplierID/role', requireAuth, requireAdmin, (req, res) => {
  const { supplierID } = req.params;
  const { role } = req.body;

  if (!VALID_ROLES.includes(role)) {
    return res.status(400).json({ error: `Rôle invalide: ${role}` });
  }

  const result = db.prepare('UPDATE users SET role = ? WHERE supplierID = ?').run(role, supplierID);
  if (result.changes === 0) return res.status(404).json({ error: 'Compte introuvable' });

  writeAudit(req.user.supplierID, 'ROLE_CHANGED', `${supplierID} → ${role}`, '');
  res.json({ success: true, supplierID, role, message: `Rôle mis à jour: ${role}` });
});

// ════════════════════════════════════════════════
// ROUTE INFO
// ════════════════════════════════════════════════

app.get('/', (req, res) => {
  const stats = db.prepare('SELECT COUNT(*) as total, SUM(is_active) as active FROM users').get();
  res.json({
    service:  'ChainTrace Auth Server v2.0',
    database: 'SQLite (chaintrace.db)',
    users:    stats,
    routes: {
      public:    ['POST /auth/register', 'POST /auth/login'],
      protected: ['GET /auth/me', 'PUT /auth/me/password', 'POST /auth/logout'],
      admin:     ['GET /auth/users', 'GET /auth/audit', 'PATCH /auth/users/:id/toggle', 'PATCH /auth/users/:id/role', 'PATCH /auth/users/:id/reset-password', 'DELETE /auth/users/:id'],
    }
  });
});

// ════════════════════════════════════════════════
// DÉMARRAGE
// ════════════════════════════════════════════════

app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  ╔═══════════════════════════════════════════╗');
  console.log('  ║   ChainTrace Auth Server v2.0             ║');
  console.log(`  ║   Port     : ${PORT}                          ║`);
  console.log(`  ║   Database : chaintrace.db (SQLite)       ║`);
  console.log('  ║   NIST SP 800-161 — Phase 6               ║');
  console.log('  ╚═══════════════════════════════════════════╝');
  console.log('');
  console.log('  Routes:');
  console.log('    POST  http://localhost:3001/auth/register');
  console.log('    POST  http://localhost:3001/auth/login');
  console.log('    GET   http://localhost:3001/auth/users  (admin)');
  console.log('');
});

// Nettoyage des sessions expirées toutes les heures
setInterval(() => {
  const result = db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();
  if (result.changes > 0) console.log(`[AUTH] Sessions expirées supprimées: ${result.changes}`);
}, 3600 * 1000);
