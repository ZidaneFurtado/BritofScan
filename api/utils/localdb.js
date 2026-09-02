// Base de dados local — armazenamento em ficheiro JSON
// Substitui o Firebase, e fica base de dados primária
const fs   = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '../../data');
const DB_FILE  = path.join(DATA_DIR, 'britofscan_db.json');

// Estrutura inicial da BD
const DB_INICIAL = { utilizadores: {}, scans: {} };

// ── Helpers de I/O ────────────────────────────────────────────────────────────

function lerDB() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE))  fs.writeFileSync(DB_FILE, JSON.stringify(DB_INICIAL, null, 2));
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch {
    return { ...DB_INICIAL };
  }
}

function gravarDB(db) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ── API de utilizadores ───────────────────────────────────────────────────────

const utilizadores = {
  /** Cria utilizador — retorna o objeto criado */
  criar(dados) {
    const db  = lerDB();
    const id  = `u_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const doc = { id, ...dados, criadoEm: new Date().toISOString() };
    db.utilizadores[id] = doc;
    gravarDB(db);
    return doc;
  },

  /** Procura por email — retorna o doc ou null */
  porEmail(email) {
    const db = lerDB();
    return Object.values(db.utilizadores).find(u => u.email === email) || null;
  },

  /** Procura por ID */
  porId(id) {
    const db = lerDB();
    return db.utilizadores[id] || null;
  },
};

// ── API de scans ──────────────────────────────────────────────────────────────

const scans = {
  /** Cria registo de scan */
  criar(id, dados) {
    const db  = lerDB();
    const doc = { id, ...dados };
    db.scans[id] = doc;
    gravarDB(db);
    return doc;
  },

  /** Atualiza campos de um scan existente */
  atualizar(id, campos) {
    const db = lerDB();
    if (!db.scans[id]) throw new Error(`Scan ${id} não encontrado`);
    db.scans[id] = { ...db.scans[id], ...campos };
    gravarDB(db);
    return db.scans[id];
  },

  /** Obtém scan por ID */
  porId(id) {
    const db = lerDB();
    return db.scans[id] || null;
  },

  /** Lista scans com filtro opcional por userId */
  listar({ userId } = {}) {
    const db   = lerDB();
    let lista  = Object.values(db.scans);
    if (userId) lista = lista.filter(s => s.userId === userId);
    return lista.sort((a, b) => new Date(b.criadoEm) - new Date(a.criadoEm)).slice(0, 50);
  },

  /** Remove scan por ID */
  remover(id) {
    const db = lerDB();
    delete db.scans[id];
    gravarDB(db);
  },
};

module.exports = { utilizadores, scans };
