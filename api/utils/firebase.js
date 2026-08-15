const admin = require('firebase-admin');

let db   = null;
let auth = null;

function initFirebase() {
  if (admin.apps.length > 0) return;

  const projectId   = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey  = process.env.FIREBASE_PRIVATE_KEY
    ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
    : undefined;

  if (!projectId || !clientEmail || !privateKey) {
    console.error('[Firebase]  Credenciais em falta no .env');
    process.exit(1);
  }

  admin.initializeApp({
    credential: admin.credential.cert({ projectId, clientEmail, privateKey }),
  });

  db   = admin.firestore();
  auth = admin.auth();

  console.log('[Firebase]  Ligado ao projeto:', projectId);
}

function getDb() {
  if (!db) initFirebase();
  return db;
}

function getAuth() {
  if (!auth) initFirebase();
  return auth;
}

module.exports = { initFirebase, getDb, getAuth };