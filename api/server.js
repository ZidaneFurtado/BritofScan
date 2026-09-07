// BritofScan — Servidor principal
require('dotenv').config();

const express      = require('express');
const http         = require('http');
const { Server }   = require('socket.io');
const helmet       = require('helmet');
const cors         = require('cors');
const path         = require('path');
const jwt          = require('jsonwebtoken');

const { swaggerUi, swaggerDocument } = require('./utils/swagger');
const { apiLimiter }   = require('./middleware/rateLimit');
const authRoutes        = require('./routes/auth');
const scanRoutes        = require('./routes/scan');
const reportsRoutes     = require('./routes/reports');
const alvosRoutes       = require('./routes/alvos');

const app    = express();
const server = http.createServer(app);

//  Socket.IO com pingTimeout longo para scans demorados
const io = new Server(server, {
  cors: {
    origin:      process.env.FRONTEND_URL || '*',
    methods:     ['GET', 'POST'],
    credentials: true,
  },
  pingTimeout:       120000,  // 2 min sem resposta → desliga
  pingInterval:       25000,  // ping a cada 25s
  upgradeTimeout:     30000,  // tempo para upgrade HTTP→WS
  maxHttpBufferSize:    1e6,  // 1MB max por mensagem
});

const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '127.0.0.1';

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 16) {
  console.error(
    '[SERVER] ERRO FATAL: JWT_SECRET não está definido ou é demasiado curto (mínimo 16 caracteres).\n' +
    '         Gere um valor forte com: openssl rand -hex 32'
  );
  process.exit(1);
}

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) {
    return next(new Error('Autenticação necessária'));
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = payload;
    next();
  } catch (err) {
    next(new Error('Token inválido ou expirado'));
  }
});

// Injetar Socket.IO nas rotas de scan
scanRoutes.setIO(io);

// ─── Middlewares ──────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/api', apiLimiter);

// Servir frontend estático
app.use(express.static(path.join(__dirname, '../frontend')));

// ─── Rotas API ────────────────────────────────────────────────────────────────
app.use('/api/auth',    authRoutes);
app.use('/api/scan',    scanRoutes);
app.use('/api/reports', reportsRoutes);
app.use('/api/alvos',   alvosRoutes);

app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, {
  customSiteTitle: 'BritofScan API Docs',
  customCss: '.swagger-ui .topbar { background-color: #0a0e1a; }',
}));

app.get('/api/health', (req, res) => {
  res.json({ estado: 'ok', versao: '1.0.0', timestamp: new Date().toISOString() });
});

// Fallback → frontend SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// ─── WebSocket ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log(`[WS] Cliente ligado: ${socket.id} (utilizador: ${socket.user.uid})`);

  // Associa o socket a uma sala identificada pelo seu próprio uid — usada
  // por scanner.js para restringir a emissão de eventos ao dono do scan.
  socket.join(`user:${socket.user.uid}`);

  //  Responde ao ping do cliente para manter ligação viva
  socket.on('ping', () => socket.emit('pong'));

  socket.on('disconnect', (reason) => {
    console.log(`[WS] Cliente desligado: ${socket.id} — motivo: ${reason}`);
  });

  socket.on('error', (err) => {
    console.error(`[WS] Erro no socket ${socket.id}:`, err.message);
  });
});

// ─── Erros ────────────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[SERVER] Erro:', err.message);
  res.status(500).json({ erro: 'Erro interno do servidor' });
});

// ─── Arranque ─────────────────────────────────────────────────────────────────
server.listen(PORT, HOST, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║           BritofScan — Plataforma de Pentest             ║
╚══════════════════════════════════════════════════════════╝

  Servidor:   http://${HOST}:${PORT}
  API Docs:   http://${HOST}:${PORT}/api/docs
  Firebase:   ${process.env.FIREBASE_PROJECT_ID || 'não configurado'}
`);
});

module.exports = { app, server, io };