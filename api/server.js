// BritofScan — Servidor principal
require('dotenv').config();

const express      = require('express');
const http         = require('http');
const { Server }   = require('socket.io');
const helmet       = require('helmet');
const cors         = require('cors');
const path         = require('path');

const { swaggerUi, swaggerDocument } = require('./utils/swagger');
const { apiLimiter }   = require('./middleware/rateLimit');
const authRoutes        = require('./routes/auth');
const scanRoutes        = require('./routes/scan');
const reportsRoutes     = require('./routes/reports');

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
  console.log(`[WS] Cliente ligado: ${socket.id}`);

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
server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║           BritofScan — Plataforma de Pentest             ║
╚══════════════════════════════════════════════════════════╝

  Servidor:   http://localhost:${PORT}
  API Docs:   http://localhost:${PORT}/api/docs
  Firebase:   ${process.env.FIREBASE_PROJECT_ID || 'não configurado'}
`);
});

module.exports = { app, server, io };