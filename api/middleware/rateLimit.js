// Middleware de rate limiting para proteger a API
const rateLimit = require('express-rate-limit');

// Limite geral: 100 pedidos por 15 minutos
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { erro: 'Demasiados pedidos — tenta novamente em 15 minutos' },
});

// Limite para autenticação: 10 pedidos por 15 minutos (anti brute-force)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { erro: 'Demasiadas tentativas de autenticação — tenta novamente em 15 minutos' },
});

// Limite para scans: 5 scans por hora (scans são computacionalmente pesados)
const scanLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.uid || req.ip,
  message: { erro: 'Limite de 5 scans por hora atingido — aguarda antes de iniciar outro' },
});

module.exports = { apiLimiter, authLimiter, scanLimiter };
