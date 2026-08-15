// Middleware de verificação JWT
const jwt = require('jsonwebtoken');

/**
 * Verifica o token JWT no header Authorization.
 * Injeta req.user com os dados do payload.
 */
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ erro: 'Token de autenticação em falta' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev_secret');
    req.user = payload;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ erro: 'Sessão expirada — faz login novamente' });
    }
    return res.status(401).json({ erro: 'Token inválido' });
  }
}

/**
 * Middleware que verifica se o utilizador tem role de admin ou professor.
 */
function requireAdmin(req, res, next) {
  if (!req.user || !['admin', 'professor'].includes(req.user.role)) {
    return res.status(403).json({ erro: 'Acesso restrito a administradores e professores' });
  }
  next();
}

module.exports = { verifyToken, requireAdmin };
