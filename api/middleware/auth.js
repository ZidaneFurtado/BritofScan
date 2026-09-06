// Middleware de verificação JWT
const jwt = require('jsonwebtoken');


const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 16) {
  console.error(
    '[AUTH-MIDDLEWARE] ERRO FATAL: JWT_SECRET não está definido ou é demasiado curto (mínimo 16 caracteres).\n' +
    '        Gere um valor forte com: openssl rand -hex 32\n' +
    '        e defina-o na variável de ambiente JWT_SECRET antes de arrancar a aplicação.'
  );
  process.exit(1);
}

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
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ erro: 'Sessão expirada — faz login novamente' });
    }
    return res.status(401).json({ erro: 'Token inválido' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'administrador') {
    return res.status(403).json({ erro: 'Acesso restrito a administradores' });
  }
  next();
}

module.exports = { verifyToken, requireAdmin };