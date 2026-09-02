// Rotas de autenticação — registo, login e perfil
const express    = require('express');
const router     = express.Router();
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { utilizadores } = require('../utils/localdb');
const { verifyToken }  = require('../middleware/auth');
const { authLimiter }  = require('../middleware/rateLimit');

// ── Registo ───────────────────────────────────────────────────────────────────
router.post('/register', authLimiter, async (req, res) => {
  try {
    const { email, password, name, role = 'estudante' } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ erro: 'Email, password e nome são obrigatórios' });
    }
    if (password.length < 8) {
      return res.status(400).json({ erro: 'Password deve ter pelo menos 8 caracteres' });
    }
    if (!['estudante', 'professor'].includes(role)) {
      return res.status(400).json({ erro: 'Role inválida — usa: estudante, professor ou admin' });
    }

    if (utilizadores.porEmail(email)) {
      return res.status(409).json({ erro: 'Este e-mail já está registado' });
    }

    const hashPassword = await bcrypt.hash(password, 12);
    const utilizador   = utilizadores.criar({ email, name, role, password: hashPassword, scansTotal: 0 });

    const token = jwt.sign(
      { uid: utilizador.id, email, name, role },
      process.env.JWT_SECRET || 'dev_secret',
      { expiresIn: '24h' },
    );

    res.status(201).json({
      mensagem: 'Conta criada com sucesso',
      token,
      utilizador: { id: utilizador.id, email, name, role },
    });
  } catch (err) {
    console.error('[AUTH] Erro no registo:', err);
    res.status(500).json({ erro: 'Erro interno — tenta novamente' });
  }
});

// ── Login ─────────────────────────────────────────────────────────────────────
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ erro: 'Email e password são obrigatórios' });
    }

    const utilizador = utilizadores.porEmail(email);
    if (!utilizador) {
      return res.status(401).json({ erro: 'Credenciais inválidas' });
    }

    const passwordValida = await bcrypt.compare(password, utilizador.password);
    if (!passwordValida) {
      return res.status(401).json({ erro: 'Credenciais inválidas' });
    }

    const token = jwt.sign(
      { uid: utilizador.id, email: utilizador.email, name: utilizador.name, role: utilizador.role },
      process.env.JWT_SECRET || 'dev_secret',
      { expiresIn: '24h' },
    );

    res.json({
      mensagem: 'Login bem-sucedido',
      token,
      utilizador: { id: utilizador.id, email: utilizador.email, name: utilizador.name, role: utilizador.role },
    });
  } catch (err) {
    console.error('[AUTH] Erro no login:', err);
    res.status(500).json({ erro: 'Erro interno' });
  }
});

// ── Perfil ────────────────────────────────────────────────────────────────────
router.get('/me', verifyToken, async (req, res) => {
  try {
    const utilizador = utilizadores.porId(req.user.uid);
    if (!utilizador) {
      return res.status(404).json({ erro: 'Utilizador não encontrado' });
    }
    const { password: _, ...dados } = utilizador;
    res.json(dados);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao obter perfil' });
  }
});

module.exports = router;
