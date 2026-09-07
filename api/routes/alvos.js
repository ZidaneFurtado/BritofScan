// Rotas de gestão da lista de alvos autorizados (whitelist)
// GET  é acessível a qualquer utilizador autenticado (para preencher o
//      formulário de novo scan no frontend).
// POST e DELETE são restritos ao papel de Administrador.
const express = require('express');
const router  = express.Router();
const { verifyToken, requireAdmin } = require('../middleware/auth');
const { alvosAutorizados }          = require('../utils/localdb');
const { validarAlvo }               = require('../modules/utils');

// ── Listar alvos autorizados ──────────────────────────────────────────────────
router.get('/', verifyToken, (req, res) => {
  try {
    const lista = alvosAutorizados.listar().map(a => ({
      id: a.id, alvo: a.alvo, criadoEm: a.criadoEm,
    }));
    res.json({ alvos: lista, total: lista.length });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao obter lista de alvos autorizados' });
  }
});

// ── Adicionar alvo autorizado (apenas Administrador) ──────────────────────────
router.post('/', verifyToken, requireAdmin, async (req, res) => {
  const { alvo } = req.body;
  if (!alvo) return res.status(400).json({ erro: 'Campo "alvo" é obrigatório' });

  // Reutiliza a mesma validação SSRF usada no arranque de scans, para não
  // permitir sequer autorizar um alvo de rede interna.
  let hostValidado;
  try {
    hostValidado = await validarAlvo(alvo);
  } catch (e) {
    return res.status(400).json({ erro: e.message });
  }

  try {
    const doc = alvosAutorizados.adicionar(hostValidado, req.user.uid);
    res.status(201).json(doc);
  } catch (e) {
    res.status(400).json({ erro: e.message });
  }
});

// ── Remover alvo autorizado (apenas Administrador) ────────────────────────────
router.delete('/:id', verifyToken, requireAdmin, (req, res) => {
  try {
    alvosAutorizados.remover(req.params.id);
    res.json({ mensagem: 'Alvo removido' });
  } catch (e) {
    res.status(404).json({ erro: e.message });
  }
});

module.exports = router;