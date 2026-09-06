// Rotas de relatórios — listar, exportar e eliminar
const express = require('express');
const router  = express.Router();
const { gerarRelatorio }        = require('../modules/reportGenerator');
const { verifyToken, requireAdmin } = require('../middleware/auth');
const { scans }                 = require('../utils/localdb');

// ── Listar relatórios (scans concluídos) ──────────────────────────────────────

router.get('/', verifyToken, async (req, res) => {
  try {
    const filtro     = req.user.role === 'utilizador' ? { userId: req.user.uid } : {};
    const relatorios = scans.listar(filtro)
      .filter(s => s.estado === 'concluido')
      .map(s => ({
        id: s.id, target: s.target, mode: s.mode,
        summary: s.summary, criadoEm: s.criadoEm,
        concluidoEm: s.concluidoEm, duration: s.duration, userName: s.userName,
      }));
    res.json({ relatorios, total: relatorios.length });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao listar relatórios' });
  }
});

// ── Exportar relatório ────────────────────────────────────────────────────────
router.get('/:id/export', verifyToken, async (req, res) => {
  try {
    const formato = req.query.format || 'json';
    if (!['json', 'markdown', 'html'].includes(formato)) {
      return res.status(400).json({ erro: 'Formato inválido — usa: json, markdown, html' });
    }
    const scan = scans.porId(req.params.id);
    if (!scan) return res.status(404).json({ erro: 'Relatório não encontrado' });
    if (req.user.role === 'utilizador' && scan.userId !== req.user.uid) {
      return res.status(403).json({ erro: 'Acesso negado' });
    }
    const { conteudo, contentType, extensao } = gerarRelatorio(scan, formato);
    const nomeAlvo    = (scan.target || 'scan').replace(/[^a-zA-Z0-9]/g, '_');
    const nomeArquivo = `britofscan_${nomeAlvo}.${extensao}`;
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${nomeArquivo}"`);
    res.send(conteudo);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao exportar relatório' });
  }
});

// ── Eliminar (apenas Administrador) ───────────────────────────────────────────

router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    if (!scans.porId(req.params.id)) {
      return res.status(404).json({ erro: 'Relatório não encontrado' });
    }
    scans.remover(req.params.id);
    res.json({ mensagem: 'Relatório eliminado com sucesso' });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao eliminar relatório' });
  }
});

module.exports = router;