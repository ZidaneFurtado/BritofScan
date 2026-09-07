// Rotas de scan — iniciar, histórico e resultados
const express        = require('express');
const router         = express.Router();
const { v4: uuidv4 } = require('uuid');
const { executarScan, validarAlvo } = require('../modules/scanner');
const { gerarRelatorio } = require('../modules/reportGenerator');
const { verifyToken }    = require('../middleware/auth');
const { scanLimiter }    = require('../middleware/rateLimit');
const { scans }          = require('../utils/localdb');

let io;
function setIO(ioInstance) { io = ioInstance; }

// ── Iniciar scan ──────────────────────────────────────────────────────────────
router.post('/start', verifyToken, scanLimiter, async (req, res) => {
  const { target, mode = 'standard', format = 'json' } = req.body;
  if (!target) return res.status(400).json({ erro: 'Alvo (target) é obrigatório' });
  try {
    await validarAlvo(target);
  } catch (e) {
    return res.status(400).json({ erro: e.message });
  }

  const modos = ['stealth', 'standard', 'aggressive'];
  if (!modos.includes(mode)) {
    return res.status(400).json({ erro: `Modo inválido — usa: ${modos.join(', ')}` });
  }

  const scanId = uuidv4();
  const inicioISO = new Date().toISOString();

  scans.criar(scanId, {
    target, mode, format,
    estado:    'a_executar',
    userId:    req.user.uid,
    userName:  req.user.name,
    criadoEm:  inicioISO,
    createdAt: inicioISO,
  });

  // Responde imediatamente com o scanId
  res.json({
    mensagem:        'Scan iniciado com sucesso',
    scanId,
    websocketEvento: `scan:line:${scanId}`,
  });

  //  CORRIGIDO: delay de 1.5s para o frontend registar os listeners WebSocket
  setTimeout(async () => {
    try {
      const resultado = await executarScan(target, mode, scanId, io, req.user.uid);
      scans.atualizar(scanId, {
        estado:      'concluido',
        findings:    resultado.findings,
        correlacoes: resultado.correlacoes,
        summary:     resultado.resumo,
        topRiscos:   resultado.topRiscos,
        duration:    resultado.duration,
        linhas:      resultado.linhas || [],
        concluidoEm: new Date().toISOString(),
      });
      console.log(`[SCAN]  Concluído: ${scanId} — ${resultado.findings?.length} findings em ${resultado.duration}s`);
    } catch (err) {
      console.error(`[SCAN]  Erro no scan ${scanId}:`, err.message);
      scans.atualizar(scanId, { estado: 'erro', erro: err.message });
    }
  }, 1500);
});

// ── Histórico ─────────────────────────────────────────────────────────────────
router.get('/history', verifyToken, async (req, res) => {
  try {
    const filtro = req.user.role !== 'administrador' ? { userId: req.user.uid } : {};
    const lista  = scans.listar(filtro).map(s => ({
      id:          s.id,
      target:      s.target,
      mode:        s.mode,
      estado:      s.estado,
      summary:     s.summary,
      criadoEm:    s.criadoEm,
      concluidoEm: s.concluidoEm,
      duration:    s.duration,
      userName:    s.userName,
    }));
    res.json({ scans: lista, total: lista.length });
  } catch (err) {
    console.error('[SCAN] Erro ao obter histórico:', err);
    res.status(500).json({ erro: 'Erro ao obter histórico de scans' });
  }
});

// ── Obter scan por ID ─────────────────────────────────────────────────────────
router.get('/:id', verifyToken, async (req, res) => {
  try {
    const scan = scans.porId(req.params.id);
    if (!scan) return res.status(404).json({ erro: 'Scan não encontrado' });
    if (req.user.role !== 'administrador' && scan.userId !== req.user.uid) {
      return res.status(403).json({ erro: 'Acesso negado' });
    }
    res.json(scan);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao obter scan' });
  }
});

// ── Exportar relatório ────────────────────────────────────────────────────────
router.get('/:id/report', verifyToken, async (req, res) => {
  try {
    const formato = req.query.format || 'json';
    const scan    = scans.porId(req.params.id);
    if (!scan) return res.status(404).json({ erro: 'Scan não encontrado' });
    if (req.user.role !== 'administrador' && scan.userId !== req.user.uid) {
      return res.status(403).json({ erro: 'Acesso negado' });
    }
    const { conteudo, contentType, extensao } = gerarRelatorio(scan, formato);
    const nomeAlvo    = (scan.target || 'scan').replace(/[^a-zA-Z0-9]/g, '_');
    const nomeArquivo = `britofscan_${nomeAlvo}_${req.params.id.substring(0, 8)}.${extensao}`;
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${nomeArquivo}"`);
    res.send(conteudo);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao gerar relatório' });
  }
});

module.exports = router;
module.exports.setIO = setIO;