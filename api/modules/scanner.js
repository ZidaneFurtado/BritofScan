// scanner.js - Orquestrador principal BritofScan
const { calcularScore, classificarSeveridade, analisarFindings } = require('./scoring');
const { validarAlvo } = require('./utils');
const { executarFase1 } = require('./fase1_recon');
const { executarFase2 } = require('./fase2_web');
const { executarFase3 } = require('./fase3_vuln');

async function executarScan(target, mode = 'standard', uid, io) {
  const inicio   = Date.now();
  const findings = [];
  const linhas   = [];

  const emitir = (texto, nivel = 'info', fase = 0) => {
    // Remove escape codes ANSI do output das ferramentas
    const limpo = String(texto || '').replace(/\x1B\[[0-9;]*[mGKHF]/g, '').trim();
    if (!limpo) return;
    const payload = { ts: new Date().toISOString(), text: limpo, level: nivel, phase: fase };
    linhas.push(payload);
    if (io) io.emit(`scan:line:${uid}`, payload);
  };

  const progresso = (label, atual, total, cor = '#3b82f6') => {
    const pct = Math.round((atual / total) * 100);
    if (io) io.emit(`scan:progress:${uid}`, { label, current: atual, total, pct, color: cor });
  };

  const faseEvento = (fase, estado) => {
    if (io) io.emit(`scan:phase:${uid}`, { phase: fase, state: estado });
  };

  // Separa findings reais de simulados
  const adicionarFinding = (titulo, descricao, ferramenta, fase, impact, confidence, remediacao = '', cve = null, simulado = false) => {
    if (!titulo || !descricao) return;
    const score = calcularScore(impact, confidence);
    findings.push({
      titulo, descricao, ferramenta, fase,
      impact, confidence, score,
      severidade: classificarSeveridade(score),
      remediacao, cve,
      simulado, // marca claramente se é dado real ou simulado
    });
  };

  let host;
  try {
    host = validarAlvo(target);
  } catch (e) {
    emitir(`ERRO: ${e.message}`, 'error', 0);
    throw e;
  }

  const targetUrl = target.startsWith('http') ? target : `https://${target}`;

  emitir(`BritofScan v2.0 - Alvo: ${target} | Modo: ${mode.toUpperCase()}`, 'info', 0);
  emitir(`Scan ID: ${uid}`, 'info', 0);
  emitir(`Inicio: ${new Date().toLocaleString('pt-PT')}`, 'info', 0);

  // FASE 1
  faseEvento(1, 'running');
  await executarFase1(host, mode, emitir, progresso, adicionarFinding);
  faseEvento(1, 'done');
  emitir(`Fase 1 concluida - ${findings.length} findings`, 'success', 1);

  // FASE 2
  faseEvento(2, 'running');
  await executarFase2(targetUrl, host, mode, emitir, progresso, adicionarFinding);
  faseEvento(2, 'done');
  emitir(`Fase 2 concluida - ${findings.length} findings`, 'success', 2);

  // FASE 3
  faseEvento(3, 'running');
  await executarFase3(targetUrl, emitir, progresso, adicionarFinding);


  findings
    .filter(f => !f.simulado && f.fase === 1 && f.cve)
    .forEach(f => {
      emitir(`CVE confirmada: ${f.cve} para ${f.titulo}`, 'warning', 3);
    });

  faseEvento(3, 'done');
  emitir(`Fase 3 concluida - ${findings.length} findings`, 'success', 3);

  // FASE 4 - Correlacao e scoring
  faseEvento(4, 'running');
  emitir(`[4/4] CORRELACAO E INTELIGENCIA`, 'phase', 4);
  if (io) io.emit(`scan:progress:${uid}`, { label: 'Score e correlacoes', current: 1, total: 1, pct: 100, color: '#3b82f6' });

  const analise = analisarFindings(findings);

  // Separa findings reais de simulados no report
  const findingsReais    = analise.findings.filter(f => !f.simulado);
  const findingsSimulados = analise.findings.filter(f => f.simulado);

  emitir(`Findings reais: ${findingsReais.length}`, 'info', 4);
  if (findingsSimulados.length > 0)
    emitir(`Findings simulados (excluidos do report): ${findingsSimulados.length}`, 'warning', 4);

  emitir('TOP 5 RISCOS REAIS:', 'info', 4);
  findingsReais.slice(0, 5).forEach((r, i) =>
    emitir(`  ${i + 1}. [${r.severidade}] ${r.titulo} - Score: ${r.score}`,
      r.severidade === 'CRITICAL' ? 'critical' : 'warning', 4));

  faseEvento(4, 'done');

  const duracao = Math.round((Date.now() - inicio) / 1000);
  const resumoFinal = {
    ...analise.resumo,
    totalReais:    findingsReais.length,
    totalSimulados: findingsSimulados.length,
  };

  emitir(`SCAN CONCLUIDO - ${duracao}s | ${findingsReais.length} findings reais | Score: ${analise.resumo.scoreGlobal}/10`, 'success', 4);

  if (io) {
    io.emit(`scan:done:${uid}`, {
      duration:      duracao,
      totalFindings: findingsReais.length,
      counts:        resumoFinal,
    });
  }

  // Retorna apenas findings reais no resultado principal
  return {
    ...analise,
    findings:    findingsReais,
    findingsAll: analise.findings,
    linhas, duration: duracao, target, mode, id: uid,
  };
}

module.exports = { executarScan, validarAlvo };