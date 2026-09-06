// reportGenerator.js - Geracao de relatorios em JSON, Markdown e HTML
const { SEVERIDADE } = require('./scoring');

function escapeHtml(valor) {
  if (valor === null || valor === undefined) return '';
  return String(valor)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const FERRAMENTAS_OBSERVACAO_DIRETA = [
  'header-audit', 'cookie-audit', 'http-methods', 'waf-detect', 'ssl-check', 'file-scanner',
];

/**
 * @param {Object} finding
 * @returns {string}
 */
function classificarOrigemScore(finding) {
  if (!finding.vetorCVSS) return 'heuristica-legado';
  if (finding.ferramenta === 'nmap') {
    return finding.cve ? 'confirmado' : 'estimado';
  }
  if (['nikto', 'nuclei'].includes(finding.ferramenta)) {
    return 'estimado';
  }
  if (FERRAMENTAS_OBSERVACAO_DIRETA.includes(finding.ferramenta)) {
    return 'confirmado';
  }
  return 'estimado'; // por defeito, conservador
}

// ── Helpers ────────────────────────────────────────────────────────────────
function extrairDados(scan) {
  return {
    meta: {
      id: scan.id || 'N/A',
      alvo: scan.target || 'N/A',
      modo: scan.mode || 'standard',
      inicio: scan.createdAt || new Date().toISOString(),
      duracao: scan.duration || 0,
    },
    resumo: scan.summary || { total: 0, criticos: 0, altos: 0, medios: 0, baixos: 0, info: 0, scoreGlobal: 0 },
    correlacoes: scan.correlacoes || [],
    findings: scan.findings || [],
  };
}

// ── JSON ───────────────────────────────────────────────────────────────────
function gerarJSON(scan) {
  const dados = {
    meta: {
      id: scan.id,
      alvo: scan.target,
      modo: scan.mode,
      inicio: scan.createdAt,
      duracao: scan.duration,
      versao: '1.0.0',
      geradoPor: 'BritofScan',
    },
    resumo: scan.summary || {},
    correlacoes: (scan.correlacoes || []).map(c => ({
      titulo: c.titulo, score: c.score, severidade: c.severidade,
      descricao: c.descricao, remediacao: c.remediacao,
      tipoScore: 'heuristica-correlacao', // NUNCA um vetor CVSS - julgamento fixo sobre combinação de findings
    })),
    findings: (scan.findings || []).map(f => ({
      titulo: f.titulo, severidade: f.severidade, score: f.score,
      fase: f.fase, ferramenta: f.ferramenta, descricao: f.descricao,
      remediacao: f.remediacao, cve: f.cve || null,
      vetorCVSS: f.vetorCVSS || null,
      tipoScore: classificarOrigemScore(f),
    })),
  };

  return {
    conteudo: JSON.stringify(dados, null, 2),
    contentType: 'application/json',
    extensao: 'json',
  };
}

// ── MARKDOWN ───────────────────────────────────────────────────────────────
function gerarMarkdown(scan) {
  const { meta, resumo, correlacoes, findings } = extrairDados(scan);
  const data = new Date(meta.inicio).toLocaleString('pt-PT');

  let md = `# BritofScan — Relatório de Penetration Testing\n\n`;
  // CORRIGIDO: meta.alvo e meta.modo agora escapados também no Markdown
  // (lacuna identificada — só estavam escapados na versão HTML).
  md += `> **Alvo:** \`${escapeHtml(meta.alvo)}\` | **Modo:** ${escapeHtml(meta.modo)} | **Data:** ${escapeHtml(data)}\n\n`;
  md += `---\n\n## Resumo Executivo\n\n`;
  md += `| Métrica | Valor |\n|---------|-------|\n`;
  md += `| Score Global de Risco | **${resumo.scoreGlobal}/10** |\n`;
  md += `| Total de Findings | ${resumo.total} |\n`;
  md += `| 🔴 Críticos | ${resumo.criticos} |\n`;
  md += `| 🟠 Altos | ${resumo.altos} |\n`;
  md += `| 🟡 Médios | ${resumo.medios} |\n`;
  md += `| 🟢 Baixos | ${resumo.baixos} |\n`;
  md += `| 🔵 Info | ${resumo.info} |\n\n`;

  if (correlacoes.length > 0) {
    md += `---\n\n## ⚡ Riscos Compostos (Correlações)\n\n`;
    md += `> Nota: os scores desta secção são uma heurística de julgamento sobre a combinação de findings, não um cálculo CVSS individual.\n\n`;
    correlacoes.forEach(c => {
      const emoji = SEVERIDADE[c.severidade]?.emoji || '';
      md += `### ${emoji} ${escapeHtml(c.titulo)} — Score: ${c.score}\n\n`;
      md += `**Severidade:** ${c.severidade} | **Tipo:** Correlação Automática (heurística, sem vetor CVSS)\n\n`;
      md += `**Descrição:** ${escapeHtml(c.descricao)}\n\n`;
      md += `**Remediação:** ${escapeHtml(c.remediacao)}\n\n`;
    });
  }

  const grupos = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  grupos.forEach(sev => {
    const grupo = findings.filter(f => f.severidade === sev);
    if (grupo.length === 0) return;
    const emoji = SEVERIDADE[sev]?.emoji || '';
    md += `---\n\n## ${emoji} Findings ${sev} (${grupo.length})\n\n`;
    grupo.forEach(f => {
      md += `### ${escapeHtml(f.titulo)}\n\n`;
      md += `| Campo | Valor |\n|-------|-------|\n`;
      md += `| Score | ${f.score} |\n`;
      md += `| Origem do Score | ${classificarOrigemScore(f)} |\n`;
      if (f.vetorCVSS) md += `| Vetor CVSS | \`${escapeHtml(f.vetorCVSS)}\` |\n`;
      md += `| Ferramenta | ${escapeHtml(f.ferramenta || 'N/A')} |\n`;
      md += `| Fase | ${f.fase || 'N/A'} |\n`;
      if (f.cve) md += `| CVE | ${escapeHtml(f.cve)} |\n`;
      md += `\n**Descrição:** ${escapeHtml(f.descricao || 'Sem descrição')}\n\n`;
      if (f.remediacao) md += `**Remediação:** ${escapeHtml(f.remediacao)}\n\n`;
    });
  });

  md += `---\n\n*Relatório gerado automaticamente pelo BritofScan v1.0.0*\n`;

  return {
    conteudo: md,
    contentType: 'text/markdown',
    extensao: 'md',
  };
}

// ── HTML ───────────────────────────────────────────────────────────────────
function gerarHTML(scan) {
  const { meta, resumo, correlacoes, findings } = extrairDados(scan);
  const data = new Date(meta.inicio).toLocaleString('pt-PT');

  const badgeHTML = (sev, score) => {
    const info = SEVERIDADE[sev] || SEVERIDADE.INFO;
    return `<span class="badge" style="background:${info.cor}20;color:${info.cor};border:1px solid ${info.cor}40">${escapeHtml(sev)} · ${score}</span>`;
  };

  const findingsHTML = findings.map(f => `
    <div class="finding sev-${escapeHtml((f.severidade || 'info').toLowerCase())}">
      <div class="finding-header">
        <span class="finding-title">${escapeHtml(f.titulo)}</span>
        ${badgeHTML(f.severidade, f.score)}
      </div>
      <div class="finding-body">
        <div class="finding-meta">
          ${f.ferramenta ? `<span>🔧 ${escapeHtml(f.ferramenta)}</span>` : ''}
          ${f.fase ? `<span>📍 Fase ${escapeHtml(f.fase)}</span>` : ''}
          ${f.cve ? `<span>🔗 ${escapeHtml(f.cve)}</span>` : ''}
          <span>📐 ${escapeHtml(classificarOrigemScore(f))}</span>
        </div>
        ${f.vetorCVSS ? `<p class="finding-desc"><code>${escapeHtml(f.vetorCVSS)}</code></p>` : ''}
        ${f.descricao ? `<p class="finding-desc">${escapeHtml(f.descricao)}</p>` : ''}
        ${f.remediacao ? `<div class="remediacao"><strong>Remediação:</strong> ${escapeHtml(f.remediacao)}</div>` : ''}
      </div>
    </div>`).join('');

  const correlacoesHTML = correlacoes.map(c => `
    <div class="correlacao">
      <div class="correlacao-header">
        <span>⚡ ${escapeHtml(c.titulo)}</span>
        ${badgeHTML(c.severidade, c.score)}
      </div>
      <p>${escapeHtml(c.descricao)}</p>
      <p style="font-size:0.8rem;color:#94a3b8;">Heurística de correlação — sem vetor CVSS individual.</p>
      <div class="remediacao"><strong>Remediação:</strong> ${escapeHtml(c.remediacao)}</div>
    </div>`).join('');

  const html = `<!DOCTYPE html>
<html lang="pt">
<head>
<meta charset="UTF-8">
<title>Relatório BritofScan — ${escapeHtml(meta.alvo)}</title>
<style>
  body { font-family: -apple-system, sans-serif; background:#0d1424; color:#e2e8f0; margin:0; padding:2rem; }
  .container { max-width: 900px; margin: 0 auto; }
  h1 { color:#3b82f6; }
  .meta { color:#94a3b8; margin-bottom: 2rem; }
  .metrics { display:grid; grid-template-columns: repeat(4,1fr); gap:1rem; margin-bottom:2rem; }
  .metric-card { background:#141e32; border-radius:12px; padding:1rem; text-align:center; }
  .metric-num { font-size:1.8rem; font-weight:bold; }
  .badge { padding:2px 10px; border-radius:6px; font-size:0.8rem; font-weight:bold; }
  .finding, .correlacao { background:#141e32; border-radius:12px; padding:1rem 1.5rem; margin-bottom:1rem; }
  .finding-header, .correlacao-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem; }
  .finding-title { font-weight:bold; }
  .finding-meta { display:flex; gap:1rem; font-size:0.85rem; color:#94a3b8; margin-bottom:0.5rem; }
  .finding-desc { color:#cbd5e1; }
  .remediacao { background:#0d2818; border-left:3px solid #10b981; padding:0.5rem 1rem; margin-top:0.5rem; border-radius:6px; }
</style>
</head>
<body>
<div class="container">
  <h1>BritofScan — Relatório de Penetration Testing</h1>
  <div class="meta">Alvo: <strong>${escapeHtml(meta.alvo)}</strong> | Modo: ${escapeHtml(meta.modo)} | Data: ${escapeHtml(data)}</div>

  <div class="metrics">
    <div class="metric-card"><div class="metric-num">${escapeHtml(resumo.scoreGlobal)}</div>Score Global</div>
    <div class="metric-card"><div class="metric-num">${escapeHtml(resumo.criticos)}</div>Críticos</div>
    <div class="metric-card"><div class="metric-num">${escapeHtml(resumo.altos)}</div>Altos</div>
    <div class="metric-card"><div class="metric-num">${escapeHtml(resumo.total)}</div>Total Findings</div>
  </div>

  ${correlacoes.length > 0 ? `<h2>⚡ Riscos Compostos</h2>${correlacoesHTML}` : ''}

  <h2> Findings</h2>
  ${findingsHTML || '<p>Nenhum finding registado.</p>'}

  <p style="color:#64748b;font-size:0.8rem;margin-top:2rem;">Relatório gerado automaticamente pelo BritofScan v1.0.0</p>
</div>
</body>
</html>`;

  return {
    conteudo: html,
    contentType: 'text/html',
    extensao: 'html',
  };
}

// ── Despachante ────────────────────────────────────────────────────────────
/**
 * Gera relatório no formato solicitado.
 * @param {Object} scan - Dados completos do scan
 * @param {string} formato - 'json' | 'markdown' | 'html'
 * @returns {{ conteudo: string, contentType: string, extensao: string }}
 */
function gerarRelatorio(scan, formato = 'json') {
  switch (formato) {
    case 'markdown': return gerarMarkdown(scan);
    case 'html':     return gerarHTML(scan);
    default:         return gerarJSON(scan);
  }
}

module.exports = { gerarRelatorio, escapeHtml, classificarOrigemScore };