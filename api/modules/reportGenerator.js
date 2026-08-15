// Gerador de relatórios BritofScan — JSON, Markdown e HTML
const { SEVERIDADE } = require('./scoring');

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

// ─── JSON ─────────────────────────────────────────────────────────────────────

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
    })),
    findings: (scan.findings || []).map(f => ({
      titulo: f.titulo, severidade: f.severidade, score: f.score,
      fase: f.fase, ferramenta: f.ferramenta, descricao: f.descricao,
      remediacao: f.remediacao, cve: f.cve || null,
    })),
  };

  return {
    conteudo: JSON.stringify(dados, null, 2),
    contentType: 'application/json',
    extensao: 'json',
  };
}

// ─── MARKDOWN ─────────────────────────────────────────────────────────────────

function gerarMarkdown(scan) {
  const { meta, resumo, correlacoes, findings } = extrairDados(scan);
  const data = new Date(meta.inicio).toLocaleString('pt-PT');

  let md = `# 🔍 BritofScan — Relatório de Penetration Testing\n\n`;
  md += `> **Alvo:** \`${meta.alvo}\` | **Modo:** ${meta.modo} | **Data:** ${data}\n\n`;
  md += `---\n\n## 📊 Resumo Executivo\n\n`;
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
    correlacoes.forEach(c => {
      const emoji = SEVERIDADE[c.severidade]?.emoji || '⚪';
      md += `### ${emoji} ${c.titulo} — Score: ${c.score}\n\n`;
      md += `**Severidade:** ${c.severidade} | **Tipo:** Correlação Automática\n\n`;
      md += `**Descrição:** ${c.descricao}\n\n`;
      md += `**Remediação:** ${c.remediacao}\n\n`;
    });
  }

  const grupos = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  grupos.forEach(sev => {
    const grupo = findings.filter(f => f.severidade === sev);
    if (grupo.length === 0) return;
    const emoji = SEVERIDADE[sev]?.emoji || '⚪';
    md += `---\n\n## ${emoji} Findings ${sev} (${grupo.length})\n\n`;
    grupo.forEach(f => {
      md += `### ${f.titulo}\n\n`;
      md += `| Campo | Valor |\n|-------|-------|\n`;
      md += `| Score | ${f.score} |\n`;
      md += `| Ferramenta | ${f.ferramenta || 'N/A'} |\n`;
      md += `| Fase | ${f.fase || 'N/A'} |\n`;
      if (f.cve) md += `| CVE | ${f.cve} |\n`;
      md += `\n**Descrição:** ${f.descricao || 'Sem descrição'}\n\n`;
      if (f.remediacao) md += `**✅ Remediação:** ${f.remediacao}\n\n`;
    });
  });

  md += `---\n\n*Relatório gerado automaticamente pelo BritofScan v1.0.0*\n`;

  return { conteudo: md, contentType: 'text/markdown', extensao: 'md' };
}

// ─── HTML ──────────────────────────────────────────────────────────────────────

function gerarHTML(scan) {
  const { meta, resumo, correlacoes, findings } = extrairDados(scan);
  const data = new Date(meta.inicio).toLocaleString('pt-PT');

  const badgeHTML = (sev, score) => {
    const info = SEVERIDADE[sev] || SEVERIDADE.INFO;
    return `<span class="badge" style="background:${info.cor}20;color:${info.cor};border:1px solid ${info.cor}40">${info.emoji} ${sev} ${score}</span>`;
  };

  const findingsHTML = findings.map(f => `
    <div class="finding sev-${f.severidade.toLowerCase()}">
      <div class="finding-header">
        <span class="finding-title">${f.titulo}</span>
        ${badgeHTML(f.severidade, f.score)}
      </div>
      <div class="finding-body">
        <div class="finding-meta">
          ${f.ferramenta ? `<span>🔧 ${f.ferramenta}</span>` : ''}
          ${f.fase ? `<span>📍 Fase ${f.fase}</span>` : ''}
          ${f.cve ? `<span>🔗 ${f.cve}</span>` : ''}
        </div>
        ${f.descricao ? `<p class="finding-desc">${f.descricao}</p>` : ''}
        ${f.remediacao ? `<div class="remediacao"><strong>✅ Remediação:</strong> ${f.remediacao}</div>` : ''}
      </div>
    </div>`).join('');

  const correlacoesHTML = correlacoes.map(c => `
    <div class="correlacao">
      <div class="correlacao-header">
        <span>⚡ ${c.titulo}</span>
        ${badgeHTML(c.severidade, c.score)}
      </div>
      <p>${c.descricao}</p>
      <div class="remediacao"><strong>✅ Remediação:</strong> ${c.remediacao}</div>
    </div>`).join('');

  const html = `<!DOCTYPE html>
<html lang="pt">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BritofScan — Relatório ${meta.alvo}</title>
<style>
  :root {
    --bg: #0a0e1a; --surface: #111827; --surface2: #1a2035;
    --border: #2a3550; --text: #e2e8f0; --muted: #64748b;
    --accent: #3b82f6; --critical: #ff3b30; --high: #ff9500;
    --medium: #ffcc00; --low: #34c759; --info: #5ac8fa;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--text); font-family:'Segoe UI',sans-serif; padding:2rem; }
  .container { max-width:1000px; margin:0 auto; }
  h1 { font-size:2rem; color:var(--accent); margin-bottom:.5rem; }
  .subtitle { color:var(--muted); margin-bottom:2rem; font-size:.9rem; }
  .grid-4 { display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin:1.5rem 0; }
  .metric { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:1.2rem; text-align:center; }
  .metric-value { font-size:2rem; font-weight:700; }
  .metric-label { color:var(--muted); font-size:.8rem; margin-top:.3rem; }
  .section { margin:2rem 0; }
  .section h2 { font-size:1.2rem; border-left:3px solid var(--accent); padding-left:1rem; margin-bottom:1rem; }
  .correlacao { background:var(--surface); border:1px solid #ff3b3040; border-radius:12px; padding:1.2rem; margin-bottom:1rem; }
  .correlacao-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:.8rem; font-weight:600; }
  .finding { background:var(--surface); border:1px solid var(--border); border-radius:8px; margin-bottom:.8rem; overflow:hidden; }
  .finding-header { display:flex; justify-content:space-between; align-items:center; padding:.8rem 1rem; background:var(--surface2); }
  .finding-title { font-weight:600; }
  .finding-body { padding:1rem; }
  .finding-meta { display:flex; gap:1rem; color:var(--muted); font-size:.85rem; margin-bottom:.6rem; }
  .finding-desc { color:var(--muted); font-size:.9rem; margin-bottom:.6rem; }
  .remediacao { background:#34c75910; border-left:3px solid var(--low); padding:.6rem .8rem; border-radius:0 6px 6px 0; font-size:.85rem; }
  .badge { padding:.25rem .6rem; border-radius:6px; font-size:.75rem; font-weight:700; }
  footer { text-align:center; color:var(--muted); margin-top:3rem; font-size:.8rem; }
</style>
</head>
<body>
<div class="container">
  <h1>🔍 BritofScan</h1>
  <p class="subtitle">Relatório de Penetration Testing — <strong>${meta.alvo}</strong> — ${data} — Modo: ${meta.modo}</p>

  <div class="grid-4">
    <div class="metric"><div class="metric-value" style="color:var(--accent)">${resumo.scoreGlobal}</div><div class="metric-label">Score Global</div></div>
    <div class="metric"><div class="metric-value" style="color:var(--critical)">${resumo.criticos}</div><div class="metric-label">🔴 Críticos</div></div>
    <div class="metric"><div class="metric-value" style="color:var(--high)">${resumo.altos}</div><div class="metric-label">🟠 Altos</div></div>
    <div class="metric"><div class="metric-value" style="color:var(--text)">${resumo.total}</div><div class="metric-label">Total Findings</div></div>
  </div>

  ${correlacoes.length > 0 ? `<div class="section"><h2>⚡ Riscos Compostos</h2>${correlacoesHTML}</div>` : ''}

  <div class="section"><h2>📋 Todos os Findings</h2>${findingsHTML}</div>

  <footer>Gerado automaticamente pelo BritofScan v1.0.0 — Plataforma Educacional de Penetration Testing</footer>
</div>
</body>
</html>`;

  return { conteudo: html, contentType: 'text/html', extensao: 'html' };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

module.exports = { gerarRelatorio };
