// Motor de scoring de vulnerabilidades BritofScan
//

const scoringCVSS = require('./scoringCVSS');

// Mantido para compatibilidade com o frontend (cores/emojis dos badges de
// severidade) e com o gerador de relatorios, que ja esperam estas 5
// categorias e a chave INFO especificamente (nao NONE).
const SEVERIDADE = {
  CRITICAL: { min: 9.0, cor: '#ff3b30', emoji: '🔴' },
  HIGH:     { min: 7.0, cor: '#ff9500', emoji: '🟠' },
  MEDIUM:   { min: 4.0, cor: '#ffcc00', emoji: '🟡' },
  LOW:      { min: 0.1, cor: '#34c759', emoji: '🟢' },
  INFO:     { min: 0.0, cor: '#5ac8fa', emoji: '🔵' },
};

/**
 * Calcula o score de uma vulnerabilidade.
 *
 * Uso preferencial (novo): passar um vetor CVSS v3.1 como primeiro
 * argumento, ex: calcularScore('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').
 *
 * Uso legado (fallback, DEPRECATED): passar impact e confidence como
 * numeros 0-10, ex: calcularScore(8, 9). Mantido apenas para findings
 * cujo ponto de chamada ainda nao foi migrado para um vetor CVSS real -
 * nao deve ser usado em novo codigo.
 *
 * @param {number|string} impactOuVetor - vetor CVSS (string) ou impact (number)
 * @param {number} [confidence] - so usado no modo legado
 * @returns {number} score entre 0 e 10
 */
function calcularScore(impactOuVetor, confidence) {
  if (typeof impactOuVetor === 'string' && impactOuVetor.includes('AV:')) {
    return scoringCVSS.calcularCVSS(impactOuVetor).score;
  }
  // Modo legado (deprecated) - heuristica pre-CVSS, mantida so como rede
  // de seguranca para findings sem vetor atribuido.
  const impact = impactOuVetor;
  return Math.round(((impact * 0.6) + (confidence * 0.4)) * 10) / 10;
}

/**
 * Classifica a severidade com base no score, usando os limiares oficiais
 * CVSS v3.1 (Critical >=9.0, High >=7.0, Medium >=4.0, Low >0, None =0).
 * O valor NONE do CVSS e traduzido para INFO, por compatibilidade com o
 * resto da plataforma (frontend e gerador de relatorios).
 * @param {number} score
 * @returns {string} CRITICAL | HIGH | MEDIUM | LOW | INFO
 */
function classificarSeveridade(score) {
  const sev = scoringCVSS.classificarCVSS(score);
  return sev === 'NONE' ? 'INFO' : sev;
}

/**
 * Calcula o score e a severidade de um finding a partir de um vetor CVSS,
 * devolvendo tambem o proprio vetor para ser guardado no finding (para
 * auditoria/transparencia do calculo).
 * @param {string} vetor - vetor CVSS v3.1
 * @returns {{ score: number, severidade: string, vetorCVSS: string }}
 */
function calcularScoreCVSS(vetor) {
  const { score } = scoringCVSS.calcularCVSS(vetor);
  return { score, severidade: classificarSeveridade(score), vetorCVSS: vetor };
}

/**
 * Analisa uma lista de findings e aplica correlações automáticas.
 * Deteta 8 padrões de risco compostos.
 * @param {Array} findings
 * @returns {{ findings: Array, correlacoes: Array, topRiscos: Array, resumo: Object }}
 */
function analisarFindings(findings) {
  // Remover duplicados pelo título
  const vistos = new Set();
  const unicos = findings.filter(f => {
    const chave = f.titulo?.toLowerCase();
    if (vistos.has(chave)) return false;
    vistos.add(chave);
    return true;
  });

  // Calcular score para cada finding. Prioriza um score ja calculado
  // (via vetor CVSS, atribuido em adicionarFinding); só recorre ao modo
  // legado (impact/confidence) como rede de seguranca para findings sem
  // vetor CVSS atribuido.
  const comScore = unicos.map(f => ({
    ...f,
    score: f.score ?? calcularScore(f.impact ?? 5, f.confidence ?? 5),
    severidade: f.severidade || classificarSeveridade(f.score ?? calcularScore(f.impact ?? 5, f.confidence ?? 5)),
  }));

  // Ordenar por score descendente
  comScore.sort((a, b) => b.score - a.score);

  // Detetar correlações automáticas (8 padrões)
  const correlacoes = detectarCorrelacoes(comScore);

  // Calcular resumo
  const resumo = {
    total: comScore.length,
    criticos: comScore.filter(f => f.severidade === 'CRITICAL').length,
    altos: comScore.filter(f => f.severidade === 'HIGH').length,
    medios: comScore.filter(f => f.severidade === 'MEDIUM').length,
    baixos: comScore.filter(f => f.severidade === 'LOW').length,
    info: comScore.filter(f => f.severidade === 'INFO').length,
    scoreGlobal: comScore.length > 0
      ? Math.round((comScore.reduce((s, f) => s + f.score, 0) / comScore.length) * 10) / 10
      : 0,
  };

  // Top 5 riscos mais críticos (correlações primeiro, depois findings)
  const topRiscos = [
    ...correlacoes.slice(0, 3),
    ...comScore.slice(0, 5 - Math.min(correlacoes.length, 3)),
  ].slice(0, 5);

  return { findings: comScore, correlacoes, topRiscos, resumo };
}

/**
 * Deteta padrões de correlação entre findings.
 * Retorna riscos compostos de alta severidade.
 *
 * NOTA: os scores das correlações mantêm-se como valores fixos atribuídos
 * por padrão (não recalculados via CVSS), uma vez que representam um
 * julgamento de risco composto sobre a COMBINAÇÃO de vulnerabilidades, não
 * uma vulnerabilidade individual passível de um único vetor CVSS. Esta
 * distinção é documentada explicitamente no relatório.
 */
function detectarCorrelacoes(findings) {
  const titulos = findings.map(f => f.titulo?.toLowerCase() || '');
  const correlacoes = [];

  const temTitulo = (...palavras) =>
    palavras.some(p => titulos.some(t => t.includes(p.toLowerCase())));

  // Padrão 1: Painel de login + SQLi → Auth Bypass + DB Dump
  if (temTitulo('login', 'admin') && temTitulo('sql', 'sqli', 'injection')) {
    correlacoes.push({
      titulo: 'Auth Bypass + Extração de Base de Dados',
      descricao: 'Painel de login exposto combinado com SQLi permite contornar autenticação e extrair toda a base de dados.',
      score: 9.8, severidade: 'CRITICAL', tipo: 'correlacao',
      remediacao: 'Implementar prepared statements, WAF e autenticação multi-fator imediatamente.',
    });
  }

  // Padrão 2: Porta de BD exposta
  if (temTitulo('3306', 'mysql', '5432', 'postgres', '27017', 'mongo', '6379', 'redis')) {
    correlacoes.push({
      titulo: 'Base de Dados Exposta à Internet',
      descricao: 'Porto de base de dados acessível publicamente. Risco extremo de acesso não autorizado e exfiltração de dados.',
      score: 9.6, severidade: 'CRITICAL', tipo: 'correlacao',
      remediacao: 'Fechar imediatamente portos de BD em firewall. Usar VPN ou túnel SSH para acesso.',
    });
  }

  // Padrão 3: .env exposto + sem CSP
  if (temTitulo('.env', 'environment') && temTitulo('csp', 'content-security')) {
    correlacoes.push({
      titulo: 'Credenciais Expostas + Sem Proteção XSS',
      descricao: 'Ficheiro .env acessível expõe credenciais. A ausência de CSP permite execução de scripts arbitrários.',
      score: 9.4, severidade: 'CRITICAL', tipo: 'correlacao',
      remediacao: 'Remover .env do webroot, configurar CSP restritiva e rotacionar todas as credenciais expostas.',
    });
  }

  // Padrão 4: Git exposto
  if (temTitulo('.git', 'git/head', 'git exposed')) {
    correlacoes.push({
      titulo: 'Repositório Git Exposto',
      descricao: 'Directório .git acessível permite reconstrução do código fonte e histórico de commits com credenciais.',
      score: 8.8, severidade: 'HIGH', tipo: 'correlacao',
      remediacao: 'Bloquear acesso ao .git via regras de servidor web. Rotacionar todas as credenciais encontradas no histórico.',
    });
  }

  // Padrão 5: RCE via upload + sem autenticação
  if (temTitulo('upload', 'file upload') && temTitulo('sem autenticação', 'unauthenticated', 'open')) {
    correlacoes.push({
      titulo: 'Upload Não Autenticado → RCE Potencial',
      descricao: 'Endpoint de upload de ficheiros sem autenticação. Pode permitir execução remota de código via webshell.',
      score: 9.5, severidade: 'CRITICAL', tipo: 'correlacao',
      remediacao: 'Exigir autenticação em uploads, validar tipos de ficheiro, usar armazenamento isolado.',
    });
  }

  // Padrão 6: SSRF + serviços internos
  if (temTitulo('ssrf', 'server-side request')) {
    correlacoes.push({
      titulo: 'SSRF com Acesso a Rede Interna',
      descricao: 'Vulnerabilidade SSRF pode expor serviços internos, metadados cloud (AWS/GCP) e credenciais de instância.',
      score: 8.5, severidade: 'HIGH', tipo: 'correlacao',
      remediacao: 'Validar e restringir URLs destino, bloquear intervalos de IP internos e metadados cloud.',
    });
  }

  // Padrão 7: Múltiplos headers em falta
  const headersEmFalta = findings.filter(f =>
    f.titulo?.toLowerCase().includes('header') && f.severidade !== 'INFO'
  ).length;
  if (headersEmFalta >= 3) {
    correlacoes.push({
      titulo: `${headersEmFalta} Headers de Segurança em Falta`,
      descricao: 'Múltiplos headers de segurança ausentes aumentam significativamente a superfície de ataque (XSS, Clickjacking, MIME sniffing).',
      score: 6.5, severidade: 'HIGH', tipo: 'correlacao',
      remediacao: 'Configurar HSTS, CSP, X-Frame-Options, X-Content-Type-Options e Referrer-Policy no servidor web.',
    });
  }

  // Padrão 8: SSL fraco + dados sensíveis
  if (temTitulo('ssl', 'tls', 'certificado') && temTitulo('login', 'password', 'formulário')) {
    correlacoes.push({
      titulo: 'SSL/TLS Fraco com Transmissão de Credenciais',
      descricao: 'Protocolo SSL/TLS desatualizado ou fraco protege formulários com credenciais. Vulnerável a ataques MITM.',
      score: 8.2, severidade: 'CRITICAL', tipo: 'correlacao',
      remediacao: 'Atualizar para TLS 1.3, desativar TLS 1.0/1.1 e RC4. Renovar certificado se necessário.',
    });
  }

  return correlacoes.sort((a, b) => b.score - a.score);
}

module.exports = {
  calcularScore, classificarSeveridade, analisarFindings, SEVERIDADE,
  calcularScoreCVSS,
};