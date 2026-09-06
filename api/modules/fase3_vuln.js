// fase3_vuln.js - Analise de Vulnerabilidades
const { executarComandoSeguro } = require('./utils');
const { VETORES_HEADER, VETORES_COOKIE, VETORES_METODO } = require('./scoringCVSS');
const VETOR_INFORMATIVO = 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';

// ── SECURITY_HEADERS ──────────────────────────────────────────────────────────
const SECURITY_HEADERS = [
  { nome: 'strict-transport-security', titulo: 'HSTS',               impacto: 6, rem: 'Strict-Transport-Security: max-age=31536000; includeSubDomains' },
  { nome: 'content-security-policy',   titulo: 'CSP',                impacto: 7, rem: "Content-Security-Policy: default-src 'self'" },
  { nome: 'x-frame-options',           titulo: 'X-Frame-Options',    impacto: 5, rem: 'X-Frame-Options: DENY' },
  { nome: 'x-content-type-options',    titulo: 'X-Content-Type',     impacto: 4, rem: 'X-Content-Type-Options: nosniff' },
  { nome: 'referrer-policy',           titulo: 'Referrer-Policy',    impacto: 3, rem: 'Referrer-Policy: strict-origin-when-cross-origin' },
  { nome: 'permissions-policy',        titulo: 'Permissions-Policy', impacto: 3, rem: 'Definir Permissions-Policy.' },
  { nome: 'x-xss-protection',          titulo: 'X-XSS-Protection',   impacto: 4, rem: 'X-XSS-Protection: 1; mode=block' },
];

// ── HTTP-METHODS: configuração ───────────────────────────────────────────────
//    haver três categorias explícitas: aceite, bloqueado, inconclusivo.
const TESTAR_METODOS_MODIFICADORES = false; // true APENAS em laboratório autorizado e descartável

const METODOS_SEM_RISCO_ESCRITA = ['TRACE'];
const METODOS_MODIFICADORES     = ['PUT', 'DELETE', 'PATCH'];
const CODIGOS_BLOQUEADO         = [403, 405, 501];
const CODIGOS_INCONCLUSIVOS     = [401, 404, 411, 500, 502, 503];

async function executarFase3(targetUrl, emitir, progresso, adicionarFinding) {
  emitir('[3/4] VULNERABILIDADES', 'phase', 3);

  // ── HEADERS + COOKIES ─────────────────────────────────────────────────────────
  progresso('Headers de seguranca', 1, 4, '#ffcc00');
  emitir('[HEADERS] a auditar headers de seguranca...', 'info', 3);

  let respostaRaw = '';
  await executarComandoSeguro('curl', [
    '-s', '-D', '-', '-o', '/dev/null',
    '--max-time', '10', '--connect-timeout', '5',
    '-L', targetUrl,
  ], l => { respostaRaw += l.toLowerCase() + '\n'; }, 12000);

  // Parsear headers para objecto chave:valor
  const headersObj = {};
  respostaRaw.split('\n').forEach(linha => {
    const idx = linha.indexOf(':');
    if (idx > 0) {
      const chave = linha.substring(0, idx).trim();
      const valor = linha.substring(idx + 1).trim();
      headersObj[chave] = valor;
    }
  });

  // Extrair cookies da mesma resposta
  const cookieLines = respostaRaw.split('\n')
    .filter(l => l.startsWith('set-cookie:'))
    .map(l => l.replace('set-cookie:', '').trim());

  if (Object.keys(headersObj).length > 0) {
    emitir(`[HEADERS] HTTP ${headersObj['http/1.1'] || '200'} obtido`, 'info', 3);
    SECURITY_HEADERS.forEach(h => {
      if (!headersObj[h.nome]) {
        emitir(`[HEADERS] em falta: ${h.titulo}`, 'warning', 3);
        // X-XSS-Protection usa vetor informativo (score 0) - descontinuado,
        // sem risco real associado. Os restantes usam o vetor CVSS real
        // do mapa central (scoringCVSS.js).
        const vetor = h.titulo === 'X-XSS-Protection'
          ? VETOR_INFORMATIVO
          : (VETORES_HEADER[h.titulo] || VETOR_INFORMATIVO);
        adicionarFinding(
          `Header em falta: ${h.titulo}`,
          `Header '${h.nome}' ausente.`,
          'header-audit', 3, h.impacto, 9, h.rem, null, false,
          vetor
        );
      } else {
        emitir(`[HEADERS] presente: ${h.titulo}`, 'success', 3);
      }
    });
  } else {
    emitir('[HEADERS] nao foi possivel ligar - headers nao verificados', 'warning', 3);
  }

  // ── COOKIES ──────────────────────────────────────────────────────────────────
  progresso('Cookies', 2, 4, '#ffcc00');
  emitir('[COOKIES] a analisar cookies...', 'info', 3);

  if (!cookieLines.length) {
    emitir('[COOKIES] nenhum cookie detetado', 'output', 3);
  } else {
    cookieLines.forEach(cookie => {
      const nome = cookie.split('=')[0].trim();
      const cl   = cookie.toLowerCase();
      emitir(`[COOKIES] cookie: ${nome}`, 'output', 3);
      if (!cl.includes('httponly'))
        adicionarFinding(`Cookie sem HttpOnly: ${nome}`,
          `${nome} vulneravel a roubo via XSS.`,
          'cookie-audit', 3, 5, 8, 'Adicionar flag HttpOnly.', null, false,
          VETORES_COOKIE.httponly);
      if (!cl.includes('secure') && targetUrl.startsWith('https'))
        adicionarFinding(`Cookie sem Secure: ${nome}`,
          `${nome} pode ser enviado via HTTP.`,
          'cookie-audit', 3, 4, 8, 'Adicionar flag Secure.', null, false,
          VETORES_COOKIE.secure);
      if (!cl.includes('samesite'))
        adicionarFinding(`Cookie sem SameSite: ${nome}`,
          `${nome} vulneravel a CSRF.`,
          'cookie-audit', 3, 4, 8, 'Adicionar SameSite=Strict.', null, false,
          VETORES_COOKIE.samesite);
    });
  }

  // ── METODOS HTTP (corrigido) ───────────────────────────────────────────────────
  progresso('Metodos HTTP', 3, 4, '#ffcc00');
  emitir('[METODOS] a verificar metodos HTTP perigosos...', 'info', 3);

  const metodosATestar = TESTAR_METODOS_MODIFICADORES
    ? [...METODOS_SEM_RISCO_ESCRITA, ...METODOS_MODIFICADORES]
    : METODOS_SEM_RISCO_ESCRITA;

  if (!TESTAR_METODOS_MODIFICADORES) {
    emitir(
      '[METODOS] Métodos modificadores (PUT/DELETE/PATCH) desativados por defeito ' +
      '— ativar apenas contra alvos de laboratório autorizados e descartáveis.',
      'warning', 3
    );
  }

  const resultadosMetodos = [];

  for (const metodo of metodosATestar) {
    let status = 0;
    let falhaLigacao = false;

    try {
      await executarComandoSeguro('curl', [
        '-s', '-o', '/dev/null', '-w', '%{http_code}',
        '--max-time', '8', '--connect-timeout', '5',
        '-X', metodo, targetUrl,
      ], l => {
        const code = parseInt(l.trim());
        if (!isNaN(code) && code > 0) status = code;
      }, 10000);
    } catch (e) {
      falhaLigacao = true;
    }

    let classificacao;
    if (falhaLigacao || status === 0) {
      classificacao = 'inconclusivo';
      emitir(`[METODOS] ${metodo}: inconclusivo (timeout/falha de ligação — não é resposta do servidor)`, 'warning', 3);
    } else if (CODIGOS_BLOQUEADO.includes(status)) {
      classificacao = 'bloqueado';
      emitir(`[METODOS] ${metodo} bloqueado (HTTP ${status})`, 'success', 3);
    } else if (CODIGOS_INCONCLUSIVOS.includes(status)) {
      classificacao = 'inconclusivo';
      emitir(`[METODOS] ${metodo}: inconclusivo (HTTP ${status} não confirma aceitação nem bloqueio)`, 'warning', 3);
    } else {
      classificacao = 'aceite';
      emitir(`[METODOS] ${metodo} aceite (HTTP ${status})`, 'critical', 3);
    }

    resultadosMetodos.push({ metodo, status: status || 'sem resposta', classificacao });
  }

  // Findings estruturados: só para resultados 'aceite' — inconclusivos
  // nunca geram finding de vulnerabilidade (evita falsos positivos).
  resultadosMetodos
    .filter(r => r.classificacao === 'aceite')
    .forEach(r => {
      if (r.metodo === 'TRACE') {
        adicionarFinding(
          'TRACE ativo', `Método TRACE aceite pelo servidor (HTTP ${r.status}). Risco de Cross-Site Tracing (XST).`,
          'http-methods', 3, 6, 8, 'Desativar TRACE no servidor.', null, false,
          VETORES_METODO.TRACE
        );
      } else {
        adicionarFinding(
          `Método ${r.metodo} disponível`, `${r.metodo} aceite pelo servidor (HTTP ${r.status}), sem confirmação de autenticação.`,
          'http-methods', 3, 7, 7, `Restringir ${r.metodo} a utilizadores autenticados ou desativar.`, null, false,
          VETORES_METODO[r.metodo]
        );
      }
    });

  emitir(
    `[METODOS] Resumo: ${resultadosMetodos.filter(r => r.classificacao === 'aceite').length} aceite(s), ` +
    `${resultadosMetodos.filter(r => r.classificacao === 'bloqueado').length} bloqueado(s), ` +
    `${resultadosMetodos.filter(r => r.classificacao === 'inconclusivo').length} inconclusivo(s)`,
    'info', 3
  );

  // ── CVE ───────────────────────────────────────────────────────────────────────
  progresso('Correlacao CVE', 4, 4, '#ffcc00');
  emitir('[CVE] a correlacionar com base de dados CVE...', 'info', 3);
}

module.exports = { executarFase3 };