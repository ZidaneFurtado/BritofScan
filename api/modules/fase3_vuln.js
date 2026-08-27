// fase3_vuln.js - Analise de Vulnerabilidades
const { executarComandoSeguro } = require('./utils');

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
        adicionarFinding(
          `Header em falta: ${h.titulo}`,
          `Header '${h.nome}' ausente.`,
          'header-audit', 3, h.impacto, 9, h.rem, null, false
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
          'cookie-audit', 3, 5, 8, 'Adicionar flag HttpOnly.', null, false);
      if (!cl.includes('secure') && targetUrl.startsWith('https'))
        adicionarFinding(`Cookie sem Secure: ${nome}`,
          `${nome} pode ser enviado via HTTP.`,
          'cookie-audit', 3, 4, 8, 'Adicionar flag Secure.', null, false);
      if (!cl.includes('samesite'))
        adicionarFinding(`Cookie sem SameSite: ${nome}`,
          `${nome} vulneravel a CSRF.`,
          'cookie-audit', 3, 4, 8, 'Adicionar SameSite=Strict.', null, false);
    });
  }

  // ── METODOS HTTP ──────────────────────────────────────────────────────────────
  // Usar curl — httpMethod Node.js falha com IIS/AWS
  // Bloqueados: 405 Not Allowed, 501 Not Implemented, 411 Length Required,
  //             403 Forbidden — servidor recusou mas metodo nao esta activo
  progresso('Metodos HTTP', 3, 4, '#ffcc00');
  emitir('[METODOS] a verificar metodos HTTP perigosos...', 'info', 3);
  const metodosTemp = [];

  for (const metodo of ['PUT', 'DELETE', 'TRACE', 'PATCH']) {
    let status = 0;
    await executarComandoSeguro('curl', [
      '-s', '-o', '/dev/null', '-w', '%{http_code}',
      '--max-time', '8', '--connect-timeout', '5',
      '-X', metodo, targetUrl,
    ], l => {
      const code = parseInt(l.trim());
      if (!isNaN(code) && code > 0) status = code;
    }, 10000);

    if (status && ![0, 403, 405, 501, 411].includes(status)) {
      emitir(`[METODOS] ${metodo} aceite (HTTP ${status})`, 'warning', 3);
      if (metodo === 'TRACE')
        metodosTemp.push({ t: 'TRACE ativo', d: 'Risco de Cross-Site Tracing (XST).', r: 'Desativar TRACE no servidor.', i: 6 });
      else if (['PUT', 'DELETE'].includes(metodo))
        metodosTemp.push({ t: `Metodo ${metodo} disponivel`, d: `${metodo} acessivel sem autenticacao.`, r: `Restringir ${metodo}.`, i: 7 });
    } else {
      emitir(`[METODOS] ${metodo} bloqueado`, 'success', 3);
    }
  }

  metodosTemp.forEach(f =>
    adicionarFinding(f.t, f.d, 'http-methods', 3, f.i, 7, f.r, null, false));

  // ── CVE ───────────────────────────────────────────────────────────────────────
  progresso('Correlacao CVE', 4, 4, '#ffcc00');
  emitir('[CVE] a correlacionar com base de dados CVE...', 'info', 3);
}

module.exports = { executarFase3 };