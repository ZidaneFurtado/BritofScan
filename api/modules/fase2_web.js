// fase2_web.js - Analise Web
const { ferramentaInstalada, executarComandoSeguro, httpGet, validarAlvo } = require('./utils');
const {
  VETORES_FICHEIRO, VETOR_WAF_AUSENTE, VETOR_HTTPS_NAO_FORCADO,
  VETOR_TLS_DESATUALIZADO, VETOR_NIKTO_GENERICO, VETORES_NUCLEI_BANDA,
} = require('./scoringCVSS');

const VETOR_INFORMATIVO = 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';
const VETOR_CERT_EXPIRANDO = 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L';

// ── WAF_ASSINATURAS ───────────────────────────────────────────────────────────
const WAF_ASSINATURAS = {
  Cloudflare:  ['cf-ray', 'cloudflare', 'cf-cache-status', 'cf-request-id', '__cfduid', 'cf-connecting-ip'],
  Akamai:      ['akamai', 'x-akamai-transformed', 'x-check-cacheable', 'x-akamai-request-id'],
  Imperva:     ['incapsula', 'x-iinfo', 'x-cdn', 'visid_incap', '_incap_ses'],
  Sucuri:      ['x-sucuri-id', 'x-sucuri-cache', 'sucuri-clientdata'],
  ModSecurity: ['mod_security', 'modsecurity', 'x-modsecurity'],
  F5BigIP:     ['x-waf-status', 'x-wa-info', 'bigipserver'],
  Barracuda:   ['barra_counter_session', 'bni__zenworkssession'],
  Fortinet:    ['fortiwafsid', 'cookiesession1'],
  AWSShield:   ['x-amzn-requestid', 'x-amz-cf-id'],
};

const WAF_PROBE = '/?id=1%27%20OR%20%271%27%3D%271';

// ── FICHEIROS_SENSIVEIS ───────────────────────────────────────────────────────
const FICHEIROS_SENSIVEIS = [
  { path: '/.env',         impacto: 9, desc: '.env exposto - pode conter credenciais.' },
  { path: '/.git/HEAD',    impacto: 8, desc: 'Git exposto - codigo fonte acessivel.' },
  { path: '/admin',        impacto: 7, desc: 'Painel admin acessivel.' },
  { path: '/wp-admin',     impacto: 7, desc: 'WordPress admin acessivel.' },
  { path: '/backup.sql',   impacto: 9, desc: 'Backup de BD exposto.' },
  { path: '/phpinfo.php',  impacto: 5, desc: 'phpinfo() expoe configuracao do servidor.' },
  { path: '/.htpasswd',    impacto: 8, desc: 'Passwords Apache expostas.' },
  { path: '/swagger.json', impacto: 4, desc: 'API docs expostos.' },
  { path: '/api/v1',       impacto: 5, desc: 'API endpoint exposto.' },
  { path: '/.DS_Store',    impacto: 3, desc: 'Estrutura de diretorios exposta.' },
];

const pausa = ms => new Promise(r => setTimeout(r, ms));

// ── WAF ───────────────────────────────────────────────────────────────────────
async function detectarWAF(targetUrl, emitir, adicionarFinding) {
  emitir('[WAF] a detetar Web Application Firewall...', 'info', 2);

  const resNormal = await httpGet(targetUrl);
  const headersNormal = JSON.stringify(resNormal.headers).toLowerCase();

  const resProbe = await httpGet(targetUrl + WAF_PROBE);
  const headersProbe = JSON.stringify(resProbe.headers).toLowerCase();
  const bloqueado = resProbe.status === 403 || resProbe.status === 406 || resProbe.status === 429;

  const headersTotal = headersNormal + ' ' + headersProbe;

  let wafFound = null;
  for (const [waf, sigs] of Object.entries(WAF_ASSINATURAS)) {
    if (sigs.some(s => headersTotal.includes(s))) { wafFound = waf; break; }
  }

  if (!wafFound && bloqueado && resNormal.status !== resProbe.status) {
    wafFound = 'WAF desconhecido (bloqueio detectado)';
  }

  if (wafFound) {
    emitir(`[WAF] detetado: ${wafFound}`, 'success', 2);
    adicionarFinding(`WAF ${wafFound} ativo`, `WAF ${wafFound} protege a aplicacao.`,
      'waf-detect', 2, 1, 9, 'Manter WAF atualizado e regras activas.', null, false,
      VETOR_INFORMATIVO);
  } else {
    emitir('[WAF] sem WAF detetado', 'warning', 2);
    if (resNormal.status > 0)
      adicionarFinding('Sem WAF detetado', 'Nenhum WAF identificado — aplicacao exposta sem protecao.',
        'waf-detect', 2, 5, 7, 'Implementar WAF (Cloudflare, ModSecurity, AWS Shield).', null, false,
        VETOR_WAF_AUSENTE);
  }
}

// ── SSL/TLS ───────────────────────────────────────────────────────────────────
async function analisarSSL(host, emitir, adicionarFinding) {
  const tls = require('tls');
  return new Promise(resolve => {
    const guard = setTimeout(() => {
      emitir('[SSL] timeout na ligacao SSL', 'warning', 2);
      resolve();
    }, 12000);

    const socket = tls.connect({ host, port: 443, rejectUnauthorized: false }, () => {
      clearTimeout(guard);
      try {
        const cert  = socket.getPeerCertificate();
        const proto = socket.getProtocol();
        emitir(`[SSL] Protocolo: ${proto}`, 'output', 2);
        emitir(`[SSL] CN: ${cert.subject?.CN || 'N/A'}`, 'output', 2);
        if (cert.valid_to) {
          const dias = Math.round((new Date(cert.valid_to) - new Date()) / 86400000);
          emitir(`[SSL] Expira em: ${dias} dias`, dias < 30 ? 'warning' : 'output', 2);
          if (dias < 30)
            adicionarFinding('Certificado SSL a expirar', `Expira em ${dias} dias.`,
              'ssl-check', 2, 6, 9, 'Renovar certificado SSL.', null, false,
              VETOR_CERT_EXPIRANDO);
        }
        if (['TLSv1', 'TLSv1.1'].includes(proto))
          adicionarFinding(`SSL desatualizado: ${proto}`, `${proto} e inseguro.`,
            'ssl-check', 2, 6, 9, 'Usar TLS 1.2 ou superior.', null, false,
            VETOR_TLS_DESATUALIZADO);
      } catch (e) {
        emitir(`[SSL] erro a ler certificado: ${e.message}`, 'warning', 2);
      }
      socket.destroy();
      resolve();
    });
    socket.on('error', err => {
      clearTimeout(guard);
      if (err.code !== 'ECONNREFUSED')
        emitir(`[SSL] ${err.message}`, 'warning', 2);
      else
        emitir('[SSL] porto 443 fechado - sem HTTPS', 'warning', 2);
      resolve();
    });
    socket.on('timeout', () => { clearTimeout(guard); socket.destroy(); resolve(); });
  });
}

// ── NIKTO ─────────────────────────────────────────────────────────────────────

const NIKTO_LINHAS_INFORMATIVAS = [
  /^target ip:/i,
  /^target hostname:/i,
  /^target port:/i,
  /^start time:/i,
  /^end time:/i,
  /^\d+ (host|item)s? tested/i,
  /^\+ \d+ requests:/i,
];

async function executarNikto(targetUrl, emitir, adicionarFinding) {
  emitir('[NIKTO] a executar scan web (sem limite de tempo)...', 'info', 2);
  if (!(await ferramentaInstalada('nikto'))) {
    emitir('[NIKTO] nao instalado - a saltar', 'warning', 2);
    return;
  }
  // Sem -maxtime — corre ate terminar. Timeout do processo: 5 minutos
  await executarComandoSeguro('nikto',
    ['-h', targetUrl, '-nointeractive', '-ask', 'no'],
    l => {
      if (l.startsWith('+ ') && !l.includes('ERROR') && !l.includes('maximum execution')) {
        const clean = l.replace(/^\+\s*/, '').trim();
        const eInformativa = NIKTO_LINHAS_INFORMATIVAS.some(padrao => padrao.test(clean));

        if (clean.length > 15 && !eInformativa) {
          emitir(`[NIKTO] ${clean}`, 'output', 2);
          adicionarFinding(
            `Nikto: ${clean.substring(0, 100)}`, clean,
            'nikto', 2, 5, 7, 'Aplicar correcoes indicadas.', null, false,
            VETOR_NIKTO_GENERICO
          );
        } else if (eInformativa) {
          emitir(`[NIKTO] (info) ${clean}`, 'output', 2);
        }
      }
    }, 180000); // 5 minutos
}

// ── NUCLEI ────────────────────────────────────────────────────────────────────
async function executarNuclei(targetUrl, emitir, adicionarFinding) {
  if (!(await ferramentaInstalada('nuclei'))) {
    emitir('[NUCLEI] nao instalado - a saltar', 'warning', 2);
    return;
  }
  emitir('[NUCLEI] a executar templates...', 'info', 2);
  await executarComandoSeguro('nuclei',
    ['-u', targetUrl, '-severity', 'medium,high,critical', '-silent', '-rate-limit', '5', '-timeout', '5'],
    l => {
      const m = l.match(/\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)/);
      if (m) {
        const [, templateId, , severidade, alvo] = m;
        const sev = severidade.toUpperCase();
        emitir(`[NUCLEI] [${sev}] ${alvo}`, 'output', 2);
        const vetorAproximado = VETORES_NUCLEI_BANDA[sev] || VETORES_NUCLEI_BANDA.MEDIUM;
        adicionarFinding(`Nuclei: ${templateId}`, alvo, 'nuclei', 2,
          sev === 'CRITICAL' ? 9 : sev === 'HIGH' ? 7 : 5, 9,
          'Aplicar remediacao do template.', null, false,
          vetorAproximado);
      }
    }, 60000);
}

// ── FILE-SCANNER (com revalidacao de redirecionamentos) ──────────────────────


const MAX_REDIRECIONAMENTOS = 2;

/** Faz um único pedido HEAD via curl, sem seguir redirecionamentos. */
function pedidoHeadCurl(url) {
  return new Promise(async resolve => {
    let statusCode = 0;
    let location = null;
    await executarComandoSeguro('curl', [
      '-sI', '-D', '-', '-o', '/dev/null',
      '--max-time', '8',
      '--connect-timeout', '5',
      url,
    ], l => {
      const mStatus = l.match(/^HTTP\/[\d.]+\s+(\d{3})/i);
      if (mStatus) statusCode = parseInt(mStatus[1], 10);
      const mLoc = l.match(/^location:\s*(\S+)/i);
      if (mLoc) location = mLoc[1];
    }, 10000);
    resolve({ statusCode, location });
  });
}

/**
 */
async function verificarCaminhoComRevalidacao(urlInicial, emitir) {
  let urlAtual = urlInicial;

  for (let salto = 0; salto <= MAX_REDIRECIONAMENTOS; salto++) {
    const { statusCode, location } = await pedidoHeadCurl(urlAtual);

    const ehRedirecionamento = [301, 302, 303, 307, 308].includes(statusCode);
    if (!ehRedirecionamento || !location) {
      return statusCode;
    }

    let proximaUrl;
    try {
      proximaUrl = new URL(location, urlAtual).toString();
    } catch {
      return statusCode; // Location inválido — tratar como resultado final
    }

    try {
      await validarAlvo(proximaUrl);
    } catch (e) {
      emitir(`[FICHEIROS] redirecionamento bloqueado (SSRF): ${proximaUrl}`, 'warning', 2);
      return -1;
    }

    urlAtual = proximaUrl;
  }

  emitir(`[FICHEIROS] demasiados redirecionamentos a partir de ${urlInicial}`, 'warning', 2);
  return -2;
}

// ── ORQUESTRADOR — Fase 2 ─────────────────────────────────────────────────────
async function executarFase2(targetUrl, host, mode, emitir, progresso, adicionarFinding) {
  emitir('[2/4] ANALISE WEB', 'phase', 2);

  progresso('Detecao WAF', 1, 5, '#ff9500');
  await detectarWAF(targetUrl, emitir, adicionarFinding);

  // Pausa apos WAF — servidor AWS faz rate limiting por sessao
  await pausa(3000);

  progresso('SSL/TLS', 2, 5, '#ff9500');
  emitir('[SSL] a analisar SSL/TLS...', 'info', 2);
  if (targetUrl.startsWith('https')) {
    await analisarSSL(host, emitir, adicionarFinding);
  } else {
    emitir('[SSL] site nao usa HTTPS', 'warning', 2);
    adicionarFinding('HTTPS nao forcado', 'Aplicacao acessivel via HTTP nao seguro.',
      'ssl-check', 2, 7, 10, 'Forcar HTTPS e ativar HSTS.', null, false,
      VETOR_HTTPS_NAO_FORCADO);
  }

  // Pausa apos SSL antes dos ficheiros
  await pausa(2000);

  progresso('Ficheiros sensiveis', 3, 5, '#ff9500');
  emitir(`[FICHEIROS] a verificar ${FICHEIROS_SENSIVEIS.length} caminhos...`, 'info', 2);
  const findingsTemp = [];

  for (const alvo of FICHEIROS_SENSIVEIS) {
    const status = await verificarCaminhoComRevalidacao(`${targetUrl}${alvo.path}`, emitir);

    if ([200, 301, 302].includes(status)) {
      emitir(`[FICHEIROS] ENCONTRADO: ${alvo.path} (HTTP ${status})`, 'critical', 2);
      findingsTemp.push({
        titulo:     `Ficheiro Sensivel: ${alvo.path}`,
        descricao:  alvo.desc, ferramenta: 'file-scanner', fase: 2,
        impact:     alvo.impacto, confidence: 9,
        remediacao: `Bloquear acesso a ${alvo.path}.`, cve: null, simulado: false,
        vetorCVSS:  VETORES_FICHEIRO[alvo.path] || null,
      });
    } else if (status === -1) {
      // Redirecionamento suspeito — já registado em emitir(), não gera finding
      // de "ficheiro encontrado" porque nunca chegámos a confirmar o destino.
    } else if (status === -2) {
      // Demasiados redirecionamentos — idem, sem finding.
    } else if (status > 0) {
      emitir(`[FICHEIROS] ${alvo.path} -> ${status}`, 'output', 2);
    } else {
      emitir(`[FICHEIROS] ${alvo.path} -> timeout`, 'warning', 2);
    }
    await pausa(300);
  }

  findingsTemp.forEach(f => adicionarFinding(
    f.titulo, f.descricao, f.ferramenta, f.fase,
    f.impact, f.confidence, f.remediacao, f.cve, f.simulado,
    f.vetorCVSS
  ));

  progresso('Nikto', 4, 5, '#ff9500');
  await executarNikto(targetUrl, emitir, adicionarFinding);

  progresso('Nuclei', 5, 5, '#ff9500');
  await executarNuclei(targetUrl, emitir, adicionarFinding);
}

module.exports = { executarFase2, httpGet };