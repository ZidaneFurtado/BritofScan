// scoringCVSS.js - Motor de pontuacao CVSS v3.1 (Base Score)
// Implementa a formula oficial publicada pelo FIRST (Forum of Incident
// Response and Security Teams): https://www.first.org/cvss/v3-1/specification-document
//
// Substitui a heuristica anterior (impact*0.6 + confidence*0.4), que nao
// correspondia a nenhuma norma reconhecida e foi identificada como tal
// durante a revisao do projeto.

// ── PESOS OFICIAIS CVSS v3.1 ────────────────────────────────────────────────
const AV_W = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
const AC_W = { L: 0.77, H: 0.44 };
const UI_W = { N: 0.85, R: 0.62 };
const CIA_W = { H: 0.56, L: 0.22, N: 0.00 };
// PR depende do Scope (S): valores diferentes se o scope for alterado (C)
const PR_W = {
  U: { N: 0.85, L: 0.62, H: 0.27 }, // Scope Unchanged
  C: { N: 0.85, L: 0.68, H: 0.50 }, // Scope Changed
};

// Funcao de arredondamento oficial CVSS ("roundup"), evita erros de
// vírgula flutuante do JavaScript nativo (Math.round/toFixed).
function roundup(x) {
  const intInput = Math.round(x * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/**
 * Calcula o Base Score CVSS v3.1 a partir de um vetor.
 * @param {string} vetor - ex: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
 * @returns {{ score: number, severidade: string, vetor: string }}
 */
function calcularCVSS(vetor) {
  const partes = Object.fromEntries(
    vetor.split('/').map(p => p.split(':'))
  );
  const { AV, AC, PR, UI, S, C, I, A } = partes;

  const iscBase = 1 - ((1 - CIA_W[C]) * (1 - CIA_W[I]) * (1 - CIA_W[A]));
  const impact = S === 'C'
    ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
    : 6.42 * iscBase;

  const exploitability = 8.22 * AV_W[AV] * AC_W[AC] * PR_W[S][PR] * UI_W[UI];

  let score;
  if (impact <= 0) {
    score = 0;
  } else if (S === 'C') {
    score = roundup(Math.min(1.08 * (impact + exploitability), 10));
  } else {
    score = roundup(Math.min(impact + exploitability, 10));
  }

  return { score, severidade: classificarCVSS(score), vetor };
}

/** Classificacao oficial de severidade CVSS v3.1 por intervalo de score. */
function classificarCVSS(score) {
  if (score === 0) return 'NONE';
  if (score < 4.0) return 'LOW';
  if (score < 7.0) return 'MEDIUM';
  if (score < 9.0) return 'HIGH';
  return 'CRITICAL';
}

// ── MAPA DE VETORES POR TIPO DE FINDING ─────────────────────────────────────
// Cada entrada e um vetor CVSS v3.1 real, atribuido com base na natureza
// tecnica do finding. Fonte de validacao cruzada onde aplicavel: NVD
// (nvd.nist.gov) para as CVEs correlacionadas.

const VETORES_PORTA = {
  '21':    'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', // FTP - credenciais em claro
  '22':    'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N', // SSH - exposto, requer força bruta
  '23':    'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', // Telnet - protocolo em claro
  '25':    'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N', // SMTP - relay potencial
  '3306':  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', // MySQL exposto
  '5432':  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', // PostgreSQL exposto
  '6379':  'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', // Redis sem auth - risco de RCE (scope alterado)
  '27017': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', // MongoDB exposto
  '8080':  'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', // HTTP alternativo
  '8443':  'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', // HTTPS alternativo
};

const VETORES_CVE = {
  // CVE-2011-2523: backdoor vsftpd 2.3.4 - RCE completo (NVD: CVSS v2 10.0;
  // vetor v3.1 equivalente por natureza do backdoor)
  'CVE-2011-2523':  'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
  // CVE-2016-6663: escalonamento de privilegios MySQL/MariaDB (NVD)
  'CVE-2016-6663':  'AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H',
  // CVE-2018-15473: enumeracao de utilizadores OpenSSH (NVD: 5.3 MEDIUM)
  'CVE-2018-15473': 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
};

const VETORES_FICHEIRO = {
  '/.env':         'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N', // credenciais -> possivel escalada
  '/.git/HEAD':    'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N', // codigo-fonte exposto
  '/admin':        'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', // apenas revela existencia
  '/wp-admin':     'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
  '/backup.sql':   'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', // dump de BD
  '/phpinfo.php':  'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
  '/.htpasswd':    'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  '/swagger.json': 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
  '/api/v1':       'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
  '/.DS_Store':    'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
};

const VETORES_HEADER = {
  'HSTS':               'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
  'CSP':                'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N',
  'X-Frame-Options':    'AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N',
  'X-Content-Type':     'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
  'Referrer-Policy':    'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
  'Permissions-Policy': 'AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N',
  // X-XSS-Protection: mecanismo descontinuado - sem CVSS aplicavel (ver nota)
};

const VETORES_COOKIE = {
  httponly: 'AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N', // roubo assistido por XSS
  secure:   'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',  // so relevante se MITM
  samesite: 'AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',  // CSRF
};

const VETORES_METODO = {
  TRACE:  'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', // Cross-Site Tracing
  PUT:    'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', // modificacao de recursos
  DELETE: 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', // remocao de recursos
};

const VETOR_WAF_AUSENTE = 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N';
const VETOR_HTTPS_NAO_FORCADO = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N';
const VETOR_TLS_DESATUALIZADO = 'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N';

// Vetores representativos por banda de severidade do Nuclei, usados como
// aproximacao enquanto o modulo nao extrai o vetor CVSS real de cada
// template (ver limitacao documentada abaixo).
const VETORES_NUCLEI_BANDA = {
  CRITICAL: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  HIGH:     'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
  MEDIUM:   'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
};

// Vetor generico conservador para findings do Nikto (output em texto livre,
// sem categorizacao estruturada de metricas CVSS na origem).
const VETOR_NIKTO_GENERICO = 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N';

module.exports = {
  calcularCVSS, classificarCVSS,
  VETORES_PORTA, VETORES_CVE, VETORES_FICHEIRO, VETORES_HEADER,
  VETORES_COOKIE, VETORES_METODO, VETORES_NUCLEI_BANDA,
  VETOR_WAF_AUSENTE, VETOR_HTTPS_NAO_FORCADO, VETOR_TLS_DESATUALIZADO,
  VETOR_NIKTO_GENERICO,
};