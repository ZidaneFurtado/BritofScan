// fase1_recon.js - Reconhecimento
const { ferramentaInstalada, executarComandoSeguro } = require('./utils');
const { existsSync } = require('fs');
const path = require('path');
const os   = require('os');

const PORTOS_INFO = {
  '21':    { impacto: 8, desc: 'FTP inseguro - usar SFTP.' },
  '22':    { impacto: 5, desc: 'SSH exposto - verificar autenticacao.' },
  '23':    { impacto: 9, desc: 'Telnet inseguro - desativar.' },
  '25':    { impacto: 5, desc: 'SMTP exposto - verificar relay.' },
  '3306':  { impacto: 8, desc: 'MySQL exposto a internet.' },
  '5432':  { impacto: 8, desc: 'PostgreSQL exposto.' },
  '6379':  { impacto: 9, desc: 'Redis exposto - sem auth por defeito.' },
  '27017': { impacto: 9, desc: 'MongoDB exposto.' },
  '8080':  { impacto: 5, desc: 'HTTP alternativo exposto.' },
  '8443':  { impacto: 3, desc: 'HTTPS alternativo.' },
};


const CVES_POR_VERSAO = [
  { porto: '21',   padrao: /vsftpd\s*2\.3\.4/i,        cve: 'CVE-2011-2523' },
  { porto: '3306', padrao: /mysql\s*5\.5\.[0-9]+/i,     cve: 'CVE-2016-6663' },
  { porto: '22',   padrao: /openssh\s*7\.4/i,           cve: 'CVE-2018-15473' },
];

function getImpacto(p)  { return PORTOS_INFO[String(p)]?.impacto || 3; }
function getDesc(p)     { return PORTOS_INFO[String(p)]?.desc || 'Porto aberto.'; }


function getCVE(p, v = '') {
  const versao = String(v).trim();
  if (!versao) return null; // sem versao confirmada, sem CVE. Ponto final.
  const match = CVES_POR_VERSAO.find(
    entry => entry.porto === String(p) && entry.padrao.test(versao)
  );
  return match ? match.cve : null;
}

// ── WHOIS ─────────────────────────────────────────────────────────────────────
const WHOIS_IGNORAR = [
  'notice', 'terms', 'verisign', 'afilias', 'by submitting', 'electronic',
  'high-volume', 'dissemination', 'repackaging', 'lawful', 'unsolicited',
  'commercial advertising', 'solicitation', 'transmission', 'sponsorship',
  'currently set to expire', 'does not necessarily', 'registrant\'s agreement',
  'sponsoring registrar', 'reported date', 'for this registration',
  'automated except', 'information purposes only', 'assist persons',
  'obtaining information', 'registry database contains',
  'allow, enable', 'support the', 'cookie', 'copyright',
  '>>>', 'last update of whois',
];

const WHOIS_UTIL = [
  'registrar:', 'registrant', 'creation date', 'updated date', 'expir',
  'name server', 'nameserver', 'status:', 'dnssec', 'admin', 'tech',
  'email', 'phone', 'country', 'city', 'street', 'postal', 'org:',
  'no match', 'not found', 'domain name:', 'registry domain',
  'whois server', 'refer:', 'netname', 'inetnum', 'route:', 'origin:',
];

async function runWhois(host, emitir) {
  if (!(await ferramentaInstalada('whois'))) {
    emitir('[WHOIS] nao instalado', 'warning', 1);
    return;
  }
  await executarComandoSeguro('whois', [host], linha => {
    const l = linha.toLowerCase().trim();
    if (l.length < 4) return;
    if (WHOIS_IGNORAR.some(termo => l.includes(termo))) return;
    const temUtil = WHOIS_UTIL.some(termo => l.includes(termo));
    const temDoisPontos = l.includes(':');
    if (!temUtil && !temDoisPontos && l.length > 60) return;
    if (!temUtil && !temDoisPontos && l.split(/\s+/).length <= 2) return;
    emitir(`[WHOIS] ${linha.trim()}`, 'output', 1);
  }, 7000);
}

// ── NMAP ──────────────────────────────────────────────────────────────────────
async function executarNmap(host, mode, emitir, adicionarFinding) {
  if (!(await ferramentaInstalada('nmap'))) {
    emitir('[NMAP] nao instalado - a simular', 'warning', 1);
    [
      { porto: '80',  servico: 'http',  versao: 'Apache/2.4' },
      { porto: '443', servico: 'https', versao: 'Apache/2.4' },
    ].forEach(p => {
      emitir(`[NMAP] ${p.porto}/tcp open ${p.servico} ${p.versao}`, 'output', 1);
      adicionarFinding(
        `Porto ${p.porto}/tcp aberto - ${p.servico}`,
        `${p.servico} ${p.versao} no porto ${p.porto}. ${getDesc(p.porto)}`,
        'nmap', 1, getImpacto(p.porto), 8,
        `Verificar necessidade do servico.`, null, true
      );
    });
    return;
  }

  const configs = {
    // -sV removido de todos os modos — demasiado lento e trigera rate limiting AWS
    stealth:    { args: ['-sT', '-Pn', '-T2', '-p', '21,22,23,25,80,443,445,3306,5432,6379,8080,8443,27017', '--open', host], timeout: 30000 },
    standard:   { args: ['-sT', '-Pn', '-T3', '-p', '21,22,23,25,80,443,445,3306,5432,6379,8080,8443,27017,3389,5900,5000,8000,8888', '--open', host], timeout: 45000 },
    aggressive: { args: ['-sT', '-Pn', '-T3', '--top-ports', '200', '--open', host], timeout: 90000 },
  };

  const { args, timeout } = configs[mode] || configs.standard;
  emitir(`[NMAP] ${args.join(' ')}`, 'info', 1);

  const NMAP_IGNORAR = [
    'other addresses', 'not scanned', 'rdns record',
    'not shown:', 'some closed ports', 'defeat-rst-ratelimit',
    'starting nmap', 'nmap done', 'nmap scan report',
    'host is up',
  ];

  await executarComandoSeguro('nmap', args, linha => {
    if (NMAP_IGNORAR.some(t => linha.toLowerCase().includes(t))) return;
    emitir(`[NMAP] ${linha}`, 'output', 1);
    const m = linha.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$/i);
    if (m) {
      const [, porto, , servico, versao = ''] = m;
      const cve = getCVE(porto, versao);
      const descricaoBase = `${servico} ${versao.trim()} no porto ${porto}. ${getDesc(porto)}`;
      const descricao = versao.trim()
        ? descricaoBase
        : `${descricaoBase} Versao do servico nao identificada (scan sem -sV) - qualquer associacao a CVE requer confirmacao manual.`;
      adicionarFinding(
        `Porto ${porto}/tcp aberto - ${servico}`,
        descricao,
        'nmap', 1, getImpacto(porto), 9,
        `Verificar se ${servico} e necessario. Fechar portos desnecessarios.`,
        cve,
        false
      );
    }
  }, timeout);
}

// ── DNS RECON ─────────────────────────────────────────────────────────────────
async function executarDNS(host, emitir) {
  if (await ferramentaInstalada('dnsrecon')) {
    emitir('[DNSRECON] a enumerar DNS...', 'info', 1);
    await executarComandoSeguro('dnsrecon', ['-d', host, '-t', 'std'],
      l => { if (!l.includes('DNSSEC')) emitir(`[DNSRECON] ${l}`, 'output', 1); },
      20000);
  } else if (await ferramentaInstalada('dig')) {
    emitir('[DIG] a consultar DNS...', 'info', 1);
    await executarComandoSeguro('dig', [host, 'ANY', '+short'],
      l => emitir(`[DIG] ${l}`, 'output', 1), 8000);
  } else {
    emitir('[DNS] nenhuma ferramenta DNS disponivel', 'warning', 1);
  }
}

// ── THEHARVESTER ──────────────────────────────────────────────────────────────
async function executarHarvester(host, emitir, adicionarFinding) {
  if (!(await ferramentaInstalada('theHarvester'))) {
    emitir('[HARVESTER] nao instalado - a saltar', 'warning', 1);
    return;
  }
  emitir('[HARVESTER] a recolher emails e dados publicos...', 'info', 1);
  await executarComandoSeguro('theHarvester', ['-d', host, '-b', 'bing', '-l', '20'],
    l => {
      if (l.includes('@') && l.includes('.') && !l.startsWith('[') && !l.startsWith('-')) {
        emitir(`[HARVESTER] ${l}`, 'output', 1);
        adicionarFinding(
          `Email exposto: ${l.trim()}`, 'Email encontrado via OSINT.',
          'theHarvester', 1, 4, 8,
          'Remover emails corporativos de publicacoes publicas.', null, false
        );
      }
    }, 25000);
}

// ── SUBLIST3R ─────────────────────────────────────────────────────────────────
async function executarSubdominios(host, emitir) {
  const python = await ferramentaInstalada('python3') ? 'python3'
               : await ferramentaInstalada('python')  ? 'python' : null;
  const sublistPaths = [
    '/opt/Sublist3r/sublist3r.py',
    '/usr/share/sublist3r/sublist3r.py',
    '/usr/local/bin/sublist3r',
  ];
  const sublistPath = sublistPaths.find(p => existsSync(p));
  if (python && sublistPath) {
    emitir('[SUBLIST3R] a enumerar subdominios...', 'info', 1);
    const output = path.join(os.tmpdir(), `subs_${Date.now()}.txt`);
    let iniciou = false;
    await executarComandoSeguro(python, ['-W', 'ignore', sublistPath, '-d', host, '-o', output, '-n'],
      l => {
        const li = l.trim();
        if (li.length < 3) return;
        if (!iniciou && li.startsWith('[-]')) iniciou = true;
        if (!iniciou) return;
        if (li.startsWith('Process')) return;
        if (li.includes('Traceback')     || li.includes('File "')        ||
            li.includes('^^^^^^^^')      || li.includes('~~~~~~~~')       ||
            li.includes('IndexError')    || li.includes('Error:')         ||
            li.includes('Exception')     || li.includes('self.')          ||
            li.includes('token =')       || li.includes('domain_list =')  ||
            li.includes('csrf_regex')    || li.includes('.enumerate(')    ||
            li.includes('.get_csrf')     || li.includes('ConnectionPool') ||
            li.includes('timed out')     || li.includes('read timeout')   ||
            li.startsWith("if '"))       return;
        emitir(`[SUBLIST3R] ${li}`, 'output', 1);
      }, 25000);
  } else if (await ferramentaInstalada('sublist3r')) {
    emitir('[SUBLIST3R] a enumerar subdominios...', 'info', 1);
    await executarComandoSeguro('sublist3r', ['-d', host, '-n'],
      l => emitir(`[SUBLIST3R] ${l}`, 'output', 1), 25000);
  } else {
    emitir('[SUBLIST3R] nao instalado - a saltar', 'warning', 1);
  }
}

// ── GOBUSTER DNS ──────────────────────────────────────────────────────────────
async function executarGobusterDNS(host, mode, emitir) {
  if (mode === 'stealth') return;
  if (!(await ferramentaInstalada('gobuster'))) {
    emitir('[GOBUSTER] nao instalado', 'warning', 1);
    return;
  }
  const wordlists = [
    '/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt',
    '/usr/share/wordlists/dnsmap.txt',
  ];
  const wordlist = wordlists.find(w => existsSync(w));
  if (!wordlist) {
    emitir('[GOBUSTER] wordlist nao encontrada - correr install.sh', 'warning', 1);
    return;
  }
  emitir(`[GOBUSTER] brute force DNS...`, 'info', 1);
  await executarComandoSeguro('gobuster', ['dns', '-d', host, '-w', wordlist, '-q', '-t', '10'],
    l => emitir(`[GOBUSTER] ${l}`, 'output', 1), 25000);
}

// ── AMASS ─────────────────────────────────────────────────────────────────────
async function executarAmass(host, emitir) {
  if (!(await ferramentaInstalada('amass'))) {
    emitir('[AMASS] nao instalado - a saltar', 'warning', 1);
    return;
  }
  emitir('[AMASS] a enumerar passivamente...', 'info', 1);
  await executarComandoSeguro('amass', ['enum', '-passive', '-d', host, '-timeout', '2'],
    l => {
      const li = l.trim();
      if (li.length < 3) return;
      if (li.includes('The enumeration has finished') ||
          li.includes('Discoveries are being migrated') ||
          li.includes('local database') ||
          li.includes('The DNS query')) return;
      emitir(`[AMASS] ${li}`, 'output', 1);
    }, 90000);
}

// ── ORQUESTRADOR — Fase 1 ─────────────────────────────────────────────────────
async function executarFase1(host, mode, emitir, progresso, adicionarFinding) {
  emitir('[1/4] RECONHECIMENTO', 'phase', 1);

  progresso('WHOIS', 1, 7, '#5ac8fa');
  await runWhois(host, emitir);

  progresso('Nmap', 2, 7, '#5ac8fa');
  await executarNmap(host, mode, emitir, adicionarFinding);

  if (mode === 'aggressive') {
    emitir('[NMAP] a aguardar reset do rate limiting (15s)...', 'info', 1);
    await new Promise(r => setTimeout(r, 15000));
  }

  progresso('theHarvester', 3, 7, '#5ac8fa');
  await executarHarvester(host, emitir, adicionarFinding);

  progresso('DNS', 4, 7, '#5ac8fa');
  await executarDNS(host, emitir);

  progresso('Sublist3r', 5, 7, '#5ac8fa');
  await executarSubdominios(host, emitir);

  progresso('Gobuster DNS', 6, 7, '#5ac8fa');
  await executarGobusterDNS(host, mode, emitir);

  progresso('Amass', 7, 7, '#5ac8fa');
  await executarAmass(host, emitir);
}

module.exports = { executarFase1, executarComandoSeguro, ferramentaInstalada };