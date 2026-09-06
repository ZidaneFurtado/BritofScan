// utils.js - Funcoes utilitarias base
const { execFile, spawn } = require('child_process');
const dns = require('dns').promises;
const net = require('net');

// ── PROTEÇÃO SSRF (validarAlvo) ──────────────────────────────────────────────
const IPV4_BLOQUEADOS = [
  /^127\./, /^10\./, /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^169\.254\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^0\./, /^224\./, /^240\./,
];

function isIPv6Bloqueado(ip) {
  const low = ip.toLowerCase();
  if (low === '::1') return true;
  if (low.startsWith('fe80:')) return true;
  if (low.startsWith('fc') || low.startsWith('fd')) return true;
  if (low.startsWith('::ffff:')) {
    const ipv4 = low.replace('::ffff:', '');
    return IPV4_BLOQUEADOS.some(p => p.test(ipv4));
  }
  return false;
}

function ipBloqueado(ip) {
  const versao = net.isIP(ip);
  if (versao === 4) return IPV4_BLOQUEADOS.some(p => p.test(ip));
  if (versao === 6) return isIPv6Bloqueado(ip);
  return true;
}

async function validarAlvo(target) {
  const semProtocolo = String(target).replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const semColchetes = semProtocolo.replace(/^\[|\]$/g, '');

  if (net.isIP(semColchetes)) {
    if (ipBloqueado(semColchetes)) {
      throw new Error(`Alvo bloqueado: ${semColchetes} (protecao SSRF)`);
    }
    return semColchetes;
  }

  let host;
  try {
    const url = new URL(target.startsWith('http') ? target : `http://${target}`);
    host = url.hostname;
  } catch (e) {
    throw new Error(`Alvo invalido: ${target}`);
  }

  let enderecos;
  try {
    const [v4, v6] = await Promise.allSettled([
      dns.resolve4(host),
      dns.resolve6(host),
    ]);
    enderecos = [
      ...(v4.status === 'fulfilled' ? v4.value : []),
      ...(v6.status === 'fulfilled' ? v6.value : []),
    ];
  } catch (e) {
    throw new Error(`Nao foi possivel resolver o alvo: ${host}`);
  }

  if (enderecos.length === 0) {
    throw new Error(`Alvo nao resolve para nenhum endereço: ${host}`);
  }

  const bloqueado = enderecos.find(ip => ipBloqueado(ip));
  if (bloqueado) {
    throw new Error(`Alvo bloqueado: ${host} resolve para ${bloqueado} (protecao SSRF - DNS Rebinding)`);
  }

  return host;
}

async function revalidarRedirecionamento(location) {
  await validarAlvo(location);
}

// ── ferramentaInstalada ───────────────────────────────────────────────────────
function ferramentaInstalada(nome) {
  return new Promise(resolve => {
    execFile('which', [nome], err => resolve(!err));
  });
}

// ── executarComandoSeguro ─────────────────────────────────────────────────────

function executarComandoSeguro(cmd, args = [], onLinha = () => {}, timeout = 15000) {
  const MAX_OUTPUT_BYTES = 5 * 1024 * 1024; // 5MB

  return new Promise(resolve => {
    let done = false;
    let outputBytes = 0;
    let linhasRecebidas = 0;
    const finish = (motivo) => {
      if (!done) { done = true; resolve({ motivo, linhasRecebidas }); }
    };

    const matarArvore = (p) => {
      if (!p || p.killed) return;
      try {
        process.kill(-p.pid, 'SIGKILL');
      } catch (_) {
        try { p.kill('SIGKILL'); } catch (__) {}
      }
    };

    const guard = setTimeout(() => {
      matarArvore(proc);
      finish('timeout');
    }, timeout + 500);

    let proc;
    try {
      proc = spawn(cmd, args, { shell: false, detached: true });
    } catch (err) {
      clearTimeout(guard);
      finish('erro');
      return;
    }

    const timer = setTimeout(() => {
      matarArvore(proc);
      finish('timeout');
    }, timeout);

    const processar = data => {
      outputBytes += data.length;
      if (outputBytes > MAX_OUTPUT_BYTES) {
        clearTimeout(timer);
        clearTimeout(guard);
        matarArvore(proc);
        finish('output_truncado');
        return;
      }
      data.toString()
        .split(/\r?\n/)
        .map(l => l.replace(/\x1B\[[0-9;]*[mGKHF]/g, '').trim())
        .filter(Boolean)
        .forEach(l => {
          linhasRecebidas++;
          try { onLinha(l); } catch (_) {}
        });
    };

    proc.stdout.on('data', processar);
    proc.stderr.on('data', processar);
    proc.on('close', (codigoSaida) => {
      clearTimeout(timer);
      clearTimeout(guard);
      // codigoSaida !== 0 nem sempre significa erro grave (muitas
      // ferramentas de scan devolvem codigo != 0 por design, ex: quando
      // encontram resultados) - regista-se como 'concluido' desde que o
      // processo tenha terminado por si so, nao por timeout/erro externo.
      finish('concluido');
    });
    proc.on('error', () => {
      clearTimeout(timer);
      clearTimeout(guard);
      finish('erro');
    });
  });
}

// ── httpGet ───────────────────────────────────────────────────────────────────
function httpGet(url, timeout = 8000) {
  return new Promise(resolve => {
    const mod   = url.startsWith('https') ? require('https') : require('http');
    const guard = setTimeout(() => resolve({ status: 0, headers: {} }), timeout + 2000);
    try {
      const urlObj = new URL(url);
      const req = mod.request({
        hostname: urlObj.hostname,
        path:     urlObj.pathname + urlObj.search,
        method:   'GET',
        rejectUnauthorized: false,
        headers: {
          'User-Agent':      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
          'Accept':          'text/html,application/xhtml+xml,*/*',
          'Accept-Language': 'en-US,en;q=0.9',
          'Connection':      'close',
          'Host':            urlObj.hostname,
        },
      }, res => {
        clearTimeout(guard);
        res.resume();
        resolve({ status: res.statusCode, headers: res.headers });
      });
      req.on('error',   () => { clearTimeout(guard); resolve({ status: 0, headers: {} }); });
      req.setTimeout(timeout, () => { req.destroy(); resolve({ status: 0, headers: {} }); });
      req.end();
    } catch (e) {
      clearTimeout(guard);
      resolve({ status: 0, headers: {} });
    }
  });
}

// ── httpMethod (código morto — mantido por compatibilidade, não invocado) ────
function httpMethod(urlStr, method, timeout = 5000) {
  return new Promise(resolve => {
    try {
      const urlObj = new URL(urlStr);
      const mod    = urlObj.protocol === 'https:' ? require('https') : require('http');
      const guard  = setTimeout(() => resolve(0), timeout + 1000);
      const req    = mod.request({
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: '/', method,
        rejectUnauthorized: false,
        headers: {
          'User-Agent':  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
          'Connection':  'close',
          'Host':        urlObj.hostname,
        },
      }, res => {
        clearTimeout(guard); res.resume(); resolve(res.statusCode);
      });
      req.on('error', () => { clearTimeout(guard); resolve(0); });
      req.setTimeout(timeout, () => { req.destroy(); resolve(0); });
      req.end();
    } catch (e) { resolve(0); }
  });
}

module.exports = {
  validarAlvo, revalidarRedirecionamento, ferramentaInstalada,
  executarComandoSeguro, httpGet, httpMethod,
};