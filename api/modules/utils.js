// utils.js - Funcoes utilitarias base
const { execFile, spawn } = require('child_process');

const BLOQUEADOS = [
  /^localhost$/i, /^127\./, /^192\.168\./, /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./, /^169\.254\./, /^::1$/, /^0\.0\.0\.0$/,
];

function validarAlvo(target) {
  try {
    const url  = new URL(target.startsWith('http') ? target : `http://${target}`);
    const host = url.hostname;
    for (const p of BLOQUEADOS) {
      if (p.test(host)) throw new Error(`Alvo bloqueado: ${host} (protecao SSRF)`);
    }
    return host;
  } catch (e) {
    if (e.message.includes('protecao SSRF')) throw e;
    throw new Error(`Alvo invalido: ${target}`);
  }
}

function ferramentaInstalada(nome) {
  return new Promise(resolve => {
    execFile('which', [nome], err => resolve(!err));
  });
}

// Executa comando com duplo guard de timeout
function executarComandoSeguro(cmd, args = [], onLinha = () => {}, timeout = 15000) {
  return new Promise(resolve => {
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(); } };

    const guard = setTimeout(() => {
      try { if (proc && !proc.killed) proc.kill('SIGKILL'); } catch (_) {}
      finish();
    }, timeout + 500);

    let proc;
    try {
      proc = spawn(cmd, args, { shell: false });
    } catch (err) {
      clearTimeout(guard);
      finish();
      return;
    }

    const timer = setTimeout(() => {
      try { if (proc && !proc.killed) proc.kill('SIGKILL'); } catch (_) {}
      finish();
    }, timeout);

    const processar = data =>
      data.toString()
        .split(/\r?\n/)
        .map(l => l.replace(/\x1B\[[0-9;]*[mGKHF]/g, '').trim()) // remove ANSI
        .filter(Boolean)
        .forEach(l => { try { onLinha(l); } catch (_) {} });

    proc.stdout.on('data', processar);
    proc.stderr.on('data', processar);
    proc.on('close', () => { clearTimeout(timer); clearTimeout(guard); finish(); });
    proc.on('error', ()  => { clearTimeout(timer); clearTimeout(guard); finish(); });
  });
}

// HTTP GET — headers completos tipo browser para compatibilidade com IIS/AWS
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

// HTTP method com timeout robusto - sem CONNECT
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

module.exports = { validarAlvo, ferramentaInstalada, executarComandoSeguro, httpGet, httpMethod };