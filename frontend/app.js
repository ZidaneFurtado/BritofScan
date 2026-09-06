// ─── ESTADO DA APLICAÇÃO ─────────────────────────────────────────────────────
const API      = window.location.origin;
let token      = null;
let utilizador = null;
let modoSelecionado = 'stealth';
let scanAtual  = null;
let socket     = null;
let ultimosResultados = null;
let pingInterval = null;

// ─── INICIALIZAÇÃO SEGURA ─────────────────────────────────────────────────────
function carregarSessao() {
  try {
    const t = localStorage.getItem('britofscan_token');
    const u = localStorage.getItem('britofscan_user');
    if (t && u && u !== 'undefined' && u !== 'null') {
      token      = t;
      utilizador = JSON.parse(u);
    }
  } catch (e) {
    console.warn('[Auth] Sessão inválida, a limpar...', e);
    localStorage.removeItem('britofscan_token');
    localStorage.removeItem('britofscan_user');
  }
}

// ─── AUTENTICAÇÃO ─────────────────────────────────────────────────────────────
function mudarAbaAuth(aba) {
  document.querySelectorAll('.auth-tab').forEach((t, i) => {
    t.classList.toggle('active', (aba === 'login' && i === 0) || (aba === 'registo' && i === 1));
  });
  document.getElementById('form-login').classList.toggle('active', aba === 'login');
  document.getElementById('form-registo').classList.toggle('active', aba === 'registo');
  document.getElementById('auth-erro').style.display = 'none';
}

function mostrarErroAuth(msg) {
  const el = document.getElementById('auth-erro');
  el.textContent = msg;
  el.style.display = 'block';
}

async function fazerLogin() {
  const email    = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  if (!email || !password) return mostrarErroAuth('Preenche todos os campos');
  try {
    const res  = await fetch(`${API}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) return mostrarErroAuth(data.erro || data.error || 'Erro ao fazer login');
    const user = data.utilizador || data.user;
    if (!data.token || !user) return mostrarErroAuth('Resposta inválida do servidor');
    guardarSessao(data.token, user);
    iniciarApp();
  } catch (e) {
    mostrarErroAuth('Erro de ligação ao servidor. Verifica se o backend está ativo em ' + API);
  }
}


async function fazerRegisto() {
  const nome     = document.getElementById('reg-nome').value.trim();
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  if (!nome || !email || !password) return mostrarErroAuth('Preenche todos os campos');
  try {
    const res  = await fetch(`${API}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: nome, nome, email, password }),
    });
    const data = await res.json();
    if (!res.ok) return mostrarErroAuth(data.erro || data.error || 'Erro ao registar');
    const user = data.utilizador || data.user;
    if (!data.token || !user) return mostrarErroAuth('Resposta inválida do servidor');
    guardarSessao(data.token, user);
    iniciarApp();
  } catch (e) {
    mostrarErroAuth('Erro de ligação ao servidor. Verifica se o backend está ativo em ' + API);
  }
}

function guardarSessao(tok, user) {
  token = tok; utilizador = user;
  localStorage.setItem('britofscan_token', tok);
  localStorage.setItem('britofscan_user', JSON.stringify(user));
}

function fazerLogout() {
  localStorage.removeItem('britofscan_token');
  localStorage.removeItem('britofscan_user');
  token = null; utilizador = null;
  if (pingInterval) { clearInterval(pingInterval); pingInterval = null; }
  if (socket) { socket.disconnect(); socket = null; }
  document.getElementById('app').style.display = 'none';
  document.getElementById('auth-overlay').style.display = 'flex';
}

// ─── INICIALIZAÇÃO DA APP ─────────────────────────────────────────────────────
function iniciarApp() {
  document.getElementById('auth-overlay').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  document.getElementById('user-nome').textContent       = utilizador?.name || utilizador?.nome || 'Utilizador';
  document.getElementById('user-role-badge').textContent = utilizador?.role || 'utilizador';

  // Só cria socket se não existir — evita perda de listeners por reconexão
  if (!socket || !socket.connected) {
    if (socket) socket.disconnect();

    socket = io(window.location.origin, {
      auth: { token },
      reconnection:        true,
      reconnectionDelay:   2000,
      reconnectionAttempts: 20,
      timeout:            120000,
      pingTimeout:        120000,
      pingInterval:        25000,
    });

    socket.on('connect', () => {
      console.log('[WS] Ligado:', socket.id);
    });
    socket.on('disconnect', (reason) => {
      console.warn('[WS] Desligado:', reason);
    });
    socket.on('connect_error', (err) => {
      console.warn('[WS] Erro de ligação:', err.message);
    });
    socket.on('reconnect', (n) => {
      console.log('[WS] Reconectado após', n, 'tentativas');
      //  Re-regista listeners do scan activo após reconexão
      if (scanAtual) {
        console.log('[WS] A re-registar listeners para scan:', scanAtual);
        ouvirWebSocket(scanAtual, document.getElementById('scan-target')?.value || '');
      }
    });

    // Ping manual a cada 20s para manter ligação viva durante scans
    if (pingInterval) clearInterval(pingInterval);
    pingInterval = setInterval(() => {
      if (socket?.connected) socket.emit('ping');
    }, 20000);
  }

  renderizarFerramentas();
  carregarHistorico();
  carregarRelatorios();
}

// ─── NAVEGAÇÃO ────────────────────────────────────────────────────────────────
function navegar(pagina) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById(`page-${pagina}`)?.classList.add('active');
  document.querySelector(`[data-page="${pagina}"]`)?.classList.add('active');
  if (pagina === 'historico')  carregarHistorico();
  if (pagina === 'relatorios') carregarRelatorios();
}

// ─── SCAN ─────────────────────────────────────────────────────────────────────
function selecionarModo(modo) {
  modoSelecionado = modo;
  document.querySelectorAll('.mode-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.mode === modo);
  });
}

async function iniciarScan() {
  const target = document.getElementById('scan-target').value.trim();
  if (!target) return alert('Insere um alvo válido');

  const btn = document.getElementById('btn-iniciar-scan');
  btn.disabled  = true;
  btn.innerHTML = '<span></span> A iniciar...';

  document.getElementById('fases-container').classList.add('visible');
  [1, 2, 3, 4].forEach(i => {
    document.getElementById(`fase-${i}`).className = 'fase-card';
    const e = document.getElementById(`fase-${i}-estado`);
    e.className = 'fase-estado aguarda'; e.textContent = 'Aguarda';
  });
  document.getElementById('terminal').innerHTML         = '';
  document.getElementById('progress-fill').style.width  = '0%';
  document.getElementById('progress-pct').textContent   = '0%';
  document.getElementById('progress-label').textContent = 'A inicializar...';

  try {
    const res  = await fetch(`${API}/api/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify({ target, mode: modoSelecionado }),
    });
    const data = await res.json();
    if (!res.ok) {
      alert(data.erro || data.error || 'Erro ao iniciar scan');
      btn.disabled = false; btn.innerHTML = '<span></span> Iniciar Scan';
      return;
    }
    scanAtual = data.scanId || data.id;
    console.log('[Scan] ID recebido:', scanAtual);
    console.log('[Scan] Socket ligado?', socket?.connected, '| ID socket:', socket?.id);
    btn.innerHTML = '<span></span> Scan em curso...';
    ouvirWebSocket(scanAtual, target);
  } catch (e) {
    console.error('[Scan] Erro:', e);
    alert('Erro de ligação ao servidor');
    btn.disabled = false; btn.innerHTML = '<span></span> Iniciar Scan';
  }
}

// ─── WEBSOCKET ────────────────────────────────────────────────────────────────
function ouvirWebSocket(scanId, target) {
  console.log('[WS] A registar listeners para scanId:', scanId);

  //  Remove listeners anteriores para evitar duplicados
  socket.off(`scan:line:${scanId}`);
  socket.off(`scan:progress:${scanId}`);
  socket.off(`scan:phase:${scanId}`);
  socket.off(`scan:done:${scanId}`);

  socket.on(`scan:line:${scanId}`, ({ ts, text, level }) => {
    adicionarLinhaTerminal(ts, text, level);
  });

  socket.on(`scan:progress:${scanId}`, ({ label, pct, color }) => {
    document.getElementById('progress-label').textContent = label;
    document.getElementById('progress-pct').textContent   = `${pct}%`;
    const fill = document.getElementById('progress-fill');
    fill.style.width      = `${pct}%`;
    fill.style.background = color || '#3b82f6';
  });

  socket.on(`scan:phase:${scanId}`, ({ phase, state }) => {
    const map = { 1:1, 2:2, 3:3, 4:4, recon:1, web:2, vuln:3, intel:4, rep:4 };
    const num  = map[phase] || parseInt(phase) || 1;
    const card   = document.getElementById(`fase-${num}`);
    const estado = document.getElementById(`fase-${num}-estado`);
    if (!card || !estado) return;
    card.className     = `fase-card ${state}`;
    estado.className   = `fase-estado ${state}`;
    estado.textContent = state === 'running' ? '⚡ A executar' : state === 'done' ? ' Concluído' : 'Aguarda';
  });

  socket.on(`scan:done:${scanId}`, ({ duration, totalFindings, counts }) => {
    console.log('[Scan] Concluído:', { duration, totalFindings });
    document.getElementById('progress-label').textContent     = ' Scan concluído!';
    document.getElementById('progress-pct').textContent       = '100%';
    document.getElementById('progress-fill').style.width      = '100%';
    document.getElementById('progress-fill').style.background = '#22c55e';
    [1, 2, 3, 4].forEach(i => {
      document.getElementById(`fase-${i}`).className = 'fase-card done';
      const e = document.getElementById(`fase-${i}-estado`);
      e.className = 'fase-estado done'; e.textContent = ' Concluído';
    });
    const btn = document.getElementById('btn-iniciar-scan');
    btn.disabled = false; btn.innerHTML = '<span></span> Novo Scan';
    setTimeout(() => carregarResultadosScan(scanAtual, target), 1000);
  });

  //  Debug — mostra eventos na consola do browser
  socket.onAny((ev, data) => {
    if (ev.includes(scanId))
      console.log('[WS]', ev, data?.text?.substring(0,60) || data?.pct || data?.phase || '');
  });
}

function adicionarLinhaTerminal(ts, text, level) {
  const terminal = document.getElementById('terminal');
  const linha    = document.createElement('div');
  linha.className = 'log-line';
  const hora = ts ? new Date(ts).toLocaleTimeString('pt-PT') : new Date().toLocaleTimeString('pt-PT');
  linha.innerHTML = `<span class="log-ts">[${hora}]</span><span class="log-text ${level || 'info'}">${escapeHtml(text)}</span>`;
  terminal.appendChild(linha);
  terminal.scrollTop = terminal.scrollHeight;
}

function escapeHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ─── RESULTADOS ───────────────────────────────────────────────────────────────
async function carregarResultadosScan(scanId, target) {
  try {
    const res = await fetch(`${API}/api/scan/${scanId}`, { headers:{'Authorization':`Bearer ${token}`} });
    if (!res.ok) return;
    const data = await res.json();
    const scan = data.scan || data;
    ultimosResultados = scan;
    renderizarResultados(scan, target);
    navegar('resultados');
  } catch (e) { console.error('Erro ao carregar resultados:', e); }
}

function renderizarResultados(scan, target) {
  const summary  = scan.summary  || scan.resumo || {};
  const findings = scan.findings || scan.vulnerabilidades || [];
  const corrs    = scan.correlations || scan.correlacoes || [];

  document.getElementById('resultados-alvo').textContent =
    `Alvo: ${scan.target||scan.alvo||target} — Modo: ${scan.mode||scan.modo} — Duração: ${scan.duration||scan.duracao||'?'}s`;
  document.getElementById('resultados-vazio').style.display    = 'none';
  document.getElementById('resultados-conteudo').style.display = 'block';

  const counts   = summary.counts || {};
  const criticos = counts.CRITICAL ?? summary.criticos ?? 0;
  const altos    = counts.HIGH     ?? summary.altos    ?? 0;
  const total    = summary.totalFindings ?? summary.total ?? findings.length;
  const score    = summary.riskScore ?? summary.scoreGlobal ?? summary.pontuacao ?? '—';

  document.getElementById('metrics-grid').innerHTML = `
    <div class="metric-card score"><div class="metric-num">${score}</div><div class="metric-label">Score Global</div></div>
    <div class="metric-card critical"><div class="metric-num">${criticos}</div><div class="metric-label"> Críticos</div></div>
    <div class="metric-card high"><div class="metric-num">${altos}</div><div class="metric-label"> Altos</div></div>
    <div class="metric-card total"><div class="metric-num">${total}</div><div class="metric-label">Total Findings</div></div>`;

  const cs = document.getElementById('correlacoes-section');
  cs.innerHTML = corrs.length
    ? `<div class="section-title">⚡ Riscos Compostos</div>` + corrs.map(c=>`
        <div class="correlacao-card">
          <div class="correlacao-icon">⚡</div>
          <div class="correlacao-info">
            <div class="correlacao-titulo">${escapeHtml(c.label||c.titulo||'')}</div>
            <div class="correlacao-desc">${escapeHtml(c.desc||c.descricao||'')}</div>
          </div>
          <div class="correlacao-badge">${c.score||''}</div>
        </div>`).join('') : '';

  const fl = document.getElementById('findings-list');
  fl.innerHTML = findings.length === 0
    ? `<div class="empty-state"><div class="empty-icon"></div><h3>Sem findings</h3><p>Nenhuma vulnerabilidade detetada</p></div>`
    : findings.map((f,i) => {
        const titulo = f.title    || f.titulo    || '—';
        const sev    = f.severity || f.severidade || 'INFO';
        const desc   = f.description || f.descricao || '';
        const rem    = f.remediation || f.remediacao || '';
        const tool   = f.tool    || f.ferramenta  || '';
        return `<div class="finding-card" id="finding-${i}">
          <div class="finding-header" onclick="toggleFinding(${i})">
            <span class="sev-badge sev-${sev}">${sev}</span>
            <span class="finding-titulo">${escapeHtml(titulo)}</span>
            <span class="finding-score">${f.score||''}</span>
            <span class="finding-toggle">▼</span>
          </div>
          <div class="finding-body">
            <div class="finding-meta">
              ${tool  ?`<span>${escapeHtml(tool)}</span>`:''}
              ${f.port?`<span>Porto ${f.port}</span>`:''}
              ${f.url ?`<span><a href="${escapeHtml(f.url)}" target="_blank" style="color:var(--accent2)">${escapeHtml(f.url)}</a></span>`:''}
            </div>
            ${desc?`<div class="finding-desc">${escapeHtml(desc)}</div>`:''}
            ${rem ?`<div class="finding-remediacao"><strong> Remediação:</strong> ${escapeHtml(rem)}</div>`:''}
          </div>
        </div>`;
      }).join('');
}

function toggleFinding(i) { document.getElementById(`finding-${i}`)?.classList.toggle('expanded'); }

// ─── HISTÓRICO ────────────────────────────────────────────────────────────────
async function carregarHistorico() {
  try {
    const res = await fetch(`${API}/api/scan/history`, { headers:{'Authorization':`Bearer ${token}`} });
    if (!res.ok) return;
    const { scans = [] } = await res.json();
    const tbody = document.getElementById('historico-tbody');
    if (!scans.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:3rem;color:var(--muted)">Sem scans no histórico</td></tr>';
      return;
    }
    tbody.innerHTML = scans.map(s => {
      const data2     = new Date(s.scannedAt||s.criadoEm||s.data).toLocaleString('pt-PT');
      const estado    = s.status||s.estado||'concluido';
      const estadoCls = (estado==='completed'||estado==='concluido') ? 'estado-concluido'
                      : (estado==='running'||estado==='a_executar')  ? 'estado-a_executar' : 'estado-erro';
      const risk  = s.riskLevel||s.nivelRisco||s.summary?.riskLevel||s.summary?.scoreGlobal||'—';
      const total = s.totalFindings??s.summary?.total??'—';
      const id    = s.id||s._id||s.scanId;
      return `<tr>
        <td style="font-family:var(--mono);font-size:.82rem;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(s.target||s.alvo)}</td>
        <td>${s.mode||s.modo||'—'}</td>
        <td><span class="estado-badge ${estadoCls}">${estado}</span></td>
        <td style="font-family:var(--mono)">${risk}</td>
        <td>${total}</td>
        <td style="color:var(--muted);font-size:.8rem">${data2}</td>
        <td><button class="btn-ver" onclick="verScan('${id}','${escapeHtml(s.target||s.alvo)}')">Ver</button></td>
      </tr>`;
    }).join('');
  } catch (e) { console.error('Erro histórico:', e); }
}

async function verScan(scanId, target) {
  try {
    const res = await fetch(`${API}/api/scan/${scanId}`, { headers:{'Authorization':`Bearer ${token}`} });
    if (!res.ok) return alert('Erro ao carregar scan');
    const data = await res.json();
    const scan = data.scan||data;
    ultimosResultados = scan;
    renderizarResultados(scan, target);
    navegar('resultados');
  } catch (e) { alert('Erro ao carregar scan'); }
}

// ─── RELATÓRIOS ───────────────────────────────────────────────────────────────
async function carregarRelatorios() {
  try {
    const res = await fetch(`${API}/api/reports`, { headers:{'Authorization':`Bearer ${token}`} });
    if (!res.ok) return;
    const data       = await res.json();
    const relatorios = data.reports||data.relatorios||[];
    const grid       = document.getElementById('relatorios-grid');
    if (!relatorios.length) {
      grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1"><div class="empty-icon"></div><h3>Sem relatórios</h3><p>Os relatórios aparecem aqui após concluir scans</p></div>`;
      return;
    }
    grid.innerHTML = relatorios.map(r => {
      const data2    = new Date(r.scannedAt||r.criadoEm).toLocaleDateString('pt-PT');
      const criticos = r.summary?.counts?.CRITICAL??r.summary?.criticos??0;
      const total2   = r.totalFindings??r.summary?.total??0;
      const id       = r.id||r._id||r.scanId;
      return `<div class="relatorio-card">
        <div class="relatorio-alvo">${escapeHtml(r.target||r.alvo)}</div>
        <div class="relatorio-meta">
          <span>${r.mode||r.modo}</span><span>${data2}</span>
          <span>${criticos} críticos</span><span>${total2} findings</span>
        </div>
        <div class="export-btns">
          <button class="btn-export html" onclick="exportarRelatorio('${id}','html')">HTML</button>
          <button class="btn-export md"   onclick="exportarRelatorio('${id}','markdown')">Markdown</button>
          <button class="btn-export json" onclick="exportarRelatorio('${id}','json')">JSON</button>
        </div>
      </div>`;
    }).join('');
  } catch (e) { console.error('Erro relatórios:', e); }
}

async function exportarRelatorio(id, formato) {
  try {
    const res = await fetch(`${API}/api/reports/${id}/export?format=${formato}`, { headers:{'Authorization':`Bearer ${token}`} });
    if (!res.ok) return alert('Erro ao exportar relatório');
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `britofscan_${id.substring(0,8)}.${formato==='markdown'?'md':formato}`;
    a.click(); URL.revokeObjectURL(url);
  } catch (e) { alert('Erro ao exportar'); }
}

// ─── FERRAMENTAS ──────────────────────────────────────────────────────────────
function renderizarFerramentas() {
  const f = {
    fase1:[
      {nome:'whois',       desc:'Informações de registo de domínio'},
      {nome:'nmap',        desc:'Scan de portos e serviços (-sT -Pn)'},
      {nome:'dnsrecon',    desc:'Enumeração DNS'},
      {nome:'sublist3r',   desc:'Subdomínios passivos via OSINT'},
      {nome:'amass',       desc:'Enumeração passiva avançada'},
      {nome:'gobuster',    desc:'Brute force de subdomínios e dirs'},
      {nome:'theHarvester',desc:'Subdomínios e e-mails via Certificate Transparency (crtsh)'},
    ],
    fase2:[
      {nome:'waf-detect',  desc:'Deteção WAF (Cloudflare, Akamai...)'},
      {nome:'nikto',       desc:'Scanner de vulnerabilidades web'},
      {nome:'nuclei',      desc:'Templates de vulnerabilidades'},
      {nome:'ssl-check',   desc:'Análise protocolo e certificado SSL/TLS'},
      {nome:'file-scanner',desc:'Ficheiros sensíveis (.env, .git...)'},
    ],
    fase3:[
      {nome:'header-audit', desc:'Auditoria 7 headers de segurança'},
      {nome:'cookie-audit', desc:'Flags HttpOnly, Secure, SameSite'},
      {nome:'http-methods', desc:'Métodos perigosos PUT/DELETE/TRACE'},
      {nome:'cve-correlate',desc:'Correlação CVE com versões detetadas'},
    ],
  };
  const cards = (lista, cls) => lista.map(t=>`
    <div class="ferramenta-card">
      <div class="ferramenta-nome">${t.nome}</div>
      <div class="ferramenta-desc">${t.desc}</div>
      <span class="ferramenta-fase ${cls}">Fase ${cls.replace('fase-','')}</span>
    </div>`).join('');
  document.getElementById('tools-fase1').innerHTML = cards(f.fase1,'fase-1');
  document.getElementById('tools-fase2').innerHTML = cards(f.fase2,'fase-2');
  document.getElementById('tools-fase3').innerHTML = cards(f.fase3,'fase-3');
}

// ─── INICIALIZAÇÃO ────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('login-password')?.addEventListener('keydown', e => { if(e.key==='Enter') fazerLogin(); });
  document.getElementById('reg-password')?.addEventListener('keydown',  e => { if(e.key==='Enter') fazerRegisto(); });
  carregarSessao();
  if (token && utilizador) iniciarApp();
});