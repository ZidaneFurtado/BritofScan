// teste_xss.js - Testes adversariais e de regressao para reportGenerator.js
//
// Testes adversariais: confirmam que payloads de XSS armazenados em campos
// de finding (titulo, descricao, remediacao, ferramenta, cve) NUNCA
// aparecem sem escape no HTML/Markdown gerado.
//
// Testes de regressao: confirmam que findings normais (sem payloads)
// continuam a ser apresentados corretamente, sem perda de informacao.

const path = require('path');
const { gerarRelatorio } = require(
  path.join(__dirname, '..', 'api', 'modules', 'reportGenerator.js')
);

let falhas = 0;
function afirmar(condicao, descricao) {
  if (condicao) {
    console.log('OK   ', descricao);
  } else {
    falhas++;
    console.log('FALHA', descricao);
  }
}

// ── Payloads adversariais comuns ────────────────────────────────────────────
const PAYLOADS = [
  '<script>alert(document.cookie)</script>',
  '"><img src=x onerror=alert(localStorage.getItem("britofscan_token"))>',
  "<svg/onload=alert('xss')>",
  "'-alert(1)-'",
];

function scanComPayload(payload) {
  return {
    id: 'scan-teste', target: 'testaspnet.vulnweb.com', mode: 'stealth',
    createdAt: new Date().toISOString(), duration: 10,
    summary: { total: 1, criticos: 1, altos: 0, medios: 0, baixos: 0, info: 0, scoreGlobal: 9.5 },
    correlacoes: [],
    findings: [{
      titulo: `Nikto: ${payload}`,
      descricao: `Output malicioso: ${payload}`,
      ferramenta: payload,
      fase: 2,
      severidade: 'CRITICAL',
      score: 9.5,
      cve: null,
      remediacao: `Corrigir: ${payload}`,
    }],
  };
}

console.log('=== TESTES ADVERSARIAIS (XSS armazenado) ===\n');

PAYLOADS.forEach((payload, i) => {
  const scan = scanComPayload(payload);

  const html = gerarRelatorio(scan, 'html').conteudo;
  afirmar(!html.includes(payload), `Payload #${i + 1} NAO aparece em bruto no HTML`);
  // Verifica que nao existe nenhuma tag HTML real (nao escapada) originada
  // do payload - isto e o que importa: o texto do payload pode continuar
  // presente como conteudo inerte (ex: "&lt;svg&gt;"), o que e o
  // comportamento correto; o que NUNCA pode acontecer e uma tag real
  // interpretavel pelo browser.
  const semTagsReais = !/<script[^&]/.test(html) && !/<svg[^&]/.test(html) && !/<img[^&]/.test(html);
  afirmar(semTagsReais, `Payload #${i + 1} nao gera nenhuma tag HTML real (apenas texto escapado)`);

  const md = gerarRelatorio(scan, 'markdown').conteudo;
  afirmar(!md.includes(payload), `Payload #${i + 1} NAO aparece em bruto no Markdown`);
});

console.log('\n=== TESTE DE REGRESSAO (finding normal, sem payload) ===\n');

const scanNormal = {
  id: 'scan-normal', target: 'testaspnet.vulnweb.com', mode: 'stealth',
  createdAt: new Date().toISOString(), duration: 337,
  summary: { total: 1, criticos: 1, altos: 0, medios: 0, baixos: 0, info: 0, scoreGlobal: 8.4 },
  correlacoes: [],
  findings: [{
    titulo: 'Porto 21/tcp aberto - ftp',
    descricao: 'FTP inseguro - usar SFTP.',
    ferramenta: 'nmap',
    fase: 1,
    severidade: 'CRITICAL',
    score: 8.4,
    cve: null,
    remediacao: 'Verificar se ftp e necessario. Fechar portos desnecessarios.',
  }],
};

const htmlNormal = gerarRelatorio(scanNormal, 'html').conteudo;
afirmar(htmlNormal.includes('Porto 21/tcp aberto - ftp'), 'Titulo normal aparece corretamente no HTML');
afirmar(htmlNormal.includes('FTP inseguro - usar SFTP.'), 'Descricao normal aparece corretamente no HTML');
afirmar(htmlNormal.includes('8.4'), 'Score aparece corretamente no HTML');

const mdNormal = gerarRelatorio(scanNormal, 'markdown').conteudo;
afirmar(mdNormal.includes('Porto 21/tcp aberto - ftp'), 'Titulo normal aparece corretamente no Markdown');

// Caracteres acentuados/especiais legitimos (nao devem ser corrompidos)
const scanAcentos = {
  ...scanNormal,
  findings: [{ ...scanNormal.findings[0], descricao: 'Configuração incorreta: níveis de permissão excessivos.' }],
};
const htmlAcentos = gerarRelatorio(scanAcentos, 'html').conteudo;
afirmar(htmlAcentos.includes('Configuração incorreta: níveis de permissão excessivos.'),
  'Caracteres acentuados (não-payload) preservados corretamente');

console.log('\n' + (falhas === 0
  ? `TODOS OS TESTES PASSARAM (${PAYLOADS.length * 3 + 5} verificacoes).`
  : `${falhas} TESTE(S) FALHARAM - rever escapeHtml.`));

process.exit(falhas === 0 ? 0 : 1);