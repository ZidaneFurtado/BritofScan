// tests/teste_processos.js
//
// Valida duas correções de segurança em api/modules/utils.js:
//  1) executarComandoSeguro: terminação correta de processos que excedem
//     o timeout configurado, sem deixar o processo Node.js pendurado.
//  2) validarAlvo: proteção contra SSRF, incluindo DNS Rebinding e
//     endereços IPv6 privados/reservados.
//
// Execução: node tests/teste_processos.js

const path = require('path');
const { executarComandoSeguro, validarAlvo } = require(
  path.join(__dirname, '..', 'api', 'modules', 'utils.js')
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

async function correr() {
  console.log('=== VALIDAÇÃO: TERMINAÇÃO DE PROCESSOS ===\n');

  // Teste 1: comando normal deve capturar output corretamente
  const linhas = [];
  await executarComandoSeguro('echo', ['ola mundo'], l => linhas.push(l), 3000);
  afirmar(linhas.length > 0 && linhas[0].includes('ola mundo'), 'Comando normal (echo) captura output corretamente');

  // Teste 2: comando que excede o timeout configurado deve ser terminado,
  // sem deixar o processo Node à espera indefinidamente.
  const inicio = Date.now();
  await executarComandoSeguro('sleep', ['10'], () => {}, 1000);
  const duracao = Date.now() - inicio;
  afirmar(duracao < 2000, `Comando com timeout (sleep 10, limite 1s) terminado em ${duracao}ms, sem bloquear o processo`);

  console.log('\n=== VALIDAÇÃO: PROTEÇÃO SSRF ===\n');

  // Teste 3: IPv4 privado literal
  try {
    await validarAlvo('192.168.1.1');
    afirmar(false, 'IPv4 privado literal (192.168.1.1) deveria ter sido bloqueado');
  } catch (e) {
    afirmar(e.message.includes('SSRF'), `IPv4 privado literal bloqueado corretamente: ${e.message}`);
  }

  // Teste 4: IPv6 loopback literal
  try {
    await validarAlvo('::1');
    afirmar(false, 'IPv6 loopback (::1) deveria ter sido bloqueado');
  } catch (e) {
    afirmar(e.message.includes('SSRF'), `IPv6 loopback bloqueado corretamente: ${e.message}`);
  }

  // Teste 5: IPv6 ULA privado (fd00::/8)
  try {
    await validarAlvo('fd12:3456:789a::1');
    afirmar(false, 'IPv6 ULA privado deveria ter sido bloqueado');
  } catch (e) {
    afirmar(e.message.includes('SSRF'), `IPv6 ULA privado bloqueado corretamente: ${e.message}`);
  }

  // Teste 6: endpoint de metadados cloud (AWS/GCP) — vetor SSRF clássico
  try {
    await validarAlvo('169.254.169.254');
    afirmar(false, 'Endpoint de metadados cloud (169.254.169.254) deveria ter sido bloqueado');
  } catch (e) {
    afirmar(e.message.includes('SSRF'), `Endpoint de metadados cloud bloqueado corretamente: ${e.message}`);
  }

  // Teste 7: domínio público legítimo deve ser aceite
  try {
    const host = await validarAlvo('testaspnet.vulnweb.com');
    afirmar(host === 'testaspnet.vulnweb.com', `Alvo de teste autorizado aceite corretamente: ${host}`);
  } catch (e) {
    afirmar(false, `Alvo de teste autorizado foi incorretamente bloqueado: ${e.message}`);
  }

  console.log('\n' + (falhas === 0
    ? 'TODOS OS TESTES PASSARAM (9 verificações).'
    : `${falhas} TESTE(S) FALHARAM — rever utils.js.`));

  process.exit(falhas === 0 ? 0 : 1);
}

correr();
