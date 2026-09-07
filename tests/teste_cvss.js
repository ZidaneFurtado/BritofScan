// tests/teste_cvss.js
//
// Valida o motor de calculo CVSS v3.1 (api/modules/scoringCVSS.js) contra
// 5 casos de referencia com resultados conhecidos, incluindo os dois
// valores-fronteira da norma (0.0 e 10.0) e uma correspondencia direta
// com o score publicado pelo NVD para uma CVE real usada no projeto.
//
// Execucao: node tests/teste_cvss.js

const path = require('path');
const { calcularCVSS, VETORES_CVE } = require(
  path.join(__dirname, '..', 'api', 'modules', 'scoringCVSS.js')
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

console.log('=== VALIDAÇÃO DO MOTOR CVSS v3.1 ===\n');

// Caso 1: vetor crítico clássico (RCE remoto sem autenticação)
// Referência: calculadora oficial FIRST.org para este vetor = 9.8
const r1 = calcularCVSS('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
afirmar(Math.abs(r1.score - 9.8) < 0.15, `Vetor crítico clássico -> ${r1.score} (esperado ~9.8, CRITICAL)`);
afirmar(r1.severidade === 'CRITICAL', `Severidade classificada corretamente como CRITICAL`);

// Caso 2: impacto reduzido, só confidencialidade baixa
// Referência: calculadora oficial FIRST.org para este vetor = 5.3
const r2 = calcularCVSS('AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N');
afirmar(Math.abs(r2.score - 5.3) < 0.15, `Vetor de baixo impacto -> ${r2.score} (esperado ~5.3, MEDIUM)`);

// Caso 3: correspondência direta com o NVD — CVE-2018-15473 (enumeração
// de utilizadores OpenSSH), usada no projeto para correlação real.
// O NVD publica um score de 5.3 (MEDIUM) para esta CVE.
const vetorCVE = VETORES_CVE['CVE-2018-15473'];
const r3 = calcularCVSS(vetorCVE);
afirmar(vetorCVE !== undefined, `Vetor da CVE-2018-15473 está definido no mapa do projeto`);
afirmar(Math.abs(r3.score - 5.3) < 0.15, `CVE-2018-15473: score calculado (${r3.score}) coincide com o NVD (5.3, MEDIUM)`);

// Caso 4: valor-fronteira superior — scope alterado, impacto total
// Referência: calculadora oficial FIRST.org para este vetor = 10.0
const r4 = calcularCVSS('AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
afirmar(r4.score === 10, `Valor-fronteira superior (scope alterado) -> ${r4.score} (esperado exatamente 10.0)`);

// Caso 5: valor-fronteira inferior — sem impacto algum
// Referência: a norma CVSS define que ausência de impacto = score 0.0
const r5 = calcularCVSS('AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N');
afirmar(r5.score === 0, `Valor-fronteira inferior (sem impacto) -> ${r5.score} (esperado exatamente 0.0)`);
afirmar(r5.severidade === 'NONE', `Severidade classificada corretamente como NONE`);

console.log('\n' + (falhas === 0
  ? 'TODOS OS TESTES PASSARAM (8 verificações).'
  : `${falhas} TESTE(S) FALHARAM — rever scoringCVSS.js.`));

process.exit(falhas === 0 ? 0 : 1);
