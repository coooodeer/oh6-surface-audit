'use strict';

/**
 * p3-prove.js —— P3 兼容入口：25 条 claim + 20 条 fixture 的 L4a 判定。
 * 端到端 runner 见 bin/run-p3p4p6.js。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');
const { loadL1 } = require('../lib/l1.js');
const { loadL2 } = require('../lib/l2.js');
const { selectP3Candidates } = require('../lib/claims.js');
const { proveP3Claims, proveFixtures } = require('../lib/prover-p3.js');

function main() {
  const out = path.join(OUT_ROOT, 'p3');
  ensureDir(out);
  const l1 = loadL1();
  const l2 = loadL2(l1);
  const sel = selectP3Candidates(l1, l2);
  const real = proveP3Claims(sel.claims, l1, l2, { impactNotAssessed: true });
  const fixtures = proveFixtures(l1);
  writeJsonl(path.join(out, 'verdicts.jsonl'), [...real, ...fixtures]);
  const count = (rows, f) => rows.reduce((a, r) => { a[r[f]] = (a[r[f]] || 0) + 1; return a; }, {});
  const summary = {
    generatedAt: new Date().toISOString(),
    real: { total: real.length, claimVerdict: count(real, 'claimVerdict'), productVerdict: count(real, 'productVerdict') },
    fixtures: { total: fixtures.length, claimVerdict: count(fixtures, 'claimVerdict') },
    fixtureGate: {
      originals: fixtures.filter((r) => r.variant === 'original').length,
      mutants: fixtures.filter((r) => r.variant === 'mutant').length,
      originalSatisfied: fixtures.filter((r) => r.variant === 'original' && r.claimVerdict === 'SATISFIED').length,
      mutantViolation: fixtures.filter((r) => r.variant === 'mutant' && r.claimVerdict === 'VIOLATION').length
    }
  };
  writeJson(path.join(out, 'summary.json'), summary);
  const lines = [
    '# P3 蕴含式判定', '', `生成时间：${summary.generatedAt}`, '',
    `真实 claim ${real.length} 条：${JSON.stringify(summary.real.claimVerdict)}；product ${JSON.stringify(summary.real.productVerdict)}。`,
    `Fixture：原函数 SATISFIED ${summary.fixtureGate.originalSatisfied}/${summary.fixtureGate.originals}；mutant VIOLATION ${summary.fixtureGate.mutantViolation}/${summary.fixtureGate.mutants}。`,
    '', '口径：O2 unproven 时 O3 无 guard 也只能 UNPROVEN；O4-local proven 的 VIOLATION 只到 claim-candidate，product=PROVEN-WEAKNESS（impact 未实现）。', ''
  ];
  ensureDir(path.join(OUT_ROOT, 'report'));
  fs.writeFileSync(path.join(OUT_ROOT, 'report', 'p3.md'), lines.join('\n'), 'utf8');
  process.stdout.write(`P3 real=${real.length} ${JSON.stringify(summary.real.claimVerdict)}; fixtures ${summary.fixtureGate.originalSatisfied}/${summary.fixtureGate.mutantViolation}\n`);
}

if (require.main === module) main();

module.exports = { main };
