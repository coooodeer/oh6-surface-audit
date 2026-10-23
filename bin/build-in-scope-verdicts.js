'use strict';

/**
 * build-in-scope-verdicts.js —— 只从 L4a verdicts 生成 R1 本仓统计。
 *
 * 用法：node bin/build-in-scope-verdicts.js
 * 产物：out/verdicts/in-scope-verdicts.jsonl、out/verdicts/summary.json、out/report/in-scope-findings.md
 */

const path = require('path');
const { OUT_ROOT, readJsonl } = require('../lib/util.js');
const { buildInScope, writeInScope } = require('../lib/in-scope.js');

function main() {
  const p3Verdicts = readJsonl(path.join(OUT_ROOT, 'l4a', 'p3-verdicts.jsonl'));
  const p4Verdicts = readJsonl(path.join(OUT_ROOT, 'l4a', 'p4-verdicts.jsonl'));
  const p6Verdicts = readJsonl(path.join(OUT_ROOT, 'l4a', 'p6-verdicts.jsonl'));
  const p4Candidates = readJsonl(path.join(OUT_ROOT, 'p4', 'candidates.jsonl'));
  const p3Unreachable = readJsonl(path.join(OUT_ROOT, 'l3', 'p3-unreachable.jsonl'));
  const result = buildInScope({ p3Verdicts, p4Verdicts, p6Verdicts, p4Candidates, p3Unreachable });
  writeInScope(OUT_ROOT, result);
  const h = result.summary.headline;
  process.stdout.write(`R1 in-scope: T1=${h.newConfirmed} T2=${h.newWeakUnits} units/${h.newWeakClaims} claims T3=${h.instrumentationGap} excluded=${result.summary.excluded.total}\n`);
}

if (require.main === module) main();

module.exports = { main };
