'use strict';

/**
 * Campaign definition — L5 dynamic oracle.
 *
 * gate spec 与 out/l5/summary.json 的 gates 一一对应；runner 默认只跑 target probe，
 * fixtures/select/report 由显式 CLI 或 audit 编排执行。
 */

function ok(pass, detail) {
  return { pass: Boolean(pass), detail };
}

const GATES = [
  ['L5-1 environment', 'l5-environment'],
  ['L5-2 fixtures', 'l5-fixtures'],
  ['L5-3 target probe', 'l5-target-probe'],
  ['L5-4 ledger', 'l5-ledger'],
  ['L5-5 classifier/repeat', 'l5-classifier'],
  ['L5-6 O10/promotion', 'l5-promotion'],
  ['L5-7 scope', 'l5-scope'],
  ['L5-8 report', 'l5-report']
];

module.exports = {
  id: 'l5',
  name: 'L5 (Dynamic Oracle)',
  order: 50,
  defaultRun: false,
  summary: 'out/l5/summary.json',
  runner: 'bin/l5.js',
  defaultArgs: ['--target'],
  liveArgs: ['--target'],
  artifacts: [
    'out/l5/environment.json',
    'out/l5/fixtures-summary.json',
    'out/l5/select-summary.json',
    'out/l5/targets-summary.json',
    'out/l5/promotion-summary.json',
    'out/l5/summary.json',
    'out/report/l5.md'
  ],
  gates: GATES.map(([name, key]) => ({ key, name, evaluate: (ctx) => ok(ctx.l5 && ctx.l5.allGatesPass === true, name) }))
};
