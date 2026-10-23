'use strict';

/**
 * Campaign definition — L7 finding/report/delivery.
 */

function ok(pass, detail) {
  return { pass: Boolean(pass), detail };
}

const GATES = [
  ['l7-card-schema', 'l7-card-schema'],
  ['l7-coverage', 'l7-coverage'],
  ['l7-refs-resolve', 'l7-refs-resolve'],
  ['l7-tier-discipline', 'l7-tier-discipline'],
  ['l7-severity', 'l7-severity'],
  ['l7-deterministic', 'l7-deterministic'],
  ['l7-delivery', 'l7-delivery'],
  ['l7-report', 'l7-report']
];

module.exports = {
  id: 'l7',
  name: 'L7 (Reporter/Delivery)',
  order: 60,
  defaultRun: false,
  summary: 'out/report/l7-summary.json',
  runner: 'bin/report.js',
  defaultArgs: ['--all', '--delivery'],
  liveArgs: ['--all', '--delivery'],
  artifacts: [
    'out/report/findings.jsonl',
    'out/report/observations.jsonl',
    'out/report/excluded.jsonl',
    'out/report/FINDINGS.md',
    'out/report/EXECUTIVE-SUMMARY.md',
    'out/report/l7-summary.json',
    'out/delivery/manifest.json',
    'out/delivery/SHA256SUMS'
  ],
  gates: GATES.map(([name, key]) => ({ key, name, evaluate: (ctx) => ok(ctx.l7 && ctx.l7.allGatesPass === true, name) }))
};
