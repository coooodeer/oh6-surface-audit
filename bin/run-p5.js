'use strict';

/**
 * run-p5.js —— P5 端到端入口。
 *
 * 当前阶段：audit -> fixtures -> claims -> verdicts/report。
 * L4b/校准在后续轮次接入。
 */

const audit = require('./p5-audit.js');
const fixtures = require('./p5-fixtures.js');
const claims = require('./p5-claims.js');
const l4b = require('./p5-l4b-judge.js');
const calibration = require('./p5-calibration.js');
const report = require('./p5-report.js');
const gates = require('./p5-gates.js');

function main() {
  audit.main();
  fixtures.main();
  claims.main();
  l4b.main().then(() => {
    calibration.main();
    report.main();
    const s = gates.main();
    process.exit(s.allGatesPass ? 0 : 3);
  }).catch((e) => {
    process.stderr.write(`${e && e.stack ? e.stack : e}\n`);
    process.exit(1);
  });
}

if (require.main === module) {
  try { main(); } catch (e) { process.stderr.write(`${e && e.stack ? e.stack : e}\n`); process.exit(1); }
}

module.exports = { main };
