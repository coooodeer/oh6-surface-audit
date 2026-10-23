'use strict';

/**
 * p5-calibration.js —— P5 3 轮抽样复核。
 */

const path = require('path');
const { OUT_ROOT, readJsonl } = require('../lib/util.js');
const { runP5Calibration } = require('../lib/p5-calibration.js');

function main() {
  const claims = readJsonl(path.join(OUT_ROOT, 'p5', 'claims.jsonl'));
  const l4bResults = readJsonl(path.join(OUT_ROOT, 'p5', 'l4b-results.jsonl'));
  const result = runP5Calibration({ claims, l4bResults, rounds: 3, nPerSide: 10 });
  const s = result.summary;
  process.stdout.write(`P5 calibration: rounds=${s.rounds.length} samples=${s.totalSampled} falseVuln=${s.falseProvenVuln} pass=${s.pass}\n`);
  if (!s.pass) process.exit(2);
}

if (require.main === module) {
  try { main(); } catch (e) { process.stderr.write(`${e && e.stack ? e.stack : e}\n`); process.exit(1); }
}

module.exports = { main };
