'use strict';

/**
 * p5-report.js —— P5 R1 verdicts / summary / report。
 */

const path = require('path');
const fs = require('fs');
const { OUT_ROOT, readJsonl } = require('../lib/util.js');
const { buildP5Verdicts, writeP5Verdicts } = require('../lib/p5-verdicts.js');

function main() {
  const claims = readJsonl(path.join(OUT_ROOT, 'p5', 'claims.jsonl'));
  const audit = fs.existsSync(path.join(OUT_ROOT, 'p5', 'data-audit.json'))
    ? JSON.parse(fs.readFileSync(path.join(OUT_ROOT, 'p5', 'data-audit.json'), 'utf8')) : null;
  const fixtures = fs.existsSync(path.join(OUT_ROOT, 'p5', 'fixture-summary.json'))
    ? JSON.parse(fs.readFileSync(path.join(OUT_ROOT, 'p5', 'fixture-summary.json'), 'utf8')) : null;
  const l4b = fs.existsSync(path.join(OUT_ROOT, 'p5', 'l4b-summary.json'))
    ? JSON.parse(fs.readFileSync(path.join(OUT_ROOT, 'p5', 'l4b-summary.json'), 'utf8')) : null;
  const calibration = fs.existsSync(path.join(OUT_ROOT, 'report', 'p5-calibration-summary.json'))
    ? JSON.parse(fs.readFileSync(path.join(OUT_ROOT, 'report', 'p5-calibration-summary.json'), 'utf8')) : null;
  const result = buildP5Verdicts(claims, { audit, fixtures, l4b, calibration });
  const w = writeP5Verdicts(result);
  const s = result.summary;
  process.stdout.write(`P5 report: claims=${s.claims.total} T1=${s.headline.newConfirmed} T2=${s.headline.newWeak} T3=${s.headline.conditions} T4=${s.headline.negative}; inScopeRows=${w.inScopeRows}\n`);
}

if (require.main === module) {
  try { main(); } catch (e) { process.stderr.write(`${e && e.stack ? e.stack : e}\n`); process.exit(1); }
}

module.exports = { main };
