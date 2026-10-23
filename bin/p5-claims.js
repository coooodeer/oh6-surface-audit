'use strict';

/**
 * p5-claims.js —— 从 P5 audit 产物生成 L3 claim。
 */

const path = require('path');
const { OUT_ROOT, readJsonl } = require('../lib/util.js');
const { buildP5Claims, writeP5Claims } = require('../lib/p5-claims.js');
const { loadL1 } = require('../lib/l1.js');

function main() {
  const units = readJsonl(path.join(OUT_ROOT, 'p5', 'method-units.jsonl'));
  const pairing = readJsonl(path.join(OUT_ROOT, 'p5', 'pairing.jsonl'));
  const paths = readJsonl(path.join(OUT_ROOT, 'p5', 'paths.jsonl'));
  const result = buildP5Claims({ units, pairing, paths, l1: loadL1() });
  writeP5Claims(result);
  const s = result.summary;
  process.stdout.write(`P5 claims: total=${s.total} pathScoped=${s.pathScopedSelected} noCheck=${s.noCheckSelected} supplementary=${s.supplementary}\n`);
  process.stdout.write(`verdict=${JSON.stringify(s.claimVerdict)} product=${JSON.stringify(s.productVerdict)}\n`);
  process.stdout.write(`available=${JSON.stringify(s.available)}\n`);
}

if (require.main === module) {
  try { main(); } catch (e) { process.stderr.write(`${e && e.stack ? e.stack : e}\n`); process.exit(1); }
}

module.exports = { main };
