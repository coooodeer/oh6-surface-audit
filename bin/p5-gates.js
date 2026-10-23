'use strict';

/**
 * p5-gates.js —— P5 §7 门禁汇总。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, readJsonl, writeJson } = require('../lib/util.js');
const { runGates } = require('../lib/agent/registry');

function readJson(file) {
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : null;
}

function main() {
  const audit = readJson(path.join(OUT_ROOT, 'p5', 'data-audit.json'));
  const fixtures = readJson(path.join(OUT_ROOT, 'p5', 'fixture-summary.json'));
  const l4b = readJson(path.join(OUT_ROOT, 'p5', 'l4b-summary.json'));
  const claims = readJsonl(path.join(OUT_ROOT, 'p5', 'claims.jsonl'));
  const verdicts = readJsonl(path.join(OUT_ROOT, 'p5', 'verdicts.jsonl'));
  const calibration = readJson(path.join(OUT_ROOT, 'report', 'p5-calibration-summary.json'));
  const oldRun = readJson(path.join(OUT_ROOT, 'report', 'run-summary.json'));
  const claimSummary = readJson(path.join(OUT_ROOT, 'p5', 'claim-summary.json'));
  const p5Summary = readJson(path.join(OUT_ROOT, 'verdicts', 'p5-summary.json'));

  const noHuman = ['out/p5/claims.jsonl', 'out/p5/verdicts.jsonl', 'out/verdicts/p5-in-scope-verdicts.jsonl'].every((f) => {
    const p = path.join(OUT_ROOT, '..', f);
    return fs.existsSync(p) && !/needs-human|"pending"|: pending/i.test(fs.readFileSync(p, 'utf8'));
  });

  const reportExists = fs.existsSync(path.join(OUT_ROOT, 'report', 'p5-implementation.md'));
  const gates = runGates('p5', {
    audit, fixtures, l4b, claims, verdicts, calibration, oldRun, claimSummary, p5Summary,
    noHuman, reportExists
  });
  const liveBlocked = !l4b || l4b.simulated === true;
  const summary = {
    generatedAt: new Date().toISOString(),
    allGatesPass: gates.every((g) => g.pass),
    liveBlocked,
    l4bSimulated: l4b ? l4b.simulated === true : null,
    gates,
    headline: p5Summary ? p5Summary.headline : null,
    claimSummary
  };
  writeJson(path.join(OUT_ROOT, 'report', 'p5-run-summary.json'), summary);
  const lines = ['# P5 门禁汇总', '', `生成时间：${summary.generatedAt}`, '', `- allGatesPass：**${summary.allGatesPass}**`, `- liveBlocked：${summary.liveBlocked}（${summary.l4bSimulated ? 'L4b mock；endpoint 连续 timeout，已记录' : 'L4b live'}）`, '', '| 门 | 结果 | 证据 |', '| --- | --- | --- |'];
  for (const g of gates) lines.push(`| ${g.name} | ${g.pass ? '✅ PASS' : '❌ FAIL'} | ${g.detail || ''} |`);
  lines.push('');
  fs.writeFileSync(path.join(OUT_ROOT, 'report', 'p5-gates.md'), lines.join('\n'), 'utf8');
  process.stdout.write(`P5 gates: ${gates.filter((g) => g.pass).length}/${gates.length} pass; liveBlocked=${liveBlocked}\n`);
  for (const g of gates.filter((x) => !x.pass)) process.stdout.write(`  FAIL ${g.name}: ${g.detail}\n`);
  return summary;
}

if (require.main === module) {
  try {
    const s = main();
    process.exit(s.allGatesPass ? 0 : 3);
  } catch (e) {
    process.stderr.write(`${e && e.stack ? e.stack : e}\n`);
    process.exit(1);
  }
}

module.exports = { main };
