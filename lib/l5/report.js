'use strict';

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, ensureDir } = require('../util.js');

const REPORT = path.join(OUT_ROOT, 'report', 'l5.md');

function readJson(p, fallback = null) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (_) { return fallback; }
}

function writeL5Report() {
  const env = readJson(path.join(OUT_ROOT, 'l5', 'environment.json'), {});
  const fixtures = readJson(path.join(OUT_ROOT, 'l5', 'fixtures-summary.json'), {});
  const select = readJson(path.join(OUT_ROOT, 'l5', 'select-summary.json'), {});
  const targets = readJson(path.join(OUT_ROOT, 'l5', 'targets-summary.json'), {});
  const promotion = readJson(path.join(OUT_ROOT, 'l5', 'promotion-summary.json'), {});
  const gates = readJson(path.join(OUT_ROOT, 'l5', 'summary.json'), {});
  const lines = [];
  lines.push('# L5 Dynamic Oracle');
  lines.push('');
  lines.push(`- generatedAt：${new Date().toISOString()}`);
  lines.push(`- WSL：${env.distro || 'n/a'}`);
  lines.push(`- clang：${env.clang && env.clang.versionLine || 'n/a'}`);
  lines.push(`- compiler：${env.compiler || 'n/a'}（${env.compilerReason || 'n/a'}）`);
  lines.push(`- ASan/UBSan probe：${env.asan}/${env.ubsan}`);
  lines.push('');
  lines.push('## Fixtures');
  lines.push('');
  lines.push(`- total：${fixtures.total || 0}`);
  lines.push(`- confirmed：${fixtures.confirmed || 0}`);
  lines.push(`- no-signal：${fixtures.noSignal || 0}`);
  lines.push(`- blocked：${fixtures.blocked || 0}`);
  lines.push(`- expected：${fixtures.allExpected === true}`);
  lines.push('');
  if (Array.isArray(fixtures.rows)) {
    lines.push('| fixture | class | result | reason |');
    lines.push('| --- | --- | --- | --- |');
    for (const r of fixtures.rows) lines.push(`| ${r.id} | ${r.class} | ${r.result} | ${r.reason} |`);
    lines.push('');
  }
  lines.push('## Target probes');
  lines.push('');
  lines.push(`- total：${targets.total || 0}`);
  lines.push(`- confirmed：${targets.confirmed || 0}`);
  lines.push(`- no-signal：${targets.noSignal || 0}`);
  lines.push(`- blocked：${targets.blocked || 0}`);
  lines.push('');
  if (Array.isArray(targets.rows)) {
    lines.push('| target | class | result | reason |');
    lines.push('| --- | --- | --- | --- |');
    for (const r of targets.rows) lines.push(`| ${r.candidateId} | ${r.class} | ${r.result} | ${r.reason} |`);
    lines.push('');
  }
  lines.push('## Promotion');
  lines.push('');
  lines.push(`- total：${promotion.total || 0}`);
  lines.push(`- promoted：${promotion.promoted || 0}`);
  lines.push(`- T1：${promotion.t1 || 0}`);
  lines.push('');
  lines.push('## Gates');
  lines.push('');
  for (const g of (gates.gates || [])) lines.push(`- ${g.pass ? 'PASS' : 'FAIL'} ${g.name}: ${g.detail || ''}`);
  lines.push('');
  lines.push('## Candidates');
  lines.push('');
  lines.push(`- selected：${select.selected || 0}/${select.total || 0}`);
  lines.push(`- byClass：${JSON.stringify(select.byClass || {})}`);
  lines.push(`- unsupported：${select.unsupported || 0}（${JSON.stringify(select.unsupportedReasons || {})}）`);
  lines.push('');
  lines.push('## Scope');
  lines.push('');
  lines.push('- P1/P2/P3/P4/P7：host harness 候选；P5/P6/P8：需要 integration harness，当前 unsupported。');
  lines.push('- fixtures 只校准 build/run/classify/ledger，不映射生产 claim，不产生 T1。');
  lines.push('- no-signal 不是 safe；blocked 必须具名。');
  lines.push('');
  ensureDir(path.dirname(REPORT));
  fs.writeFileSync(REPORT, lines.join('\n'), 'utf8');
  const summary = require('./gates.js').buildL5Summary();
  return { report: 'out/report/l5.md', env, fixtures, select, summary };
}

module.exports = { REPORT, writeL5Report };
