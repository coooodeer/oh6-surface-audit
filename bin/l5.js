#!/usr/bin/env node
'use strict';

/**
 * bin/l5.js —— L5 入口（environment / select / fixtures / target / report / promote）。
 */

const fs = require('fs');
const path = require('path');
const { probe } = require('../lib/l5/env.js');
const { runFixtures, FIXTURES } = require('../lib/l5/fixtures.js');
const { selectCandidates } = require('../lib/l5/select.js');
const { runTargets, TARGETS } = require('../lib/l5/harness.js');
const { promoteRows } = require('../lib/l5/promote.js');
const { writeL5Report } = require('../lib/l5/report.js');
const { OUT_ROOT } = require('../lib/util.js');

function parseArgs(argv) {
  const opts = { probe: false, fixtures: false, select: false, target: false, promote: false, report: false, json: false, ids: [], limit: 0, help: false };
  for (const a of argv) {
    if (a === '--probe') opts.probe = true;
    else if (a === '--fixtures') opts.fixtures = true;
    else if (a === '--select' || a === '--candidates') opts.select = true;
    else if (a === '--target') opts.target = true;
    else if (a === '--promote') opts.promote = true;
    else if (a === '--report') opts.report = true;
    else if (a === '--json') opts.json = true;
    else if (a.startsWith('--id=')) opts.ids.push(a.slice('--id='.length));
    else if (a.startsWith('--limit=')) opts.limit = Number(a.slice('--limit='.length));
    else if (a === '--help' || a === '-h') opts.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return opts;
}

function readTargetRows() {
  const p = path.join(OUT_ROOT, 'l5', 'targets.jsonl');
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help || (!opts.probe && !opts.fixtures && !opts.select && !opts.target && !opts.promote && !opts.report)) {
    process.stdout.write([
      'Usage:',
      '  node bin/l5.js --probe',
      '  node bin/l5.js --select [--limit=N] [--json]',
      '  node bin/l5.js --fixtures [--id=<fixture>] [--json]',
      '  node bin/l5.js --target [--id=<target>] [--json]',
      '  node bin/l5.js --promote [--json]',
      '  node bin/l5.js --report',
      '',
      `fixtures: ${FIXTURES.map((f) => f.id).join(', ')}`,
      `targets: ${TARGETS.map((t) => t.candidateId).join(', ')}`
    ].join('\n') + '\n');
    return 0;
  }
  if (opts.report) {
    const r = writeL5Report();
    process.stdout.write(`L5 report: ${r.report}\n`);
    return 0;
  }
  if (opts.promote) {
    const r = promoteRows(readTargetRows());
    if (opts.json) process.stdout.write(JSON.stringify(r.summary, null, 2) + '\n');
    else process.stdout.write(`L5 promote: ${r.summary.promoted}/${r.summary.total} eligible; T1=${r.summary.t1}\n`);
    return 0;
  }
  if (opts.target) {
    const r = runTargets({ ids: opts.ids });
    const p = promoteRows(r.rows);
    if (opts.json) process.stdout.write(JSON.stringify({ target: r.summary, promotion: p.summary }, null, 2) + '\n');
    else process.stdout.write(`L5 target: ${r.summary.confirmed} confirmed, ${r.summary.noSignal} no-signal, ${r.summary.blocked} blocked; promoted=${p.summary.promoted}; T1=${p.summary.t1}\n`);
    return r.summary.confirmed > 0 ? 0 : 3;
  }
  if (opts.select) {
    const r = selectCandidates({ limit: opts.limit });
    if (opts.json) process.stdout.write(JSON.stringify(r.summary, null, 2) + '\n');
    else process.stdout.write(`L5 select: ${r.summary.selected}/${r.summary.total} candidates; unsupported=${r.summary.unsupported}\n`);
    return r.summary.selected > 0 ? 0 : 3;
  }
  const env = probe();
  if (!opts.fixtures) {
    process.stdout.write(`L5 env: clang=${env.clang.versionLine} asan=${env.asan} ubsan=${env.ubsan}\n`);
    return env.asan || env.ubsan ? 0 : 3;
  }
  const r = runFixtures({ env, ids: opts.ids });
  if (opts.json) process.stdout.write(JSON.stringify(r.summary, null, 2) + '\n');
  else {
    process.stdout.write(`L5 fixtures: ${r.summary.confirmed} confirmed, ${r.summary.noSignal} no-signal, ${r.summary.blocked} blocked; expected=${r.summary.allExpected}\n`);
    for (const row of r.summary.rows) process.stdout.write(`  ${row.id}: ${row.result} (${row.reason})\n`);
    for (const m of r.summary.expectedMismatch) process.stderr.write(`  MISMATCH ${m.id}: expected=${m.expected} actual=${m.actual} (${m.reason})\n`);
  }
  return r.summary.allExpected ? 0 : 3;
}

if (require.main === module) {
  try {
    process.exitCode = main();
  } catch (e) {
    process.stderr.write(`${e && e.stack ? e.stack : e}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, parseArgs };
