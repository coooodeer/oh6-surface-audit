'use strict';

/**
 * lib/l5/fixtures.js —— L5 的 sanitizer 校准 fixtures。
 *
 * 当前只跑 host 级小 fixture；它们只校准 L5 的 build/run/classify/ledger，
 * 不映射到任何生产 claim，也不能产生 T1。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ensureDir, writeJson, writeJsonl } = require('../util.js');
const { toWslPath, wslScript, probe } = require('./env.js');
const { classify } = require('./classify.js');

const AUDIT_ROOT = path.resolve(__dirname, '..', '..');
const FIXTURE_DIR = path.join(AUDIT_ROOT, 'eval', 'l5', 'fixtures');
const BUILD_DIR = path.join(AUDIT_ROOT, 'eval', 'l5', 'build');
const OUT_DIR = path.join(AUDIT_ROOT, 'out', 'l5');
const RUN_DIR = path.join(OUT_DIR, 'runs');

const FIXTURES = [
  {
    id: 'P1-heap-oob', class: 'P1', file: 'p1_heap_oob.cpp', sanitizer: 'asan+ubsan',
    expected: 'confirmed', enabled: true, repeat: 3
  },
  {
    id: 'P2-uaf', class: 'P2', file: 'p2_uaf.cpp', sanitizer: 'asan+ubsan',
    expected: 'confirmed', enabled: true, repeat: 3
  },
  {
    id: 'P3-null-deref', class: 'P3', file: 'p3_null.cpp', sanitizer: 'ubsan',
    expected: 'confirmed', enabled: true, repeat: 3
  },
  {
    id: 'P4-signed-overflow', class: 'P4', file: 'p4_signed_overflow.cpp', sanitizer: 'ubsan',
    expected: 'confirmed', enabled: true, repeat: 3
  },
  {
    id: 'NEG-safe-array', class: 'NEG', file: 'negative_safe.cpp', sanitizer: 'asan+ubsan',
    expected: 'no-signal', enabled: true, repeat: 3
  },
  {
    id: 'NEG-checked-null', class: 'NEG', file: 'negative_checked_null.cpp', sanitizer: 'asan+ubsan',
    expected: 'no-signal', enabled: true, repeat: 3
  },
  {
    id: 'P7-unbounded-alloc', class: 'P7', file: 'p7_unbounded_alloc.cpp', sanitizer: 'timeout',
    expected: 'blocked:timeout', enabled: false, repeat: 1
  }
];

function hashFile(file) {
  const h = crypto.createHash('sha256');
  h.update(fs.readFileSync(file));
  return h.digest('hex');
}

function buildCommand(fixture, opts = {}) {
  const src = `${toWslPath(FIXTURE_DIR)}/${fixture.file}`;
  const out = `${toWslPath(BUILD_DIR)}/${fixture.id}`;
  const sanitize = fixture.sanitizer === 'ubsan'
    ? '-fsanitize=undefined -fno-sanitize-recover=undefined'
    : '-fsanitize=address,undefined -fno-sanitize-recover=undefined';
  return [
    opts.compiler || process.env.OH6_L5_CXX || 'g++', '-std=c++17', '-g', '-O1', '-fno-omit-frame-pointer',
    sanitize, `'${src}'`, '-o', `'${out}'`
  ].join(' ');
}

function runCommand(fixture) {
  const bin = `${toWslPath(BUILD_DIR)}/${fixture.id}`;
  const timeout = fixture.class === 'P7' ? 5 : 8;
  return [
    `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1`,
    `UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1`,
    `timeout ${timeout}s '${bin}'`
  ].join(' ');
}

function runFixture(fixture, opts = {}) {
  if (!fixture.enabled) {
    return { fixture, skipped: true, row: null };
  }
  ensureDir(BUILD_DIR);
  ensureDir(RUN_DIR);
  const started = Date.now();
  wslScript(`mkdir -p '${toWslPath(BUILD_DIR)}' '${toWslPath(RUN_DIR)}'`, { timeout: 30000 });
  const compiler = opts.compiler || process.env.OH6_L5_CXX || 'g++';
  const bcmd = buildCommand(fixture, { compiler });
  const build = wslScript(bcmd, { timeout: opts.buildTimeout || 120000 });
  const runs = [];
  const clsList = [];
  if (build.ok) {
    const rcmd = runCommand(fixture);
    for (let i = 0; i < fixture.repeat; i += 1) {
      const run = wslScript(rcmd, { timeout: opts.runTimeout || 30000 });
      run.command = rcmd;
      const cls = classify({
        buildOk: true,
        status: run.status,
        signal: run.signal,
        stdout: run.stdout,
        stderr: run.stderr
      });
      runs.push({
        attempt: i + 1,
        status: run.status,
        signal: run.signal,
        result: cls.result,
        reason: cls.reason,
        stdoutHash: crypto.createHash('sha256').update(run.stdout || '').digest('hex'),
        stderrHash: crypto.createHash('sha256').update(run.stderr || '').digest('hex'),
        stderrHead: String(run.stderr || '').slice(0, 2000)
      });
      clsList.push(cls);
    }
  }
  const first = runs[0] || { status: null, signal: null, stdout: '', stderr: '' };
  const unstable = new Set(clsList.map((c) => `${c.result}:${c.reason}`)).size > 1;
  const cls = !build.ok
    ? { result: 'blocked', reason: 'compile-failed' }
    : (unstable
      ? { result: 'blocked', reason: 'unstable-repeat' }
      : (clsList[0] || { result: 'blocked', reason: 'no-run' }));
  const sourceFile = path.join(FIXTURE_DIR, fixture.file);
  const runId = `L5-FIX-${fixture.id}-${Date.now()}`;
  const row = {
    runId,
    candidateId: `FIX-${fixture.id}`,
    claimId: null,
    fixture: true,
    class: fixture.class,
    sanitizer: fixture.sanitizer,
    expected: fixture.expected,
    compiler: `${compiler} (WSL)`,
    buildCommand: bcmd,
    runCommand: build.ok ? runCommand(fixture) : null,
    source: `eval/l5/fixtures/${fixture.file}`,
    sourceHash: hashFile(sourceFile),
    inputHash: null,
    exitCode: first.status,
    signal: first.signal,
    result: cls.result,
    reason: cls.reason,
    stdoutHash: first.stdoutHash || null,
    stderrHash: first.stderrHash || null,
    stderrHead: first.stderrHead || '',
    wallMs: Date.now() - started,
    repeat: fixture.repeat,
    repeats: runs,
    blockedReason: cls.result === 'blocked' ? cls.reason : null
  };
  writeJson(path.join(RUN_DIR, `${runId}.json`), row);
  return {
    fixture,
    skipped: false,
    row,
    expectedOk: row.result === fixture.expected
  };
}

function runFixtures(opts = {}) {
  const env = opts.env || probe();
  const ids = opts.ids && opts.ids.length ? new Set(opts.ids) : null;
  const rows = [];
  const results = [];
  for (const fixture of FIXTURES) {
    if (ids && !ids.has(fixture.id)) continue;
    const r = runFixture(fixture, opts);
    results.push(r);
    if (r.row) rows.push(r.row);
  }
  const summary = {
    generatedAt: new Date().toISOString(),
    environment: {
      distro: env.distro,
      clang: env.clang && env.clang.versionLine,
      asan: env.asan,
      ubsan: env.ubsan
    },
    total: rows.length,
    confirmed: rows.filter((r) => r.result === 'confirmed').length,
    noSignal: rows.filter((r) => r.result === 'no-signal').length,
    blocked: rows.filter((r) => r.result === 'blocked').length,
    expectedMismatch: results.filter((r) => !r.skipped && !r.expectedOk).map((r) => ({
      id: r.fixture.id,
      expected: r.fixture.expected,
      actual: r.row.result,
      reason: r.row.reason
    })),
    rows: rows.map((r) => ({
      id: r.candidateId,
      class: r.class,
      result: r.result,
      reason: r.reason,
      runId: r.runId
    }))
  };
  summary.allExpected = summary.expectedMismatch.length === 0;
  ensureDir(OUT_DIR);
  writeJsonl(path.join(OUT_DIR, 'fixtures.jsonl'), rows);
  writeJson(path.join(OUT_DIR, 'fixtures-summary.json'), summary);
  return { env, rows, results, summary };
}

module.exports = {
  FIXTURES,
  FIXTURE_DIR,
  BUILD_DIR,
  OUT_DIR,
  hashFile,
  buildCommand,
  runCommand,
  runFixture,
  runFixtures
};
