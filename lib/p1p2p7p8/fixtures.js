'use strict';

/**
 * fixtures.js —— P1/P2/P7/P8 fixture 运行器。
 *
 * 三类来源：
 *   - synthetic：eval/p1p2p7p8/<class>/cases.js 的 inline snippet；
 *   - history-local：data/facts/history-invariants.jsonl 的 pre/post/mutant（git show 提取）；
 *   - history-positive：result/optimization/.../positives.jsonl 的 before/after code。
 *
 * 全部只作 fixture/校准：不进入生产 D4 统计，不写 O10。
 */

const fs = require('fs');
const path = require('path');
const { escapeRe, TOOL_ROOT } = require('./common');
const { loadHistoryRows, extractHistorySample } = require('./history');
const { proveP1Fixture } = require('./prover-p1');
const { proveP2Fixture } = require('./prover-p2');
const { proveP7Fixture, analyzeP7FixtureSource } = require('./prover-p7');
const { proveP8Fixture } = require('./prover-p8');

const EVAL_ROOT = path.join(__dirname, '..', '..', 'eval', 'p1p2p7p8');
const POSITIVES_FILE = path.join(TOOL_ROOT, 'result', 'optimization', 'historical-positive-agent-list-20261012-final', 'positives.jsonl');

function loadCaseModules() {
  return {
    P1: require(path.join(EVAL_ROOT, 'p1', 'cases.js')),
    P2: require(path.join(EVAL_ROOT, 'p2', 'cases.js')),
    P7: require(path.join(EVAL_ROOT, 'p7', 'cases.js')),
    P8: require(path.join(EVAL_ROOT, 'p8', 'cases.js'))
  };
}

function loadPositives() {
  try {
    return fs.readFileSync(POSITIVES_FILE, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
  } catch (_) {
    return [];
  }
}

function fixtureCaseFromExtraction(caseRow, extraction) {
  const analysisBySource = caseRow.analysisBySource || {};
  const baseAnalysis = { ...(caseRow.analysis || {}) };
  if (baseAnalysis.useWitnessAsGuard) {
    baseAnalysis.guardPattern = escapeRe(extraction.witness);
    delete baseAnalysis.useWitnessAsGuard;
  }
  let mutantSource = extraction.mutantSource;
  if (caseRow.mutantRemovePattern) {
    const re = new RegExp(caseRow.mutantRemovePattern);
    mutantSource = String(extraction.postSource).split(/\r?\n/).filter((l) => !re.test(l)).join('\n');
  }
  return {
    ...caseRow,
    source: {
      pre: extraction.preSource,
      post: extraction.postSource,
      mutant: mutantSource
    },
    analysis: baseAnalysis,
    analysisBySource
  };
}

function checkExpected(caseRow, actual) {
  const failures = [];
  const exp = caseRow.expected || {};
  for (const key of ['pre', 'post', 'mutant', 'original']) {
    if (exp[key] == null) continue;
    const got = actual[key] && actual[key].verdict;
    if (got !== exp[key]) failures.push({ sourceKey: key, expected: exp[key], actual: got, reason: actual[key] && actual[key].reason });
  }
  return failures;
}

function runFixtureSet(caseRows, proveFn, kind) {
  const rows = [];
  for (const c of caseRows) {
    const proved = proveFn(c);
    const actual = {};
    for (const r of proved) actual[r.sourceKey] = r;
    const failures = checkExpected(c, actual);
    rows.push({
      id: c.id,
      class: c.class,
      kind: c.kind || kind,
      label: c.label || null,
      expected: c.expected || {},
      actual,
      failures,
      pass: failures.length === 0,
      coverage: c.negativeCoverage || null,
      preAlready: Boolean(c.expected && c.expected.preAlready)
    });
  }
  const passed = rows.filter((r) => r.pass).length;
  return {
    rows,
    summary: {
      total: rows.length,
      passed,
      failed: rows.length - passed,
      failures: rows.filter((r) => !r.pass),
      gate: rows.length > 0 && passed === rows.length
    }
  };
}

function runHistoryLocal(caseRows, historyRows, proveFn) {
  const byId = new Map(historyRows.map((r) => [r.id, r]));
  const fixtures = [];
  const unavailable = [];
  for (const c of caseRows) {
    const row = byId.get(c.historyId);
    if (!row) { unavailable.push({ id: c.id, historyId: c.historyId, reason: 'history-row-missing' }); continue; }
    const extraction = extractHistorySample(row, c.extract || {});
    extraction.witness = row.witness;
    if (extraction.status === 'fixture-unavailable' || extraction.status === 'post-absent' || extraction.status === 'mutant-unchanged') {
      unavailable.push({ id: c.id, historyId: c.historyId, status: extraction.status, reason: extraction.reason });
      continue;
    }
    const fixture = fixtureCaseFromExtraction(c, extraction);
    fixture.expected = { ...(c.expected || {}) };
    if (extraction.status === 'pre-already') fixture.expected.pre = 'SATISFIED';
    fixtures.push(fixture);
  }
  const result = runFixtureSet(fixtures, proveFn, 'history-local');
  result.summary.requested = caseRows.length;
  result.summary.validated = fixtures.length;
  result.summary.unavailable = unavailable;
  result.summary.preAlready = result.rows.filter((r) => r.preAlready).length;
  result.summary.gate = fixtures.length === caseRows.length && result.summary.failed === 0;
  result.rows = result.rows.map((r) => ({ ...r, historyId: (caseRows.find((c) => c.id === r.id) || {}).historyId || null }));
  return result;
}

function runHistoryPositive(caseRows, proveFn) {
  const positives = loadPositives();
  const fixtures = [];
  const unavailable = [];
  for (const c of caseRows) {
    const p = positives.find((x) => x.id === c.positiveId);
    if (!p) { unavailable.push({ id: c.id, positiveId: c.positiveId, reason: 'positive-record-missing' }); continue; }
    const root = (p.roots || []).find((r) => r.before && r.before.code && r.after && r.after.code);
    if (!root) { unavailable.push({ id: c.id, positiveId: c.positiveId, reason: 'before-after-code-missing' }); continue; }
    const fixture = {
      ...c,
      source: { pre: root.before.code, post: root.after.code },
      analysisBySource: c.analysisBySource || {},
      positiveRepo: root.componentRoot,
      positiveFile: root.file
    };
    fixtures.push(fixture);
  }
  const result = runFixtureSet(fixtures, proveFn, 'history-positive');
  result.summary.requested = caseRows.length;
  result.summary.validated = fixtures.length;
  result.summary.unavailable = unavailable;
  result.summary.gate = fixtures.length === caseRows.length && result.summary.failed === 0;
  return result;
}

function runP1Fixtures() {
  const mod = loadCaseModules().P1;
  const synthetic = runFixtureSet(mod.synthetic, proveP1Fixture, 'synthetic');
  const historyRows = loadHistoryRows({ family: 'bounds-check-added', cls: 'P1' });
  const historyLocal = runHistoryLocal(mod.historyLocal, historyRows, proveP1Fixture);
  const historyPositive = runHistoryPositive(mod.historyPositive, proveP1Fixture);
  const positiveFixtures = synthetic.rows.filter((r) => r.kind === 'synthetic-positive' && r.pass).length;
  const negativeFixtures = synthetic.rows.filter((r) => r.kind === 'synthetic-negative' && r.pass).length;
  return {
    class: 'P1',
    synthetic,
    historyLocal,
    historyPositive,
    summary: {
      class: 'P1',
      synthetic: synthetic.summary,
      historyLocal: historyLocal.summary,
      historyPositive: historyPositive.summary,
      positiveFixtures,
      negativeFixtures,
      total: synthetic.summary.total + historyLocal.rows.length + historyPositive.rows.length,
      passed: synthetic.summary.passed + historyLocal.summary.passed + historyPositive.summary.passed,
      failed: synthetic.summary.failed + historyLocal.summary.failed + historyPositive.summary.failed,
      gate: synthetic.summary.gate && historyLocal.summary.gate && historyPositive.summary.gate
    }
  };
}

function runP2Fixtures() {
  const mod = loadCaseModules().P2;
  const synthetic = runFixtureSet(mod.synthetic, proveP2Fixture, 'synthetic');
  const historyRows = loadHistoryRows({ family: 'lifetime-guard-added', cls: 'P2' });
  const historyLocal = runHistoryLocal(mod.historyLocal, historyRows, proveP2Fixture);
  const historyPositive = runHistoryPositive(mod.historyPositive, proveP2Fixture);
  const repos = new Set(historyLocal.rows.map((r) => {
    const c = mod.historyLocal.find((x) => x.id === r.id);
    const row = historyRows.find((x) => x.id === (c && c.historyId));
    return row ? row.repo : null;
  }).filter(Boolean));
  return {
    class: 'P2',
    synthetic,
    historyLocal,
    historyPositive,
    summary: {
      class: 'P2',
      synthetic: synthetic.summary,
      historyLocal: historyLocal.summary,
      historyPositive: historyPositive.summary,
      positiveFixtures: synthetic.rows.filter((r) => r.kind === 'synthetic-positive' && r.pass).length,
      negativeFixtures: synthetic.rows.filter((r) => r.kind === 'synthetic-negative' && r.pass).length,
      localValidated: historyLocal.rows.length,
      localRepos: [...repos],
      total: synthetic.summary.total + historyLocal.rows.length + historyPositive.rows.length,
      passed: synthetic.summary.passed + historyLocal.summary.passed + historyPositive.summary.passed,
      failed: synthetic.summary.failed + historyLocal.summary.failed + historyPositive.summary.failed,
      gate: synthetic.summary.gate && historyLocal.summary.gate && historyLocal.rows.length >= 6 && repos.size >= 2 && historyPositive.summary.gate
    }
  };
}

function runP7Fixtures() {
  const mod = loadCaseModules().P7;
  const synthetic = runFixtureSet(mod.synthetic, proveP7Fixture, 'synthetic');
  const external = require(path.join(__dirname, '..', '..', 'eval', 'external-cve', 'p7-cases.js'));
  const externalRows = [];
  for (const c of external.cases) {
    const analysisBySource = mod.externalAnalysis[c.id] || {};
    const row = { ...c, analysisBySource };
    const pre = analyzeP7FixtureSource(row, 'pre');
    const post = analyzeP7FixtureSource(row, 'post');
    const failures = [];
    if (pre.verdict !== c.expected.preVerdict) failures.push({ sourceKey: 'pre', expected: c.expected.preVerdict, actual: pre.verdict });
    if (post.verdict !== c.expected.postVerdict) failures.push({ sourceKey: 'post', expected: c.expected.postVerdict, actual: post.verdict });
    if (c.production !== false) failures.push({ sourceKey: 'production', expected: false, actual: c.production });
    if ('inTarget' in c || 'codeState' in c) failures.push({ sourceKey: 'mapping', expected: 'none', actual: 'inTarget/codeState present' });
    externalRows.push({ id: c.id, class: 'P7', kind: 'external-cve', expected: c.expected, actual: { pre, post }, failures, pass: failures.length === 0 });
  }
  const v = external.validateAll();
  const amplificationClaims = mod.synthetic.filter((c) => c.kind === 'fixture-claim');
  return {
    class: 'P7',
    synthetic,
    external: {
      rows: externalRows,
      validation: v,
      summary: {
        total: externalRows.length,
        passed: externalRows.filter((r) => r.pass).length,
        gate: v.ok && externalRows.every((r) => r.pass)
      }
    },
    fixtureClaims: amplificationClaims,
    summary: {
      class: 'P7',
      synthetic: synthetic.summary,
      external: { total: externalRows.length, passed: externalRows.filter((r) => r.pass).length, validationOk: v.ok },
      total: synthetic.summary.total + externalRows.length,
      passed: synthetic.summary.passed + externalRows.filter((r) => r.pass).length,
      failed: synthetic.summary.failed + externalRows.filter((r) => !r.pass).length,
      gate: synthetic.summary.gate && v.ok && externalRows.every((r) => r.pass)
    }
  };
}

function runP8Fixtures() {
  const mod = loadCaseModules().P8;
  const synthetic = runFixtureSet(mod.synthetic, proveP8Fixture, 'synthetic');
  const historyRows = loadHistoryRows({ family: 'state-guard-added', cls: 'P8' });
  const historyLocal = runHistoryLocal(mod.historyLocal, historyRows, proveP8Fixture);
  return {
    class: 'P8',
    synthetic,
    historyLocal,
    summary: {
      class: 'P8',
      synthetic: synthetic.summary,
      historyLocal: historyLocal.summary,
      localValidated: historyLocal.rows.length,
      total: synthetic.summary.total + historyLocal.rows.length,
      passed: synthetic.summary.passed + historyLocal.summary.passed,
      failed: synthetic.summary.failed + historyLocal.summary.failed,
      gate: synthetic.summary.gate && historyLocal.summary.gate && historyLocal.rows.length >= 4
    }
  };
}

function runAllFixtures() {
  const p1 = runP1Fixtures();
  const p2 = runP2Fixtures();
  const p7 = runP7Fixtures();
  const p8 = runP8Fixtures();
  const classes = { P1: p1, P2: p2, P7: p7, P8: p8 };
  const gate = Object.values(classes).every((c) => c.summary.gate);
  return { classes, gate };
}

module.exports = {
  EVAL_ROOT, POSITIVES_FILE, loadCaseModules, loadPositives, fixtureCaseFromExtraction,
  checkExpected, runFixtureSet, runHistoryLocal, runHistoryPositive,
  runP1Fixtures, runP2Fixtures, runP7Fixtures, runP8Fixtures, runAllFixtures
};
