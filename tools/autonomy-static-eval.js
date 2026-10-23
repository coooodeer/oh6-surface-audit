'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const factsLib = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const knowledgeLib = require('../lib/autonomy/knowledge');
const permissionArgument = require('../lib/autonomy/permission-argument');
const staticProof = require('../lib/autonomy/static-proof');
const mutantLabels = require('../eval/autonomy/static-builder-mutants.json');
const scope = require('../K/policies/autonomy-pilot-scope.json');

const root = path.resolve(__dirname, '..');
const labels = require('../eval/autonomy/static-builder-labels.json');

function summarize(rows) {
  const agreed = rows.filter((row) => row.expected === row.observed).length;
  return { labelSource: labels.labelSource, modelFamily: labels.modelFamily, familyCount: 1,
    sampleCount: rows.length, agreementWithBuilderLabels: agreed / rows.length,
    findingPrecisionAgainstBuilderLabels: rows.filter((row) => row.observed === 'finding').length
      ? rows.filter((row) => row.observed === 'finding' && row.expected === 'finding').length /
        rows.filter((row) => row.observed === 'finding').length : null,
    independentAccuracy: null, discoveryRecall: null, abcdComparison: 'not-run',
    limitation: 'Two production entries in one component/family; Builder labels are not independent truth.', rows };
}

function evaluate() {
  const rows = [];
  for (const label of labels.labels) {
    const runDir = path.join(root, 'out', 'autonomy', label.runId.replace(':', '-'));
    const result = spawnSync(process.execPath, ['bin/autonomy.js', 'check', `--run=${label.runId}`],
      { cwd: root, encoding: 'utf8' });
    if (result.status !== 0) throw new Error(`check failed for ${label.runId}: ${result.stdout} ${result.stderr}`);
    const report = fs.readFileSync(path.join(runDir, 'report-model.jsonl'), 'utf8').trim()
      .split('\n').map(JSON.parse).filter((row) => row.payload.entryRef === label.entryRef &&
        row.payload.origin === 'entry-scan');
    if (report.length !== 1) throw new Error(`entry report not unique: ${label.runId}`);
    rows.push({ method: label.method, runId: label.runId, expected: label.expected,
      observed: report[0].payload.reportability, source: label.source });
  }
  return summarize(rows);
}

function mutantFacts(base, bound, label) {
  const file = `test/fixtures/autonomy/mutants/${label.file}`;
  const text = fs.readFileSync(path.join(root, file), 'utf8');
  const sha256 = crypto.createHash('sha256').update(text).digest('hex');
  if (sha256 !== label.sha256) throw new Error(`mutant source drift: ${label.file}`);
  const lines = text.split(/\r?\n/);
  const fn = { ...bound, factId: `F:mutant:${sha256.slice(0, 16)}`,
    sourceRange: { file }, startLine: 1, endLine: lines.length };
  const calls = [];
  for (let i = 0; i < lines.length; i++) {
    const check = /\bCheckPermission\s*\(/.test(lines[i]);
    const operation = /PolicyInfoManager::GetInstance\(\)\.SetPolicy\s*\(/.test(lines[i]);
    if (!check && !operation) continue;
    calls.push({ factId: `F:mutant-call:${sha256.slice(0, 12)}:${i + 1}`,
      caller: fn.factId, callerName: fn.name, line: i + 1,
      calleeName: check ? 'CheckPermission' : 'SetPolicy',
      callee: check ? 'F:mutant-check' : null, argc: check ? 2 : 5,
      quality: { resolution: check ? 'exact' : 'name-only', parse: 'controlled-mutant' } });
  }
  const indexed = base.index();
  const facts = Object.create(base);
  facts.index = () => ({ ...indexed, calls: [...indexed.calls, ...calls] });
  facts.callsOf = (qualified, opts) => qualified === fn.qualified ? calls : base.callsOf(qualified, opts);
  facts.verifyFile = (rel) => rel === file ? { ok: true, actual: sha256 } : base.verifyFile(rel);
  facts.sourceWindow = (rel, start, end, opts) => rel === file
    ? { file, startLine: 1, endLine: lines.length, text, sha256, truncated: false }
    : base.sourceWindow(rel, start, end, opts);
  return { facts, fn };
}

function evaluateMutants(base = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope })) {
  const anchors = discovery.buildAnchors(base, scope);
  const entry = anchors.entries.find((row) => row.kind === 'idl' && row.method === mutantLabels.normMethod);
  const original = discovery.resolveBinding(entry.entityId, { facts: base, scope, anchors: anchors.anchors });
  const knowledge = knowledgeLib.loadPublished(path.join(root, 'K/norms',
    '050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c', 'knowledge.json'), null, base);
  const files = fs.readdirSync(path.join(root, 'test/fixtures/autonomy/mutants')).sort();
  if (files.join('|') !== mutantLabels.labels.map((row) => row.file).sort().join('|')) {
    throw new Error('mutant corpus differs from frozen labels');
  }
  const rows = mutantLabels.labels.map((label) => {
    const { facts, fn } = mutantFacts(base, original.bound, label);
    const binding = { binding: 'resolved', bound: fn };
    const comparison = permissionArgument.compare(facts, entry, binding, knowledge);
    const proof = staticProof.analyze(facts, entry, binding, knowledge, comparison, { includeNewFamilies: true });
    return { file: label.file, familyId: label.familyId, source: 'controlled-mutant',
      sha256: label.sha256, expected: label.expected, observed: proof.status,
      observedFamily: proof.family || null, reason: proof.reason || null };
  });
  const positive = rows.filter((row) => row.expected === 'finding');
  const findings = rows.filter((row) => row.observed === 'finding');
  const unknown = rows.filter((row) => row.expected === 'insufficient');
  return { labelSource: mutantLabels.labelSource, labelAuthority: mutantLabels.labelAuthority,
    needsHumanTuning: true, snapshotId: mutantLabels.snapshotId, sourceType: mutantLabels.sourceType,
    sampleCount: rows.length, familyCount: new Set(rows.map((row) => row.familyId)).size,
    denominators: { judgments: rows.length, positiveMutants: positive.length,
      reportedFindings: findings.length, insufficientMutants: unknown.length },
    judgmentAccuracy: rows.filter((row) => row.expected === row.observed).length / rows.length,
    findingPrecision: findings.filter((row) => row.expected === 'finding').length / (findings.length || 1),
    discoveryRecall: positive.filter((row) => row.observed === 'finding').length / positive.length,
    falseCertaintyRate: unknown.filter((row) => ['finding', 'excluded'].includes(row.observed)).length / unknown.length,
    independentAccuracy: null,
    limitation: 'Controlled-mutant fixture enumeration and Builder labels only; not unseeded production discovery or independent human accuracy.',
    rows };
}

function evaluateStaticContrast() {
  const start = performance.now();
  const base = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  base.index();
  const preprocessingMs = performance.now() - start;
  const coldStart = performance.now();
  const baseline = evaluateMutants(base);
  const coldMs = performance.now() - coldStart;
  const hotStart = performance.now();
  const repeated = evaluateMutants(base);
  const hotMs = performance.now() - hotStart;
  if (JSON.stringify(baseline.rows) !== JSON.stringify(repeated.rows)) throw new Error('hot result drift');
  const groups = ['A', 'B', 'C', 'D'].map((group) => {
    const rows = baseline.rows.map((row) => {
      const text = fs.readFileSync(path.join(root, 'test/fixtures/autonomy/mutants', row.file), 'utf8');
      const checks = text.match(/\bCheckPermission\s*\(/g) || [];
      const operations = text.match(/PolicyInfoManager::GetInstance\(\)\.SetPolicy\s*\(/g) || [];
      let observed;
      if (group === 'A') {
        observed = checks.length === 0 ? 'finding' :
          /return\s+PERMISSION_DENIED\s*;/.test(text) ? 'excluded' : 'finding';
      } else if (group === 'B') {
        observed = operations.length !== 1 ? 'insufficient' : checks.length === 0 ? 'finding' :
          /if\s*\(\s*!\s*CheckPermission\s*\([^)]*\)\s*\)\s*\{\s*return\s+PERMISSION_DENIED\s*;\s*\}/.test(text)
            ? 'excluded' : 'finding';
      } else observed = row.observed;
      return { file: row.file, expected: row.expected, observed };
    });
    return { group, correct: rows.filter((row) => row.expected === row.observed).length,
      total: rows.length, falseCertainty: rows.filter((row) => row.expected === 'insufficient' &&
        ['finding', 'excluded'].includes(row.observed)).length, rows };
  });
  return { kind: 'deterministic-static-ablation-not-model-comparison', labelSource: baseline.labelSource,
    input: 'Five frozen controlled mutants; A raw-text heuristic, B source-call/guard heuristic, C published norm plus bounded proof, D program-curated sufficient local context with the same proof.',
    independentOracle: false, modelRequests: 0, preprocessingMs, coldMs, hotMs,
    groups, limitation: 'D is not an independent oracle; these five same-method fixtures do not establish production unseeded recall or model uplift.' };
}

function evaluateSuite(runId) {
  const runDir = path.join(root, 'out', 'autonomy', runId.replace(':', '-'));
  const result = spawnSync(process.execPath, ['bin/autonomy.js', 'check', `--run=${runId}`],
    { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`suite check failed: ${result.stdout} ${result.stderr}`);
  const run = JSON.parse(fs.readFileSync(path.join(runDir, 'run.json'), 'utf8'));
  if (run.payload.architectureVersion !== '1.0.17-static-scan') throw new Error('not a static suite run');
  const rows = fs.readFileSync(path.join(runDir, 'report-model.jsonl'), 'utf8').trim().split('\n')
    .map(JSON.parse).map((record) => record.payload);
  const counts = Object.fromEntries(['finding', 'excluded', 'candidate', 'observation']
    .map((status) => [status, rows.filter((row) => row.reportability === status).length]));
  return { runId, snapshotId: run.payload.snapshotId, mode: run.payload.mode,
    tasks: rows.length, entryTasks: rows.filter((row) => row.origin === 'entry-scan').length,
    coverageTasks: rows.filter((row) => row.origin === 'coverage-sample').length,
    counts, families: Object.fromEntries([...new Set(rows.map((row) => row.findingFamily).filter(Boolean))]
      .map((family) => [family, rows.filter((row) => row.findingFamily === family).length])),
    limitation: 'Production classifications are not independently labeled; no production precision or recall is inferred.' };
}

if (require.main === module) {
  try {
    const runArg = process.argv.find((arg) => arg.startsWith('--suite-run='));
    const result = runArg ? { production: evaluateSuite(runArg.slice(12)), mutants: evaluateMutants(),
      abcd: evaluateStaticContrast() }
      : process.argv.includes('--mutants') ? evaluateMutants() : evaluate();
    if (runArg && process.argv.includes('--write')) {
      const target = path.join(root, 'out', 'autonomy', 'eval', `${runArg.slice(12).replace(':', '-')}.json`);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
    }
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  }
  catch (e) { process.stderr.write(`${e.message}\n`); process.exitCode = 1; }
}

module.exports = { evaluate, summarize, evaluateMutants, evaluateSuite, evaluateStaticContrast };
