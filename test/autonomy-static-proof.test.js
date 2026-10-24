'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const factsLib = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const knowledgeLib = require('../lib/autonomy/knowledge');
const permission = require('../lib/autonomy/permission-argument');
const proofLib = require('../lib/autonomy/static-proof');
const staticEval = require('../tools/autonomy-static-eval');
const scope = require('../K/policies/autonomy-pilot-scope.json');

const root = path.join(__dirname, '..');
const knowledgeFiles = {
  SetPolicyAsync: '050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c',
  UnSetPolicyAsync: '79e3aaca70682d07c67243730795149fc6ccf8c6f7be2aedc9d0381482301de3'
};

test('static permission contract has scoped positive, negative and missing outcomes', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  for (const [method, status] of [['SetPolicyAsync', 'excluded'], ['UnSetPolicyAsync', 'finding']]) {
    const entry = anchors.entries.find((e) => e.method === method);
    const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
    const knowledge = knowledgeLib.loadPublished(path.join(knowledgeLib.PUBLISHED_DIR,
      knowledgeFiles[method], 'knowledge.json'), null, facts);
    const comparison = permission.compare(facts, entry, binding, knowledge);
    const proof = proofLib.analyze(facts, entry, binding, knowledge, comparison);
    assert.equal(proof.status, status);
    assert.equal(proof.verificationStatus, 'static-only');
    assert.equal(proofLib.analyze(facts, entry, binding, knowledge, null).status, 'insufficient');
    assert.equal(proofLib.analyze(facts, entry, binding, knowledgeLib.loadAuthorization(facts), comparison).status,
      'insufficient');
  }
  assert.equal(proofLib.guardBeforeOperation(
    'f() {\nauto callingTokenId = IPCSkeleton::GetCallingTokenID();\nif (!CheckPermission(callingTokenId, WRONG)) {\n  log();\n}\nMutate();\n}',
    1, 3, 6), false);
  assert.equal(proofLib.guardBeforeOperation(
    'f() {\nauto callingTokenId = IPCSkeleton::GetCallingTokenID();\nif (!CheckPermission(callingTokenId, WRONG)) {\n  return PERMISSION_DENIED;\n}\nMutate();\n}',
    1, 3, 6), true);
  assert.equal(proofLib.guardBeforeOperation(
    'f() {\nauto callingTokenId = IPCSkeleton::GetCallingTokenID();\nif (condition) {\nif (!CheckPermission(callingTokenId, WRONG)) {\n  return PERMISSION_DENIED;\n}\n}\nMutate();\n}',
    1, 4, 8), false);
});

test('static run report and source-backed check agree on a narrow finding', () => {
  const run = spawnSync(process.execPath, ['bin/autonomy.js', 'run', '--experiment=vertical-v2', '--mode=off',
    '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
    '--task=TASK:ce534608cd00a85c',
    `--knowledge=K/norms/${knowledgeFiles.UnSetPolicyAsync}/knowledge.json`],
  { cwd: root, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const { runId, runDir, counts } = JSON.parse(run.stdout);
  const dir = path.resolve(root, runDir);
  try {
    assert.equal(counts.finding, 1);
    const checked = spawnSync(process.execPath, ['bin/autonomy.js', 'check', `--run=${runId}`],
      { cwd: root, encoding: 'utf8' });
    assert.equal(checked.status, 0, checked.stdout + checked.stderr);
  } finally {
    if (dir.startsWith(path.join(root, 'out', 'autonomy') + path.sep) &&
        path.basename(dir) === runId.replace(':', '-')) fs.rmSync(dir, { recursive: true });
  }
});

test('published norm selects a unique scoped entry without a task seed', () => {
  const common = ['bin/autonomy.js', 'run', '--experiment=vertical-v2', '--mode=off',
    '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
    '--max-tasks=1'];
  const noNorm = spawnSync(process.execPath, common, { cwd: root, encoding: 'utf8' });
  assert.equal(noNorm.status, 2);
  assert.match(noNorm.stderr, /requires --task or a uniquely applicable published --knowledge/);

  const run = spawnSync(process.execPath, [...common,
    `--knowledge=K/norms/${knowledgeFiles.UnSetPolicyAsync}/knowledge.json`],
  { cwd: root, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const { runId, runDir, counts, planned } = JSON.parse(run.stdout);
  const dir = path.resolve(root, runDir);
  try {
    assert.equal(planned.tasks, 1);
    assert.equal(counts.finding, 1);
    const task = JSON.parse(fs.readFileSync(path.join(dir, 'tasks.jsonl'), 'utf8').trim());
    assert.equal(task.recordId, 'TASK:ce534608cd00a85c');
    const checked = spawnSync(process.execPath, ['bin/autonomy.js', 'check', `--run=${runId}`],
      { cwd: root, encoding: 'utf8' });
    assert.equal(checked.status, 0, checked.stdout + checked.stderr);
  } finally {
    if (dir.startsWith(path.join(root, 'out', 'autonomy') + path.sep) &&
        path.basename(dir) === runId.replace(':', '-')) fs.rmSync(dir, { recursive: true });
  }
});

test('Builder-source pilot evaluation keeps independent metrics unknown', () => {
  const result = staticEval.summarize([
    { expected: 'excluded', observed: 'excluded' },
    { expected: 'finding', observed: 'finding' }
  ]);
  assert.equal(result.labelSource, 'builder-llm-oracle');
  assert.equal(result.sampleCount, 2);
  assert.equal(result.familyCount, 1);
  assert.equal(result.independentAccuracy, null);
  assert.equal(result.discoveryRecall, null);
  assert.equal(result.abcdComparison, 'not-run');
});

test('published suite distinguishes direct checks, documented mismatch, alternate gates and unknown target', () => {
  const scope = require('../K/policies/autonomy-pilot-scope.json');
  const facts = require('../lib/autonomy/facts').AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const discovery = require('../lib/autonomy/discovery');
  const anchors = discovery.buildAnchors(facts, scope);
  const suite = knowledgeLib.loadKnowledgeSuite([
    path.join(root, 'K/norms', knowledgeFiles.SetPolicyAsync, 'knowledge.json'),
    path.join(root, 'K/norms/7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f/knowledge.json')
  ], facts);
  const expected = {
    SetPolicy: ['excluded', 'compliant-excluded'],
    PersistPolicy: ['excluded', 'compliant-excluded'],
    UnSetPolicy: ['finding', 'permission-mismatch'],
    CleanPolicyByUserId: ['finding', 'missing-permission-check'],
    CheckPolicy: ['insufficient', undefined],
    SetPolicyByBundleName: ['insufficient', undefined]
  };
  for (const [method, [status, family]] of Object.entries(expected)) {
    const entry = anchors.entries.find((row) => row.kind === 'idl' && row.method === method);
    const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
    const knowledge = suite.byMethod.get(method);
    const comparison = permission.compare(facts, entry, binding, knowledge);
    const proof = proofLib.analyze(facts, entry, binding, knowledge, comparison, { includeNewFamilies: true });
    assert.equal(proof.status, status, method);
    assert.equal(proof.family, family, method);
  }
});

test('suite scan aligns task operation, question, assessment and report, then check recomputes', () => {
  const run = spawnSync(process.execPath, ['bin/autonomy.js', 'run', '--mode=off',
    '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
    '--task=TASK:b8aebdde9b294f64',
    `--knowledge=K/norms/${knowledgeFiles.SetPolicyAsync}/knowledge.json,` +
      'K/norms/7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f/knowledge.json'],
  { cwd: root, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const { runId, runDir, counts } = JSON.parse(run.stdout);
  const dir = path.join(root, runDir);
  const rows = (file) => fs.readFileSync(path.join(dir, file), 'utf8').trim().split('\n').map(JSON.parse);
  try {
    assert.equal(counts.finding, 1);
    const task = rows('tasks.jsonl')[0].payload;
    const contract = rows('questions.jsonl').find((row) => row.payload.kind === 'static-contract');
    const decision = rows('assessments.jsonl').find((row) => row.payload.questionId === contract.recordId);
    const report = rows('report-model.jsonl')[0].payload;
    assert.match(task.operationRef, /^F:/);
    assert.equal(contract.payload.status, 'refuted');
    assert.equal(decision.payload.decision, 'refuted');
    assert.equal(report.reportability, 'finding');
    assert.equal(report.findingFamily, 'permission-mismatch');
    assert.equal(report.operationRef, task.operationRef);
    const checked = spawnSync(process.execPath, ['bin/autonomy.js', 'check', `--run=${runId}`],
      { cwd: root, encoding: 'utf8' });
    assert.equal(checked.status, 0, checked.stdout + checked.stderr);
    const proofsFile = path.join(dir, 'static-proofs.json');
    const proofs = JSON.parse(fs.readFileSync(proofsFile, 'utf8'));
    proofs[task.taskId].status = 'excluded';
    fs.writeFileSync(proofsFile, JSON.stringify(proofs), 'utf8');
    const drift = spawnSync(process.execPath, ['bin/autonomy.js', 'check', `--run=${runId}`],
      { cwd: root, encoding: 'utf8' });
    assert.notEqual(drift.status, 0);
    assert.ok(JSON.parse(drift.stdout).errors.some((item) => item.code === 'static-proof-drift'));
  } finally {
    if (dir.startsWith(path.join(root, 'out', 'autonomy') + path.sep) &&
        path.basename(dir) === runId.replace(':', '-')) fs.rmSync(dir, { recursive: true });
  }
});

test('frozen Builder mutants remain separate from production runs and retain five family labels', () => {
  const result = staticEval.evaluateMutants();
  assert.equal(result.sampleCount, 5);
  assert.equal(result.familyCount, 5);
  assert.equal(result.judgmentAccuracy, 1);
  assert.equal(result.givenMutantFindingRecall, 1);
  assert.equal(result.discoveryRecall, null);
  assert.equal(result.falseCertaintyRate, 0);
  assert.equal(result.independentAccuracy, null);
  assert.ok(result.rows.every((row) => row.source === 'controlled-mutant'));
});

test('model A/B/C/D uses one model and a shared 20-request budget across five families', async () => {
  const labels = require('../eval/autonomy/static-builder-mutants.json').labels;
  const expected = new Map(labels.map((row) => ['SRC:' + row.sha256.slice(0, 16), row.expected]));
  const budget = { modelRequests: 0, policy: { maxModelRequests: 20 } };
  const gateway = { mode: 'live', config: { model: 'test-open-model' }, budget,
    keyPresent: () => true,
    invoke: async (request) => {
      budget.modelRequests++;
      const sourceRef = JSON.parse(request.messages[1].content).sourceRef;
      return { status: 'ok', model: 'test-open-model', callId: 'CALL:mock',
        parsed: { verdict: expected.get(sourceRef), evidenceRefs: [sourceRef] },
        contentSha256: 'a'.repeat(64), usage: { promptTokens: 10, completionTokens: 10 }, wallMs: 1 };
    } };
  const result = await staticEval.evaluateModelContrast(gateway);
  assert.equal(result.rows.length, 20);
  assert.equal(result.requests, 20);
  assert.deepEqual(result.groups.map((group) => [group.total, group.correct]),
    [[5, 5], [5, 5], [5, 5], [5, 5]]);
  assert.equal(new Set(result.rows.map((row) => row.familyId)).size, 5);
});

test('proof summary reuses the shared service body and invalidates on norm or source drift', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  const knowledge = knowledgeLib.loadPublished(path.join(knowledgeLib.PUBLISHED_DIR,
    knowledgeFiles.SetPolicyAsync, 'knowledge.json'), null, facts);
  const cache = new Map();
  let hits = 0;
  const options = { includeNewFamilies: true, cache, onCacheHit: () => { hits++; } };
  for (const method of ['SetPolicy', 'SetPolicyAsync']) {
    const entry = anchors.entries.find((row) => row.kind === 'idl' && row.method === method);
    const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
    const comparison = permission.compare(facts, entry, binding, knowledge);
    assert.equal(proofLib.analyze(facts, entry, binding, knowledge, comparison, options).status, 'excluded');
  }
  assert.equal(hits, 1);
  const entry = anchors.entries.find((row) => row.kind === 'idl' && row.method === 'SetPolicy');
  const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
  const comparison = permission.compare(facts, entry, binding, knowledge);
  const changed = { ...knowledge, norm: { ...knowledge.norm, reviewRef: 'REVIEW:changed' } };
  proofLib.analyze(facts, entry, binding, changed, comparison, options);
  assert.equal(hits, 1);
  const stale = Object.create(facts);
  stale.verifyFile = () => ({ ok: false });
  assert.equal(proofLib.analyze(stale, entry, binding, knowledge, comparison, options).status, 'insufficient');
  assert.equal(hits, 1);
});
