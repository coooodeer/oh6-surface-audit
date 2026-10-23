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
