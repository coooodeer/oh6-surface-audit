'use strict';

/**
 * 跨组件受控盲测的回归：
 *   - 语料 spec 与冻结标签一致（18 案例 / 2 组件 / 文件哈希）；
 *   - 评分器在已存在的盲测 run 上复现 8 提名 / 18 状态一致；
 *   - 篡改一条期望值后评分下降，证明评分不是恒真。
 * 没有盲测 run 时 skip（不把“没跑过”伪装成通过）。
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const storeLib = require('../lib/autonomy/store');
const blindEval = require('../tools/autonomy-blind-eval');

const BLIND_RUN = 'RUN:cf05827a914570e3';
const LABELS = path.resolve('eval/autonomy/blind-cross-component.json');
const SPEC = path.resolve('eval/autonomy/blind-corpus-spec.json');

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function blindRunDir() {
  try { return storeLib.RunStore.resolve(BLIND_RUN); } catch (_) { return null; }
}

test('blind corpus: spec and frozen labels agree on 18 cases across 2 components', () => {
  const spec = JSON.parse(fs.readFileSync(SPEC, 'utf8'));
  const labels = JSON.parse(fs.readFileSync(LABELS, 'utf8'));
  assert.equal(labels.cases.length, 18);
  assert.equal(labels.components.length, 2);
  assert.deepEqual(labels.denominators, {
    cases: 18, components: 2, positiveExpectations: 8,
    excludedExpectations: 7, insufficientExpectations: 3
  });
  assert.equal(labels.snapshotId,
    'sha256:13f40945a59d89f3635c164ffe472367d36ab248d5e068245641a2c90e0e052e');
  assert.equal(spec.cases.length, labels.cases.length);
  for (const label of labels.cases) {
    const file = path.resolve('test/fixtures/autonomy', label.file);
    assert.equal(sha256File(file), label.sha256, label.file);
    assert.ok(spec.cases.some((row) => row.file === label.file && row.method === label.method));
  }
});

test('blind eval: re-scores the frozen run without reading labels at eval time', { skip: !blindRunDir() && 'no blind run' }, () => {
  const metrics = blindEval.score(BLIND_RUN, LABELS);
  assert.equal(metrics.denominators.cases, 18);
  assert.equal(metrics.statusAccuracy, 1);
  assert.equal(metrics.securityFamilyAccuracy, 1);
  assert.equal(metrics.blindNomination.nominated, 8);
  assert.deepEqual(metrics.blindNomination.byComponent, { sandbox_manager: 5, os_account: 3 });
  assert.equal(metrics.positiveRecall, 1);
  assert.equal(metrics.excludedRecall, 1);
  assert.equal(metrics.ambiguityHoldRate, 1);
  assert.equal(metrics.falseCertaintyRate, 0);
  assert.equal(metrics.missedNominations.length, 0);
  assert.equal(metrics.wrongExclusions.length, 0);
  assert.equal(metrics.wrongNominations.length, 0);
  assert.equal(metrics.nominationPrecision, 1);
  assert.equal(metrics.realFinding.observedFindings, 0);
  assert.equal(metrics.discoveryRecall, null);
  assert.equal(metrics.independentAccuracy, null);
  assert.equal(metrics.inputHashes.labelsSha256, sha256File(LABELS));
});

test('blind eval: tampering one expected status lowers status accuracy', { skip: !blindRunDir() && 'no blind run' }, () => {
  const labels = JSON.parse(fs.readFileSync(LABELS, 'utf8'));
  const tampered = { ...labels, cases: labels.cases.map((row, index) =>
    index === 0 ? { ...row, expected: row.expected === 'candidate' ? 'excluded' : 'candidate' } : row) };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oh6-blind-'));
  const file = path.join(dir, 'labels.json');
  try {
    fs.writeFileSync(file, JSON.stringify(tampered), 'utf8');
    const metrics = blindEval.score(BLIND_RUN, file);
    assert.ok(metrics.statusAccuracy < 1);
    assert.ok(metrics.missedNominations.length + metrics.wrongExclusions.length +
      metrics.wrongNominations.length >= 1);
  } finally {
    if (path.resolve(dir).startsWith(path.resolve(os.tmpdir()) + path.sep)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});
