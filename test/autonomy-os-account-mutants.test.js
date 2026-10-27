'use strict';

/**
 * 第二组件受控变异体评测的回归测试（E3）。
 * 固定：8 个家族 × OpenSession、Builder 标签来源、冻结源码哈希、无正向 finding 分母。
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const evalTool = require('../tools/autonomy-os-account-eval');

test('os_account mutants: 8 frozen families reproduce expected verdicts and families', () => {
  const metrics = evalTool.evaluate();
  assert.equal(metrics.sampleCount, 8);
  assert.equal(metrics.familyCount, 8);
  assert.equal(metrics.judgmentAccuracy, 1);
  assert.equal(metrics.securityFamilyAccuracy, 1);
  assert.equal(metrics.contractFamilyAccuracy, 1);
  assert.equal(metrics.falseCertaintyRate, 0);
  assert.equal(metrics.denominators.positiveMutants, 0);
  assert.equal(metrics.denominators.reportedFindings, 0);
  assert.equal(metrics.findingPrecision, null);
  assert.equal(metrics.givenMutantFindingRecall, null);
  assert.equal(metrics.discoveryRecall, null);
  assert.equal(metrics.independentAccuracy, null);
  assert.equal(metrics.labelSource, 'builder-llm-oracle');
  assert.deepEqual(metrics.uncovered.methodsWithoutPublishedNorm, ['GetCredentialInfo', 'GetAccountState']);
  for (const row of metrics.rows) {
    assert.equal(row.operationBound, true, `${row.familyId} operation`);
    assert.equal(row.observed, row.expected, row.familyId);
  }
});

test('os_account mutants: labels hash is frozen and source drift is rejected', () => {
  const loaded = evalTool.loadLabels();
  assert.equal(loaded.sha256, '7548cf345351f1e51b6c2672e3d009a610ac117dd114ccbcfeb51ec76f5d8b6a');
  const tampered = { ...loaded.labels,
    labels: [{ ...loaded.labels.labels[0], sha256: '0'.repeat(64) }, ...loaded.labels.labels.slice(1)] };
  assert.throws(() => evalTool.evaluate({ labels: tampered }),
    /os-account-mutant-source-drift/);
  const extra = { ...loaded.labels, labels: [...loaded.labels.labels,
    { ...loaded.labels.labels[0], file: 'not-present.cpp' }] };
  assert.throws(() => evalTool.evaluate({ labels: extra }),
    /os-account-mutant-corpus-differs-from-frozen-labels/);
  const wrongScope = { ...loaded.labels, scopeId: 'sandbox_manager-pilot' };
  assert.throws(() => evalTool.evaluate({ labels: wrongScope }),
    /os-account-mutants-scope-or-snapshot-mismatch/);
});
