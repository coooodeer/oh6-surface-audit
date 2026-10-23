'use strict';

/**
 * test/fact-quality.test.js —— AG0.5（P5）质量/覆盖/unsupported 汇总。
 * 覆盖：计数聚合、ratio 除零、coverage 行唯一且取值域正确、unsupported 合并去重与原因分布。
 */

const test = require('node:test');
const assert = require('node:assert');

const q = require('../lib/facts/quality');

const ROWS = [
  { file: 'a.cpp', role: 'production', parse: 'full', errorNodes: 0, counts: { functions: 3, calls: 10 }, macroFunctions: 0, astCallExpressions: 12, astFunctionDefinitions: 3, cfgCoverageAvg: 1, dfgCoverageAvg: 0.5, cfgUnsupportedEdges: 0 },
  { file: 'b.cpp', role: 'test', parse: 'partial', errorNodes: 7, counts: { functions: 2, calls: 5 }, macroFunctions: 2, astCallExpressions: 5, astFunctionDefinitions: 0, cfgCoverageAvg: 0.8, dfgCoverageAvg: 0.3, cfgUnsupportedEdges: 2 },
  { file: 'c.cpp', role: 'test', parse: 'failed', errorNodes: 0, counts: { functions: 0, calls: 0 }, macroFunctions: 0, astCallExpressions: 0, astFunctionDefinitions: 0, cfgCoverageAvg: null, dfgCoverageAvg: null, cfgUnsupportedEdges: 0 }
];

test('summarize：计数与平均值', () => {
  const s = q.summarize(ROWS);
  assert.strictEqual(s.totals.files, 3);
  assert.strictEqual(s.totals.production, 1);
  assert.strictEqual(s.totals.test, 2);
  assert.strictEqual(s.totals.parseFull, 1);
  assert.strictEqual(s.totals.parsePartial, 1);
  assert.strictEqual(s.totals.parseFailed, 1);
  assert.strictEqual(s.totals.functions, 5);
  assert.strictEqual(s.totals.calls, 15);
  assert.strictEqual(s.totals.macroFunctions, 2);
  assert.strictEqual(s.totals.astCallExpressions, 17);
  assert.strictEqual(s.totals.astFunctionDefinitions, 3);
  assert.strictEqual(s.totals.cfgUnsupportedEdges, 2);
  assert.strictEqual(s.cfgCoverageAvg, Number(((1 + 0.8) / 2).toFixed(4)));
  assert.strictEqual(s.dfgCoverageAvg, 0.4);
});

test('ratio：除零返回 null（失败用例）', () => {
  assert.strictEqual(q.ratio(1, 0), null);
  assert.strictEqual(q.ratio(0, 0), null);
  assert.strictEqual(q.ratio(1, 4), 0.25);
});

test('coverageRows：行唯一、关键比率正确', () => {
  const s = q.summarize(ROWS);
  const rows = q.coverageRows({
    totals: s.totals,
    callsWritten: 15,
    compdb: { entries: 100, rootFiles: 3 },
    gen: { referenced: 4, missing: 1 },
    cfgAvg: s.cfgCoverageAvg,
    dfgAvg: s.dfgCoverageAvg
  });
  const metrics = rows.map((r) => r.metric);
  assert.deepStrictEqual([...new Set(metrics)].sort(), [...metrics].sort(), 'metric 不能重复');
  const by = new Map(rows.map((r) => [r.metric, r]));
  assert.strictEqual(by.get('call-attribution').value, Number((15 / 17).toFixed(4)));
  assert.strictEqual(by.get('function-coverage').value, Number((3 / 3).toFixed(4)), '3 个普通函数 / 3 个 AST 函数定义');
  assert.strictEqual(by.get('compdb-coverage').value, 1);
  assert.strictEqual(by.get('generated-headers').value, 0.75);
  assert.strictEqual(by.get('parse').value, Number((1 / 3).toFixed(4)));
  assert.strictEqual(by.get('macro-expansion').value, 0);
  for (const r of rows) {
    if (r.value !== null && typeof r.value === 'number' && r.metric !== 'files') {
      assert.ok(r.value >= 0 && r.value <= 1, `${r.metric} 应在 [0,1]：${r.value}`);
    }
  }
});

test('coverageRows：空输入不崩（失败用例）', () => {
  const s = q.summarize([]);
  const rows = q.coverageRows({ totals: s.totals, callsWritten: 0, compdb: { entries: 0, rootFiles: 0 }, gen: { referenced: 0, missing: 0 }, cfgAvg: null, dfgAvg: null });
  assert.ok(rows.length >= 8);
  assert.strictEqual(rows.find((r) => r.metric === 'call-attribution').value, null);
});

test('coverageRows：有 clang 数据时追加 clang-sampled/clang-ok；无数据时不追加', () => {
  const s = q.summarize(ROWS);
  const base = q.coverageRows({ totals: s.totals, callsWritten: 15, compdb: { entries: 1, rootFiles: 3 }, gen: { referenced: 1, missing: 0 }, cfgAvg: 1, dfgAvg: 1 });
  assert.strictEqual(base.some((r) => r.metric.startsWith('clang-')), false);

  const withClang = q.coverageRows({
    totals: s.totals, callsWritten: 15, compdb: { entries: 1, rootFiles: 3 }, gen: { referenced: 1, missing: 0 }, cfgAvg: 1, dfgAvg: 1,
    clang: { checked: 2, ok: 1, byStatus: { ok: 1, 'missing-header': 1 }, mode: 'sample' }
  });
  const by = new Map(withClang.map((r) => [r.metric, r]));
  assert.strictEqual(by.get('clang-sampled').value, Number((2 / 3).toFixed(4)));
  assert.strictEqual(by.get('clang-ok').value, 0.5);
  assert.deepStrictEqual(by.get('clang-ok').detail.byStatus, { ok: 1, 'missing-header': 1 });
});

test('mergeUnsupported：按 id 去重并保留全部原因', () => {
  const a = [{ id: 'U:1', reason: 'ast-error-nodes', file: 'a.cpp' }, { id: 'U:2', reason: 'token-absent', file: 'x.idl' }];
  const b = [{ id: 'U:2', reason: 'token-absent', file: 'x.idl' }, { id: 'U:3', reason: 'definition-pending', file: null }];
  const merged = q.mergeUnsupported([a, b]);
  assert.strictEqual(merged.length, 3);
  assert.deepStrictEqual(q.countByReason(merged), { 'ast-error-nodes': 1, 'token-absent': 1, 'definition-pending': 1 });
});

test('mergeUnsupported：无 id 的行用 reason+file 兜底', () => {
  const merged = q.mergeUnsupported([[{ reason: 'no-compdb', file: 'a.cpp' }], [{ reason: 'no-compdb', file: 'a.cpp' }]]);
  assert.strictEqual(merged.length, 1);
  assert.ok(merged[0].id);
});
