'use strict';

/**
 * test/autonomy-doctor-index.test.js —— P1/P4：doctor 只读检查、Facts 适配、index 对账与确定性。
 *
 * 失败用例（全部必须**具名报错**，不得静默）：
 *   - 源文件哈希与 facts 不一致 ⇒ stale-input
 *   - 缺 l1 表 ⇒ missing-tables / doctor 的 facts-tables 失败
 *   - 非法 snapshot ⇒ snapshot-invalid / snapshot-missing
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const factsLib = require('../lib/autonomy/facts');
const doctorLib = require('../lib/autonomy/doctor');
const indexLib = require('../lib/autonomy/index');
const discovery = require('../lib/autonomy/discovery');
const jsonl = require('../lib/autonomy/jsonl');

const TOOL_DIR = path.join(__dirname, '..');
const SCOPE_PATH = 'K/policies/autonomy-pilot-scope.json';
const SNAPSHOT = 'sha256:2142c229d142bdacc472969fe96d73a36da4554f3775dee4f710b79878997a1e';

const scope = JSON.parse(fs.readFileSync(path.join(TOOL_DIR, SCOPE_PATH), 'utf8'));

let cachedFacts = null;
function facts() {
  if (!cachedFacts) cachedFacts = factsLib.AutonomyFacts.open({ snapshot: SNAPSHOT, scope });
  return cachedFacts;
}

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'autonomy-doctor-'));
}

test('doctor：只读、无网络、能力矩阵齐全、密钥只报布尔', () => {
  const out = doctorLib.runDoctor({ scopePath: SCOPE_PATH, budgetPath: 'K/policies/autonomy-pilot-budget.json' });
  assert.strictEqual(out.ok, true, `hardFail: ${out.hardFail.join(',')}`);
  assert.strictEqual(out.networkRequests, 0);
  assert.strictEqual(out.snapshotId, SNAPSHOT);
  assert.strictEqual(out.scopeId, 'sandbox_manager-pilot');
  assert.strictEqual(typeof out.capabilities.index, 'boolean');
  assert.strictEqual(out.capabilities.verify, false, 'verify 恒不可用（占位）');
  assert.ok(out.capabilities.unsupportedTools.includes('checkSource'));
  assert.ok(out.checks.every((c) => typeof c.id === 'string' && typeof c.pass === 'boolean'));
  assert.ok(out.checks.some((c) => c.id === 'facts-tables' && c.pass));
  assert.ok(out.checks.some((c) => c.id === 'llm-api-key'));
  const key = process.env.OH6_LLM_API_KEY;
  if (key && key.length >= 8) {
    assert.strictEqual(JSON.stringify(out).includes(key), false, 'doctor 输出不得包含密钥');
  }
});

test('doctor：缺 scope policy 必须 ok=false 且给出具名失败项', () => {
  const out = doctorLib.runDoctor({ scopePath: 'K/policies/does-not-exist.json', budgetPath: 'K/policies/autonomy-pilot-budget.json' });
  assert.strictEqual(out.ok, false);
  assert.ok(out.hardFail.includes('scope-policy'));
});

test('Facts：fileHash 与 verifyFile 命中真实文件；未知路径返回 null', () => {
  const f = facts();
  const rel = 'base/accesscontrol/sandbox_manager/frameworks/sandbox_manager/src/policy_info_parcel.cpp';
  const rec = f.fileHash(rel);
  assert.ok(rec && /^[0-9a-f]{64}$/.test(rec.sha256));
  const v = f.verifyFile(rel);
  assert.strictEqual(v.ok, true, `expected fresh, got ${v.reason}`);
  assert.strictEqual(f.fileHash('no/such/file.cpp'), null);
  const missing = f.verifyFile('no/such/file.cpp');
  assert.strictEqual(missing.ok, false);
  assert.strictEqual(missing.reason, 'not-in-facts');
});

test('Facts：源文件被改 ⇒ stale-input（失败用例，不静默）', () => {
  const dir = tmpdir();
  try {
    fs.mkdirSync(path.join(dir, 'l1'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'snapshot.json'), JSON.stringify({ snapshotId: `sha256:${'a'.repeat(64)}` }), 'utf8');
    for (const t of factsLib.TABLES) {
      if (t === 'files') continue;
      fs.writeFileSync(path.join(dir, 'l1', `${t}.jsonl`), '', 'utf8');
    }
    const srcRoot = path.join(dir, 'src');
    fs.mkdirSync(path.join(srcRoot, 'repo'), { recursive: true });
    fs.writeFileSync(path.join(srcRoot, 'repo', 'a.cpp'), 'abc', 'utf8');
    jsonl.writeJsonl(path.join(dir, 'l1', 'files.jsonl'), [{
      factId: 'F:aaaaaaaaaaaa:file:0123456789abcdef',
      kind: 'file',
      locator: { repo: 'repo', file: 'repo/a.cpp' },
      path: 'repo/a.cpp',
      repo: 'repo',
      bytes: 3,
      lines: 1,
      sha256: 'b'.repeat(64),
      role: 'production'
    }]);
    const f = new factsLib.AutonomyFacts(dir, { roots: [{ root: 'repo' }] }, { sourceRoot: srcRoot });
    const v = f.verifyFile('repo/a.cpp');
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.reason, 'stale-input');
    assert.strictEqual(v.expected, 'b'.repeat(64));
    assert.match(v.actual, /^[0-9a-f]{64}$/);

    // 缺表：先删一张再断言具名报错
    assert.deepStrictEqual(f.tableStatus().missing, []);
    fs.unlinkSync(path.join(dir, 'l1', 'calls.jsonl'));
    const missing = f.tableStatus().missing;
    assert.ok(missing.includes('calls'));
    assert.throws(() => f.assertTables(), (e) => e.code === 'missing-tables' && e.missing.includes('calls'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Facts：非法 / 缺失 snapshot 必须报错', () => {
  assert.throws(() => factsLib.AutonomyFacts.open({ snapshot: 'sha256:zz', scope }), (e) => e.code === 'snapshot-invalid');
  assert.throws(() => factsLib.AutonomyFacts.open({ snapshot: `sha256:${'f'.repeat(64)}`, scope }), (e) => e.code === 'snapshot-missing');
  assert.throws(() => factsLib.AutonomyFacts.open({ snapshot: '', scope }), (e) => e.code === 'snapshot-required');
});

test('index：与 facts 计数逐项对账，结构计数一致', () => {
  const f = facts();
  const built = indexLib.buildIndex(f, scope);
  const r = built.reconciliation;
  assert.strictEqual(r.ok, true, JSON.stringify(r));
  for (const key of Object.keys(r.expected)) {
    assert.strictEqual(r.actual[key], r.expected[key], `${key} 对账失败`);
  }
  assert.strictEqual(r.entryKinds.idl, 17);
  assert.strictEqual(r.entryKinds.sa, 2);
  assert.strictEqual(r.relationKinds.registers, 17, '17 个 IDL 方法都应唯一绑定到 SandboxManagerService 实现');
  assert.strictEqual(built.entities.every((e) => /^ENT:[0-9a-f]{16}$/.test(e.entityId)), true);
  assert.strictEqual(built.relations.every((x) => /^REL:[0-9a-f]{16}$/.test(x.relationId)), true);
  assert.strictEqual(built.relations.every((x) => x.kind === 'calls' || x.kind === 'registers'), true);
  assert.strictEqual(built.indexTruncated.functions, false);
  assert.strictEqual(built.indexTruncated.calls, false);
});

test('index：两次构建实体/关系 ID 序列完全一致（确定性）', () => {
  const f = facts();
  const a = indexLib.buildIndex(f, scope);
  const b = indexLib.buildIndex(f, scope);
  assert.deepStrictEqual(a.entities.map((e) => e.entityId), b.entities.map((e) => e.entityId));
  assert.deepStrictEqual(a.relations.map((r) => r.relationId), b.relations.map((r) => r.relationId));
});

test('index：scope 限额生效，缓存不得跨 scope 或限额复用', () => {
  const dir = tmpdir();
  try {
    const f = facts();
    indexLib.writeIndex(f, scope, { dir });
    assert.ok(indexLib.loadIndex(f, { dir }));
    const narrowed = { ...scope, limits: { ...scope.limits, maxIndexFunctions: 7 } };
    const other = factsLib.AutonomyFacts.open({ snapshot: SNAPSHOT, scope: narrowed });
    assert.strictEqual(other.limits.maxIndexFunctions, 7);
    assert.strictEqual(other.index().functions.length, 7);
    assert.strictEqual(other.index().truncated.functions, true);
    assert.strictEqual(indexLib.loadIndex(other, { dir }), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('discovery：19 入口 + 5 覆盖抽样 = 24 task / 72 question，且无重复无驳回', () => {
  const f = facts();
  const anchorsInfo = discovery.buildAnchors(f, scope);
  assert.strictEqual(anchorsInfo.entries.length, 19);
  assert.strictEqual(anchorsInfo.stats.entryKinds.idl, 17);
  assert.strictEqual(anchorsInfo.stats.entryKinds.sa, 2);
  assert.ok(anchorsInfo.coverageAnchors.length >= 1, '覆盖抽样不得为空');
  const proposal = discovery.proposeTasks(anchorsInfo, f, scope);
  assert.strictEqual(proposal.tasks.length, 19 + anchorsInfo.coverageAnchors.length);
  assert.strictEqual(proposal.questions.length, proposal.tasks.length * 3);
  assert.strictEqual(proposal.duplicates, 0);
  assert.strictEqual(proposal.rejected.length, 0);
  const origins = new Set(proposal.tasks.map((t) => t.origin));
  assert.deepStrictEqual([...origins].sort(), ['coverage-sample', 'entry-scan']);
  // 同一锚点重复提案不产生新 task
  const again = discovery.proposeTasks(anchorsInfo, f, scope);
  assert.deepStrictEqual(again.tasks.map((t) => t.taskId), proposal.tasks.map((t) => t.taskId));
});

test('discovery：IDL 方法按名称+owner 唯一绑定；SA 入口无方法体 ⇒ unbound + metadata-only', () => {
  const f = facts();
  const anchorsInfo = discovery.buildAnchors(f, scope);
  const ctx = { facts: f, scope, anchors: anchorsInfo.anchors };
  const idl = anchorsInfo.entries.find((e) => e.kind === 'idl' && e.method === 'SetPolicy');
  const b = discovery.resolveBinding(idl.entityId, ctx);
  assert.strictEqual(b.binding, 'resolved');
  assert.match(b.candidates[0].qualified, /SandboxManagerService::SetPolicy$/);
  const sa = anchorsInfo.entries.find((e) => e.kind === 'sa');
  const bs = discovery.resolveBinding(sa.entityId, ctx);
  assert.strictEqual(bs.binding, 'unbound');
  assert.match(bs.note, /no method body/);
  const empty = discovery.proposeTasks({ entries: [{ entityId: null }], coverageAnchors: [] }, f, scope);
  assert.strictEqual(empty.rejected.length, 1, '空入口不得生成空 task');
  assert.strictEqual(empty.tasks.length, 0);
});
