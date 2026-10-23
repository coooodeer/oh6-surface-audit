'use strict';

/**
 * test/autonomy-tools.test.js —— P2 工具 dispatcher 与受控工具清单。
 *
 * 失败用例（§6/P2 验收）：
 *   缺参 ⇒ status=error + invalid-args；超时 ⇒ cancelled；
 *   超限 ⇒ completeness.truncated=true；未实现工具 ⇒ status=unsupported（不得冒充实现）；
 *   源文件哈希不一致 ⇒ error + stale-input；预算用尽 ⇒ cancelled + budget-exhausted。
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const factsLib = require('../lib/autonomy/facts');
const tools = require('../lib/autonomy/tools');
const storeLib = require('../lib/autonomy/store');
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

function ctx(extra = {}) {
  return { facts: facts(), scope, budget: tools.createBudget({ maxToolCalls: 200 }), ...extra };
}

const ENTRY_SET_POLICY = 'OHOS.AccessControl.SandboxManager.ISandboxManager#SetPolicy';

function entryIdFor(method) {
  const discovery = require('../lib/autonomy/discovery');
  const info = discovery.buildAnchors(facts(), scope);
  const e = info.entries.find((x) => x.kind === 'idl' && x.method === method);
  assert.ok(e, `missing idl entry ${method}`);
  return e;
}

test('listTools：10 个 available + 4 个 unsupported，unsupported 都带具名 reason', () => {
  const list = tools.listTools();
  const avail = list.filter((t) => t.status === 'available').map((t) => t.name).sort();
  const un = list.filter((t) => t.status === 'unsupported');
  assert.deepStrictEqual(avail, [
    'getApplicableNorms', 'getEvidence', 'getScopeOverview', 'inspectAuthorization', 'inspectDelegation', 'inspectEntry', 'inspectOperationCandidate', 'inspectPermissionArgument', 'inspectRelation', 'searchEntities'
  ]);
  assert.strictEqual(un.length, 4);
  assert.deepStrictEqual(un.map((t) => t.name).sort(), [
    'checkSource', 'collectEvidence', 'inspectLifetime', 'traceValue'
  ]);
  for (const t of un) assert.match(t.reason, /not-implemented/);
});

test('getScopeOverview：计数与 scope 一致，观察项齐备', async () => {
  const r = await tools.run('getScopeOverview', { scopeId: scope.scopeId }, ctx());
  assert.strictEqual(r.payload.status, 'ok');
  assert.strictEqual(r.payload.answer.status, 'supported');
  const o = r.payload.observations;
  assert.strictEqual(o.functions, 566);
  assert.strictEqual(o.calls, 4958);
  assert.strictEqual(o.metadata.idl, 17);
  assert.strictEqual(o.entryCandidates.idl, 17);
  assert.strictEqual(o.entryCandidates.sa, 2);
  assert.strictEqual(r.payload.completeness.truncated, false);
  assert.match(r.recordId, /^EVID:[0-9a-f]{16}$/);
  assert.strictEqual(r.payload.resultId, r.recordId);
});

test('searchEntities：命中 supported、未命中 refuted（不伪造空结果）', async () => {
  const hit = await tools.run('searchEntities', { query: 'SetPolicy', limit: 5 }, ctx());
  assert.strictEqual(hit.payload.answer.status, 'supported');
  assert.ok(hit.payload.items.length > 0 && hit.payload.items.length <= 5);
  const miss = await tools.run('searchEntities', { query: 'ZzNoSuchSymbolZz' }, ctx());
  assert.strictEqual(miss.payload.answer.status, 'refuted');
  assert.deepStrictEqual(miss.payload.items, []);
});

test('inspectEntry / inspectRelation：resolved 与 registers 邻接可回查', async () => {
  const e = entryIdFor('SetPolicy');
  const r = await tools.run('inspectEntry', { entryRef: e.entityId }, ctx());
  assert.strictEqual(r.payload.answer.status, 'supported');
  assert.strictEqual(r.payload.observations.binding, 'resolved');
  assert.match(r.payload.observations.candidates[0].qualified, /SandboxManagerService::SetPolicy$/);
  const reg = await tools.run('inspectRelation', { ref: e.entityId, relation: 'registers' }, ctx());
  assert.strictEqual(reg.payload.answer.status, 'supported');
  assert.strictEqual(reg.payload.observations.binding, 'resolved');
  const calls = await tools.run('inspectRelation', { ref: e.entityId, relation: 'calls' }, ctx());
  assert.strictEqual(calls.payload.answer.status, 'supported');
  assert.ok(calls.payload.observations.edges.some((x) => x.calleeName === 'CheckPermission'));
  assert.strictEqual(calls.payload.observations.edges.every((x) => x.resolution), true);
});

test('inspectAuthorization：strong 命中 supported / 无命中 refuted / 只有 weak 信号 insufficient', async () => {
  const a = await tools.run('inspectAuthorization', { entryRef: entryIdFor('SetPolicy').entityId }, ctx());
  assert.strictEqual(a.payload.answer.status, 'supported');
  assert.ok(a.payload.observations.matches.some((m) => m.calleeName === 'CheckPermission' && m.tier === 'strong'));

  const b = await tools.run('inspectAuthorization', { entryRef: entryIdFor('SetPolicyAsync').entityId }, ctx());
  assert.strictEqual(b.payload.answer.status, 'refuted');
  assert.deepStrictEqual(b.payload.observations.callees, ['SetPolicy']);

  const c = await tools.run('inspectAuthorization', { entryRef: entryIdFor('StartAccessingByTokenId').entityId }, ctx());
  assert.strictEqual(c.payload.answer.status, 'unknown');
  assert.strictEqual(c.payload.errorCode, 'check-call-weak-only');
  assert.strictEqual(c.payload.observations.strongTier, 0);
  assert.ok(c.payload.observations.weakTier > 0);
});

test('inspectOperationCandidate returns sourced suspect, not a resolved operation', async () => {
  const result = await tools.run('inspectOperationCandidate',
    { entryRef: entryIdFor('PersistPolicy').entityId }, ctx());
  assert.strictEqual(result.payload.status, 'ok');
  assert.strictEqual(result.payload.answer.status, 'unknown');
  assert.strictEqual(result.payload.observations.candidates.length, 1);
  const candidate = result.payload.observations.candidates[0];
  assert.strictEqual(candidate.status, 'suspect');
  assert.deepStrictEqual(result.payload.evidenceRefs,
    [candidate.callRef, candidate.targetRef].sort());
  assert.match(candidate.source.sha256, /^[0-9a-f]{64}$/);
  assert.match(candidate.target.sha256, /^[0-9a-f]{64}$/);
});

test('getEvidence：窗口 + 哈希校验；不在 facts 的文件 ⇒ error + 具名 reason', async () => {
  const file = 'base/accesscontrol/sandbox_manager/frameworks/sandbox_manager/src/policy_info_parcel.cpp';
  const r = await tools.run('getEvidence', { file, line: 22, count: 6 }, ctx());
  assert.strictEqual(r.payload.status, 'ok');
  assert.strictEqual(r.payload.sourceWindows.length, 1);
  assert.match(r.payload.sourceWindows[0].sha256, /^[0-9a-f]{64}$/);
  assert.ok(r.payload.observations.text.includes('Marshalling') || r.payload.observations.text.length > 0);
  assert.strictEqual(r.payload.usage.bytesRead > 0, true);

  const missing = await tools.run('getEvidence', { file: 'base/accesscontrol/sandbox_manager/no-such.cpp', line: 1 }, ctx());
  assert.strictEqual(missing.payload.status, 'error');
  assert.strictEqual(missing.payload.errorCode, 'not-in-facts');
  assert.strictEqual(missing.payload.answer.status, 'unknown');
});

test('getEvidence：源文件哈希与 facts 不一致 ⇒ error + stale-input（拒引旧快照）', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'autonomy-tools-'));
  try {
    fs.mkdirSync(path.join(dir, 'l1'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'snapshot.json'), JSON.stringify({ snapshotId: `sha256:${'a'.repeat(64)}` }), 'utf8');
    for (const t of factsLib.TABLES) {
      if (t === 'files') continue;
      fs.writeFileSync(path.join(dir, 'l1', `${t}.jsonl`), '', 'utf8');
    }
    const srcRoot = path.join(dir, 'src');
    fs.mkdirSync(path.join(srcRoot, 'repo'), { recursive: true });
    fs.writeFileSync(path.join(srcRoot, 'repo', 'a.cpp'), 'int main(){return 0;}\n', 'utf8');
    jsonl.writeJsonl(path.join(dir, 'l1', 'files.jsonl'), [{
      factId: 'F:aaaaaaaaaaaa:file:0123456789abcdef',
      kind: 'file',
      locator: { repo: 'repo', file: 'repo/a.cpp' },
      path: 'repo/a.cpp',
      repo: 'repo',
      bytes: 21,
      lines: 1,
      sha256: 'c'.repeat(64),
      role: 'production'
    }]);
    const f = new factsLib.AutonomyFacts(dir, { roots: [{ root: 'repo' }] }, { sourceRoot: srcRoot });
    const r = await tools.run('getEvidence', { file: 'repo/a.cpp', line: 1 }, { facts: f, scope });
    assert.strictEqual(r.payload.status, 'error');
    assert.strictEqual(r.payload.errorCode, 'stale-input');
    assert.strictEqual(r.payload.completeness.enumeration, 'partial');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('失败用例：缺参 invalid-args、未知工具 unknown-tool、未实现工具 unsupported', async () => {
  const bad = await tools.run('inspectAuthorization', {}, ctx());
  assert.strictEqual(bad.payload.status, 'error');
  assert.strictEqual(bad.payload.errorCode, 'invalid-args');

  const unknown = await tools.run('noSuchTool', {}, ctx());
  assert.strictEqual(unknown.payload.status, 'error');
  assert.strictEqual(unknown.payload.errorCode, 'unknown-tool');

  for (const name of ['collectEvidence', 'inspectLifetime', 'traceValue', 'checkSource']) {
    const r = await tools.run(name, {}, ctx());
    assert.strictEqual(r.payload.status, 'unsupported', `${name} 必须是 unsupported`);
    assert.strictEqual(r.payload.errorCode, 'tool-unsupported');
    assert.ok(r.payload.answer.text.length > 10, `${name} 不得返回空结果冒充实现`);
    assert.strictEqual(r.payload.answer.status, 'unknown');
  }
});

test('失败用例：超时 ⇒ cancelled，超限 ⇒ truncated，预算 ⇒ budget-exhausted', async () => {
  tools.TOOLS.__slow = {
    version: '1',
    status: 'available',
    args: {},
    description: 'test-only slow tool',
    run() { return new Promise(() => {}); }
  };
  try {
    const timed = await tools.run('__slow', {}, { ...ctx(), timeoutMs: 15 });
    assert.strictEqual(timed.payload.status, 'cancelled');
    assert.strictEqual(timed.payload.errorCode, 'timeout');
  } finally {
    delete tools.TOOLS.__slow;
  }

  const capped = await tools.run('getScopeOverview', { scopeId: 'x' }, { ...ctx(), maxBytes: 600 });
  assert.strictEqual(capped.payload.completeness.truncated, true);
  assert.strictEqual(capped.payload.completeness.enumeration, 'partial');
  assert.ok(Buffer.byteLength(JSON.stringify(capped.payload), 'utf8') < 1500);

  const budget = tools.createBudget({ maxToolCalls: 1 });
  const bctx = { facts: facts(), scope, budget, taskId: 'TASK:0123456789abcdef' };
  await tools.run('searchEntities', { query: 'Policy' }, bctx);
  const second = await tools.run('searchEntities', { query: 'Policy' }, bctx);
  assert.strictEqual(second.payload.status, 'cancelled');
  assert.strictEqual(second.payload.errorCode, 'budget-exhausted');
});

test('EVID 只由语义字段派生：usage 变化不改变 resultId', async () => {
  const e = entryIdFor('SetPolicy');
  const a = await tools.run('inspectAuthorization', { entryRef: e.entityId }, ctx());
  const b = await tools.run('inspectAuthorization', { entryRef: e.entityId }, ctx());
  assert.strictEqual(a.recordId, b.recordId, '同一语义输入必须得到同一 EVID');
  const tampered = JSON.parse(JSON.stringify(a.payload));
  tampered.usage = { wallMs: 999999, bytesRead: 123456, cacheHit: true };
  tampered.nextActions = ['whatever'];
  assert.strictEqual(tools.evidenceIdOf(tampered), a.recordId, 'usage/nextActions 不得进入 EVID');
  const changed = JSON.parse(JSON.stringify(a.payload));
  changed.answer.text = `${changed.answer.text} (different)`;
  assert.notStrictEqual(tools.evidenceIdOf(changed), a.recordId);
});

test('归档：evidence/<EVID>.json + tool-ledger.jsonl（内容哈希可回查）', async () => {
  let runDir = null;
  try {
    const store = storeLib.RunStore.create({
      scopeId: scope.scopeId,
      snapshotId: SNAPSHOT,
      inputManifestId: facts().inputManifestId,
      mode: 'off',
      capabilityProfile: 'readonly-local',
      budget: { maxToolCalls: 10 },
      manifestId: facts().inputManifestId
    });
    runDir = store.dir;
    const r = await tools.run('searchEntities', { query: 'Policy' }, { ...ctx(), store });
    assert.strictEqual(fs.existsSync(path.join(runDir, 'evidence', `${r.recordId.replace(':', '-')}.json`)), true);
    const ledger = jsonl.readJsonl(path.join(runDir, 'tool-ledger.jsonl'));
    assert.strictEqual(ledger.rows.length, 1);
    assert.strictEqual(ledger.rows[0].resultId, r.recordId);
    assert.match(ledger.rows[0].archivedSha256, /^[0-9a-f]{64}$/);
    const archived = JSON.parse(fs.readFileSync(path.join(runDir, 'evidence', `${r.recordId.replace(':', '-')}.json`), 'utf8'));
    assert.deepStrictEqual(archived.payload, r.payload);
    // 归档件不得多出 schema 之外的可枚举字段
    assert.deepStrictEqual(Object.keys(archived).sort(), ['createdAt', 'dependencyRefs', 'manifestId', 'payload', 'producer', 'recordId', 'recordType', 'schemaVersion']);
  } finally {
    if (runDir && path.resolve(runDir).startsWith(path.resolve(storeLib.AUTONOMY_ROOT) + path.sep)) {
      fs.rmSync(runDir, { recursive: true, force: true });
    }
  }
});
