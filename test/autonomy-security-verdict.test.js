'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { main } = require('../bin/autonomy');
const { ModelGateway } = require('../lib/autonomy/model');
const { AUTONOMY_ROOT } = require('../lib/autonomy/store');

const root = path.join(__dirname, '..');
const knowledge = [
  'K/norms/050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c/knowledge.json',
  'K/norms/7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f/knowledge.json'
].join(',');
const common = ['--scope=K/policies/autonomy-pilot-scope.json',
  '--budget=K/policies/autonomy-pilot-budget.json', `--knowledge=${knowledge}`];
const unsetPolicyAsyncTask = 'TASK:ce534608cd00a85c';

function cleanup(runIds) {
  for (const runId of runIds) {
    const dir = path.resolve(AUTONOMY_ROOT, runId.replace(':', '-'));
    if (dir.startsWith(path.resolve(AUTONOMY_ROOT) + path.sep) &&
        /^RUN-[0-9a-f]{16}$/.test(path.basename(dir))) fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('new-old comparison: same snapshot keeps legacy contract finding and produces scoped security exclusion', async () => {
  const runIds = [];
  const invoke = async (args) => {
    const res = spawnSync(process.execPath, ['bin/autonomy.js', ...args],
      { cwd: root, encoding: 'utf8' });
    assert.equal(res.status, 0, res.stdout + res.stderr);
    return JSON.parse(res.stdout);
  };
  try {
    // 旧语义（≤1.0.19）经显式 --legacy-contract 保留：文档权限契约命题仍可产 finding。
    const legacy = await invoke(['run', '--mode=off', '--legacy-contract', ...common, `--task=${unsetPolicyAsyncTask}`]);
    runIds.push(legacy.runId);
    assert.equal(legacy.counts.finding, 1);
    const legacyRow = fs.readFileSync(path.resolve(root, legacy.runDir, 'report-model.jsonl'), 'utf8')
      .trim().split('\n').map((l) => JSON.parse(l).payload)
      .find((r) => r.origin === 'entry-scan');
    assert.equal(legacyRow.findingFamily, 'permission-mismatch');
    assert.equal(legacyRow.observedPermission, 'ohos.permission.SET_SANDBOX_POLICY');
    const legacyChecked = await invoke(['check', `--run=${legacy.runId}`]);
    assert.equal(legacyChecked.errors.length, 0);

    // 默认出口是 1.0.20：不加 flag 的静态套件 run 必须是新双命题语义。
    const defaulted = await invoke(['run', '--mode=off', ...common, `--task=${unsetPolicyAsyncTask}`]);
    runIds.push(defaulted.runId);
    const defaultDoc = JSON.parse(fs.readFileSync(
      path.resolve(root, defaulted.runDir, 'run.json'), 'utf8'));
    assert.equal(defaultDoc.payload.architectureVersion, '1.0.20-security-verdict');
    assert.equal(defaulted.counts.finding, 0);

    // 新语义（1.0.20）：同一入口不再因契约差异出 finding，改出限定主体 excluded。
    const verdict = await invoke(['run', '--mode=off', ...common, '--security-verdict',
      `--task=${unsetPolicyAsyncTask}`]);
    runIds.push(verdict.runId);
    assert.equal(verdict.counts.finding, 0);
    assert.equal(verdict.counts.excluded, 1);
    const verdictRow = fs.readFileSync(path.resolve(root, verdict.runDir, 'report-model.jsonl'), 'utf8')
      .trim().split('\n').map((l) => JSON.parse(l).payload)
      .find((r) => r.origin === 'entry-scan');
    assert.equal(verdictRow.contractDeviation, 'permission-mismatch');
    assert.equal(verdictRow.securityFamily, 'scoped-gate-rejection');
    assert.match(verdictRow.securitySubject, /FILE_ACCESS_PERSIST/);
    assert.match(verdictRow.securitySubject, /holds/);
    assert.equal(verdictRow.decision, 'refuted');
    const verdictChecked = await invoke(['check', `--run=${verdict.runId}`]);
    assert.equal(verdictChecked.errors.length, 0);
  } finally {
    cleanup(runIds);
  }
});

test('1.0.20 live security-gate-review replays with zero remote requests', async () => {
  const originalCreate = ModelGateway.create;
  const originalWrite = process.stdout.write;
  const output = [];
  const runIds = [];
  let sends = 0;
  process.stdout.write = (chunk) => { output.push(String(chunk)); return true; };
  ModelGateway.create = (options) => {
    const gateway = originalCreate(options);
    if (options.mode === 'live') gateway._transport = {
      keyPresent: () => true,
      send: async (request) => {
        sends++;
        return { kind: 'ok', content: JSON.stringify({ decision: 'insufficient',
          evidenceRefs: [firstAllowedEvidenceRef(request)],
          rationale: 'Gates appear to block; insufficient.' }), usage: { promptTokens: 10, completionTokens: 10 },
        usageKnown: true, finishReason: 'stop', model: 'test-transport', wallMs: 1 };
      }
    };
    return gateway;
  };
  const invoke = async (args) => {
    output.length = 0;
    const code = await main(args);
    assert.equal(code, 0, output.join(''));
    return JSON.parse(output.join(''));
  };
  try {
    const live = await invoke(['run', ...common, '--security-verdict', '--mode=live', '--max-tasks=3']);
    runIds.push(live.runId);
    assert.equal(sends, 3);
    const runDoc = JSON.parse(fs.readFileSync(
      path.resolve(AUTONOMY_ROOT, live.runId.replace(':', '-'), 'run.json'), 'utf8'));
    assert.equal(runDoc.payload.architectureVersion, '1.0.20-security-verdict');
    const callPurposes = fs.readdirSync(path.resolve(AUTONOMY_ROOT, live.runId.replace(':', '-'), 'model-calls'))
      .map((file) => JSON.parse(fs.readFileSync(
        path.resolve(AUTONOMY_ROOT, live.runId.replace(':', '-'), 'model-calls', file), 'utf8')).purpose);
    assert.ok(callPurposes.every((purpose) => purpose === 'security-gate-review'));
    const replay = await invoke(['run', ...common, '--security-verdict', '--mode=replay',
      `--replay-run=${live.runId}`, '--max-tasks=3']);
    runIds.push(replay.runId);
    assert.equal(sends, 3);
    assert.equal(replay.executed.modelRequests, 0);
    assert.equal(replay.executed.modelCalls, 3);
    assert.equal(replay.semanticHash, live.semanticHash);
    for (const runId of runIds) {
      const checked = await invoke(['check', `--run=${runId}`]);
      assert.deepEqual(checked.errors, []);
    }
  } finally {
    ModelGateway.create = originalCreate;
    process.stdout.write = originalWrite;
    cleanup(runIds);
  }
});

function firstAllowedEvidenceRef(request) {
  const blob = request.messages.map((m) => m.content).join('\n');
  const line = /允许引用的证据 ID：(.+)/.exec(blob);
  if (!line) return 'EVID:none';
  return line[1].split(',').map((s) => s.trim()).find((ref) => ref.startsWith('EVID:')) || 'EVID:none';
}

test('full off run yields a security finding under a controlled stub anchor (run → report → check)', async () => {
  const os = require('node:os');
  const crypto = require('node:crypto');
  const invoke = (args) => {
    const res = spawnSync(process.execPath, ['bin/autonomy.js', ...args],
      { cwd: root, encoding: 'utf8' });
    assert.equal(res.status, 0, res.stdout + res.stderr);
    return JSON.parse(res.stdout);
  };
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'oh6-stub-anchors-'));
  const runIds = [];
  try {
    // 受控桩：预期权限 FILE_ACCESS_PERSIST 伪装为 system_core+ACL 关闭（可锚定），
    // 门禁权限 SET_SANDBOX_POLICY 伪装为 normal（主体可获得）——仅用于贯通验证
    // 正向 finding 机制，不声称真实策略。
    const defs = { definePermissions: [
      { name: 'ohos.permission.SET_SANDBOX_POLICY', grantMode: 'system_grant',
        availableLevel: 'normal', availableType: 'NORMAL', since: 11, provisionEnable: false },
      { name: 'ohos.permission.FILE_ACCESS_PERSIST', grantMode: 'system_grant',
        availableLevel: 'system_core', availableType: 'SYSTEM', since: 11, provisionEnable: false },
      { name: 'ohos.permission.CHECK_SANDBOX_POLICY', grantMode: 'system_grant',
        availableLevel: 'system_basic', availableType: 'SYSTEM', since: 15, provisionEnable: true },
      { name: 'ohos.permission.FILE_ACCESS_MANAGER', grantMode: 'system_grant',
        availableLevel: 'system_basic', availableType: 'SYSTEM', since: 9, provisionEnable: true }
    ] };
    const defsPath = path.join(temp, 'stub-permissions.json').split(path.sep).join('/');
    fs.writeFileSync(defsPath, JSON.stringify(defs, null, 2) + '\n', 'utf8');
    const anchors = JSON.parse(fs.readFileSync(path.resolve(root,
      'K/policies/autonomy-security-anchors.json'), 'utf8'));
    anchors.permissionDefinitions.file = defsPath;
    anchors.permissionDefinitions.sha256 = crypto.createHash('sha256')
      .update(fs.readFileSync(defsPath)).digest('hex');
    const anchorsPath = path.join(temp, 'stub-anchors.json');
    fs.writeFileSync(anchorsPath, JSON.stringify(anchors, null, 2) + '\n', 'utf8');

    const run = invoke(['run', '--mode=off', ...common, '--security-anchors=' + anchorsPath,
      `--task=${unsetPolicyAsyncTask}`]);
    runIds.push(run.runId);
    assert.equal(run.counts.finding, 1, JSON.stringify(run.counts));
    const dir = path.resolve(root, run.runDir);
    const row = fs.readFileSync(path.join(dir, 'report-model.jsonl'), 'utf8').trim()
      .split('\n').map((l) => JSON.parse(l).payload).find((r) => r.origin === 'entry-scan');
    assert.equal(row.reportability, 'finding');
    assert.equal(row.securityFamily, 'gate-permission-weakened');
    assert.match(row.securitySubject, /SET_SANDBOX_POLICY/);
    assert.match(row.securityProposition, /can complete the scoped operation/);
    assert.ok(row.gates.some((g) => g.kind === 'permission-check' && g.blocksOperation === true));
    const findings = fs.readFileSync(path.join(dir, 'FINDINGS.md'), 'utf8');
    assert.match(findings, /SECURITY FINDINGS/);
    assert.match(findings, /gate-permission-weakened/);
    assert.match(findings, /策略锚点/);
    const checked = invoke(['check', `--run=${run.runId}`]);
    assert.equal(checked.errors.length, 0);
  } finally {
    cleanup(runIds);
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('full off run keeps the real anchor at candidate cap for the same entry', async () => {
  const invoke = (args) => {
    const res = spawnSync(process.execPath, ['bin/autonomy.js', ...args],
      { cwd: root, encoding: 'utf8' });
    assert.equal(res.status, 0, res.stdout + res.stderr);
    return JSON.parse(res.stdout);
  };
  const runIds = [];
  try {
    const run = invoke(['run', '--mode=off', ...common, `--task=${unsetPolicyAsyncTask}`]);
    runIds.push(run.runId);
    assert.equal(run.counts.finding, 0);
    assert.equal(run.counts.excluded, 1);
  } finally {
    cleanup(runIds);
  }
});

test('1.0.20 accepted model counterexample downgrades scoped exclusion to candidate', async () => {
  const originalCreate = ModelGateway.create;
  const originalWrite = process.stdout.write;
  const output = [];
  const runIds = [];
  let sends = 0;
  process.stdout.write = (chunk) => { output.push(String(chunk)); return true; };
  ModelGateway.create = (options) => {
    const gateway = originalCreate(options);
    if (options.mode === 'live') gateway._transport = {
      keyPresent: () => true,
      send: async (request) => {
        sends++;
        // 反例必须针对同一主体与路径命题，且引用本任务可回查证据（空引用会被证据门拒绝）。
        return { kind: 'ok', content: JSON.stringify({ decision: 'refuted',
          evidenceRefs: [firstAllowedEvidenceRef(request)],
          rationale: 'The scoped subject is rejected only in this delegate; the same oneway entry path reaches the operation without this gate.' }),
        usage: { promptTokens: 10, completionTokens: 10 },
        usageKnown: true, finishReason: 'stop', model: 'test-transport', wallMs: 1 };
      }
    };
    return gateway;
  };
  const invoke = async (args) => {
    output.length = 0;
    const code = await main(args);
    assert.equal(code, 0, output.join(''));
    return JSON.parse(output.join(''));
  };
  try {
    const live = await invoke(['run', ...common, '--security-verdict', '--mode=live',
      '--max-tasks=1', `--task=${unsetPolicyAsyncTask}`]);
    runIds.push(live.runId);
    assert.equal(sends, 1);
    const rows = fs.readFileSync(path.resolve(AUTONOMY_ROOT, live.runId.replace(':', '-'),
      'report-model.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l).payload);
    const row = rows.find((r) => r.origin === 'entry-scan');
    assert.equal(row.reportability, 'candidate');
    assert.ok(row.missing.includes('prover-model-conflict'));
    const checked = await invoke(['check', `--run=${live.runId}`]);
    assert.deepEqual(checked.errors, []);
  } finally {
    ModelGateway.create = originalCreate;
    process.stdout.write = originalWrite;
    cleanup(runIds);
  }
});
