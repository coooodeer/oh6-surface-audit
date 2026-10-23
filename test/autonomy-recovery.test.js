'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { AUTONOMY_ROOT } = require('../lib/autonomy/store');
const { reconcileModelLedger, reconcileToolEvents } = require('../lib/autonomy/recovery');
const { ModelGateway } = require('../lib/autonomy/model');

test('reserved paid request without a result is uncertain, never replayed automatically', () => {
  const id = 'CALL:aaaaaaaaaaaaaaaa';
  const intent = { callId: id, status: 'reserved', requestSha256: 'a'.repeat(64) };
  const unknown = reconcileModelLedger([intent]);
  assert.deepEqual(unknown.pending, [id]);
  assert.equal(unknown.outcome, 'remote-outcome-unknown');
  assert.equal(unknown.autoResend, false);
  const settled = reconcileModelLedger([intent, { callId: id, status: 'ok' }]);
  assert.equal(settled.pending.length, 0);
  assert.equal(settled.finished, 1);
  assert.throws(() => reconcileModelLedger([intent, intent]), /duplicate-model-intent/);
});

test('tool intent pairs are checked and an uncompleted action stays pending', () => {
  const intent = { kind: 'tool-intent', actionId: 'ACT:aaaaaaaaaaaaaaaa',
    taskId: 'TASK:aaaaaaaaaaaaaaaa', detail: { tool: 'inspectEntry', argumentsSha256: 'a'.repeat(64) } };
  const done = { kind: 'tool-completed', taskId: intent.taskId,
    detail: { intentId: intent.actionId, resultId: 'EVID:aaaaaaaaaaaaaaaa' } };
  assert.equal(reconcileToolEvents([intent]).pendingTools.length, 1);
  assert.equal(reconcileToolEvents([intent, done]).completedTools.length, 1);
  assert.throws(() => reconcileToolEvents([done]), /tool-completion-unbound/);
  assert.throws(() => reconcileToolEvents([intent, done, done]), /tool-completion-unbound/);
});

test('Windows crash at first read-only tool intent resumes the same run once', () => {
  const crashed = spawnSync(process.execPath, ['tools/fixtures/crash-tool-intent.js'],
    { cwd: path.join(__dirname, '..'), encoding: 'utf8' });
  assert.equal(crashed.status, 71, crashed.stderr);
  const { runId, dir } = JSON.parse(crashed.stdout);
  let cleanDir;
  try {
    const events = fs.readFileSync(path.join(dir, 'events.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(events.at(-1).kind, 'tool-intent');
    const recovered = spawnSync(process.execPath, ['bin/autonomy.js', 'recover', '--run=' + runId],
      { cwd: path.join(__dirname, '..'), encoding: 'utf8' });
    assert.equal(recovered.status, 3, recovered.stderr);
    const outcome = JSON.parse(recovered.stdout);
    assert.equal(outcome.toolTraceStatus, 'recorded');
    assert.equal(outcome.pendingTools.length, 1);
    assert.equal(outcome.autoRerunTools, false);
    assert.deepEqual(outcome.incompleteTasks, ['TASK:108bcc806d3fc6f0']);
    const resumed = spawnSync(process.execPath, ['bin/autonomy.js', 'resume', '--run=' + runId,
      '--mode=off', '--scope=K/policies/autonomy-pilot-scope.json',
      '--budget=K/policies/autonomy-pilot-budget.json'],
    { cwd: path.join(__dirname, '..'), encoding: 'utf8' });
    assert.equal(resumed.status, 0, resumed.stderr);
    assert.equal(JSON.parse(resumed.stdout).runId, runId);
    const after = fs.readFileSync(path.join(dir, 'events.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(after.filter((ev) => ev.kind === 'run-resumed').length, 1);
    assert.equal(after.filter((ev) => ev.kind === 'task-started' && ev.taskId === events.at(-1).taskId).length, 1);
    assert.equal(after.filter((ev) => ev.kind === 'tool-intent').length, 8);
    assert.equal(after.filter((ev) => ev.kind === 'tool-completed').length, 8);
    const checked = spawnSync(process.execPath, ['bin/autonomy.js', 'check', '--run=' + runId],
      { cwd: path.join(__dirname, '..'), encoding: 'utf8' });
    assert.equal(checked.status, 0, checked.stderr);
    const clean = spawnSync(process.execPath, ['bin/autonomy.js', 'run', '--experiment=vertical-v1',
      '--mode=off', '--scope=K/policies/autonomy-pilot-scope.json',
      '--budget=K/policies/autonomy-pilot-budget.json', '--task=TASK:108bcc806d3fc6f0'],
    { cwd: path.join(__dirname, '..'), encoding: 'utf8' });
    assert.equal(clean.status, 0, clean.stderr);
    cleanDir = path.resolve(__dirname, '..', JSON.parse(clean.stdout).runDir);
    const hash = (target) => JSON.parse(fs.readFileSync(path.join(target, 'report-model.json'), 'utf8')).semanticHash;
    assert.equal(hash(dir), hash(cleanDir));
  } finally {
    for (const item of [dir, cleanDir]) {
      const target = item && path.resolve(item);
      if (target && target.startsWith(path.resolve(AUTONOMY_ROOT) + path.sep) &&
          /^RUN-[0-9a-f]{16}$/.test(path.basename(target))) fs.rmSync(target, { recursive: true, force: true });
    }
  }
});

test('first-tool resume rejects drift and uncommitted artifacts before appending', () => {
  for (const corrupt of ['intent', 'ledger', 'task', 'implementation']) {
    const crashed = spawnSync(process.execPath, ['tools/fixtures/crash-tool-intent.js'],
      { cwd: path.join(__dirname, '..'), encoding: 'utf8' });
    assert.equal(crashed.status, 71, crashed.stderr);
    const { runId, dir } = JSON.parse(crashed.stdout);
    try {
      const eventFile = path.join(dir, 'events.jsonl');
      const before = fs.readFileSync(eventFile, 'utf8');
      if (corrupt === 'intent') {
        const events = before.trim().split('\n').map(JSON.parse);
        events.at(-1).detail.argumentsSha256 = 'f'.repeat(64);
        fs.writeFileSync(eventFile, events.map((ev) => JSON.stringify(ev)).join('\n') + '\n', 'utf8');
      } else if (corrupt === 'ledger') fs.writeFileSync(path.join(dir, 'tool-ledger.jsonl'), '{}\n', 'utf8');
      else if (corrupt === 'implementation') {
        const file = path.join(dir, 'manifest.json');
        const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
        assert.match(manifest.implementationFingerprint, /^[0-9a-f]{64}$/);
        manifest.implementationFingerprint = '0'.repeat(64);
        fs.writeFileSync(file, JSON.stringify(manifest), 'utf8');
      } else {
        const file = path.join(dir, 'tasks.jsonl');
        const record = JSON.parse(fs.readFileSync(file, 'utf8').trim());
        record.payload.question = 'changed during interruption';
        fs.writeFileSync(file, JSON.stringify(record) + '\n', 'utf8');
      }
      const eventCount = fs.readFileSync(eventFile, 'utf8').trim().split('\n').length;
      const resumed = spawnSync(process.execPath, ['bin/autonomy.js', 'resume', '--run=' + runId,
        '--mode=off', '--scope=K/policies/autonomy-pilot-scope.json',
        '--budget=K/policies/autonomy-pilot-budget.json'],
      { cwd: path.join(__dirname, '..'), encoding: 'utf8' });
      assert.equal(resumed.status, 3);
      if (corrupt === 'implementation') assert.match(resumed.stderr, /resume implementation drift/);
      assert.equal(fs.readFileSync(eventFile, 'utf8').trim().split('\n').length, eventCount);
    } finally {
      const target = path.resolve(dir);
      if (target.startsWith(path.resolve(AUTONOMY_ROOT) + path.sep) &&
          /^RUN-[0-9a-f]{16}$/.test(path.basename(target))) fs.rmSync(target, { recursive: true, force: true });
    }
  }
});

test('live gateway commits intent before transport send, then result', async () => {
  const ledger = [];
  const store = { appendModelLedger: (entry) => ledger.push(entry), writeModelCall: () => {} };
  const budget = { reserveModel: () => {}, settleModel: () => {} };
  const gateway = new ModelGateway({ mode: 'live', modelOverride: 'cn:test', store, budget });
  gateway._transport = { keyPresent: () => true, send: () => {
    assert.equal(ledger.length, 1);
    assert.equal(ledger[0].status, 'reserved');
    assert.match(ledger[0].requestSha256, /^[0-9a-f]{64}$/);
    return Promise.resolve({ kind: 'ok', content: '{"decision":"insufficient"}',
      usage: { promptTokens: 1, completionTokens: 1 }, usageKnown: true,
      finishReason: 'stop', model: 'test', wallMs: 1 });
  } };
  const call = await gateway.invoke({ purpose: 'test', taskId: 'TASK:aaaaaaaaaaaaaaaa',
    contextId: 'CTX:aaaaaaaaaaaaaaaa', messages: [] });
  assert.equal(call.status, 'ok');
  assert.deepEqual(ledger.map((entry) => entry.status), ['reserved', 'ok']);
  assert.equal(reconcileModelLedger(ledger).pending.length, 0);
});

test('Windows process termination leaves a non-replayed unknown paid outcome', async () => {
  const child = spawn(process.execPath, [path.join(__dirname, '../tools/fixtures/crash-live-intent.js')],
    { cwd: path.join(__dirname, '..'), stdio: ['ignore', 'pipe', 'pipe'] });
  let dir;
  try {
    const info = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('intent fixture timed out')), 5000);
      child.once('error', reject);
      child.stdout.once('data', (data) => { clearTimeout(timer); resolve(JSON.parse(String(data).trim())); });
    });
    dir = info.dir;
    child.kill();
    await new Promise((resolve) => child.once('exit', resolve));
    const inspected = spawnSync(process.execPath, ['bin/autonomy.js', 'recover', `--run=${dir}`],
      { cwd: path.join(__dirname, '..'), encoding: 'utf8' });
    const result = JSON.parse(inspected.stdout);
    assert.equal(inspected.status, 3);
    assert.equal(result.outcome, 'remote-outcome-unknown');
    assert.equal(result.pending.length, 1);
    assert.equal(result.autoResend, false);
    assert.equal(result.toolTraceStatus, 'not-recorded');
    assert.equal(result.pendingTools, null);
    assert.equal(result.modelRequests, 0);
  } finally {
    if (child.exitCode === null) child.kill();
    const target = dir && path.resolve(dir);
    if (target && target.startsWith(path.resolve(AUTONOMY_ROOT) + path.sep) &&
        /^RUN-[0-9a-f]{16}$/.test(path.basename(target))) fs.rmSync(target, { recursive: true, force: true });
  }
});
