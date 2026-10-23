'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { RunStore, AUTONOMY_ROOT } = require('../lib/autonomy/store');
const { ModelGateway, loadReplaySource } = require('../lib/autonomy/model');

test('parsed live response replays only for the identical request and intact source', async () => {
  const source = RunStore.create({ scopeId: 'replay-test', snapshotId: `sha256:${'a'.repeat(64)}`,
    inputManifestId: 'AM-aaaaaaaaaaaaaaaa', manifestId: 'AM-aaaaaaaaaaaaaaaa',
    architectureVersion: '1.0.5-vertical-experiment', knowledgeVersion: `sha256:${'b'.repeat(64)}`,
    modelId: 'cn:test', mode: 'live', capabilityProfile: 'model-enabled', budget: {} });
  try {
    const live = new ModelGateway({ mode: 'live', modelOverride: 'cn:test', store: source,
      budget: { reserveModel: () => {}, settleModel: () => {} } });
    live._transport = { keyPresent: () => true, send: () => Promise.resolve({ kind: 'ok',
      content: '{"decision":"insufficient"}', usage: { promptTokens: 3, completionTokens: 2 },
      usageKnown: true, finishReason: 'stop', model: 'test', wallMs: 1 }) };
    const request = { purpose: 'vertical-plan', taskId: 'TASK:aaaaaaaaaaaaaaaa',
      contextId: 'CTX:aaaaaaaaaaaaaaaa', maxTokens: 100, messages: [{ role: 'user', content: 'bounded' }] };
    const original = await live.invoke(request);
    source.writeChecksums();
    const replaySource = loadReplaySource(source);
    assert.match(replaySource.sourceFilesSha256, /^[0-9a-f]{64}$/);
    const replay = new ModelGateway({ mode: 'replay', replaySource,
      store: { runId: 'RUN:bbbbbbbbbbbbbbbb', writeModelCall: () => {}, appendModelLedger: () => {} } });
    const response = replay.invoke(request);
    assert.equal(response.status, 'ok');
    assert.deepEqual(response.parsed, original.parsed);
    assert.equal(response.sourceCallId, original.callId);
    assert.equal(response.sourceRunId, source.runId);
    assert.equal(response.content, null);
    assert.throws(() => replay.invoke({ ...request, messages: [{ role: 'user', content: 'changed' }] }),
      /no archived response/);
    source.writeJson('verification/placeholder.json', { status: 'blocked' });
    source.updateManifest({ verification: { status: 'blocked' } });
    source.appendEvent({ kind: 'verify-placeholder', detail: { status: 'blocked' } });
    source.writeChecksums();
    const afterVerify = loadReplaySource(source);
    assert.equal(afterVerify.sourceFilesSha256, replaySource.sourceFilesSha256);
    assert.notEqual(afterVerify.checksumsSha256, replaySource.checksumsSha256);
    fs.appendFileSync(source.file(`model-calls/${original.callId.replace(':', '-')}.json`), ' ');
    assert.throws(() => loadReplaySource(source), /checksums do not match/);
  } finally {
    const target = path.resolve(source.dir);
    if (target.startsWith(path.resolve(AUTONOMY_ROOT) + path.sep) &&
        /^RUN-[0-9a-f]{16}$/.test(path.basename(target))) fs.rmSync(target, { recursive: true, force: true });
  }
});

test('truncated live JSON is charged and archived but cannot be interpreted or replayed', async () => {
  const source = RunStore.create({ scopeId: 'truncated-test', snapshotId: 'sha256:' + 'a'.repeat(64),
    inputManifestId: 'AM-aaaaaaaaaaaaaaaa', manifestId: 'AM-aaaaaaaaaaaaaaaa',
    architectureVersion: '1.0.8-vertical-experiment', knowledgeVersion: 'sha256:' + 'b'.repeat(64),
    modelId: 'cn:test', mode: 'live', capabilityProfile: 'model-enabled', budget: {} });
  try {
    const settled = [];
    const gateway = new ModelGateway({ mode: 'live', modelOverride: 'cn:test', store: source,
      budget: { reserveModel: () => {}, settleModel: (usage) => settled.push(usage) } });
    gateway._transport = { keyPresent: () => true, send: () => Promise.resolve({ kind: 'ok',
      content: '{"decision":"supported"}', usage: { promptTokens: 3, completionTokens: 100 },
      usageKnown: true, finishReason: 'length', model: 'test', wallMs: 1 }) };
    const result = await gateway.invoke({ purpose: 'vertical-interpret', taskId: 'TASK:aaaaaaaaaaaaaaaa',
      contextId: 'CTX:aaaaaaaaaaaaaaaa', messages: [{ role: 'user', content: 'bounded' }] });
    assert.equal(result.status, 'error');
    assert.equal(result.reason, 'model-response-incomplete');
    assert.equal(result.parsed, null);
    assert.equal(result.finishReason, 'length');
    assert.deepEqual(settled, [{ inputTokens: 3, outputTokens: 100 }]);
    source.writeChecksums();
    assert.throws(() => loadReplaySource(source), /not settled and successful/);
  } finally {
    const target = path.resolve(source.dir);
    if (target.startsWith(path.resolve(AUTONOMY_ROOT) + path.sep) &&
        /^RUN-[0-9a-f]{16}$/.test(path.basename(target))) fs.rmSync(target, { recursive: true, force: true });
  }
});

test('authentication failure stops later live network requests in the same run', async () => {
  let sends = 0;
  let reserved = 0;
  const gateway = new ModelGateway({ mode: 'live', modelOverride: 'cn:test',
    budget: { reserveModel: () => { reserved++; } } });
  gateway._transport = { keyPresent: () => true, send: () => {
    sends++;
    return Promise.resolve({ kind: 'auth-failed', reason: 'http-401', wallMs: 1 });
  } };
  const request = { purpose: 'check-presence', contextId: 'CTX:aaaaaaaaaaaaaaaa',
    messages: [{ role: 'user', content: 'bounded' }] };
  const first = await gateway.invoke({ ...request, taskId: 'TASK:aaaaaaaaaaaaaaaa' });
  const second = gateway.invoke({ ...request, taskId: 'TASK:bbbbbbbbbbbbbbbb' });
  assert.equal(first.reason, 'auth-failed');
  assert.equal(second.reason, 'auth-failed');
  assert.equal(sends, 1);
  assert.equal(reserved, 1);
});
