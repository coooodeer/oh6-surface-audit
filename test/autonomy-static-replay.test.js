'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { main } = require('../bin/autonomy');
const { ModelGateway } = require('../lib/autonomy/model');
const { AUTONOMY_ROOT } = require('../lib/autonomy/store');

const knowledge = [
  'K/norms/050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c/knowledge.json',
  'K/norms/7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f/knowledge.json'
].join(',');
const common = ['--scope=K/policies/autonomy-pilot-scope.json',
  '--budget=K/policies/autonomy-pilot-budget.json', `--knowledge=${knowledge}`, '--max-tasks=3'];

test('1.0.17 multi-entry live responses replay without transport and pass source-backed check', async () => {
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
      send: async () => {
        sends++;
        return { kind: 'ok', content: JSON.stringify({ decision: 'insufficient', evidenceRefs: [],
          rationale: 'Local test response.' }), usage: { promptTokens: 10, completionTokens: 10 },
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
    const live = await invoke(['run', ...common, '--mode=live', '--max-model-requests=3']);
    runIds.push(live.runId);
    assert.equal(live.planned.tasks, 3);
    assert.equal(sends, 3);
    const replay = await invoke(['run', ...common, '--mode=replay', `--replay-run=${live.runId}`]);
    runIds.push(replay.runId);
    assert.equal(sends, 3);
    assert.equal(replay.executed.modelRequests, 0);
    assert.equal(replay.executed.modelCalls, 3);
    assert.match(live.semanticHash, /^sha256:[0-9a-f]{64}$/);
    assert.equal(replay.semanticHash, live.semanticHash);
    for (const runId of runIds) {
      const checked = await invoke(['check', `--run=${runId}`]);
      assert.deepEqual(checked.errors, []);
    }
  } finally {
    ModelGateway.create = originalCreate;
    process.stdout.write = originalWrite;
    for (const runId of runIds) {
      const dir = path.resolve(AUTONOMY_ROOT, runId.replace(':', '-'));
      if (dir.startsWith(path.resolve(AUTONOMY_ROOT) + path.sep) &&
          /^RUN-[0-9a-f]{16}$/.test(path.basename(dir))) fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});
