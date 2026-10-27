'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { main } = require('../bin/autonomy');
const { ModelGateway } = require('../lib/autonomy/model');
const { AUTONOMY_ROOT } = require('../lib/autonomy/store');

const knowledge = [
  'K/norms/050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c/knowledge.json',
  'K/norms/7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f/knowledge.json'
].join(',');
const common = ['--scope=K/policies/autonomy-pilot-scope.json',
  '--budget=K/policies/autonomy-pilot-budget.json', '--legacy-contract', `--knowledge=${knowledge}`, '--max-tasks=3'];

test('legacy 1.0.19 empty-evidence-ref reviews stay acceptable and replay identically', async () => {
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
        // ≤1.0.19 沿用其当时接受规则：空引用的反例意见可被接受（1.0.20 起才要求非空）。
        return { kind: 'ok', content: JSON.stringify({ decision: 'refuted', evidenceRefs: [],
          rationale: 'Legacy-shaped review with no cited refs.' }),
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
    const live = await invoke(['run', ...common, '--mode=live', '--max-tasks=1']);
    runIds.push(live.runId);
    assert.equal(sends, 1);
    const liveDir = path.resolve(AUTONOMY_ROOT, live.runId.replace(':', '-'));
    const review = JSON.parse(fs.readFileSync(path.join(liveDir, 'model-calls',
      fs.readdirSync(path.join(liveDir, 'model-calls'))[0]), 'utf8'));
    assert.equal(review.parsed.decision, 'refuted');
    assert.deepEqual(review.parsed.evidenceRefs, []);
    // 仲裁消费断言：空引用意见必须真的进入 static-contract 评估（modelCallRef 挂接、
    // 裁决与门禁结果可复算），而不是被静默拒绝后仅哈希碰巧一致。
    const arbitrationOf = (dir) => {
      const questions = fs.readFileSync(path.join(dir, 'questions.jsonl'), 'utf8').trim()
        .split('\n').map(JSON.parse);
      const contract = questions.find((row) => row.payload.kind === 'static-contract');
      const assessments = fs.readFileSync(path.join(dir, 'assessments.jsonl'), 'utf8').trim()
        .split('\n').map(JSON.parse);
      const assessment = assessments.find((row) => row.payload.questionId === contract.recordId).payload;
      const report = fs.readFileSync(path.join(dir, 'report-model.jsonl'), 'utf8').trim()
        .split('\n').map(JSON.parse).find((row) => row.payload.origin === 'entry-scan').payload;
      return { assessment, report };
    };
    const liveArb = arbitrationOf(liveDir);
    assert.equal(liveArb.assessment.modelCallRef, review.callId);
    assert.equal(liveArb.assessment.basis, 'mixed');
    assert.ok(['conflict', 'insufficient'].includes(liveArb.assessment.decision));
    assert.ok(liveArb.report.missing.includes('prover-model-conflict') ||
      liveArb.report.missing.includes('static-contract-suspect'));
    // replay 逐字节复现同一仲裁消费（replay 侧重放调用使用新 callId，溯源经 sourceCallId）。
    const replay = await invoke(['run', ...common, '--mode=replay', '--max-tasks=1',
      `--replay-run=${live.runId}`]);
    runIds.push(replay.runId);
    const replayDir = path.resolve(AUTONOMY_ROOT, replay.runId.replace(':', '-'));
    const replayArb = arbitrationOf(replayDir);
    assert.ok(replayArb.assessment.modelCallRef);
    assert.equal(replayArb.assessment.decision, liveArb.assessment.decision);
    assert.equal(replayArb.assessment.basis, 'mixed');
    const replayCall = JSON.parse(fs.readFileSync(path.join(replayDir, 'model-calls',
      fs.readdirSync(path.join(replayDir, 'model-calls'))[0]), 'utf8'));
    assert.equal(replayCall.sourceCallId, review.callId);
    assert.equal(replayArb.assessment.modelCallRef, replayCall.callId);
    assert.equal(sends, 1);
    assert.equal(replay.executed.modelRequests, 0);
    assert.equal(replay.executed.modelCalls, 1);
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

test('1.0.19 multi-entry live responses replay and resume without transport', async () => {
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
      send: async ({ maxTokens }) => {
        assert.equal(maxTokens, 4096);
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
    const crashed = spawnSync(process.execPath,
      ['tools/fixtures/crash-after-vertical-task.js', '--static-suite', '--max-tasks=3', '--replay-run=' + live.runId],
      { cwd: path.join(__dirname, '..'), encoding: 'utf8' });
    assert.equal(crashed.status, 71, crashed.stderr);
    const crashedRun = JSON.parse(crashed.stdout).runId;
    runIds.push(crashedRun);
    const resumed = await invoke(['resume', '--run=' + crashedRun, '--mode=replay',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
      '--replay-run=' + live.runId]);
    assert.equal(resumed.semanticHash, live.semanticHash);
    assert.equal(resumed.executed.modelRequests, 0);
    assert.equal(sends, 3);
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
