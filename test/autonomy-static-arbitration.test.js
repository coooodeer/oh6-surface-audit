'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const assessment = require('../lib/autonomy/assessment');
const { main } = require('../bin/autonomy');
const { ModelGateway } = require('../lib/autonomy/model');
const { AUTONOMY_ROOT } = require('../lib/autonomy/store');

const knowledge = [
  'K/norms/050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c/knowledge.json',
  'K/norms/7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f/knowledge.json'
].join(',');
const common = ['--scope=K/policies/autonomy-pilot-scope.json',
  '--budget=K/policies/autonomy-pilot-budget.json', '--legacy-contract', `--knowledge=${knowledge}`];

test('arbitration requires an accepted model decision and a scoped operation', () => {
  const excluded = { status: 'excluded', operationRef: 'F:target' };
  const insufficient = { status: 'insufficient', operationRef: 'F:target', reason: 'guard-shape-unsupported' };
  const model = { gate: 'accepted', decision: 'refuted', rationale: 'guard bypass', modelCallRef: 'CALL:test' };
  assert.equal(assessment.arbitrateStaticContract(excluded, model).decision, 'conflict');
  assert.equal(assessment.arbitrateStaticContract(insufficient, model).reasonCode, 'static-contract-suspect');
  assert.equal(assessment.arbitrateStaticContract(insufficient, { ...model, gate: 'rejected:invalid-ref' }).reasonCode, null);
  assert.equal(assessment.arbitrateStaticContract({ status: 'insufficient' }, model).reasonCode, null);
  assert.equal(assessment.arbitrateStaticContract({ ...insufficient, candidateSignal: 'no-resolved-check' }, null).reasonCode,
    'static-contract-suspect');
});

test('accepted Runtime-LLM counterexample downgrades excluded and promotes scoped insufficient, with replay and check', async () => {
  const originalCreate = ModelGateway.create;
  const originalWrite = process.stdout.write;
  const output = [];
  const runs = [];
  let sends = 0;
  process.stdout.write = (chunk) => { output.push(String(chunk)); return true; };
  ModelGateway.create = (options) => {
    const gateway = originalCreate(options);
    if (options.mode === 'live') gateway._transport = {
      keyPresent: () => true,
      send: async (request) => {
        sends++;
        const line = /允许引用的证据 ID：(.+)/.exec(request.messages.map((m) => m.content).join('\n'));
        const ref = line ? (line[1].split(',').map((s) => s.trim())
          .find((item) => item.startsWith('EVID:')) || 'EVID:none') : 'EVID:none';
        return { kind: 'ok', content: JSON.stringify({ decision: 'refuted', evidenceRefs: [ref],
          rationale: 'Check may not protect the operation.' }),
        usage: { promptTokens: 10, completionTokens: 10 }, usageKnown: true,
        finishReason: 'stop', model: 'test-transport', wallMs: 1 };
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
  const records = (runId, file) => fs.readFileSync(path.join(AUTONOMY_ROOT,
    runId.replace(':', '-'), file), 'utf8').trim().split('\n').map(JSON.parse);
  try {
    for (const [taskId, expected] of [
      ['TASK:9a646d4ee41c30a7', { decision: 'conflict', reason: 'prover-model-conflict' }],
      ['TASK:c3a12af04f6d34a4', { decision: 'insufficient', reason: 'static-contract-suspect' }]
    ]) {
      const live = await invoke(['run', ...common, '--mode=live', `--task=${taskId}`, '--max-model-requests=1']);
      runs.push(live.runId);
      const report = records(live.runId, 'report-model.jsonl')[0].payload;
      const contract = records(live.runId, 'questions.jsonl').find((q) => q.payload.kind === 'static-contract');
      const verdict = records(live.runId, 'assessments.jsonl').find((a) => a.payload.questionId === contract.recordId);
      assert.equal(report.reportability, 'candidate');
      assert.equal(report.decision, expected.decision);
      assert.equal(contract.payload.status, expected.decision);
      assert.equal(verdict.payload.decision, expected.decision);
      assert.match(verdict.payload.rationale, /Check may not protect the operation/);
      assert.ok(report.missing.includes(expected.reason));
      assert.match(report.operationRef, /^F:/);
      assert.equal(report.operationRef, records(live.runId, 'tasks.jsonl')[0].payload.operationRef);
      assert.equal((await invoke(['check', `--run=${live.runId}`])).errors.length, 0);
      const replay = await invoke(['run', ...common, '--mode=replay', `--task=${taskId}`,
        `--replay-run=${live.runId}`]);
      runs.push(replay.runId);
      assert.equal(replay.semanticHash, live.semanticHash);
      assert.equal((await invoke(['check', `--run=${replay.runId}`])).errors.length, 0);
    }
    assert.equal(sends, 2);
  } finally {
    ModelGateway.create = originalCreate;
    process.stdout.write = originalWrite;
    for (const runId of runs) {
      const dir = path.resolve(AUTONOMY_ROOT, runId.replace(':', '-'));
      if (dir.startsWith(path.resolve(AUTONOMY_ROOT) + path.sep) &&
          /^RUN-[0-9a-f]{16}$/.test(path.basename(dir))) fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});
