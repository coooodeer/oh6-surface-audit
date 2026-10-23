'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const delegation = require('../lib/autonomy/delegation');
const factsLib = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const tools = require('../lib/autonomy/tools');
const report = require('../lib/autonomy/report');
const storeLib = require('../lib/autonomy/store');
const { main } = require('../bin/autonomy');

const scope = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'K/policies/autonomy-pilot-scope.json'), 'utf8'));

function fakeFacts({ exact = true, stale = false, check = true } = {}) {
  const entry = { name: 'Async', qualified: 'Service::Async', factId: 'F:entry' };
  const callee = { name: 'Apply', qualified: 'Service::Apply', factId: 'F:apply', sourceRange: { file: 'apply.cpp' } };
  const edge = { factId: 'F:edge', calleeName: 'Apply', callee: exact ? 'F:apply' : null,
    quality: { resolution: exact ? 'exact' : 'name-only' } };
  return {
    entry,
    facts: {
      index: () => ({ functions: [entry, callee], truncated: { calls: false } }),
      callsOf: (name) => name === 'Service::Async' ? [edge]
        : (check ? [{ factId: 'F:check', calleeName: 'CheckPermission' }] : []),
      verifyFile: () => ({ ok: !stale })
    }
  };
}

test('one-hop: exact check is counterevidence, not an authorization verdict', () => {
  const { entry, facts } = fakeFacts();
  const out = delegation.inspect(facts, entry, { strong: ['CheckPermission'] });
  assert.equal(out.partial, false);
  assert.equal(out.delegates[0].status, 'check-observed');
  assert.deepEqual(out.delegates[0].checkRefs, ['F:check']);
  assert.deepEqual(out.evidenceRefs, ['F:apply', 'F:check', 'F:edge']);
});

test('one-hop: unresolved edge, stale input and absent check never become proof of absence', () => {
  const unknown = fakeFacts({ exact: false });
  assert.equal(delegation.inspect(unknown.facts, unknown.entry, { strong: ['CheckPermission'] }).partial, true);
  const stale = fakeFacts({ stale: true });
  assert.equal(delegation.inspect(stale.facts, stale.entry, { strong: ['CheckPermission'] }).delegates[0].status, 'stale-or-unresolved');
  const absent = fakeFacts({ check: false });
  assert.equal(delegation.inspect(absent.facts, absent.entry, { strong: ['CheckPermission'] }).delegates[0].status, 'no-direct-check');
});

test('real sandbox_manager: both async entry bodies delegate to checked callees', async () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  for (const method of ['SetPolicyAsync', 'UnSetPolicyAsync']) {
    const entry = anchors.entries.find((e) => e.kind === 'idl' && e.method === method);
    assert.ok(entry);
    const out = await tools.run('inspectDelegation', { entryRef: entry.entityId }, { facts, scope });
    assert.equal(out.payload.status, 'ok');
    assert.equal(out.payload.answer.status, 'unknown');
    assert.ok(out.payload.observations.delegates.some((d) => d.status === 'check-observed'));
    assert.ok(out.payload.evidenceRefs.length >= 3);
  }
});

function reportRow(origin, operationRef, missingReason) {
  const taskId = 'TASK:aaaaaaaaaaaaaaaa';
  const kinds = ['binding', 'check-presence', 'dominance'];
  const questions = kinds.map((kind, i) => ({ payload: {
    taskId, kind, questionId: `Q:${String(i + 1).padStart(16, '0')}`, missingRefs: []
  } }));
  const assessments = questions.map((q, i) => ({ payload: {
    questionId: q.payload.questionId,
    decision: i === 0 ? 'supported' : (i === 1 ? 'refuted' : 'insufficient'),
    evidenceRefs: [], missingRefs: i === 1 && missingReason ? ['MISS:aaaaaaaaaaaaaaaa'] : []
  } }));
  const task = { payload: { taskId, origin, operationRef, anchorRefs: ['ENT:aaaaaaaaaaaaaaaa'] } };
  const missing = missingReason ? [{ payload: { missingId: 'MISS:aaaaaaaaaaaaaaaa', reasonCode: missingReason } }] : [];
  return report.buildReportModel({
    tasks: [task], questions, assessments, missing,
    manifestId: 'AM-aaaaaaaaaaaaaaaa', snapshotId: `sha256:${'a'.repeat(64)}`,
    architectureVersion: '1.0.1-auth-experiment'
  }).rows[0];
}

test('experimental report needs a real entry and operation; delegation stays conditional', () => {
  assert.equal(reportRow('coverage-sample', 'F:operation').reportability, 'observation');
  assert.equal(reportRow('entry-scan', null).reportability, 'observation');
  assert.equal(reportRow('entry-scan', 'F:operation').reportability, 'candidate');
  assert.equal(reportRow('entry-scan', 'F:operation', 'delegated-check-unproven').reportability, 'observation');
  assert.equal(reportRow('entry-scan', null).origin, 'entry-scan');
});

test('experimental run report can be rebuilt by check', async () => {
  let runDir;
  const oldWrite = process.stdout.write;
  const output = [];
  process.stdout.write = (chunk) => { output.push(String(chunk)); return true; };
  try {
    assert.equal(await main(['run', '--scope=K/policies/autonomy-pilot-scope.json',
      '--budget=K/policies/autonomy-pilot-budget.json', '--mode=off',
      '--experiment=authorization-v1', '--max-tasks=1']), 0);
    const run = JSON.parse(output.join(''));
    runDir = path.join(__dirname, '..', run.runDir);
    assert.equal(run.missingByReason['operation-unbound'], 1);
    assert.equal(JSON.parse(fs.readFileSync(path.join(runDir, 'run.json'), 'utf8')).payload.architectureVersion,
      '1.0.2-auth-experiment');
    output.length = 0;
    assert.equal(await main(['check', `--run=${run.runId}`]), 0);
    assert.deepEqual(JSON.parse(output.join('')).errors, []);
  } finally {
    process.stdout.write = oldWrite;
    if (runDir && path.resolve(runDir).startsWith(path.resolve(storeLib.AUTONOMY_ROOT) + path.sep) &&
        /RUN-[0-9a-f]{16}$/.test(runDir)) fs.rmSync(runDir, { recursive: true, force: true });
  }
});

test('new scope scan records suspect operation targets without upgrading candidates', async () => {
  let runDir;
  const oldWrite = process.stdout.write;
  const output = [];
  process.stdout.write = (chunk) => { output.push(String(chunk)); return true; };
  try {
    assert.equal(await main(['run', '--scope=K/policies/autonomy-pilot-scope.json',
      '--budget=K/policies/autonomy-pilot-budget.json', '--mode=off']), 0);
    const run = JSON.parse(output.join(''));
    runDir = path.join(__dirname, '..', run.runDir);
    assert.equal(run.planned.tasks, 24);
    assert.equal(run.counts.candidate, 0);
    assert.equal(run.counts.observation, 24);
    assert.equal(run.missingByReason['delegated-check-unproven'], 2);
    assert.equal(run.missingByReason['operation-target-unproven'], 16);
    assert.equal(run.missingByReason['operation-unbound'], 3);
    assert.equal(run.executed.toolCalls, 111);
    assert.equal(JSON.parse(fs.readFileSync(path.join(runDir, 'run.json'), 'utf8')).payload.architectureVersion,
      '1.0.16-static-scan');
    assert.equal(JSON.parse(fs.readFileSync(path.join(runDir, 'report-model.json'), 'utf8')).reportVersion, '4');
    assert.doesNotMatch(fs.readFileSync(path.join(runDir, 'FINDINGS.md'), 'utf8'), /runtime witness/);
    output.length = 0;
    assert.equal(await main(['check', `--run=${run.runId}`]), 0);
    assert.deepEqual(JSON.parse(output.join('')).errors, []);
  } finally {
    process.stdout.write = oldWrite;
    if (runDir && path.resolve(runDir).startsWith(path.resolve(storeLib.AUTONOMY_ROOT) + path.sep) &&
        /RUN-[0-9a-f]{16}$/.test(runDir)) fs.rmSync(runDir, { recursive: true, force: true });
  }
});
