'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { main } = require('../bin/autonomy');
const storeLib = require('../lib/autonomy/store');
const factsLib = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const vertical = require('../lib/autonomy/vertical');
const permissionArgument = require('../lib/autonomy/permission-argument');
const knowledgeLib = require('../lib/autonomy/knowledge');
const modelLib = require('../lib/autonomy/model');
const scope = require('../K/policies/autonomy-pilot-scope.json');

test('bounded evidence keeps exact delegation and name-only operation distinct', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  const entry = anchors.entries.find((e) => e.method === 'SetPolicyAsync');
  const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
  const out = vertical.selectEvidence(facts, binding.bound);
  assert.equal(out.status, 'observed');
  assert.equal(out.checkRefs.length, 1);
  assert.equal(out.operationCallsites.length, 1);
  assert.equal(out.operationCallsites[0].resolution, 'name-only');
  assert.equal(out.operationCandidates.length, 1);
  assert.equal(out.operationCandidates[0].status, 'suspect');
  assert.match(out.operationCandidates[0].targetRef, /^F:/);
  assert.equal(out.operationCandidates[0].source.line, 409);
  const stale = Object.create(facts);
  stale.verifyFile = () => ({ ok: false, reason: 'stale-input' });
  assert.equal(vertical.selectEvidence(stale, binding.bound).reason, 'stale-input');
});

test('source-qualified operation candidates remain suspect and reject ambiguity or stale targets', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  for (const [method, line] of [['SetPolicyAsync', 409], ['UnSetPolicyAsync', 435]]) {
    const entry = anchors.entries.find((e) => e.method === method);
    const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
    const delegate = method.replace('Async', '');
    const observed = vertical.selectEvidence(facts, binding.bound, delegate);
    assert.equal(observed.operationCandidates.length, 1);
    assert.equal(observed.operationCandidates[0].source.line, line);
    assert.equal(observed.operationCandidates[0].target.sha256.length, 64);
    assert.equal(observed.operationCallsites[0].resolution, 'name-only');
    const ambiguous = Object.create(facts);
    ambiguous.index = () => ({ ...facts.index(), functions: [
      ...facts.index().functions,
      facts.index().functions.find((fn) => fn.factId === observed.operationCandidates[0].targetRef)
    ] });
    assert.deepEqual(vertical.selectEvidence(ambiguous, binding.bound, delegate).operationCandidates, []);
    const stale = Object.create(facts);
    stale.verifyFile = (file) => file === observed.operationCandidates[0].target.file
      ? { ok: false, reason: 'stale-input' } : facts.verifyFile(file);
    assert.deepEqual(vertical.selectEvidence(stale, binding.bound, delegate).operationCandidates, []);
  }
});

test('direct IDL methods expose only source-qualified suspect operation candidates', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  const bound = (method) => {
    const entry = anchors.entries.find((e) => e.method === method);
    return discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors }).bound;
  };
  const persist = vertical.inspectOperationCandidates(facts, bound('PersistPolicy'));
  assert.equal(persist.status, 'observed');
  assert.equal(persist.candidates.length, 1);
  assert.equal(persist.candidates[0].status, 'suspect');
  assert.match(persist.candidates[0].targetRef, /^F:/);
  assert.deepEqual(vertical.inspectOperationCandidates(facts, bound('SetPolicyByBundleName')).candidates, []);
  const stale = Object.create(facts);
  stale.verifyFile = (file) => file === persist.candidates[0].target.file
    ? { ok: false, reason: 'stale-input' } : facts.verifyFile(file);
  assert.deepEqual(vertical.inspectOperationCandidates(stale, bound('PersistPolicy')).candidates, []);
  const ambiguous = Object.create(facts);
  ambiguous.index = () => ({ ...facts.index(), functions: [
    ...facts.index().functions,
    facts.index().functions.find((fn) => fn.factId === persist.candidates[0].targetRef)
  ] });
  assert.deepEqual(vertical.inspectOperationCandidates(ambiguous, bound('PersistPolicy')).candidates, []);
});

test('literal permission comparison has supported, refuted and insufficient outcomes', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  for (const [method, expected] of [['SetPolicyAsync', 'supported'], ['UnSetPolicyAsync', 'refuted']]) {
    const entry = anchors.entries.find((e) => e.method === method);
    const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
    const knowledge = method === 'SetPolicyAsync' ? knowledgeLib.loadAuthorization(facts) :
      knowledgeLib.loadPersistenceAuthorization(facts);
    const result = permissionArgument.compare(facts, entry, binding, knowledge);
    assert.equal(result.status, expected);
    assert.equal(result.expectedPermission, knowledge.norm.permission);
    assert.match(result.checkRef, /^F:/);
    const stale = Object.create(facts);
    stale.verifyFile = () => ({ ok: false, reason: 'stale-input' });
    assert.equal(permissionArgument.compare(stale, entry, binding, knowledge).status, 'insufficient');
    assert.equal(permissionArgument.compare(facts, { ...entry, method: 'Unknown' }, binding, knowledge).status, 'insufficient');
    const other = method === 'SetPolicyAsync' ? knowledgeLib.loadPersistenceAuthorization(facts) :
      knowledgeLib.loadAuthorization(facts);
    assert.equal(permissionArgument.compare(facts, entry, binding, other).status, 'insufficient');
  }
});

test('no operation callsite cannot count as a resolved operation target', async () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  const entry = anchors.entries.find((e) => e.method === 'UnSetPolicyAsync');
  const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
  const callee = facts.index().functions.find((fn) => fn.name === 'UnSetPolicy' &&
    fn.qualified?.includes('SandboxManagerService'));
  assert.ok(callee);
  const noOperation = Object.create(facts);
  noOperation.callsOf = (name, options) => facts.callsOf(name, options)
    .filter((call) => name !== callee.qualified || call.calleeName !== 'UnSetPolicy');
  const result = await vertical.analyze({ facts: noOperation, anchor: entry, binding,
    task: { taskId: 'TASK:ce534608cd00a85c' },
    store: { writeJson: () => {}, appendEvent: () => {} }, gateway: { mode: 'off' },
    knowledge: require('../lib/autonomy/knowledge').loadPersistenceAuthorization(facts),
    pushResult: async () => ({ recordId: 'EVID:aaaaaaaaaaaaaaaa',
      payload: { status: 'ok', completeness: { enumeration: 'complete' } } }) });
  assert.equal(result.status, 'observation');
  assert.deepEqual(result.operationCallsites, []);
  assert.equal(result.completeness.operationTargetResolved, false);
});

test('vertical-v2 has a distinct sourced UnSetPolicyAsync question without upgrading the verdict', () => {
  const root = path.join(__dirname, '..');
  const wrongKnowledge = spawnSync(process.execPath, ['bin/autonomy.js', 'run',
    '--experiment=vertical-v2', '--mode=off',
    '--scope=K/policies/autonomy-pilot-scope.json',
    '--budget=K/policies/autonomy-pilot-budget.json',
    '--task=TASK:ce534608cd00a85c', '--knowledge=K/norms/setpolicy/knowledge.json'],
  { cwd: root, encoding: 'utf8' });
  assert.equal(wrongKnowledge.status, 2);
  assert.match(wrongKnowledge.stderr, /knowledge-version-path-invalid/);
  const run = spawnSync(process.execPath, ['bin/autonomy.js', 'run', '--experiment=vertical-v2',
    '--mode=off', '--scope=K/policies/autonomy-pilot-scope.json',
    '--budget=K/policies/autonomy-pilot-budget.json', '--task=TASK:ce534608cd00a85c'],
  { cwd: root, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const { runId, runDir } = JSON.parse(run.stdout);
  const dir = path.resolve(root, runDir);
  try {
    const checked = spawnSync(process.execPath, ['bin/autonomy.js', 'check', `--run=${runId}`],
      { cwd: root, encoding: 'utf8' });
    assert.equal(checked.status, 0, checked.stdout);
    const read = (name) => JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
    const knowledge = read('vertical-knowledge.json');
    assert.equal(read('run.json').payload.architectureVersion, '1.0.13-vertical-experiment');
    const analysis = read('vertical-analysis.json');
    const questions = fs.readFileSync(path.join(dir, 'questions.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(knowledge.norm.permission, 'ohos.permission.FILE_ACCESS_PERSIST');
    assert.equal(knowledge.norm.state, 'proposed');
    assert.equal(analysis.applicability.status, 'unknown');
    assert.equal(analysis.checkRefs.length, 1);
    assert.equal(analysis.operationCallsites[0].resolution, 'name-only');
    assert.equal(analysis.operationCandidates[0].status, 'suspect');
    assert.equal(analysis.completeness.operationTargetResolved, false);
    assert.deepEqual(analysis.followups.map((item) => item.action.tool),
      ['inspectPermissionArgument', 'getEvidence']);
    assert.equal(analysis.followups[1].taskRevision, 1);
    assert.deepEqual(analysis.followups[1].missing, ['operation-target-unproven']);
    assert.equal(analysis.permissionArgument.status, 'refuted');
    assert.equal(questions.find((q) => q.payload.kind === 'authorization-effect').recordId,
      'Q:b1753db52e17ebc1');
    const permissionQ = questions.find((q) => q.payload.kind === 'permission-argument-match');
    const assessments = fs.readFileSync(path.join(dir, 'assessments.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const localAssessment = assessments.find((a) => a.payload.questionId === permissionQ.recordId);
    assert.equal(localAssessment.payload.decision, 'refuted');
    assert.deepEqual(localAssessment.payload.counterEvidenceRefs, localAssessment.payload.evidenceRefs);
    const reportRows = fs.readFileSync(path.join(dir, 'report-model.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const localReport = reportRows.find((row) => row.payload.permissionArgument);
    assert.equal(localReport.payload.permissionArgument.decision, 'refuted');
    assert.equal(localReport.payload.decision, 'insufficient');
    assert.match(fs.readFileSync(path.join(dir, 'report.md'), 'utf8'), /权限参数局部比较：refuted/);
    assert.match(fs.readFileSync(path.join(dir, 'report.md'), 'utf8'), /源码限定操作候选/);
    assert.equal(read('report-model.json').counts.finding, 0);
    const sidecar = path.join(dir, 'vertical-analysis.json');
    const original = fs.readFileSync(sidecar, 'utf8');
    analysis.followups[0].action.tool = 'getEvidence';
    fs.writeFileSync(sidecar, JSON.stringify(analysis), 'utf8');
    const badAction = spawnSync(process.execPath, ['bin/autonomy.js', 'check', '--run=' + runId],
      { cwd: root, encoding: 'utf8' });
    assert.equal(badAction.status, 3);
    assert.ok(JSON.parse(badAction.stdout).errors.some((e) => e.code === 'vertical-replan-mismatch'));
    fs.writeFileSync(sidecar, original, 'utf8');
    analysis.followups[0].action.tool = 'inspectPermissionArgument';
    analysis.operationCandidates[0].targetRef = 'F:forged';
    fs.writeFileSync(sidecar, JSON.stringify(analysis), 'utf8');
    const badCandidate = spawnSync(process.execPath, ['bin/autonomy.js', 'check', '--run=' + runId],
      { cwd: root, encoding: 'utf8' });
    assert.equal(badCandidate.status, 3);
    assert.ok(JSON.parse(badCandidate.stdout).errors.some((e) => e.code === 'operation-candidate-mismatch'));
    fs.writeFileSync(sidecar, original, 'utf8');
    analysis.operationCandidates[0].targetRef = read('vertical-analysis.json').operationCandidates[0].targetRef;
    analysis.permissionArgument.observedPermission = 'ohos.permission.FILE_ACCESS_PERSIST';
    fs.writeFileSync(sidecar, JSON.stringify(analysis), 'utf8');
    const tampered = spawnSync(process.execPath, ['bin/autonomy.js', 'check', '--run=' + runId],
      { cwd: root, encoding: 'utf8' });
    assert.equal(tampered.status, 3);
    assert.ok(JSON.parse(tampered.stdout).errors.some((e) => e.code === 'permission-argument-mismatch'));
  } finally {
    if (dir.startsWith(path.resolve(storeLib.AUTONOMY_ROOT) + path.sep) &&
        /^RUN-[0-9a-f]{16}$/.test(path.basename(dir))) fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('model action rejects wrong task, stale context and unregistered tool', () => {
  const task = { taskId: 'TASK:aaaaaaaaaaaaaaaa' };
  const good = { taskId: task.taskId, contextId: 'CTX:aaaaaaaaaaaaaaaa',
    action: { type: 'callTool', tool: 'inspectDelegation', arguments: { entryRef: 'ENT:aaaaaaaaaaaaaaaa' } } };
  assert.equal(vertical.validatePlan(good, task, good.contextId, good.action.arguments.entryRef).ok, true);
  assert.equal(vertical.validatePlan({ ...good, contextId: 'CTX:bbbbbbbbbbbbbbbb' },
    task, good.contextId, good.action.arguments.entryRef).ok, false);
  assert.equal(vertical.validatePlan({ ...good, action: { ...good.action, tool: 'executeShell' } },
    task, good.contextId, good.action.arguments.entryRef).ok, false);
});

test('followup chooses one bounded action and rejects stale or invented actions', async () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  const entry = anchors.entries.find((e) => e.method === 'UnSetPolicyAsync');
  const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
  const task = { taskId: 'TASK:ce534608cd00a85c', revision: 1 };
  const calls = [];
  const tools = [];
  const gateway = { mode: 'live', async invoke(req) {
    calls.push(req.purpose);
    const data = JSON.parse(req.messages[1].content);
    if (req.purpose === 'vertical-plan') return { status: 'ok', callId: 'CALL:aaaaaaaaaaaaaaaa',
      parsed: { taskId: task.taskId, contextId: req.contextId,
        action: { type: 'callTool', tool: 'inspectDelegation', arguments: { entryRef: entry.entityId } } } };
    if (req.purpose === 'vertical-followup-plan') return { status: 'ok', callId: 'CALL:bbbbbbbbbbbbbbbb',
      parsed: { taskId: task.taskId, taskRevision: task.revision, contextId: req.contextId,
        action: data.allowedActions.find((item) => item.tool === 'getEvidence') } };
    return { status: 'ok', callId: 'CALL:cccccccccccccccc',
      parsed: { decision: 'insufficient', evidenceRefs: [], rationale: 'path unresolved' } };
  } };
  const result = await vertical.analyze({ facts, anchor: entry, binding, task, gateway,
    knowledge: knowledgeLib.loadPersistenceAuthorization(facts), enableFollowup: true,
    followupQuestionId: 'Q:aaaaaaaaaaaaaaaa',
    store: { writeJson: () => {}, appendEvent: () => {} },
    pushResult: async (name, args, questionId) => {
      tools.push({ name, args, questionId });
      return { recordId: 'EVID:' + String(tools.length).padStart(16, '0'),
        payload: { status: 'ok', completeness: { enumeration: 'complete' } } };
    } });
  assert.deepEqual(calls, ['vertical-plan', 'vertical-followup-plan', 'vertical-interpret']);
  assert.equal(tools.filter((item) => item.name === 'inspectPermissionArgument').length, 0);
  assert.equal(tools.filter((item) => item.name === 'getEvidence').length, 2);
  assert.equal(result.followup.action.tool, 'getEvidence');
  assert.equal(result.permissionArgument, undefined);
  assert.equal(result.completeness.operationTargetResolved, false);
  const options = [{ type: 'callTool', tool: 'getEvidence', arguments: { file: 'target.cpp', line: 1, count: 12 } }];
  const action = { taskId: task.taskId, taskRevision: 1, contextId: 'CTX:aaaaaaaaaaaaaaaa', action: options[0] };
  assert.equal(vertical.validateFollowup(action, task, action.contextId, options).ok, true);
  assert.equal(vertical.validateFollowup({ ...action, taskRevision: 2 }, task, action.contextId, options).ok, false);
  assert.equal(vertical.validateFollowup({ ...action, action: { ...options[0],
    arguments: { file: 'other.cpp', line: 1, count: 12 } } }, task, action.contextId, options).ok, false);
});

test('replanning uses the committed first result and removes its resolved gap', async () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  const entry = anchors.entries.find((e) => e.method === 'SetPolicyAsync');
  const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
  const task = { taskId: 'TASK:108bcc806d3fc6f0', revision: 1 };
  const tools = [];
  const replans = [];
  const gateway = { mode: 'live', async invoke(req) {
    if (req.purpose === 'vertical-plan') return { status: 'ok', callId: 'CALL:aaaaaaaaaaaaaaaa',
      parsed: { taskId: task.taskId, contextId: req.contextId,
        action: { type: 'callTool', tool: 'inspectDelegation', arguments: { entryRef: entry.entityId } } } };
    if (req.purpose === 'vertical-followup-replan') {
      const data = JSON.parse(req.messages[1].content);
      replans.push(data);
      return { status: 'ok', callId: `CALL:${String(replans.length).repeat(16)}`,
        parsed: { taskId: task.taskId, taskRevision: task.revision, contextId: req.contextId,
          action: data.allowedActions[0] } };
    }
    return { status: 'ok', callId: 'CALL:cccccccccccccccc',
      parsed: { decision: 'insufficient', evidenceRefs: [], rationale: 'path unresolved' } };
  } };
  const result = await vertical.analyze({ facts, anchor: entry, binding, task, gateway,
    knowledge: knowledgeLib.loadAuthorization(facts), enableFollowup: true, twoRoundFollowup: true,
    followupQuestionId: 'Q:aaaaaaaaaaaaaaaa',
    store: { writeJson: () => {}, appendEvent: () => {} },
    pushResult: async (name, args) => {
      tools.push({ name, args });
      return { recordId: 'EVID:' + String(tools.length).padStart(16, '0'), payload: {
        status: 'ok', tool: name, completeness: { enumeration: 'complete' },
        ...(name === 'inspectPermissionArgument' ? { observations: { status: 'refuted' } } : {})
      } };
    } });
  assert.equal(replans.length, 2);
  assert.deepEqual(replans[0].missing, ['permission-argument-unresolved', 'operation-target-unproven']);
  assert.deepEqual(replans[1].missing, ['operation-target-unproven']);
  assert.equal(replans[1].previous.toolResultId, result.followups[0].toolResultId);
  assert.deepEqual(result.followups.map((f) => f.action.tool), ['inspectPermissionArgument', 'getEvidence']);
  assert.equal(result.followupStopReason, 'round-limit');
  assert.equal(tools.filter((row) => row.name === 'inspectPermissionArgument').length, 1);
  assert.equal(result.completeness.operationTargetResolved, false);
});

test('stale second response stops without executing its proposed tool', async () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(facts, scope);
  const entry = anchors.entries.find((e) => e.method === 'SetPolicyAsync');
  const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
  const task = { taskId: 'TASK:108bcc806d3fc6f0', revision: 1 };
  const tools = [];
  const result = await vertical.analyze({ facts, anchor: entry, binding, task,
    knowledge: knowledgeLib.loadAuthorization(facts), enableFollowup: true, twoRoundFollowup: true,
    followupQuestionId: 'Q:aaaaaaaaaaaaaaaa',
    store: { writeJson: () => {}, appendEvent: () => {} },
    gateway: { mode: 'live', async invoke(req) {
      if (req.purpose === 'vertical-plan') return { status: 'ok', callId: 'CALL:aaaaaaaaaaaaaaaa',
        parsed: { taskId: task.taskId, contextId: req.contextId,
          action: { type: 'callTool', tool: 'inspectDelegation', arguments: { entryRef: entry.entityId } } } };
      if (req.purpose === 'vertical-followup-replan') {
        const data = JSON.parse(req.messages[1].content);
        return { status: 'ok', callId: 'CALL:bbbbbbbbbbbbbbbb',
          parsed: { taskId: task.taskId, taskRevision: task.revision,
            contextId: data.round === 2 ? 'CTX:aaaaaaaaaaaaaaaa' : req.contextId,
            action: data.allowedActions[0] } };
      }
      return { status: 'ok', callId: 'CALL:cccccccccccccccc',
        parsed: { decision: 'insufficient', evidenceRefs: [], rationale: 'unknown' } };
    } },
    pushResult: async (name) => {
      tools.push(name);
      return { recordId: 'EVID:' + String(tools.length).padStart(16, '0'), payload: {
        status: 'ok', tool: name, completeness: { enumeration: 'complete' },
        ...(name === 'inspectPermissionArgument' ? { observations: { status: 'supported' } } : {})
      } };
    } });
  assert.equal(result.followups[1].ok, false);
  assert.equal(result.followupStopReason, 'invalid-or-stale-followup');
  assert.equal(tools.filter((name) => name === 'getEvidence').length, 1);
});

test('injected transport completes two-round live ledger and zero-request replay', async () => {
  const oldTransport = Object.getOwnPropertyDescriptor(modelLib.ModelGateway.prototype, 'transport');
  const oldWrite = process.stdout.write;
  const output = [];
  const dirs = [];
  Object.defineProperty(modelLib.ModelGateway.prototype, 'transport', { configurable: true,
    get() { return { keyPresent: () => true, send: async (request) => {
      const user = JSON.parse(request.messages[1].content);
      let parsed;
      if (user.directCall) parsed = { taskId: user.taskId, contextId: user.contextId,
        action: { type: 'callTool', tool: 'inspectDelegation', arguments: { entryRef: user.entryRef } } };
      else if (user.allowedActions) parsed = { taskId: user.taskId,
        taskRevision: user.taskRevision, contextId: user.contextId,
        action: user.allowedActions.find((item) =>
          item.tool === (user.round === 1 ? 'getEvidence' : 'inspectPermissionArgument')) };
      else parsed = { decision: 'insufficient', evidenceRefs: [], rationale: 'unknown path' };
      return { kind: 'ok', content: JSON.stringify(parsed), model: 'injected-test',
        usage: { promptTokens: 100, completionTokens: 30 }, usageKnown: true,
        finishReason: 'stop', wallMs: 1 };
    } }; } });
  process.stdout.write = (chunk) => { output.push(String(chunk)); return true; };
  try {
    const common = ['--experiment=vertical-v2',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
      '--task=TASK:108bcc806d3fc6f0'];
    assert.equal(await main(['run', '--mode=live', ...common]), 0);
    const live = JSON.parse(output.join(''));
    dirs.push(path.join(__dirname, '..', live.runDir));
    assert.equal(live.executed.modelRequests, 4);
    const analysis = JSON.parse(fs.readFileSync(path.join(dirs[0], 'vertical-analysis.json'), 'utf8'));
    assert.deepEqual(analysis.followups.map((item) => item.action.tool),
      ['getEvidence', 'inspectPermissionArgument']);
    assert.equal(analysis.permissionArgument.status, 'supported');
    output.length = 0;
    assert.equal(await main(['check', `--run=${live.runId}`]), 0);
    assert.deepEqual(JSON.parse(output.join('')).errors, []);
    output.length = 0;
    assert.equal(await main(['run', '--mode=replay', `--replay-run=${live.runId}`, ...common]), 0);
    const replay = JSON.parse(output.join(''));
    dirs.push(path.join(__dirname, '..', replay.runDir));
    assert.equal(replay.executed.modelRequests, 0);
    assert.equal(replay.executed.modelCalls, 4);
    assert.equal(replay.semanticHash, live.semanticHash);
    output.length = 0;
    assert.equal(await main(['check', `--run=${replay.runId}`]), 0);
    assert.deepEqual(JSON.parse(output.join('')).errors, []);
  } finally {
    Object.defineProperty(modelLib.ModelGateway.prototype, 'transport', oldTransport);
    process.stdout.write = oldWrite;
    for (const dir of dirs) {
      if (path.resolve(dir).startsWith(path.resolve(storeLib.AUTONOMY_ROOT) + path.sep) &&
          /^RUN-[0-9a-f]{16}$/.test(path.basename(dir))) fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

test('failed live plan stops before unselected tools and remains checkable', async () => {
  const oldTransport = Object.getOwnPropertyDescriptor(modelLib.ModelGateway.prototype, 'transport');
  const oldWrite = process.stdout.write;
  const output = [];
  let dir;
  Object.defineProperty(modelLib.ModelGateway.prototype, 'transport', { configurable: true,
    get() { return { keyPresent: () => true,
      send: async () => ({ kind: 'transport-error', reason: 'injected', wallMs: 1 }) }; } });
  process.stdout.write = (chunk) => { output.push(String(chunk)); return true; };
  try {
    assert.equal(await main(['run', '--experiment=vertical-v2', '--mode=live',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
      '--task=TASK:ce534608cd00a85c', '--max-model-requests=1']), 0);
    const run = JSON.parse(output.join(''));
    dir = path.join(__dirname, '..', run.runDir);
    const analysis = JSON.parse(fs.readFileSync(path.join(dir, 'vertical-analysis.json'), 'utf8'));
    assert.equal(analysis.plan.ok, false);
    assert.equal(analysis.reason, 'transport-error');
    assert.equal(analysis.followup, undefined);
    const tools = fs.readFileSync(path.join(dir, 'tool-results.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(tools.some((item) => item.payload.tool === 'inspectPermissionArgument'), false);
    output.length = 0;
    assert.equal(await main(['check', '--run=' + run.runId]), 0);
    assert.deepEqual(JSON.parse(output.join('')).errors, []);
  } finally {
    Object.defineProperty(modelLib.ModelGateway.prototype, 'transport', oldTransport);
    process.stdout.write = oldWrite;
    if (dir && path.resolve(dir).startsWith(path.resolve(storeLib.AUTONOMY_ROOT) + path.sep) &&
        /RUN-[0-9a-f]{16}$/.test(dir)) fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('model opinion cannot publish an unapproved norm or upgrade name-only operation', () => {
  const allowed = new Set(['F:check']);
  const evidence = { checkRefs: ['F:check'] };
  const applicability = { status: 'unknown' };
  assert.equal(vertical.gateInterpretation({ status: 'ok', parsed: {
    decision: 'supported', evidenceRefs: ['F:check'], rationale: 'local check'
  } }, allowed, evidence, applicability).status, 'insufficient');
  assert.equal(vertical.gateInterpretation({ status: 'ok', parsed: {
    decision: 'supported', evidenceRefs: ['F:forged']
  } }, allowed, evidence, applicability).reason, 'invalid-model-evidence');
});

test('model gateway archives a response hash but not raw reasoning text', async () => {
  const gateway = new modelLib.ModelGateway({ mode: 'mock', fixturesDir: path.join(__dirname, 'fixtures/autonomy/model') });
  const result = await gateway.invoke({ purpose: 'check-presence', taskId: 'TASK:aaaaaaaaaaaaaaaa', contextId: 'CTX:aaaaaaaaaaaaaaaa' });
  assert.equal(result.status, 'ok');
  assert.equal(result.content, null);
  assert.match(result.contentSha256, /^[0-9a-f]{64}$/);
});

test('vertical off run archives knowledge/action/context and check can rebuild', async () => {
  const output = [];
  const original = process.stdout.write;
  let dir;
  process.stdout.write = (chunk) => { output.push(String(chunk)); return true; };
  try {
    const args = ['run', '--experiment=vertical-v1', '--mode=off',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
      '--task=TASK:108bcc806d3fc6f0'];
    assert.equal(await main(args), 0);
    const run = JSON.parse(output.join(''));
    dir = path.join(__dirname, '..', run.runDir);
    const v = JSON.parse(fs.readFileSync(path.join(dir, 'vertical-analysis.json'), 'utf8'));
    assert.equal(v.status, 'observation');
    assert.equal(v.completeness.operationTargetResolved, false);
    assert.equal(v.verification.status, 'blocked');
    const questions = fs.readFileSync(path.join(dir, 'questions.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const assessments = fs.readFileSync(path.join(dir, 'assessments.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const effect = questions.find((q) => q.payload.kind === 'authorization-effect');
    assert.equal(questions.length, 5);
    assert.equal(assessments.length, 5);
    const branch = JSON.parse(fs.readFileSync(path.join(dir, 'vertical-branch.json'), 'utf8'));
    assert.equal(branch.view, 'input-boundary');
    assert.equal(branch.candidate.binding, 'type-hint-only');
    assert.equal(questions.find((q) => q.payload.kind === 'input-boundary-local').payload.status, 'insufficient');
    assert.equal(effect.payload.status, 'insufficient');
    assert.ok(assessments.find((a) => a.payload.questionId === effect.recordId).payload.evidenceRefs.length >= 3);
    const report = JSON.parse(fs.readFileSync(path.join(dir, 'report-model.json'), 'utf8'));
    assert.equal(report.missingByReason['norm-applicability-unapproved'], 1);
    assert.equal(report.missingByReason['operation-target-unproven'], 1);
    assert.equal(report.missingByReason['input-parser-unproven'], 1);
    assert.equal(report.counts.excluded, 1);
    assert.equal(report.counts.finding, 0);
    output.length = 0;
    assert.equal(await main(['check', `--run=${run.runId}`]), 0);
    assert.deepEqual(JSON.parse(output.join('')).errors, []);
  } finally {
    process.stdout.write = original;
    if (dir && path.resolve(dir).startsWith(path.resolve(storeLib.AUTONOMY_ROOT) + path.sep) &&
        /RUN-[0-9a-f]{16}$/.test(dir)) fs.rmSync(dir, { recursive: true, force: true });
  }
});
