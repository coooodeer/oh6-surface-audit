'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const { AutonomyFacts } = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const { sourceProof, analyze } = require('../lib/autonomy/ipc-verdict');

const scope = require('../K/policies/autonomy-r3-tokensync-verdict-scope.json');
const facts = AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
const idx = facts.index();
const cfg = scope.ipcCodeVerdict;
const anchors = discovery.buildAnchors(facts, scope);
const entry = anchors.entries[0];
const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
const read = (rel) => fs.readFileSync(path.join(facts.sourceRoot, ...rel.split('/')), 'utf8');
const texts = Object.fromEntries(Object.entries({ stub: cfg.stubFile, stubHeader: cfg.stubHeader,
  service: cfg.serviceFile, serviceHeader: cfg.serviceHeader, interfaceHeader: cfg.interfaceHeader,
  tokenHeader: cfg.tokenHeader, codeHeader: scope.ipcDispatch.codeHeader,
  profile: cfg.profileFile, ...cfg.pinned }).map(([key, rel]) => [key, read(rel.file || rel)]));
const proof = (changes = {}, changedEntry = entry, changedBinding = binding) =>
  sourceProof(changedEntry, changedBinding, cfg, idx, { ...texts, ...changes });

test('real local HAP caller is excluded from the scoped Delete call', () => {
  const result = analyze(facts, entry, binding, cfg);
  assert.equal(result.status, 'excluded');
  assert.deepEqual(result, proof());
  assert.equal(result.contract.status, 'not-applicable');
  assert.equal(result.security.subject.tokenType, 'TOKEN_HAP');
  assert.equal(result.security.rejectingGates[0], 'root-or-native');
  assert.equal(result.operationRef.startsWith('F:'), true);
  assert.equal(result.operationCallRef.startsWith('F:'), true);
  assert.equal(result.saRegistration.profileRef.startsWith('M:'), true);
});

test('non-blocking rejection is candidate, never a policy-backed finding', () => {
  const stub = texts.stub.replace('reply.WriteInt32(ERR_IDENTITY_CHECK_FAILED);\n        return;\n    }\n    AccessTokenID tokenID',
    'reply.WriteInt32(ERR_IDENTITY_CHECK_FAILED);\n               \n    }\n    AccessTokenID tokenID');
  assert.notEqual(stub, texts.stub);
  const result = proof({ stub });
  assert.equal(result.status, 'candidate');
  assert.equal(result.security.reason, 'policy-anchor-doc-only');
  assert.equal(result.gates[0].blocksOperation, false);
});

test('binding, dispatch, gate and identity drift remain insufficient', () => {
  assert.equal(proof({}, { ...entry, factRef: 'F:wrong' }).reason, 'ipc-code-binding-unresolved');
  assert.equal(proof({ codeHeader: texts.codeHeader.replace('DELETE_REMOTE_HAP_TOKEN_INFO,',
    'OTHER_CODE,') }).reason, 'ipc-dispatch-drift');
  assert.equal(proof({ stub: texts.stub.replace('return type == TOKEN_NATIVE;',
    'return type != TOKEN_NATIVE;') }).reason, 'ipc-caller-or-gate-shape-unknown');
  assert.equal(proof({ stub: texts.stub.replaceAll('!IsRootCalling() && !IsNativeProcessCalling()',
    '!IsRootCalling() || !IsNativeProcessCalling()') }).reason, 'ipc-identity-gate-unknown');
  assert.equal(proof({ profile: texts.profile.replace('token_sync_service', 'other_service') }).reason,
    'sa-build-or-ownership-unresolved');
  assert.equal(proof({ service: texts.service +
    'SystemAbility::MakeAndRegisterAbility(DelayedSingleton<TokenSyncManagerService>::GetInstance().get());' }).reason,
  'sa-publish-or-operation-unresolved');
  assert.equal(proof({ serviceBuild: texts.serviceBuild.replace('token_sync_enable == true',
    'token_sync_enable == false') }).reason, 'sa-build-or-ownership-unresolved');
});

test('real IPC code runs off to report and source-backed check without a document norm', (t) => {
  const root = path.join(__dirname, '..');
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'oh6-ipc-verdict-'));
  t.after(() => fs.rmSync(out, { recursive: true, force: true }));
  const invoke = (args) => spawnSync(process.execPath, ['bin/autonomy.js', ...args],
    { cwd: root, encoding: 'utf8', env: { ...process.env, OH6_AUTONOMY_ROOT: out } });
  const options = ['--scope=K/policies/autonomy-r3-tokensync-verdict-scope.json',
    '--budget=K/policies/autonomy-r3-ipc-code-budget.json'];
  const denied = invoke(['run', ...options, '--mode=live']);
  assert.equal(denied.status, 2, denied.stdout + denied.stderr);
  const run = invoke(['run', ...options, '--mode=off']);
  assert.equal(run.status, 0, run.stdout + run.stderr);
  const result = JSON.parse(run.stdout);
  assert.deepEqual(result.counts, { tasks: 1, candidate: 0, observation: 0, excluded: 1, finding: 0 });
  const dir = path.join(out, result.runId.replace(':', '-'));
  const record = JSON.parse(fs.readFileSync(path.join(dir, 'run.json'), 'utf8'));
  assert.equal(record.payload.architectureVersion, '1.0.22-ipc-code-verdict');
  assert.equal(record.payload.knowledgeVersion, null);
  const report = invoke(['report', `--run=${result.runId}`]);
  assert.equal(report.status, 0, report.stdout + report.stderr);
  const checked = invoke(['check', `--run=${result.runId}`]);
  assert.equal(checked.status, 0, checked.stdout + checked.stderr);
  assert.deepEqual(JSON.parse(checked.stdout).errors, []);
  const row = JSON.parse(fs.readFileSync(path.join(dir, 'report-model.jsonl'), 'utf8')).payload;
  assert.equal(row.contractDeviation, 'not-applicable');
  assert.equal(row.securitySubject, 'local IPC caller with non-root UID and HAP access token');
  assert.equal(row.securityFamily, 'scoped-gate-rejection');
  assert.equal(row.operationRef.startsWith('F:'), true);
  assert.deepEqual(row.missing, []);
  const questions = fs.readFileSync(path.join(dir, 'questions.jsonl'), 'utf8').trim()
    .split(/\r?\n/).map((line) => JSON.parse(line).payload);
  assert.equal(questions.find((q) => q.kind === 'contract-deviation').status, 'not-applicable');
  assert.equal(questions.find((q) => q.kind === 'security-decision').status, 'refuted');
  assert.equal(questions.find((q) => q.kind === 'check-presence').status, 'supported');
  const questionFile = path.join(dir, 'questions.jsonl');
  const altered = fs.readFileSync(questionFile, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  altered.find((q) => q.payload.kind === 'security-decision').payload.status = 'not-applicable';
  fs.writeFileSync(questionFile, altered.map(JSON.stringify).join('\n') + '\n', 'utf8');
  const rejected = invoke(['check', `--run=${result.runId}`]);
  assert.equal(rejected.status, 3, rejected.stdout + rejected.stderr);
  assert.ok(JSON.parse(rejected.stdout).errors.some((error) => error.code === 'bad-enum'));
});
