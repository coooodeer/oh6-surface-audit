'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const { AutonomyFacts } = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const { sourceProof, analyze } = require('../lib/autonomy/rust-verdict');
const { probeRows } = require('../lib/autonomy/ipc-dispatch');

const scope = require('../K/policies/autonomy-r3-asset-rust-verdict-scope.json');
const facts = AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
const idx = facts.index();
const cfg = scope.ipcCodeVerdict;
const anchors = discovery.buildAnchors(facts, scope);
const entry = anchors.entries[0];
const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
const read = (rel) => fs.readFileSync(path.join(facts.sourceRoot, ...rel.split('/')), 'utf8');
const textRels = { enum: cfg.enumFile, stub: cfg.stubFile, service: cfg.serviceFile,
  operation: cfg.operationFile, gate: cfg.gateFile, calling: cfg.callingFile,
  process: cfg.processFile, ffi: cfg.ffiFile, ffiHeader: cfg.ffiHeaderFile,
  profile: cfg.profileFile, ...cfg.pinned };
const texts = Object.fromEntries(Object.entries(textRels).map(([key, rel]) => [key, read(rel.file || rel)]));
const binary = require('../lib/facts/rust').probeBinary();
const probe = Object.fromEntries(['enum', 'stub', 'service', 'operation', 'gate'].map((key) =>
  [key, probeRows(binary, path.join(facts.sourceRoot, ...cfg[`${key}File`].split('/')))]));
const proof = (changedTexts = {}, changedProbe = probe, changedEntry = entry, changedBinding = binding) =>
  sourceProof(changedEntry, changedBinding, cfg, idx, { ...texts, ...changedTexts }, changedProbe);

test('real non-system HAP cross-user Query caller is excluded by the scoped gate', () => {
  const result = analyze(facts, entry, binding, cfg);
  assert.equal(result.status, 'excluded');
  assert.deepEqual(result, proof());
  assert.equal(result.contract.status, 'not-applicable');
  assert.equal(result.security.subject.tokenType, 'TOKEN_HAP');
  assert.equal(result.security.subject.systemApp, false);
  assert.equal(result.security.rejectingGates[0], 'cross-user-system-hap-permission');
  assert.equal(result.gates.length, 3);
  assert.equal(result.gates.every((gate) => gate.blocksOperation === true), true);
  assert.equal(result.operationRef.startsWith('F:'), true);
  assert.equal(result.operationCallRef.startsWith('F:'), true);
  assert.equal(result.saRegistration.profileRef.startsWith('M:'), true);
});

test('non-blocking gate shape is candidate, never a policy-backed finding', () => {
  const mutated = { ...probe, gate: probe.gate.map((row) =>
    row.kind === 'asset-gate' ? { ...row, kind: 'asset-gate-noblock' } : row) };
  const result = proof({}, mutated);
  assert.equal(result.status, 'candidate');
  assert.equal(result.security.reason, 'policy-anchor-doc-only');
  assert.equal(result.gates.every((gate) => gate.blocksOperation === false), true);
  assert.equal(result.operationRef.startsWith('F:'), true);
});

test('binding, dispatch, gate and identity drift remain insufficient', () => {
  assert.equal(proof({}, probe, { ...entry, factRef: 'F:wrong' }).reason, 'rust-code-binding-unresolved');
  // 派发边缺失（Query arm 无唯一 stub 调用）→ 具名 dispatch-drift
  const noCall = { ...probe, stub: probe.stub.filter((row) => !(row.kind === 'ipc-call' && row.name === 'Query->query')) };
  assert.equal(proof({}, noCall).reason, 'rust-dispatch-drift');
  // 门禁形状不可识别（真实变异在探针层已证；此处固定其判形结果）→ gate-shape-unknown
  const noGate = { ...probe, gate: probe.gate.map((row) => ({ ...row, kind: 'asset-gate-unresolved' })) };
  assert.equal(proof({}, noGate).reason, 'rust-gate-shape-unknown');
  // 调用方身份 FFI 形状漂移
  assert.equal(proof({ ffi: texts.ffi.replace('GetCallingTokenID()', 'GetSelfTokenID()') }).reason,
    'rust-ffi-identity-unknown');
  // 对象链漂移：Tag::UserId 覆盖被移除
  assert.equal(proof({ stub: texts.stub.replace('map.get(&Tag::UserId).cloned()', 'None') }).reason,
    'rust-stub-gate-or-object-unknown');
  assert.equal(proof({ calling: texts.calling.replace('user_id = specific_user_id;', 'user_id = 0;') }).reason,
    'rust-object-link-unknown');
  // 宏与操作链漂移
  assert.equal(proof({ service: texts.service.replaceAll('create_user_de_dir($calling_info.user_id())?',
    'create_user_de_dir(0)?') }).reason, 'rust-macro-shape-unknown');
  assert.equal(proof({ operation: texts.operation.replace('check_arguments(query, calling_info)?;',
    'check_arguments(query, calling_info);') }).reason, 'rust-operation-chain-unknown');
  // SA 注册与 profile 漂移
  assert.equal(proof({ profile: texts.profile.replace('asset_service', 'other_service') }).reason,
    'rust-sa-profile-unresolved');
  assert.equal(proof({ service: texts.service.replace('sa.register();', 'sa.deregister();') }).reason,
    'rust-sa-registration-unknown');
  assert.equal(proof({ serviceBuild: texts.serviceBuild.replace('crate_type = "dylib"', 'crate_type = "cdylib"') }).reason,
    'rust-sa-registration-unknown');
});

test('real Rust enum-code run goes off to report and source-backed check without a document norm', (t) => {
  const root = path.join(__dirname, '..');
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'oh6-rust-verdict-'));
  t.after(() => fs.rmSync(out, { recursive: true, force: true }));
  const invoke = (args) => spawnSync(process.execPath, ['bin/autonomy.js', ...args],
    { cwd: root, encoding: 'utf8', env: { ...process.env, OH6_AUTONOMY_ROOT: out } });
  const options = ['--scope=K/policies/autonomy-r3-asset-rust-verdict-scope.json',
    '--budget=K/policies/autonomy-r3-asset-rust-verdict-budget.json'];
  const denied = invoke(['run', ...options, '--mode=live']);
  assert.equal(denied.status, 2, denied.stdout + denied.stderr);
  const run = invoke(['run', ...options, '--mode=off']);
  assert.equal(run.status, 0, run.stdout + run.stderr);
  const result = JSON.parse(run.stdout);
  assert.deepEqual(result.counts, { tasks: 1, candidate: 0, observation: 0, excluded: 1, finding: 0 });
  const dir = path.join(out, result.runId.replace(':', '-'));
  const record = JSON.parse(fs.readFileSync(path.join(dir, 'run.json'), 'utf8'));
  assert.equal(record.payload.architectureVersion, '1.0.23-rust-ipc-code-verdict');
  assert.equal(record.payload.knowledgeVersion, null);
  const report = invoke(['report', `--run=${result.runId}`]);
  assert.equal(report.status, 0, report.stdout + report.stderr);
  const checked = invoke(['check', `--run=${result.runId}`]);
  assert.equal(checked.status, 0, checked.stdout + checked.stderr);
  assert.deepEqual(JSON.parse(checked.stdout).errors, []);
  const row = JSON.parse(fs.readFileSync(path.join(dir, 'report-model.jsonl'), 'utf8')).payload;
  assert.equal(row.contractDeviation, 'not-applicable');
  assert.equal(row.securityFamily, 'scoped-gate-rejection');
  assert.equal(row.securitySubject, 'local IPC caller with a HAP access token that is not a system application');
  assert.equal(row.operationRef.startsWith('F:'), true);
  assert.deepEqual(row.missing, []);
  const questions = fs.readFileSync(path.join(dir, 'questions.jsonl'), 'utf8').trim()
    .split(/\r?\n/).map((line) => JSON.parse(line).payload);
  assert.equal(questions.find((q) => q.kind === 'contract-deviation').status, 'not-applicable');
  assert.equal(questions.find((q) => q.kind === 'security-decision').status, 'refuted');
  assert.equal(questions.find((q) => q.kind === 'check-presence').status, 'supported');
  assert.equal(questions.find((q) => q.kind === 'dominance').status, 'supported');
  const questionFile = path.join(dir, 'questions.jsonl');
  const altered = fs.readFileSync(questionFile, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  altered.find((q) => q.payload.kind === 'security-decision').payload.status = 'not-applicable';
  fs.writeFileSync(questionFile, altered.map(JSON.stringify).join('\n') + '\n', 'utf8');
  const rejected = invoke(['check', `--run=${result.runId}`]);
  assert.equal(rejected.status, 3, rejected.stdout + rejected.stderr);
  assert.ok(JSON.parse(rejected.stdout).errors.some((error) => error.code === 'bad-enum'));
});
