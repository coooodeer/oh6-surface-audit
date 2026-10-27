'use strict';

/**
 * tools/autonomy-os-account-eval.js —— 第二组件受控变异体评测（E3）。
 *
 * 输入（全部冻结、按 sha256 校验）：
 *   - `eval/autonomy/os-account-mutants.json`：Builder-LLM 来源的标签与期望出口；
 *   - `test/fixtures/autonomy/os-account-mutants/*.cpp`：受控变异体源码。
 * 事实层只读复用固定快照；每个变异体只替换"入口函数体 + 其直接调用事实"，
 * 操作目标仍解析到真实 `InnerAccountIAMManager::<Method>`，权限常量仍从真实
 * `account_iam_service.cpp` 解析，helper 仍解析到真实的 `AccountIAMService::CheckPermission`。
 *
 * 输出区分：Builder 标签判定（给定样本）与无种子发现召回是两件事。本工具只报告
 * 前者；`discoveryRecall` / `independentAccuracy` 恒为 null，除非另有独立真值。
 *
 * 用法：node tools/autonomy-os-account-eval.js [--write]
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const factsLib = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const knowledgeLib = require('../lib/autonomy/knowledge');
const permissionArgument = require('../lib/autonomy/permission-argument');
const staticProof = require('../lib/autonomy/static-proof');
const policyLib = require('../lib/autonomy/policy');

const root = path.resolve(__dirname, '..');
const SCOPE_FILE = path.join(root, 'K/policies/autonomy-os-account-iam-scope.json');
const ANCHORS_FILE = path.join(root, 'K/policies/autonomy-security-anchors-os-account.json');
const LABELS_FILE = path.join(root, 'eval/autonomy/os-account-mutants.json');
const FIXTURE_DIR = path.join(root, 'test/fixtures/autonomy/os-account-mutants');
const OUT_FILE = path.join(root, 'out/autonomy/eval/os-account-mutants.json');
const NORMS = [
  'K/norms/71191d8bd0eadd5e7b7a05d6ab55e0e3df4d38918663a21e34520e3ed47236a4/knowledge.json',
  'K/norms/ffed41e7fdd596e26b7a02eef58bbdb1cadb69c14c4079d1940c8c892ccb9472/knowledge.json',
  'K/norms/2046964ca080ff6fee5c0540775d2815482c573bd59e8b6b8180246ec7c6896a/knowledge.json'
];

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function loadLabels(file = LABELS_FILE) {
  const buf = fs.readFileSync(file);
  const labels = JSON.parse(buf.toString('utf8'));
  if (labels.labelSource !== 'builder-llm-oracle' || labels.needsHumanTuning !== true) {
    throw new Error('os-account-mutants-label-source-invalid');
  }
  return { labels, sha256: sha256(buf) };
}

function mutantFacts(base, bound, label, helperFactId) {
  const file = `test/fixtures/autonomy/os-account-mutants/${label.file}`;
  const text = fs.readFileSync(path.join(root, file), 'utf8');
  const sha = sha256(Buffer.from(text, 'utf8'));
  if (sha !== label.sha256) throw new Error(`os-account-mutant-source-drift: ${label.file}`);
  const lines = text.split(/\r?\n/);
  const fn = { ...bound, factId: `F:osmutant:${sha.slice(0, 16)}`,
    sourceRange: { file }, startLine: 1, endLine: lines.length };
  const calls = [];
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const operation = /InnerAccountIAMManager::GetInstance\(\)\.OpenSession\s*\(/.test(line);
    if (operation) {
      calls.push({ factId: `F:osmutant-call:${sha.slice(0, 12)}:${i + 1}:op`,
        caller: fn.factId, callerName: fn.qualified, line: i + 1,
        calleeName: 'OpenSession', callee: null, argc: 2,
        quality: { resolution: 'name-only', parse: 'controlled-mutant' } });
    }
    const check = /\bCheckPermission\s*\(/g;
    let match;
    while ((match = check.exec(line)) !== null) {
      const tail = line.slice(match.index);
      const close = tail.indexOf(')');
      const args = close > 0 ? tail.slice(tail.indexOf('(') + 1, close) : '';
      const argc = args.includes(',') ? 2 : 1;
      calls.push({ factId: `F:osmutant-call:${sha.slice(0, 12)}:${i + 1}:${match.index}`,
        caller: fn.factId, callerName: fn.qualified, line: i + 1,
        calleeName: 'CheckPermission', callee: helperFactId, argc,
        quality: { resolution: 'exact', parse: 'controlled-mutant' } });
    }
  }
  const indexed = base.index();
  const facts = Object.create(base);
  facts.index = () => ({ ...indexed, functions: [...indexed.functions, fn],
    calls: [...indexed.calls, ...calls] });
  facts.callsOf = (qualified, opts) => qualified === fn.qualified ? calls : base.callsOf(qualified, opts);
  facts.verifyFile = (rel) => rel === file ? { ok: true, actual: sha } : base.verifyFile(rel);
  facts.sourceWindow = (rel, start, end, opts) => rel === file
    ? { file, startLine: 1, endLine: lines.length, text, sha256: sha, truncated: false }
    : base.sourceWindow(rel, start, end, opts);
  return { facts, fn };
}

function evaluate(options = {}) {
  const scope = JSON.parse(fs.readFileSync(SCOPE_FILE, 'utf8'));
  const { labels, sha256: labelsSha256 } = options.labels
    ? { labels: options.labels, sha256: options.labelsSha256 || null } : loadLabels();
  if (labels.scopeId !== scope.scopeId || labels.snapshotId !== scope.snapshotId) {
    throw new Error('os-account-mutants-scope-or-snapshot-mismatch');
  }
  const base = options.base || factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const anchors = discovery.buildAnchors(base, scope);
  const suite = knowledgeLib.loadKnowledgeSuite(NORMS.map((rel) => path.join(root, rel)), base);
  const policy = policyLib.load(base, ANCHORS_FILE);
  const helper = base.index().functions.find((fn) =>
    fn.qualified === 'OHOS::AccountSA::AccountIAMService::CheckPermission');
  if (!helper) throw new Error('os-account-check-permission-helper-missing');
  const entry = anchors.entries.find((row) => row.kind === 'idl' && row.method === labels.method);
  if (!entry) throw new Error(`os-account-mutant-method-entry-missing: ${labels.method}`);
  const original = discovery.resolveBinding(entry.entityId, { facts: base, scope, anchors: anchors.anchors });
  if (original.binding !== 'resolved') throw new Error('os-account-mutant-method-binding-unresolved');

  const files = fs.readdirSync(FIXTURE_DIR).filter((name) => name.endsWith('.cpp')).sort();
  if (files.join('|') !== labels.labels.map((row) => row.file).sort().join('|')) {
    throw new Error('os-account-mutant-corpus-differs-from-frozen-labels');
  }

  const rows = labels.labels.map((label) => {
    const method = label.method || labels.method;
    const { facts, fn } = mutantFacts(base, original.bound, label, helper.factId);
    const binding = { binding: 'resolved', bound: fn };
    const knowledge = suite.byMethod.get(method);
    const comparison = permissionArgument.compare(facts, entry, binding, knowledge);
    const proof = staticProof.analyzeSecurity(facts, entry, binding, knowledge, comparison, { policy });
    return {
      file: label.file, sha256: label.sha256, familyId: label.familyId,
      source: 'controlled-mutant', method,
      expected: label.expected, expectedSecurityFamily: label.expectedSecurityFamily,
      expectedContractFamily: label.expectedContractFamily ?? null,
      observed: proof.status,
      observedSecurityFamily: proof.security?.family || null,
      observedSecurityReason: proof.security?.reason || proof.reason || null,
      observedContractFamily: proof.contract ? (proof.contract.family || proof.contract.status) : null,
      operationBound: Boolean(proof.operationRef),
      reason: proof.reason || null
    };
  });

  const positives = rows.filter((row) => row.expected === 'finding');
  const findings = rows.filter((row) => row.observed === 'finding');
  const insufficient = rows.filter((row) => row.expected === 'insufficient');
  const observedSecurity = (row) => row.observedSecurityFamily || row.observedSecurityReason;
  const contractRows = rows.filter((row) => row.expectedContractFamily !== null);
  const metrics = {
    osAccountMutantsVersion: labels.labelsVersion,
    scopeId: scope.scopeId,
    snapshotId: scope.snapshotId,
    semantics: labels.semantics,
    labelSource: labels.labelSource,
    labelAuthority: labels.labelAuthority,
    needsHumanTuning: true,
    sourceType: 'controlled-mutant',
    inputs: {
      labelsFile: path.relative(root, LABELS_FILE).split(path.sep).join('/'),
      labelsSha256,
      fixtureCorpus: files,
      knowledgeVersions: suite.versions.map((k) => k.knowledgeVersion).sort(),
      anchorsSha256: policy.anchorsSha256
    },
    sampleCount: rows.length,
    familyCount: new Set(rows.map((row) => row.familyId)).size,
    denominators: {
      judgments: rows.length,
      positiveMutants: positives.length,
      reportedFindings: findings.length,
      insufficientMutants: insufficient.length,
      contractComparisons: contractRows.length
    },
    judgmentAccuracy: rows.filter((row) => row.expected === row.observed).length / rows.length,
    securityFamilyAccuracy: rows.filter((row) => observedSecurity(row) === row.expectedSecurityFamily).length / rows.length,
    contractFamilyAccuracy: contractRows.length
      ? contractRows.filter((row) => row.observedContractFamily === row.expectedContractFamily).length / contractRows.length
      : null,
    findingPrecision: findings.length
      ? findings.filter((row) => row.expected === 'finding').length / findings.length : null,
    givenMutantFindingRecall: positives.length
      ? positives.filter((row) => row.observed === 'finding').length / positives.length : null,
    falseCertaintyRate: insufficient.length
      ? insufficient.filter((row) => ['finding', 'excluded'].includes(row.observed)).length / insufficient.length
      : null,
    discoveryRecall: null,
    independentAccuracy: null,
    abcdComparison: 'not-run',
    limitation: 'Builder-LLM 来源的受控变异体与冻结标签；不是真实入口漏洞召回或独立人工准确率。变异体只替换入口函数体与直接调用事实，操作目标和权限常量仍来自真实快照。',
    uncovered: {
      methodsWithoutPublishedNorm: ['GetCredentialInfo', 'GetAccountState'],
      note: '本评测只覆盖 OpenSession 的 8 个门禁家族；其余 16 个 IAccountIAM 入口未进入受控样本分母。'
    },
    rows
  };
  return metrics;
}

function main(argv) {
  const write = argv.includes('--write');
  const metrics = evaluate();
  const body = `${JSON.stringify(metrics, null, 2)}\n`;
  if (write) {
    fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
    fs.writeFileSync(OUT_FILE, body, { encoding: 'utf8' });
    process.stdout.write(`${JSON.stringify({ ok: true, out: path.relative(root, OUT_FILE)
      .split(path.sep).join('/'), sha256: sha256(Buffer.from(body, 'utf8')),
      judgmentAccuracy: metrics.judgmentAccuracy, securityFamilyAccuracy: metrics.securityFamilyAccuracy,
      sampleCount: metrics.sampleCount })}\n`);
    return metrics;
  }
  process.stdout.write(body);
  return metrics;
}

module.exports = { evaluate, loadLabels, mutantFacts, OUT_FILE };

if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: e.message })}\n`);
    process.exitCode = 1;
  }
}
