'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const factsLib = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const knowledgeLib = require('../lib/autonomy/knowledge');
const permissionArgument = require('../lib/autonomy/permission-argument');
const staticProof = require('../lib/autonomy/static-proof');
const ids = require('../lib/autonomy/ids');
const tools = require('../lib/autonomy/tools');
const { ModelGateway } = require('../lib/autonomy/model');
const mutantLabels = require('../eval/autonomy/static-builder-mutants.json');
const securityMutantLabels = require('../eval/autonomy/security-verdict-mutants.json');
const policyLib = require('../lib/autonomy/policy');
const scope = require('../K/policies/autonomy-pilot-scope.json');

const root = path.resolve(__dirname, '..');
const labels = require('../eval/autonomy/static-builder-labels.json');

function summarize(rows) {
  const agreed = rows.filter((row) => row.expected === row.observed).length;
  return { labelSource: labels.labelSource, modelFamily: labels.modelFamily, familyCount: 1,
    sampleCount: rows.length, agreementWithBuilderLabels: agreed / rows.length,
    findingPrecisionAgainstBuilderLabels: rows.filter((row) => row.observed === 'finding').length
      ? rows.filter((row) => row.observed === 'finding' && row.expected === 'finding').length /
        rows.filter((row) => row.observed === 'finding').length : null,
    independentAccuracy: null, discoveryRecall: null, abcdComparison: 'not-run',
    limitation: 'Two production entries in one component/family; Builder labels are not independent truth.', rows };
}

function evaluate() {
  const rows = [];
  for (const label of labels.labels) {
    const runDir = path.join(root, 'out', 'autonomy', label.runId.replace(':', '-'));
    const result = spawnSync(process.execPath, ['bin/autonomy.js', 'check', `--run=${label.runId}`],
      { cwd: root, encoding: 'utf8' });
    if (result.status !== 0) throw new Error(`check failed for ${label.runId}: ${result.stdout} ${result.stderr}`);
    const report = fs.readFileSync(path.join(runDir, 'report-model.jsonl'), 'utf8').trim()
      .split('\n').map(JSON.parse).filter((row) => row.payload.entryRef === label.entryRef &&
        row.payload.origin === 'entry-scan');
    if (report.length !== 1) throw new Error(`entry report not unique: ${label.runId}`);
    rows.push({ method: label.method, runId: label.runId, expected: label.expected,
      observed: report[0].payload.reportability, source: label.source });
  }
  return summarize(rows);
}

function mutantFacts(base, bound, label) {
  const file = `test/fixtures/autonomy/mutants/${label.file}`;
  const text = fs.readFileSync(path.join(root, file), 'utf8');
  const sha256 = crypto.createHash('sha256').update(text).digest('hex');
  if (sha256 !== label.sha256) throw new Error(`mutant source drift: ${label.file}`);
  const lines = text.split(/\r?\n/);
  const fn = { ...bound, factId: `F:mutant:${sha256.slice(0, 16)}`,
    sourceRange: { file }, startLine: 1, endLine: lines.length };
  const calls = [];
  for (let i = 0; i < lines.length; i++) {
    const check = /\bCheckPermission\s*\(/.test(lines[i]);
    const operation = /PolicyInfoManager::GetInstance\(\)\.SetPolicy\s*\(/.test(lines[i]);
    if (!check && !operation) continue;
    calls.push({ factId: `F:mutant-call:${sha256.slice(0, 12)}:${i + 1}`,
      caller: fn.factId, callerName: fn.name, line: i + 1,
      calleeName: check ? 'CheckPermission' : 'SetPolicy',
      callee: check ? 'F:mutant-check' : null, argc: check ? 2 : 5,
      quality: { resolution: check ? 'exact' : 'name-only', parse: 'controlled-mutant' } });
  }
  const indexed = base.index();
  const facts = Object.create(base);
  facts.index = () => ({ ...indexed, calls: [...indexed.calls, ...calls] });
  facts.callsOf = (qualified, opts) => qualified === fn.qualified ? calls : base.callsOf(qualified, opts);
  facts.verifyFile = (rel) => rel === file ? { ok: true, actual: sha256 } : base.verifyFile(rel);
  facts.sourceWindow = (rel, start, end, opts) => rel === file
    ? { file, startLine: 1, endLine: lines.length, text, sha256, truncated: false }
    : base.sourceWindow(rel, start, end, opts);
  return { facts, fn };
}

function evaluateMutants(base = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope })) {
  const anchors = discovery.buildAnchors(base, scope);
  const entry = anchors.entries.find((row) => row.kind === 'idl' && row.method === mutantLabels.normMethod);
  const original = discovery.resolveBinding(entry.entityId, { facts: base, scope, anchors: anchors.anchors });
  const knowledge = knowledgeLib.loadPublished(path.join(root, 'K/norms',
    '050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c', 'knowledge.json'), null, base);
  const files = fs.readdirSync(path.join(root, 'test/fixtures/autonomy/mutants')).sort();
  if (files.join('|') !== mutantLabels.labels.map((row) => row.file).sort().join('|')) {
    throw new Error('mutant corpus differs from frozen labels');
  }
  const rows = mutantLabels.labels.map((label) => {
    const { facts, fn } = mutantFacts(base, original.bound, label);
    const binding = { binding: 'resolved', bound: fn };
    const comparison = permissionArgument.compare(facts, entry, binding, knowledge);
    const proof = staticProof.analyze(facts, entry, binding, knowledge, comparison, { includeNewFamilies: true });
    return { file: label.file, familyId: label.familyId, source: 'controlled-mutant',
      sha256: label.sha256, expected: label.expected, observed: proof.status,
      observedFamily: proof.family || null, reason: proof.reason || null };
  });
  const positive = rows.filter((row) => row.expected === 'finding');
  const findings = rows.filter((row) => row.observed === 'finding');
  const unknown = rows.filter((row) => row.expected === 'insufficient');
  return { labelSource: mutantLabels.labelSource, labelAuthority: mutantLabels.labelAuthority,
    needsHumanTuning: true, snapshotId: mutantLabels.snapshotId, sourceType: mutantLabels.sourceType,
    sampleCount: rows.length, familyCount: new Set(rows.map((row) => row.familyId)).size,
    denominators: { judgments: rows.length, positiveMutants: positive.length,
      reportedFindings: findings.length, insufficientMutants: unknown.length },
    judgmentAccuracy: rows.filter((row) => row.expected === row.observed).length / rows.length,
    findingPrecision: findings.filter((row) => row.expected === 'finding').length / (findings.length || 1),
    givenMutantFindingRecall: positive.filter((row) => row.observed === 'finding').length / positive.length,
    discoveryRecall: null,
    falseCertaintyRate: unknown.filter((row) => ['finding', 'excluded'].includes(row.observed)).length / unknown.length,
    independentAccuracy: null,
    limitation: 'Controlled-mutant fixture enumeration and Builder labels only; not unseeded production discovery or independent human accuracy.',
    rows };
}

/** §24.28 阶段 C1：双命题语义下的受控变异体（真实门禁家族）。 */
function securityMutantFacts(base, bound, label) {
  const file = `test/fixtures/autonomy/security-mutants/${label.file}`;
  const text = fs.readFileSync(path.join(root, file), 'utf8');
  const sha256 = crypto.createHash('sha256').update(text).digest('hex');
  if (sha256 !== label.sha256) throw new Error(`security mutant source drift: ${label.file}`);
  const lines = text.split(/\r?\n/);
  const fn = { ...bound, factId: `F:secmutant:${sha256.slice(0, 16)}`,
    sourceRange: { file }, startLine: 1, endLine: lines.length };
  const calls = [];
  for (let i = 0; i < lines.length; i++) {
    const check = /^\s*if\s*\(\s*!\s*CheckPermission\s*\(/.test(lines[i]);
    const operation = new RegExp(`PolicyInfoManager::GetInstance\\(\\)\\.${label.method}\\s*\\(`).test(lines[i]);
    if (!check && !operation) continue;
    calls.push({ factId: `F:secmutant-call:${sha256.slice(0, 12)}:${i + 1}`,
      caller: fn.factId, callerName: fn.name, line: i + 1,
      calleeName: check ? 'CheckPermission' : label.method,
      callee: check ? 'F:secmutant-check' : null, argc: check ? 2 : label.method === 'SetPolicy' ? 5 : 2,
      quality: { resolution: check ? 'exact' : 'name-only', parse: 'controlled-mutant' } });
  }
  const indexed = base.index();
  const facts = Object.create(base);
  facts.index = () => ({ ...indexed, calls: [...indexed.calls, ...calls] });
  facts.callsOf = (qualified, opts) => qualified === fn.qualified ? calls : base.callsOf(qualified, opts);
  facts.verifyFile = (rel) => rel === file ? { ok: true, actual: sha256 } : base.verifyFile(rel);
  facts.sourceWindow = (rel, start, end, opts) => rel === file
    ? { file, startLine: 1, endLine: lines.length, text, sha256, truncated: false }
    : base.sourceWindow(rel, start, end, opts);
  return { facts, fn };
}

function evaluateSecurityMutants(base = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope })) {
  const anchors = discovery.buildAnchors(base, scope);
  const suite = knowledgeLib.loadKnowledgeSuite([
    path.join(root, 'K/norms/050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c', 'knowledge.json'),
    path.join(root, 'K/norms/7b1ad465ab401111ad3bfa060d31e4e790e390ad3c6f68d7b30b74ee09fd215f', 'knowledge.json')
  ], base);
  const policy = policyLib.load(base);
  const files = fs.readdirSync(path.join(root, 'test/fixtures/autonomy/security-mutants')).sort();
  if (files.join('|') !== securityMutantLabels.labels.map((row) => row.file).sort().join('|')) {
    throw new Error('security mutant corpus differs from frozen labels');
  }
  const rows = securityMutantLabels.labels.map((label) => {
    const entry = anchors.entries.find((row) => row.kind === 'idl' && row.method === label.method);
    if (!entry) throw new Error(`security mutant method missing: ${label.method}`);
    const original = discovery.resolveBinding(entry.entityId, { facts: base, scope, anchors: anchors.anchors });
    const { facts, fn } = securityMutantFacts(base, original.bound, label);
    const binding = { binding: 'resolved', bound: fn };
    const knowledge = suite.byMethod.get(label.method);
    const comparison = permissionArgument.compare(facts, entry, binding, knowledge);
    const proof = staticProof.analyzeSecurity(facts, entry, binding, knowledge, comparison, { policy });
    return { file: label.file, familyId: label.familyId, source: 'controlled-mutant',
      sha256: label.sha256, expected: label.expected, expectedSecurityFamily: label.expectedSecurityFamily,
      observed: proof.status, observedSecurityFamily: proof.security?.family || null,
      observedSecurityReason: proof.security?.reason || proof.reason || null,
      observedContract: proof.contract ? (proof.contract.family || proof.contract.status) : null,
      reason: proof.reason || null };
  });
  const positives = rows.filter((row) => row.expected === 'finding');
  const findings = rows.filter((row) => row.observed === 'finding');
  const insufficient = rows.filter((row) => row.expected === 'insufficient');
  return { labelSource: securityMutantLabels.labelSource,
    labelAuthority: securityMutantLabels.labelAuthority, needsHumanTuning: true,
    snapshotId: securityMutantLabels.snapshotId, sourceType: securityMutantLabels.sourceType,
    semantics: '1.0.20-security-verdict',
    sampleCount: rows.length, familyCount: new Set(rows.map((row) => row.familyId)).size,
    denominators: { judgments: rows.length, positiveMutants: positives.length,
      reportedFindings: findings.length, insufficientMutants: insufficient.length },
    judgmentAccuracy: rows.filter((row) => row.expected === row.observed).length / rows.length,
    familyAccuracy: rows.filter((row) => (row.observedSecurityFamily || row.observedSecurityReason) ===
      row.expectedSecurityFamily).length / rows.length,
    findingPrecision: findings.length
      ? findings.filter((row) => row.expected === 'finding').length / findings.length : null,
    givenMutantFindingRecall: positives.length
      ? positives.filter((row) => row.observed === 'finding').length / positives.length : null,
    discoveryRecall: null,
    falseCertaintyRate: insufficient.filter((row) => ['finding', 'excluded'].includes(row.observed)).length / insufficient.length,
    independentAccuracy: null,
    limitation: 'Controlled security-verdict mutant enumeration with Builder labels only; ACL-enabled permissions cap expected positives at candidate, so no real-anchor finding is asserted here; not unseeded discovery or independent human accuracy.',
    rows };
}

function evaluateStaticContrast() {
  const start = performance.now();
  const base = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  base.index();
  const preprocessingMs = performance.now() - start;
  const coldStart = performance.now();
  const baseline = evaluateMutants(base);
  const coldMs = performance.now() - coldStart;
  const hotStart = performance.now();
  const repeated = evaluateMutants(base);
  const hotMs = performance.now() - hotStart;
  if (JSON.stringify(baseline.rows) !== JSON.stringify(repeated.rows)) throw new Error('hot result drift');
  const groups = ['A', 'B', 'C', 'D'].map((group) => {
    const rows = baseline.rows.map((row) => {
      const text = fs.readFileSync(path.join(root, 'test/fixtures/autonomy/mutants', row.file), 'utf8');
      const checks = text.match(/\bCheckPermission\s*\(/g) || [];
      const operations = text.match(/PolicyInfoManager::GetInstance\(\)\.SetPolicy\s*\(/g) || [];
      let observed;
      if (group === 'A') {
        observed = checks.length === 0 ? 'finding' :
          /return\s+PERMISSION_DENIED\s*;/.test(text) ? 'excluded' : 'finding';
      } else if (group === 'B') {
        observed = operations.length !== 1 ? 'insufficient' : checks.length === 0 ? 'finding' :
          /if\s*\(\s*!\s*CheckPermission\s*\([^)]*\)\s*\)\s*\{\s*return\s+PERMISSION_DENIED\s*;\s*\}/.test(text)
            ? 'excluded' : 'finding';
      } else observed = row.observed;
      return { file: row.file, expected: row.expected, observed };
    });
    return { group, correct: rows.filter((row) => row.expected === row.observed).length,
      total: rows.length, falseCertainty: rows.filter((row) => row.expected === 'insufficient' &&
        ['finding', 'excluded'].includes(row.observed)).length, rows };
  });
  return { kind: 'deterministic-static-ablation-not-model-comparison', labelSource: baseline.labelSource,
    input: 'Five frozen controlled mutants; A raw-text heuristic, B source-call/guard heuristic, C published norm plus bounded proof, D program-curated sufficient local context with the same proof.',
    independentOracle: false, modelRequests: 0, preprocessingMs, coldMs, hotMs,
    groups, limitation: 'D is not an independent oracle; these five same-method fixtures do not establish production unseeded recall or model uplift.' };
}

async function evaluateModelContrast(gateway, base = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope }), logFile = null) {
  if (gateway.mode !== 'live' || !gateway.keyPresent()) throw new Error('model contrast requires a live profile key');
  const anchors = discovery.buildAnchors(base, scope);
  const entry = anchors.entries.find((row) => row.kind === 'idl' && row.method === mutantLabels.normMethod);
  const binding = discovery.resolveBinding(entry.entityId, { facts: base, scope, anchors: anchors.anchors });
  const knowledge = knowledgeLib.loadPublished(path.join(root, 'K/norms',
    '050e10d78c6e93541813beb477a3c1000cbfd46817a5bf8fbf7bc5dc21b7572c', 'knowledge.json'), null, base);
  const rows = [];
  for (const label of mutantLabels.labels) {
    const { facts, fn } = mutantFacts(base, binding.bound, label);
    const source = fs.readFileSync(path.join(root, 'test/fixtures/autonomy/mutants', label.file), 'utf8');
    const sourceRef = 'SRC:' + label.sha256.slice(0, 16);
    const comparison = permissionArgument.compare(facts, entry, { binding: 'resolved', bound: fn }, knowledge);
    const proof = staticProof.analyze(facts, entry, { binding: 'resolved', bound: fn }, knowledge,
      comparison, { includeNewFamilies: true });
    const raw = { proposition: 'Does this local service enforce the published permission before its policy operation?',
      sourceRef, source, allowedVerdicts: ['finding', 'excluded', 'insufficient'] };
    const structured = { ...raw, calls: facts.callsOf(fn.qualified), sourceSha256: label.sha256 };
    const inputs = { A: raw, B: structured, C: { ...structured, norm: knowledge.norm },
      D: { ...structured, norm: knowledge.norm, boundedProof: proof } };
    for (const [group, input] of Object.entries(inputs)) {
      const taskId = ids.taskId('mutant-contrast', { file: label.file });
      const contextId = ids.contextId('mutant-contrast', { group, input });
      if (logFile) fs.appendFileSync(logFile, JSON.stringify({ status: 'reserved', file: label.file,
        group, taskId, contextId, model: gateway.config.model,
        inputSha256: ids.sha256Hex(ids.canonicalJson(input)) }) + '\n', 'utf8');
      const call = await gateway.invoke({ purpose: 'mutant-contrast-' + group, taskId, contextId,
        maxTokens: 4096, messages: [
          { role: 'system', content: 'Return JSON only: verdict (finding|excluded|insufficient), evidenceRefs (array), rationale. Use the supplied source only; do not assume a missing check is globally exploitable.' },
          { role: 'user', content: JSON.stringify(input) }
        ] });
      const verdict = call.status === 'ok' && ['finding', 'excluded', 'insufficient'].includes(call.parsed?.verdict) &&
        Array.isArray(call.parsed.evidenceRefs) && call.parsed.evidenceRefs.includes(sourceRef) &&
        call.parsed.evidenceRefs.every((ref) => ref === sourceRef) ? call.parsed.verdict : null;
      rows.push({ file: label.file, familyId: label.familyId, expected: label.expected,
        group, verdict, failure: verdict ? null : call.reason || 'invalid-model-verdict',
        model: call.model, callId: call.callId, inputSha256: ids.sha256Hex(ids.canonicalJson(input)),
        responseSha256: call.contentSha256, usage: call.usage, wallMs: call.wallMs });
      if (logFile) fs.appendFileSync(logFile, JSON.stringify({ status: call.status, file: label.file,
        group, callId: call.callId, reason: call.reason || null,
        detail: call.detail || null, finishReason: call.finishReason || null, wallMs: call.wallMs,
        responseSha256: call.contentSha256 || null }) + '\n', 'utf8');
    }
  }
  return { kind: 'same-model-mutant-contrast', labelAuthority: mutantLabels.labelAuthority,
    needsHumanTuning: true, model: gateway.config.model, snapshotId: base.snapshotId,
    requests: gateway.budget.modelRequests, maxModelRequests: gateway.budget.policy.maxModelRequests,
    groups: ['A', 'B', 'C', 'D'].map((group) => {
      const groupRows = rows.filter((row) => row.group === group);
      return { group, correct: groupRows.filter((row) => row.verdict === row.expected).length,
        total: groupRows.length, invalid: groupRows.filter((row) => !row.verdict).length,
        falseCertainty: groupRows.filter((row) => row.expected === 'insufficient' &&
          ['finding', 'excluded'].includes(row.verdict)).length };
    }), rows, limitation: 'Given controlled mutants and Builder labels; D contains program proof. No scope-only discovery recall or independent oracle.' };
}

function evaluateSuite(runId) {
  const runDir = path.join(root, 'out', 'autonomy', runId.replace(':', '-'));
  const result = spawnSync(process.execPath, ['bin/autonomy.js', 'check', `--run=${runId}`],
    { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`suite check failed: ${result.stdout} ${result.stderr}`);
  const run = JSON.parse(fs.readFileSync(path.join(runDir, 'run.json'), 'utf8'));
  if (!['1.0.17-static-scan', '1.0.18-static-arbitration', '1.0.19-autonomous-static',
      '1.0.20-security-verdict'].includes(run.payload.architectureVersion)) {
    throw new Error('not a static suite run');
  }
  const rows = fs.readFileSync(path.join(runDir, 'report-model.jsonl'), 'utf8').trim().split('\n')
    .map(JSON.parse).map((record) => record.payload);
  const counts = Object.fromEntries(['finding', 'excluded', 'candidate', 'observation']
    .map((status) => [status, rows.filter((row) => row.reportability === status).length]));
  const familyKey = (row) => row.findingFamily || row.securityFamily || row.contractDeviation || null;
  return { runId, snapshotId: run.payload.snapshotId, mode: run.payload.mode,
    tasks: rows.length, entryTasks: rows.filter((row) => row.origin === 'entry-scan').length,
    coverageTasks: rows.filter((row) => row.origin === 'coverage-sample').length,
    counts, families: Object.fromEntries([...new Set(rows.map(familyKey).filter(Boolean))]
      .map((family) => [family, rows.filter((row) => familyKey(row) === family).length])),
    limitation: 'Production classifications are not independently labeled; no production precision or recall is inferred.' };
}

if (require.main === module) {
  (async () => {
  try {
    if (process.argv.includes('--model-abcd')) {
      const gateway = ModelGateway.create({ mode: 'live',
        budget: tools.createBudget({ maxModelRequests: 20, maxTaskModelRequests: 4,
          maxInputTokens: 200000, maxOutputTokens: 60000 }) });
      const dir = path.join(root, 'out', 'autonomy', 'eval');
      if (process.argv.includes('--write')) fs.mkdirSync(dir, { recursive: true });
      const logFile = process.argv.includes('--write') ? path.join(dir,
        'model-abcd-' + Date.now() + '-' + process.pid + '.jsonl') : null;
      const result = await evaluateModelContrast(gateway, undefined, logFile);
      if (process.argv.includes('--write')) {
        result.logFile = path.relative(root, logFile).split(path.sep).join('/');
        fs.writeFileSync(logFile.replace(/\.jsonl$/, '.json'),
          JSON.stringify(result, null, 2) + '\n', 'utf8');
      }
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      return;
    }
    const runArg = process.argv.find((arg) => arg.startsWith('--suite-run='));
    const result = runArg ? { production: evaluateSuite(runArg.slice(12)), mutants: evaluateMutants(),
      security: process.argv.includes('--security-mutants') ? evaluateSecurityMutants() : undefined,
      abcd: evaluateStaticContrast() }
      : process.argv.includes('--security-mutants') ? evaluateSecurityMutants()
        : process.argv.includes('--mutants') ? evaluateMutants() : evaluate();
    if (runArg && process.argv.includes('--write')) {
      const target = path.join(root, 'out', 'autonomy', 'eval', `${runArg.slice(12).replace(':', '-')}.json`);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
    }
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  }
  catch (e) { process.stderr.write(`${e.message}\n`); process.exitCode = 1; }
  })();
}

module.exports = { evaluate, summarize, evaluateMutants, evaluateSecurityMutants, securityMutantFacts,
  evaluateSuite, evaluateStaticContrast, evaluateModelContrast };
