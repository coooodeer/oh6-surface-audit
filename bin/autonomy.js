'use strict';

/**
 * bin/autonomy.js —— 自主审计 Agent MVP 的唯一 CLI。
 *
 * 用法：
 *   node bin/autonomy.js doctor  --scope=K/policies/autonomy-pilot-scope.json [--budget=...] [--snapshot=<id>]
 *   node bin/autonomy.js index   --snapshot=<id> --scope=<policy>
 *   node bin/autonomy.js run     --snapshot=<id> --scope=<policy> --budget=<policy> --mode=off|live|mock
 *                                [--max-tasks=<n>] [--max-model-requests=<n>] [--task=<TASK:id>]
 *                                [--experiment=authorization-v1] (off only; isolated pilot contract)
 *   node bin/autonomy.js tools   --scope=<policy>
 *   node bin/autonomy.js check   --run=<RUN:id|目录>
 *   node bin/autonomy.js report  --run=<RUN:id|目录>
 *   node bin/autonomy.js verify  --run=<RUN:id> --plan=<file>
 *
 * 退出码（§4.1）：0 正常 / 2 参数或配置错误 / 3 check|eval 失败 / 4 未实现 / 5 内部错误 /
 *                6 预算停止（已保存 checkpoint）/ 130 用户取消。
 */

const fs = require('fs');
const path = require('path');

const ids = require('../lib/autonomy/ids');
const jsonl = require('../lib/autonomy/jsonl');
const state = require('../lib/autonomy/state');
const storeLib = require('../lib/autonomy/store');
const schemaLib = require('../lib/autonomy/schema');
const factsLib = require('../lib/autonomy/facts');
const indexLib = require('../lib/autonomy/index');
const discovery = require('../lib/autonomy/discovery');
const tools = require('../lib/autonomy/tools');
const retrieval = require('../lib/autonomy/retrieval');
const modelLib = require('../lib/autonomy/model');
const assessment = require('../lib/autonomy/assessment');
const reportLib = require('../lib/autonomy/report');
const verticalLib = require('../lib/autonomy/vertical');
const staticProofLib = require('../lib/autonomy/static-proof');
const permissionArgumentLib = require('../lib/autonomy/permission-argument');
const branchLib = require('../lib/autonomy/branch');
const recoveryLib = require('../lib/autonomy/recovery');
const verificationLib = require('../lib/autonomy/verification');
const knowledgeLib = require('../lib/autonomy/knowledge');
const doctorLib = require('../lib/autonomy/doctor');
const platform = require('../lib/autonomy/platform');

const TOOL_DIR = path.resolve(__dirname, '..');
const K_DIR = path.join(TOOL_DIR, 'K');
const SCHEMA_DIR = path.join(K_DIR, 'schemas');

const DEFAULT_SCOPE = 'K/policies/autonomy-pilot-scope.json';
const DEFAULT_BUDGET = 'K/policies/autonomy-pilot-budget.json';

const EXIT = Object.freeze({ OK: 0, ARG: 2, CHECK: 3, NOT_IMPLEMENTED: 4, INTERNAL: 5, BUDGET: 6, CANCELLED: 130 });

class CliError extends Error {
  constructor(message, exitCode = EXIT.ARG, code = 'cli-error') {
    super(message);
    this.code = code;
    this.exitCode = exitCode;
  }
}

const USAGE = [
  'Usage:',
  '  node bin/autonomy.js doctor  --scope=<policy> [--budget=<policy>] [--snapshot=<id|latest>]',
  '  node bin/autonomy.js index   --snapshot=<id|latest> --scope=<policy>',
  '  node bin/autonomy.js run     --snapshot=<id|latest> --scope=<policy> --budget=<policy> --mode=off|live|mock',
  '                               [--max-tasks=<n>] [--max-model-requests=<n>] [--task=<TASK:id>]',
  '                               [--experiment=authorization-v1] (off only)',
   '                               [--experiment=vertical-v1|vertical-v2] [--model=<catalog-id>] (off or live)',
   '                               vertical-v2: --task or uniquely applicable published --knowledge',
  '                               [--mode=replay --replay-run=<live RUN:id>] (vertical experiments only)',
  '  node bin/autonomy.js tools   --scope=<policy>',
  '  node bin/autonomy.js check   --run=<RUN:id|dir>',
  '  node bin/autonomy.js report  --run=<RUN:id|dir>',
  '  node bin/autonomy.js recover --run=<RUN:id|dir> (read-only; never resends)',
  '  node bin/autonomy.js resume  --run=<RUN:id> --scope=<policy> --budget=<policy> --mode=off|replay',
  '  node bin/autonomy.js verify  --run=<RUN:id|dir> --plan=<file>',
  '  node bin/autonomy.js knowledge propose --scope=<policy> --doc-set=sandbox-manager-pilot [--norm=SetPolicy|UnSetPolicy]',
  '  node bin/autonomy.js knowledge publish --scope=<policy> --proposal=<file> --approval-file=<file> --review-public-key=<file>',
  '',
  'commands: doctor | index | run | resume | recover | tools | check | report | verify | knowledge propose|publish | help',
  'exit: 0 ok / 2 bad args / 3 check failed / 4 not implemented / 5 internal / 6 budget stop'
].join('\n');

function parseFlags(argv) {
  const opts = { cmd: null, flags: {}, help: false };
  const rest = argv.slice();
  if (rest[0] && !rest[0].startsWith('-')) opts.cmd = rest.shift();
  if (opts.cmd === 'knowledge' && rest[0] && !rest[0].startsWith('-')) opts.cmd += ` ${rest.shift()}`;
  for (const arg of rest) {
    if (arg === '--help' || arg === '-h') { opts.help = true; continue; }
    if (arg === 'help') { opts.cmd = 'help'; continue; }
    if (!arg.startsWith('--')) throw new CliError(`unknown argument: ${arg}`);
    const eq = arg.indexOf('=');
    if (eq < 0) throw new CliError(`flag requires value: ${arg}`);
    opts.flags[arg.slice(2, eq)] = arg.slice(eq + 1);
  }
  return opts;
}

function resolvePath(p) {
  if (!p) return null;
  return path.isAbsolute(p) ? p : path.join(TOOL_DIR, p);
}

function loadScope(flagValue) {
  const p = resolvePath(flagValue || DEFAULT_SCOPE);
  if (!p || !fs.existsSync(p)) throw new CliError(`scope policy not found: ${flagValue || DEFAULT_SCOPE}`);
  const doc = JSON.parse(fs.readFileSync(p, 'utf8'));
  doc.__path = p;
  return doc;
}

function loadBudget(flagValue, overrideMaxModelRequests) {
  const p = resolvePath(flagValue || DEFAULT_BUDGET);
  if (!p || !fs.existsSync(p)) throw new CliError(`budget policy not found: ${flagValue || DEFAULT_BUDGET}`);
  const doc = JSON.parse(fs.readFileSync(p, 'utf8'));
  const budget = { ...(doc.budget || {}) };
  if (overrideMaxModelRequests !== undefined) budget.maxModelRequests = Number(overrideMaxModelRequests);
  const required = ['maxModelRequests', 'maxToolCalls', 'maxInputTokens', 'maxOutputTokens', 'maxWallSeconds',
    'maxTasks', 'maxTaskModelRequests', 'maxTaskToolCalls', 'maxConcurrentTools', 'maxConcurrentModels'];
  const missing = required.filter((k) => !Number.isInteger(budget[k]));
  if (missing.length) throw new CliError(`budget policy missing integer keys: ${missing.join(',')}`);
  // __path 只供本进程使用，**不可枚举**：否则会进 run.json 并破坏 schema
  Object.defineProperty(budget, '__path', { value: p, enumerable: false });
  return budget;
}

function loadTrustedReviewKey(flagValue) {
  if (!flagValue) throw new CliError('knowledge review requires --review-public-key');
  const requested = path.resolve(flagValue);
  if (!fs.existsSync(requested)) throw new CliError('review public key file missing');
  const keyPath = fs.realpathSync.native(requested);
  const workspace = fs.realpathSync.native(path.resolve(TOOL_DIR, '..'));
  if (keyPath.toLowerCase() === workspace.toLowerCase() ||
      keyPath.toLowerCase().startsWith((workspace + path.sep).toLowerCase())) {
    throw new CliError('review public key must be an existing operator-controlled file outside the workspace');
  }
  return fs.readFileSync(keyPath);
}

function cmdKnowledgePropose(opts) {
  if (opts.flags['doc-set'] !== 'sandbox-manager-pilot') {
    throw new CliError('knowledge propose requires --doc-set=sandbox-manager-pilot');
  }
  const scope = loadScope(opts.flags.scope);
  const facts = openFacts(scope, opts.flags.snapshot);
  const norm = opts.flags.norm || 'SetPolicy';
  if (!['SetPolicy', 'UnSetPolicy'].includes(norm)) throw new CliError('unsupported knowledge norm');
  const proposal = norm === 'SetPolicy' ? knowledgeLib.loadAuthorization(facts)
    : knowledgeLib.loadPersistenceAuthorization(facts);
  const file = knowledgeLib.writeProposal(proposal);
  emit({ state: 'proposed', normId: proposal.norm.normId, snapshotId: facts.snapshotId,
    proposalVersion: proposal.knowledgeVersion, file: path.relative(TOOL_DIR, file).split(path.sep).join('/') });
  return EXIT.OK;
}

function cmdKnowledgePublish(opts) {
  if (!opts.flags.proposal || !opts.flags['approval-file']) {
    throw new CliError('knowledge publish requires --proposal and --approval-file');
  }
  const scope = loadScope(opts.flags.scope);
  const facts = openFacts(scope, opts.flags.snapshot);
  const proposalFile = resolvePath(opts.flags.proposal);
  const reviewFile = resolvePath(opts.flags['approval-file']);
  if (!proposalFile.startsWith(knowledgeLib.PROPOSAL_DIR + path.sep) ||
      !reviewFile.startsWith(path.join(K_DIR, 'reviews') + path.sep)) {
    throw new CliError('proposal or review outside the registered knowledge directories');
  }
  try {
    const published = knowledgeLib.publishAuthorization(
      JSON.parse(fs.readFileSync(proposalFile, 'utf8')),
      JSON.parse(fs.readFileSync(reviewFile, 'utf8')),
      opts.flags['review-public-key'] ? loadTrustedReviewKey(opts.flags['review-public-key']) : null, facts);
    emit({ state: 'accepted', knowledgeVersion: published.knowledge.knowledgeVersion,
      normId: published.knowledge.norm.normId, created: published.created,
      file: path.relative(TOOL_DIR, published.file).split(path.sep).join('/') });
  } catch (e) { if (e instanceof CliError) throw e; throw new CliError(`knowledge publish rejected: ${e.message}`); }
  return EXIT.OK;
}

function openFacts(scope, snapshotFlag) {
  const snapshot = snapshotFlag || scope.snapshotId || 'latest';
  const facts = factsLib.AutonomyFacts.open({ snapshot, scope });
  if (scope.snapshotId && facts.snapshotId !== scope.snapshotId) {
    throw new CliError(`snapshot mismatch: scope pins ${scope.snapshotId}, resolved ${facts.snapshotId}`);
  }
  return facts;
}

function emit(obj) {
  process.stdout.write(`${JSON.stringify(obj, null, 2)}\n`);
}

// ---------------------------------------------------------------------------
// doctor / tools / index
// ---------------------------------------------------------------------------

function cmdDoctor(opts) {
  const out = doctorLib.runDoctor({
    scopePath: opts.flags.scope || DEFAULT_SCOPE,
    budgetPath: opts.flags.budget || DEFAULT_BUDGET,
    snapshot: opts.flags.snapshot
  });
  emit(out);
  return out.ok ? EXIT.OK : EXIT.ARG;
}

function cmdTools(opts) {
  const scope = loadScope(opts.flags.scope);
  emit({
    scopeId: scope.scopeId,
    tools: tools.listTools(),
    available: tools.listTools().filter((t) => t.status === 'available').map((t) => t.name),
    unsupported: tools.listTools().filter((t) => t.status === 'unsupported').map((t) => t.name)
  });
  return EXIT.OK;
}

function cmdIndex(opts) {
  const scope = loadScope(opts.flags.scope);
  if (!opts.flags.snapshot) throw new CliError('index requires --snapshot');
  const facts = openFacts(scope, opts.flags.snapshot);
  const res = indexLib.writeIndex(facts, scope);
  emit({
    ok: res.manifest.reconciliation.ok,
    indexDir: path.relative(TOOL_DIR, res.dir).split(path.sep).join('/'),
    snapshotId: facts.snapshotId,
    counts: res.manifest.counts,
    reconciliation: res.manifest.reconciliation,
    indexTruncated: res.manifest.indexTruncated,
    manifest: path.relative(TOOL_DIR, path.join(res.dir, 'index-manifest.json')).split(path.sep).join('/')
  });
  return res.manifest.reconciliation.ok ? EXIT.OK : EXIT.CHECK;
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

function buildAnchorDetail(anchor) {
  if (!anchor) return { label: '', location: '' };
  if (anchor.kind === 'idl') {
    return {
      label: `${anchor.interface || '?'}#${anchor.method}`,
      location: `${anchor.file}:${anchor.line}`
    };
  }
  if (anchor.kind === 'sa') return { label: `SA ${anchor.saId} (${anchor.process || 'unknown'})`, location: `${anchor.file}:${anchor.line}` };
  if (anchor.kind === 'napi') return { label: `NAPI ${anchor.module}`, location: `${anchor.file}:${anchor.line}` };
  return { label: anchor.qualified || anchor.method || anchor.entityId, location: `${anchor.file}:${anchor.line}` };
}

async function cmdRun(opts) {
  const resuming = opts.cmd === 'resume';
  if (resuming && (!/^RUN:[0-9a-f]{16}$/.test(opts.flags.run || '') ||
      !opts.flags.scope || !opts.flags.budget || !opts.flags.mode)) {
    throw new CliError('resume requires --run=RUN:id, --scope, --budget and --mode');
  }
  const previousStore = resuming ? new storeLib.RunStore(storeLib.RunStore.resolve(opts.flags.run)) : null;
  const priorEvents = resuming ? jsonl.readJsonl(previousStore.file('events.jsonl'), { strict: true }).rows : [];
  const created = resuming ? priorEvents.find((ev) => ev.kind === 'run-created') : null;
  if (resuming && (!created || opts.flags.experiment && opts.flags.experiment !== created.detail.experiment)) {
    throw new CliError('resume run origin or experiment mismatch');
  }
  const scope = loadScope(opts.flags.scope);
  const budgetPolicy = loadBudget(opts.flags.budget, opts.flags['max-model-requests']);
  const mode = opts.flags.mode || 'off';
  if (!modelLib.MODES.includes(mode)) throw new CliError(`bad --mode: ${mode}`);
  const experiment = resuming ? created.detail.experiment : (opts.flags.experiment || null);
  const verticalExperiment = ['vertical-v1', 'vertical-v2'].includes(experiment);
  if (resuming && (!verticalExperiment || !['off', 'replay'].includes(mode) ||
      opts.flags['max-tasks'] !== undefined || opts.flags.task || opts.flags.model ||
      opts.flags['max-model-requests'] !== undefined)) {
    throw new CliError('resume supports only a pinned vertical off/replay run and original budget');
  }
  if (experiment && !((experiment === 'authorization-v1' && mode === 'off') ||
      (verticalExperiment && ['off', 'live', 'replay'].includes(mode)))) {
    throw new CliError('authorization-v1 requires off; vertical experiments require off, live or replay');
  }
  const modelOverride = opts.flags.model || null;
  if (modelOverride && ((!verticalExperiment && !opts.flags.knowledge) || mode !== 'live' ||
      !/^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(modelOverride))) {
    throw new CliError('--model requires vertical live and a catalog-style model ID');
  }
  const maxTasks = resuming ? created.detail.maxTasks :
    (opts.flags['max-tasks'] !== undefined ? Number(opts.flags['max-tasks']) : 0);
  if (!Number.isInteger(maxTasks) || maxTasks < 0) throw new CliError('--max-tasks must be an integer >= 0');
  const onlyTask = opts.flags.task || null;
  if (onlyTask) ids.assertId(onlyTask, 'task');

  const facts = openFacts(scope, opts.flags.snapshot);
  const manifestId = facts.inputManifestId;
  const anchorsInfo = discovery.buildAnchors(facts, scope);
  let selectedTaskId = resuming ? previousStore.readRecords('task').rows
    .find((row) => row.payload.origin === 'entry-scan')?.recordId : onlyTask;
  let selectedEntry = anchorsInfo.entries.find((entry) => ids.taskId('task',
    { origin: 'entry-scan', anchorRefs: [entry.entityId] }) === selectedTaskId);
  let verticalKnowledge = verticalExperiment ? (selectedEntry?.method === 'UnSetPolicyAsync'
    ? knowledgeLib.loadPersistenceAuthorization(facts) : knowledgeLib.loadAuthorization(facts)) : null;
  let staticSuite = null;
  if (opts.flags['knowledge-review']) throw new CliError('run requires a published --knowledge version; direct review is not a version');
  if (opts.flags.knowledge) {
    if (!verticalExperiment) {
      if (scope.scopeId !== 'sandbox_manager-pilot') throw new CliError('static suite requires sandbox_manager-pilot scope');
      try { staticSuite = knowledgeLib.loadKnowledgeSuite(opts.flags.knowledge.split(',').map(resolvePath), facts); }
      catch (e) { throw new CliError(`knowledge suite rejected: ${e.message}`); }
    } else {
    try {
      verticalKnowledge = knowledgeLib.loadPublished(resolvePath(opts.flags.knowledge),
        opts.flags['review-public-key'] ? loadTrustedReviewKey(opts.flags['review-public-key']) : null, facts);
      if (experiment === 'vertical-v2' && !selectedTaskId) {
        const matches = anchorsInfo.entries.filter((entry) =>
          ['SetPolicyAsync', 'UnSetPolicyAsync'].includes(entry.method) &&
          verticalKnowledge.norm.appliesTo.includes(entry.method));
        if (matches.length !== 1) throw new Error('knowledge-entry-not-unique');
        selectedEntry = matches[0];
        selectedTaskId = ids.taskId('task', { origin: 'entry-scan', anchorRefs: [selectedEntry.entityId] });
      }
      const expected = selectedEntry?.method === 'UnSetPolicyAsync'
        ? knowledgeLib.loadPersistenceAuthorization(facts) : knowledgeLib.loadAuthorization(facts);
      if (verticalKnowledge.norm.normId !== expected.norm.normId) {
        throw new Error('knowledge-norm-entry-mismatch');
      }
    } catch (e) { if (e instanceof CliError) throw e; throw new CliError(`knowledge version rejected: ${e.message}`); }
    }
  }
  if (opts.flags['review-public-key'] && !opts.flags.knowledge) {
    throw new CliError('--review-public-key requires --knowledge');
  }
  if (experiment === 'vertical-v2' &&
      !['SetPolicyAsync', 'UnSetPolicyAsync'].includes(selectedEntry?.method)) {
    throw new CliError('vertical-v2 requires --task or a uniquely applicable published --knowledge');
  }
  if (verticalKnowledge?.norm?.authority === 'builder-llm-review' &&
      scope.scopeId !== 'sandbox_manager-pilot') {
    throw new CliError('static experiment requires sandbox_manager-pilot scope');
  }
  if (Boolean(opts.flags['replay-run']) !== (mode === 'replay')) {
    throw new CliError('replay requires --replay-run; other modes reject it');
  }
  let replaySource = null;
  if (mode === 'replay') {
    if (!/^RUN:[0-9a-f]{16}$/.test(opts.flags['replay-run'])) throw new CliError('replay requires a registered RUN:id');
    try {
      replaySource = modelLib.loadReplaySource(new storeLib.RunStore(storeLib.RunStore.resolve(opts.flags['replay-run'])));
    } catch (e) { throw new CliError(`replay source invalid: ${e.message}`); }
    if (replaySource.snapshotId !== facts.snapshotId || replaySource.scopeId !== scope.scopeId ||
        replaySource.knowledgeVersion !== (staticSuite || verticalKnowledge)?.knowledgeVersion) {
      throw new CliError('replay source scope, snapshot or knowledge version mismatch');
    }
    if (experiment === 'vertical-v2' &&
        [...replaySource.calls.values()].some((call) => call.finishReason !== 'stop')) {
      throw new CliError('replay source has an incomplete model response');
    }
    if (staticSuite && replaySource.architectureVersion !== '1.0.18-static-arbitration') {
      throw new CliError('static suite replay requires a matching live source');
    }
    if (experiment === 'vertical-v2' &&
        replaySource.architectureVersion !== (verticalKnowledge?.norm?.authority === 'builder-llm-review'
          ? '1.0.14-static-experiment' : '1.0.13-vertical-experiment')) {
      throw new CliError('vertical-v2 replay requires a matching live source');
    }
  }

  // 索引：缺就建（run 自足；`index` 命令只是显式入口）
  let indexArtifacts = indexLib.loadIndex(facts);
  if (!indexArtifacts) {
    const written = indexLib.writeIndex(facts, scope);
    indexArtifacts = indexLib.loadIndex(facts);
    if (!indexArtifacts) throw new CliError('index build failed', EXIT.INTERNAL);
    if (!written.manifest.reconciliation.ok) throw new CliError('index reconciliation failed', EXIT.INTERNAL);
  }

  const proposal = discovery.proposeTasks(anchorsInfo, facts, scope);

  const budget = tools.createBudget(budgetPolicy);
  if (staticSuite && mode === 'live' &&
      (!Number.isInteger(budgetPolicy.maxModelRequests) || budgetPolicy.maxModelRequests > 30 ||
       budgetPolicy.maxModelRequests < 1)) {
    throw new CliError('static suite live requires 1 <= maxModelRequests <= 30');
  }
  const capabilityProfile = ['off', 'replay'].includes(mode) ? 'readonly-local' : 'model-enabled';
  const gateway = modelLib.ModelGateway.create({ mode, budget, modelOverride, replaySource });
  if (mode === 'live' && !gateway.keyPresent()) {
    throw new CliError(`live mode requires ${gateway.config.apiKeyEnv || 'OH6_LLM_API_KEY'} (live never downgrades to mock)`, EXIT.ARG, 'missing-key');
  }

  const selectedModelId = verticalExperiment || staticSuite
    ? (replaySource ? replaySource.modelId : (modelOverride || gateway.config.model)) : null;
  const implementationFingerprint = recoveryLib.implementationFingerprint();
  const pinnedImplementation = resuming
    ? previousStore.readJson('manifest.json').implementationFingerprint : implementationFingerprint;
  if (pinnedImplementation && pinnedImplementation !== implementationFingerprint) {
    throw new CliError('resume implementation drift', EXIT.CHECK);
  }
  const { __path, ...scopeDocument } = scope;
  const resumeFingerprint = ids.sha256Hex(ids.canonicalJson({ scope: scopeDocument, budget: budgetPolicy,
    snapshotId: facts.snapshotId, inputManifestId: manifestId,
    knowledgeVersion: (staticSuite || verticalKnowledge)?.knowledgeVersion || null,
    mode, experiment, modelId: selectedModelId,
    ...(pinnedImplementation ? { implementationFingerprint: pinnedImplementation } : {}) }));
  let prepared = null;
  if (resuming) {
    if (previousStore.run.payload.mode !== mode || previousStore.run.payload.scopeId !== scope.scopeId ||
        previousStore.run.payload.snapshotId !== facts.snapshotId ||
        previousStore.run.payload.inputManifestId !== manifestId ||
        previousStore.run.payload.modelId !== selectedModelId) {
      throw new CliError('resume run identity mismatch');
    }
    try { prepared = previousStore.readCheckpoint()
      ? recoveryLib.prepareTaskBoundary(previousStore, resumeFingerprint)
      : recoveryLib.prepareFirstToolIntent(previousStore, resumeFingerprint); }
    catch (e) { throw new CliError(`resume preflight failed: ${e.message}`, EXIT.CHECK); }
    if (mode === 'replay') {
      const pinned = previousStore.readJson('manifest.json').replaySource;
      if (pinned?.runId !== replaySource.runId || (pinned.sourceFilesSha256
        ? pinned.sourceFilesSha256 !== replaySource.sourceFilesSha256
        : pinned.checksumsSha256 !== replaySource.checksumsSha256)) {
        throw new CliError('resume replay source mismatch');
      }
    }
  }
  const store = previousStore || storeLib.RunStore.create({
    scopeId: scope.scopeId,
    snapshotId: facts.snapshotId,
    inputManifestId: manifestId,
    mode,
    capabilityProfile,
    budget: budgetPolicy,
    manifestId,
      architectureVersion: staticSuite ? '1.0.18-static-arbitration' : experiment === 'vertical-v2' ? (verticalKnowledge?.norm?.authority === 'builder-llm-review'
        ? '1.0.14-static-experiment' : '1.0.13-vertical-experiment')
        : experiment === 'vertical-v1' ? '1.0.5-vertical-experiment'
      : (experiment ? '1.0.2-auth-experiment' : '1.0.16-static-scan'),
    knowledgeVersion: (staticSuite || verticalKnowledge)?.knowledgeVersion || null,
    modelId: selectedModelId
  });
  // 台账必须挂在 run 目录上；网关在 store 之前创建是为了先做 key 预检
  gateway.store = store;
  if (!resuming) store.updateManifest({ resumeFingerprint, toolTraceVersion: '1', implementationFingerprint });
  if (replaySource && !resuming) store.updateManifest({ replaySource: {
    runId: replaySource.runId, sourceFilesSha256: replaySource.sourceFilesSha256,
    kind: 'parsed-response-only' } });

  // 任务/问题落盘
  let plannedTasks = prepared ? prepared.records.task.map((row) => row.payload) : proposal.tasks;
  const budgetMaxTasks = budgetPolicy.maxTasks > 0 ? budgetPolicy.maxTasks : 0;
  if (!resuming) {
    if (selectedTaskId && (verticalExperiment || onlyTask)) {
      plannedTasks = plannedTasks.filter((t) => t.taskId === selectedTaskId);
    }
    if (budgetMaxTasks && plannedTasks.length > budgetMaxTasks) plannedTasks = plannedTasks.slice(0, budgetMaxTasks);
    if (maxTasks > 0 && plannedTasks.length > maxTasks) plannedTasks = plannedTasks.slice(0, maxTasks);
  }
  const rootTasks = plannedTasks.filter((task) => task.origin === 'entry-scan');
  if (experiment === 'vertical-v1' && (rootTasks.length !== 1 ||
      anchorsInfo.anchors.get(rootTasks[0].anchorRefs[0])?.method !== 'SetPolicyAsync')) {
    throw new CliError('vertical-v1 requires --task for the one SetPolicyAsync entry');
  }
  if (experiment === 'vertical-v2' && (rootTasks.length !== 1 ||
      rootTasks[0].anchorRefs[0] !== selectedEntry.entityId)) {
    throw new CliError('vertical-v2 task does not match the selected entry');
  }
  const taskIds = new Set(plannedTasks.map((t) => t.taskId));
  const plannedQuestions = prepared ? prepared.records.question.map((row) => row.payload) :
    proposal.questions.filter((q) => taskIds.has(q.taskId));
  if (staticSuite) {
    for (const task of plannedTasks.filter((t) => t.origin === 'entry-scan')) {
      const anchor = anchorsInfo.anchors.get(task.anchorRefs[0]);
      if (anchor?.kind !== 'idl') continue;
      for (const kind of ['static-contract', ...(staticSuite.byMethod.has(anchor.method)
        ? ['static-permission-match'] : [])]) {
        const proposition = state.TASK_QUESTION_TEXT[kind];
        plannedQuestions.push({
          questionId: ids.questionId('question', { anchorRef: anchor.entityId, kind, text: proposition }),
          taskId: task.taskId, kind, proposition, polarity: 'forall',
          status: 'unknown', basis: 'derived', assurance: 'bounded-analysis', evidenceRefs: [], missingRefs: []
        });
      }
    }
  }
  let effectQuestion = null;
  let permissionQuestion = null;
  if (verticalExperiment) {
    const task = plannedTasks[0];
    const proposition = state.TASK_QUESTION_TEXT['authorization-effect'];
    effectQuestion = {
      questionId: ids.questionId('question', { anchorRef: task.anchorRefs[0], kind: 'authorization-effect', text: proposition }),
      taskId: task.taskId, kind: 'authorization-effect', proposition, polarity: 'forall',
      status: 'unknown', basis: 'derived', assurance: 'bounded-analysis', evidenceRefs: [], missingRefs: []
    };
    if (!resuming) plannedQuestions.push(effectQuestion);
    if (experiment === 'vertical-v2') {
      const proposition = state.TASK_QUESTION_TEXT['permission-argument-match'];
      permissionQuestion = {
        questionId: ids.questionId('question', { anchorRef: task.anchorRefs[0],
          kind: 'permission-argument-match', text: proposition }),
        taskId: task.taskId, kind: 'permission-argument-match', proposition, polarity: 'forall',
        status: 'unknown', basis: 'derived', assurance: 'bounded-analysis', evidenceRefs: [], missingRefs: []
      };
      if (!resuming) plannedQuestions.push(permissionQuestion);
    }
  }
  if (prepared?.resumeKind === 'first-tool-intent') {
    const expectedTask = proposal.tasks.find((item) => item.taskId === plannedTasks[0].taskId);
    const expectedQuestions = proposal.questions.filter((item) => item.taskId === plannedTasks[0].taskId);
    expectedQuestions.push(effectQuestion);
    if (permissionQuestion) expectedQuestions.push(permissionQuestion);
    if (!expectedTask || ids.canonicalJson(expectedTask) !== ids.canonicalJson(plannedTasks[0]) ||
        ids.canonicalJson(expectedQuestions.sort((a, b) => a.questionId.localeCompare(b.questionId))) !==
        ids.canonicalJson([...plannedQuestions].sort((a, b) => a.questionId.localeCompare(b.questionId)))) {
      throw new CliError('resume first-tool plan drift', EXIT.CHECK);
    }
  }

  const taskRecords = prepared ? prepared.records.task : plannedTasks.map((p) => state.makeRecord({
    recordId: p.taskId,
    recordType: 'task',
    manifestId,
    producer: state.PRODUCERS.discovery,
    dependencyRefs: p.anchorRefs,
    payload: p
  }));
  const questionRecords = prepared ? prepared.records.question : plannedQuestions.map((p) => state.makeRecord({
    recordId: p.questionId,
    recordType: 'question',
    manifestId,
    producer: state.PRODUCERS.discovery,
    dependencyRefs: [p.taskId],
    payload: p
  }));
  if (resuming) {
    try { store.acquireLock({ afterCrash: true }); }
    catch (e) { throw new CliError(`resume writer lock: ${e.message}`, EXIT.CHECK); }
  }
  if (!resuming) {
    store.writeRecords('task', taskRecords);
    store.writeRecords('question', questionRecords);

  // 索引副本进 run 目录（自足可回查）
  fs.copyFileSync(path.join(indexArtifacts.dir, 'entities.jsonl'), store.file('entities.jsonl'));
  fs.copyFileSync(path.join(indexArtifacts.dir, 'relations.jsonl'), store.file('relations.jsonl'));
  fs.copyFileSync(path.join(indexArtifacts.dir, 'index-manifest.json'), store.file('index-manifest.json'));
  if (staticSuite) store.writeJson('static-knowledge.json', {
    knowledgeVersion: staticSuite.knowledgeVersion,
    versions: staticSuite.versions.map((k) => k.knowledgeVersion).sort()
  });

  store.appendEvent({
    kind: 'run-created',
    detail: {
      scopeId: scope.scopeId,
      snapshotId: facts.snapshotId,
      mode,
      experiment,
      plannedTasks: plannedTasks.length,
      plannedQuestions: plannedQuestions.length,
      maxTasks,
      budget: budgetPolicy
    }
  });
  if (replaySource) store.appendEvent({ kind: 'replay-source', detail: {
    runId: replaySource.runId, sourceFilesSha256: replaySource.sourceFilesSha256,
    kind: 'parsed-response-only' } });
  for (const t of plannedTasks) {
    store.appendEvent({ kind: 'task-admitted', taskId: t.taskId, to: 'queued', detail: { origin: t.origin } });
  }
  } else {
    store.appendEvent({ kind: 'run-resumed', detail: {
      fromSeq: prepared.checkpoint.throughSeq, resumeFingerprint,
      resumeKind: prepared.resumeKind || 'task-boundary' } });
    budget.toolCalls = prepared.checkpoint.budget.toolCalls;
    budget.modelRequests = prepared.checkpoint.budget.modelRequests;
    budget.inputTokens = prepared.checkpoint.budget.inputTokens;
    budget.outputTokens = prepared.checkpoint.budget.outputTokens;
    for (const row of prepared.toolLedger) budget.perTaskToolCalls.set(row.taskId,
      (budget.perTaskToolCalls.get(row.taskId) || 0) + 1);
    if (fs.existsSync(store.file('model-calls'))) {
      gateway.calls = fs.readdirSync(store.file('model-calls')).filter((name) => name.endsWith('.json'))
        .map((name) => store.readJson(`model-calls/${name}`));
    }
  }

  const entitiesById = new Map(plannedTasks.map((t) => {
    const a = anchorsInfo.anchors.get(t.anchorRefs[0]);
    return [t.anchorRefs[0], {
      entityId: t.anchorRefs[0],
      kind: a && (a.kind === 'function' || a.kind === 'on-remote-request') ? 'function' : 'entry',
      payload: { factRef: a ? a.factRef : null, method: a ? a.method : null, qualified: a ? a.qualified : null }
    }];
  }));

  const ctxBase = {
    facts,
    scope,
    knowledge: verticalKnowledge,
    knowledgeSuite: staticSuite,
    store,
    budget,
    anchors: anchorsInfo.anchors,
    entries: anchorsInfo.anchors,
    entitiesById,
    maxBytes: (scope.limits && scope.limits.maxEvidenceBytes) || tools.DEFAULT_MAX_BYTES,
    timeoutMs: (scope.limits && scope.limits.toolTimeoutMs) || tools.DEFAULT_TIMEOUT_MS
  };
  ctxBase.resolveBinding = (ref) => discovery.resolveBinding(ref, ctxBase);
  ctxBase.resolveFunctionRef = (ref) => discovery.resolveFunctionRef(ref, ctxBase);
  ctxBase.loadEvidence = (resultRef) => tools.loadEvidenceFromDir(store.dir, resultRef);

  const taskStateById = new Map(plannedTasks.map((t) => [t.taskId, { ...t }]));
  const summaryCache = new Map();
  const branchByTask = new Map(prepared?.branch ? [[prepared.branch.task.taskId, prepared.branch]] : []);
  const missingRecords = prepared ? prepared.records.missing : [];
  const assessmentRecords = prepared ? prepared.records.assessment : [];
  const contextRecords = prepared ? prepared.records.context : [];
  const detailById = new Map();
  const staticProofs = {};
  for (const [entityId, a] of anchorsInfo.anchors) detailById.set(entityId, buildAnchorDetail(a));

  let stoppedReason = null;
  const startedAt = Date.now() - (prepared ? prepared.checkpoint.activeWallMs : 0);
  budget.startedAt = startedAt;
  let pendingIntent = prepared?.pendingIntent || null;

  for (const task of plannedTasks) {
    if (task.state === 'done') continue;
    try {
      if (budget.exceededWall()) {
        stoppedReason = 'maxWallSeconds';
        break;
      }
      if (!pendingIntent || pendingIntent.taskId !== task.taskId) {
        store.appendEvent({ kind: 'task-started', taskId: task.taskId, from: 'queued', to: 'running' });
      }
      const anchor = anchorsInfo.anchors.get(task.anchorRefs[0]);
      const entryRef = task.anchorRefs[0];
      const taskCtx = { ...ctxBase, taskId: task.taskId,
        knowledge: staticSuite?.byMethod.get(anchor?.method) || verticalKnowledge,
        buildMissingRef: null };
      const results = [];

      const pushResult = async (toolName, args, questionId) => {
        const detail = { tool: toolName, questionId: questionId || null,
          argumentsSha256: ids.sha256Hex(ids.canonicalJson(args)) };
        if (pendingIntent && (pendingIntent.taskId !== task.taskId ||
            ids.canonicalJson(pendingIntent.detail) !== ids.canonicalJson(detail))) {
          throw new Error('resume-first-tool-action-drift');
        }
        const intent = pendingIntent || store.appendEvent({ kind: 'tool-intent', taskId: task.taskId, detail });
        pendingIntent = null;
        const rec = await tools.run(toolName, args, { ...taskCtx, questionId });
        store.appendRecord('tool-result', rec);
        store.appendEvent({ kind: 'tool-completed', taskId: task.taskId,
          detail: { intentId: intent.actionId, resultId: rec.recordId } });
        results.push(rec);
        // 运行级工具预算耗尽：必须停整体运行并保留状态（不是"这个任务少一条证据"）
        if (rec.payload && rec.payload.errorCode === 'budget-exhausted') {
          const err = new Error(`run tool budget exhausted before ${toolName}`);
          err.code = 'budget-exhausted';
          throw err;
        }
        return rec;
      };
      if (task.origin === 'analysis-branch') {
        const branch = branchByTask.get(task.taskId);
        if (!branch) throw new Error('analysis-branch-without-pinned-proposal');
        const q = plannedQuestions.find((item) => item.taskId === task.taskId);
        const source = branch.candidate;
        const evidence = await pushResult('getEvidence', { file: source.file, line: source.startLine,
          count: Math.min(60, source.endLine - source.startLine + 1) }, q.questionId);
        const ctx = retrieval.buildContext({ facts, scope, task: { taskId: task.taskId },
          anchor: anchorsInfo.anchors.get(task.anchorRefs[0]),
          binding: ctxBase.resolveBinding(task.anchorRefs[0]) });
        const ctxRecord = retrieval.contextRecord(ctx, manifestId);
        contextRecords.push(ctxRecord);
        store.appendRecord('context', ctxRecord);
        const miss = state.buildMissing({ questionId: q.questionId, reasonCode: 'input-parser-unproven',
          targetRefs: [branch.callsite.ref, source.factRef],
          nextActions: ['resolve-parser-call-target', 'approved-isolated-input-test'] });
        const missRec = state.makeRecord({ recordId: miss.missingId, recordType: 'missing', manifestId,
          producer: state.PRODUCERS.assessment, dependencyRefs: [q.questionId, ...miss.targetRefs], payload: miss });
        missingRecords.push(missRec); store.appendRecord('missing', missRec);
        const refs = evidence.payload.status === 'ok' ? [evidence.recordId] : [];
        q.status = 'insufficient'; q.evidenceRefs = refs; q.missingRefs = [miss.missingId];
        const qRec = questionRecords.find((row) => row.recordId === q.questionId);
        Object.assign(qRec.payload, q);
        const a = assessment.makeAssessment({ task, question: q, entryRef: task.anchorRefs[0],
          snapshotId: facts.snapshotId, decision: 'insufficient', basis: 'derived',
          assurance: 'bounded-analysis', evidenceRefs: refs, missingRefs: [miss.missingId],
          contextId: ctx.contextId, modelCallRef: null,
          rationale: 'Parser candidate retrieved by type hint; call target and adversarial input behavior remain unproven.' });
        const aRec = state.makeRecord({ recordId: a.assessmentId, recordType: 'assessment', manifestId,
          producer: state.PRODUCERS.assessment, dependencyRefs: [task.taskId, q.questionId, ...refs], payload: a });
        assessmentRecords.push(aRec); store.appendRecord('assessment', aRec);
        const taskRec = taskRecords.find((row) => row.recordId === task.taskId);
        taskRec.payload.state = 'done'; taskRec.payload.revision += 1; taskRec.payload.missingRefs = [miss.missingId];
        taskStateById.set(task.taskId, { ...task, state: 'done' });
        store.writeRecords('task', taskRecords); store.writeRecords('question', questionRecords);
        store.appendEvent({ kind: 'task-finished', taskId: task.taskId, from: 'running', to: 'done',
          detail: { view: branch.view, tools: 1, assessments: 1, decision: 'insufficient' } });
        store.writeCheckpoint({ runId: store.runId, updatedAt: state.nowIso(), mode,
          activeWallMs: Date.now() - startedAt,
          budget: { toolCalls: budget.toolCalls, modelRequests: budget.modelRequests,
            inputTokens: budget.inputTokens, outputTokens: budget.outputTokens },
          tasks: { planned: plannedTasks.length, done: [...taskStateById.values()].filter((t) => t.state === 'done').length },
          lastTaskId: task.taskId, stoppedReason: null });
        continue;
      }

      const bindingQ = plannedQuestions.find((q) => q.taskId === task.taskId && q.kind === 'binding');
      const checkQ = plannedQuestions.find((q) => q.taskId === task.taskId && q.kind === 'check-presence');
      const effectQ = plannedQuestions.find((q) => q.taskId === task.taskId && q.kind === 'authorization-effect');
      const permissionQ = plannedQuestions.find((q) => q.taskId === task.taskId && q.kind === 'permission-argument-match');
      const contractQ = plannedQuestions.find((q) => q.taskId === task.taskId && q.kind === 'static-contract');
      const suitePermissionQ = plannedQuestions.find((q) => q.taskId === task.taskId && q.kind === 'static-permission-match');

      await pushResult('inspectEntry', { entryRef }, bindingQ ? bindingQ.questionId : null);
      const binding = ctxBase.resolveBinding(entryRef);
      if (staticSuite && anchor?.kind === 'idl' && binding.binding === 'resolved') {
        await pushResult('getApplicableNorms', { entryRef }, contractQ?.questionId);
      }
      const direct = await pushResult('inspectAuthorization', { entryRef }, checkQ ? checkQ.questionId : null);
      if ((experiment === 'authorization-v1' ||
          ['1.0.15-static-scan', '1.0.16-static-scan', '1.0.17-static-scan', '1.0.18-static-arbitration'].includes(store.run.payload.architectureVersion)) &&
          task.origin === 'entry-scan' && binding.binding === 'resolved' &&
          direct.payload.status === 'ok' && direct.payload.answer.status === 'refuted') {
        await pushResult('inspectDelegation', { entryRef }, checkQ ? checkQ.questionId : null);
      }
      const relQ = plannedQuestions.find((q) => q.taskId === task.taskId && q.kind === 'dominance');
      if (['1.0.16-static-scan', '1.0.17-static-scan', '1.0.18-static-arbitration'].includes(store.run.payload.architectureVersion) &&
          task.origin === 'entry-scan' && anchor?.kind === 'idl' && binding.binding === 'resolved') {
        await pushResult('inspectOperationCandidate', { entryRef }, relQ?.questionId);
      }
      let suiteComparison = null;
      let suiteProof = null;
      if (staticSuite && contractQ) {
        if (suitePermissionQ && binding.binding === 'resolved') {
          const compared = await pushResult('inspectPermissionArgument', { entryRef }, suitePermissionQ.questionId);
          suiteComparison = compared.payload.observations;
        }
        suiteProof = staticProofLib.analyze(facts, anchor, binding, taskCtx.knowledge,
          suiteComparison, { includeNewFamilies: true,
            includeCandidateContext: store.run.payload.architectureVersion === '1.0.18-static-arbitration' });
        staticProofs[task.taskId] = suiteProof;
        if (suiteProof.operationRef) task.operationRef = suiteProof.operationRef;
      }
      let vertical = null;
      if (effectQ && verticalExperiment) {
        vertical = await verticalLib.analyze({ facts, anchor, binding, task, store, gateway,
          knowledge: verticalKnowledge, summaryCache,
          enableFollowup: experiment === 'vertical-v2', twoRoundFollowup: experiment === 'vertical-v2',
          followupQuestionId: permissionQ?.questionId,
          pushResult: (name, args, questionId) => pushResult(name, args, questionId || effectQ.questionId) });
        if (verticalKnowledge?.norm?.authority === 'builder-llm-review') {
          vertical.staticProof = staticProofLib.analyze(facts, anchor, binding,
            verticalKnowledge, vertical.permissionArgument);
        }
        store.writeJson('vertical-analysis.json', vertical);
        const branch = branchLib.proposeInputBoundary(vertical, task, facts);
        if (branch && (!maxTasks || plannedTasks.length < maxTasks) &&
            (!budgetMaxTasks || plannedTasks.length < budgetMaxTasks)) {
          plannedTasks.push(branch.task); plannedQuestions.push(branch.question);
          branchByTask.set(branch.task.taskId, branch);
          taskStateById.set(branch.task.taskId, branch.task);
          taskRecords.push(state.makeRecord({ recordId: branch.task.taskId, recordType: 'task',
            manifestId, producer: state.PRODUCERS.discovery, dependencyRefs: branch.task.anchorRefs, payload: branch.task }));
          questionRecords.push(state.makeRecord({ recordId: branch.question.questionId, recordType: 'question',
            manifestId, producer: state.PRODUCERS.discovery, dependencyRefs: [branch.task.taskId], payload: branch.question }));
          store.writeRecords('task', taskRecords); store.writeRecords('question', questionRecords);
          store.writeJson('vertical-branch.json', branch);
          store.appendEvent({ kind: 'view-changed', taskId: task.taskId,
            detail: { view: branch.view, childTaskId: branch.task.taskId, callsite: branch.callsite.ref } });
          store.appendEvent({ kind: 'task-admitted', taskId: branch.task.taskId, to: 'queued',
            detail: { origin: branch.task.origin, parentTaskId: task.taskId, view: branch.view } });
        } else if (branch) {
          store.appendEvent({ kind: 'branch-rejected', taskId: task.taskId,
            detail: { reason: 'maxTasks', view: branch.view } });
        }
      }
      if (binding.binding === 'resolved' && binding.bound) {
        await pushResult('inspectRelation', { ref: entryRef, relation: 'calls' }, relQ ? relQ.questionId : null);
        const fn = binding.bound;
        const file = fn.sourceRange && fn.sourceRange.file;
        if (file) {
          await pushResult('getEvidence', { file, line: fn.startLine, count: 12 }, relQ ? relQ.questionId : null);
        }
      }

      const context = retrieval.buildContext({
        facts,
        scope,
        task: { taskId: task.taskId },
        anchor: anchor || { entityId: entryRef, kind: 'unknown' },
        binding
      });
      const ctxRecord = retrieval.contextRecord(context, manifestId);
      contextRecords.push(ctxRecord);
      store.appendRecord('context', ctxRecord);

      const taskQuestions = plannedQuestions.filter((q) => q.taskId === task.taskId);
      let liveCheck = null;
      let liveReview = null;
      if (store.run.payload.architectureVersion === '1.0.18-static-arbitration' &&
          ['live', 'mock', 'replay'].includes(mode) && contractQ && !verticalExperiment) {
        const allowed = new Set([...results.map((r) => r.recordId), ...contextRecords.map((c) => c.recordId)]);
        liveReview = await assessment.adjudicateLiveCheck({ gateway, task, purpose: 'static-contract-review',
          question: contractQ, context, allowedRefs: allowed,
          contextText: retrieval.renderForModel(context) + '\n' + JSON.stringify({
            norm: taskCtx.knowledge?.norm || null, staticProof: suiteProof,
            permissionComparison: suiteComparison
          }), maxTokens: 1200 });
      }
      const off = assessment.adjudicateOff({
        task,
        questions: taskQuestions,
        results,
        binding: { ...binding, entry: anchor },
        snapshotId: facts.snapshotId,
        contextId: context.contextId,
        experiment: experiment || (['1.0.15-static-scan', '1.0.16-static-scan']
          .includes(store.run.payload.architectureVersion) ? 'static-scan' : null)
      });
      if (contractQ) {
        const arbitration = store.run.payload.architectureVersion === '1.0.18-static-arbitration'
          ? assessment.arbitrateStaticContract(suiteProof, liveReview) : null;
        const decision = arbitration?.decision || (suiteProof?.status === 'finding' ? 'refuted' :
          suiteProof?.status === 'excluded' ? 'supported' : 'insufficient');
        const reasonCode = arbitration?.reasonCode || (suiteProof?.reason === 'guard-shape-unsupported' ? 'guard-shape-unsupported' :
          !taskCtx.knowledge ? 'norm-not-applicable' :
          suiteProof?.reason === 'permission-argument-unresolved' || suiteProof?.reason === 'permission-check-ambiguous'
            ? 'permission-argument-unresolved' : 'operation-target-unproven');
        const miss = ['insufficient', 'conflict'].includes(decision) ? state.buildMissing({
          questionId: contractQ.questionId, reasonCode,
          targetRefs: [entryRef, ...(arbitration?.reasonCode && suiteProof?.operationRef ? [suiteProof.operationRef] : [])],
          nextActions: reasonCode === 'norm-not-applicable' ? [] : ['inspect-source-and-contract']
        }) : null;
        if (miss) off.extraMissing.push(miss);
        const refs = results.filter((row) => ['getApplicableNorms', 'inspectOperationCandidate',
          'inspectPermissionArgument'].includes(row.payload.tool)).map((row) => row.recordId);
        off.updates.push({ questionId: contractQ.questionId, status: decision,
          basis: arbitration?.modelCallRef ? 'mixed' : 'derived',
          assurance: 'bounded-analysis', evidenceRefs: refs, missingRefs: miss ? [miss.missingId] : [] });
        off.assessments.push(assessment.makeAssessment({
          task, question: contractQ, entryRef, snapshotId: facts.snapshotId, decision,
          basis: arbitration?.modelCallRef ? 'mixed' : 'derived', assurance: 'bounded-analysis', evidenceRefs: refs,
          counterEvidenceRefs: decision === 'refuted' ? refs : [],
          missingRefs: miss ? [miss.missingId] : [], contextId: context.contextId,
          modelCallRef: arbitration?.modelCallRef || null,
          rationale: arbitration?.rationale || suiteProof?.family || suiteProof?.reason || 'No applicable published norm.'
        }));
      }
      if (suitePermissionQ) {
        const decision = ['supported', 'refuted'].includes(suiteComparison?.status)
          ? suiteComparison.status : 'insufficient';
        const tool = results.find((row) => row.payload.tool === 'inspectPermissionArgument');
        const refs = tool ? [tool.recordId] : [];
        const miss = decision === 'insufficient' ? state.buildMissing({
          questionId: suitePermissionQ.questionId, reasonCode: 'permission-argument-unresolved',
          targetRefs: [entryRef], nextActions: ['inspect-permission-argument']
        }) : null;
        if (miss) off.extraMissing.push(miss);
        off.updates.push({ questionId: suitePermissionQ.questionId, status: decision, basis: 'derived',
          assurance: 'bounded-analysis', evidenceRefs: refs, missingRefs: miss ? [miss.missingId] : [] });
        off.assessments.push(assessment.makeAssessment({
          task, question: suitePermissionQ, entryRef, snapshotId: facts.snapshotId, decision,
          basis: 'derived', assurance: 'bounded-analysis', evidenceRefs: refs,
          counterEvidenceRefs: decision === 'refuted' ? refs : [],
          missingRefs: miss ? [miss.missingId] : [], contextId: context.contextId,
          rationale: suiteComparison?.reason || (suiteComparison
            ? `${suiteComparison.observedPermission} vs ${suiteComparison.expectedPermission}` : 'comparison unavailable')
        }));
      }
      if (effectQ) {
        const reasons = [];
        if (vertical.applicability?.status !== 'applicable') reasons.push('norm-applicability-unapproved');
        if (!vertical.completeness?.operationTargetResolved) reasons.push('operation-target-unproven');
        if (!vertical.checkRefs?.length) reasons.push('delegation-incomplete');
        reasons.push('verification-disabled');
        const gaps = reasons.map((reasonCode) => state.buildMissing({
          questionId: effectQ.questionId, reasonCode, targetRefs: [entryRef],
          nextActions: reasonCode === 'norm-applicability-unapproved' ? ['review-async-applicability']
            : reasonCode === 'operation-target-unproven' ? ['resolve-operation-callsite']
              : reasonCode === 'verification-disabled' ? [] : ['inspect-delegation'],
          terminalReason: reasonCode === 'verification-disabled' ? 'no-approved-isolated-runner' : null
        }));
        const refs = results.filter((r) => r.payload.questionId === effectQ.questionId).map((r) => r.recordId);
        off.extraMissing.push(...gaps);
        off.updates.push({ questionId: effectQ.questionId, status: 'insufficient', basis: 'derived',
          assurance: 'bounded-analysis', evidenceRefs: refs, missingRefs: gaps.map((g) => g.missingId) });
        off.assessments.push(assessment.makeAssessment({
          task, question: effectQ, entryRef, snapshotId: facts.snapshotId, decision: 'insufficient',
          basis: vertical.modelCallRef ? 'mixed' : 'derived', assurance: 'bounded-analysis',
          evidenceRefs: refs, missingRefs: gaps.map((g) => g.missingId),
          assumptions: ['Local ordering and a proposed norm do not establish end-to-end authorization.'],
          contextId: vertical.contextId || context.contextId, modelCallRef: vertical.modelCallRef || null,
          rationale: vertical.reason || 'The authorization effect is not established.'
        }));
      }
      if (permissionQ) {
        const compared = vertical.permissionArgument || {};
        const decision = ['supported', 'refuted'].includes(compared.status) ? compared.status : 'insufficient';
        const refs = results.some((row) => row.recordId === compared.toolResultId) ? [compared.toolResultId] : [];
        const miss = decision === 'insufficient' ? state.buildMissing({
          questionId: permissionQ.questionId, reasonCode: 'permission-argument-unresolved',
          targetRefs: [entryRef], nextActions: ['inspect-permission-argument']
        }) : null;
        if (miss) off.extraMissing.push(miss);
        off.updates.push({ questionId: permissionQ.questionId, status: decision, basis: 'derived',
          assurance: 'bounded-analysis', evidenceRefs: refs, missingRefs: miss ? [miss.missingId] : [] });
        off.assessments.push(assessment.makeAssessment({
          task, question: permissionQ, entryRef, snapshotId: facts.snapshotId, decision,
          basis: 'derived', assurance: 'bounded-analysis', evidenceRefs: refs,
          counterEvidenceRefs: decision === 'refuted' ? refs : [],
          missingRefs: miss ? [miss.missingId] : [],
          assumptions: ['Literal document-to-call comparison only; not authorization effectiveness or an approved norm.'],
          contextId: vertical.contextId || context.contextId, modelCallRef: null,
          rationale: decision === 'insufficient' ? (compared.reason || 'permission-argument-unresolved')
            : 'CheckPermission argument resolves to ' + compared.observedPermission +
              '; sourced document names ' + compared.expectedPermission + '.'
        }));
      }

      if (store.run.payload.architectureVersion !== '1.0.18-static-arbitration' &&
          ['live', 'mock', 'replay'].includes(mode) && checkQ && !verticalExperiment) {
        const allowed = new Set([...results.map((r) => r.recordId), ...contextRecords.map((c) => c.recordId)]);
        liveCheck = await assessment.adjudicateLiveCheck({
          gateway,
          task,
          question: taskQuestions.find((q) => q.kind === 'check-presence'),
          context,
          allowedRefs: allowed,
          contextText: retrieval.renderForModel(context),
          maxTokens: 1200
        });
      }

      // 记录 missing（去重）
      const seenMissing = new Set(missingRecords.map((m) => m.payload.missingId));
      for (const miss of [...off.extraMissing, ...(liveCheck ? liveCheck.extraMissing : []),
        ...(liveReview ? liveReview.extraMissing : [])]) {
        if (seenMissing.has(miss.missingId)) continue;
        seenMissing.add(miss.missingId);
        const rec = state.makeRecord({
          recordId: miss.missingId,
          recordType: 'missing',
          manifestId,
          producer: state.PRODUCERS.assessment,
          dependencyRefs: [miss.questionId, ...miss.targetRefs],
          payload: miss
        });
        missingRecords.push(rec);
        store.appendRecord('missing', rec);
      }

      // 记录 assessment（live 覆盖 check-presence 的那条）
      let offAssessments = off.assessments;
      if (liveCheck && checkQ) {
        offAssessments = offAssessments.map((a) => {
          if (a.questionId !== checkQ.questionId) return a;
          return assessment.makeAssessment({
            task,
            question: taskQuestions.find((q) => q.kind === 'check-presence'),
            entryRef,
            snapshotId: facts.snapshotId,
            decision: liveCheck.decision,
            basis: liveCheck.basis,
            assurance: liveCheck.assurance,
            evidenceRefs: liveCheck.evidenceRefs,
            counterEvidenceRefs: [],
            assumptions: [`程序证据门：${liveCheck.gate}`],
            missingRefs: liveCheck.missingRefs,
            contextId: context.contextId,
            modelCallRef: liveCheck.modelCallRef,
            rationale: liveCheck.rationale
          });
        });
      }
      for (const a of offAssessments) {
        const rec = state.makeRecord({
          recordId: a.assessmentId,
          recordType: 'assessment',
          manifestId,
          producer: state.PRODUCERS.assessment,
          dependencyRefs: [a.taskId, a.questionId, ...a.evidenceRefs],
          payload: a
        });
        assessmentRecords.push(rec);
        store.appendRecord('assessment', rec);
      }

      // 更新 question 与 task
      for (const upd of off.updates) {
        const qr = questionRecords.find((q) => q.recordId === upd.questionId);
        if (!qr) continue;
        qr.payload.status = upd.status;
        qr.payload.basis = upd.basis;
        qr.payload.assurance = upd.assurance;
        qr.payload.evidenceRefs = ids.uniqueSorted([...qr.payload.evidenceRefs, ...upd.evidenceRefs]);
        qr.payload.missingRefs = ids.uniqueSorted([...qr.payload.missingRefs, ...upd.missingRefs]);
      }
      if (liveCheck && checkQ) {
        const qr = questionRecords.find((q) => q.recordId === checkQ.questionId);
        if (qr) {
          qr.payload.status = liveCheck.decision;
          qr.payload.basis = liveCheck.basis;
          qr.payload.assurance = liveCheck.assurance;
          qr.payload.evidenceRefs = ids.uniqueSorted([...qr.payload.evidenceRefs, ...liveCheck.evidenceRefs]);
          qr.payload.missingRefs = ids.uniqueSorted([...qr.payload.missingRefs, ...liveCheck.missingRefs]);
        }
      }
      const taskRec = taskRecords.find((t) => t.recordId === task.taskId);
      if (taskRec) {
        taskRec.payload.questionRefs = taskQuestions.map((q) => q.questionId).sort();
        taskRec.payload.state = 'done';
        taskRec.payload.revision += 1;
        const tMiss = ids.uniqueSorted(taskQuestions.flatMap((q) => {
          const qr = questionRecords.find((x) => x.recordId === q.questionId);
          return qr ? qr.payload.missingRefs : [];
        }));
        taskRec.payload.missingRefs = tMiss;
      }
      taskStateById.set(task.taskId, { ...taskStateById.get(task.taskId), state: 'done' });

      store.writeRecords('task', taskRecords);
      store.writeRecords('question', questionRecords);
      store.appendEvent({
        kind: 'task-finished',
        taskId: task.taskId,
        from: 'running',
        to: 'done',
        detail: { tools: results.length, assessments: offAssessments.length }
      });
      store.writeCheckpoint({
        runId: store.runId,
        updatedAt: state.nowIso(),
        mode,
        activeWallMs: Date.now() - startedAt,
        budget: {
          toolCalls: budget.toolCalls,
          modelRequests: budget.modelRequests,
          inputTokens: budget.inputTokens,
          outputTokens: budget.outputTokens
        },
        tasks: {
          planned: plannedTasks.length,
          done: [...taskStateById.values()].filter((t) => t.state === 'done').length
        },
        lastTaskId: task.taskId,
        stoppedReason: null
      });
    } catch (e) {
      if (e.code === 'budget-exhausted') {
        stoppedReason = 'budget-exhausted';
        const taskRec = taskRecords.find((t) => t.recordId === task.taskId);
        if (taskRec) {
          taskRec.payload.state = 'blocked';
          taskRec.payload.revision += 1;
          store.writeRecords('task', taskRecords);
        }
        store.appendEvent({ kind: 'budget-stop', taskId: task.taskId, from: 'running', to: 'blocked', detail: { reason: e.message } });
        store.writeCheckpoint({
          runId: store.runId,
          updatedAt: state.nowIso(),
          mode,
          activeWallMs: Date.now() - startedAt,
          budget: {
            toolCalls: budget.toolCalls,
            modelRequests: budget.modelRequests,
            inputTokens: budget.inputTokens,
            outputTokens: budget.outputTokens
          },
          tasks: {
            planned: plannedTasks.length,
            done: [...taskStateById.values()].filter((t) => t.state === 'done').length
          },
          lastTaskId: task.taskId,
          stoppedReason
        });
        break;
      }
      store.appendEvent({ kind: 'task-finished', taskId: task.taskId, from: 'running', to: 'failed', detail: { error: String(e.message || e) } });
      const taskRec = taskRecords.find((t) => t.recordId === task.taskId);
      if (taskRec) taskRec.payload.state = 'failed';
      store.writeRecords('task', taskRecords);
      throw e;
    }
  }

  store.writeCheckpoint({
    runId: store.runId,
    updatedAt: state.nowIso(),
    mode,
    activeWallMs: Date.now() - startedAt,
    budget: {
      toolCalls: budget.toolCalls,
      modelRequests: budget.modelRequests,
      inputTokens: budget.inputTokens,
      outputTokens: budget.outputTokens
    },
    tasks: {
      planned: plannedTasks.length,
      done: [...taskStateById.values()].filter((t) => t.state === 'done').length
    },
    lastTaskId: null,
    stoppedReason
  });

  if (staticSuite) store.writeJson('static-proofs.json', staticProofs);

  const reportRes = reportLib.writeReport(store, {
    scopeId: scope.scopeId,
    mode,
    experiment,
    inputManifestId: manifestId,
    detailById
  });

  store.appendEvent({
    kind: 'report-written',
    detail: { counts: reportRes.summary.counts, semanticHash: reportRes.summary.semanticHash }
  });
  store.appendEvent({
    kind: 'run-finished',
    detail: {
      tasks: plannedTasks.length,
      toolCalls: budget.toolCalls,
      modelRequests: budget.modelRequests,
      modelCalls: gateway.calls.length,
      wallMs: Date.now() - startedAt,
      stoppedReason,
      mode
    }
  });
  store.updateManifest({
    artifactRefs: Object.keys(store.computeChecksums()),
    counts: reportRes.summary.counts,
    semanticHash: reportRes.summary.semanticHash,
    plannedTasks: plannedTasks.length,
    questions: plannedQuestions.length,
    toolCalls: budget.toolCalls,
    modelRequests: budget.modelRequests,
    modelCalls: gateway.calls.length,
    stoppedReason
  });
  store.writeChecksums({ counts: reportRes.summary.counts, semanticHash: reportRes.summary.semanticHash });
  store.releaseLock();

  emit({
    ok: stoppedReason === null,
    runId: store.runId,
    runDir: path.relative(TOOL_DIR, store.dir).split(path.sep).join('/'),
    snapshotId: facts.snapshotId,
    scopeId: scope.scopeId,
    mode,
    planned: {
      entries: anchorsInfo.stats.entries,
      entryKinds: anchorsInfo.stats.entryKinds,
      coverageAnchors: anchorsInfo.stats.coverageAnchors,
      tasks: plannedTasks.length,
      questions: plannedQuestions.length,
      rejected: proposal.rejected.length,
      duplicates: proposal.duplicates
    },
    executed: {
      tasks: [...taskStateById.values()].filter((t) => t.state === 'done').length,
      toolCalls: budget.toolCalls,
      modelRequests: budget.modelRequests,
      modelCalls: gateway.calls.length,
      wallMs: Date.now() - startedAt
    },
    counts: reportRes.summary.counts,
    missingByReason: reportRes.summary.missingByReason,
    semanticHash: reportRes.summary.semanticHash,
    stoppedReason
  });

  if (stoppedReason) return EXIT.BUDGET;
  return EXIT.OK;
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

const SCHEMA_FOR = Object.freeze({
  run: 'run',
  task: 'task',
  question: 'question',
  missing: 'missing',
  'tool-result': 'toolresult',
  assessment: 'assessment',
  'report-model': 'report-model',
  context: 'context',
  event: 'event'
});

function loadSchemas() {
  const cache = {};
  for (const [recordType, name] of Object.entries(SCHEMA_FOR)) {
    cache[recordType] = schemaLib.loadSchema(SCHEMA_DIR, name);
  }
  return cache;
}

function cmdCheck(opts) {
  if (!opts.flags.run) throw new CliError('check requires --run');
  const dir = storeLib.RunStore.resolve(opts.flags.run);
  const schemas = loadSchemas();
  const errors = [];
  const warnings = [];
  const add = (code, detail, extra) => errors.push({ code, detail, ...(extra || {}) });

  // run.json
  let runRecord;
  let store = null;
  let evRes = null;
  let tasks = [];
  let questions = [];
  let missings = [];
  let toolResults = [];
  let assessments = [];
  let contexts = [];
  let reportRows = [];
  let snapshotId = null;

  try {
    runRecord = JSON.parse(fs.readFileSync(path.join(dir, 'run.json'), 'utf8'));
  } catch (e) {
    add('run-unparsable', e.message);
    const summary = {
      ok: false,
      runId: null,
      runDir: path.relative(TOOL_DIR, dir).split(path.sep).join('/'),
      snapshotId: null,
      counts: { events: 0, tasks: 0, questions: 0, missing: 0, toolResults: 0, assessments: 0, contexts: 0, reportRows: 0 },
      errors,
      warnings
    };
    emit(summary);
    return EXIT.CHECK;
  }
  store = new storeLib.RunStore(dir);
  const runCheck = schemaLib.validate(schemas.run, runRecord);
  if (!runCheck.valid) add('schema-invalid', 'run.json', { errors: runCheck.errors });
  snapshotId = runRecord.payload ? runRecord.payload.snapshotId : null;

  // events
  evRes = jsonl.readJsonl(path.join(dir, 'events.jsonl'));
  if (evRes.malformed.length) {
    add('ledger-corrupt', `events.jsonl has ${evRes.malformed.length} malformed line(s)`, { malformed: evRes.malformed.slice(0, 3) });
  }
  if (evRes.tailPartial) add('tail-partial', 'events.jsonl 末行不完整');
  const seqs = evRes.rows.map((r) => r.seq);
  let last = 0;
  for (const s of seqs) {
    if (typeof s !== 'number' || s !== last + 1) { add('seq-gap', `expected ${last + 1}, got ${s}`); break; }
    last = s;
  }
  for (const ev of evRes.rows) {
    const v = schemaLib.validate(schemas.event, ev);
    if (!v.valid) add('schema-invalid', `event seq=${ev.seq}`, { errors: v.errors });
    if (ev.runId !== store.runId) add('run-id-mismatch', `event seq=${ev.seq} runId=${ev.runId}`);
  }

  const readRec = (name) => {
    const res = jsonl.readJsonl(path.join(dir, name));
    if (res.malformed.length) add('ledger-corrupt', `${name} has ${res.malformed.length} malformed line(s)`);
    if (res.tailPartial && res.lines > 0) add('tail-partial', `${name} 末行不完整`);
    return res.rows;
  };
  const tasksRead = readRec('tasks.jsonl');
  const questionsRead = readRec('questions.jsonl');
  const missingsRead = readRec('missing.jsonl');
  const toolResultsRead = readRec('tool-results.jsonl');
  const assessmentsRead = readRec('assessments.jsonl');
  const contextsRead = readRec('contexts.jsonl');
  const reportRowsRead = readRec('report-model.jsonl');
  tasks = tasksRead; questions = questionsRead; missings = missingsRead;
  toolResults = toolResultsRead; assessments = assessmentsRead; contexts = contextsRead;
  reportRows = reportRowsRead;

  const validateAll = (rows, recordType, label) => {
    for (const row of rows) {
      const v = schemaLib.validate(schemas[recordType], row);
      if (!v.valid) add('schema-invalid', `${label} ${row.recordId || '?'}`, { errors: v.errors });
      if (row.recordId && row.payload) {
        const inline = row.payload[Object.keys(row.payload).find((k) => k.endsWith('Id') && k !== 'runId') || ''];
        if (inline && inline !== row.recordId) add('record-id-mismatch', `${label} ${row.recordId} != ${inline}`);
      }
    }
  };
  validateAll(tasks, 'task', 'task');
  validateAll(questions, 'question', 'question');
  validateAll(missings, 'missing', 'missing');
  validateAll(toolResults, 'tool-result', 'tool-result');
  validateAll(assessments, 'assessment', 'assessment');
  validateAll(contexts, 'context', 'context');
  validateAll(reportRows, 'report-model', 'report-model');

  const taskIds = new Set(tasks.map((t) => t.recordId));
  const questionIds = new Set(questions.map((q) => q.recordId));
  const missingIds = new Set(missings.map((m) => m.recordId));
  const evidenceFiles = new Set(fs.existsSync(path.join(dir, 'evidence')) ? fs.readdirSync(path.join(dir, 'evidence')) : []);

  for (const q of questions) {
    if (!taskIds.has(q.payload.taskId)) add('dangling-ref', `question ${q.recordId} -> task ${q.payload.taskId}`);
    for (const m of q.payload.missingRefs) if (!missingIds.has(m)) add('dangling-ref', `question ${q.recordId} -> missing ${m}`);
  }
  for (const t of tasks) {
    for (const q of t.payload.questionRefs) if (!questionIds.has(q)) add('dangling-ref', `task ${t.recordId} -> question ${q}`);
    for (const m of t.payload.missingRefs) if (!missingIds.has(m)) add('dangling-ref', `task ${t.recordId} -> missing ${m}`);
  }
  for (const m of missings) {
    if (!questionIds.has(m.payload.questionId)) add('dangling-ref', `missing ${m.recordId} -> question ${m.payload.questionId}`);
  }
  const toolIds = new Set(toolResults.map((r) => r.recordId));
  for (const a of assessments) {
    if (!questionIds.has(a.payload.questionId)) add('dangling-ref', `assessment ${a.recordId} -> question ${a.payload.questionId}`);
    for (const e of a.payload.evidenceRefs) if (!toolIds.has(e)) add('dangling-ref', `assessment ${a.recordId} -> evidence ${e}`);
    for (const m of a.payload.missingRefs) if (!missingIds.has(m)) add('dangling-ref', `assessment ${a.recordId} -> missing ${m}`);
    if (a.payload.scope.snapshotId !== snapshotId) add('snapshot-mismatch', `assessment ${a.recordId}`);
    if (!assessment.DECISIONS.includes(a.payload.decision)) add('bad-enum', `assessment ${a.recordId} decision=${a.payload.decision}`);
    // 禁用词按**词元**匹配：'T1' 不能命中时间戳里的 'T17'
    const blob = JSON.stringify(a.payload);
    if (/PROVEN[-_]VULN/i.test(blob)) add('forbidden-token', `assessment ${a.recordId} contains PROVEN-VULN`);
    if (/(?:^|[^A-Za-z0-9_-])T1(?:[^A-Za-z0-9_-]|$)/.test(blob)) add('forbidden-token', `assessment ${a.recordId} contains T1`);
  }
  for (const r of reportRows) {
    if (!taskIds.has(r.payload.taskId)) add('dangling-ref', `report ${r.recordId} -> task ${r.payload.taskId}`);
    if (r.payload.snapshotId !== snapshotId) add('snapshot-mismatch', `report ${r.recordId}`);
    if (!['candidate', 'observation', 'excluded', 'finding'].includes(r.payload.reportability)) add('bad-enum', `report ${r.recordId}`);
    if (r.payload.reportability === 'finding' &&
        (!['1.0.14-static-experiment', '1.0.17-static-scan', '1.0.18-static-arbitration'].includes(runRecord.payload.architectureVersion) ||
          r.payload.verificationStatus !== 'static-only')) add('finding-not-allowed', `report ${r.recordId}`);
    for (const e of r.payload.evidenceRefs) if (!toolIds.has(e)) add('dangling-ref', `report ${r.recordId} -> evidence ${e}`);
  }
  for (const tr of toolResults) {
    const file = `${String(tr.recordId).replace(':', '-')}.json`;
    if (!evidenceFiles.has(file)) add('evidence-archived-missing', `${tr.recordId} (${file})`);
    if (runRecord.payload && tr.payload.inputManifestId !== runRecord.payload.inputManifestId) add('manifest-mismatch', `tool-result ${tr.recordId}`);
  }

  // 记录状态必须与事件归约一致（截断/中止时不得留下"queue 里写着 done"）
  const reduced = state.reduceTaskStates(evRes.rows);
  try {
    const trace = recoveryLib.reconcileToolEvents(evRes.rows);
    if (trace.pendingTools.length) add('tool-intent-unsettled', trace.pendingTools.map((item) => item.actionId).join(','));
    for (const item of trace.completedTools) {
      if (!toolIds.has(item.resultId)) add('tool-completion-missing-result', item.resultId);
    }
    if (store.readJson('manifest.json').toolTraceVersion === '1' &&
        ids.canonicalJson(trace.completedTools.map((item) => item.resultId).sort()) !==
        ids.canonicalJson(toolResults.map((item) => item.recordId).sort())) {
      add('tool-trace-result-mismatch', 'completed tool events differ from result records');
    }
  } catch (e) { add('tool-event-invalid', e.message); }
  for (const t of tasks) {
    const r = reduced.get(t.recordId);
    if (r && r.state && t.payload.state !== r.state) {
      add('task-state-mismatch', `${t.recordId}: record=${t.payload.state} events=${r.state}`);
    }
  }
  for (const c of contexts) {
    if (c.payload.taskId && !taskIds.has(c.payload.taskId)) add('dangling-ref', `context ${c.recordId} -> task ${c.payload.taskId}`);
  }

  // report-model 一致性（语义哈希可复算）
  let staticProofs = null;
  if (['1.0.17-static-scan', '1.0.18-static-arbitration'].includes(runRecord.payload.architectureVersion)) {
    try {
      const pin = JSON.parse(fs.readFileSync(path.join(dir, 'static-knowledge.json'), 'utf8'));
      staticProofs = JSON.parse(fs.readFileSync(path.join(dir, 'static-proofs.json'), 'utf8'));
      const scope = loadScope(DEFAULT_SCOPE);
      const facts = openFacts(scope, snapshotId);
      const suite = knowledgeLib.loadKnowledgeSuite(pin.versions.map((v) =>
        path.join(knowledgeLib.PUBLISHED_DIR, v.slice(7), 'knowledge.json')), facts);
      if (pin.knowledgeVersion !== suite.knowledgeVersion ||
          pin.knowledgeVersion !== runRecord.payload.knowledgeVersion) throw new Error('suite version drift');
      const anchors = discovery.buildAnchors(facts, scope);
      for (const task of tasks.filter((row) => row.payload.origin === 'entry-scan')) {
        const entry = anchors.anchors.get(task.payload.anchorRefs[0]);
        if (entry?.kind !== 'idl') continue;
        const binding = discovery.resolveBinding(entry.entityId, { facts, scope, anchors: anchors.anchors });
        const knowledge = suite.byMethod.get(entry.method);
        const comparison = knowledge && permissionArgumentLib.compare(facts, entry, binding, knowledge);
        const proof = staticProofLib.analyze(facts, entry, binding, knowledge, comparison,
          { includeNewFamilies: true,
            includeCandidateContext: runRecord.payload.architectureVersion === '1.0.18-static-arbitration' });
        if (ids.canonicalJson(proof) !== ids.canonicalJson(staticProofs[task.recordId])) {
          add('static-proof-drift', task.recordId);
        }
        const contract = questions.find((q) => q.payload.taskId === task.recordId && q.payload.kind === 'static-contract');
        const contractAssessment = assessments.find((a) => a.payload.questionId === contract?.recordId)?.payload;
        let modelReview = null;
        if (runRecord.payload.architectureVersion === '1.0.18-static-arbitration') {
          const callDir = path.join(dir, 'model-calls');
          const calls = fs.existsSync(callDir) ? fs.readdirSync(callDir) : [];
          const review = calls.map((file) => JSON.parse(fs.readFileSync(path.join(dir, 'model-calls', file), 'utf8')))
            .find((call) => call.taskId === task.recordId && call.purpose === 'static-contract-review');
          const allowed = new Set([...evRes.rows.filter((event) => event.kind === 'tool-completed' &&
            event.taskId === task.recordId).map((event) => event.detail.resultId),
          ...contexts.filter((row) => row.payload.taskId === task.recordId).map((row) => row.recordId)]);
          if (review?.status === 'ok' && ['refuted', 'conflict'].includes(review.parsed?.decision) &&
              Array.isArray(review.parsed.evidenceRefs) && review.parsed.evidenceRefs.every((ref) => allowed.has(ref)) &&
              !assessment.FORBIDDEN_TOKENS.some((token) => JSON.stringify(review.parsed).includes(token))) {
            modelReview = { decision: review.parsed.decision, gate: 'accepted',
              rationale: String(review.parsed.rationale || '').slice(0, 400), modelCallRef: review.callId };
          }
        }
        const arbitration = runRecord.payload.architectureVersion === '1.0.18-static-arbitration'
          ? assessment.arbitrateStaticContract(proof, modelReview) : null;
        const verdict = arbitration?.decision || (proof.status === 'finding' ? 'refuted' :
          proof.status === 'excluded' ? 'supported' : 'insufficient');
        const contractMissing = contractAssessment?.missingRefs.map((id) =>
          missings.find((row) => row.recordId === id)?.payload.reasonCode);
        if (!contract || contract.payload.status !== verdict ||
            contractAssessment?.decision !== verdict ||
            (proof.operationRef && task.payload.operationRef !== proof.operationRef) ||
            (arbitration?.reasonCode && (!contractMissing?.includes(arbitration.reasonCode) ||
              contractAssessment.modelCallRef !== arbitration.modelCallRef))) {
          add('static-assessment-drift', task.recordId);
        }
        const tool = toolResults.find((row) => row.payload.questionId ===
          questions.find((q) => q.payload.taskId === task.recordId &&
            q.payload.kind === 'static-permission-match')?.recordId &&
          row.payload.tool === 'inspectPermissionArgument');
        if (knowledge && binding.binding === 'resolved' &&
            ids.canonicalJson(tool?.payload.observations) !== ids.canonicalJson(comparison)) {
          add('static-permission-drift', task.recordId);
        }
      }
    } catch (e) { add('static-suite-drift', e.message); }
  }
  const rebuilt = reportLib.buildReportModel({
    tasks,
    questions,
    assessments,
    missing: missings,
    manifestId: runRecord.manifestId,
    snapshotId,
    architectureVersion: runRecord.payload.architectureVersion,
    staticProof: fs.existsSync(path.join(dir, 'vertical-analysis.json'))
      ? JSON.parse(fs.readFileSync(path.join(dir, 'vertical-analysis.json'), 'utf8')) : null,
    staticProofs
  });
  if (['1.0.7-vertical-experiment', '1.0.8-vertical-experiment',
    '1.0.9-vertical-experiment', '1.0.10-vertical-experiment',
    '1.0.11-vertical-experiment', '1.0.12-vertical-experiment',
    '1.0.13-vertical-experiment', '1.0.14-static-experiment', '1.0.17-static-scan',
    '1.0.18-static-arbitration'].includes(runRecord.payload.architectureVersion) &&
      ids.canonicalJson(reportRows.map((row) => row.payload).sort((a, b) => a.reportId.localeCompare(b.reportId))) !==
      ids.canonicalJson(rebuilt.rows)) {
    add('report-model-drift', 'report rows differ from assessments');
  }
  if (['1.0.3-vertical-experiment', '1.0.4-vertical-experiment',
    '1.0.5-vertical-experiment', '1.0.6-vertical-experiment',
    '1.0.7-vertical-experiment', '1.0.8-vertical-experiment',
    '1.0.9-vertical-experiment', '1.0.10-vertical-experiment',
    '1.0.11-vertical-experiment', '1.0.12-vertical-experiment',
    '1.0.13-vertical-experiment', '1.0.14-static-experiment'].includes(runRecord.payload.architectureVersion)) {
    const knowledgeFile = path.join(dir, 'vertical-knowledge.json');
    const analysisFile = path.join(dir, 'vertical-analysis.json');
    if (!fs.existsSync(knowledgeFile) || !fs.existsSync(analysisFile)) {
      add('vertical-artifact-missing', 'knowledge or analysis record missing');
    } else {
      const k = JSON.parse(fs.readFileSync(knowledgeFile, 'utf8'));
      const v = JSON.parse(fs.readFileSync(analysisFile, 'utf8'));
      if (k.knowledgeVersion !== runRecord.payload.knowledgeVersion ||
          v.knowledgeVersion !== k.knowledgeVersion) add('knowledge-version-mismatch', 'vertical evidence');
      const revisedFollowup = ['1.0.12-vertical-experiment', '1.0.13-vertical-experiment', '1.0.14-static-experiment']
        .includes(runRecord.payload.architectureVersion);
      if (runRecord.payload.architectureVersion === '1.0.14-static-experiment') {
        try {
          const scope = loadScope(DEFAULT_SCOPE);
          const facts = openFacts(scope, snapshotId);
          const anchors = discovery.buildAnchors(facts, scope);
          const entry = anchors.entries.find((row) => row.entityId === v.entryRef);
          const binding = discovery.resolveBinding(v.entryRef, { facts, scope, anchors: anchors.anchors });
          const knowledge = knowledgeLib.loadPublished(path.join(knowledgeLib.PUBLISHED_DIR,
            k.knowledgeVersion.slice(7), 'knowledge.json'), null, facts);
          const proof = staticProofLib.analyze(facts, entry, binding, knowledge, v.permissionArgument);
          if (ids.canonicalJson(proof) !== ids.canonicalJson(v.staticProof)) {
            add('static-proof-drift', 'source, norm or proof differs from archived static analysis');
          }
        } catch (e) { add('static-proof-drift', e.message); }
      }
      const earlyStop = v.plan?.ok !== true &&
        ['1.0.10-vertical-experiment', '1.0.11-vertical-experiment',
          '1.0.12-vertical-experiment', '1.0.13-vertical-experiment', '1.0.14-static-experiment'].includes(runRecord.payload.architectureVersion);
      if (earlyStop && (v.followup || v.followups || fs.existsSync(path.join(dir, 'vertical-context.json')) ||
          toolResults.some((row) => row.payload.tool === 'inspectPermissionArgument' &&
            row.payload.questionId === questions.find((q) => q.payload.kind === 'permission-argument-match' &&
              q.payload.taskId === v.taskId)?.recordId))) {
        add('vertical-early-stop-mismatch', 'unselected action executed after plan failure');
      }
      if (!earlyStop && ['1.0.9-vertical-experiment', '1.0.10-vertical-experiment',
        '1.0.11-vertical-experiment', '1.0.12-vertical-experiment',
        '1.0.13-vertical-experiment', '1.0.14-static-experiment'].includes(runRecord.payload.architectureVersion)) {
        const contextFile = path.join(dir, 'vertical-context.json');
        const context = fs.existsSync(contextFile) ? JSON.parse(fs.readFileSync(contextFile, 'utf8')) : null;
        const entities = jsonl.readJsonl(path.join(dir, 'entities.jsonl'), { strict: true }).rows;
        const relations = jsonl.readJsonl(path.join(dir, 'relations.jsonl'), { strict: true }).rows;
        const functions = new Map(entities.filter((e) => e.kind === 'function')
          .map((e) => [e.payload.factRef, e.payload]));
        const files = new Map(entities.filter((e) => e.kind === 'file')
          .map((e) => [e.payload.path, e.payload]));
        const sourceCalls = new Map(relations.filter((r) => r.kind === 'calls')
          .map((r) => [r.payload.factRef, r.payload]));
        const calls = new Map((v.operationCallsites || []).map((c) => [c.ref, c]));
        if (!context || !Array.isArray(v.operationCandidates) ||
            ids.canonicalJson(v.operationCandidates) !== ids.canonicalJson(context.operationCandidates) ||
            v.operationCandidates.some((item) => {
              const fn = functions.get(item.targetRef);
              const call = calls.get(item.callRef);
              const archived = sourceCalls.get(item.callRef);
              const line = context.sourceText?.split('\n')[item.source?.line - context.source?.startLine];
              return item.status !== 'suspect' || item.reason !== 'source-qualified-name-only' ||
                !call || call.resolution !== 'name-only' || call.line !== item.source?.line ||
                !archived || archived.file !== item.source.file || archived.line !== item.source.line ||
                archived.calleeName !== fn?.name ||
                item.source.file !== context.source?.file ||
                item.source.sha256 !== context.source?.sha256 ||
                files.get(item.source.file)?.sha256 !== item.source.sha256 ||
                !/^\s*(?:return\s+|[A-Za-z_]\w*\s*=\s*)PolicyInfoManager::GetInstance\(\)\.(?:SetPolicy|UnSetPolicy)\s*\(/.test(line || '') ||
                !line.includes(`.${fn?.name}(`) ||
                !fn || fn.role !== 'production' || fn.file !== item.target?.file ||
                fn.startLine !== item.target.line ||
                !fn.qualified?.includes('::PolicyInfoManager::') ||
                files.get(fn.file)?.sha256 !== item.target.sha256;
            }) || (v.operationCandidates.length > 0 && v.completeness?.operationTargetResolved)) {
          add('operation-candidate-mismatch', 'source-qualified candidate is not a resolved edge');
        }
      }
      if (['1.0.10-vertical-experiment', '1.0.11-vertical-experiment'].includes(runRecord.payload.architectureVersion) && !earlyStop) {
        const f = v.followup;
        const context = JSON.parse(fs.readFileSync(path.join(dir, 'vertical-context.json'), 'utf8'));
        const options = [{ type: 'callTool', tool: 'inspectPermissionArgument',
          arguments: { entryRef: v.entryRef } }];
        if (v.operationCandidates?.length === 1) {
          const target = v.operationCandidates[0].target;
          options.push({ type: 'callTool', tool: 'getEvidence',
            arguments: { file: target.file, line: target.line, count: 12 } });
        }
        const expectedContext = ids.contextId('vertical-followup-plan', {
          taskId: v.taskId, taskRevision: f?.taskRevision, entryRef: v.entryRef,
          sourceSha256: context.source?.sha256, options
        });
        const selected = f?.ok ? verticalLib.validateFollowup({ taskId: v.taskId,
          taskRevision: f.taskRevision, contextId: f.contextId, action: f.action },
        { taskId: v.taskId, revision: f.taskRevision }, expectedContext, options) : null;
        const tool = toolResults.find((row) => row.recordId === f?.toolResultId);
        const question = questions.find((row) => row.payload.kind ===
          (f?.action?.tool === 'inspectPermissionArgument' ? 'permission-argument-match' : 'authorization-effect') &&
          row.payload.taskId === v.taskId);
        if (!f || ids.canonicalJson(context.followup) !== ids.canonicalJson(f) ||
            f.contextId !== expectedContext || f.taskRevision !== 1 ||
            (f.ok && (!selected?.ok || !tool || tool.payload.tool !== f.action.tool ||
              tool.payload.questionId !== question?.recordId)) ||
            (!f.ok && (f.action || f.toolResultId))) {
          add('vertical-followup-mismatch', 'action, task revision, context or tool result changed');
        }
      }
      if (revisedFollowup && !earlyStop) {
        const contextFile = path.join(dir, 'vertical-context.json');
        const context = fs.existsSync(contextFile) ? JSON.parse(fs.readFileSync(contextFile, 'utf8')) : null;
        const followups = v.followups;
        let previous = null;
        let permissionStatus = null;
        let stopReason = null;
        const executed = new Set();
        if (!context || !Array.isArray(followups) || followups.length < 1 || followups.length > 2 ||
            v.followup || ids.canonicalJson(context?.followups) !== ids.canonicalJson(followups) ||
            ids.canonicalJson(context?.evidenceRefs) !== ids.canonicalJson(v.evidenceRefs)) {
          add('vertical-replan-mismatch', 'missing or divergent replan trace');
        }
        for (const [index, f] of (Array.isArray(followups) ? followups : []).entries()) {
          const missing = [...(!['supported', 'refuted'].includes(permissionStatus)
            ? ['permission-argument-unresolved'] : []), 'operation-target-unproven'];
          const options = [{ type: 'callTool', tool: 'inspectPermissionArgument',
            arguments: { entryRef: v.entryRef } }];
          if (v.operationCandidates?.length === 1) {
            const target = v.operationCandidates[0].target;
            options.push({ type: 'callTool', tool: 'getEvidence',
              arguments: { file: target.file, line: target.line, count: 12 } });
          }
          const allowed = options.filter((item) => !executed.has(item.tool) &&
            (item.tool !== 'inspectPermissionArgument' || missing.includes('permission-argument-unresolved')));
          const expectedContext = ids.contextId('vertical-followup-replan', {
            taskId: v.taskId, taskRevision: f.taskRevision, entryRef: v.entryRef,
            sourceSha256: context?.source?.sha256, round: index + 1,
            previous, missing, options: allowed
          });
          const selected = f.ok ? verticalLib.validateFollowup({ taskId: v.taskId,
            taskRevision: f.taskRevision, contextId: f.contextId, action: f.action },
          { taskId: v.taskId, revision: f.taskRevision }, expectedContext, allowed) : null;
          const actionEvents = evRes.rows.filter((ev) => ev.kind === 'vertical-action' &&
            ev.taskId === v.taskId && ev.detail?.step === `followup-${index + 1}`);
          const tool = toolResults.find((row) => row.recordId === f.toolResultId);
          const question = questions.find((row) => row.payload.kind ===
            (f.action?.tool === 'inspectPermissionArgument' ? 'permission-argument-match' : 'authorization-effect') &&
            row.payload.taskId === v.taskId);
          if (stopReason || !allowed.length || f.round !== index + 1 || f.taskRevision !== 1 ||
              f.contextId !== expectedContext ||
              ids.canonicalJson(f.previous) !== ids.canonicalJson(previous) ||
              ids.canonicalJson(f.missing) !== ids.canonicalJson(missing) ||
              ids.canonicalJson(f.allowedActions) !== ids.canonicalJson(allowed) ||
              (f.ok && (!selected?.ok || !tool || tool.payload.tool !== f.action.tool ||
                tool.payload.questionId !== question?.recordId)) ||
              (!f.ok && (f.action || f.toolResultId)) || actionEvents.length !== 1 ||
              actionEvents[0].detail.status !== (f.ok ? 'accepted' : 'rejected') ||
              actionEvents[0].detail.tool !== (f.ok ? f.action.tool : null) ||
              actionEvents[0].detail.modelCallRef !== (f.modelCallRef || null)) {
            add('vertical-replan-mismatch', `round ${index + 1} action, evidence, or event changed`);
          }
          if (!f.ok) { stopReason = f.reason; break; }
          executed.add(f.action.tool);
          if (f.action.tool === 'inspectPermissionArgument') permissionStatus = tool?.payload.observations?.status;
          const { usage, ...semanticPayload } = tool?.payload || {};
          previous = { tool: f.action.tool, toolResultId: f.toolResultId,
            status: tool?.payload.status,
            payloadSha256: tool ? ids.sha256Hex(ids.canonicalJson(
              runRecord.payload.architectureVersion === '1.0.12-vertical-experiment'
                ? tool.payload : semanticPayload)) : null };
          if (tool?.payload.status !== 'ok') { stopReason = 'tool-failed'; break; }
        }
        if (!stopReason) {
          if (followups?.length === 2) stopReason = 'round-limit';
          else if (followups?.[0]?.ok &&
              (executed.has('inspectPermissionArgument') || ['supported', 'refuted'].includes(permissionStatus)) &&
              (executed.has('getEvidence') || v.operationCandidates?.length !== 1)) {
            stopReason = 'no-new-action';
          }
        }
        if (v.followupStopReason !== stopReason || context?.followupStopReason !== stopReason) {
          add('vertical-replan-mismatch', 'replan stop reason differs from committed results');
        }
      }
      if (['1.0.7-vertical-experiment', '1.0.8-vertical-experiment',
        '1.0.9-vertical-experiment', '1.0.10-vertical-experiment',
        '1.0.11-vertical-experiment', '1.0.12-vertical-experiment',
        '1.0.13-vertical-experiment', '1.0.14-static-experiment'].includes(runRecord.payload.architectureVersion)) {
        const permissionQs = questions.filter((row) => row.payload.kind === 'permission-argument-match' &&
          row.payload.taskId === v.taskId);
        const q = permissionQs[0];
        const tool = toolResults.filter((row) => row.payload.tool === 'inspectPermissionArgument' &&
          row.payload.questionId === q?.recordId);
        const a = assessments.filter((row) => row.payload.questionId === q?.recordId);
        const compared = v.permissionArgument;
        const observation = tool[0]?.payload.observations;
        const decision = ['supported', 'refuted'].includes(observation?.status) ? observation.status : 'insufficient';
        if (['1.0.10-vertical-experiment', '1.0.11-vertical-experiment',
          '1.0.12-vertical-experiment', '1.0.13-vertical-experiment', '1.0.14-static-experiment'].includes(runRecord.payload.architectureVersion) &&
            !(revisedFollowup ? v.followups?.some((item) => item.ok &&
              item.action.tool === 'inspectPermissionArgument') :
              v.followup?.action?.tool === 'inspectPermissionArgument')) {
          if (permissionQs.length !== 1 || tool.length || a.length !== 1 || compared ||
              q.payload.status !== 'insufficient' || a[0].payload.decision !== 'insufficient' ||
              a[0].payload.evidenceRefs.length ||
              !a[0].payload.missingRefs.some((id) => missings.some((row) =>
                row.recordId === id && row.payload.reasonCode === 'permission-argument-unresolved'))) {
            add('permission-argument-mismatch', 'unselected permission check must remain insufficient');
          }
        } else if (permissionQs.length !== 1 || tool.length !== 1 || a.length !== 1 ||
            !compared || !observation || tool[0].payload.status !== 'ok' ||
            tool[0].payload.answer.status !== (decision === 'insufficient' ? 'unknown' : decision) ||
            ids.canonicalJson(compared) !== ids.canonicalJson({ ...observation, toolResultId: tool[0].recordId }) ||
            q.payload.status !== decision || a[0].payload.decision !== decision ||
            ids.canonicalJson(a[0].payload.evidenceRefs) !== ids.canonicalJson([tool[0].recordId]) ||
            ids.canonicalJson(a[0].payload.counterEvidenceRefs) !==
              ids.canonicalJson(decision === 'refuted' ? [tool[0].recordId] : []) ||
            ids.canonicalJson(q.payload.evidenceRefs) !== ids.canonicalJson([tool[0].recordId]) ||
            (decision === 'insufficient' && !a[0].payload.missingRefs.some((id) =>
              missings.some((row) => row.recordId === id && row.payload.reasonCode === 'permission-argument-unresolved')))) {
          add('permission-argument-mismatch', 'question, assessment, tool observation and sidecar disagree');
        }
      }
      if (['1.0.4-vertical-experiment', '1.0.5-vertical-experiment',
        '1.0.6-vertical-experiment', '1.0.7-vertical-experiment',
        '1.0.8-vertical-experiment', '1.0.9-vertical-experiment',
        '1.0.10-vertical-experiment', '1.0.11-vertical-experiment',
        '1.0.12-vertical-experiment', '1.0.13-vertical-experiment', '1.0.14-static-experiment'].includes(runRecord.payload.architectureVersion)) {
        const q = questions.find((row) => row.payload.kind === 'authorization-effect' && row.payload.taskId === v.taskId);
        const a = q && assessments.find((row) => row.payload.questionId === q.recordId);
        if (!q || !a || a.payload.decision !== 'insufficient' ||
            (!earlyStop && a.payload.contextId !== v.contextId) ||
            a.payload.modelCallRef !== (v.modelCallRef || null)) {
          add('vertical-assessment-mismatch', 'authorization-effect assessment and sidecar disagree');
        }
      }
      if (['1.0.5-vertical-experiment', '1.0.6-vertical-experiment',
        '1.0.7-vertical-experiment', '1.0.8-vertical-experiment',
        '1.0.9-vertical-experiment', '1.0.10-vertical-experiment',
        '1.0.11-vertical-experiment', '1.0.12-vertical-experiment',
        '1.0.13-vertical-experiment', '1.0.14-static-experiment'].includes(runRecord.payload.architectureVersion)) {
        const readCall = (ref) => {
          if (!/^CALL:[0-9a-f]{16}$/.test(String(ref || ''))) {
            add('vertical-model-trace-missing', `invalid call reference ${ref}`); return null;
          }
          const file = path.join(dir, 'model-calls', `${ref.replace(':', '-')}.json`);
          if (!fs.existsSync(file)) { add('vertical-model-trace-missing', ref); return null; }
          return JSON.parse(fs.readFileSync(file, 'utf8'));
        };
        if (['live', 'replay'].includes(runRecord.payload.mode)) {
          if (['1.0.10-vertical-experiment', '1.0.11-vertical-experiment'].includes(runRecord.payload.architectureVersion) && !earlyStop) {
            const f = v.followup;
            const call = readCall(f?.modelCallRef);
            const options = [{ type: 'callTool', tool: 'inspectPermissionArgument',
              arguments: { entryRef: v.entryRef } }];
            if (v.operationCandidates?.length === 1) {
              const target = v.operationCandidates[0].target;
              options.push({ type: 'callTool', tool: 'getEvidence',
                arguments: { file: target.file, line: target.line, count: 12 } });
            }
            if (call) {
              const accepted = call.status === 'ok' ? verticalLib.validateFollowup(call.parsed,
                { taskId: v.taskId, revision: f.taskRevision }, f.contextId, options)
                : { ok: false, reason: call.reason || 'model-followup-unavailable' };
              if (call.purpose !== 'vertical-followup-plan' || call.taskId !== v.taskId ||
                  call.contextId !== f.contextId || accepted.ok !== f.ok ||
                  (accepted.ok ? ids.canonicalJson(accepted.action) !== ids.canonicalJson(f.action)
                    : accepted.reason !== f.reason)) add('vertical-followup-model-mismatch', v.taskId);
            }
          }
          if (revisedFollowup && !earlyStop) {
            for (const f of v.followups || []) {
              const call = readCall(f.modelCallRef);
              if (!call) continue;
              const accepted = call.status === 'ok' ? verticalLib.validateFollowup(call.parsed,
                { taskId: v.taskId, revision: f.taskRevision }, f.contextId, f.allowedActions)
                : { ok: false, reason: call.reason || 'model-followup-unavailable' };
              if (call.purpose !== 'vertical-followup-replan' || call.taskId !== v.taskId ||
                  call.contextId !== f.contextId || accepted.ok !== f.ok ||
                  (accepted.ok ? ids.canonicalJson(accepted.action) !== ids.canonicalJson(f.action)
                    : accepted.reason !== f.reason)) add('vertical-replan-model-mismatch', `${v.taskId} round ${f.round}`);
            }
          }
          const planCall = v.plan ? readCall(v.plan.modelCallRef) : null;
          if (!v.plan && !earlyStop) add('vertical-model-plan-mismatch', 'plan missing');
          if (planCall) {
            const accepted = verticalLib.validatePlan(planCall.parsed, { taskId: v.taskId },
              v.planContextId, v.entryRef);
            if (planCall.taskId !== v.taskId || planCall.contextId !== v.planContextId ||
                planCall.purpose !== 'vertical-plan' || accepted.ok !== v.plan.ok ||
                (accepted.ok && ids.canonicalJson(accepted.action) !== ids.canonicalJson(v.plan.action))) {
              add('vertical-model-plan-mismatch', v.taskId);
            }
          }
          if (v.modelCallRef) {
            const opinionCall = readCall(v.modelCallRef);
            if (opinionCall) {
              const interpreted = verticalLib.gateInterpretation(opinionCall, new Set(v.evidenceRefs),
                { checkRefs: v.checkRefs }, v.applicability);
              if (opinionCall.taskId !== v.taskId || opinionCall.contextId !== v.contextId ||
                  opinionCall.purpose !== 'vertical-interpret' ||
                  ids.canonicalJson(interpreted) !== ids.canonicalJson(v.interpretation) ||
                  interpreted.reason !== v.reason) add('vertical-model-opinion-mismatch', v.taskId);
            }
          }
        } else if (v.plan?.source !== 'deterministic-off' || v.modelCallRef ||
            (revisedFollowup && v.followups?.some((item) => item.source !== 'deterministic-off' ||
              item.modelCallRef || ids.canonicalJson(item.action) !==
                ids.canonicalJson(item.allowedActions?.[0]))) ||
            (['1.0.10-vertical-experiment', '1.0.11-vertical-experiment'].includes(runRecord.payload.architectureVersion) &&
              (v.followup?.source !== 'deterministic-off' || v.followup?.modelCallRef ||
                v.followup?.action?.tool !== 'inspectPermissionArgument'))) {
          add('vertical-mode-mismatch', v.taskId);
        }
      }
    }
  }
  const storedSummaryFile = path.join(dir, 'report-model.json');
  if (fs.existsSync(storedSummaryFile)) {
    const stored = JSON.parse(fs.readFileSync(storedSummaryFile, 'utf8'));
    if (stored.semanticHash !== rebuilt.semanticHash) {
      add('report-model-drift', `stored ${stored.semanticHash} != rebuilt ${rebuilt.semanticHash}`);
    }
  } else {
    warnings.push({ code: 'report-model-missing', detail: 'report-model.json 不存在（先跑 report）' });
  }

  if (runRecord.payload.mode === 'replay') {
    try {
      const manifest = JSON.parse(fs.readFileSync(store.file('manifest.json'), 'utf8'));
      const pinned = manifest.replaySource;
      if (!pinned || !/^RUN:[0-9a-f]{16}$/.test(pinned.runId) ||
          pinned.kind !== 'parsed-response-only') throw new Error('missing replay provenance');
      const source = modelLib.loadReplaySource(new storeLib.RunStore(storeLib.RunStore.resolve(pinned.runId)));
      if ((pinned.sourceFilesSha256
        ? source.sourceFilesSha256 !== pinned.sourceFilesSha256
        : source.checksumsSha256 !== pinned.checksumsSha256) ||
          source.snapshotId !== runRecord.payload.snapshotId ||
          source.knowledgeVersion !== runRecord.payload.knowledgeVersion ||
          source.scopeId !== runRecord.payload.scopeId) throw new Error('replay source changed or mismatched');
      const archived = [...source.calls.values()];
      if (['1.0.8-vertical-experiment', '1.0.9-vertical-experiment',
        '1.0.10-vertical-experiment', '1.0.11-vertical-experiment',
        '1.0.12-vertical-experiment', '1.0.13-vertical-experiment', '1.0.14-static-experiment'].includes(runRecord.payload.architectureVersion) &&
          archived.some((call) => call.finishReason !== 'stop')) throw new Error('incomplete replay source');
      for (const name of fs.readdirSync(store.file('model-calls')).filter((f) => f.endsWith('.json'))) {
        const call = JSON.parse(fs.readFileSync(store.file(`model-calls/${name}`), 'utf8'));
        const original = archived.find((item) => item.callId === call.sourceCallId);
        if (call.sourceRunId !== pinned.runId || !original ||
            ids.canonicalJson(call.parsed) !== ids.canonicalJson(original.parsed)) {
          throw new Error(`replay call mismatch: ${name}`);
        }
      }
    } catch (e) { add('replay-source-invalid', e.message); }
  }

  const resumes = evRes.rows.filter((ev) => ev.kind === 'run-resumed');
  if (resumes.length) {
    const pinned = store.readJson('manifest.json').resumeFingerprint;
    const checkpoint = store.readCheckpoint();
    for (const ev of resumes) {
      const prior = evRes.rows[ev.detail.fromSeq - 1];
      const firstTool = ev.detail.resumeKind === 'first-tool-intent';
      if (!prior || prior.seq !== ev.detail.fromSeq ||
          (firstTool ? prior.kind !== 'tool-intent' ||
            store.readJson('manifest.json').toolTraceVersion !== '1' :
            prior.kind !== 'task-finished' || prior.to !== 'done') ||
          ev.seq !== prior.seq + 1 ||
          ev.detail.resumeFingerprint !== pinned) {
        add('resume-boundary-mismatch', `event seq=${ev.seq}`);
      }
    }
    if (!checkpoint || !Number.isInteger(checkpoint.throughSeq) ||
        checkpoint.throughSeq > evRes.rows.length ||
        (checkpoint.activeWallMs !== undefined &&
          (!Number.isInteger(checkpoint.activeWallMs) || checkpoint.activeWallMs < 0))) {
      add('resume-checkpoint-invalid', 'final checkpoint');
    }
  }

  // checksums
  const csFile = path.join(dir, 'checksums.json');
  if (fs.existsSync(csFile)) {
    const cs = JSON.parse(fs.readFileSync(csFile, 'utf8'));
    for (const [rel, meta] of Object.entries(cs.files || {})) {
      const abs = path.join(dir, rel.split('/').join(path.sep));
      if (!fs.existsSync(abs)) { add('checksum-missing-file', rel); continue; }
      const actual = storeLib.sha256File(abs);
      if (actual !== meta.sha256) add('checksum-mismatch', `${rel}: ${actual} != ${meta.sha256}`);
    }
  } else {
    warnings.push({ code: 'checksums-missing', detail: 'checksums.json 不存在' });
  }

  function finish() {
    const summary = {
      ok: errors.length === 0,
      runId: store.runId,
      runDir: path.relative(TOOL_DIR, dir).split(path.sep).join('/'),
      snapshotId,
      counts: {
        events: evRes ? evRes.rows.length : 0,
        tasks: tasks ? tasks.length : 0,
        questions: questions ? questions.length : 0,
        missing: missings ? missings.length : 0,
        toolResults: toolResults ? toolResults.length : 0,
        assessments: assessments ? assessments.length : 0,
        contexts: contexts ? contexts.length : 0,
        reportRows: reportRows ? reportRows.length : 0
      },
      errors,
      warnings
    };
    emit(summary);
    return summary.ok ? EXIT.OK : EXIT.CHECK;
  }
  return finish();
}

// ---------------------------------------------------------------------------
// report / verify
// ---------------------------------------------------------------------------

function detailMapFromEntities(store) {
  const map = new Map();
  const file = store.file('entities.jsonl');
  if (!fs.existsSync(file)) return map;
  for (const row of jsonl.readJsonl(file).rows) {
    if (row.kind === 'entry') {
      const e = row.payload;
      const label = e.entryKind === 'idl'
        ? `${e.entryKey.interface || '?'}#${e.entryKey.method}`
        : (e.entryKind === 'sa' ? `SA ${e.entryKey.saId}` : (e.entryKind === 'napi' ? `NAPI ${e.entryKey.module}` : e.entryKey.method));
      map.set(row.entityId, { label, location: `${e.file}:${e.line}` });
    } else if (row.kind === 'function') {
      map.set(row.entityId, { label: row.payload.qualified || row.payload.name, location: `${row.payload.file}:${row.payload.startLine}` });
    }
  }
  return map;
}

function cmdReport(opts) {
  if (!opts.flags.run) throw new CliError('report requires --run');
  const dir = storeLib.RunStore.resolve(opts.flags.run);
  const store = new storeLib.RunStore(dir);
  const res = reportLib.writeReport(store, {
    scopeId: store.run.payload.scopeId,
    mode: store.run.payload.mode,
    inputManifestId: store.run.payload.inputManifestId,
    detailById: detailMapFromEntities(store)
  });
  emit({
    ok: true,
    runId: store.runId,
    runDir: path.relative(TOOL_DIR, dir).split(path.sep).join('/'),
    counts: res.summary.counts,
    missingByReason: res.summary.missingByReason,
    semanticHash: res.summary.semanticHash,
    artifacts: res.artifacts
  });
  return EXIT.OK;
}

function cmdVerify(opts) {
  if (!opts.flags.run) throw new CliError('verify requires --run');
  if (!opts.flags.plan) throw new CliError('verify requires --plan');
  const dir = storeLib.RunStore.resolve(opts.flags.run);
  const store = new storeLib.RunStore(dir);
  const planPath = resolvePath(opts.flags.plan);
  if (!fs.existsSync(planPath)) throw new CliError(`plan not found: ${opts.flags.plan}`);
  let plan;
  try {
    plan = JSON.parse(fs.readFileSync(planPath, 'utf8'));
  } catch (e) {
    throw new CliError(`plan unparsable: ${e.message}`);
  }
  if (!plan || typeof plan !== 'object' || Array.isArray(plan)) throw new CliError('plan must be a JSON object');
  let verticalVerification = null;
  if (['1.0.5-vertical-experiment', '1.0.6-vertical-experiment',
    '1.0.7-vertical-experiment', '1.0.8-vertical-experiment',
    '1.0.9-vertical-experiment', '1.0.10-vertical-experiment',
    '1.0.11-vertical-experiment', '1.0.12-vertical-experiment',
    '1.0.13-vertical-experiment', '1.0.14-static-experiment'].includes(store.run.payload.architectureVersion)) {
    try {
      verticalVerification = verificationLib.validatePlan(plan, store);
    } catch (e) {
      if (e instanceof verificationLib.VerificationPlanError) throw new CliError(e.message);
      throw e;
    }
  }

  const missing = [{
    category: 'environment',
    reasonCode: 'verification-disabled',
    whyNeeded: verticalVerification ? verticalVerification.reason : 'MVP 不做设备/host 验证：verify 只登记计划并返回 blocked',
    nextActions: []
  }];
  const placeholder = {
    runId: store.runId,
    snapshotId: store.run.payload.snapshotId,
    status: 'blocked',
    planFile: path.relative(TOOL_DIR, planPath).split(path.sep).join('/'),
    planKeys: Object.keys(plan).sort(),
    executedCommands: [],
    missing,
    generatedAt: state.nowIso(),
    note: verticalVerification ? 'Unapproved plan: no isolated runner or harness was invoked.'
      : '占位：不执行任何设备、编译或宿主进程命令',
    ...(verticalVerification ? { entryFaithfulness: verticalVerification.entryFaithfulness } : {})
  };
  const rel = path.join('verification', 'placeholder.json');
  store.writeJson(rel, placeholder);
  store.appendEvent({ kind: 'verify-placeholder', detail: { status: 'blocked', planFile: placeholder.planFile } });
  store.updateManifest({ verification: { status: 'blocked', artifact: 'verification/placeholder.json' } });
  store.writeChecksums();
  emit({
    result: 'blocked',
    status: 'blocked',
    runId: store.runId,
    planFile: placeholder.planFile,
    missing,
    executedCommands: [],
    artifact: path.relative(TOOL_DIR, store.file(rel)).split(path.sep).join('/')
  });
  return EXIT.OK;
}

function cmdRecover(opts) {
  if (!opts.flags.run) throw new CliError('recover requires --run');
  const dir = storeLib.RunStore.resolve(opts.flags.run);
  const store = new storeLib.RunStore(dir);
  const ledgerFile = store.file('model-ledger.jsonl');
  const ledger = store.run.payload.mode === 'off' && !fs.existsSync(ledgerFile)
    ? { rows: [], tailPartial: false } : jsonl.readJsonl(ledgerFile, { strict: true });
  if (ledger.tailPartial) throw new CliError('model ledger tail incomplete', EXIT.CHECK);
  const result = recoveryLib.reconcileModelLedger(ledger.rows);
  const events = jsonl.readJsonl(store.file('events.jsonl'), { strict: true });
  if (events.tailPartial) throw new CliError('event ledger tail incomplete', EXIT.CHECK);
  const states = state.reduceTaskStates(events.rows);
  const toolTrace = recoveryLib.reconcileToolEvents(events.rows);
  const toolTraceAvailable = store.readJson('manifest.json').toolTraceVersion === '1';
  const incompleteTasks = [...states].filter(([, value]) => value.state === 'running')
    .map(([taskId]) => taskId).sort();
  emit({ runId: store.runId, mode: store.run.payload.mode, ...result,
    toolTraceStatus: toolTraceAvailable ? 'recorded' : 'not-recorded',
    pendingTools: toolTraceAvailable ? toolTrace.pendingTools : null,
    incompleteTasks, autoRerunTools: false,
    tasks: [...states].map(([taskId, value]) => ({ taskId, state: value.state })).sort((a, b) =>
      a.taskId.localeCompare(b.taskId)), checkpoint: store.readCheckpoint(),
    executedCommands: [], modelRequests: 0 });
  return result.pending.length || toolTrace.pendingTools.length || incompleteTasks.length ? EXIT.CHECK : EXIT.OK;
}

// ---------------------------------------------------------------------------

async function main(argv) {
  let opts;
  try {
    opts = parseFlags(argv);
  } catch (e) {
    process.stderr.write(`${e.message}\n\n${USAGE}\n`);
    return EXIT.ARG;
  }
  if (opts.help || opts.cmd === 'help' || !opts.cmd) {
    process.stdout.write(`${USAGE}\n`);
    return opts.cmd === 'help' || opts.help ? EXIT.OK : EXIT.ARG;
  }
  try {
    platform.requireWindowsNative();
    switch (opts.cmd) {
      case 'doctor': return cmdDoctor(opts);
      case 'tools': return cmdTools(opts);
      case 'index': return cmdIndex(opts);
      case 'run': return await cmdRun(opts);
      case 'resume': return await cmdRun(opts);
      case 'check': return cmdCheck(opts);
      case 'report': return cmdReport(opts);
      case 'recover': return cmdRecover(opts);
      case 'knowledge propose': return cmdKnowledgePropose(opts);
      case 'knowledge publish': return cmdKnowledgePublish(opts);
      case 'verify': return cmdVerify(opts);
      default:
        process.stderr.write(`unknown command: ${opts.cmd}\n\n${USAGE}\n`);
        return EXIT.ARG;
    }
  } catch (e) {
    if (e && e.code === 'windows-native-required') {
      process.stderr.write('windows-native-required: ' + e.message + '\n');
      return EXIT.NOT_IMPLEMENTED;
    }
    if (e instanceof CliError) {
      process.stderr.write(`${e.code}: ${e.message}\n`);
      return e.exitCode;
    }
    if (e && e.code === 'budget-exhausted') {
      process.stderr.write(`budget-exhausted: ${e.message}\n`);
      return EXIT.BUDGET;
    }
    process.stderr.write(`${e && e.stack ? e.stack : e}\n`);
    return EXIT.INTERNAL;
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }).catch((e) => {
    process.stderr.write(`${e && e.stack ? e.stack : e}\n`);
    process.exitCode = EXIT.INTERNAL;
  });
}

module.exports = { main, parseFlags, EXIT, SCHEMA_FOR, loadScope, loadBudget };
