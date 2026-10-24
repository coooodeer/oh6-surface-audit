'use strict';

/**
 * lib/autonomy/discovery.js —— 入口枚举、绑定、任务提案与接纳、覆盖抽样（P4）。
 *
 * Binding uses an exact owner segment and method name; ambiguity remains unresolved.
 *   idl method  → 作用域内 name === method 且 qualified 含 `::<implOwnerSuffix>::`
 *                 唯一 ⇒ resolved；多个 ⇒ suspect；没有 ⇒ unbound
 *   sa / napi   → 元数据级入口，无方法体 ⇒ unbound + 具名 reason
 *   on-remote-request / function → 自绑定 ⇒ resolved
 *
 * 任务：每个锚点一个 Task，固定三个子问题（binding / check-presence / dominance）。
 * 去重键：Task=锚点集合；Question=(锚点, kind)。
 */

const ids = require('./ids');
const state = require('./state');
const indexLib = require('./index');

function readPolicy(file) {
  const fs = require('fs');
  const path = require('path');
  const abs = path.isAbsolute(file)
    ? file
    : path.join(path.resolve(__dirname, '..', '..'), String(file || ''));
  if (!fs.existsSync(abs)) throw new Error(`scope-policy-missing: ${file}`);
  return JSON.parse(fs.readFileSync(abs, 'utf8'));
}

/** 每个 Task 的固定三问（§3.1） */
function questionsFor(anchor) {
  const base = { anchorRef: anchor.entityId };
  return [
    {
      kind: 'binding',
      proposition: state.TASK_QUESTION_TEXT.binding,
      polarity: 'exists',
      semantic: { ...base, kind: 'binding', text: state.TASK_QUESTION_TEXT.binding }
    },
    {
      kind: 'check-presence',
      proposition: state.TASK_QUESTION_TEXT['check-presence'],
      polarity: 'exists',
      semantic: { ...base, kind: 'check-presence', text: state.TASK_QUESTION_TEXT['check-presence'] }
    },
    {
      kind: 'dominance',
      proposition: state.TASK_QUESTION_TEXT.dominance,
      polarity: 'forall',
      semantic: { ...base, kind: 'dominance', text: state.TASK_QUESTION_TEXT.dominance }
    }
  ];
}

function taskPayload(origin, anchorRefs, taskId) {
  return {
    taskId,
    origin,
    anchorRefs,
    question: '入口能否绑定实现、实现体内是否有校验、校验是否支配敏感操作？',
    state: 'queued',
    questionRefs: [],
    missingRefs: [],
    revision: 1
  };
}

/** 按 sha256(path) 升序决定抽样顺序（确定性，与目录遍历顺序无关） */
function deterministicSample(items, fraction) {
  const scored = items
    .map((it) => ({ it, key: ids.sha256Hex(String(it)) }))
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const n = Math.max(1, Math.ceil(scored.length * fraction));
  return scored.slice(0, Math.min(n, scored.length)).map((s) => s.it).sort();
}

/**
 * 建锚点：入口实体 + 覆盖抽样函数。
 * @returns {{anchors:Map, entries:Array, coverageAnchors:Array, stats:object}}
 */
function buildAnchors(facts, scope) {
  const idx = facts.index();
  const entries = indexLib.buildEntries(facts, scope);
  const anchors = new Map();

  for (const e of entries) anchors.set(e.entityId, { ...e, kind: e.kind });

  const coverageCfg = (scope && scope.coverageSample) || {};
  const fraction = typeof coverageCfg.fraction === 'number' ? coverageCfg.fraction : 0.2;
  const role = coverageCfg.role || 'production';
  const exts = Array.isArray(coverageCfg.extensions) && coverageCfg.extensions.length
    ? coverageCfg.extensions.map((e) => String(e).toLowerCase())
    : null;
  const isImpl = (p) => {
    if (!exts) return true;
    const lower = String(p).toLowerCase();
    return exts.some((e) => lower.endsWith(e));
  };
  const prodFiles = idx.files.filter((f) => (f.role || 'production') === role && isImpl(f.path));
  const sampledFiles = deterministicSample(prodFiles.map((f) => f.path), fraction);

  const byFile = new Map();
  for (const fn of idx.functions) {
    if ((fn.role || 'production') !== role) continue;
    const file = fn.sourceRange && fn.sourceRange.file;
    if (!file) continue;
    if (!byFile.has(file)) byFile.set(file, []);
    byFile.get(file).push(fn);
  }
  for (const rows of byFile.values()) rows.sort((a, b) => a.startLine - b.startLine || (a.name < b.name ? -1 : 1));

  const coverageAnchors = [];
  for (const file of sampledFiles) {
    const rows = byFile.get(file);
    if (!rows || !rows.length) continue;
    const fn = rows[0];
    const entityId = indexLib.functionEntityId(fn);
    coverageAnchors.push({
      entityId,
      kind: 'function',
      method: fn.name,
      qualified: fn.qualified || null,
      file: fn.sourceRange.file,
      line: fn.startLine,
      factRef: fn.factId,
      interface: null,
      saId: null,
      module: null,
      metadataRef: null,
      sampledFile: file
    });
    if (!anchors.has(entityId)) anchors.set(entityId, coverageAnchors[coverageAnchors.length - 1]);
  }

  return {
    anchors,
    entries,
    coverageAnchors,
    stats: {
      entries: entries.length,
      entryKinds: entries.reduce((m, e) => { m[e.kind] = (m[e.kind] || 0) + 1; return m; }, {}),
      productionFiles: prodFiles.length,
      sampledFiles: sampledFiles.length,
      coverageAnchors: coverageAnchors.length,
      fraction
    }
  };
}

/** 绑定：入口 → 实现函数（名称 + owner 段） */
function resolveBinding(ref, ctx) {
  const { facts, scope, anchors } = ctx;
  const implSuffix = scope && scope.modelMetadata ? scope.modelMetadata.implOwnerSuffix : null;
  const anchor = anchors ? anchors.get(ref) : null;
  if (!anchor) {
    return {
      binding: 'unbound',
      candidates: [],
      bound: null,
      note: `anchor ${ref} not in discovery anchors`,
      implOwnerSuffix: implSuffix,
      searchSpace: 'anchors'
    };
  }
  if (anchor.kind === 'function' || anchor.kind === 'on-remote-request') {
    const fn = findFunctionByFact(facts, anchor.factRef) || findFunction(facts, anchor.method, anchor.qualified);
    if (!fn) {
      return { binding: 'unbound', candidates: [], bound: null, note: `anchor ${ref} function not found in facts`, implOwnerSuffix: implSuffix, searchSpace: 'functions' };
    }
    const candidate = {
      name: fn.name,
      qualified: fn.qualified || null,
      file: fn.sourceRange && fn.sourceRange.file,
      startLine: fn.startLine,
      factRef: fn.factId
    };
    return {
      binding: 'resolved',
      candidates: [candidate],
      bound: fn,
      note: `self-bound function ${candidate.qualified || candidate.name}`,
      implOwnerSuffix: implSuffix,
      searchSpace: 'self'
    };
  }
  if (anchor.kind === 'idl') {
    const method = anchor.method;
    const all = facts.findFunctions(method, { limit: 50 });
    const candidates = all
      .filter((fn) => fn.name === method)
      .filter((fn) => (implSuffix ? String(fn.qualified || '').includes(`::${implSuffix}::`) : true))
      .map((fn) => ({
        name: fn.name,
        qualified: fn.qualified || null,
        file: fn.sourceRange && fn.sourceRange.file,
        startLine: fn.startLine,
        factRef: fn.factId
      }));
    if (candidates.length === 1) {
      return {
        binding: 'resolved',
        candidates,
        bound: all.find((fn) => fn.factId === candidates[0].factRef),
        note: `bound ${candidates[0].qualified} by name+owner(${implSuffix})`,
        implOwnerSuffix: implSuffix,
        searchSpace: `functions(name=${method})`
      };
    }
    if (candidates.length > 1) {
      return {
        binding: 'suspect',
        candidates,
        bound: null,
        note: `${candidates.length} candidates for method ${method} under owner ${implSuffix}`,
        implOwnerSuffix: implSuffix,
        searchSpace: `functions(name=${method})`
      };
    }
    return {
      binding: 'unbound',
      candidates: [],
      bound: null,
      note: `no implementation named ${method} under owner ${implSuffix}`,
      implOwnerSuffix: implSuffix,
      searchSpace: `functions(name=${method})`
    };
  }
  if (anchor.kind === 'sa') {
    return {
      binding: 'unbound',
      candidates: [],
      bound: null,
      note: `sa entry saId=${anchor.saId} has no method body (metadata-only)`,
      implOwnerSuffix: implSuffix,
      searchSpace: 'metadata/sa'
    };
  }
  return {
    binding: 'unbound',
    candidates: [],
    bound: null,
    note: `napi module ${anchor.module} registration has no bound method body`,
    implOwnerSuffix: implSuffix,
    searchSpace: 'metadata/napi'
  };
}

function findFunctionByFact(facts, factRef) {
  if (!factRef) return null;
  const idx = facts.index();
  return idx.functions.find((fn) => fn.factId === factRef) || null;
}

function findFunction(facts, name, qualified) {
  const idx = facts.index();
  if (qualified) {
    const rows = idx.functionsByQualified.get(qualified);
    if (rows && rows.length) return rows[0];
  }
  const rows = idx.functionsByName.get(name);
  return rows && rows.length ? rows[0] : null;
}

/** 把任意 ref（ENT of function / 已绑定入口 / 函数名）解析成函数行 */
function resolveFunctionRef(ref, ctx) {
  const { facts, entitiesById } = ctx;
  const entity = entitiesById ? entitiesById.get(ref) : null;
  if (entity) {
    if (entity.kind === 'function') return findFunctionByFact(facts, entity.payload.factRef);
    if (entity.kind === 'entry') {
      const b = resolveBinding(ref, ctx);
      return b.bound || null;
    }
  }
  // 没有 entitiesById 时也要能解析入口实体（工具独立调用路径）
  if (/^ENT:[0-9a-f]{16}$/.test(String(ref))) {
    const b = resolveBinding(ref, ctx);
    return b.bound || null;
  }
  return findFunction(facts, ref, ref);
}

/**
 * 任务提案 + 接纳。
 * @returns {{tasks:Array, questions:Array, rejected:Array, duplicates:number, stats:object}}
 */
function proposeTasks(anchorsInfo, facts, scope) {
  const tasks = [];
  const questions = [];
  const rejected = [];
  const seenTask = new Set();
  const seenQuestion = new Set();
  let duplicates = 0;

  const push = (anchor, origin) => {
    if (!anchor || !anchor.entityId) {
      rejected.push({ anchor: null, reason: 'empty-anchor' });
      return;
    }
    const anchorRefs = [anchor.entityId];
    const tId = ids.taskId('task', { origin, anchorRefs });
    if (seenTask.has(tId)) { duplicates += 1; return; }
    seenTask.add(tId);
    const payload = taskPayload(origin, anchorRefs, tId);
    const qs = [];
    for (const q of questionsFor(anchor)) {
      const qId = ids.questionId('question', q.semantic);
      if (seenQuestion.has(qId)) { duplicates += 1; continue; }
      seenQuestion.add(qId);
      const qPayload = {
        questionId: qId,
        taskId: tId,
        kind: q.kind,
        proposition: q.proposition,
        polarity: q.polarity,
        status: 'unknown',
        basis: 'derived',
        assurance: 'bounded-analysis',
        evidenceRefs: [],
        missingRefs: []
      };
      qs.push(qPayload);
      questions.push(qPayload);
    }
    payload.questionRefs = qs.map((q) => q.questionId).sort();
    // 接纳器：必须有可观察对象 + 至少一个可执行的问题
    if (!anchor.kind || !qs.length) {
      rejected.push({ anchor: anchor.entityId, reason: 'no-observable-object' });
      return;
    }
    tasks.push(payload);
  };

  for (const e of anchorsInfo.entries) push(e, 'entry-scan');
  for (const a of anchorsInfo.coverageAnchors) push(a, 'coverage-sample');

  tasks.sort((a, b) => (a.taskId < b.taskId ? -1 : a.taskId > b.taskId ? 1 : 0));
  questions.sort((a, b) => (a.questionId < b.questionId ? -1 : a.questionId > b.questionId ? 1 : 0));

  return {
    tasks,
    questions,
    rejected,
    duplicates,
    stats: {
      proposed: tasks.length,
      questions: questions.length,
      rejected: rejected.length,
      duplicates,
      byOrigin: tasks.reduce((m, t) => { m[t.origin] = (m[t.origin] || 0) + 1; return m; }, {})
    }
  };
}

module.exports = {
  readPolicy,
  buildAnchors,
  resolveBinding,
  resolveFunctionRef,
  proposeTasks,
  deterministicSample,
  questionsFor
};
