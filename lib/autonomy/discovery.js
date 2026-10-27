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

/** 按 sha256(path) 升序决定抽样顺序（确定性，与目录遍历顺序无关）；fraction=0 明确表示不抽样。 */
function deterministicSample(items, fraction) {
  const scored = items
    .map((it) => ({ it, key: ids.sha256Hex(String(it)) }))
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  if (!(fraction > 0)) return [];
  const n = Math.max(1, Math.ceil(scored.length * fraction));
  return scored.slice(0, Math.min(n, scored.length)).map((s) => s.it).sort();
}

/**
 * 组件局部入口过滤（E1）：scope.entryFilter 可限定纳入的 IDL 接口 / 入口类型，
 * 只影响发现分母，不改变绑定或裁决规则；未配置时保持全部入口（pilot 语义）。
 */
function filterEntries(entries, scope) {
  const filter = scope && scope.entryFilter;
  if (!filter) return entries;
  const interfaces = Array.isArray(filter.interfaces) && filter.interfaces.length
    ? new Set(filter.interfaces.map(String)) : null;
  const kinds = Array.isArray(filter.entryKinds) && filter.entryKinds.length
    ? new Set(filter.entryKinds.map(String)) : null;
  const methods = Array.isArray(filter.methods) && filter.methods.length
    ? new Set(filter.methods.map(String)) : null;
  return entries.filter((entry) => {
    if (kinds && !kinds.has(entry.kind)) return false;
    if (interfaces && entry.kind === 'idl' && !interfaces.has(String(entry.interface))) return false;
    if (methods && (entry.kind === 'idl' || entry.kind === 'ipc-code' || entry.kind === 'arkts-export') &&
        !methods.has(String(entry.method))) return false;
    return true;
  });
}

/** 入口的绑定 owner 段：接口级覆盖优先于 scope 默认值（第二组件起使用）。 */
function ownerSuffixFor(scope, anchor) {
  const metadata = (scope && scope.modelMetadata) || {};
  const byInterface = metadata.interfaces && anchor && anchor.interface
    ? metadata.interfaces[anchor.interface] : null;
  if (byInterface && typeof byInterface.implOwnerSuffix === 'string' && byInterface.implOwnerSuffix) {
    return byInterface.implOwnerSuffix;
  }
  return metadata.implOwnerSuffix || null;
}

/**
 * 建锚点：入口实体 + 覆盖抽样函数。
 * @returns {{anchors:Map, entries:Array, coverageAnchors:Array, stats:object}}
 */
function buildAnchors(facts, scope) {
  const idx = facts.index();
  const entries = filterEntries(indexLib.buildEntries(facts, scope), scope);
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

/** IDL 类型 → 类型族（vector/map/string/primitive-or-other）；未建模别名归 other。 */
function idlTypeFamily(t) {
  const s = String(t || '').trim();
  const head = s.split('<')[0].toLowerCase();
  if (/^(list|sequence|map|unordered_map)$/.test(head)) {
    return head === 'map' || head === 'unordered_map' ? 'map' : 'vector';
  }
  if (/^string$/.test(head)) return 'string';
  return 'primitive-or-other';
}

/** C++ 签名 → 逐参数类型文本（顶层逗号切分，忽略 <>/() 深度内的逗号）。 */
function signatureParamTypes(signature) {
  const sig = String(signature || '');
  const open = sig.indexOf('(');
  const close = sig.lastIndexOf(')');
  if (open < 0 || close <= open) return [];
  const inner = sig.slice(open + 1, close);
  const parts = [];
  let depth = 0;
  let cur = '';
  for (const ch of inner) {
    if (ch === '<' || ch === '(') depth += 1;
    else if (ch === '>' || ch === ')') depth -= 1;
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; } else cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  return parts.map((p) => p.trim()).filter((p) => p && p !== '...' && p !== 'void');
}

function cppTypeFamily(paramText) {
  const s = String(paramText || '').replace(/&|\*/g, ' ').trim();
  if (/std::(vector|list|set)</.test(s)) return 'vector';
  if (/std::(unordered_)?map</.test(s)) return 'map';
  if (/std::string|std::wstring|char\s*\*/.test(s)) return 'string';
  const first = s.split(/\s+/).filter(Boolean)[0] || '';
  if (/^(u?int\d*_t|unsigned|signed|long|short|float|double|bool|char|size_t|uint\d+)$/i.test(first)) return 'primitive';
  return 'other';
}

/**
 * 类型族兼容：仅在两侧都能给出 vector/map/string 证据的参数位上强制一致；
 * IDL 别名（AccessTokenID 等 → primitive-or-other）不参与判定，避免别名未解误判。
 * @returns {boolean} 该候选是否与 IDL 参数类型族兼容（至少一个可判位）
 */
function paramTypesCompatible(idlParams, signature, evidence) {
  const types = signatureParamTypes(signature);
  if (!types.length) return false; // 签名缺失不提供证据
  let enforced = 0;
  for (let i = 0; i < idlParams.length && i < types.length; i += 1) {
    const idlFam = idlTypeFamily(idlParams[i] && idlParams[i].type);
    const cppFam = cppTypeFamily(types[i]);
    const definitive = (f) => f === 'vector' || f === 'map' || f === 'string';
    if (!definitive(idlFam) || !definitive(cppFam)) continue;
    enforced += 1;
    if (idlFam !== cppFam) return false;
  }
  if (evidence) evidence.count = Math.max(evidence.count || 0, enforced);
  return enforced > 0;
}

/** 绑定：入口 → 实现函数（名称 + owner 段） */
function resolveBinding(ref, ctx) {
  const { facts, scope, anchors } = ctx;
  const anchor = anchors ? anchors.get(ref) : null;
  const implSuffix = ownerSuffixFor(scope, anchor);
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
  if (anchor.kind === 'function' || anchor.kind === 'on-remote-request' ||
      anchor.kind === 'napi-export' || anchor.kind === 'arkts-export' || anchor.kind === 'ipc-code') {
    const fn = findFunctionByFact(facts, anchor.factRef) ||
      (anchor.kind === 'napi-export' ? null : findFunction(facts, anchor.method, anchor.qualified));
    if (!fn) {
      return { binding: anchor.kind === 'napi-export' && anchor.registration?.candidateCount > 1
        ? 'suspect' : 'unbound', candidates: anchor.handlerCandidates || [], bound: null,
      note: anchor.kind === 'napi-export'
        ? `napi export ${anchor.module}.${anchor.method} handler ${anchor.handler}: ${anchor.registration?.candidateCount ?? 0} candidates`
        : `anchor ${ref} function not found in facts`,
      implOwnerSuffix: implSuffix, searchSpace: 'functions' };
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
      note: anchor.kind === 'napi-export'
        ? `module ${anchor.module} export ${anchor.method} -> ${candidate.qualified} (registration + descriptor)`
        : `self-bound function ${candidate.qualified || candidate.name}`,
      implOwnerSuffix: implSuffix,
      searchSpace: 'self'
    };
  }
  if (anchor.kind === 'idl') {
    const method = anchor.method;
    let matchParamTypesApplied = null;
    let all = facts.findFunctions(method, { limit: 50 })
      .filter((fn) => fn.name === method)
      .filter((fn) => (implSuffix ? String(fn.qualified || '').includes(`::${implSuffix}::`) : true));
    // 受控/盲测语料可能把同一入口的多个变体放在不同文件；scope 显式 opt-in 时
    // 优先选与入口元数据同一文件的实现，避免把不同变体误当同名歧义。
    // 默认关闭，pilot 与真实组件绑定语义不变。
    if (scope && scope.binding && scope.binding.preferSameFile === true && anchor.file) {
      const sameFile = all.filter((fn) => fn.sourceRange && fn.sourceRange.file === anchor.file);
      if (sameFile.length) all = sameFile;
    }
    // scope 显式 opt-in：仅在同名多候选时用 IDL paramCount 做 tie-breaker；
    // 唯一候选可能因 [out] 引用参数而 argc 大于 IDL paramCount，不能因此丢实现。
    if (scope && scope.binding && scope.binding.matchArgc === true &&
        Number.isInteger(anchor.paramCount) && all.length > 1) {
      const byArgc = all.filter((fn) => fn.argc === anchor.paramCount);
      if (byArgc.length) all = byArgc;
    }
    // scope 显式 opt-in（R2-D1）：同 argc 重载用 IDL 参数类型族 vs C++ 签名类型族消歧。
    // 仅在能给出 vector/map/string 证据且恰好唯一时收敛；别名未解/多候选保持 suspect。
    // 同名测试函数（role=test）在该 opt-in 下不作为绑定候选。
    if (scope && scope.binding && scope.binding.matchParamTypes === true &&
        Array.isArray(anchor.params) && anchor.params.length && all.length > 1) {
      const production = all.filter((fn) => (fn.role || 'production') === 'production');
      if (production.length >= 1 && production.length < all.length) all = production;
      if (all.length > 1) {
        const evidence = { count: 0 };
        const survivors = all.filter((fn) => paramTypesCompatible(anchor.params, fn.signature, evidence));
        if (evidence.count > 0 && survivors.length >= 1 && survivors.length < all.length) {
          all = survivors;
          matchParamTypesApplied = { enforcedParams: evidence.count,
            idlParams: anchor.params.map((p) => `${p.direction || 'in'} ${p.type} ${p.name || ''}`.trim()) };
        }
      }
    }
    const candidates = all.map((fn) => ({
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
        note: `bound ${candidates[0].qualified} by name+owner(${implSuffix})`
          + (matchParamTypesApplied
            ? ` +param-types(enforced=${matchParamTypesApplied.enforcedParams}`
              + ` idl=[${matchParamTypesApplied.idlParams.join('; ')}])`
            : ''),
        implOwnerSuffix: implSuffix,
        searchSpace: `functions(name=${method})`
      };
    }
    if (candidates.length > 1) {
      return {
        binding: 'suspect',
        candidates,
        bound: null,
        note: `${candidates.length} candidates for method ${method} under owner ${implSuffix}`
          + (matchParamTypesApplied ? ' (param-type evidence insufficient to disambiguate)' : ''),
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
  filterEntries,
  ownerSuffixFor,
  questionsFor,
  idlTypeFamily,
  signatureParamTypes,
  cppTypeFamily,
  paramTypesCompatible
};
