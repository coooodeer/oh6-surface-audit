'use strict';

/**
 * Build entity and relation indexes from the pinned facts snapshot.
 *
 * 产物：`out/autonomy/index/<snapshot>/<scope-fingerprint>/{entities.jsonl, relations.jsonl, index-manifest.json}`
 *
 * 实体：entry（idl/sa/napi/on-remote-request）、function、file。
 * 关系：calls（函数体直接调用）、registers（入口 → 唯一实现体）。
 *
 * 对账（必须相等，否则 `index` 失败）：
 *   entities(kind=function) == facts 作用域内 functions 行数
 *   entities(kind=file)     == facts 作用域内 files 行数
 *   relations(relation=calls) == facts 作用域内 calls 行数
 *   entry(idl/sa/napi)       == metadata 行数
 */

const fs = require('fs');
const path = require('path');

const ids = require('./ids');
const store = require('./store');
const jsonl = require('./jsonl');
const napi = require('./napi');
const ipcDispatch = require('./ipc-dispatch');
const ani = require('./ani');
const sa = require('./sa');

const INDEX_VERSION = '1';

function scopeFingerprint(facts) {
  const { __path, ...scope } = facts.scope || {};
  const revision = scope?.saMethodBinding ? 'r3-sa-method-v1'
    : scope?.aniBinding?.shape === 'direct-namespace' ? 'r3-ani-direct-v1'
    : scope?.aniBinding ? 'r3-ani-v2'
    : scope?.napiBindings ? 'r3-napi-v2'
      : scope?.ipcDispatch?.shape === 'tokensync-enum' ? 'r3-ipc-code-enum-v1'
      : scope?.ipcDispatch?.shape === 'rust-enum' ? 'r3-ipc-code-rust-v1'
      : scope?.ipcDispatch ? 'r3-ipc-code-v3'
      : scope?.entryFilter?.exactOnRemoteRequest ? 'r3-ipc-v1'
      : scope?.entryFilter?.entryKinds?.includes('arkts-export') ? 'r3-arkts-v1' : null;
  return ids.sha256Hex(ids.canonicalJson(revision
    ? { scope, limits: facts.limits, revision } : { scope, limits: facts.limits }));
}

/** 入口实体的**唯一**语义键：只放稳定身份字段（不含行号/时间）。 */
function entrySemantic(e) {
  return {
    entryKind: e.kind,
    metadataRef: e.metadataRef === undefined ? null : e.metadataRef,
    interface: e.interface === undefined ? null : e.interface,
    method: e.method === undefined ? null : e.method,
    saId: e.saId === undefined ? null : e.saId,
    module: e.module === undefined ? null : e.module,
    factRef: e.factRef === undefined ? null : e.factRef,
    ...(e.kind === 'ipc-code' ? { ipcCode: e.ipcCode, dispatchRef: e.dispatchRef } : {})
  };
}

function entryEntityId(e) {
  return ids.entityId('entry', entrySemantic(e));
}

function buildEntries(facts, scope) {
  const idx = facts.index();
  const entries = [];
  const dispatch = ipcDispatch.enumerate(facts, scope, idx);

  for (const row of idx.metadata.idl) {
    const p = row.payload || {};
    const entry = {
      kind: 'idl',
      interface: p.interface || null,
      method: p.method || null,
      saId: null,
      module: null,
      file: row.sourceFile,
      line: row.sourceLine,
      metadataRef: row.metadataId || null,
      factRef: null,
      token: p.token || null,
      descriptor: p.descriptor || null,
      paramCount: p.paramCount === undefined ? null : p.paramCount,
      params: Array.isArray(p.params) ? p.params : null,
      ipcCode: p.ipcCode === undefined ? null : p.ipcCode
    };
    if (scope?.saMethodBinding && entry.interface === scope.saMethodBinding.interface &&
        entry.method === scope.saMethodBinding.method) {
      entry.saId = scope.saMethodBinding.saId;
      entry.saRegistration = sa.bridgeOf(facts, entry, scope.saMethodBinding, idx);
    }
    entries.push(entry);
  }

  for (const row of idx.metadata.sa) {
    const p = row.payload || {};
    entries.push({
      kind: 'sa',
      interface: null,
      method: null,
      saId: p.saId === undefined ? null : p.saId,
      module: null,
      file: row.sourceFile,
      line: row.sourceLine,
      metadataRef: row.metadataId || null,
      factRef: null,
      process: p.process || null,
      library: p.library || null
    });
  }

  for (const row of idx.metadata.napi) {
    const p = row.payload || {};
    entries.push({
      kind: 'napi',
      interface: null,
      method: null,
      saId: null,
      module: p.module || null,
      file: row.sourceFile,
      line: row.sourceLine,
      metadataRef: row.metadataId || null,
      factRef: null,
      registration: p.registration || null
    });
    const binding = scope?.napiBindings?.[p.module];
    if (binding) entries.push(...napi.exportsOf(facts, row, binding));
  }

  for (const fn of idx.functions) {
    // 只把生产函数的 OnRemoteRequest 当入口；HWTEST_F 宏展开出的测试函数名也含
    // OnRemoteRequest，按名字匹配会把测试当入口（E0 口径修正，2026-10-25）。
    // Rust 等新形态用 entryFilter.onRemoteRequestNames 显式列出入口函数名。
    if (fn.role !== 'production') continue;
    const orrNames = scope?.entryFilter?.onRemoteRequestNames;
    const matched = Array.isArray(orrNames) && orrNames.length ? orrNames.includes(fn.name)
      : scope?.entryFilter?.exactOnRemoteRequest === true
        ? fn.name === 'OnRemoteRequest' : /OnRemoteRequest/.test(fn.name || '');
    if (!matched) continue;
    const model = dispatch.get(fn.factId);
    entries.push({
      kind: 'on-remote-request',
      interface: null,
      method: fn.name,
      saId: null,
      module: null,
      file: fn.sourceRange && fn.sourceRange.file,
      line: fn.startLine,
      metadataRef: null,
      factRef: fn.factId,
      qualified: fn.qualified || null,
      ...(model ? { dispatchStatus: model.status, dispatchShape: model.shapeStatus || model.status,
        dispatchEdges: model.edges.map((edge) => ({ code: edge.code, status: edge.status })) } : {})
    });
    if (model) for (const edge of model.edges) {
      if (edge.status !== 'resolved-dispatch') continue;
      entries.push({
        kind: 'ipc-code', interface: null, method: edge.handler.name,
        saId: null, module: null, file: fn.sourceRange.file, line: edge.line,
        metadataRef: null, factRef: edge.handler.factId, dispatchRef: fn.factId,
        ipcCode: edge.code, codeDef: `${scope.ipcDispatch.codeHeader}:${edge.defLine}`,
        handlerCallLine: edge.handlerCallLine, defaultLine: model.defaultLine,
        qualified: edge.handler.qualified
      });
    }
  }

  for (const fn of idx.functions) {
    if (fn.role !== 'production' || fn.language !== 'arkts' || !fn.exported) continue;
    const entry = {
      kind: 'arkts-export', interface: null, method: fn.name, saId: null, module: null,
      file: fn.sourceRange.file, line: fn.startLine, metadataRef: null, factRef: fn.factId,
      qualified: fn.qualified, paramCount: fn.argc
    };
    if (scope?.aniBinding) entry.aniBridge = ani.bridgeOf(facts, entry, scope.aniBinding, idx);
    entries.push(entry);
  }

  for (const e of entries) e.entityId = entryEntityId(e);
  entries.sort((a, b) => (a.entityId < b.entityId ? -1 : a.entityId > b.entityId ? 1 : 0));
  return entries;
}

function entryRecord(entry) {
  return {
    entityId: entryEntityId(entry),
    payload: {
      kind: 'entry',
      entryKind: entry.kind,
      entryKey: {
        interface: entry.interface,
        method: entry.method,
        saId: entry.saId,
        module: entry.module
      },
      file: entry.file,
      line: entry.line,
      metadataRef: entry.metadataRef,
      factRef: entry.factRef,
      token: entry.token === undefined ? null : entry.token,
      process: entry.process === undefined ? null : entry.process,
      library: entry.library === undefined ? null : entry.library,
      ...(entry.registration === undefined ? {} : { registration: entry.registration }),
      ...(entry.handlerCandidates === undefined ? {} : { handlerCandidates: entry.handlerCandidates }),
      ...(entry.aniBridge === undefined ? {} : { aniBridge: entry.aniBridge }),
      ...(entry.saRegistration === undefined ? {} : { saRegistration: entry.saRegistration }),
      ...(entry.dispatchStatus === undefined ? {} : {
        dispatchStatus: entry.dispatchStatus, dispatchShape: entry.dispatchShape,
        dispatchEdges: entry.dispatchEdges
      }),
      ...(entry.kind !== 'ipc-code' ? {} : {
        ipcCode: entry.ipcCode, codeDef: entry.codeDef, dispatchRef: entry.dispatchRef,
        handlerCallLine: entry.handlerCallLine, defaultLine: entry.defaultLine
      })
    }
  };
}

function functionEntityId(fn) {
  return ids.entityId('function', { factRef: fn.factId });
}

function fileEntityId(row) {
  return ids.entityId('file', { factRef: row.factId || row.path });
}

/**
 * 建索引（纯函数，不写盘）。
 * @returns {{entities:Array, relations:Array, entries:Array, reconciliation:object}}
 */
function buildIndex(facts, scope) {
  const idx = facts.index();
  const entries = buildEntries(facts, scope);
  const entities = [];
  const relations = [];

  const fnByName = new Map();
  for (const fn of idx.functions) {
    if (!fnByName.has(fn.name)) fnByName.set(fn.name, []);
    fnByName.get(fn.name).push(fn);
  }

  for (const e of entries) {
    entities.push({
      entityId: e.entityId,
      kind: 'entry',
      payload: entryRecord(e).payload
    });
  }

  for (const fn of idx.functions) {
    entities.push({
      entityId: functionEntityId(fn),
      kind: 'function',
      payload: {
        kind: 'function',
        name: fn.name,
        qualified: fn.qualified || null,
        owner: fn.owner || null,
        file: fn.sourceRange && fn.sourceRange.file,
        startLine: fn.startLine,
        endLine: fn.endLine,
        signature: fn.signature || null,
        role: fn.role || null,
        factRef: fn.factId,
        quality: fn.quality || null
      }
    });
  }

  for (const row of idx.files) {
    entities.push({
      entityId: fileEntityId(row),
      kind: 'file',
      payload: {
        kind: 'file',
        path: row.path,
        repo: row.repo,
        role: row.role,
        sha256: row.sha256,
        bytes: row.bytes,
        lines: row.lines,
        language: row.language || null,
        factRef: row.factId
      }
    });
  }

  const fnEntityByFact = new Map();
  for (const fn of idx.functions) fnEntityByFact.set(fn.factId, functionEntityId(fn));

  for (const call of idx.calls) {
    const callerId = fnEntityByFact.get(call.caller) || null;
    const callees = fnByName.get(call.calleeName) || [];
    const targetId = callees.length === 1 && callees[0].name === call.calleeName ? functionEntityId(callees[0]) : null;
    const payload = {
      kind: 'calls',
      callerRef: callerId,
      callerName: call.callerName || null,
      calleeName: call.calleeName || null,
      targetRef: targetId,
      resolution: targetId ? 'resolved-in-scope' : 'name-only',
      candidateCount: callees.length,
      file: call.sourceRange && call.sourceRange.file,
      line: call.line,
      factRef: call.factId
    };
    relations.push({
      relationId: ids.relationId('calls', { factRef: call.factId }),
      kind: 'calls',
      payload
    });
  }

  // registers：IDL 入口 → 唯一实现体（owner 后缀 + 方法名）
  const defaultImplSuffix = scope && scope.modelMetadata && scope.modelMetadata.implOwnerSuffix
    ? scope.modelMetadata.implOwnerSuffix
    : null;
  const ifaceOwners = (scope && scope.modelMetadata && scope.modelMetadata.interfaces) || null;
  const ownerFor = (entry) => {
    const byIface = ifaceOwners && entry.interface ? ifaceOwners[entry.interface] : null;
    return byIface && typeof byIface.implOwnerSuffix === 'string' && byIface.implOwnerSuffix
      ? byIface.implOwnerSuffix : defaultImplSuffix;
  };
  for (const e of entries) {
    if (e.saRegistration?.status === 'resolved') {
      const saEntry = entries.find((item) => item.kind === 'sa' && item.saId === e.saId &&
        item.metadataRef === e.saRegistration.profileRef);
      if (saEntry) relations.push({ relationId: ids.relationId('sa-exposes-method', {
        entryRef: saEntry.entityId, targetRef: e.entityId }), kind: 'sa-exposes-method',
      payload: { kind: 'sa-exposes-method', entryRef: saEntry.entityId, targetRef: e.entityId,
        serviceRef: functionEntityId({ factId: e.saRegistration.serviceFactRef }),
        profileRef: e.saRegistration.profileRef, registrationFile: e.saRegistration.registrationFile,
        registrationLine: e.saRegistration.registrationLine, publishLine: e.saRegistration.publishLine,
        resolution: 'profile-register-publish-generated-stub-method' } });
    }
    if ((e.kind === 'napi-export' || e.kind === 'arkts-export' || e.kind === 'ipc-code') && e.factRef) {
      relations.push({
        relationId: ids.relationId('registers', { entryRef: e.entityId, targetRef: functionEntityId({ factId: e.factRef }) }),
        kind: 'registers',
        payload: { kind: 'registers', entryRef: e.entityId,
          targetRef: functionEntityId({ factId: e.factRef }), method: e.method,
          registration: e.registration,
          resolution: e.kind === 'ipc-code' ? 'ipc-switch-code-same-object'
            : e.kind === 'arkts-export' ? 'arkts-export-declaration' : 'napi-module-init-literal-export',
          ...(e.kind === 'ipc-code' ? { ipcCode: e.ipcCode, codeDef: e.codeDef,
            dispatchRef: e.dispatchRef, caseLine: e.line,
            handlerCallLine: e.handlerCallLine, defaultLine: e.defaultLine } : {}) }
      });
    }
    if (e.aniBridge?.status === 'resolved') {
      relations.push({ relationId: ids.relationId('bridges-to-native', {
        entryRef: e.entityId, targetRef: functionEntityId({ factId: e.aniBridge.nativeFactRef }) }),
      kind: 'bridges-to-native', payload: { kind: 'bridges-to-native', entryRef: e.entityId,
        targetRef: functionEntityId({ factId: e.aniBridge.nativeFactRef }),
        resolution: e.aniBridge.shape === 'direct-namespace' ? 'arkts-direct-ani-table-conditional' : 'taskpool-ani-table',
        callLine: e.aniBridge.callLine,
        tableLine: e.aniBridge.tableLine, nativeLine: e.aniBridge.nativeLine } });
    }
    if (e.kind !== 'idl' || !e.method) continue;
    const implSuffix = ownerFor(e);
    const candidates = (fnByName.get(e.method) || []).filter((fn) => {
      if (!implSuffix) return true;
      return String(fn.qualified || '').includes(`::${implSuffix}::`);
    });
    if (candidates.length !== 1) continue;
    relations.push({
      relationId: ids.relationId('registers', { entryRef: e.entityId, targetRef: functionEntityId(candidates[0]) }),
      kind: 'registers',
      payload: {
        kind: 'registers',
        entryRef: e.entityId,
        targetRef: functionEntityId(candidates[0]),
        method: e.method,
        implOwnerSuffix: implSuffix,
        resolution: 'name-and-owner'
      }
    });
  }

  entities.sort((a, b) => (a.entityId < b.entityId ? -1 : a.entityId > b.entityId ? 1 : 0));
  relations.sort((a, b) => (a.relationId < b.relationId ? -1 : a.relationId > b.relationId ? 1 : 0));

  const countBy = (rows, keyFn) => {
    const m = {};
    for (const r of rows) {
      const k = keyFn(r);
      m[k] = (m[k] || 0) + 1;
    }
    return m;
  };

  const reconciliation = {
    expected: {
      functions: idx.counts.functions,
      files: idx.counts.files,
      calls: idx.counts.calls,
      idl: idx.counts.idl,
      sa: idx.counts.sa,
      napi: idx.counts.napi
    },
    actual: {
      functions: entities.filter((e) => e.kind === 'function').length,
      files: entities.filter((e) => e.kind === 'file').length,
      calls: relations.filter((r) => r.kind === 'calls').length,
      idl: entities.filter((e) => e.kind === 'entry' && e.payload.entryKind === 'idl').length,
      sa: entities.filter((e) => e.kind === 'entry' && e.payload.entryKind === 'sa').length,
      napi: entities.filter((e) => e.kind === 'entry' && e.payload.entryKind === 'napi').length
    },
    entityKinds: countBy(entities, (e) => e.kind),
    relationKinds: countBy(relations, (r) => r.kind),
    entryKinds: countBy(entities.filter((e) => e.kind === 'entry'), (e) => e.payload.entryKind)
  };
  reconciliation.ok = Object.keys(reconciliation.expected)
    .every((k) => reconciliation.expected[k] === reconciliation.actual[k]);

  return { entities, relations, entries, reconciliation, indexTruncated: idx.truncated };
}

/** 写盘：entities.jsonl / relations.jsonl / index-manifest.json（逐文件原子替换，允许并发只读进程） */
function writeIndex(facts, scope, opts = {}) {
  const built = buildIndex(facts, scope);
  const dir = opts.dir || store.indexPath(facts.snapshotId, scopeFingerprint(facts));
  store.ensureDir(dir);

  const writeAtomic = (name, rows) => {
    const abs = path.join(dir, name);
    const body = rows.map((r) => JSON.stringify(r)).join('\n');
    store.atomicWrite(abs, rows.length ? `${body}\n` : '');
    return abs;
  };
  writeAtomic('entities.jsonl', built.entities.map((e) => ({
    entityId: e.entityId,
    kind: e.kind,
    snapshotId: facts.snapshotId,
    payload: e.payload
  })));
  writeAtomic('relations.jsonl', built.relations.map((r) => ({
    relationId: r.relationId,
    kind: r.kind,
    snapshotId: facts.snapshotId,
    payload: r.payload
  })));

  const files = ['entities.jsonl', 'relations.jsonl'].map((n) => {
    const abs = path.join(dir, n);
    return { file: n, bytes: fs.statSync(abs).size, sha256: store.sha256File(abs) };
  });
  const manifest = {
    indexVersion: INDEX_VERSION,
    snapshotId: facts.snapshotId,
    inputManifestId: facts.inputManifestId,
    scopeId: scope && scope.scopeId ? scope.scopeId : null,
    scopeFingerprint: scopeFingerprint(facts),
    roots: facts.index().roots,
    counts: {
      entities: built.entities.length,
      relations: built.relations.length,
      entries: built.entries.length
    },
    reconciliation: built.reconciliation,
    indexTruncated: built.indexTruncated,
    limits: facts.index().limits,
    files
  };
  store.atomicWrite(path.join(dir, 'index-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  return { dir, manifest, built };
}

/** 读取已建索引（run 不重复建，除非缺失） */
function loadIndex(facts, opts = {}) {
  const dir = opts.dir || store.indexPath(facts.snapshotId, scopeFingerprint(facts));
  const entFile = path.join(dir, 'entities.jsonl');
  const relFile = path.join(dir, 'relations.jsonl');
  const manifestFile = path.join(dir, 'index-manifest.json');
  if (!fs.existsSync(entFile) || !fs.existsSync(relFile) || !fs.existsSync(manifestFile)) return null;
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  if (manifest.indexVersion !== INDEX_VERSION || manifest.snapshotId !== facts.snapshotId ||
      manifest.inputManifestId !== facts.inputManifestId ||
      manifest.scopeFingerprint !== scopeFingerprint(facts)) return null;
  const entities = jsonl.readJsonl(entFile, { strict: true }).rows;
  const relations = jsonl.readJsonl(relFile, { strict: true }).rows;
  return { dir, entities, relations };
}

module.exports = { buildIndex, writeIndex, loadIndex, buildEntries, functionEntityId, fileEntityId, INDEX_VERSION };
