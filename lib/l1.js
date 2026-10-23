'use strict';

/**
 * l1.js —— L1 事实查询层。
 *
 * 权威输入是 out/l1、out/l2、out/gaps 与 miner 的只读产物；本模块只建内存索引，
 * 不重新发明函数索引，也不写任何产物。
 *
 * 查询约定：
 *   - 函数用稳定 `functionId = repo|file:startLine`；
 *   - 所有返回带 `file` / `startLine` / `functionId` 或 `siteKey`；
 *   - 找不到时返回 null，不抛异常。
 */

const fs = require('fs');
const path = require('path');
const { WORKSPACE, OUT_ROOT, readJsonl } = require('./util.js');

const DEFAULT_MINER = path.join(WORKSPACE, 'oh6-framework-want-leak-miner');
const DEFAULT_SOURCE = path.join(WORKSPACE, 'OpenHarmony');

function functionIdOf(row) {
  return row.functionId || `${row.repo}|${row.file}:${row.startLine}`;
}

function indexBy(list, keyFn) {
  const map = new Map();
  for (const row of list) {
    const k = keyFn(row);
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(row);
  }
  return map;
}

class L1 {
  constructor(opts = {}) {
    this.outRoot = opts.outRoot || OUT_ROOT;
    this.minerRoot = opts.minerRoot || DEFAULT_MINER;
    this.sourceRoot = opts.sourceRoot || DEFAULT_SOURCE;
    this._cache = new Map();
    this._sourceCache = new Map();
    this._lazy = {
      functions: null,
      producers: null,
      callEdges: null,
      p6Payload: null,
      p6Index: null,
      entries: null,
      actions: null,
      reachability: null,
      derefs: null,
      minerSites: null,
      minerEntities: null,
      minerGates: null,
      minerSlices: null,
      minerRejections: null,
      minerFindings: null,
      restrictedApis: null
    };
  }

  _file(name) {
    return path.join(this.outRoot, name);
  }

  _miner(name) {
    return path.join(this.minerRoot, name);
  }

  _rows(key, file) {
    if (!this._lazy[key]) this._lazy[key] = readJsonl(file);
    return this._lazy[key];
  }

  /** 读取函数表（17,534 行） */
  functions() {
    if (!this._lazy.functions) {
      const rows = this._rows('functions', this._file('l1/functions.jsonl'));
      const byId = new Map();
      const byFile = new Map();
      for (const row of rows) {
        const id = functionIdOf(row);
        row.functionId = id;
        byId.set(id, row);
        const k = `${row.repo}\u0000${row.file}`;
        if (!byFile.has(k)) byFile.set(k, []);
        byFile.get(k).push(row);
      }
      for (const list of byFile.values()) list.sort((a, b) => a.startLine - b.startLine);
      this._lazy.functions = { rows, byId, byFile };
    }
    return this._lazy.functions;
  }

  /** 函数 id 查询 */
  getFunctionById(functionId) {
    return this.functions().byId.get(functionId) || null;
  }

  /**
   * getFunction(repo, file, line) -> 包含该行的最内层函数（与 enclosingFunction 同义）。
   */
  getFunction(repo, file, line) {
    const list = this.functions().byFile.get(`${repo}\u0000${file}`);
    if (!list) return null;
    let best = null;
    for (const fn of list) {
      if (fn.startLine > line) break;
      if (line <= fn.endLine && (!best || fn.endLine - fn.startLine < best.endLine - best.startLine)) best = fn;
    }
    return best;
  }

  enclosingFunction(repo, file, line) {
    return this.getFunction(repo, file, line);
  }

  /** 文件内全部函数 */
  functionsOfFile(repo, file) {
    return this.functions().byFile.get(`${repo}\u0000${file}`) || [];
  }

  /** 仓内全部函数 */
  functionsOfRepo(repo) {
    return this.functions().rows.filter((f) => f.repo === repo);
  }

  /** 文件 -> 函数（可复算 1,084 个文件） */
  functionFileCount() {
    return this.functions().byFile.size;
  }

  _callIndex() {
    if (!this._lazy.callEdges) {
      const rows = this._rows('callEdges', this._file('l1/call-edges.jsonl'));
      const byFrom = new Map();
      const byTo = new Map();
      for (const r of rows) {
        if (!byFrom.has(r.from)) byFrom.set(r.from, []);
        byFrom.get(r.from).push(r);
        if (!byTo.has(r.to)) byTo.set(r.to, []);
        byTo.get(r.to).push(r);
      }
      this._lazy.callEdges = { rows, byFrom, byTo };
    }
    return this._lazy.callEdges;
  }

  _calleeSummary(edge) {
    const target = this.getFunctionById(edge.to);
    return {
      functionId: edge.to,
      name: edge.name,
      line: edge.line,
      resolution: edge.resolution,
      candidateCount: edge.candidateCount,
      repo: target ? target.repo : null,
      file: target ? target.file : null,
      startLine: target ? target.startLine : null
    };
  }

  /** callees(functionId) -> 直接调用（最多 500 条） */
  callees(functionId, limit = 500) {
    const edges = this._callIndex().byFrom.get(functionId) || [];
    return edges.slice(0, limit).map((e) => this._calleeSummary(e));
  }

  /** callers(functionId) -> 反向调用 */
  callers(functionId, limit = 500) {
    const edges = this._callIndex().byTo.get(functionId) || [];
    return edges.slice(0, limit).map((e) => {
      const source = this.getFunctionById(e.from);
      return {
        functionId: e.from,
        name: e.name,
        line: e.line,
        resolution: e.resolution,
        repo: source ? source.repo : null,
        file: source ? source.file : null,
        startLine: source ? source.startLine : null
      };
    });
  }

  callEdgeCount() {
    return this._callIndex().rows.length;
  }

  _producerIndex() {
    if (!this._lazy.producers) {
      const rows = this._rows('producers', this._file('l1/producers.jsonl'));
      const byId = new Map();
      const byName = new Map();
      for (const r of rows) {
        const id = functionIdOf(r);
        r.functionId = id;
        byId.set(id, r);
        if (!byName.has(r.name)) byName.set(r.name, []);
        byName.get(r.name).push(r);
      }
      this._lazy.producers = { rows, byId, byName };
    }
    return this._lazy.producers;
  }

  producerType(functionId) {
    return this._producerIndex().byId.get(functionId) || null;
  }

  producersByName(name, repo = null) {
    const list = this._producerIndex().byName.get(name) || [];
    return repo ? list.filter((r) => r.repo === repo) : list.slice();
  }

  producerCount() {
    return this._producerIndex().rows.length;
  }

  /** guards(functionId) -> 源码 guard 行（含绝对行号） */
  guards(functionId) {
    const fn = this.getFunctionById(functionId);
    if (!fn) return [];
    return (fn.guards || []).map((g) => ({
      ...g,
      absoluteLine: fn.startLine + Number(g.line || 0) - 1
    }));
  }

  publishSites(functionId) {
    const fn = this.getFunctionById(functionId);
    return fn ? (fn.publishes || []).slice() : [];
  }

  _payloadIndex() {
    if (!this._lazy.p6Payload) {
      const rows = this._rows('p6Payload', this._file('l2/p6-payload.jsonl'));
      const byRecord = new Map();
      for (const r of rows) {
        if (!byRecord.has(r.recordId)) byRecord.set(r.recordId, []);
        byRecord.get(r.recordId).push(r);
      }
      this._lazy.p6Payload = { rows, byRecord };
    }
    return this._lazy.p6Payload;
  }

  /** p6Payload(recordId) -> payload setter/实参（多行按 recordId 归并） */
  p6Payload(recordId) {
    const list = this._payloadIndex().byRecord.get(recordId) || [];
    if (!list.length) return null;
    if (list.length === 1) return list[0];
    const base = { ...list[0], rows: list.length };
    base.payloadCandidates = list.flatMap((r) => r.payloadCandidates || []);
    base.payloadNames = [...new Set(list.flatMap((r) => r.payloadNames || []))];
    return base;
  }

  _p6Index() {
    if (!this._lazy.p6Index) {
      const rows = this._rows('p6Index', this._file('l2/p6-index.jsonl'));
      const byRecord = new Map();
      const byPayload = new Map();
      for (const r of rows) {
        if (!byRecord.has(r.recordId)) byRecord.set(r.recordId, []);
        byRecord.get(r.recordId).push(r);
        if (!byPayload.has(r.payload)) byPayload.set(r.payload, []);
        byPayload.get(r.payload).push(r);
      }
      this._lazy.p6Index = { rows, byRecord, byPayload };
    }
    return this._lazy.p6Index;
  }

  /** p6Index(recordId) -> 全部 payload 的 restricted/public/design 命中 */
  p6Index(recordId) {
    const rows = this._p6Index().byRecord.get(recordId) || [];
    return rows.length ? rows : null;
  }

  p6IndexByPayload(payload) {
    return (this._p6Index().byPayload.get(payload) || []).slice();
  }

  p6IndexRowCount() {
    return this._p6Index().rows.length;
  }

  _entryIndex() {
    if (!this._lazy.entries) {
      const rows = this._rows('entries', this._file('l2/entries.jsonl'));
      const byFile = new Map();
      const byId = new Map();
      const bySymbol = new Map();
      for (const r of rows) {
        byId.set(r.entryKey, r);
        const f = r.site && r.site.file;
        if (f) {
          const k = `${r.repo}\u0000${f}`;
          if (!byFile.has(k)) byFile.set(k, []);
          byFile.get(k).push(r);
        }
        const sym = r.site && r.site.symbol;
        if (sym) {
          if (!bySymbol.has(sym)) bySymbol.set(sym, []);
          bySymbol.get(sym).push(r);
        }
      }
      this._lazy.entries = { rows, byFile, byId, bySymbol };
    }
    return this._lazy.entries;
  }

  entries() {
    return this._entryIndex().rows;
  }

  entryById(entryKey) {
    return this._entryIndex().byId.get(entryKey) || null;
  }

  entriesBySymbol(symbol) {
    return (this._entryIndex().bySymbol.get(symbol) || []).slice();
  }

  _actionIndex() {
    if (!this._lazy.actions) {
      const rows = this._rows('actions', this._file('l2/actions.jsonl'));
      const byRecord = new Map();
      for (const r of rows) {
        if (!byRecord.has(r.recordId)) byRecord.set(r.recordId, []);
        byRecord.get(r.recordId).push(r);
      }
      this._lazy.actions = { rows, byRecord };
    }
    return this._lazy.actions;
  }

  actions() {
    return this._actionIndex().rows;
  }

  actionsByRecord(recordId) {
    return (this._actionIndex().byRecord.get(recordId) || []).slice();
  }

  _reachIndex() {
    if (!this._lazy.reachability) {
      const rows = this._rows('reachability', this._file('gaps/p3-reachability.jsonl'));
      const byId = new Map();
      const byFunction = new Map();
      for (const r of rows) {
        byId.set(r.id, r);
        const fid = r.functionId;
        if (fid) {
          const prev = byFunction.get(fid);
          if (!prev || (r.reachable && (!prev.reachable || (r.depth != null && (prev.depth == null || r.depth < prev.depth))))) {
            byFunction.set(fid, r);
          }
        }
      }
      this._lazy.reachability = { rows, byId, byFunction };
    }
    return this._lazy.reachability;
  }

  /** deref 级可达性（L2 的 73/182 口径） */
  derefReachability(derefId) {
    return this._reachIndex().byId.get(derefId) || null;
  }

  /** 函数级可达性：返回 {reachable, depth, seed} 或 null */
  reachabilityOfFunction(functionId) {
    const r = this._reachIndex().byFunction.get(functionId);
    if (!r) return null;
    return { reachable: !!r.reachable, depth: r.depth == null ? null : r.depth, seed: r.seed || null, derefId: r.id };
  }

  reachableFunctionCount() {
    let n = 0;
    for (const r of this._reachIndex().byFunction.values()) if (r.reachable) n += 1;
    return n;
  }

  _derefIndex() {
    if (!this._lazy.derefs) {
      const rows = this._rows('derefs', this._file('gaps/p3-probe.jsonl'));
      this._lazy.derefs = { rows, byId: new Map(rows.map((r) => [r.id, r])) };
    }
    return this._lazy.derefs;
  }

  derefs() {
    return this._derefIndex().rows;
  }

  derefById(id) {
    return this._derefIndex().byId.get(id) || null;
  }

  _siteIndex() {
    if (!this._lazy.minerSites) {
      const rows = this._rows('minerSites', this._miner('result/latest/broadcast-sites.jsonl'));
      const byKey = new Map();
      const byAction = new Map();
      const byRecord = new Map();
      for (const r of rows) {
        byKey.set(r.siteKey, r);
        if (!byAction.has(r.action)) byAction.set(r.action, []);
        byAction.get(r.action).push(r);
        const recs = (r.src && r.src.recordIds) || [];
        for (const rec of recs) {
          if (!byRecord.has(rec)) byRecord.set(rec, []);
          byRecord.get(rec).push(r);
        }
      }
      this._lazy.minerSites = { rows, byKey, byAction, byRecord };
    }
    return this._lazy.minerSites;
  }

  /** minerSite(siteKey) -> 624 站点记录 */
  minerSite(siteKey) {
    return this._siteIndex().byKey.get(siteKey) || null;
  }

  minerSiteCount() {
    return this._siteIndex().rows.length;
  }

  minerSitesForAction(action) {
    return (this._siteIndex().byAction.get(action) || []).slice();
  }

  minerSitesForRecord(recordId) {
    return (this._siteIndex().byRecord.get(recordId) || []).slice();
  }

  _entityIndex() {
    if (!this._lazy.minerEntities) {
      const rows = this._rows('minerEntities', this._miner('result/latest/sensitive-entities.jsonl'));
      const byId = new Map();
      const bySymbol = new Map();
      const byMember = new Map();
      for (const r of rows) {
        byId.set(r.entityId, r);
        if (r.symbol) {
          if (!bySymbol.has(r.symbol)) bySymbol.set(r.symbol, []);
          bySymbol.get(r.symbol).push(r);
        }
        if (r.member) {
          if (!byMember.has(r.member)) byMember.set(r.member, []);
          byMember.get(r.member).push(r);
        }
      }
      this._lazy.minerEntities = { rows, byId, bySymbol, byMember };
    }
    return this._lazy.minerEntities;
  }

  /** minerEntity(entityId) -> 敏感实体 */
  minerEntity(entityId) {
    return this._entityIndex().byId.get(entityId) || null;
  }

  minerEntityCount() {
    return this._entityIndex().rows.length;
  }

  sensitiveEntitiesBySymbol(symbol) {
    return (this._entityIndex().bySymbol.get(symbol) || []).slice();
  }

  sensitiveEntitiesByMember(member) {
    return (this._entityIndex().byMember.get(member) || []).slice();
  }

  _gateIndex() {
    if (!this._lazy.minerGates) {
      const rows = this._rows('minerGates', this._miner('result/latest/gate.jsonl'));
      this._lazy.minerGates = { rows, byKey: new Map(rows.map((r) => [r.siteKey, r])) };
    }
    return this._lazy.minerGates;
  }

  /** minerGate(siteKey) -> C2/C3/T7 输入 */
  minerGate(siteKey) {
    return this._gateIndex().byKey.get(siteKey) || null;
  }

  _sliceIndex() {
    if (!this._lazy.minerSlices) {
      const rows = this._rows('minerSlices', this._miner('result/latest/slices.jsonl'));
      this._lazy.minerSlices = { rows, byKey: new Map(rows.map((r) => [r.siteKey, r])) };
    }
    return this._lazy.minerSlices;
  }

  /** minerSlice(siteKey) -> 写点/替换/切片 */
  minerSlice(siteKey) {
    this._sliceIndex();
    return this._lazy.minerSlices.byKey.get(siteKey) || null;
  }

  _rejectionIndex() {
    if (!this._lazy.minerRejections) {
      const rows = this._rows('minerRejections', this._miner('result/latest/rejections.jsonl'));
      this._lazy.minerRejections = { rows, byKey: new Map(rows.map((r) => [r.siteKey, r])) };
    }
    return this._lazy.minerRejections;
  }

  minerRejection(siteKey) {
    return this._rejectionIndex().byKey.get(siteKey) || null;
  }

  minerRejections() {
    return this._rejectionIndex().rows;
  }

  _findingIndex() {
    if (!this._lazy.minerFindings) {
      const rows = this._rows('minerFindings', this._miner('result/latest/findings.jsonl'));
      this._lazy.minerFindings = { rows, byKey: new Map(rows.map((r) => [r.siteKey, r])) };
    }
    return this._lazy.minerFindings;
  }

  minerFinding(siteKey) {
    return this._findingIndex().byKey.get(siteKey) || null;
  }

  minerFindings() {
    return this._findingIndex().rows;
  }

  _restrictedApiIndex() {
    if (!this._lazy.restrictedApis) {
      const rows = this._rows('restrictedApis', this._miner('index/restricted-apis.jsonl'));
      const byName = new Map();
      for (const r of rows) {
        const key = r.qualifiedName || r.fullName || r.name;
        if (!key) continue;
        if (!byName.has(key)) byName.set(key, []);
        byName.get(key).push(r);
      }
      this._lazy.restrictedApis = { rows, byName };
    }
    return this._lazy.restrictedApis;
  }

  restrictedApi(nameOrQualified) {
    return (this._restrictedApiIndex().byName.get(nameOrQualified) || [])[0] || null;
  }

  restrictedApiRows() {
    return this._restrictedApiIndex().rows;
  }

  /** 源码读取（带缓存），失败返回 null */
  sourceLines(repo, file) {
    const k = `${repo}\u0000${file}`;
    if (this._sourceCache.has(k)) return this._sourceCache.get(k);
    let lines = null;
    try {
      lines = fs.readFileSync(path.join(this.sourceRoot, repo, file), 'utf8').split(/\r?\n/);
    } catch (_) {
      lines = null;
    }
    this._sourceCache.set(k, lines);
    return lines;
  }

  lineAt(repo, file, line) {
    const lines = this.sourceLines(repo, file);
    if (!lines || line < 1 || line > lines.length) return null;
    return lines[line - 1];
  }

  stats() {
    const entries = this.entries();
    const actions = this.actions();
    const payloadRows = this._payloadIndex().rows;
    return {
      functions: this.functions().rows.length,
      functionFiles: this.functionFileCount(),
      callEdges: this.callEdgeCount(),
      producers: this.producerCount(),
      entries: entries.length,
      entryFiles: new Set(entries.map((e) => `${e.repo}\u0000${e.site && e.site.file}`)).size,
      actionRows: actions.length,
      uniqueActions: new Set(actions.map((a) => a.action)).size,
      p6PayloadRows: payloadRows.length,
      p6PayloadItems: payloadRows.reduce((n, r) => n + ((r.payloadCandidates || []).length), 0),
      p6IndexRows: this.p6IndexRowCount(),
      minerSites: this.minerSiteCount(),
      minerEntities: this.minerEntityCount(),
      minerFindings: this.minerFindings().length,
      minerRejections: this.minerRejections().length,
      derefs: this.derefs().length,
      reachableDerefs: this._reachIndex().rows.filter((r) => r.reachable).length
    };
  }
}

function loadL1(opts) {
  return new L1(opts);
}

module.exports = { L1, loadL1, functionIdOf };
