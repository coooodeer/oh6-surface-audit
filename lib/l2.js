'use strict';

/**
 * l2.js —— 入口 / site / action 绑定层。
 *
 * 关键口径：
 *   - P3 的文件/函数必须绑定到 entry；无绑定只能 NOT-APPLICABLE / UNPROVEN；
 *   - P6 一条 action 可能对应多个 site，**判定单位是 site**；
 *   - 1a：68 条 reachable-unbound 按函数级可达性重分类，标记 `entryBinding=callgraph-name-only`，
 *     不冒充 file-entry；
 *   - 2a：owner-aware producer 解析；owner 不在范围内或候选不唯一 -> unproven。
 */

const { readJsonl } = require('./util.js');

const OS_ACCOUNT = 'base/account/os_account';

function normSymbol(symbol) {
  return String(symbol || '').replace(/\s+/g, '');
}

function lastSymbolPart(symbol) {
  const s = normSymbol(symbol);
  const idx = s.lastIndexOf('::');
  return idx >= 0 ? s.slice(idx + 2) : s;
}

class L2 {
  constructor(l1) {
    this.l1 = l1;
    this._cache = {};
  }

  /** 文件 -> entries[]（按 entryKey 去重） */
  entryForFile(repo, file) {
    const key = `${repo}\u0000${file}`;
    if (this._cache.entryForFile && this._cache.entryForFile.key === key) return this._cache.entryForFile.rows;
    const rows = this.l1.entries().filter((e) => e.repo === repo && e.site && e.site.file === file);
    const seen = new Set();
    const out = [];
    for (const e of rows) {
      if (seen.has(e.entryKey)) continue;
      seen.add(e.entryKey);
      out.push(e);
    }
    this._cache.entryForFile = { key, rows: out };
    return out;
  }

  /** 函数 -> entries[]：优先 symbol / 文件行号，再退回同文件入口 */
  entriesForFunction(repo, file, functionName, startLine = null, endLine = null) {
    const bySymbol = this._symbolEntryIndex();
    const name = lastSymbolPart(functionName);
    const direct = (bySymbol.get(name) || []).filter((e) => e.repo === repo);
    const inFile = [];
    for (const e of this.entryForFile(repo, file)) {
      const line = e.site && e.site.line;
      if (startLine != null && endLine != null && line != null) {
        if (line >= startLine && line <= endLine) inFile.push(e);
      } else {
        inFile.push(e);
      }
    }
    const all = [];
    const seen = new Set();
    for (const e of [...direct, ...inFile]) {
      if (seen.has(e.entryKey)) continue;
      seen.add(e.entryKey);
      all.push(e);
    }
    return all;
  }

  _symbolEntryIndex() {
    if (!this._cache.symbolEntryIndex) {
      const map = new Map();
      for (const e of this.l1.entries()) {
        const sym = e.site && e.site.symbol;
        if (!sym) continue;
        for (const name of new Set([normSymbol(sym), lastSymbolPart(sym)])) {
          if (!name) continue;
          if (!map.has(name)) map.set(name, []);
          map.get(name).push(e);
        }
      }
      this._cache.symbolEntryIndex = map;
    }
    return this._cache.symbolEntryIndex;
  }

  /**
   * 1a：对 182 个 deref 重新分类。
   * entryBinding ∈ {file-entry, callgraph-name-only, unreachable}
   *
   * 只有 entry.site.file 与函数文件相同、且 entry 行落在函数内，才算 file-entry；
   * 仅靠 IDL method 名/调用图命中的一律标 callgraph-name-only，不冒充 file-entry。
   */
  derefClassification() {
    if (this._cache.derefClassification) return this._cache.derefClassification;
    const rows = [];
    const findEntryByReverseBfs = this._makeReverseEntryFinder();
    const allEntries = this.l1.entries();
    for (const probe of this.l1.derefs()) {
      const reach = this.l1.derefReachability(probe.id);
      const functionId = reach ? reach.functionId : null;
      const fn = functionId ? this.l1.getFunctionById(functionId) : null;
      const sameFile = allEntries.filter((e) => e.repo === probe.repo && e.site && e.site.file === probe.file
        && (fn == null || e.site.line == null || (e.site.line >= fn.startLine && e.site.line <= fn.endLine)));
      let entryBinding;
      let entryKey = null;
      let depth = reach ? reach.depth : null;
      let seedReason = 'file-entry';
      if (!reach || !reach.reachable) {
        entryBinding = 'unreachable';
      } else if (sameFile.length) {
        entryBinding = 'file-entry';
        entryKey = sameFile[0].entryKey;
      } else {
        entryBinding = 'callgraph-name-only';
        if (reach.seed && reach.seed.entryKey) {
          entryKey = reach.seed.entryKey;
          seedReason = reach.seed.reason || 'idl-method-name';
        } else {
          const found = functionId ? findEntryByReverseBfs(functionId) : null;
          if (found) {
            entryKey = found.entryKey;
            depth = found.depth;
            seedReason = 'callgraph';
          } else {
            seedReason = 'callgraph-no-entry-found';
          }
        }
      }
      rows.push({
        id: probe.id,
        repo: probe.repo,
        file: probe.file,
        line: probe.line,
        function: probe.function,
        functionId,
        reachable: !!(reach && reach.reachable),
        depth,
        entryBinding,
        entryKey,
        seedReason,
        producer: probe.producer,
        producerMayNull: probe.producerMayNull,
        guardBefore: probe.guardBefore,
        status: probe.status
      });
    }
    const summary = {
      total: rows.length,
      reachable: rows.filter((r) => r.reachable).length,
      unreachable: rows.filter((r) => !r.reachable).length,
      entryBinding: rows.reduce((a, r) => { a[r.entryBinding] = (a[r.entryBinding] || 0) + 1; return a; }, {}),
      callgraphNameOnly: rows.filter((r) => r.entryBinding === 'callgraph-name-only').length,
      unboundCallgraphNameOnly: rows.filter((r) => r.entryBinding === 'callgraph-name-only' && (this.l1.derefById(r.id).entryCount === 0)).length,
      withEntryKey: rows.filter((r) => r.entryKey).length,
      seedReasons: rows.filter((r) => r.reachable).reduce((a, r) => { a[r.seedReason] = (a[r.seedReason] || 0) + 1; return a; }, {})
    };
    this._cache.derefClassification = rows;
    this._cache.derefClassificationSummary = summary;
    return rows;
  }

  _makeReverseEntryFinder() {
    const targetMap = new Map();
    for (const e of this.l1.entries()) {
      const sym = e.site && e.site.symbol;
      if (!sym) continue;
      for (const name of new Set([normSymbol(sym), lastSymbolPart(sym)])) {
        if (!name) continue;
        if (!targetMap.has(name)) targetMap.set(name, e);
      }
    }
    const cache = new Map();
    return (functionId) => {
      if (cache.has(functionId)) return cache.get(functionId);
      const seen = new Set([functionId]);
      let frontier = [functionId];
      let depth = 0;
      while (frontier.length && depth < 8) {
        depth += 1;
        const next = [];
        for (const fid of frontier) {
          for (const caller of this.l1.callers(fid, 200)) {
            if (!caller.functionId || seen.has(caller.functionId)) continue;
            seen.add(caller.functionId);
            const fn = this.l1.getFunctionById(caller.functionId);
            if (fn) {
              const hit = targetMap.get(fn.name);
              if (hit) {
                const out = { entryKey: hit.entryKey, depth, via: caller.functionId };
                cache.set(functionId, out);
                return out;
              }
            }
            next.push(caller.functionId);
          }
        }
        frontier = next;
      }
      cache.set(functionId, null);
      return null;
    };
  }

  reachableDerefs() {
    return this.derefClassification().filter((r) => r.reachable);
  }

  /** 105 条 unreachable-unbound + 可达但无法绑定的记录 */
  unreachableDerefs() {
    return this.derefClassification().filter((r) => !r.reachable);
  }

  /** isReachable(functionId) -> depth / false */
  isReachable(functionId) {
    const r = this.l1.reachabilityOfFunction(functionId);
    if (!r || !r.reachable) return false;
    return { reachable: true, depth: r.depth, derefId: r.derefId };
  }

  actionForRecord(recordId) {
    const actions = this.l1.actionsByRecord(recordId);
    if (!actions.length) return null;
    const payload = this.l1.p6Payload(recordId);
    return { ...actions[0], payload: payload || null, rowCount: actions.length };
  }

  actionForSite(siteKey) {
    const site = this.l1.minerSite(siteKey);
    if (!site) return null;
    const records = (site.src && site.src.recordIds) || [];
    for (const rec of records) {
      const action = this.actionForRecord(rec);
      if (action) return action;
    }
    return {
      recordId: records[0] == null ? null : records[0],
      action: site.action,
      sink: site.sink,
      subscriberPermissions: site.subscriberPermissions || [],
      directedSubscriberUids: site.directedSubscriberUids || [],
      thirdPartyReachability: site.thirdPartyReachability || null,
      payload: null
    };
  }

  /**
   * siteForAction(action) -> miner sites[]。
   * 默认只返回 os_account 发布点（miner 95 站点口径）；opts.all=true 返回全部 624 中的匹配。
   */
  siteForAction(action, opts = {}) {
    const list = this.l1.minerSitesForAction(action);
    if (opts.all) return list;
    return list.filter((s) => String((s.sink && s.sink.file) || '').includes(OS_ACCOUNT));
  }

  /** 95 个 os_account 站点 */
  p6Sites() {
    if (!this._cache.p6Sites) {
      this._cache.p6Sites = this.l1.minerSiteCount()
        ? (() => {
          const out = [];
          for (const site of this.l1._siteIndex().rows) {
            if (String((site.sink && site.sink.file) || '').includes(OS_ACCOUNT)) out.push(site);
          }
          return out;
        })()
        : [];
    }
    return this._cache.p6Sites;
  }

  /**
   * 2a：owner-aware producer 解析。
   * 从 deref 文本抽 `owner::method`；owner 不在范围内/候选不唯一 -> unproven。
   */
  resolveProducer(repo, derefRow) {
    const name = derefRow && derefRow.producer;
    const text = String((derefRow && derefRow.text) || '');
    if (!name) return { status: 'unproven', reason: 'producer-unresolved', evidence: {} };
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const ownerMatch = new RegExp(`([A-Za-z_]\\w*(?:::\\w+)*)\\s*::\\s*${escaped}\\s*\\(`).exec(text);
    const owner = ownerMatch ? ownerMatch[1] : null;
    if (!owner) {
      return { status: 'unproven', reason: 'owner-not-resolved', evidence: { producer: name } };
    }
    const candidates = this.l1.producersByName(name, repo).filter((prod) => {
      const lines = this.l1.sourceLines(prod.repo, prod.file);
      if (!lines) return false;
      const head = lines.slice(Math.max(0, prod.startLine - 4), Math.min(lines.length, prod.startLine + 3)).join('\n');
      return head.includes(`${owner}::${name}`);
    });
    if (candidates.length === 0) {
      return { status: 'unproven', reason: 'producer-not-in-scope', evidence: { producer: name, owner } };
    }
    if (candidates.length > 1) {
      return { status: 'unproven', reason: 'producer-ambiguous', evidence: { producer: name, owner, candidates: candidates.length } };
    }
    const prod = candidates[0];
    const body = this.producerBody(prod);
    const nullablePattern = /return\s+(nullptr|NULL)\b|new\s*\(\s*std::nothrow|malloc\s*\(|calloc\s*\(|realloc\s*\(|\.find\s*\(|\.get\s*\(/.test(body);
    const evidence = {
      producer: prod.name,
      owner,
      functionId: prod.functionId,
      file: prod.file,
      startLine: prod.startLine,
      returnType: prod.returnType,
      pointerLike: !!prod.pointerLike,
      typeKnown: !!prod.typeKnown,
      nullablePattern
    };
    if (prod.typeKnown && prod.pointerLike && nullablePattern) return { status: 'proven', evidence };
    if (prod.typeKnown && !prod.pointerLike && !nullablePattern) return { status: 'disproven', evidence, reason: 'non-pointer-type' };
    return {
      status: 'unproven',
      reason: !prod.typeKnown ? 'producer-type-unknown' : (!nullablePattern ? 'no-null-pattern' : 'producer-type-not-pointer'),
      evidence
    };
  }

  producerBody(prod) {
    const fn = this.l1
      .functionsOfFile(prod.repo, prod.file)
      .find((f) => f.name === prod.name && f.startLine === prod.startLine);
    const lines = this.l1.sourceLines(prod.repo, prod.file);
    if (!lines) return '';
    if (fn) return lines.slice(fn.startLine - 1, fn.endLine).join('\n');
    return lines.slice(Math.max(0, prod.startLine - 2), Math.min(lines.length, prod.startLine + 80)).join('\n');
  }

  summary() {
    const cls = this.derefClassification();
    return {
      entries: this.l1.entries().length,
      actions: this.l1.actions().length,
      p6Sites: this.p6Sites().length,
      derefs: cls.length,
      reachable: cls.filter((r) => r.reachable).length,
      unreachable: cls.filter((r) => !r.reachable).length,
      entryBinding: cls.reduce((a, r) => { a[r.entryBinding] = (a[r.entryBinding] || 0) + 1; return a; }, {})
    };
  }
}

function loadL2(l1) {
  return new L2(l1);
}

module.exports = { L2, loadL2, OS_ACCOUNT };
