'use strict';

/**
 * lib/autonomy/facts.js —— AG0 事实层的**只读适配**。
 *
 * 复用规则（§4）：`lib/facts/*` 一行不改；AG0 的三个已知缺陷在这里自行规避：
 *   1. `forEachRow` 跨块 UTF-8 截断 → 用 `lib/autonomy/jsonl.js` 的 StringDecoder 实现；
 *   2. `getSource` 无哈希校验 → 读源码后与 `l1/files.jsonl` 的 sha256 比对，不一致返回 `stale-input`；
 *   3. `Qcg` 每次全扫 254 MB → 这里一次性建作用域索引（只 JSON.parse 命中仓库的行）。
 *
 * 不变量：
 *   - `snapshotId` 在 open 时固定，运行中不得变化；
 *   - 13 张 `l1/*` 表必须齐全，缺表 ⇒ `missing=environment`；
 *   - 所有查询带显式上限（limit / maxLines / maxBytes）。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const jsonl = require('./jsonl');

const TOOL_DIR = path.resolve(__dirname, '..', '..');
const WORKSPACE = path.resolve(TOOL_DIR, '..');
const SRC_ROOT = path.join(WORKSPACE, 'OpenHarmony');
const FACTS_ROOT = path.join(TOOL_DIR, 'out', 'facts');

const TABLES = Object.freeze([
  'calls', 'cfg', 'dfg', 'files', 'functions', 'guards', 'locks',
  'quality', 'reads', 'sinks', 'symbols', 'types', 'writes'
]);

const METADATA_KINDS = Object.freeze(['idl', 'sa', 'napi', 'permission', 'ces', 'harness', 'unsupported']);

const DEFAULT_LIMITS = Object.freeze({
  maxIndexFunctions: 5000,
  maxIndexCalls: 20000,
  maxWindowLines: 80,
  maxEvidenceBytes: 262144
});

function fail(code, message, extra) {
  const e = new Error(message);
  e.code = code;
  if (extra) Object.assign(e, extra);
  return e;
}

function sha256File(abs) {
  return crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex');
}

function normRel(p) {
  return String(p || '').split(path.sep).join('/').replace(/^\/+/, '');
}

function absOf(rel) {
  return path.join(SRC_ROOT, normRel(rel).split('/').join(path.sep));
}

/** 解析 facts 目录：接受 sha256:<64hex> / 裸 64hex / 目录名 / latest */
function resolveFactsDir(snapshot) {
  const raw = String(snapshot || '');
  if (!raw) throw fail('snapshot-required', 'facts: --snapshot required (sha256:<64hex> | latest)');
  if (raw === 'latest') {
    const entries = fs.existsSync(FACTS_ROOT)
      ? fs.readdirSync(FACTS_ROOT).filter((n) => /^[0-9a-f]{64}$/.test(n))
      : [];
    if (!entries.length) throw fail('snapshot-missing', `facts: no snapshot under ${FACTS_ROOT}`);
    entries.sort((a, b) => {
      const ta = fs.statSync(path.join(FACTS_ROOT, a)).mtimeMs;
      const tb = fs.statSync(path.join(FACTS_ROOT, b)).mtimeMs;
      return tb - ta;
    });
    return path.join(FACTS_ROOT, entries[0]);
  }
  const hex = raw.replace(/^sha256:/, '');
  if (!/^[0-9a-f]{64}$/.test(hex)) throw fail('snapshot-invalid', `facts: bad snapshot id ${raw}`);
  const dir = path.join(FACTS_ROOT, hex);
  if (!fs.existsSync(path.join(dir, 'snapshot.json'))) throw fail('snapshot-missing', `facts: snapshot not built: ${hex}`);
  return dir;
}

class AutonomyFacts {
  constructor(dir, scope, opts = {}) {
    this.dir = dir;
    this.scope = scope || null;
    this.sourceRoot = opts.sourceRoot || SRC_ROOT;
    this.limits = { ...DEFAULT_LIMITS, ...(scope?.limits || {}), ...(opts.limits || {}) };
    const snapFile = path.join(dir, 'snapshot.json');
    if (!fs.existsSync(snapFile)) throw fail('snapshot-missing', `facts: snapshot.json missing in ${dir}`);
    this.snapshotDoc = JSON.parse(fs.readFileSync(snapFile, 'utf8'));
    this._snapshotId = this.snapshotDoc.snapshotId;
    if (!/^sha256:[0-9a-f]{64}$/.test(this._snapshotId)) {
      throw fail('snapshot-invalid', `facts: bad snapshotId in snapshot.json: ${this._snapshotId}`);
    }
    this._manifest = null;
    this._files = null;
    this._index = null;
    this._coverage = null;
    this._tableStatus = null;
  }

  static open({ snapshot, scope, sourceRoot, limits } = {}) {
    return new AutonomyFacts(resolveFactsDir(snapshot), scope, { sourceRoot, limits });
  }

  get snapshotId() { return this._snapshotId; }

  snapshot() { return this.snapshotDoc; }

  manifest() {
    if (!this._manifest) {
      const f = path.join(this.dir, 'manifest.json');
      this._manifest = fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : { manifestId: `AM-${'0'.repeat(16)}` };
    }
    return this._manifest;
  }

  /** 输入产物清单 id（AG0 的 AM-<16hex>），用于全部记录封套 */
  get inputManifestId() {
    const m = this.manifest();
    if (!/^AM-[0-9a-f]{16}$/.test(m.manifestId || '')) {
      throw fail('manifest-invalid', `facts: bad manifestId ${m.manifestId}`);
    }
    return m.manifestId;
  }

  l1(name) { return path.join(this.dir, 'l1', `${name}.jsonl`); }

  metadataFile(kind) { return path.join(this.dir, 'metadata', `${kind}.jsonl`); }

  tableStatus() {
    const rows = TABLES.map((name) => {
      const file = this.l1(name);
      let bytes = 0;
      let present = false;
      try { bytes = fs.statSync(file).size; present = true; } catch (_) { present = false; }
      return { name, file: `l1/${name}.jsonl`, present, bytes };
    });
    const meta = METADATA_KINDS.map((kind) => {
      const file = this.metadataFile(kind);
      let bytes = 0;
      let present = false;
      try { bytes = fs.statSync(file).size; present = true; } catch (_) { present = false; }
      return { name: kind, file: `metadata/${kind}.jsonl`, present, bytes };
    });
    this._tableStatus = { tables: rows, metadata: meta, missing: rows.filter((r) => !r.present).map((r) => r.name) };
    return this._tableStatus;
  }

  missingTables() { return this.tableStatus().missing; }

  assertTables() {
    const st = this.tableStatus();
    if (st.missing.length) {
      throw fail('missing-tables', `facts: missing l1 tables: ${st.missing.join(', ')}`, { missing: st.missing });
    }
    return true;
  }

  coverage() {
    if (!this._coverage) {
      this._coverage = jsonl.readJsonl(path.join(this.dir, 'coverage.jsonl')).rows;
    }
    return this._coverage;
  }

  /** l1/files.jsonl → Map<path, row>，用于 getEvidence 的 stale 检查 */
  fileRows() {
    if (this._files) return this._files;
    const res = jsonl.readJsonl(this.l1('files'), { strict: true });
    const map = new Map();
    for (const row of res.rows) {
      const rel = normRel(row.path || (row.locator && row.locator.file));
      if (!rel) continue;
      map.set(rel, row);
    }
    if (!map.size) throw fail('files-table-empty', 'facts: l1/files.jsonl produced no rows');
    this._files = { map, malformed: res.malformed.length, rows: res.rows.length };
    return this._files;
  }

  /** facts 记录的 (sha256, bytes, lines, role, repo) */
  fileHash(rel) {
    const key = normRel(rel);
    const row = this.fileRows().map.get(key);
    if (!row) return null;
    return {
      path: key,
      sha256: row.sha256 || null,
      bytes: row.bytes || 0,
      lines: row.lines || 0,
      role: row.role || null,
      repo: row.repo || (row.locator && row.locator.repo) || null,
      factId: row.factId || null
    };
  }

  /** 与磁盘现况比对；不一致 ⇒ stale-input（禁止据旧快照出结论） */
  verifyFile(rel, opts = {}) {
    const key = normRel(rel);
    const rec = this.fileHash(key);
    if (!rec) return { ok: false, path: key, reason: 'not-in-facts', expected: null, actual: null };
    const abs = path.join(this.sourceRoot, key.split('/').join(path.sep));
    if (!fs.existsSync(abs)) return { ok: false, path: key, reason: 'file-missing', expected: rec.sha256, actual: null };
    if (opts.skipHash) return { ok: true, path: key, reason: null, expected: rec.sha256, actual: rec.sha256, record: rec };
    const st = fs.statSync(abs);
    if (rec.bytes && st.size !== rec.bytes) {
      return { ok: false, path: key, reason: 'stale-input', expected: rec.sha256, actual: null, detail: `bytes ${st.size} != ${rec.bytes}` };
    }
    const actual = sha256File(abs);
    if (rec.sha256 && actual !== rec.sha256) {
      return { ok: false, path: key, reason: 'stale-input', expected: rec.sha256, actual, detail: 'sha256 mismatch' };
    }
    return { ok: true, path: key, reason: null, expected: rec.sha256, actual, record: rec };
  }

  /** 源码窗口（唯一允许读源码的入口）；超上限截断并声明 truncated */
  sourceWindow(rel, startLine, endLine, opts = {}) {
    const key = normRel(rel);
    const maxLines = opts.maxLines || this.limits.maxWindowLines;
    const abs = path.join(this.sourceRoot, key.split('/').join(path.sep));
    if (!fs.existsSync(abs)) throw fail('file-missing', `facts: file missing on disk: ${key}`);
    const text = fs.readFileSync(abs, 'utf8');
    const lines = text.split(/\r?\n/);
    const totalLines = lines.length;
    let s = Math.max(1, Math.floor(startLine || 1));
    let e = Math.min(totalLines, Math.floor(endLine || s + maxLines - 1));
    let truncated = false;
    if (e - s + 1 > maxLines) { e = s + maxLines - 1; truncated = true; }
    return {
      file: key,
      startLine: s,
      endLine: e,
      totalLines,
      lines: e - s + 1,
      truncated,
      text: lines.slice(s - 1, e).join('\n'),
      sha256: crypto.createHash('sha256').update(text, 'utf8').digest('hex')
    };
  }

  /** 作用域索引（一次构建、进程内缓存） */
  index() {
    if (this._index) return this._index;
    this.assertTables();
    const roots = (this.scope && this.scope.roots ? this.scope.roots : []).map((r) => r.root);
    if (!roots.length) throw fail('scope-roots-empty', 'facts: scope policy has no roots');
    const repoNeedles = roots.map((r) => `"repo":"${r}"`);
    const fileNeedles = roots.map((r) => `"${r}/`);

    const limits = this.limits;
    const functions = [];
    let functionsTruncated = false;
    for (const res of [jsonl.readJsonl(this.l1('functions'), { needles: repoNeedles })]) {
      if (res.malformed.length) throw fail('malformed-record', `facts: malformed functions rows: ${res.malformed.length}`);
      for (const row of res.rows) {
        const repo = row.locator && row.locator.repo;
        if (!roots.includes(repo)) continue;
        functions.push(row);
        if (functions.length >= limits.maxIndexFunctions) { functionsTruncated = true; break; }
      }
    }

    const calls = [];
    let callsTruncated = false;
    {
      const res = jsonl.readJsonl(this.l1('calls'), { needles: repoNeedles });
      if (res.malformed.length) throw fail('malformed-record', `facts: malformed calls rows: ${res.malformed.length}`);
      for (const row of res.rows) {
        const repo = row.locator && row.locator.repo;
        if (!roots.includes(repo)) continue;
        calls.push(row);
        if (calls.length >= limits.maxIndexCalls) { callsTruncated = true; break; }
      }
    }

    const guards = [];
    {
      const res = jsonl.readJsonl(this.l1('guards'), { needles: repoNeedles });
      for (const row of res.rows) {
        const repo = row.locator && row.locator.repo;
        if (roots.includes(repo)) guards.push(row);
      }
    }

    const sinks = [];
    {
      const res = jsonl.readJsonl(this.l1('sinks'), { needles: repoNeedles });
      for (const row of res.rows) {
        const repo = row.locator && row.locator.repo;
        if (roots.includes(repo)) sinks.push(row);
      }
    }

    const files = [];
    for (const row of this.fileRows().map.values()) {
      const repo = row.repo || (row.locator && row.locator.repo) || null;
      if (repo && roots.includes(repo)) files.push(row);
    }

    const metadata = {};
    for (const kind of ['idl', 'sa', 'napi']) {
      const res = jsonl.readJsonl(this.metadataFile(kind), { needles: fileNeedles });
      metadata[kind] = res.rows.filter((row) => roots.some((r) => String(row.sourceFile || '').startsWith(`${r}/`)));
    }

    const functionsByName = new Map();
    const functionsByQualified = new Map();
    for (const fn of functions) {
      const n = fn.name || '';
      if (!functionsByName.has(n)) functionsByName.set(n, []);
      functionsByName.get(n).push(fn);
      const q = fn.qualified || '';
      if (q) {
        if (!functionsByQualified.has(q)) functionsByQualified.set(q, []);
        functionsByQualified.get(q).push(fn);
      }
    }

    const callsByCaller = new Map();
    const callsByCallee = new Map();
    for (const c of calls) {
      const cn = c.callerName || '';
      if (!callsByCaller.has(cn)) callsByCaller.set(cn, []);
      callsByCaller.get(cn).push(c);
      const ce = c.calleeName || '';
      if (!callsByCallee.has(ce)) callsByCallee.set(ce, []);
      callsByCallee.get(ce).push(c);
    }

    const groupBy = (rows, keyFn) => {
      const m = new Map();
      for (const r of rows) {
        const k = keyFn(r);
        if (!k) continue;
        if (!m.has(k)) m.set(k, []);
        m.get(k).push(r);
      }
      return m;
    };

    this._index = {
      roots,
      functions,
      calls,
      guards,
      sinks,
      files,
      metadata,
      functionsByName,
      functionsByQualified,
      callsByCaller,
      callsByCallee,
      guardsByFunctionName: groupBy(guards, (g) => g.functionName),
      sinksByFunctionName: groupBy(sinks, (s) => s.functionName),
      truncated: { functions: functionsTruncated, calls: callsTruncated },
      limits,
      counts: {
        functions: functions.length,
        calls: calls.length,
        guards: guards.length,
        sinks: sinks.length,
        files: files.length,
        idl: metadata.idl.length,
        sa: metadata.sa.length,
        napi: metadata.napi.length
      }
    };
    return this._index;
  }

  /** 按名字找函数（精确名优先，其次 qualified 后缀） */
  findFunctions(name, opts = {}) {
    const idx = this.index();
    const limit = opts.limit || 20;
    const hits = [];
    for (const fn of idx.functionsByName.get(name) || []) hits.push(fn);
    if (!hits.length) {
      for (const [q, rows] of idx.functionsByQualified) {
        if (q === name || q.endsWith(`::${name}`)) hits.push(...rows);
        if (hits.length >= limit) break;
      }
    }
    return hits.slice(0, limit);
  }

  callsOf(callerName, opts = {}) {
    const idx = this.index();
    const limit = opts.limit || 200;
    return (idx.callsByCaller.get(callerName) || []).slice(0, limit);
  }

  callersOf(calleeName, opts = {}) {
    const idx = this.index();
    const limit = opts.limit || 200;
    return (idx.callsByCallee.get(calleeName) || []).slice(0, limit);
  }

  guardsOf(functionName, opts = {}) {
    const idx = this.index();
    return (idx.guardsByFunctionName.get(functionName) || []).slice(0, opts.limit || 100);
  }

  sinksOf(functionName, opts = {}) {
    const idx = this.index();
    return (idx.sinksByFunctionName.get(functionName) || []).slice(0, opts.limit || 100);
  }

  searchByName(query, opts = {}) {
    const idx = this.index();
    const q = String(query || '').toLowerCase();
    if (!q) throw fail('invalid-args', 'facts: empty query');
    const limit = opts.limit || 20;
    const out = [];
    for (const fn of idx.functions) {
      if (!String(fn.name || '').toLowerCase().includes(q) && !String(fn.qualified || '').toLowerCase().includes(q)) continue;
      out.push(fn);
      if (out.length >= limit) break;
    }
    return out;
  }
}

module.exports = {
  AutonomyFacts,
  resolveFactsDir,
  TABLES,
  METADATA_KINDS,
  DEFAULT_LIMITS,
  FACTS_ROOT,
  SRC_ROOT,
  WORKSPACE,
  TOOL_DIR,
  normRel,
  absOf,
  sha256File
};
