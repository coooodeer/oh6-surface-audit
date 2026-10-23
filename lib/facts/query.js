'use strict';

/**
 * lib/facts/query.js —— AG0.4 Query API（进程内、只读、可回查）。
 *
 * 接口：Qname / Qast / Qcg / getSource / getType / findCheckSites / Qflow。
 * 每个结果都带 {snapshotId, factRefs, sourceRange, quality}。
 *
 * 设计：
 *   - JSONL 一律流式扫描，避免把 240 MB 的 calls.jsonl 读进内存；
 *   - Qast 需要 AST，按需用 tree-sitter 重新解析单个文件（ms 级）；
 *   - getType 默认 syntax-only；--exact 走 clang 定向 AST（拼接 JSON 需平衡括号切片）；
 *   - Qflow 固定 unsupported（DFG 粒度不足）。
 */

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const scope = require('./scope');
const compdb = require('./compdb');
const { buildArgs } = require('./cmdline');

const CHUNK = 1 << 20;

/** 流式逐行读 JSONL */
function forEachRow(file, cb) {
  if (!fs.existsSync(file)) return 0;
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(CHUNK);
  let carry = '';
  let count = 0;
  try {
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      const text = carry + buf.toString('utf8', 0, n);
      const parts = text.split('\n');
      carry = parts.pop();
      for (const line of parts) {
        if (!line) continue;
        let row;
        try { row = JSON.parse(line); } catch (_) { continue; }
        count += 1;
        if (cb(row) === false) return count;
      }
    }
    if (carry) {
      try { const row = JSON.parse(carry); count += 1; cb(row); } catch (_) { /* 尾行损坏忽略 */ }
    }
  } finally {
    fs.closeSync(fd);
  }
  return count;
}

function wrap(row, extra = {}) {
  return {
    snapshotId: row.snapshotId,
    factRefs: [row.factId].filter(Boolean),
    sourceRange: row.sourceRange,
    quality: row.quality,
    ...extra
  };
}

class FactsIndex {
  constructor(dir, opts = {}) {
    this.dir = dir;
    this.snapshot = JSON.parse(fs.readFileSync(path.join(dir, 'snapshot.json'), 'utf8'));
    this.snapshotId = this.snapshot.snapshotId;
    this.sourceRoot = opts.sourceRoot || scope.SRC_ROOT;
  }

  l1(name) { return path.join(this.dir, 'l1', `${name}.jsonl`); }

  /** Qname：按名字查函数/符号（大小写不敏感子串；--regex 可选） */
  Qname(pattern, opts = {}) {
    const re = opts.regex ? new RegExp(pattern, 'i') : null;
    const match = (s) => (re ? re.test(String(s || '')) : String(s || '').toLowerCase().includes(String(pattern).toLowerCase()));
    const kinds = opts.kind ? [opts.kind] : ['function', 'symbol'];
    const out = [];
    if (kinds.includes('function')) {
      forEachRow(this.l1('functions'), (row) => {
        if (opts.repo && row.locator && row.locator.repo !== opts.repo) return;
        if (!match(row.name) && !match(row.qualified)) return;
        out.push(wrap(row, { kind: 'function', name: row.name, qualified: row.qualified, owner: row.owner, signature: row.signature }));
        if (out.length >= (opts.limit || 50)) return false;
      });
    }
    if (kinds.includes('symbol') && out.length < (opts.limit || 50)) {
      forEachRow(this.l1('symbols'), (row) => {
        if (opts.repo && row.locator && row.locator.repo !== opts.repo) return;
        if (!match(row.name)) return;
        out.push(wrap(row, { kind: 'symbol', name: row.name, symbolKind: row.symbolKind }));
        if (out.length >= (opts.limit || 50)) return false;
      });
    }
    return out;
  }

  /** Qast：在指定文件的区间内找某类语法结构（按需重解析） */
  Qast(operation, opts = {}) {
    const ops = {
      call: new Set(['call_expression']),
      assign: new Set(['assignment_expression']),
      deref: new Set(['pointer_expression']),
      subscript: new Set(['subscript_expression']),
      'switch-case': new Set(['case_statement'])
    };
    const types = ops[operation];
    if (!types) throw new Error(`unsupported-operation: ${operation}（可用：${Object.keys(ops).join('|')}）`);
    const rel = String(opts.file || '').split(path.sep).join('/');
    if (!rel) throw new Error('file-required');
    const abs = path.join(this.sourceRoot, rel.split('/').join(path.sep));
    if (!fs.existsSync(abs)) throw new Error(`file-missing: ${rel}`);
    const mods = path.join(scope.WORKSPACE, 'oh6-framework-want-leak-miner', 'node_modules');
    const Parser = require(path.join(mods, 'tree-sitter'));
    const Cpp = require(path.join(mods, 'tree-sitter-cpp'));
    const C = require(path.join(mods, 'tree-sitter-c'));
    const text = fs.readFileSync(abs, 'utf8');
    const parser = new Parser();
    parser.setLanguage(/\.c$/i.test(rel) ? C : Cpp);
    const tree = parser.parse(text, null, { bufferSize: 1024 * 1024 });
    const startLine = opts.startLine || 1;
    const endLine = opts.endLine || Number.MAX_SAFE_INTEGER;
    const out = [];
    const stack = [tree.rootNode];
    while (stack.length) {
      const n = stack.pop();
      if (types.has(n.type)) {
        const line = n.startPosition.row + 1;
        if (line >= startLine && line <= endLine) {
          out.push({
            snapshotId: this.snapshotId,
            factRefs: [],
            sourceRange: { file: rel, startLine: line, endLine: n.endPosition.row + 1 },
            quality: { parse: tree.rootNode.hasError ? 'partial' : 'full', resolution: 'syntax-only' },
            operation,
            text: n.text.replace(/\s+/g, ' ').slice(0, 240),
            column: n.startPosition.column
          });
          if (out.length >= (opts.limit || 200)) break;
        }
      }
      for (let i = 0; i < n.namedChildCount; i += 1) stack.push(n.namedChild(i));
    }
    out.sort((a, b) => a.sourceRange.startLine - b.sourceRange.startLine || a.column - b.column);
    return out;
  }

  /** Qcg：按函数名查调用边（callees=该函数调用了谁；callers=谁调用了它） */
  Qcg(fnName, opts = {}) {
    const direction = opts.direction || 'callees';
    const out = [];
    forEachRow(this.l1('calls'), (row) => {
      const hit = direction === 'callers'
        ? row.calleeName === fnName
        : row.callerName === fnName;
      if (!hit) return;
      out.push(wrap(row, {
        direction,
        caller: row.caller,
        callerName: row.callerName,
        calleeName: row.calleeName,
        callee: row.callee,
        argc: row.argc,
        line: row.line
      }));
      if (out.length >= (opts.limit || 200)) return false;
    });
    return out;
  }

  /** getSource：返回源码窗口（唯一允许绕开 facts 读源码的入口） */
  getSource(file, line, count = 3) {
    const rel = String(file || '').split(path.sep).join('/');
    const abs = path.join(this.sourceRoot, rel.split('/').join(path.sep));
    if (!fs.existsSync(abs)) throw new Error(`file-missing: ${rel}`);
    const lines = fs.readFileSync(abs, 'utf8').split(/\r?\n/);
    const start = Math.max(1, line - Math.floor(count / 2));
    const end = Math.min(lines.length, start + count - 1);
    return {
      snapshotId: this.snapshotId,
      factRefs: [],
      sourceRange: { file: rel, startLine: start, endLine: end },
      quality: { parse: 'full', resolution: 'syntax-only' },
      text: lines.slice(start - 1, end).join('\n'),
      totalLines: lines.length
    };
  }

  /** findCheckSites：函数内的条件守卫 + 汇点（通用事实，不含类语义） */
  findCheckSites(fnName, opts = {}) {
    const guards = [];
    const sinks = [];
    forEachRow(this.l1('guards'), (row) => {
      if (row.functionName !== fnName) return;
      guards.push(wrap(row, { guardKind: row.guardKind, variables: row.variables, line: row.line }));
      if (guards.length >= (opts.limit || 100)) return false;
    });
    forEachRow(this.l1('sinks'), (row) => {
      if (row.functionName !== fnName) return;
      sinks.push(wrap(row, { sinkKind: row.sinkKind, calleeName: row.calleeName, argc: row.argc, line: row.line }));
      if (sinks.length >= (opts.limit || 100)) return false;
    });
    return {
      snapshotId: this.snapshotId,
      function: fnName,
      guards,
      sinks,
      factRefs: [...guards, ...sinks].flatMap((r) => r.factRefs),
      sourceRange: (guards[0] || sinks[0] || {}).sourceRange || null,
      quality: (guards[0] || sinks[0] || {}).quality || null
    };
  }

  /** getType：默认从 types.jsonl 取 syntax-only；--exact 走定向 AST */
  getType(target, opts = {}) {
    const isLoc = /^(.+):(\d+)$/.test(String(target));
    const file = isLoc ? String(target).replace(/:\d+$/, '') : opts.file;
    const line = isLoc ? Number(String(target).match(/:(\d+)$/)[1]) : opts.line;
    const rows = [];
    forEachRow(this.l1('types'), (row) => {
      if (isLoc) {
        if (row.file !== file || (line && Math.abs(row.line - line) > 3)) return;
      } else if (row.expr !== target) return;
      rows.push(wrap(row, { expr: row.expr, type: row.type, typeKind: row.typeKind, resolution: row.quality.resolution }));
      if (rows.length >= (opts.limit || 20)) return false;
    });
    if (!opts.exact || !file) return { snapshotId: this.snapshotId, target, mode: 'syntax-only', rows };
    // file:line 形式时，用同位置 types 行里的表达式名做 ast-dump-filter
    const name = !isLoc ? String(target) : ((rows[0] && rows[0].expr) || opts.expr || null);
    if (!name) return { snapshotId: this.snapshotId, target, mode: 'exact', rows, exact: { ok: false, reason: 'no-expr-for-loc' } };
    const exact = this.getTypeExact(file, name, line);
    return { snapshotId: this.snapshotId, target, mode: 'exact', rows, exact };
  }

  /** 定向 AST：clang -ast-dump-filter，输出是拼接 JSON，需要平衡括号切片 */
  getTypeExact(file, name, line) {
    try {
      const entry = this.findCompdbEntry(file);
      if (!entry) return { ok: false, reason: 'no-compdb-entry' };
      const { compiler, args } = buildArgs(entry.command);
      const exe = path.join(scope.SRC_ROOT, 'prebuilts', 'clang', 'ohos', 'windows-x86_64', 'llvm', 'bin',
        path.posix.basename(compiler) === 'clang' ? 'clang.exe' : 'clang++.exe');
      if (!fs.existsSync(exe)) return { ok: false, reason: 'clang-missing' };
      const win = args.map((a) => (a.startsWith('-I/mnt/') ? `-I${compdb.wslToWin(a.slice(2))}` : (a.startsWith('/mnt/') ? compdb.wslToWin(a) : a)));
      const full = [...win, '-fsyntax-only', '-Xclang', '-ast-dump=json', '-Xclang', `-ast-dump-filter=${name}`];
      const rsp = path.join(scope.WORKSPACE, 'runtime', 'query-type.rsp');
      fs.mkdirSync(path.dirname(rsp), { recursive: true });
      fs.writeFileSync(rsp, full.map((a) => `"${a.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join('\n') + '\n', 'utf8');
      const cwd = path.join(scope.SRC_ROOT, 'out', 'rk3568');
      const r = cp.spawnSync(exe, [`@${rsp}`], { cwd, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, timeout: 120000, windowsHide: true });
      try { fs.unlinkSync(rsp); } catch (_) { /* ignore */ }
      if (r.error) return { ok: false, reason: `spawn:${r.error.code || 'error'}` };
      const objs = splitConcatenatedJson(r.stdout || '');
      for (const o of objs) {
        const t = findTypeInDecl(o, name, line);
        if (t) return { ok: true, type: t.qualType, kind: t.kind, resolution: 'exact' };
      }
      return { ok: false, reason: 'not-found-in-ast', objects: objs.length };
    } catch (e) {
      return { ok: false, reason: String(e.message || e) };
    }
  }

  findCompdbEntry(file) {
    const absWsl = `/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/${file}`;
    const parts = ['account', 'communication', 'notification', 'accesscontrol'];
    for (const part of parts) {
      const p = path.join(scope.SRC_ROOT, 'out', 'rk3568', 'compdb_parts', part, 'compile_commands.json');
      if (!fs.existsSync(p)) continue;
      const text = fs.readFileSync(p, 'utf8');
      const at = text.indexOf(`"file": "${absWsl}"`);
      if (at < 0) continue;
      const s = text.lastIndexOf('{"directory"', at);
      const e = text.indexOf('"}', text.indexOf('"_strategy"', at));
      if (s < 0 || e < 0) continue;
      try { return JSON.parse(text.slice(s, e + 2)); } catch (_) { return null; }
    }
    return null;
  }

  /** Qflow：固定 unsupported（DFG 只有函数内最近 def，不支撑跨函数数据流） */
  Qflow() {
    return {
      snapshotId: this.snapshotId,
      status: 'unsupported',
      reason: 'dfg-incomplete',
      detail: 'DFG 仅覆盖函数内最近 def-use；无别名/跨函数/分支合流建模，不能作为数据流结论'
    };
  }
}

/** 把 clang 的拼接 JSON 切成对象数组 */
function splitConcatenatedJson(text) {
  const out = [];
  let depth = 0;
  let inStr = false;
  let esc = false;
  let start = -1;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === '{') { if (depth === 0) start = i; depth += 1; continue; }
    if (ch === '}') {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        try { out.push(JSON.parse(text.slice(start, i + 1))); } catch (_) { /* 跳过坏块 */ }
        start = -1;
      }
    }
  }
  return out;
}

/** 在 AST decl 里找匹配名字的声明，取其 qualType */
function findTypeInDecl(obj, name, line) {
  const stack = [obj];
  while (stack.length) {
    const n = stack.pop();
    if (!n || typeof n !== 'object') continue;
    if (n.kind === 'VarDecl' && n.name === name && n.type) {
      return { qualType: n.type.qualType || null, kind: 'VarDecl' };
    }
    if (n.kind === 'FunctionDecl' && n.name === name && n.type) {
      return { qualType: n.type.qualType || null, kind: 'FunctionDecl' };
    }
    for (const k of Object.keys(n)) {
      const v = n[k];
      if (Array.isArray(v)) for (const x of v) if (x && typeof x === 'object') stack.push(x);
      else if (v && typeof v === 'object') stack.push(v);
    }
  }
  return null;
}

module.exports = { FactsIndex, forEachRow, splitConcatenatedJson, findTypeInDecl };
