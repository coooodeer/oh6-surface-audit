'use strict';

/**
 * tools/autonomy-r2-ipc-probe.js —— R2-D3：ipc 生产 OnRemoteRequest 的对象/code 派发最小探针。
 *
 * 对 ipc scope L1 中的每个生产 OnRemoteRequest 实现：
 *   1) 读函数体源码窗口（L1 startLine..endLine）；
 *   2) 提取派发形状：switch(code) 的 case 常量与 handler 调用 / 其他形状；
 *   3) 在组件头文件中解析 case 常量定义（file:line 证据）；
 *   4) handler 是否为同一对象（this 分派）的成员：L1 中查同名成员函数。
 * 一个 case 的 code 常量与 handler 都可定位 ⇒ 该分派边 resolved-dispatch；
 * 否则 entry 保持 suspect/unbound 并注明形状。不遍历全域 1,116 处（R3 范畴）。
 *
 * 只读。输出 --out（默认 out/autonomy/inventory/r2-ipc-dispatch-probe.json）。
 *
 * 用法：node tools/autonomy-r2-ipc-probe.js [--scope=ipc-r2] [--out=<file>]
 */

const fs = require('node:fs');
const path = require('node:path');

const factsLib = require('../lib/autonomy/facts');
const scopeLib = require('../lib/facts/scope');

const TOOL_DIR = path.resolve(__dirname, '..');
const SRC_ROOT = scopeLib.SRC_ROOT;

function parseArgs(argv) {
  const out = { scope: 'ipc-r2', out: null };
  for (const a of argv) {
    if (a.startsWith('--scope=')) out.scope = a.slice('--scope='.length);
    else if (a.startsWith('--out=')) out.out = a.slice('--out='.length);
    else throw new Error(`unknown-arg: ${a}`);
  }
  return out;
}

function relOf(abs) {
  return scopeLib.posix(path.relative(SRC_ROOT, abs));
}

function listHeaderFiles(rootAbs) {
  const out = [];
  const stack = [rootAbs];
  while (stack.length) {
    const dir = stack.pop();
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const ent of ents) {
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!['.git', 'out', 'test', 'tests', 'unittest', 'fuzztest', 'mock', 'moduletest'].includes(ent.name)) stack.push(p);
        continue;
      }
      if (/\.(h|hh|hpp)$/.test(p)) out.push(p);
    }
  }
  return out;
}

/** 解析函数体窗口中的 switch(code) case 表 */
function extractSwitchCases(bodyText) {
  const cases = [];
  if (!/switch\s*\(\s*code\s*\)/.test(bodyText)) return { shape: 'other', cases };
  const caseRe = /case\s+([A-Za-z_][\w.]*)\s*:\s*\{([^{}]*)\}/g;
  let m;
  while ((m = caseRe.exec(bodyText)) !== null) {
    const body = m[2];
    const call = /([A-Za-z_]\w*)\s*\(/.exec(body.replace(/^(?:\s|result\s*=\s*)/, ''));
    cases.push({
      codeConst: m[1],
      handler: call ? call[1] : null,
      bodyPreview: body.trim().slice(0, 120)
    });
  }
  return { shape: 'switch-codes', cases };
}

function analyzeEntry(fn, idx, headerIndex) {
  const fileAbs = path.join(SRC_ROOT, fn.sourceRange.file.split('/').join(path.sep));
  let text = '';
  try { text = fs.readFileSync(fileAbs, 'utf8'); } catch (_) { /* keep empty */ }
  const lines = text.split('\n');
  const start = Math.max(0, (fn.startLine || 1) - 1);
  const end = Math.min(lines.length, fn.endLine || start + 80);
  const body = lines.slice(start, end + 1).join('\n');

  const dispatch = extractSwitchCases(body);
  // owner 字段即类限定名（如 OHOS::DBinderServiceStub），不能再切最后一段——
  // 那会把前缀砍成命名空间，导致跨类同名方法误绑。
  const ownerPrefix = String(fn.owner || '').trim();
  const resolvedEdges = [];
  const unresolvedEdges = [];
  for (const c of dispatch.cases || []) {
    const def = headerIndex.get(c.codeConst) || null;
    // handler 必须是同对象（C++ 同 owner 类前缀）的成员；C 函数（owner 为空且
    // qualified 无 ::）退而要求与入口同一翻译单元。禁止退回任意同名函数。
    let handlerRow = null;
    let sameObject = false;
    if (c.handler) {
      if (ownerPrefix && ownerPrefix.includes('::')) {
        handlerRow = idx.functions.find((f) => f.name === c.handler
          && String(f.qualified || '').startsWith(`${ownerPrefix}::`)) || null;
        sameObject = !!handlerRow;
      } else {
        handlerRow = idx.functions.find((f) => f.name === c.handler
          && f.sourceRange && f.sourceRange.file === fn.sourceRange.file) || null;
        sameObject = handlerRow ? 'same-file-c' : false;
      }
    }
    const edge = {
      codeConst: c.codeConst,
      codeDef: def ? `${def.file}:${def.line}` : null,
      handler: c.handler,
      handlerDef: handlerRow ? `${handlerRow.sourceRange.file}:${handlerRow.startLine}` : null,
      handlerQualified: handlerRow ? handlerRow.qualified : null,
      sameObjectDispatch: sameObject,
      unresolvedReason: !def ? 'code-constant-definition-not-in-component'
        : !handlerRow ? (ownerPrefix ? 'handler-not-a-method-of-same-object' : 'handler-not-in-same-translation-unit')
        : null
    };
    if (def && handlerRow) resolvedEdges.push(edge);
    else unresolvedEdges.push(edge);
  }
  const shape = dispatch.cases.length ? dispatch.shape
    : (/\bcase\s+/.test(body) ? 'switch-unparsed' : 'other');
  return {
    entry: {
      object: fn.owner || fn.qualified,
      qualified: fn.qualified,
      file: fn.sourceRange.file,
      startLine: fn.startLine,
      endLine: fn.endLine
    },
    shape,
    resolvedDispatchEdges: resolvedEdges,
    unresolvedDispatchEdges: unresolvedEdges,
    dispatchModel: resolvedEdges.length > 0 ? 'resolved-dispatch'
      : (dispatch.cases.length > 0 ? 'suspect' : 'unbound'),
    note: resolvedEdges.length > 0
      ? 'code 常量定义在组件头文件中定位，handler 为同对象成员（C++ 同 owner 前缀 / C 同翻译单元）'
      : (dispatch.cases.length > 0
        ? 'case 常量或同对象 handler 未能定位（R3 补 per-code 绑定）；不退回任意同名函数'
        : '无 switch(code) 可解析派发表')
  };
}

function main(argv = []) {
  const args = parseArgs(argv);
  const policy = JSON.parse(fs.readFileSync(path.join(TOOL_DIR, 'K', 'policies', `scope-${args.scope}.json`), 'utf8'));
  const facts = factsLib.AutonomyFacts.open({ snapshot: 'latest', scope: policy });
  const idx = facts.index();

  const componentRoot = policy.roots[0].root;
  const rootAbs = path.join(SRC_ROOT, componentRoot.split('/').join(path.sep));
  const headerIndex = new Map();
  for (const hf of listHeaderFiles(rootAbs)) {
    const text = fs.readFileSync(hf, 'utf8');
    const rel = relOf(hf);
    const re = /\b([A-Z][A-Z0-9_]+)\s*=\s*[^,;\n]+/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (!headerIndex.has(m[1])) headerIndex.set(m[1], { file: rel, line: text.slice(0, m.index).split('\n').length });
    }
    const defRe = /#define\s+([A-Z][A-Z0-9_]+)\b/g;
    while ((m = defRe.exec(text)) !== null) {
      if (!headerIndex.has(m[1])) headerIndex.set(m[1], { file: rel, line: text.slice(0, m.index).split('\n').length });
    }
  }

  // 分母口径：精确名 OnRemoteRequest 的生产实现（=R0 ipc-dispatch 的 7 条）；
  // *OnRemoteRequest* 辅助函数（Inner/Callback/TraceInfo 等）是分派邻接函数，不是入口。
  const entries = idx.functions
    .filter((f) => (f.role || 'production') === 'production' && f.name === 'OnRemoteRequest')
    .map((fn) => analyzeEntry(fn, idx, headerIndex));
  const adjacent = idx.functions
    .filter((f) => (f.role || 'production') === 'production' && f.name !== 'OnRemoteRequest'
      && /OnRemoteRequest/.test(f.name || ''))
    .map((f) => ({ name: f.name, file: f.sourceRange.file, line: f.startLine }));

  const dist = { 'resolved-dispatch': 0, suspect: 0, unbound: 0 };
  for (const e of entries) dist[e.dispatchModel] = (dist[e.dispatchModel] || 0) + 1;

  const result = {
    experimentVersion: 'r2-ipc-dispatch-probe-v1',
    generatedAt: new Date().toISOString(),
    scope: args.scope,
    snapshotId: facts.snapshotId,
    totalOnRemoteRequest: entries.length,
    adjacentFunctions: { count: adjacent.length, rows: adjacent },
    dist,
    entries,
    note: 'ipc 0 个 IDL/SA 入口不等于无生产入口；本探针给出对象/code 分派边的可定位模型。'
      + '全域 1,116 处 OnRemoteRequest 的 per-code 绑定属 R3，不在此冒充完成。'
  };
  const outFile = args.out || path.join(TOOL_DIR, 'out', 'autonomy', 'inventory', 'r2-ipc-dispatch-probe.json');
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({
    ok: true, totalOnRemoteRequest: entries.length, dist,
    resolvedSamples: entries.flatMap((e) => e.resolvedDispatchEdges).slice(0, 6),
    out: path.relative(TOOL_DIR, outFile).split(path.sep).join('/')
  })}\n`);
  return 0;
}

module.exports = { main, analyzeEntry, extractSwitchCases };

if (require.main === module) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (e) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: e.message })}\n`);
    process.exitCode = 1;
  }
}
