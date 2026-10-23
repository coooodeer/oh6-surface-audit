'use strict';
/* 临时探针：tree-sitter 全量解析 5 个 root，统计耗时/失败/节点规模。用完删除。 */
const fs = require('fs');
const path = require('path');

const WORKSPACE = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(WORKSPACE, 'OpenHarmony');
const MOD = path.join(WORKSPACE, 'oh6-framework-want-leak-miner', 'node_modules');
const Parser = require(path.join(MOD, 'tree-sitter'));
const Cpp = require(path.join(MOD, 'tree-sitter-cpp'));
const C = require(path.join(MOD, 'tree-sitter-c'));

const ROOTS = ['base/account/os_account', 'foundation/communication/dsoftbus', 'foundation/communication/ipc',
  'base/notification/eventhandler', 'base/accesscontrol/sandbox_manager'];
const SKIP = new Set(['.git', 'node_modules', 'third_party', 'prebuilts', 'out', 'build']);

function walk(dir, acc) {
  let ents;
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
  for (const e of ents) {
    const abs = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP.has(e.name)) walk(abs, acc); continue; }
    if (!e.isFile()) continue;
    const ext = path.extname(e.name).toLowerCase();
    if (['.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx'].includes(ext)) acc.push(abs);
  }
}

function main() {
  const parser = new Parser();
  const rows = [];
  let totalMs = 0;
  let bytes = 0;
  for (const root of ROOTS) {
    const files = [];
    walk(path.join(SRC, root.split('/').join(path.sep)), files);
    for (const abs of files) {
      const st = fs.statSync(abs);
      const text = fs.readFileSync(abs, 'utf8');
      const lang = abs.toLowerCase().endsWith('.c') ? C : Cpp;
      const t0 = process.hrtime.bigint();
      let err = null;
      let tree = null;
      try {
        parser.setLanguage(lang);
        tree = parser.parse(text, null, { bufferSize: 1024 * 1024 });
      } catch (e) {
        err = String(e.message || e);
      }
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      totalMs += ms;
      bytes += st.size;
      let fns = 0; let calls = 0; let ifs = 0; let loops = 0;
      if (tree) {
        const stack = [tree.rootNode];
        while (stack.length) {
          const n = stack.pop();
          if (n.type === 'function_definition') fns += 1;
          else if (n.type === 'call_expression') calls += 1;
          else if (n.type === 'if_statement' || n.type === 'switch_statement') ifs += 1;
          else if (n.type === 'for_statement' || n.type === 'while_statement' || n.type === 'do_statement') loops += 1;
          for (let i = 0; i < n.namedChildCount; i += 1) stack.push(n.namedChild(i));
        }
      }
      rows.push({
        root, rel: path.relative(SRC, abs).split(path.sep).join('/'), bytes: st.size, ms: Number(ms.toFixed(3)),
        hasError: tree ? tree.rootNode.hasError : null, error: err, fns, calls, ifs, loops
      });
    }
  }
  const failed = rows.filter((r) => r.error);
  const result = {
    files: rows.length, bytes, totalMs: Math.round(totalMs), avgMsPerFile: Number((totalMs / rows.length).toFixed(3)),
    errors: failed.length,
    errorSamples: failed.slice(0, 8).map((r) => ({ rel: r.rel, bytes: r.bytes, error: r.error })),
    hasErrorNodes: rows.filter((r) => r.hasError).length,
    functions: rows.reduce((a, b) => a + b.fns, 0),
    calls: rows.reduce((a, b) => a + b.calls, 0),
    branches: rows.reduce((a, b) => a + b.ifs, 0),
    loops: rows.reduce((a, b) => a + b.loops, 0),
    largestFiles: rows.sort((a, b) => b.bytes - a.bytes).slice(0, 5).map((r) => ({ rel: r.rel, bytes: r.bytes, ms: r.ms, error: r.error }))
  };
  fs.writeFileSync(path.join(__dirname, 'ts-sweep.json'), JSON.stringify({ result, rows }, null, 0), 'utf8');
  console.log(JSON.stringify(result, null, 2));
}

main();
