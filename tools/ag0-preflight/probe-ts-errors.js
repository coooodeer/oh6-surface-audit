'use strict';
/* 临时探针：tree-sitter 错误节点特征（哪些文件 ERROR、什么节点、集中在哪）。用完删除。 */
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
    if (e.isFile() && /\.(c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(e.name)) acc.push(abs);
  }
}

const parser = new Parser();
const stats = { files: 0, withError: 0, errorNodes: 0, missingNodes: 0, byType: {}, examples: [] };
const N = Number(process.argv[2] || 400);
const all = [];
for (const r of ROOTS) walk(path.join(SRC, r.split('/').join(path.sep)), all);
all.sort();
const step = Math.max(1, Math.floor(all.length / N));
for (let i = 0; i < all.length; i += step) {
  const abs = all[i];
  let text;
  try { text = fs.readFileSync(abs, 'utf8'); } catch (_) { continue; }
  parser.setLanguage(abs.toLowerCase().endsWith('.c') ? C : Cpp);
  let tree;
  try { tree = parser.parse(text, null, { bufferSize: 1024 * 1024 }); } catch (_) { continue; }
  stats.files += 1;
  if (!tree.rootNode.hasError) continue;
  stats.withError += 1;
  let nErr = 0; let nMiss = 0;
  const stack = [tree.rootNode];
  while (stack.length) {
    const n = stack.pop();
    if (n.type === 'ERROR') { nErr += 1; stats.byType.ERROR = (stats.byType.ERROR || 0) + 1; }
    else if (n.isMissing) { nMiss += 1; stats.byType[`missing:${n.type}`] = (stats.byType[`missing:${n.type}`] || 0) + 1; }
    for (let k = 0; k < n.namedChildCount; k += 1) stack.push(n.namedChild(k));
  }
  stats.errorNodes += nErr; stats.missingNodes += nMiss;
  if (stats.examples.length < 6 && nErr + nMiss > 0) {
    const first = (() => {
      const st = [tree.rootNode];
      while (st.length) { const n = st.shift(); if (n.type === 'ERROR' || n.isMissing) return n; for (let k = 0; k < n.namedChildCount; k += 1) st.push(n.namedChild(k)); }
      return null;
    })();
    stats.examples.push({
      rel: path.relative(SRC, abs).split(path.sep).join('/'),
      bytes: text.length,
      errorNodes: nErr,
      first: first ? { type: first.type, line: first.startPosition.row + 1, text: text.slice(first.startIndex, Math.min(first.endIndex, first.startIndex + 90)).replace(/\n/g, ' ') } : null
    });
  }
}
console.log(JSON.stringify(stats, null, 2));
