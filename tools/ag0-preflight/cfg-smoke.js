'use strict';
/* 探针：用 tree-sitter AST 为单个函数构建 CFG（验证 AG0.3 自建 CFG 的可行性）。 */
const fs = require('fs');
const path = require('path');

const WORKSPACE = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(WORKSPACE, 'OpenHarmony');
const MOD = path.join(WORKSPACE, 'oh6-framework-want-leak-miner', 'node_modules');
const Parser = require(path.join(MOD, 'tree-sitter'));
const Cpp = require(path.join(MOD, 'tree-sitter-cpp'));

const TARGET = path.join(SRC, 'base', 'notification', 'eventhandler', 'frameworks', 'eventhandler', 'src', 'event_handler.cpp');
const FN = process.argv[2] || 'Handle';

function nameOf(node, src) {
  const d = node.childForFieldName('declarator');
  if (!d) return null;
  // declarator -> function_declarator -> declarator -> identifier/field_identifier
  let n = d;
  for (let i = 0; i < 4 && n; i += 1) {
    if (n.type === 'function_declarator') n = n.childForFieldName('declarator');
    else break;
  }
  if (!n) return null;
  if (n.type === 'qualified_identifier') return n.childForFieldName('name') ? n.childForFieldName('name').text : n.text;
  return n.text;
}

function buildCfg(fnNode, src) {
  const nodes = [];
  const edges = [];
  let seq = 0;
  const add = (kind, line) => { const id = `n${++seq}`; nodes.push({ id, kind, line }); return id; };
  const link = (from, to, kind) => edges.push({ from, to, kind });

  const entry = add('entry', fnNode.startPosition.row + 1);
  const body = fnNode.childForFieldName('body');
  const exit = { id: 'nEXIT' };

  // 返回语句集合：块内顺序执行；遇到 return/分支/循环时切断 fallthrough
  function walk(node, from, ctx) {
    const stack = [node];
    let cur = from;
    while (stack.length) {
      const stmt = stack.shift();
      if (!stmt) break;
      if (stmt.type === 'return_statement') {
        const r = add('return', stmt.startPosition.row + 1);
        link(cur, r, 'fallthrough');
        return { next: null, rets: [r] };
      }
      if (stmt.type === 'if_statement') {
        const b = add('branch', stmt.startPosition.row + 1);
        link(cur, b, 'fallthrough');
        const cons = stmt.childForFieldName('consequence');
        const alt = stmt.childForFieldName('alternative');
        const a = cons ? walk(cons, b, ctx) : { next: b, rets: [] };
        const c = alt ? walk(alt, b, ctx) : { next: b, rets: [] };
        if (a.next) link(b, a.next, 'true');
        if (c.next) link(b, c.next, 'false');
        return { next: 'JOIN', rets: [...a.rets, ...c.rets], join: b };
      }
      if (['for_statement', 'while_statement', 'do_statement'].includes(stmt.type)) {
        const l = add('loop', stmt.startPosition.row + 1);
        link(cur, l, 'fallthrough');
        const bodyNode = stmt.childForFieldName('body');
        const inner = bodyNode ? walk(bodyNode, l, ctx) : { next: l, rets: [] };
        if (inner.next) link(inner.next, l, 'back');
        return { next: 'JOIN', rets: inner.rets, loop: l };
      }
      if (stmt.type === 'call_expression') {
        const c = add('call', stmt.startPosition.row + 1);
        link(cur, c, 'fallthrough');
        cur = c;
        continue;
      }
      if (stmt.type === 'compound_statement' || stmt.type === 'declaration') {
        for (let i = 0; i < stmt.namedChildCount; i += 1) stack.push(stmt.namedChild(i));
        continue;
      }
      // 其它语句：块内顺序继续
      for (let i = 0; i < stmt.namedChildCount; i += 1) {
        const ch = stmt.namedChild(i);
        if (ch.type.endsWith('_statement') || ch.type === 'compound_statement') stack.push(ch);
      }
    }
    return { next: 'JOIN', rets: [] };
  }

  const res = body ? walk(body, entry, {}) : { next: entry, rets: [] };
  if (res.next && res.next !== 'JOIN') link(res.next, 'nEXIT', 'fallthrough');
  for (const r of res.rets) link(r, 'nEXIT', 'return');
  if (res.next === 'JOIN') link('nJOIN', 'nEXIT', 'fallthrough');
  nodes.push({ id: 'nEXIT', kind: 'exit', line: fnNode.endPosition.row + 1 });
  return { nodes, edges };
}

const src = fs.readFileSync(TARGET, 'utf8');
const parser = new Parser();
parser.setLanguage(Cpp);
const tree = parser.parse(src, null, { bufferSize: 1024 * 1024 });
let found = null;
const stack = [tree.rootNode];
while (stack.length) {
  const n = stack.pop();
  if (n.type === 'function_definition' && nameOf(n, src) === FN) { found = n; break; }
  for (let i = 0; i < n.namedChildCount; i += 1) stack.push(n.namedChild(i));
}
if (!found) { console.log(JSON.stringify({ error: `function ${FN} not found` })); process.exit(1); }
const cfg = buildCfg(found, src);
console.log(JSON.stringify({
  function: FN,
  startLine: found.startPosition.row + 1,
  endLine: found.endPosition.row + 1,
  nodes: cfg.nodes.length,
  edges: cfg.edges.length,
  kinds: cfg.nodes.reduce((a, n) => { a[n.kind] = (a[n.kind] || 0) + 1; return a; }, {}),
  edgeKinds: cfg.edges.reduce((a, e) => { a[e.kind] = (a[e.kind] || 0) + 1; return a; }, {}),
  sampleNodes: cfg.nodes.slice(0, 10),
  sampleEdges: cfg.edges.slice(0, 10)
}, null, 2));
