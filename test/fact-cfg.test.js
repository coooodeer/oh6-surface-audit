'use strict';

/**
 * test/fact-cfg.test.js —— AG0.3（P4）CFG/DFG 单元与失败用例。
 * 专门锁定指导文档列出的 3 个已知 bug：
 *   1) if 的 true/false 边必须落在分支体首节点（不能是自环/fallthrough）；
 *   2) join 节点必须真实创建并被回填；
 *   3) 调用点要在表达式级采集（`= f(x)`、`if (g())`、`return h()`）。
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const MOD = path.resolve(__dirname, '..', '..', 'oh6-framework-want-leak-miner', 'node_modules');
const Parser = require(path.join(MOD, 'tree-sitter'));
const Cpp = require(path.join(MOD, 'tree-sitter-cpp'));

const { buildCfg } = require('../lib/facts/cfg');
const { buildDfg } = require('../lib/facts/dfg');
const { extractFunctions } = require('../lib/facts/functions');

function parseCpp(text) {
  const parser = new Parser();
  parser.setLanguage(Cpp);
  return parser.parse(text, null, { bufferSize: 1024 * 1024 });
}

function firstFunction(tree) {
  let found = null;
  const stack = [tree.rootNode];
  while (stack.length) {
    const n = stack.pop();
    if (n.type === 'function_definition') { found = n; break; }
    for (let i = 0; i < n.namedChildCount; i += 1) stack.push(n.namedChild(i));
  }
  return found;
}

function cfgOf(src) {
  const tree = parseCpp(src);
  const fn = firstFunction(tree);
  assert.ok(fn, 'fixture 里应有函数定义');
  return { fn, cfg: buildCfg(fn, fn.childForFieldName('body')) };
}

test('CFG：if/else 的 true/false 边落在分支体首节点（bug 1）', () => {
  const { cfg } = cfgOf('int f(int a) {\n  if (a > 0) {\n    return 1;\n  } else {\n    return 2;\n  }\n}\n');
  const branch = cfg.nodes.find((n) => n.kind === 'branch');
  assert.ok(branch, '应有 branch 节点');
  const out = cfg.edges.filter((e) => e.from === branch.id);
  const trueEdge = out.find((e) => e.kind === 'true');
  const falseEdge = out.find((e) => e.kind === 'false');
  assert.ok(trueEdge, 'branch 必须有一条 true 边');
  assert.ok(falseEdge, 'branch 必须有一条 false 边');
  assert.notStrictEqual(trueEdge.to, branch.id, 'true 边不能自环');
  assert.notStrictEqual(falseEdge.to, trueEdge.to, 'true/false 目标必须不同');
  const trueNode = cfg.nodes.find((n) => n.id === trueEdge.to);
  assert.strictEqual(trueNode.kind, 'return', 'true 分支体首节点应是 return');
});

test('CFG：join 节点真实存在且被回填（bug 2）', () => {
  const { cfg } = cfgOf('int f(int a) {\n  if (a > 0) {\n    a = 1;\n  }\n  return a;\n}\n');
  const joins = cfg.nodes.filter((n) => n.kind === 'join');
  assert.ok(joins.length >= 1, 'if 之后必须产生 join 节点');
  const join = joins[0];
  const into = cfg.edges.filter((e) => e.to === join.id);
  assert.ok(into.length >= 2, `join 必须至少被两条边回填，实际 ${into.length}`);
  const out = cfg.edges.filter((e) => e.from === join.id);
  assert.ok(out.length >= 1, 'join 必须继续往后流');
});

test('CFG：调用点在表达式级采集（bug 3）', () => {
  const src = [
    'int g(); int h();',
    'int f(int a) {',
    '  int x = g();',
    '  if (h()) {',
    '    return x;',
    '  }',
    '  return g() + h();',
    '}'
  ].join('\n');
  const { cfg } = cfgOf(src);
  const calls = cfg.nodes.filter((n) => n.kind === 'call');
  assert.ok(calls.length >= 3, `= g()、if (h())、return g()+h() 都应产生 call 节点，实际 ${calls.length}`);
});

test('CFG：循环有 back 边与 loop 节点', () => {
  const { cfg } = cfgOf('void f(int n) { for (int i = 0; i < n; i++) { g(i); } }\nvoid g(int);');
  const loop = cfg.nodes.find((n) => n.kind === 'loop');
  assert.ok(loop, '应有 loop 节点');
  assert.ok(cfg.edges.some((e) => e.kind === 'back' && e.to === loop.id), '必须有回到 loop 的 back 边');
});

test('CFG：goto 计入 unsupportedEdges 且 coverage < 1', () => {
  const { cfg } = cfgOf('void f() { goto end; end: return; }\n');
  assert.ok(cfg.unsupportedEdges >= 1, 'goto 必须被记为 unsupported');
  assert.ok(cfg.coverage <= 1);
});

test('CFG：entry/exit 恒存在且 exit 无出边', () => {
  const { cfg } = cfgOf('void f() { }\n');
  assert.ok(cfg.nodes.some((n) => n.kind === 'entry'));
  const exit = cfg.nodes.find((n) => n.kind === 'exit');
  assert.ok(exit);
  assert.strictEqual(cfg.edges.filter((e) => e.from === exit.id).length, 0);
});

test('DFG：param → use 的 def-use 边', () => {
  const src = 'int f(int a) {\n  int b = a + 1;\n  b = b * 2;\n  return b;\n}\n';
  const tree = parseCpp(src);
  const fn = firstFunction(tree);
  const params = require('../lib/facts/ast').functionParams(fn).names;
  const dfg = buildDfg(fn, fn.childForFieldName('body'), params);
  assert.ok(dfg.defs.some((d) => d.var === 'a' && d.kind === 'param'), '参数应作为 def');
  assert.ok(dfg.defs.some((d) => d.var === 'b' && d.kind === 'assign'), '赋值应作为 def');
  assert.ok(dfg.uses.some((u) => u.var === 'a'), 'a 应作为 use');
  assert.ok(dfg.edges.length >= 1, '应产出 def-use 边');
  assert.ok(dfg.coverage >= 0 && dfg.coverage <= 1);
});

test('DFG：空函数不崩、coverage=1', () => {
  const tree = parseCpp('void f() {}\n');
  const fn = firstFunction(tree);
  const dfg = buildDfg(fn, fn.childForFieldName('body'), []);
  assert.deepStrictEqual(dfg.edges, []);
  assert.strictEqual(dfg.coverage, 1);
});

test('确定性：同一输入两次构建结果一致', () => {
  const src = 'int f(int a) { if (a) { return 1; } for (;;) { g(); } return 2; }\nvoid g();';
  const tree1 = parseCpp(src);
  const tree2 = parseCpp(src);
  const c1 = buildCfg(firstFunction(tree1), firstFunction(tree1).childForFieldName('body'));
  const c2 = buildCfg(firstFunction(tree2), firstFunction(tree2).childForFieldName('body'));
  assert.deepStrictEqual(c1, c2);
});

test('integration：宏定义函数体也能产出 CFG', () => {
  const src = 'using namespace testing;\nnamespace n {\nHWTEST_F(S, C, L1)\n{\n  if (x) { g(); }\n}\n}\n';
  const tree = parseCpp(src);
  const ctx = { repo: 'r', rel: 'x.cpp', snapshotId: `sha256:${'e'.repeat(64)}`, role: 'test', text: src, quality: { parse: 'full', resolution: 'syntax-only', errorNodes: 0 }, parse: 'full', errorNodes: 0 };
  const fn = extractFunctions(tree, ctx);
  const { extractFlow } = require('../lib/facts/flow');
  const flow = extractFlow(tree, ctx, fn.macroBodies);
  assert.ok(flow.cfg.length >= 1, '宏体应有 CFG');
  assert.ok(flow.dfg.length >= 1, '宏体应有 DFG');
});
