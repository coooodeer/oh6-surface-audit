'use strict';

/**
 * lib/facts/flow.js —— 把 CFG/DFG 挂到函数建树上（AG0.3）。
 * 遍历规则与 calls.js / generic.js 一致（namespace/class 祖先 + 宏体），保证 function factId 对齐。
 */

const ids = require('./ids');
const ast = require('./ast');
const { buildCfg } = require('./cfg');
const { buildDfg } = require('./dfg');

function extractFlow(tree, ctx, macroBodies) {
  const cfgRows = [];
  const dfgRows = [];

  function emit(fnNode, bodyNode, qualified, params) {
    const line = fnNode.startPosition.row + 1;
    const locator = { repo: ctx.repo, file: ctx.rel, function: qualified, startLine: line };
    const fnFact = ids.factIdOf(ctx.snapshotId, 'function', { repo: ctx.repo, file: ctx.rel, startLine: line, name: qualified });

    const cfg = buildCfg(fnNode, bodyNode);
    cfgRows.push({
      factId: ids.factIdOf(ctx.snapshotId, 'cfg', locator),
      snapshotId: ctx.snapshotId,
      kind: 'cfg',
      locator,
      sourceRange: { file: ctx.rel, startLine: line, endLine: fnNode.endPosition.row + 1 },
      role: ctx.role,
      quality: { parse: ctx.parse, resolution: 'syntax-only', errorNodes: ctx.errorNodes },
      producer: 'AG0',
      schemaVersion: '1',
      function: fnFact,
      functionName: qualified,
      nodes: cfg.nodes,
      edges: cfg.edges,
      coverage: cfg.coverage,
      unsupportedEdges: cfg.unsupportedEdges
    });

    const dfg = buildDfg(fnNode, bodyNode, params);
    dfgRows.push({
      factId: ids.factIdOf(ctx.snapshotId, 'dfg', locator),
      snapshotId: ctx.snapshotId,
      kind: 'dfg',
      locator,
      sourceRange: { file: ctx.rel, startLine: line, endLine: fnNode.endPosition.row + 1 },
      role: ctx.role,
      quality: { parse: ctx.parse, resolution: 'syntax-only', errorNodes: ctx.errorNodes },
      producer: 'AG0',
      schemaVersion: '1',
      function: fnFact,
      functionName: qualified,
      defs: dfg.defs,
      uses: dfg.uses,
      edges: dfg.edges,
      coverage: dfg.coverage
    });
  }

  function visit(node, owner) {
    if (node.type === 'namespace_definition' || node.type === 'class_specifier' || node.type === 'struct_specifier') {
      const nameNode = node.childForFieldName('name');
      const next = nameNode ? [...owner, nameNode.text] : owner;
      for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), next);
      return;
    }
    if (node.type === 'compound_statement' && macroBodies && macroBodies.has(node.startIndex)) {
      const m = macroBodies.get(node.startIndex);
      emit(node, node, m.name, []);
      for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), owner);
      return;
    }
    if (node.type === 'function_definition') {
      const decl = node.childForFieldName('declarator');
      const named = ast.declaratorName(decl);
      const resolved = ast.resolveFunctionName(named, owner);
      const qualified = resolved.owner.length ? `${resolved.owner.join('::')}::${resolved.name}` : resolved.name;
      const params = ast.functionParams(node).names;
      emit(node, node.childForFieldName('body'), qualified, params);
      return; // 不递归进函数体
    }
    for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), owner);
  }

  visit(tree.rootNode, []);
  return { cfg: cfgRows, dfg: dfgRows };
}

module.exports = { extractFlow };
