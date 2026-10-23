'use strict';

/**
 * lib/facts/calls.js —— 调用事实（AG0.3）。
 *
 * resolution 规则（不把 name-only 当 exact）：
 *   - 直接调用 identifier / qualified_identifier：同文件同名且参数个数唯一命中 → exact；
 *   - 成员调用 a.f() / a->f()：只记 name-only（receiver 类型未知）；
 *   - 括号/解引用再调用（函数指针）：unsupported。
 */

const ids = require('./ids');
const ast = require('./ast');

function shortName(calleeText) {
  const t = String(calleeText || '').replace(/\s+/g, '');
  const parts = t.split(/::|->|\./);
  return parts[parts.length - 1].replace(/[^A-Za-z0-9_~]/g, '');
}

function classify(calleeNode, byName, argc) {
  const text = calleeNode ? calleeNode.text.replace(/\s+/g, '') : '';
  const name = shortName(text);
  if (!name) return { name: text, resolution: 'unsupported', callee: null };
  if (calleeNode.type === 'field_expression') return { name, resolution: 'name-only', callee: null };
  if (!['identifier', 'qualified_identifier', 'template_function', 'operator_name', 'destructor_name'].includes(calleeNode.type)) {
    return { name, resolution: 'unsupported', callee: null };
  }
  const candidates = byName.get(name) || [];
  const argcMatch = candidates.filter((c) => c.argc === argc);
  if (candidates.length === 1 && argcMatch.length === 1) {
    return { name, resolution: 'exact', callee: candidates[0].factId };
  }
  return { name, resolution: 'name-only', callee: null };
}

/** 遍历所有函数体，抽 call_expression */
function extractCalls(tree, ctx, byName, macroBodies) {
  const rows = [];
  let seq = 0;

  function visit(node, fn, owner) {
    if (node.type === 'namespace_definition' || node.type === 'class_specifier' || node.type === 'struct_specifier') {
      const nameNode = node.childForFieldName('name');
      const next = nameNode ? [...owner, nameNode.text] : owner;
      for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), fn, next);
      return;
    }
    if (node.type === 'compound_statement' && macroBodies && macroBodies.has(node.startIndex)) {
      const m = macroBodies.get(node.startIndex);
      for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), { factId: m.factId, name: m.name }, owner);
      return;
    }
    if (node.type === 'function_definition') {
      const decl = node.childForFieldName('declarator');
      const named = ast.declaratorName(decl);
      const resolved = ast.resolveFunctionName(named, owner);
      const qualified = resolved.owner.length ? `${resolved.owner.join('::')}::${resolved.name}` : resolved.name;
      const locator = { repo: ctx.repo, file: ctx.rel, startLine: ast.lineOf(node), name: qualified };
      const factId = ids.factIdOf(ctx.snapshotId, 'function', locator);
      for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), { factId, name: qualified }, resolved.owner);
      return;
    }
    if (node.type === 'call_expression' && fn) {
      const calleeNode = node.childForFieldName('function');
      const args = node.childForFieldName('arguments');
      const argc = args ? args.namedChildCount : 0;
      const c = classify(calleeNode, byName, argc);
      const line = ast.lineOf(node);
      const column = ast.columnOf(node);
      seq += 1;
      const locator = { repo: ctx.repo, file: ctx.rel, line, column, caller: fn.name, callee: c.name };
      rows.push({
        factId: ids.factIdOf(ctx.snapshotId, 'call', locator),
        snapshotId: ctx.snapshotId,
        kind: 'call',
        locator,
        sourceRange: { file: ctx.rel, startLine: line, endLine: line },
        role: ctx.role,
        quality: { parse: ctx.parse, resolution: c.resolution, errorNodes: ctx.errorNodes },
        producer: 'AG0',
        schemaVersion: '1',
        caller: fn.factId,
        callerName: fn.name,
        calleeName: c.name,
        callee: c.callee,
        line,
        column,
        argc
      });
    }
    for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), fn, owner);
  }

  visit(tree.rootNode, null, []);
  return rows;
}

module.exports = { extractCalls, shortName, classify };
