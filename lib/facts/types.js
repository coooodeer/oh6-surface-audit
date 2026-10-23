'use strict';

/**
 * lib/facts/types.js —— 语法层类型事实（AG0.3）。
 *
 * 没有 clang 语义分析，所以：
 *   - 只从声明里取「写在源码上的类型」；
 *   - typeKind 只认 builtin 与同文件已声明的 record，其余 unknown（不猜）；
 *   - resolution 固定 syntax-only。
 */

const ids = require('./ids');
const ast = require('./ast');

const DECLARATOR_TYPES = new Set([
  'identifier', 'field_identifier', 'pointer_declarator', 'reference_declarator',
  'array_declarator', 'init_declarator', 'function_declarator', 'parenthesized_declarator',
  'qualified_identifier', 'destructor_name'
]);

function emit(rows, ctx, records, expr, type, line) {
  const typeText = String(type || '').replace(/\s+/g, ' ').trim();
  if (!typeText) return;
  const typeKind = ast.typeKindOf(typeText, records);
  const locator = { repo: ctx.repo, file: ctx.rel, line, expr, type: typeText };
  rows.push({
    factId: ids.factIdOf(ctx.snapshotId, 'type', locator),
    snapshotId: ctx.snapshotId,
    kind: 'type',
    locator,
    sourceRange: { file: ctx.rel, startLine: line, endLine: line },
    role: ctx.role,
    quality: { parse: ctx.parse, resolution: 'syntax-only', errorNodes: ctx.errorNodes },
    producer: 'AG0',
    schemaVersion: '1',
    expr,
    type: typeText,
    typeKind,
    file: ctx.rel,
    line
  });
}

function extractTypes(tree, ctx, records) {
  const rows = [];

  function visit(node) {
    if (node.type === 'function_definition') {
      const t = node.childForFieldName('type');
      const decl = node.childForFieldName('declarator');
      const named = ast.declaratorName(decl);
      const fnName = named.qualified || named.name;
      if (fnName && t) emit(rows, ctx, records, `${fnName}()`, t.text, ast.lineOf(node));
      for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i));
      return;
    }
    if (node.type === 'declaration' || node.type === 'field_declaration') {
      const typeText = ast.declarationType(node);
      if (typeText) {
        for (let i = 0; i < node.namedChildCount; i += 1) {
          const ch = node.namedChild(i);
          if (!DECLARATOR_TYPES.has(ch.type)) continue;
          const nm = ast.declaratorName(ch).name;
          if (nm) emit(rows, ctx, records, nm, typeText, ast.lineOf(ch));
        }
      }
      return;
    }
    for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i));
  }

  visit(tree.rootNode);
  return rows;
}

module.exports = { extractTypes };
