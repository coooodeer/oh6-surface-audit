'use strict';

/**
 * lib/facts/functions.js —— 函数与符号事实（AG0.3）。
 * 纯语法层：签名来自 declarator/type 文本，owner 来自 namespace/class 祖先链。
 */

const ids = require('./ids');
const ast = require('./ast');

function fullName(owner, name) {
  const o = (owner || []).filter(Boolean).join('::');
  return o ? `${o}::${name}` : name;
}

function truncate(s, n = 400) {
  const t = String(s || '');
  return t.length > n ? t.slice(0, n) : t;
}

/** 一次遍历：函数 + 符号 + 同文件 record 名 + 函数索引（供调用解析） */
function extractFunctions(tree, ctx) {
  const functions = [];
  const symbols = [];
  const records = new Set();
  const byName = new Map();
  const macroBodies = new Map(); // startIndex(compound_statement) -> {factId, name}

  function visit(node, owner) {
    if (node.type === 'namespace_definition' || node.type === 'class_specifier' || node.type === 'struct_specifier' || node.type === 'enum_specifier') {
      const nameNode = node.childForFieldName('name');
      const name = nameNode ? nameNode.text : null;
      if (name) {
        const symbolKind = node.type === 'namespace_definition' ? 'namespace'
          : node.type === 'class_specifier' ? 'class'
            : node.type === 'struct_specifier' ? 'struct' : 'enum';
        if (symbolKind !== 'namespace') records.add(name);
        const locator = { repo: ctx.repo, file: ctx.rel, declLine: ast.lineOf(node), name, symbolKind };
        symbols.push({
          factId: ids.factIdOf(ctx.snapshotId, 'symbol', locator),
          snapshotId: ctx.snapshotId,
          kind: 'symbol',
          locator,
          sourceRange: { file: ctx.rel, startLine: ast.lineOf(node), endLine: ast.lineOf(node) },
          role: ctx.role,
          quality: ctx.quality,
          producer: 'AG0',
          schemaVersion: '1',
          name,
          symbolKind,
          declFile: ctx.rel,
          declLine: ast.lineOf(node),
          scope: owner.join('::')
        });
      }
      for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), name ? [...owner, name] : owner);
      return;
    }

    if (node.type === 'preproc_def' || node.type === 'preproc_function_def') {
      const nameNode = node.childForFieldName('name');
      const name = nameNode ? nameNode.text : null;
      if (name) {
        const locator = { repo: ctx.repo, file: ctx.rel, declLine: ast.lineOf(node), name, symbolKind: 'macro' };
        symbols.push({
          factId: ids.factIdOf(ctx.snapshotId, 'symbol', locator),
          snapshotId: ctx.snapshotId,
          kind: 'symbol',
          locator,
          sourceRange: { file: ctx.rel, startLine: ast.lineOf(node), endLine: ast.lineOf(node) },
          role: ctx.role,
          quality: ctx.quality,
          producer: 'AG0',
          schemaVersion: '1',
          name,
          symbolKind: 'macro',
          declFile: ctx.rel,
          declLine: ast.lineOf(node),
          scope: owner.join('::')
        });
      }
      return;
    }

    if (node.type === 'type_definition' || node.type === 'alias_declaration') {
      let name = null;
      if (node.type === 'alias_declaration') {
        const n = node.childForFieldName('name');
        name = n ? n.text : null;
      } else {
        const d = node.childForFieldName('declarator');
        name = d ? ast.declaratorName(d).name : null;
      }
      if (name) {
        const locator = { repo: ctx.repo, file: ctx.rel, declLine: ast.lineOf(node), name, symbolKind: 'typedef' };
        symbols.push({
          factId: ids.factIdOf(ctx.snapshotId, 'symbol', locator),
          snapshotId: ctx.snapshotId,
          kind: 'symbol',
          locator,
          sourceRange: { file: ctx.rel, startLine: ast.lineOf(node), endLine: ast.lineOf(node) },
          role: ctx.role,
          quality: ctx.quality,
          producer: 'AG0',
          schemaVersion: '1',
          name,
          symbolKind: 'typedef',
          declFile: ctx.rel,
          declLine: ast.lineOf(node),
          scope: owner.join('::')
        });
      }
      return;
    }

    if (node.type === 'function_definition') {
      const decl = node.childForFieldName('declarator');
      const named = ast.declaratorName(decl);
      const params = ast.functionParams(node);
      const body = node.childForFieldName('body');
      const resolved = ast.resolveFunctionName(named, owner);
      const name = resolved.name;
      const fnOwner = resolved.owner;
      const startLine = ast.lineOf(node);
      const signature = body
        ? ctx.text.slice(node.startIndex, body.startIndex).replace(/\s+/g, ' ').trim()
        : ctx.text.slice(node.startIndex, node.endIndex).replace(/\s+/g, ' ').trim().slice(0, 400);
      const bodyHash = body ? ast.sha256(body.text) : ast.sha256('');
      const qualified = fullName(fnOwner, name);
      const locator = { repo: ctx.repo, file: ctx.rel, startLine, name: qualified };
      const factId = ids.factIdOf(ctx.snapshotId, 'function', locator);
      const row = {
        factId,
        snapshotId: ctx.snapshotId,
        kind: 'function',
        locator,
        sourceRange: { file: ctx.rel, startLine, endLine: node.endPosition.row + 1 },
        role: ctx.role,
        quality: ctx.quality,
        producer: 'AG0',
        schemaVersion: '1',
        name,
        owner: fnOwner.join('::'),
        qualified,
        signature: signature.slice(0, 400),
        startLine,
        endLine: node.endPosition.row + 1,
        bodyHash,
        argc: params.count,
        isTest: ctx.role === 'test'
      };
      functions.push(row);
      if (!byName.has(name)) byName.set(name, []);
      byName.get(name).push({ factId, argc: params.count, startLine });
      return; // 不递归进函数体（符号只收类型/namespace 级）
    }

    for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), owner);
  }

  visit(tree.rootNode, []);

  // 宏定义的"函数体"：`TEST_F(Suite, Name) { ... }` 在 tree-sitter 里是
  // expression_statement(call_expression) + compound_statement 的兄弟组合。
  // 不展开宏，但把它当作一个具名作用域，避免 gtest/断言宏里的调用整段丢失。
  const MACRO_CONTAINERS = new Set(['translation_unit', 'declaration_list', 'linkage_specification',
    'preproc_ifdef', 'preproc_if', 'preproc_else', 'preproc_elif', 'namespace_definition']);
  function collectMacroBodies(container, owner) {
    const kids = [];
    for (let i = 0; i < container.namedChildCount; i += 1) {
      const c = container.namedChild(i);
      if (c.type === 'comment') continue; // 注释不参与相邻判定
      kids.push(c);
    }
    if (MACRO_CONTAINERS.has(container.type)) {
      for (let i = 0; i < kids.length - 1; i += 1) {
        const cur = kids[i];
        const next = kids[i + 1];
        if (next.type !== 'compound_statement') continue;
        if (cur.type !== 'expression_statement') continue;
        const call = cur.namedChildCount === 1 ? cur.namedChild(0) : null;
        if (!call || call.type !== 'call_expression') continue;
        const callee = call.childForFieldName('function');
        const args = call.childForFieldName('arguments');
        const macro = callee ? callee.text.replace(/\s+/g, '') : null;
        if (!macro || !/^[A-Za-z_]\w*$/.test(macro)) continue;
        if (!/[A-Z]/.test(macro)) continue; // 排除普通小写函数调用后接块
        const argText = args ? args.text.replace(/\s+/g, ' ').replace(/^\(|\)$/g, '').slice(0, 120) : '';
        const name = argText ? `${macro}(${argText})` : macro;
        const startLine = ast.lineOf(cur);
        const locator = { repo: ctx.repo, file: ctx.rel, startLine, name };
        const factId = ids.factIdOf(ctx.snapshotId, 'function', locator);
        functions.push({
          factId,
          snapshotId: ctx.snapshotId,
          kind: 'function',
          locator,
          sourceRange: { file: ctx.rel, startLine, endLine: next.endPosition.row + 1 },
          role: ctx.role,
          quality: ctx.quality,
          producer: 'AG0',
          schemaVersion: '1',
          name,
          owner,
          qualified: owner ? `${owner}::${name}` : name,
          signature: truncate(`${macro}(${argText})`),
          startLine,
          endLine: next.endPosition.row + 1,
          bodyHash: ast.sha256(next.text),
          argc: null,
          isTest: ctx.role === 'test',
          macroDefined: true
        });
        macroBodies.set(next.startIndex, { factId, name });
      }
    }
    for (const kid of kids) {
      if (kid.type === 'namespace_definition') {
        const n = kid.childForFieldName('name');
        const nested = n ? (owner ? `${owner}::${n.text}` : n.text) : owner;
        collectMacroBodies(kid.childForFieldName('body') || kid, nested);
      } else if (['preproc_ifdef', 'preproc_if', 'preproc_else', 'preproc_elif', 'linkage_specification', 'declaration_list'].includes(kid.type)) {
        collectMacroBodies(kid, owner);
      }
    }
  }
  collectMacroBodies(tree.rootNode, '');

  return { functions, symbols, records, byName, macroBodies };
}

module.exports = { extractFunctions, fullName };
