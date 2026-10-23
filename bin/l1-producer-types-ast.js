'use strict';

/**
 * l1-producer-types-ast.js —— 用 tree-sitter-cpp 的 function_definition.type
 * 重抽返回类型，替代声明行正则。
 *
 * 输出：out/l1/producers-ast.jsonl
 */

const fs = require('fs');
const path = require('path');
const { TOOL_ROOT, SOURCE_ROOT, OUT_ROOT, readJsonl, writeJsonl, ensureDir } = require('../lib/util.js');

const Parser = require(path.join(TOOL_ROOT, '..', 'oh6-framework-want-leak-miner', 'node_modules', 'tree-sitter'));
const Cpp = require(path.join(TOOL_ROOT, '..', 'oh6-framework-want-leak-miner', 'node_modules', 'tree-sitter-cpp'));
const L1 = path.join(OUT_ROOT, 'l1', 'functions.jsonl');
const OUT = path.join(OUT_ROOT, 'l1', 'producers-ast.jsonl');

function idOf(f) { return `${f.repo}|${f.file}:${f.startLine}`; }

function main() {
  ensureDir(path.dirname(OUT));
  const fns = readJsonl(L1);
  const byFile = new Map();
  for (const f of fns) {
    const k = `${f.repo}\u0000${f.file}`;
    if (!byFile.has(k)) byFile.set(k, []);
    byFile.get(k).push(f);
  }
  const parser = new Parser();
  parser.setLanguage(Cpp);
  const rows = [];
  let parsedFiles = 0;
  let parseErrors = 0;
  for (const [key, list] of byFile) {
    const [repo, file] = key.split('\u0000');
    let text;
    try { text = fs.readFileSync(path.join(SOURCE_ROOT, repo, file), 'utf8'); } catch (_) { continue; }
    let tree;
    try {
      tree = parser.parse(text);
    } catch (e) {
      process.stderr.write(`parse-fail ${file} bytes=${text.length} ${e.message}\n`);
      continue;
    }
    parsedFiles += 1;
    if (tree.rootNode.hasError) parseErrors += 1;
    const stack = [tree.rootNode];
    while (stack.length) {
      const n = stack.pop();
      if (n.type === 'function_definition') {
        const typeNode = n.childForFieldName('type');
        const decl = n.childForFieldName('declarator');
        if (typeNode && decl) {
          const ret = text.slice(typeNode.startIndex, decl.startIndex).replace(/\s+/g, ' ').trim();
          const line = n.startPosition.row + 1;
          const match = list.find((f) => f.startLine === line)
            || list.find((f) => f.startLine <= line && f.endLine >= line)
            || null;
          if (match) {
            rows.push({
              functionId: idOf(match),
              repo,
              file,
              name: match.name,
              startLine: match.startLine,
              astStartLine: line,
              returnType: ret,
              pointerLike: /\*|shared_ptr|weak_ptr|unique_ptr|sptr|optional/.test(ret),
              typeKnown: true
            });
          }
        }
      }
      for (let i = 0; i < n.namedChildren.length; i += 1) stack.push(n.namedChildren[i]);
    }
  }
  // 去重（同一 functionId 取第一条）
  const seen = new Set();
  const dedup = [];
  for (const r of rows) {
    if (seen.has(r.functionId)) continue;
    seen.add(r.functionId);
    dedup.push(r);
  }
  writeJsonl(OUT, dedup);
  process.stdout.write(`producer types AST: functions=${fns.length} matched=${dedup.length} files=${parsedFiles} parseErrors=${parseErrors} pointerLike=${dedup.filter((r) => r.pointerLike).length}\n`);
}

main();
