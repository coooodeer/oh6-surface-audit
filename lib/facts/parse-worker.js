'use strict';

/**
 * lib/facts/parse-worker.js —— AG0.3 的短命解析进程。
 *
 * 输入（IPC）：{ shardDir, snapshotId, files:[{abs, rel, repo, role, language}] }
 * 输出：shardDir 下按 kind 分文件的 JSONL + IPC 回传计数。
 *
 * 内存纪律：tree-sitter 0.21 的 Node 绑定没有 Tree.delete()，每个 worker 只处理
 * 一个分组（约 1/4 语料）就退出，避免长进程累计原生内存。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ast = require('./ast');
const ids = require('./ids');
const { extractFunctions } = require('./functions');
const { extractCalls } = require('./calls');
const { extractTypes } = require('./types');
const { extractGeneric } = require('./generic');
const { extractFlow } = require('./flow');

function loadTreeSitter() {
  const workspace = path.resolve(__dirname, '..', '..', '..');
  const mods = path.join(workspace, 'oh6-framework-want-leak-miner', 'node_modules');
  return {
    Parser: require(path.join(mods, 'tree-sitter')),
    Cpp: require(path.join(mods, 'tree-sitter-cpp')),
    C: require(path.join(mods, 'tree-sitter-c'))
  };
}

const KINDS = ['files', 'functions', 'symbols', 'types', 'calls', 'cfg', 'dfg', 'sinks', 'guards', 'reads', 'writes', 'locks', 'quality'];

function countErrors(root) {
  let n = 0;
  const stack = [root];
  while (stack.length) {
    const node = stack.pop();
    if (node.type === 'ERROR' || node.isMissing) n += 1;
    for (let i = 0; i < node.namedChildCount; i += 1) stack.push(node.namedChild(i));
  }
  return n;
}

function processFile(ts, file, snapshotId, buckets, unsupported) {
  let buf;
  try {
    buf = fs.readFileSync(file.abs);
  } catch (e) {
    unsupported.push({ id: `U:read:${file.rel}`, kind: 'file', reason: 'parse-failed', file: file.rel, detail: { error: String(e.message || e) } });
    return;
  }
  const text = buf.toString('utf8');
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  const bytes = buf.length;
  let lines = 0;
  for (let i = 0; i < buf.length; i += 1) if (buf[i] === 0x0a) lines += 1;
  if (buf.length > 0 && buf[buf.length - 1] !== 0x0a) lines += 1;

  const language = file.language;
  let tree;
  try {
    // 每个文件用独立 Parser：避免跨文件复用 parser 时 setLanguage 切换带来的非确定性
    const parser = new ts.Parser();
    parser.setLanguage(language === 'c' ? ts.C : ts.Cpp);
    tree = parser.parse(text, null, { bufferSize: 1024 * 1024 });
  } catch (e) {
    unsupported.push({ id: `U:parse:${file.rel}`, kind: 'file', reason: 'parse-failed', file: file.rel, detail: { error: String(e.message || e) } });
    const locator = { repo: file.repo, file: file.rel };
    buckets.files.push({
      factId: ids.factIdOf(snapshotId, 'file', locator), snapshotId, kind: 'file', locator,
      sourceRange: { file: file.rel, startLine: 1, endLine: lines || 1 },
      role: file.role, quality: { parse: 'failed', resolution: 'unknown', errorNodes: 0 },
      producer: 'AG0', schemaVersion: '1',
      path: file.rel, repo: file.repo, bytes, lines, sha256, language
    });
    return;
  }

  const errorNodes = countErrors(tree.rootNode);
  const parse = tree.rootNode.hasError ? 'partial' : 'full';
  const quality = { parse, resolution: 'syntax-only', errorNodes };
  const locator = { repo: file.repo, file: file.rel };
  buckets.files.push({
    factId: ids.factIdOf(snapshotId, 'file', locator), snapshotId, kind: 'file', locator,
    sourceRange: { file: file.rel, startLine: 1, endLine: lines || 1 },
    role: file.role, quality, producer: 'AG0', schemaVersion: '1',
    path: file.rel, repo: file.repo, bytes, lines, sha256, language
  });

  const ctx = { repo: file.repo, rel: file.rel, snapshotId, role: file.role, text, quality, parse, errorNodes };

  const before = {};
  for (const k of KINDS) if (k !== 'files' && k !== 'quality') before[k] = buckets[k].length;

  const fn = extractFunctions(tree, ctx);
  buckets.functions.push(...fn.functions);
  buckets.symbols.push(...fn.symbols);

  const calls = extractCalls(tree, ctx, fn.byName, fn.macroBodies);
  buckets.calls.push(...calls);

  const types = extractTypes(tree, ctx, fn.records);
  buckets.types.push(...types);

  const flow = extractFlow(tree, ctx, fn.macroBodies);
  buckets.cfg.push(...flow.cfg);
  buckets.dfg.push(...flow.dfg);

  const generic = extractGeneric(tree, ctx, fn.macroBodies);
  buckets.sinks.push(...generic.sinks);
  buckets.guards.push(...generic.guards);
  buckets.reads.push(...generic.reads);
  buckets.writes.push(...generic.writes);
  buckets.locks.push(...generic.locks);

  // 质量账本（每文件一行）：计数 + 覆盖率均值 + AST 参考数（用于归属率）
  const counts = {};
  for (const k of KINDS) if (before[k] !== undefined) counts[k] = buckets[k].length - before[k];
  const cfgRows = buckets.cfg.slice(before.cfg);
  const dfgRows = buckets.dfg.slice(before.dfg);
  let astCalls = 0;
  let astFnDefs = 0;
  {
    const stack = [tree.rootNode];
    while (stack.length) {
      const n = stack.pop();
      if (n.type === 'call_expression') astCalls += 1;
      else if (n.type === 'function_definition') astFnDefs += 1;
      for (let i = 0; i < n.namedChildCount; i += 1) stack.push(n.namedChild(i));
    }
  }
  buckets.quality.push({
    id: `Q:${file.rel}`,
    file: file.rel,
    repo: file.repo,
    role: file.role,
    language,
    parse,
    errorNodes,
    bytes,
    lines,
    counts,
    macroFunctions: fn.functions.filter((f) => f.macroDefined).length,
    cfgCoverageAvg: cfgRows.length ? Number((cfgRows.reduce((a, r) => a + r.coverage, 0) / cfgRows.length).toFixed(4)) : null,
    dfgCoverageAvg: dfgRows.length ? Number((dfgRows.reduce((a, r) => a + r.coverage, 0) / dfgRows.length).toFixed(4)) : null,
    cfgUnsupportedEdges: cfgRows.reduce((a, r) => a + r.unsupportedEdges, 0),
    astCallExpressions: astCalls,
    astFunctionDefinitions: astFnDefs
  });

  if (parse === 'partial') {
    unsupported.push({ id: `U:ast:${file.rel}`, kind: 'file', reason: 'ast-error-nodes', file: file.rel, detail: { errorNodes } });
  }
}

process.on('message', (msg) => {
  const ts = loadTreeSitter();
  ts.parser = new ts.Parser();
  const buckets = Object.fromEntries(KINDS.map((k) => [k, []]));
  const unsupported = [];

  fs.mkdirSync(msg.shardDir, { recursive: true });
  for (const file of msg.files) processFile(ts, file, msg.snapshotId, buckets, unsupported);

  const counts = {};
  for (const kind of KINDS) {
    const file = path.join(msg.shardDir, `${kind}.jsonl`);
    const rows = buckets[kind];
    fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''), 'utf8');
    counts[kind] = rows.length;
  }
  const uf = path.join(msg.shardDir, 'unsupported.jsonl');
  fs.writeFileSync(uf, unsupported.map((r) => JSON.stringify(r)).join('\n') + (unsupported.length ? '\n' : ''), 'utf8');
  counts.unsupported = unsupported.length;

  process.send({ type: 'done', counts });
  process.exit(0);
});
