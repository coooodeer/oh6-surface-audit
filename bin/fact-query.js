#!/usr/bin/env node
'use strict';

/**
 * bin/fact-query.js —— AG0.4 Query API 的 CLI。
 *
 * 子命令：
 *   name <pattern> [--kind=function|symbol] [--repo=] [--regex] [--limit=]
 *   ast <op> --file=<rel> [--line-from=] [--line-to=] [--limit=]
 *   cg <fnName> [--direction=callees|callers] [--limit=]
 *   source <file> <line> [--count=5]
 *   type <expr|file:line> [--exact]
 *   check-sites <fnName>
 *   flow [--from=] [--to=]
 *
 * 所有结果都带 snapshotId / factRefs / sourceRange / quality。
 */

const fs = require('fs');
const path = require('path');

const scope = require('../lib/facts/scope');
const { FactsIndex } = require('../lib/facts/query');

function parseArgs(argv) {
  const args = { _: [], snapshot: null, limit: null, kind: null, repo: null, regex: false, direction: null, file: null, count: null, exact: false, lineFrom: null, lineTo: null };
  for (const a of argv) {
    if (a.startsWith('--snapshot=')) args.snapshot = a.slice('--snapshot='.length);
    else if (a.startsWith('--kind=')) args.kind = a.slice('--kind='.length);
    else if (a.startsWith('--repo=')) args.repo = a.slice('--repo='.length);
    else if (a === '--regex') args.regex = true;
    else if (a.startsWith('--limit=')) args.limit = Number(a.slice('--limit='.length));
    else if (a.startsWith('--direction=')) args.direction = a.slice('--direction='.length);
    else if (a.startsWith('--file=')) args.file = a.slice('--file='.length);
    else if (a.startsWith('--count=')) args.count = Number(a.slice('--count='.length));
    else if (a === '--exact') args.exact = true;
    else if (a.startsWith('--line-from=')) args.lineFrom = Number(a.slice('--line-from='.length));
    else if (a.startsWith('--line-to=')) args.lineTo = Number(a.slice('--line-to='.length));
    else if (a.startsWith('--')) throw new Error(`unknown-arg: ${a}`);
    else args._.push(a);
  }
  return args;
}

function resolveSnapshotDir(arg) {
  if (!fs.existsSync(scope.FACTS_ROOT)) throw new Error('no-facts: out/facts 不存在');
  if (arg) {
    const dir = path.join(scope.FACTS_ROOT, arg.replace(/^sha256:/, ''));
    if (!fs.existsSync(dir)) throw new Error(`snapshot-missing: ${arg}`);
    return dir;
  }
  const dirs = fs.readdirSync(scope.FACTS_ROOT, { withFileTypes: true })
    .filter((d) => d.isDirectory() && /^[0-9a-f]{64}$/.test(d.name))
    .map((d) => ({ abs: path.join(scope.FACTS_ROOT, d.name), mtime: fs.statSync(path.join(scope.FACTS_ROOT, d.name)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
  if (!dirs.length) throw new Error('no-facts: out/facts 为空');
  return dirs[0].abs;
}

function usage() {
  console.log([
    'usage: node bin/fact-query.js [--snapshot=<id>] <command> ...',
    '',
    '  name <pattern>        [--kind=function|symbol] [--repo=<root>] [--regex] [--limit=50]',
    '  ast <op>              --file=<rel> [--line-from=N] [--line-to=N] [--limit=200]   op=call|assign|deref|subscript|switch-case',
    '  cg <fnName>           [--direction=callees|callers] [--limit=200]',
    '  source <file> <line>  [--count=5]',
    '  type <expr|file:line> [--exact] [--limit=20]',
    '  check-sites <fnName>',
    '  flow                  [--from=a] [--to=b]'
  ].join('\n'));
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];
  if (!cmd || cmd === 'help' || cmd === '--help') { usage(); return 0; }
  const idx = new FactsIndex(resolveSnapshotDir(args.snapshot));

  switch (cmd) {
    case 'name': {
      if (!args._[1]) throw new Error('name-required');
      return { command: 'Qname', pattern: args._[1], results: idx.Qname(args._[1], { kind: args.kind, repo: args.repo, regex: args.regex, limit: args.limit || 50 }) };
    }
    case 'ast': {
      if (!args._[1]) throw new Error('operation-required');
      return { command: 'Qast', operation: args._[1], results: idx.Qast(args._[1], { file: args.file, startLine: args.lineFrom, endLine: args.lineTo, limit: args.limit || 200 }) };
    }
    case 'cg': {
      if (!args._[1]) throw new Error('function-required');
      return { command: 'Qcg', function: args._[1], direction: args.direction || 'callees', results: idx.Qcg(args._[1], { direction: args.direction, limit: args.limit || 200 }) };
    }
    case 'source': {
      if (!args._[1] || !args._[2]) throw new Error('file-and-line-required');
      return { command: 'getSource', result: idx.getSource(args._[1], Number(args._[2]), args.count || 5) };
    }
    case 'type': {
      if (!args._[1]) throw new Error('target-required');
      return { command: 'getType', result: idx.getType(args._[1], { exact: args.exact, limit: args.limit || 20 }) };
    }
    case 'check-sites': {
      if (!args._[1]) throw new Error('function-required');
      return { command: 'findCheckSites', result: idx.findCheckSites(args._[1]) };
    }
    case 'flow': {
      return { command: 'Qflow', result: idx.Qflow() };
    }
    default:
      throw new Error(`unknown-command: ${cmd}`);
  }
}

try {
  const out = main();
  if (out) console.log(JSON.stringify(out, null, 2));
  process.exitCode = 0;
} catch (e) {
  console.error(String(e.message || e));
  process.exitCode = 1;
}
