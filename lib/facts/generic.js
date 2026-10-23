'use strict';

/**
 * lib/facts/generic.js —— 通用结构事实（AG0.4 的输入）：sinks / guards / reads / writes / locks。
 *
 * 纪律：只认通用形态（分配、拷贝、读写、发布、加锁、条件），不做任何类特定判定。
 * 每条事实都挂在函数 factId 上；没有所属函数（文件级）的调用不产出。
 */

const ids = require('./ids');
const ast = require('./ast');

const SINK_RULES = [
  { kind: 'alloc', re: /^(malloc|calloc|realloc|aligned_alloc|valloc|new|operatornew)$/i },
  { kind: 'copy', re: /^(memcpy|memmove|memset|strcpy|strncpy|strcat|strncat|memcpy_s|memmove_s|strcpy_s|strncpy_s|strcat_s|sprintf|snprintf|vsnprintf|sprintf_s|snprintf_s|wcscpy|wcsncpy)$/i },
  { kind: 'read', re: /^(read|recv|recvfrom|recvmsg|fread|fgets|getc|fgetc|pread|readv|Read|ReadInt32|ReadUint32|ReadString)$/ },
  { kind: 'write', re: /^(write|send|sendto|sendmsg|fwrite|fputs|putc|fputc|pwrite|writev)$/i },
  { kind: 'publish', re: /^(publish|Publish|PublishCommonEvent|PublishEvent|PublishCustomEvent|PostEvent|SendEvent|SendCustomEvent|Notify|NotifyEvent)$/ },
  { kind: 'lock', re: /^(lock|try_lock|pthread_mutex_lock|pthread_rwlock_rdlock|pthread_rwlock_wrlock|LockGuard|UniqueLock|AutoLock|ScopedLock)$/ }
];

const LOCK_ACQUIRE = /^(lock|try_lock|pthread_mutex_lock|pthread_rwlock_rdlock|pthread_rwlock_wrlock|LockGuard|UniqueLock|AutoLock|ScopedLock)$/;
const LOCK_RELEASE = /^(unlock|pthread_mutex_unlock|pthread_rwlock_unlock)$/;

const GUARD_NODES = {
  if_statement: 'if',
  switch_statement: 'switch',
  conditional_expression: 'if',
  while_statement: 'loop',
  for_statement: 'loop',
  do_statement: 'loop'
};

function sinkKindOf(name) {
  const n = String(name || '').replace(/[^A-Za-z0-9_]/g, '');
  for (const r of SINK_RULES) if (r.re.test(n)) return r.kind;
  return null;
}

function hasNullCheck(condText) {
  return /(==|!=)\s*(nullptr|NULL|0)\b/.test(condText) || /^\s*!\s*[A-Za-z_]\w*\s*$/.test(condText);
}


function extractGeneric(tree, ctx, macroBodies) {
  const sinks = [];
  const guards = [];
  const reads = [];
  const writes = [];
  const locks = [];

  function push(list, kind, payload) {
    const seq = list.length + 1;
    const { fn, ...rest } = payload;
    const locator = { repo: ctx.repo, file: ctx.rel, line: payload.line, column: payload.column, fn: fn.factId, seq };
    list.push({
      factId: ids.factIdOf(ctx.snapshotId, kind, locator),
      snapshotId: ctx.snapshotId,
      kind,
      locator,
      sourceRange: { file: ctx.rel, startLine: payload.line, endLine: payload.line },
      role: ctx.role,
      quality: { parse: ctx.parse, resolution: 'syntax-only', errorNodes: ctx.errorNodes },
      producer: 'AG0',
      schemaVersion: '1',
      ...rest,
      function: fn.factId,
      functionName: fn.name
    });
  }

  function visit(node, fn, owner) {
    if (node.type === 'namespace_definition' || node.type === 'class_specifier' || node.type === 'struct_specifier') {
      const nameNode = node.childForFieldName('name');
      const next = nameNode ? [...owner, nameNode.text] : owner;
      for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), fn, next);
      return;
    }
    if (node.type === 'compound_statement' && macroBodies && macroBodies.has(node.startIndex)) {
      const m = macroBodies.get(node.startIndex);
      const mctx = { factId: m.factId, name: m.name, params: new Set(), locals: new Set() };
      for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), mctx, owner);
      return;
    }
    if (node.type === 'function_definition') {
      const decl = node.childForFieldName('declarator');
      const named = ast.declaratorName(decl);
      const resolved = ast.resolveFunctionName(named, owner);
      const qualified = resolved.owner.length ? `${resolved.owner.join('::')}::${resolved.name}` : resolved.name;
      const locator = { repo: ctx.repo, file: ctx.rel, startLine: ast.lineOf(node), name: qualified };
      const factId = ids.factIdOf(ctx.snapshotId, 'function', locator);
      const params = new Set(ast.functionParams(node).names);
      const fnCtx = { factId, name: qualified, params, locals: new Set() };
      for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), fnCtx, resolved.owner);
      return;
    }

    if (!fn) {
      for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), fn, owner);
      return;
    }

    const line = ast.lineOf(node);
    const column = ast.columnOf(node);

    if (node.type === 'call_expression') {
      const calleeNode = node.childForFieldName('function');
      const calleeName = calleeNode ? calleeNode.text.replace(/\s+/g, '') : '';
      const short = calleeName.split(/::|->|\./).pop().replace(/[^A-Za-z0-9_]/g, '');
      const args = node.childForFieldName('arguments');
      const argc = args ? args.namedChildCount : 0;
      const sk = sinkKindOf(short);
      if (sk) push(sinks, 'sink', { line, column, fn, sinkKind: sk, calleeName, argc });
      if (LOCK_ACQUIRE.test(short)) {
        push(locks, 'lock', { line, column, fn, lockKind: 'acquire', name: calleeName });
      } else if (LOCK_RELEASE.test(short)) {
        push(locks, 'lock', { line, column, fn, lockKind: 'release', name: calleeName });
      }
      if (/^(assert|ASSERT|CHECK|DCHECK)$/.test(short)) {
        push(guards, 'guard', { line, column, fn, guardKind: 'assert', variables: [], dominates: false });
      }
    }

    if (GUARD_NODES[node.type]) {
      const cond = node.childForFieldName('condition') || node.childForFieldName('value');
      const condText = cond ? cond.text : '';
      const vars = ast.identifiersIn(condText, 8);
      const kind = hasNullCheck(condText) && GUARD_NODES[node.type] === 'if' ? 'null-check' : GUARD_NODES[node.type];
      push(guards, 'guard', { line, column, fn, guardKind: kind, variables: vars, dominates: false });
    }

    if (node.type === 'assignment_expression') {
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      const leftText = left ? left.text.replace(/\s+/g, ' ') : '';
      if (leftText) {
        push(writes, 'write', { line, column, fn, expr: leftText.slice(0, 200), varKind: ast.varKindOf(leftText, fn) });
      }
      if (right) {
        for (const v of ast.identifiersIn(right.text, 4)) {
          push(reads, 'read', { line, column, fn, expr: v, varKind: ast.varKindOf(v, fn) });
        }
      }
    }

    if (node.type === 'update_expression') {
      const arg = node.childForFieldName('argument');
      const t = arg ? arg.text.replace(/\s+/g, ' ') : '';
      if (t) push(writes, 'write', { line, column, fn, expr: t.slice(0, 200), varKind: ast.varKindOf(t, fn) });
    }

    for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i), fn, owner);
  }

  visit(tree.rootNode, null, []);
  return { sinks, guards, reads, writes, locks };
}

module.exports = { extractGeneric, sinkKindOf, SINK_RULES, GUARD_NODES };
