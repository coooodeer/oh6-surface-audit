'use strict';

/**
 * lib/facts/cfg.js —— 函数级 CFG（AG0.3）。
 *
 * 结构：entry / exit / branch / loop / call / return / join。
 * 边：true / false / fallthrough / back / return / jump。
 *
 * 设计取舍：
 *   - goto / 异常路径 / switch 落穿不精确建模，记为 unsupportedEdges 并计入 coverage；
 *   - 调用点在**表达式级**采集（`= f(x)`、`if (g())`、`return h()`），按源码顺序串成 call 节点；
 *   - if 的两个分支分别用 true/false 边连到分支体首节点，join 节点显式创建。
 */

function lineOf(node) {
  return node.startPosition.row + 1;
}

/** 收集子树里的 call_expression（按源码顺序；不进入 lambda/嵌套函数体） */
function callsIn(node) {
  const out = [];
  if (!node) return out;
  const stack = [node];
  while (stack.length) {
    const n = stack.pop();
    if (n.type === 'lambda_expression' || n.type === 'function_definition') continue;
    if (n.type === 'call_expression') out.push(n);
    for (let i = n.namedChildCount - 1; i >= 0; i -= 1) stack.push(n.namedChild(i));
  }
  out.sort((a, b) => a.startIndex - b.startIndex);
  return out;
}

/**
 * @param {object} fnNode tree-sitter function_definition（宏体时传 compound_statement 自身）
 * @param {object} bodyNode 函数体
 */
function buildCfg(fnNode, bodyNode) {
  const nodes = [];
  const edges = [];
  let unsupportedEdges = 0;
  const EXIT = 'nEXIT';

  const push = (kind, line) => {
    const id = `n${nodes.length + 1}`;
    nodes.push({ id, kind, line });
    return id;
  };
  const link = (from, to, kind) => {
    if (!from || !to) return;
    edges.push({ from, to, kind });
  };
  const consume = (incoming, target) => {
    for (const p of incoming || []) link(p.from, target, p.kind);
  };
  const pass = (target) => [{ from: target, kind: 'fallthrough' }];
  /** 把 expr 里的调用按顺序串成 call 节点 */
  const emitCalls = (exprNode, incoming) => {
    let cur = incoming;
    for (const c of callsIn(exprNode)) {
      const id = push('call', lineOf(c));
      consume(cur, id);
      cur = pass(id);
    }
    return cur;
  };

  const entry = push('entry', fnNode.startPosition.row + 1);
  const loopStack = [];

  function run(stmt, incoming) {
    if (!stmt) return incoming;
    switch (stmt.type) {
      case 'compound_statement': {
        let cur = incoming;
        for (let i = 0; i < stmt.namedChildCount; i += 1) cur = run(stmt.namedChild(i), cur);
        return cur;
      }
      case 'declaration':
      case 'expression_statement':
        return emitCalls(stmt, incoming);
      case 'if_statement': {
        const cond = stmt.childForFieldName('condition');
        const pre = emitCalls(cond, incoming);
        const b = push('branch', lineOf(stmt));
        consume(pre, b);
        const cons = stmt.childForFieldName('consequence');
        const alt = stmt.childForFieldName('alternative');
        const consOut = cons ? run(cons, [{ from: b, kind: 'true' }]) : [];
        const altOut = alt ? run(alt, [{ from: b, kind: 'false' }]) : [{ from: b, kind: 'false' }];
        const join = push('join', lineOf(stmt));
        for (const p of [...consOut, ...altOut]) {
          const kind = p.kind === 'return' ? 'return'
            : (p.kind === 'true' || p.kind === 'false') ? p.kind
              : 'fallthrough';
          link(p.from, join, kind);
        }
        return pass(join);
      }
      case 'for_statement':
      case 'for_range_loop':
      case 'while_statement':
      case 'do_statement': {
        const cond = stmt.childForFieldName('condition') || stmt.childForFieldName('operator');
        const pre = emitCalls(cond, incoming);
        const loop = push('loop', lineOf(stmt));
        consume(pre, loop);
        const join = push('join', lineOf(stmt));
        loopStack.push({ loop, join });
        const bodyNode = stmt.childForFieldName('body');
        const bodyOut = bodyNode ? run(bodyNode, [{ from: loop, kind: 'true' }]) : [];
        loopStack.pop();
        for (const p of bodyOut) link(p.from, loop, 'back');
        link(loop, join, 'false');
        return pass(join);
      }
      case 'switch_statement': {
        const cond = stmt.childForFieldName('condition');
        const pre = emitCalls(cond, incoming);
        const b = push('branch', lineOf(stmt));
        consume(pre, b);
        const join = push('join', lineOf(stmt));
        const bodyNode = stmt.childForFieldName('body');
        if (bodyNode) {
          let cur = [{ from: b, kind: 'true' }];
          for (let i = 0; i < bodyNode.namedChildCount; i += 1) {
            const caseNode = bodyNode.namedChild(i);
            if (caseNode.type !== 'case_statement') continue;
            cur = run(caseNode, cur);
          }
          for (const p of cur) link(p.from, join, 'fallthrough');
        }
        unsupportedEdges += 1;
        link(b, join, 'false');
        return pass(join);
      }
      case 'return_statement': {
        const pre = emitCalls(stmt, incoming);
        const r = push('return', lineOf(stmt));
        consume(pre, r);
        link(r, EXIT, 'return');
        return [];
      }
      case 'break_statement':
      case 'continue_statement': {
        const top = loopStack[loopStack.length - 1];
        const from = incoming.length ? incoming[0].from : null;
        if (top) link(from, stmt.type === 'break_statement' ? top.join : top.loop, 'jump');
        else { link(from, EXIT, 'jump'); unsupportedEdges += 1; }
        return [];
      }
      case 'goto_statement': {
        unsupportedEdges += 1;
        link(incoming.length ? incoming[0].from : null, EXIT, 'jump');
        return [];
      }
      case 'try_statement': {
        const bodyOut = run(stmt.childForFieldName('body'), incoming);
        const handlerOut = run(stmt.childForFieldName('handler'), incoming);
        unsupportedEdges += 1;
        return [...bodyOut, ...handlerOut];
      }
      case 'case_statement': {
        let cur = incoming;
        for (let i = 0; i < stmt.namedChildCount; i += 1) {
          const ch = stmt.namedChild(i);
          if (ch.type === 'case_statement' || ch.type === 'switch_case' || ch.type === 'case_label') continue;
          cur = run(ch, cur);
        }
        return cur;
      }
      default:
        return emitCalls(stmt, incoming);
    }
  }

  const body = bodyNode || fnNode.childForFieldName('body');
  const out = body ? run(body, [{ from: entry, kind: 'fallthrough' }]) : pass(entry);
  for (const p of out) link(p.from, EXIT, p.kind === 'return' ? 'return' : 'fallthrough');
  nodes.push({ id: EXIT, kind: 'exit', line: fnNode.endPosition.row + 1 });

  const coverage = edges.length === 0 ? 1 : Number(Math.max(0, 1 - unsupportedEdges / edges.length).toFixed(4));
  return { nodes, edges, coverage, unsupportedEdges };
}

module.exports = { buildCfg, callsIn };
