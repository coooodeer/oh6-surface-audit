'use strict';

/**
 * lib/facts/dfg.js —— 函数内粗粒度 def-use（AG0.3）。
 *
 * 纪律：
 *   - 只做函数内、按源码顺序的「最近一次 def → 后续 use」；
 *   - 不建模别名/指针逃逸/跨分支合流（这些正是 Qflow 固定 unsupported 的原因）；
 *   - coverage = 有 reaching def 的 use 占比，作为诚实度指标。
 */

const { identifiersIn } = require('./ast');

function lineOf(node) {
  return node.startPosition.row + 1;
}

function nameOfDeclarator(d) {
  const { declaratorName } = require('./ast');
  return declaratorName(d).name;
}

/** 宏体/函数体共用：给出 body 节点即可 */
function buildDfg(fnNode, bodyNode, paramNames) {
  const defs = [];
  const uses = [];
  const edges = [];
  let defSeq = 0;
  let useSeq = 0;
  const lastDef = new Map();

  const addDef = (name, line, kind) => {
    if (!name) return null;
    const id = `d${(defSeq += 1)}`;
    defs.push({ id, var: name, line, kind });
    lastDef.set(name, id);
    return id;
  };
  const addUse = (name, line) => {
    if (!name) return null;
    const id = `u${(useSeq += 1)}`;
    uses.push({ id, var: name, line });
    if (lastDef.has(name)) edges.push({ from: lastDef.get(name), to: id, kind: 'def-use' });
    return id;
  };

  for (const p of paramNames || []) addDef(p, fnNode.startPosition.row + 1, 'param');

  function walk(node) {
    if (!node) return;
    if (node.type === 'function_definition' || node.type === 'lambda_expression') return; // 跨函数不建模
    switch (node.type) {
      case 'assignment_expression': {
        const left = node.childForFieldName('left');
        const right = node.childForFieldName('right');
        if (right) walkUses(right, 4);
        addDef(left ? left.text.replace(/\s+/g, ' ') : null, lineOf(node), 'assign');
        return;
      }
      case 'update_expression': {
        const arg = node.childForFieldName('argument');
        if (arg) { addUse(arg.text.replace(/\s+/g, ' '), lineOf(node)); addDef(arg.text.replace(/\s+/g, ' '), lineOf(node), 'assign'); }
        return;
      }
      case 'declaration': {
        const typeNode = node.childForFieldName('type');
        const typeStart = typeNode ? typeNode.startIndex : -1;
        for (let i = 0; i < node.namedChildCount; i += 1) {
          const ch = node.namedChild(i);
          // 不能用对象身份比较：tree-sitter 的 Node 包装器可能每次访问都新建
          if (ch.startIndex === typeStart) continue;
          if (ch.type === 'init_declarator') {
            const value = ch.childForFieldName('value');
            if (value) walkUses(value, 4);
            addDef(nameOfDeclarator(ch), lineOf(ch), 'assign');
          } else {
            addDef(nameOfDeclarator(ch), lineOf(ch), 'assign');
          }
        }
        return;
      }
      case 'return_statement': {
        for (let i = 0; i < node.namedChildCount; i += 1) walkUses(node.namedChild(i), 4);
        return;
      }
      case 'if_statement':
      case 'while_statement':
      case 'do_statement':
      case 'for_statement':
      case 'switch_statement': {
        const cond = node.childForFieldName('condition') || node.childForFieldName('value');
        if (cond) walkUses(cond, 6);
        const condStart = cond ? cond.startIndex : -1;
        for (let i = 0; i < node.namedChildCount; i += 1) {
          const ch = node.namedChild(i);
          if (ch.startIndex === condStart) continue;
          walk(ch);
        }
        return;
      }
      case 'call_expression': {
        const args = node.childForFieldName('arguments');
        if (args) walkUses(args, 3);
        return;
      }
      default:
        for (let i = 0; i < node.namedChildCount; i += 1) walk(node.namedChild(i));
    }
  }

  function walkUses(node, limit) {
    const ids = identifiersIn(node.text, limit);
    for (const id of ids) addUse(id, lineOf(node));
  }

  const body = bodyNode || fnNode.childForFieldName('body');
  if (body) walk(body);

  const coverage = uses.length === 0 ? 1 : Number((edges.length / uses.length).toFixed(4));
  return { defs, uses, edges, coverage };
}

module.exports = { buildDfg };
