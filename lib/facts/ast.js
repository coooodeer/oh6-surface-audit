'use strict';

/**
 * lib/facts/ast.js —— tree-sitter AST 的通用helpers（AG0.3）。
 *
 * 只做通用结构：不引入任何类语义。所有提取器共用这里的遍历/命名/文本工具。
 */

const crypto = require('crypto');

const BUILTIN_TYPES = new Set([
  'void', 'bool', 'char', 'short', 'int', 'long', 'float', 'double', 'signed', 'unsigned',
  'size_t', 'ssize_t', 'wchar_t', 'char8_t', 'char16_t', 'char32_t', 'auto',
  'int8_t', 'int16_t', 'int32_t', 'int64_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
  'intptr_t', 'uintptr_t', 'ptrdiff_t', 'nullptr_t', 'byte', 'string', 'wstring',
  'errno_t', 'OHOS::ErrCode'
]);

const KEYWORDS = new Set([
  'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default', 'return', 'break', 'continue',
  'goto', 'sizeof', 'alignof', 'decltype', 'static_cast', 'dynamic_cast', 'const_cast',
  'reinterpret_cast', 'new', 'delete', 'throw', 'try', 'catch', 'const', 'static', 'inline',
  'virtual', 'explicit', 'override', 'final', 'noexcept', 'constexpr', 'consteval', 'volatile',
  'mutable', 'typename', 'template', 'class', 'struct', 'enum', 'union', 'namespace', 'using',
  'typedef', 'public', 'private', 'protected', 'this', 'nullptr', 'true', 'false', 'operator',
  'and', 'or', 'not', 'true', 'false'
]);

function sha256(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

/** 迭代遍历（先序），visit(node) 返回 false 可跳过子树 */
function walk(root, visit) {
  const stack = [root];
  while (stack.length) {
    const node = stack.pop();
    if (visit(node) === false) continue;
    for (let i = node.namedChildCount - 1; i >= 0; i -= 1) stack.push(node.namedChild(i));
  }
}

function textOf(node) {
  return node ? node.text : '';
}

function lineOf(node) {
  return node ? node.startPosition.row + 1 : 0;
}

function columnOf(node) {
  return node ? node.startPosition.column : 0;
}

/** 声明器链上最后一层的名字（identifier / field_identifier / qualified_identifier / operator_name） */
function declaratorName(decl) {
  let d = decl;
  let guard = 0;
  while (d && guard < 10) {
    guard += 1;
    if (['function_declarator', 'pointer_declarator', 'reference_declarator', 'parenthesized_declarator',
      'array_declarator', 'init_declarator'].includes(d.type)) {
      const inner = d.childForFieldName('declarator');
      if (!inner) break;
      d = inner;
      continue;
    }
    break;
  }
  if (!d) return { name: null, qualified: null };
  if (d.type === 'qualified_identifier') {
    const nameNode = d.childForFieldName('name');
    return { name: nameNode ? nameNode.text : d.text, qualified: d.text.replace(/\s+/g, '') };
  }
  if (d.type === 'destructor_name' || d.type === 'operator_name' || d.type === 'field_identifier' || d.type === 'identifier') {
    return { name: d.text.replace(/\s+/g, ''), qualified: d.text.replace(/\s+/g, '') };
  }
  return { name: d.text.replace(/\s+/g, ''), qualified: d.text.replace(/\s+/g, '') };
}

/** 从声明里取类型文本（跳过 storage/qualifier） */
function declarationType(node) {
  const t = node.childForFieldName('type');
  return t ? t.text.replace(/\s+/g, ' ').trim() : null;
}

/** 提取函数参数名与个数 */
function functionParams(fnNode) {
  const decl = fnNode.childForFieldName('declarator');
  const params = decl ? decl.childForFieldName('parameters') : null;
  if (!params) return { count: 0, names: [] };
  const names = [];
  let count = 0;
  for (let i = 0; i < params.namedChildCount; i += 1) {
    const p = params.namedChild(i);
    if (p.type !== 'parameter_declaration' && p.type !== 'optional_parameter_declaration') continue;
    count += 1;
    const d = p.childForFieldName('declarator');
    const nm = d ? declaratorName(d).name : null;
    if (nm) names.push(nm);
  }
  return { count, names };
}

/** 从一段文本里抽标识符（去关键字/纯数字），保序去重 */
function identifiersIn(text, limit = 32) {
  const out = [];
  const seen = new Set();
  const re = /[A-Za-z_][A-Za-z0-9_]*/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const id = m[0];
    if (KEYWORDS.has(id) || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
    if (out.length >= limit) break;
  }
  return out;
}

/** 类型文本 → 语法层 kind（不猜：只认内建与同文件已声明的 record） */
function typeKindOf(typeText, records) {
  const t = String(typeText || '').replace(/\b(const|volatile|static|inline|struct|class|enum|typename)\b/g, ' ').trim();
  if (!t) return 'unknown';
  const base = t.replace(/[*&\s<>\[\],:]+/g, ' ').trim().split(/\s+/)[0] || '';
  if (BUILTIN_TYPES.has(base)) return 'builtin';
  if (records && records.has(base)) return 'record';
  return 'unknown';
}

/** 变量种类：param / local / field / global / unknown */
function varKindOf(name, ctx) {
  if (!name) return 'unknown';
  if (name.includes('->') || name.includes('.')) return 'field';
  if (name.startsWith('::')) return 'global';
  const bare = name.replace(/^[^A-Za-z_]*/, '');
  if (ctx && ctx.params && ctx.params.has(bare)) return 'param';
  if (ctx && ctx.locals && ctx.locals.has(bare)) return 'local';
  if (ctx && ctx.fields && ctx.fields.has(bare)) return 'field';
  return 'unknown';
}

/** 由 function_definition 的 declarator 解析出 {name, owner}：
 *  限定名（Out::Method）与祖先 owner（namespace/class）合并，且避免重复前缀。 */
function resolveFunctionName(named, ownerParts) {
  let name = (named && named.name) || '<anonymous>';
  let parts = [];
  if (named && named.qualified && named.qualified.includes('::')) {
    parts = named.qualified.split('::');
    name = parts.pop();
  }
  const base = [...(ownerParts || [])];
  if (parts.length) {
    if (base.length && parts[0] === base[base.length - 1]) parts = parts.slice(1);
    return { name, owner: [...base, ...parts] };
  }
  return { name, owner: base };
}

module.exports = {
  BUILTIN_TYPES, KEYWORDS, sha256, walk, textOf, lineOf, columnOf,
  declaratorName, declarationType, functionParams, identifiersIn, typeKindOf, varKindOf,
  resolveFunctionName
};
