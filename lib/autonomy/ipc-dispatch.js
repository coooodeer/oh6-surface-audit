'use strict';

const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { sha256File } = require('../facts/ids');

/** 复用事实层的 rust-ast-probe：行格式 file\tkind\tname\tline\tendLine\tctx\targc */
function probeRows(binary, fileAbs) {
  const r = cp.spawnSync(binary, [fileAbs], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (r.status !== 0 || r.error) return null;
  const rows = [];
  for (const line of r.stdout.split('\n')) {
    if (!line.trim()) continue;
    const [absolute, kind, name, rowLine, endLine, ctx, argc] = line.trimEnd().split('\t');
    rows.push({ file: absolute, kind, name, line: Number(rowLine), endLine: Number(endLine) || 0,
      ctx: ctx || '', argc: Number(argc) || 0 });
  }
  return rows;
}

/** Rust `impl_enum_trait!` 派发：enum 顺序固定 + 同一 stub 参数对象的唯一 `stub.<method>` 调用。 */
function rustDispatchOf(fn, stubRows, enumRows, functions, cfg) {
  const qualified = fn.qualified || fn.name;
  const arms = stubRows.filter((row) => row.kind === 'ipc-arm' && row.ctx === qualified);
  const calls = stubRows.filter((row) => row.kind === 'ipc-call' && row.ctx === qualified);
  const unresolved = stubRows.filter((row) => row.kind === 'ipc-unresolved' && row.ctx === qualified);
  if (!arms.length) return { status: 'no-rust-dispatch-arms', edges: [], defaultLine: null, shapeStatus: 'no-rust-dispatch-arms' };
  const variants = enumRows.filter((row) => row.kind === 'ipc-enum');
  const enumOk = Array.isArray(cfg.expectedEnum) && variants.length === cfg.expectedEnum.length &&
    variants.every((row, i) => row.name === cfg.expectedEnum[i]);
  const edges = arms.map((arm) => {
    const defLine = enumOk ? (variants.find((v) => v.name === arm.name) || {}).line || null : null;
    const matching = calls.filter((c) => c.name.startsWith(`${arm.name}->`));
    const bad = unresolved.some((u) => u.name === arm.name) || matching.length !== 1;
    if (bad) {
      return { code: arm.name, line: arm.line, calls: [], terminates: true, defLine,
        handler: null, handlerCallLine: null,
        status: !enumOk ? 'code-definition-unresolved'
          : unresolved.some((u) => u.name === arm.name) ? 'same-object-handler-unresolved'
          : 'same-object-handler-unresolved' };
    }
    const methodName = matching[0].name.slice(arm.name.length + 2);
    const candidates = functions.filter((other) => other.role === 'production' && other.language === 'rust' &&
      other.name === methodName && other.owner === cfg.handlerOwner && other.factId !== fn.factId);
    return { code: arm.name, line: arm.line, calls: [{ name: methodName, line: matching[0].line }],
      terminates: true, defLine,
      handler: candidates.length === 1 ? candidates[0] : null,
      handlerCallLine: candidates.length === 1 ? matching[0].line : null,
      status: !enumOk || !defLine ? 'code-definition-unresolved'
        : candidates.length !== 1 ? 'same-object-handler-unresolved' : 'resolved-dispatch' };
  });
  return { status: enumOk ? 'parsed' : 'rust-enum-definition-drift', edges, defaultLine: null,
    shapeStatus: enumOk ? 'parsed' : 'rust-enum-definition-drift' };
}

function rustEnumerate(facts, cfg, idx) {
  const binary = require('../facts/rust').probeBinary();
  if (!binary || !fs.existsSync(binary)) throw new Error('rust-probe-missing');
  if (cfg.probeSha256 && sha256File(binary) !== cfg.probeSha256) throw new Error('rust-probe-stale');
  const enumAbs = path.join(facts.sourceRoot, ...cfg.codeHeader.split('/'));
  const stubAbs = path.join(facts.sourceRoot, ...cfg.stubFile.split('/'));
  if (!fs.existsSync(enumAbs) || !fs.existsSync(stubAbs) ||
      sha256File(enumAbs) !== cfg.codeHeaderSha256) throw new Error('rust-ipc-code-header-stale');
  const stubCheck = facts.verifyFile(cfg.stubFile);
  if (!stubCheck.ok) throw new Error(`rust-dispatch-source-stale: ${cfg.stubFile}`);
  const enumRows = probeRows(binary, enumAbs);
  const stubRows = probeRows(binary, stubAbs);
  if (!enumRows || !stubRows) throw new Error('rust-probe-failed');
  const out = new Map();
  for (const fn of idx.functions.filter((f) => f.role === 'production' && f.language === 'rust' &&
    (cfg.dispatchNames || ['on_remote_request']).includes(f.name))) {
    out.set(fn.factId, rustDispatchOf(fn, stubRows, enumRows, idx.functions, cfg));
  }
  return out;
}

function casesOf(source, startLine, shape) {
  const Parser = require('../../../oh6-framework-want-leak-miner/node_modules/tree-sitter');
  const Cpp = require('../../../oh6-framework-want-leak-miner/node_modules/tree-sitter-cpp');
  const parser = new Parser();
  parser.setLanguage(Cpp);
  const tree = parser.parse(source, null, { bufferSize: 1024 * 1024 });
  let fn = tree.rootNode.descendantForPosition({ row: startLine - 1, column: 0 });
  while (fn && fn.type !== 'function_definition') fn = fn.parent;
  if (!fn || fn.startPosition.row + 1 !== startLine || fn.hasError) {
    return { status: 'function-ast-unavailable', cases: [] };
  }
  const switches = [];
  function visit(node) {
    if (node.type === 'switch_statement' && node.namedChild(0)?.text === '(code)') switches.push(node);
    for (let i = 0; i < node.namedChildCount; i += 1) visit(node.namedChild(i));
  }
  visit(fn);
  if (switches.length !== 1) return { status: 'switch-code-not-unique', cases: [] };
  const sw = switches[0];
  if (/#\s*(if|elif|else|endif|define)\b/.test(sw.text)) {
    return { status: 'conditional-dispatch-unknown', cases: [] };
  }
  const body = sw.namedChild(1);
  const rows = [];
  let hasDefault = false;
  for (let i = 0; i < body.namedChildCount; i += 1) {
    const branch = body.namedChild(i);
    if (branch.type !== 'case_statement') return { status: 'switch-branch-unknown', cases: [] };
    const label = branch.namedChild(0);
    const code = shape === 'tokensync-enum'
      ? /^static_cast<uint32_t>\(TokenSyncInterfaceCode::([A-Z_]+)\)$/.exec(label?.text)?.[1] || null
      : label?.type === 'identifier' ? label.text : null;
    if (!code) {
      if (!/^default\s*:/.test(branch.text) || hasDefault) {
        return { status: 'code-label-unknown', cases: [] };
      }
      hasDefault = true;
      continue;
    }
    const calls = [];
    function collect(node) {
      if (node.type === 'call_expression') {
        const callee = node.childForFieldName('function');
        if (callee?.type === 'identifier') calls.push({ name: callee.text, line: node.startPosition.row + 1 });
      }
      for (let j = 0; j < node.namedChildCount; j += 1) collect(node.namedChild(j));
    }
    collect(branch);
    const statements = shape === 'tokensync-enum' ? branch.namedChildren.slice(1)
      : branch.namedChild(1)?.namedChildren || [];
    const terminates = statements[statements.length - 1]?.type === 'break_statement';
    rows.push({ code, line: branch.startPosition.row + 1, calls, terminates });
  }
  return { status: hasDefault ? 'parsed' : 'default-branch-unknown', cases: rows,
    defaultLine: hasDefault ? body.namedChildren.find((n) => n.type === 'case_statement' &&
      /^default\s*:/.test(n.text)).startPosition.row + 1 : null };
}

function codeDefinition(text, code, shape) {
  if (shape === 'tokensync-enum') {
    const Parser = require('../../../oh6-framework-want-leak-miner/node_modules/tree-sitter');
    const Cpp = require('../../../oh6-framework-want-leak-miner/node_modules/tree-sitter-cpp');
    const parser = new Parser();
    parser.setLanguage(Cpp);
    const root = parser.parse(text).rootNode;
    const enums = [];
    function visit(node) {
      if (node.type === 'enum_specifier' && node.namedChildren.some((c) =>
        c.type === 'type_identifier' && c.text === 'TokenSyncInterfaceCode')) enums.push(node);
      for (const child of node.namedChildren) visit(child);
    }
    visit(root);
    if (enums.length !== 1 || enums[0].hasError || /#\s*(if|elif|else|endif|define)\b/.test(enums[0].text)) return null;
    const rows = enums[0].namedChildren.find((c) => c.type === 'enumerator_list')?.namedChildren || [];
    // shortcut: only the fixed sequential TokenSync enum is supported; prove numeric aliases before generalizing.
    if (rows.length !== 3 || rows[0].text !== 'GET_REMOTE_HAP_TOKEN_INFO = 0x0000' ||
        rows[1].text !== 'DELETE_REMOTE_HAP_TOKEN_INFO' ||
        rows[2].text !== 'UPDATE_REMOTE_HAP_TOKEN_INFO') return null;
    const matches = rows.filter((row) => row.type === 'enumerator' && row.namedChild(0)?.text === code);
    return matches.length === 1 ? matches[0].startPosition.row + 1 : null;
  }
  const lines = text.split(/\r?\n/);
  const matches = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (new RegExp(`^\\s*${code}\\s*=`).test(lines[i])) matches.push(i + 1);
  }
  return matches.length === 1 ? matches[0] : null;
}

function dispatchOf(fn, source, header, functions, shape) {
  const parsed = casesOf(source, fn.startLine, shape);
  const edges = [];
  for (const branch of parsed.cases) {
    const candidates = branch.calls.flatMap((call) => functions.filter((other) =>
      other.role === 'production' && other.name === call.name && other.owner === fn.owner &&
      other.factId !== fn.factId).map((handler) => ({ handler, call })));
    const defLine = codeDefinition(header, branch.code, shape);
    edges.push({ ...branch, defLine, handler: candidates.length === 1 ? candidates[0].handler : null,
      handlerCallLine: candidates.length === 1 ? candidates[0].call.line : null,
      status: !branch.terminates ? 'fallthrough-unknown'
        : !defLine ? 'code-definition-unresolved'
        : candidates.length !== 1 ? 'same-object-handler-unresolved' : 'resolved-dispatch' });
  }
  return { ...parsed, edges };
}

function enumerate(facts, scope, idx) {
  const cfg = scope.ipcDispatch;
  if (!cfg) return new Map();
  if (cfg.shape === 'rust-enum') return rustEnumerate(facts, cfg, idx);
  const headerCheck = facts.verifyFile(cfg.codeHeader);
  if (!headerCheck.ok || headerCheck.actual !== cfg.codeHeaderSha256) {
    throw new Error(`ipc-code-header-stale: ${cfg.codeHeader}`);
  }
  for (const proof of cfg.buildProofs) {
    const abs = path.join(facts.sourceRoot, ...proof.file.split('/'));
    if (sha256File(abs) !== proof.sha256) throw new Error(`ipc-build-proof-stale: ${proof.file}`);
    const text = fs.readFileSync(abs, 'utf8');
    if (!(proof.requiredTokens || [path.posix.basename(proof.source),
      'interfaces/innerkits/ipc_core/include']).every((token) => text.includes(token))) {
      throw new Error(`ipc-build-proof-unresolved: ${proof.file}`);
    }
  }
  const header = fs.readFileSync(path.join(facts.sourceRoot, ...cfg.codeHeader.split('/')), 'utf8');
  const byFile = new Map();
  const out = new Map();
  for (const fn of idx.functions.filter((f) => f.role === 'production' && f.name === 'OnRemoteRequest')) {
    const rel = fn.sourceRange.file;
    const check = facts.verifyFile(rel);
    if (!check.ok) throw new Error(`ipc-dispatch-source-stale: ${rel}`);
    if (!byFile.has(rel)) byFile.set(rel, fs.readFileSync(path.join(facts.sourceRoot, ...rel.split('/')), 'utf8'));
    const build = cfg.buildProofs.find((proof) => proof.source === rel);
    const model = build ? dispatchOf(fn, byFile.get(rel), header, idx.functions, cfg.shape)
      : { status: 'build-proof-not-selected', edges: [],
        shapeStatus: casesOf(byFile.get(rel), fn.startLine, cfg.shape).status };
    out.set(fn.factId, model);
  }
  return out;
}

module.exports = { casesOf, codeDefinition, dispatchOf, enumerate, rustDispatchOf, probeRows };
