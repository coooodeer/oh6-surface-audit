'use strict';

/**
 * tools/autonomy-blind-corpus-build.js —— 构建跨组件受控盲测事实快照。
 *
 * 设计：
 *   - 输入只有 `eval/autonomy/blind-corpus-spec.json`（组件/接口/方法/文件），**不含期望出口**；
 *     期望标签在 `eval/autonomy/blind-cross-component.json`，构建器不读取。
 *   - 语料文件放在 `test/fixtures/autonomy/`，快照 root 用相对 OpenHarmony 的 `../oh6-surface-audit/...`
 *     路径（`AutonomyFacts.sourceRoot` 仍是 OpenHarmony，path.join 会归一化 `..`），
 *     因此不需要为受控语料改生产代码的 sourceRoot。
 *   - 每个 case 生成：entry function、直接调用事实（gate/operation）、IDL 元数据行；
 *     操作目标/权限 helper 从固定 d4 快照复制真实函数行，保证 verifyFile/源码窗口读取真实源码。
 *   - 输出 `out/facts/<snapshotId>`；不碰五根 d4 与 CES 补充快照。
 *
 * 用法：node tools/autonomy-blind-corpus-build.js [--spec=<file>] [--json]
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ids = require('../lib/autonomy/ids');
const jsonl = require('../lib/autonomy/jsonl');
const schema = require('../lib/facts/schema');

const TOOL_DIR = path.resolve(__dirname, '..');
const WORKSPACE = path.resolve(TOOL_DIR, '..');
const SRC_ROOT = path.join(WORKSPACE, 'OpenHarmony');
const FACTS_ROOT = path.join(TOOL_DIR, 'out', 'facts');
const D4 = 'sha256:2142c229d142bdacc472969fe96d73a36da4554f3775dee4f710b79878997a1e';
const DEFAULT_SPEC = path.join(TOOL_DIR, 'eval', 'autonomy', 'blind-corpus-spec.json');

const L1_TABLES = ['calls', 'cfg', 'dfg', 'files', 'functions', 'guards', 'locks',
  'quality', 'reads', 'sinks', 'symbols', 'types', 'writes'];
const META_TABLES = ['idl', 'sa', 'napi', 'permission', 'ces', 'harness', 'unsupported'];

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function sha256Text(text) {
  return sha256(Buffer.from(text, 'utf8'));
}

function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function parseArgs(argv) {
  const out = { spec: DEFAULT_SPEC, json: false };
  for (const arg of argv) {
    if (arg.startsWith('--spec=')) out.spec = path.resolve(arg.slice('--spec='.length));
    else if (arg === '--json') out.json = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
    else throw new Error(`unknown-arg: ${arg}`);
  }
  return out;
}

function loadD4Functions() {
  const file = path.join(FACTS_ROOT, D4.replace('sha256:', ''), 'l1', 'functions.jsonl');
  const res = jsonl.readJsonl(file, { strict: true });
  return res.rows;
}

function findFunction(rows, predicate, label) {
  const hits = rows.filter(predicate);
  if (hits.length !== 1) throw new Error(`blind-corpus-function-not-unique: ${label} (${hits.length})`);
  return hits[0];
}

function targetFunction(rows, targetClass, method) {
  return findFunction(rows, (row) => row.role === 'production' && row.name === method &&
    String(row.qualified || '').includes(`::${targetClass}::`) &&
    String(row.qualified || '').endsWith(`::${method}`), `${targetClass}::${method}`);
}

function copyFunction(real, snapshotId, blindRoot, kindSeed) {
  return {
    ...real,
    factId: `F:${snapshotId.replace('sha256:', '').slice(0, 12)}:function:${sha256Text(kindSeed).slice(0, 16)}`,
    snapshotId,
    locator: { ...real.locator, repo: blindRoot, file: real.sourceRange.file },
    sourceRange: { ...real.sourceRange },
    quality: { ...real.quality },
    role: 'production'
  };
}

function callArgs(line, openIndex) {
  const open = line.indexOf('(', openIndex);
  if (open < 0) return { argc: 0, args: '' };
  let depth = 0;
  for (let i = open; i < line.length; i += 1) {
    if (line[i] === '(') depth += 1;
    else if (line[i] === ')') {
      depth -= 1;
      if (depth === 0) {
        const args = line.slice(open + 1, i).trim();
        return { argc: args ? args.split(',').length : 0, args };
      }
    }
  }
  const args = line.slice(open + 1).trim();
  return { argc: args ? args.split(',').length : 0, args };
}

function build(specFile) {
  const spec = JSON.parse(fs.readFileSync(specFile, 'utf8'));
  if (!spec.root || !spec.components || !Array.isArray(spec.cases)) {
    throw new Error('blind-corpus-spec-invalid');
  }
  const blindRoot = spec.root.replace(/\\/g, '/').replace(/\/+$/, '');
  const d4 = loadD4Functions();

  // 1) 语料文件与真实依赖文件
  const corpus = spec.cases.map((item) => {
    const rel = `${blindRoot}/${item.file}`;
    const abs = path.resolve(SRC_ROOT, ...rel.split('/'));
    const text = fs.readFileSync(abs, 'utf8');
    return { ...item, rel, text, lines: text.split(/\r?\n/), sha256: sha256Text(text),
      bytes: Buffer.byteLength(text, 'utf8') };
  });

  const realPaths = new Set();
  const helpers = {};
  const targets = {};
  for (const [name, component] of Object.entries(spec.components)) {
    const targetRows = {};
    for (const item of corpus.filter((row) => row.component === name)) {
      const real = targetFunction(d4, component.operation.targetClass, item.method);
      targetRows[item.method] = real;
      realPaths.add(real.sourceRange.file);
    }
    targets[name] = targetRows;
    if (component.checkPermissionQualified) {
      const real = findFunction(d4, (row) => row.qualified === component.checkPermissionQualified &&
        row.role === 'production', component.checkPermissionQualified);
      helpers[`${name}:check`] = real;
      realPaths.add(real.sourceRange.file);
    }
    if (component.nativeHelperQualified) {
      const real = findFunction(d4, (row) => row.qualified === component.nativeHelperQualified &&
        row.role === 'production', component.nativeHelperQualified);
      helpers[`${name}:native`] = real;
      realPaths.add(real.sourceRange.file);
    }
  }
  // 知识头文件（发布规范时 verifyFile 需要）
  for (const rel of [
    'base/accesscontrol/sandbox_manager/services/sandbox_manager/main/cpp/include/service/sandbox_manager_const.h',
    'base/account/os_account/services/accountmgr/src/account_iam/account_iam_service.cpp',
    'base/account/os_account/services/accountmgr/src/account_mgr_service.cpp'
  ]) realPaths.add(rel);

  const fileRows = new Map();
  const fileRow = (rel, text, repo) => {
    const key = rel;
    if (fileRows.has(key)) return fileRows.get(key);
    const row = {
      factId: `F:${'0'.repeat(12)}:file:${sha256Text(rel).slice(0, 16)}`,
      snapshotId: 'pending', kind: 'file',
      locator: { repo, file: rel }, sourceRange: { file: rel, startLine: 1, endLine: text.split(/\r?\n/).length },
      role: 'production', quality: { parse: 'full', resolution: 'syntax-only', errorNodes: 0 },
      producer: 'AG0', schemaVersion: '1',
      path: rel, repo, bytes: Buffer.byteLength(text, 'utf8'),
      lines: text.split(/\r?\n/).length, sha256: sha256Text(text), language: 'cpp'
    };
    fileRows.set(key, row);
    return row;
  };
  for (const item of corpus) fileRow(item.rel, item.text, blindRoot);
  for (const rel of realPaths) {
    const abs = path.resolve(SRC_ROOT, ...rel.split('/'));
    fileRow(rel, fs.readFileSync(abs, 'utf8'), blindRoot);
  }

  // 2) 快照 ID（payload 不含 factId，避免自引用）
  const payload = {
    scope: 'blind-r1',
    corpusVersion: spec.corpusVersion,
    cases: corpus.map((item) => ({ interface: spec.components[item.component].interface,
      method: item.method, file: item.rel, sha256: item.sha256, bytes: item.bytes })),
    realFiles: [...realPaths].sort().map((rel) => ({ path: rel,
      sha256: fileRow(rel).sha256 })),
    tools: { node: process.version, platform: process.platform }
  };
  const snapshotId = `sha256:${sha256(Buffer.from(ids.canonicalJson(payload), 'utf8'))}`;
  const snapHex = snapshotId.replace('sha256:', '');
  const snapShort = snapHex.slice(0, 12);

  // 3) 函数与调用
  const functions = [];
  const calls = [];
  const idlRows = [];
  const seenFact = new Set();
  const pushFunction = (row) => {
    if (seenFact.has(row.factId)) return row;
    seenFact.add(row.factId);
    functions.push({ ...row, snapshotId });
    return row;
  };
  for (const item of corpus) {
    const component = spec.components[item.component];
    const entryQualified = `${component.namespace || ''}${component.owner}::${item.method}`;
    const entryFactId = `F:${snapShort}:function:${sha256Text(`entry:${item.rel}:${item.component}:${item.method}`).slice(0, 16)}`;
    const signature = (item.lines[0] || '').trim();
    pushFunction({
      factId: entryFactId, snapshotId, kind: 'function',
      locator: { repo: blindRoot, file: item.rel, startLine: 1, name: item.method },
      sourceRange: { file: item.rel, startLine: 1, endLine: item.lines.length },
      role: 'production', quality: { parse: 'full', resolution: 'syntax-only', errorNodes: 0 },
      producer: 'AG0', schemaVersion: '1', name: item.method, owner: component.owner,
      qualified: entryQualified, signature, startLine: 1, endLine: item.lines.length,
      bodyHash: item.sha256, argc: 0, isTest: false
    });
    const helper = helpers[`${item.component}:check`];
    const helperFactId = helper ? copyFunction(helper, snapshotId, blindRoot,
      `helper:${item.component}`).factId : null;
    if (helper) pushFunction({ ...copyFunction(helper, snapshotId, blindRoot, `helper:${item.component}`), factId: helperFactId });
    const native = helpers[`${item.component}:native`];
    const nativeFactId = native ? copyFunction(native, snapshotId, blindRoot,
      `native:${item.component}`).factId : null;
    if (native) pushFunction({ ...copyFunction(native, snapshotId, blindRoot, `native:${item.component}`), factId: nativeFactId });
    const target = targets[item.component][item.method];
    const targetCopy = copyFunction(target, snapshotId, blindRoot, `target:${item.component}:${item.method}`);
    pushFunction(targetCopy);

    const addCall = (index, line, calleeName, callee, argc) => {
      const callFactId = `F:${snapShort}:call:${sha256Text(`${item.rel}:${index}:${calleeName}`).slice(0, 16)}`;
      calls.push({
        factId: callFactId, snapshotId, kind: 'call',
        locator: { repo: blindRoot, file: item.rel, line: index + 1, column: 0,
          caller: entryQualified, callee: calleeName },
        sourceRange: { file: item.rel, startLine: index + 1, endLine: index + 1 },
        role: 'production',
        quality: { parse: 'full', resolution: callee ? 'exact' : 'name-only', errorNodes: 0 },
        producer: 'AG0', schemaVersion: '1',
        // 盲测语料把同一方法的多个变体放在不同文件；以 factId 作为 caller key，
        // 避免不同变体的同名入口调用事实混在一起（scope.binding.callerKey=fact）。
        caller: entryFactId, callerName: entryFactId, calleeName,
        callee: callee || null, line: index + 1, column: 0, argc
      });
    };
    for (let i = 0; i < item.lines.length; i += 1) {
      const line = item.lines[i];
      const checkRe = /\bCheckPermission\s*\(/g;
      let match;
      while ((match = checkRe.exec(line)) !== null) {
        const parsed = callArgs(line, match.index);
        // os_account helper 形状是 CheckPermission(CONST)（argc=1）；sandbox 直接形状是 (token, CONST)。
        addCall(i, line, 'CheckPermission', parsed.argc === 1 ? helperFactId : helpers['sandbox_manager:check'].factId, parsed.argc);
      }
      const nativeMatch = /\bIsFileManagerCalling\s*\(/.exec(line);
      if (nativeMatch && nativeFactId) {
        const parsed = callArgs(line, nativeMatch.index);
        addCall(i, line, 'IsFileManagerCalling', nativeFactId, parsed.argc);
      }
      const opRe = new RegExp(`${escapeRegExp(component.operation.instanceExpression)}\\(\\)\\.([A-Za-z_]\\w*)\\s*\\(`);
      const opMatch = opRe.exec(line);
      if (opMatch) {
        // opRe 的最后一个字符就是方法调用的 '('；从那里解析实参，不能用第一个 '('
        // （GetInstance() 的括号会截断成 0 参数）。
        const openIndex = opMatch.index + opMatch[0].length - 1;
        const parsed = callArgs(line, openIndex);
        addCall(i, line, opMatch[1], null, parsed.argc);
      }
    }
    idlRows.push({
      metadataId: `M:${snapShort}:idl:${sha256Text(`${item.component}:${item.method}:${item.rel}`).slice(0, 16)}`,
      kind: 'idl', snapshotId, sourceFile: item.rel, sourceLine: 1,
      sha256: item.sha256, source: 'own', producer: 'AG0', schemaVersion: '1',
      payload: {
        interface: component.interface, package: null, descriptor: component.interface,
        method: item.method, returnType: 'int', paramCount: 0, params: [],
        ipcCode: null, oneway: false, token: component.token, tokenSource: 'interface_token'
      }
    });
  }

  // 4) 校验行 schema
  for (const row of [...fileRows.values()].map((row) => ({ ...row, snapshotId }))) {
    const res = schema.validateFact(row);
    if (!res.ok) throw new Error(`blind-corpus-file-schema: ${res.errors.join('; ')}`);
  }
  for (const row of functions) {
    const res = schema.validateFact(row);
    if (!res.ok) throw new Error(`blind-corpus-function-schema: ${res.errors.join('; ')}`);
  }
  for (const row of calls) {
    const res = schema.validateFact(row);
    if (!res.ok) throw new Error(`blind-corpus-call-schema: ${res.errors.join('; ')}`);
  }
  for (const row of idlRows) {
    const res = schema.validateMetadata(row);
    if (!res.ok) throw new Error(`blind-corpus-idl-schema: ${res.errors.join('; ')}`);
  }
  if (new Set(idlRows.map((row) => `${row.payload.method}:${row.sourceFile}`)).size !== idlRows.length) {
    throw new Error('blind-corpus-duplicate-entry');
  }

  // 5) 写快照
  const dir = path.join(FACTS_ROOT, snapHex);
  if (fs.existsSync(dir)) throw new Error(`blind-corpus-snapshot-exists: ${snapHex}`);
  fs.mkdirSync(path.join(dir, 'l1'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'metadata'), { recursive: true });
  const writeRows = (file, rows) => {
    fs.writeFileSync(file, rows.length ? `${rows.map((row) => JSON.stringify(row)).join('\n')}\n` : '',
      { encoding: 'utf8' });
  };
  for (const table of L1_TABLES) {
    const rows = table === 'files' ? [...fileRows.values()].map((row) => ({ ...row, snapshotId }))
      : table === 'functions' ? functions : table === 'calls' ? calls : [];
    writeRows(path.join(dir, 'l1', `${table}.jsonl`), rows);
  }
  for (const table of META_TABLES) {
    writeRows(path.join(dir, 'metadata', `${table}.jsonl`), table === 'idl' ? idlRows : []);
  }
  const snapshot = {
    snapshotId, scope: 'blind-r1', policyVersion: '1.0.0', workingTreeDirty: false,
    roots: [{
      root: blindRoot, repo: blindRoot, part: 'blind', head: 'controlled-corpus',
      dirty: false, dirtyEntries: 0, files: fileRows.size, productionFiles: fileRows.size,
      bytes: [...fileRows.values()].reduce((sum, row) => sum + row.bytes, 0),
      sourceManifestHash: sha256Text([...fileRows.keys()].sort().join('\n'))
    }],
    compdb: { parts: [], totals: { entries: 0, rootFiles: 0 } },
    genVisibility: { referenced: 0, missing: 0 },
    metadata: { counts: { idl: idlRows.length, sa: 0, permission: 0, external: 0 } },
    toolVersions: { node: process.version, platform: process.platform }
  };
  const artifactRefs = ['snapshot.json', 'manifest.json', 'build-manifest.json', 'metadata-manifest.json',
    ...L1_TABLES.map((table) => `l1/${table}.jsonl`), ...META_TABLES.map((table) => `metadata/${table}.jsonl`)];
  const manifest = {
    manifestId: `AM-${sha256Text(`${snapshotId}:${artifactRefs.join('|')}`).slice(0, 16)}`,
    snapshotId, factSchemaVersion: '1', rulesVersion: 'blind-corpus-1.0.0',
    obligationVersion: null, l6IndexVersion: null, verificationRunId: null,
    reportVersion: null, createdAt: new Date().toISOString(), producer: 'AG0', artifactRefs
  };
  fs.writeFileSync(path.join(dir, 'snapshot.json'), `${JSON.stringify(snapshot, null, 2)}\n`, 'utf8');
  fs.writeFileSync(path.join(dir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  fs.writeFileSync(path.join(dir, 'build-manifest.json'), `${JSON.stringify({
    snapshotId, parts: [], genVisibility: snapshot.genVisibility,
    compdbWin: { file: 'compdb-win.jsonl', rows: 0, note: 'controlled corpus: no compdb' }
  }, null, 2)}\n`, 'utf8');
  fs.writeFileSync(path.join(dir, 'metadata-manifest.json'), `${JSON.stringify({
    snapshotId, sources: [], counts: snapshot.metadata.counts
  }, null, 2)}\n`, 'utf8');
  fs.writeFileSync(path.join(dir, 'compdb-win.jsonl'), '', 'utf8');
  fs.writeFileSync(path.join(dir, 'coverage.jsonl'), '', 'utf8');

  return { snapshotId, manifestId: manifest.manifestId, dir, blindRoot,
    cases: corpus.length, functions: functions.length, calls: calls.length,
    files: fileRows.size, idl: idlRows.length, components: Object.keys(spec.components) };
}

function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write('usage: node tools/autonomy-blind-corpus-build.js [--spec=<file>] [--json]\n');
    return 0;
  }
  const result = build(args.spec);
  process.stdout.write(`${JSON.stringify({ ok: true, ...result })}\n`);
  return 0;
}

module.exports = { build, main };

if (require.main === module) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: e.message })}\n`);
    process.exitCode = 1;
  }
}
