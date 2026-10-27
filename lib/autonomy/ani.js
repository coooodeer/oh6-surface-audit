'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { sha256File } = require('../facts/ids');
const { normalizeDefaultNamespace } = require('../facts/arkts');

const ts = require('../../../oh6-framework-want-leak-miner/node_modules/typescript');

function resolveDirect(entry, cfg, texts, functions) {
  if (cfg.method !== 'on' || cfg.nativeName !== 'onExecute' ||
      cfg.handler !== 'RegisterPermActiveStatusCallback' || cfg.namespace !== 'privacyManager' ||
      cfg.library !== 'privacy_ani' || entry.qualified !== 'privacyManager::on') {
    return { status: 'direct-shape-unsupported' };
  }
  const source = ts.createSourceFile(cfg.etsFile, normalizeDefaultNamespace(texts.ets),
    ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const exported = [];
  const native = [];
  function visit(node) {
    const owner = node.parent?.parent;
    if (ts.isFunctionDeclaration(node) && owner && ts.isModuleDeclaration(owner) &&
        owner.name.text === cfg.namespace) {
      if (node.name?.text === entry.method && node.body &&
          node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) exported.push(node);
      if (node.name?.text === cfg.nativeName && !node.body) native.push(node);
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
  if (exported.length !== 1 || native.length !== 1 ||
      source.getLineAndCharacterOfPosition(exported[0].getStart(source)).line + 1 !== entry.line ||
      source.parseDiagnostics.some((d) => d.start >= exported[0].getStart(source) && d.start < exported[0].end)) {
    return { status: 'arkts-function-ambiguous' };
  }
  const fn = exported[0];
  const statement = fn.body.statements[0];
  const call = statement && ts.isExpressionStatement(statement) ? statement.expression : null;
  if (fn.body.statements.length !== 1 || !call || !ts.isCallExpression(call) ||
      !ts.isIdentifier(call.expression) || call.expression.text !== cfg.nativeName ||
      fn.parameters.map((p) => p.name.getText(source)).join(',') !== 'type,permissionList,callback' ||
      call.arguments.map((a) => a.getText(source)).join(',') !== 'type,permissionList,callback') {
    return { status: 'direct-call-ambiguous' };
  }
  const declaration = native[0];
  const namespace = fn.parent.parent;
  const loaders = namespace.body.statements.filter((node) => ts.isExpressionStatement(node) &&
    ts.isCallExpression(node.expression) && ts.isIdentifier(node.expression.expression) &&
    node.expression.expression.text === 'loadLibrary' && node.expression.arguments.length === 1 &&
    ts.isStringLiteral(node.expression.arguments[0]) &&
    node.expression.arguments[0].text === `${cfg.library}.z`);
  if (texts.ets.slice(declaration.getStart(source) - 7, declaration.getStart(source)) !== 'native ' ||
      declaration.parameters.map((p) => `${p.name.getText(source)}:${p.type?.getText(source)}`).join(',') !==
        'type:string,permissionList:Array<Permissions>,callback:Callback<ActiveChangeResponse>' ||
      declaration.type?.getText(source) !== 'void' || loaders.length !== 1) {
    return { status: 'native-declaration-unresolved' };
  }
  const unique = (name) => functions.filter((row) => row.role === 'production' &&
    row.sourceRange?.file === cfg.cppFile &&
    row.qualified === `OHOS::Security::AccessToken::${name}` && row.quality?.errorNodes === 0);
  const init = unique('InitPrivacyFunction');
  const constructor = unique('ANI_Constructor');
  const targets = unique(cfg.handler);
  if (init.length !== 1 || constructor.length !== 1 || targets.length !== 1) {
    return { status: 'native-handler-ambiguous', candidateCount: targets.length };
  }
  const cppLines = texts.cpp.split(/\r?\n/);
  const table = cppLines.slice(init[0].startLine - 1, init[0].endLine).join('\n');
  const constructorBody = cppLines.slice(constructor[0].startLine - 1, constructor[0].endLine).join('\n');
  const rowPattern = /ani_native_function\s*\{\s*"onExecute"\s*,\s*nullptr\s*,\s*reinterpret_cast<void\s*\*>\(RegisterPermActiveStatusCallback\)\s*\}/g;
  const rows = [...table.matchAll(rowPattern)];
  if (rows.length !== 1 ||
      !table.includes('FindNamespace("L@ohos/privacyManager/privacyManager;", &ns)') ||
      !table.includes('Namespace_BindNativeFunctions(ns, nsMethods.data(), nsMethods.size())') ||
      !table.includes('if (status != ANI_OK)') ||
      !/^\s*InitPrivacyFunction\(env\);\s*$/m.test(constructorBody)) {
    return { status: 'ani-table-unresolved' };
  }
  if (!texts.build.includes('ohos_shared_library("privacy_ani")') ||
      !texts.build.includes('"src/privacy_manager.cpp"') ||
      !texts.build.includes('generate_static_abc("privacy_manager")') ||
      !texts.build.includes('"./ets/@ohos.privacyManager.ets"') ||
      !texts.build.includes('"${access_token_path}/interfaces/innerkits/privacy:libprivacy_sdk"')) {
    return { status: 'build-proof-unresolved' };
  }
  return { status: 'resolved', shape: 'direct-namespace', registrationConditional: 'ANI_OK',
    nativeName: cfg.nativeName, nativeFactRef: targets[0].factId,
    callLine: source.getLineAndCharacterOfPosition(call.getStart(source)).line + 1,
    nativeLine: targets[0].startLine,
    tableLine: init[0].startLine + table.slice(0, rows[0].index).split('\n').length - 1 };
}

function resolve(entry, cfg, texts, functions) {
  if (cfg.shape === 'direct-namespace') return resolveDirect(entry, cfg, texts, functions);
  const source = ts.createSourceFile(cfg.etsFile, texts.ets, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const matches = [];
  function visit(node) {
    if (ts.isFunctionDeclaration(node) && node.name?.text === entry.method && node.body &&
        source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1 === entry.line &&
        node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) &&
        node.parent?.parent?.name?.text === 'commonEventManager') matches.push(node);
    ts.forEachChild(node, visit);
  }
  visit(source);
  if (matches.length !== 1 || source.parseDiagnostics.some((d) =>
    d.start >= matches[0].getStart(source) && d.start < matches[0].end)) {
    return { status: 'arkts-function-ambiguous' };
  }
  const calls = [];
  function collect(node) {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
        node.expression.expression.getText(source) === 'taskpool' && node.expression.name.text === 'execute') {
      calls.push(node);
    }
    ts.forEachChild(node, collect);
  }
  collect(matches[0].body);
  if (calls.length !== 1 || calls[0].arguments.length !== 2 ||
      !ts.isPropertyAccessExpression(calls[0].arguments[0]) ||
      calls[0].arguments[0].expression.getText(source) !== 'commonEventManager' ||
      calls[0].arguments[1].getText(source) !== 'event') return { status: 'taskpool-target-ambiguous' };
  const nativeName = calls[0].arguments[0].name.text;
  if (!/^[A-Za-z_]\w*$/.test(nativeName)) return { status: 'taskpool-target-ambiguous' };
  const declaration = new RegExp(`^\\s*export native function ${nativeName}\\(event: string\\):int;`);
  const declarations = [];
  function findDeclaration(node) {
    if (ts.isFunctionDeclaration(node) && !node.body && node.name?.text === nativeName &&
        node.parent?.parent?.name?.text === 'commonEventManager') {
      const line = texts.ets.split(/\r?\n/)[source.getLineAndCharacterOfPosition(node.getStart(source)).line];
      if (declaration.test(line)) declarations.push(node);
    }
    ts.forEachChild(node, findDeclaration);
  }
  findDeclaration(source);
  if (declarations.length !== 1 ||
      !texts.ets.includes(`loadLibrary("${cfg.library}.z")`)) return { status: 'native-declaration-unresolved' };
  const tableStart = texts.cpp.indexOf('ani_status init(');
  const tableEnd = texts.cpp.indexOf('Namespace_BindNativeFunctions', tableStart);
  if (tableStart < 0 || tableEnd < 0) return { status: 'ani-table-unresolved' };
  const table = texts.cpp.slice(tableStart, tableEnd);
  const tableRow = new RegExp(`ani_native_function\\s*\\{\\s*"${nativeName}"\\s*,\\s*"Lstd/core/String;:I"\\s*,\\s*` +
    `reinterpret_cast<void\\*>\\(OHOS::EventManagerFwkAni::${nativeName}\\)\\s*\\}`, 'g');
  if ([...table.matchAll(tableRow)].length !== 1 ||
      !texts.cpp.includes('FindNamespace("L@ohos/commonEventManager/commonEventManager;", &kitNs)') ||
      !texts.cpp.includes('Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size())') ||
      !texts.cpp.includes('status = init(env, kitNs)')) {
    return { status: 'ani-table-unresolved' };
  }
  const targets = functions.filter((fn) => fn.role === 'production' && fn.sourceRange?.file === cfg.cppFile &&
    fn.qualified === `OHOS::EventManagerFwkAni::${nativeName}` && fn.quality?.errorNodes === 0);
  if (targets.length !== 1) return { status: 'native-handler-ambiguous', candidateCount: targets.length };
  if (!texts.build.includes(`ohos_shared_library("${cfg.library}")`) ||
      !texts.build.includes('"src/ani_common_event.cpp"') ||
      !texts.build.includes('generate_static_abc("common_event_manager")') ||
      !texts.build.includes('"./ets/@ohos.commonEventManager.ets"')) {
    return { status: 'build-proof-unresolved' };
  }
  return { status: 'resolved', nativeName, nativeFactRef: targets[0].factId,
    callLine: source.getLineAndCharacterOfPosition(calls[0].getStart(source)).line + 1,
    nativeLine: targets[0].startLine, tableLine: texts.cpp.slice(0, texts.cpp.indexOf(table.match(tableRow)[0])).split(/\r?\n/).length };
}

function bridgeOf(facts, entry, cfg, idx) {
  if (entry.file !== cfg.etsFile || entry.method !== cfg.method) return null;
  if (!facts.verifyFile(cfg.etsFile).ok || !facts.verifyFile(cfg.cppFile).ok) {
    return { status: 'source-stale' };
  }
  const build = path.join(facts.sourceRoot, ...cfg.buildFile.split('/'));
  if (!fs.existsSync(build) || sha256File(build) !== cfg.buildSha256) return { status: 'build-proof-stale' };
  return resolve(entry, cfg, {
    ets: fs.readFileSync(path.join(facts.sourceRoot, ...cfg.etsFile.split('/')), 'utf8'),
    cpp: fs.readFileSync(path.join(facts.sourceRoot, ...cfg.cppFile.split('/')), 'utf8'),
    build: fs.readFileSync(build, 'utf8')
  }, idx.functions);
}

module.exports = { bridgeOf, resolve };
