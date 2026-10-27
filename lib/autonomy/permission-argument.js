'use strict';

const fs = require('node:fs');
const path = require('node:path');
const ids = require('./ids');
const knowledgeLib = require('./knowledge');
const vertical = require('./vertical');
const gates = require('./gates');

const DELEGATES = Object.freeze({ SetPolicyAsync: 'SetPolicy', UnSetPolicyAsync: 'UnSetPolicy' });

function compare(facts, anchor, binding, knowledge) {
  const unknown = (reason) => ({ status: 'insufficient', reason });
  const delegate = anchor && (DELEGATES[anchor.method] || null);
  // 契约基准必须来自某个受校验的 pilot 来源描述符；具体文件以规范记录携带的来源引用为准。
  const source = knowledge && knowledgeLib.sourceByPermission(knowledge.norm?.permission);
  const applicable = delegate && knowledge?.norm?.authority !== 'builder-llm-review'
    ? knowledge?.norm?.appliesTo?.includes(delegate)
    : knowledge?.norm && knowledgeLib.applicability(knowledge, anchor.method, delegate).status === 'applicable';
  if (anchor?.kind !== 'idl' || binding?.binding !== 'resolved' || !binding.bound ||
      !knowledge?.norm || !source ||
      knowledge.norm.source?.file !== source.docFile ||
      knowledge.norm.header?.file !== source.headerFile ||
      !applicable) {
    return unknown('permission-argument-scope-unresolved');
  }
  const local = vertical.selectEvidence(facts, binding.bound, delegate);
  if (local.status !== 'observed') return unknown(local.reason);
  const inlineLiteral = facts.scope?.contractVocabulary?.inlineLiteral === true;
  let checkRef = local.checkRefs.length === 1 ? local.checkRefs[0] : null;
  if (!checkRef && inlineLiteral && local.checkRefs.length === 0 && !local.truncated) {
    // CES 快照未解析 AccessTokenHelper::* 的 callee（name-only）；仅在内联字面量 scope
    // 且调用点名称/行形状唯一时，允许用该 name-only 调用做局部契约比较，不冒充跨文件解析。
    const nameOnly = local.checkCallsites.filter((item) => item.resolution === 'name-only');
    if (nameOnly.length === 1) checkRef = nameOnly[0].ref;
  }
  if (!checkRef || local.checkRefs.length > 1 || local.truncated) return unknown('permission-check-ambiguous');
  const call = facts.index().calls.find((item) => item.factId === checkRef);
  if (!call || call.caller !== local.calleeRef || ![1, 2].includes(call.argc) ||
      call.line < local.callee.startLine || call.line > local.callee.endLine) {
    return unknown('permission-check-ambiguous');
  }
  const line = local.text.split(/\r?\n/)[call.line - local.callee.startLine];
  let constantSymbol = null;
  let checkShape = null;
  let inlinePermission = null;
  if (inlineLiteral && call.argc === 2) {
    // 第三组件形状：bool ret = VerifyAccessToken(callingTokenId, permission);
    // const std::string permission = "ohos.permission.X";
    const match = /^\s*(?:bool|auto)\s+[A-Za-z_]\w*\s*=\s*(?:[A-Za-z_]\w*::)*VerifyAccessToken\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*\)\s*;\s*$/.exec(line || '');
    if (!match) return unknown('permission-argument-unresolved');
    const tokenVar = match[1];
    const permissionVar = match[2];
    const tokenAssigned = new RegExp(`(?:auto|uint32_t|AccessTokenID|int32_t)\\s+${tokenVar}\\s*=\\s*IPCSkeleton::GetCallingTokenID\\s*\\(\\s*\\)`).test(local.text);
    const literal = new RegExp(`const\\s+std::string\\s+${permissionVar}\\s*=\\s*"([^"]+)"\\s*;`).exec(local.text);
    if (!tokenAssigned || !literal) return unknown('permission-argument-unresolved');
    constantSymbol = permissionVar;
    inlinePermission = literal[1];
    checkShape = 'inline-literal';
  } else if (call.argc === 2) {
    // pilot 形状：if (!CheckPermission(callingTokenId, CONST))
    const match = /^\s*if\s*\(\s*!\s*CheckPermission\s*\(\s*callingTokenId\s*,\s*([A-Z][A-Z0-9_]*)\s*\)\s*\)\s*\{\s*$/.exec(line || '');
    if (!match) return unknown('permission-argument-unresolved');
    constantSymbol = match[1];
    checkShape = null; // pilot 直接形状保持旧比较载荷不变（旧 run 复算依赖）
  } else {
    // 第二组件形状：if (!<本地 helper>(CONST))，helper 体一跳委托到调用方权限校验。
    const match = /^\s*if\s*\(\s*!\s*([A-Z]\w*)\s*\(\s*([A-Z][A-Z0-9_]*)\s*\)\s*\)\s*\{\s*$/.exec(line || '');
    if (!match) return unknown('permission-argument-unresolved');
    const calleeFn = facts.index().functions.find((fn) => fn.factId === local.calleeRef) || binding.bound;
    const resolved = gates.resolvePermissionHelper(facts, calleeFn, match[1], call.line);
    if (resolved.status !== 'caller-permission') return unknown(resolved.reason || 'permission-helper-unresolved');
    constantSymbol = match[2];
    checkShape = 'local-helper';
  }
  const doc = fs.readFileSync(path.join(facts.sourceRoot, ...source.docFile.split('/')));
  const normSource = knowledge.norm.source;
  const sourceLine = doc.toString('utf8').split(/\r?\n/)[normSource.line - 1];
  if (ids.sha256Hex(doc) !== normSource.sha256 || sourceLine?.trim() !== normSource.text ||
      !normSource.text.includes(knowledge.norm.permission)) return unknown('permission-norm-stale');
  const header = facts.verifyFile(source.headerFile);
  if (!header.ok || header.actual !== knowledge.norm.header.sha256) return unknown('stale-input');
  let observedPermission = null;
  if (checkShape === 'inline-literal') {
    observedPermission = inlinePermission;
  } else {
    const text = fs.readFileSync(path.join(facts.sourceRoot, ...source.headerFile.split('/')), 'utf8');
    const declarations = text.split(/\r?\n/).map((row) =>
      /^\s*const\s+[\w: ]+?\s+([A-Z][A-Z0-9_]*)\s*(?:\[\s*\])?\s*=\s*"([^"]+)"\s*;\s*$/.exec(row))
      .filter((row) => row && row[1] === constantSymbol);
    if (declarations.length !== 1) return unknown('permission-constant-unresolved');
    observedPermission = declarations[0][2];
  }
  return { status: observedPermission === knowledge.norm.permission ? 'supported' : 'refuted',
    reason: null, entryRef: anchor.entityId, delegateRef: local.calleeRef, checkRef: call.factId,
    file: local.callee.file, line: call.line, symbol: constantSymbol,
    ...(checkShape ? { checkShape } : {}), observedPermission,
    expectedPermission: knowledge.norm.permission, normRef: knowledge.norm.normId,
    headerRef: knowledge.norm.header.factRef };
}

module.exports = { compare };
