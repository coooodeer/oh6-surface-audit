'use strict';

/**
 * 实际门禁识别器目录（指南 §15.4 双命题裁决 / §24.28 阶段 B1）。
 *
 * 有界识别入口到操作路径上约束调用方的门禁形态：
 *   - permission-check：`if (!CheckPermission(subject, CONST)) { ...; return PERMISSION_DENIED; }`
 *   - native-token-match：`if (!IsXxxCalling(callingTokenId)) { ... }`，辅助函数体
 *     解析为 `tokenCaller == <GetNativeTokenId("process")>` 的精确匹配
 *   - uid-match：`if (IPCSkeleton::GetCallingUid() != FOUNDATION_UID) { ... }`
 *   - 正向 `==` 形状且块内无 return/策略调用 → 记录为 modifier（非门禁、非缺口）
 *   - 组合条件 / 非 if 形状 / 检查非调用方主体：不猜语义，登记具名 reasonCode
 * 拒绝分支允许至多 2 行简单语句（如日志行）后早退；阻断判定 = 深度 1 +
 * 早退 + 直线到达操作。本模块不证明编译变体、别名或全局控制流。
 */

const GATE_TOKEN_RE = /\b(?:CheckPermission\s*\(|Is[A-Z]\w*Calling\s*\(|GetCallingUid\s*\()/;
// 调用方身份 token：出现在条件里且未被识别为已知门禁/modifier 时，视为未识别门禁。
const IDENTITY_CONDITION_RE = /\b(?:callingTokenId|callingUid|callingPid|callerTokenId|GetCallingTokenID|GetCallingUid|GetCallingPid)\b/;

/**
 * 按 scope 追加门禁/身份词表。默认（不配置）保持 pilot 的原始正则，旧 run 复算不变；
 * 第二/第三组件可在 scope.gateVocabulary 中登记自己实际出现的 token。
 */
function addTokens(baseRe, extraTokens) {
  if (!Array.isArray(extraTokens) || !extraTokens.length) return baseRe;
  const escaped = extraTokens.map((token) => String(token).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  return new RegExp(`(?:${baseRe.source}|\\b(?:${escaped.join('|')})\\b)`);
}

function stripCode(line) {
  return line.replace(/"(?:\\.|[^"\\])*"/g, '""').replace(/\/\/.*$/, '');
}

function depthBefore(lines, index) {
  let depth = 0;
  for (let i = 0; i < index; i += 1) {
    for (const char of stripCode(lines[i])) {
      if (char === '{') depth += 1;
      if (char === '}') depth -= 1;
    }
  }
  return depth;
}

function straightLineBetween(lines, fromIndex, toIndex) {
  const blob = lines.slice(fromIndex, toIndex).join('\n');
  return !/\b(?:goto|co_return|try|catch)\b|#\s*(?:if|else|endif|define)/.test(blob);
}

const PERMISSION_IF_RE = /^\s*if\s*\(\s*!\s*CheckPermission\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Z][A-Z0-9_]*)\s*\)\s*\)\s*\{\s*$/;
// 第二组件（os_account）新形状：`if (!<本地 helper>(<CONST>))`，helper 体一跳委托到
// 调用方权限校验（VerifyPermission/VerifyAccessToken/CheckCallingPermission）。
// helper 是否真是调用方权限门由 resolvePermissionHelper 有界解析，未解析不猜语义。
const HELPER_PERMISSION_IF_RE = /^\s*if\s*\(\s*!\s*([A-Z]\w*)\s*\(\s*([A-Z][A-Z0-9_]*)\s*\)\s*\)\s*\{\s*$/;
const NATIVE_IF_RE = /^\s*if\s*\(\s*!\s*(Is[A-Z]\w*Calling)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\)\s*\{\s*$/;
const UID_REJECT_RE = /^\s*if\s*\(\s*(?:IPCSkeleton::GetCallingUid\s*\(\s*\)\s*!=\s*([A-Z][A-Z0-9_]*)|!\s*\(IPCSkeleton::GetCallingUid\s*\(\s*\)\s*==\s*([A-Z][A-Z0-9_]*)\s*\))\s*\)\s*\{\s*$/;
const UID_ALLOW_RE = /^\s*if\s*\(\s*IPCSkeleton::GetCallingUid\s*\(\s*\)\s*==\s*([A-Z][A-Z0-9_]*)\s*\)\s*\{\s*$/;
const NATIVE_ALLOW_RE = /^\s*if\s*\(\s*(Is[A-Z]\w*Calling)\s*\(\s*[A-Za-z_]\w*\s*\)\s*\)\s*\{\s*$/;
// 第三组件新形状：
//   bool isSubsystem = AccessTokenHelper::VerifyNativeToken(tokenId);
//   if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) { funcResult=...; return ERR_OK; }
const SYSTEM_APP_OR_NATIVE_IF_RE = /^\s*if\s*\(\s*!\s*([A-Za-z_]\w*)\s*&&\s*!\s*(?:[A-Za-z_]\w*::)*IsSystemApp\s*\(\s*\)\s*\)\s*\{\s*$/;
//   bool ret = ...VerifyAccessToken(tokenId, permission);
//   if (!ret && (!isSubsystem || <bypass>)) { funcResult=...; return ERR_OK; }
const PERMISSION_BYPASS_IF_RE = /^\s*if\s*\(\s*!\s*([A-Za-z_]\w*)\s*&&\s*\(\s*!\s*([A-Za-z_]\w*)\s*\|\|.*\)\s*\)\s*\{\s*$/;
// 拒绝码族：PERMISSION_DENIED 以及组件私有前缀（如 ERR_ACCOUNT_COMMON_PERMISSION_DENIED）。
// 只有名字明确以 PERMISSION_DENIED 结尾的返回值才被当作权限拒绝早退。
const EARLY_RETURN_RE = /^\s*return\s+([A-Z][A-Z0-9_]*)\s*;\s*$/;
const RETURN_VAR_RE = /^\s*return\s+([A-Za-z_]\w*)\s*;\s*$/;
const FUNC_RESULT_ASSIGN_RE = /^\s*(?:funcResult|result)\s*=\s*([A-Z][A-Z0-9_]*)\s*;\s*$/;
const CLOSE_BRACE_RE = /^\s*\}\s*$/;

function isPermissionDeniedCode(code) {
  return code === 'PERMISSION_DENIED' || /_PERMISSION_DENIED$/.test(code);
}

/**
 * 解析 if 行后的拒绝分支。允许至多 2 行简单语句（无控制流、无花括号）后：
 *   - `return <...PERMISSION_DENIED>;`（权限拒绝码族）；
 *   - `return <statusVar>;`（调用方显式传入的状态变量，如 CheckSystemApp 的返回值）；
 *   - `funcResult = <CODE>; return ERR_OK;`（IDL funcResult 风格，仍早退阻断操作）。
 * 返回 {type, code, closeIndex}；closeIndex 为块结束行下标或 null。
 */
function rejectBranchOf(lines, ifIndex, options = {}) {
  const statusVars = options.statusVars || new Set();
  let j = ifIndex + 1;
  let statements = 0;
  while (j < lines.length && statements <= 2) {
    const line = lines[j];
    const early = EARLY_RETURN_RE.exec(line);
    const scopedReturn = /^\s*return\s+(PrivacyError::ERR_(?:NOT_SYSTEM_APP|PERMISSION_DENIED))\s*;\s*$/.exec(line);
    const code = early?.[1] || (options.privacyManagerReturn ? scopedReturn?.[1] : null);
    if (code && (isPermissionDeniedCode(early?.[1]) ||
        (options.privacyManagerReturn && scopedReturn))) {
      return CLOSE_BRACE_RE.test(lines[j + 1] || '')
        ? { type: 'early-return', code, closeIndex: j + 1 }
        : { type: 'malformed', closeIndex: null };
    }
    const statusReturn = RETURN_VAR_RE.exec(line);
    if (statusReturn && statusVars.has(statusReturn[1])) {
      return CLOSE_BRACE_RE.test(lines[j + 1] || '')
        ? { type: 'early-return', code: `status:${statusReturn[1]}`, closeIndex: j + 1 }
        : { type: 'malformed', closeIndex: null };
    }
    const funcResult = FUNC_RESULT_ASSIGN_RE.exec(line);
    if (funcResult && /^\s*return\s+ERR_OK\s*;\s*$/.test(lines[j + 1] || '') &&
        CLOSE_BRACE_RE.test(lines[j + 2] || '')) {
      return { type: 'early-return', code: funcResult[1], closeIndex: j + 2 };
    }
    if (CLOSE_BRACE_RE.test(line)) return { type: 'none-observed', closeIndex: j };
    if (/\b(?:if|for|while|switch|return|goto)\b/.test(stripCode(line)) ||
        /[{}]/.test(stripCode(line))) {
      return { type: 'none-observed', closeIndex: null };
    }
    statements += 1;
    j += 1;
  }
  return { type: 'none-observed', closeIndex: null };
}

/** 正向 `==`/无取反形状：块内只有简单语句则视为 modifier，否则视为不可分析。 */
function allowShapeOutcome(lines, ifIndex) {
  let depth = 1;
  for (let j = ifIndex + 1; j < lines.length && depth > 0; j += 1) {
    const code = stripCode(lines[j]);
    for (const char of code) {
      if (char === '{') depth += 1;
      if (char === '}') depth -= 1;
    }
    if (depth === 0) {
      return { modifier: true, closeIndex: j };
    }
    if (/\b(?:return|goto|break|continue)\b/.test(code) || /PolicyInfoManager/.test(code)) {
      return { modifier: false, closeIndex: null };
    }
  }
  return { modifier: false, closeIndex: null };
}

/**
 * 解析 native-token 辅助函数体。精确要求三件事：
 *   1. `GetNativeTokenId("literal")` 赋值给变量 V（且 V 只赋值一次）；
 *   2. return 比较形如 `P == V` 或 `V == P`；
 *   3. 比较另一侧 P 恰为该 helper 的入参名（从签名解析），保证比较的是调用方令牌。
 * 任一不满足（含另一侧为无关变量、中途重赋值）一律返回 unresolved，不猜语义。
 */
function resolveNativeHelper(facts, helperName) {
  const hits = facts.findFunctions(helperName).filter((fn) => fn.role === 'production');
  if (hits.length !== 1) return { status: 'unresolved', reason: 'native-token-helper-unresolved' };
  const helper = hits[0];
  const file = helper.sourceRange && helper.sourceRange.file;
  const verified = file && facts.verifyFile(file);
  if (!verified || !verified.ok) return { status: 'unresolved', reason: 'stale-input' };
  const window = facts.sourceWindow(file, helper.startLine, helper.endLine, { maxLines: 40 });
  if (window.truncated || window.sha256 !== verified.actual) {
    return { status: 'unresolved', reason: 'native-token-helper-truncated' };
  }
  const param = /\(\s*[A-Za-z_][\w]*\s*\**\s*([A-Za-z_]\w*)\s*(?:,|\))/.exec(helper.signature || '');
  if (!param) return { status: 'unresolved', reason: 'native-token-helper-shape-unsupported' };
  const assignment = new RegExp(`(\\w+)\\s*=\\s*(?:[A-Za-z_][\\w:]*::)*GetNativeTokenId\\s*\\(\\s*\"([^\"]+)\"\\s*\\)`).exec(window.text);
  if (!assignment) return { status: 'unresolved', reason: 'native-token-helper-shape-unsupported' };
  const cachedVar = assignment[1];
  // 统计真赋值（排除 ==）：GetNativeTokenId 赋值必须唯一，且不得中途改赋他值。
  const realAssignments = window.text.split(new RegExp(`\\b${cachedVar.replace(/[$]/g, '\\$')}\\s*=(?!=)`)).length - 1;
  if (realAssignments !== 1) return { status: 'unresolved', reason: 'native-token-helper-shape-unsupported' };
  const escaped = cachedVar.replace(/[$]/g, '\\$');
  const comparesParamAndCache =
    new RegExp(`return\\s+${param[1]}\\s*==\\s*${escaped}\\s*;`).test(window.text) ||
    new RegExp(`return\\s+${escaped}\\s*==\\s*${param[1]}\\s*;`).test(window.text);
  if (!comparesParamAndCache) return { status: 'unresolved', reason: 'native-token-helper-shape-unsupported' };
  return {
    status: 'resolved', nativeProcess: assignment[2],
    helper: { name: helperName, file, startLine: helper.startLine,
      endLine: helper.endLine, sha256: verified.actual }
  };
}

/**
 * 解析"本地 helper 委托的权限检查"（第二组件 os_account 新形状）。
 * 有界要求：
 *   1. 调用点行号 + helper 名在 `callee` 的直接调用事实中唯一解析（不按名字猜实现）；
 *   2. helper 体恰好包含一次账号/令牌权限校验调用（VerifyPermission /
 *      VerifyAccessToken / CheckCallingPermission），其唯一实参就是 helper 形参；
 *   3. 校验结果与 ERR_OK 比较且失败路径 `return false`。
 * 任一不满足返回具名 unresolved / not-caller-permission，不猜门禁语义。
 * @returns {{status:'caller-permission'|'not-caller-permission'|'unresolved', reason?:string,
 *            helperName:string, verifyCall?:string, helper?:object}}
 */
function resolvePermissionHelper(facts, callee, helperName, callLine) {
  if (!facts || !callee || !helperName) return { status: 'unresolved', helperName, reason: 'permission-helper-unresolved' };
  // 受控盲测语料按 factId 隔离同名变体；默认仍按入口 qualified 名查调用事实。
  const callerKey = facts.scope && facts.scope.binding && facts.scope.binding.callerKey === 'fact'
    ? callee.factId : (callee.qualified || callee.name);
  const calls = facts.callsOf(callerKey, { limit: 400 })
    .filter((call) => call.line === callLine && call.calleeName === helperName);
  if (calls.length !== 1 || !calls[0].callee) {
    return { status: 'unresolved', helperName, reason: 'permission-helper-unresolved' };
  }
  const helper = facts.index().functions.find((fn) => fn.factId === calls[0].callee);
  if (!helper) return { status: 'unresolved', helperName, reason: 'permission-helper-unresolved' };
  const file = helper.sourceRange && helper.sourceRange.file;
  const verified = file && facts.verifyFile(file);
  if (!verified || !verified.ok) return { status: 'unresolved', helperName, reason: 'stale-input' };
  const window = facts.sourceWindow(file, helper.startLine, helper.endLine, { maxLines: 40 });
  if (window.truncated || window.sha256 !== verified.actual) {
    return { status: 'unresolved', helperName, reason: 'permission-helper-truncated' };
  }
  const paramMatch = /\(([^)]*)\)/.exec(helper.signature || '');
  const firstParam = paramMatch
    ? /([A-Za-z_]\w*)\s*(?:,|$)/.exec(paramMatch[1].replace(/^\s*(?:const\s+)?[\w:<>]+\s*[&*]?\s*/, ''))
    : null;
  const param = firstParam ? firstParam[1] : null;
  if (!param) return { status: 'unresolved', helperName, reason: 'permission-helper-shape-unsupported' };
  const verifyRe = new RegExp(`(?:[A-Za-z_]\\w*::)*(VerifyPermission|VerifyAccessToken|CheckCallingPermission)\\s*\\(\\s*` +
    `(?:[^,()]+,\\s*)?${param.replace(/[$]/g, '\\$')}\\s*\\)`);
  const verify = verifyRe.exec(window.text);
  if (!verify) return { status: 'not-caller-permission', helperName, reason: 'permission-helper-not-caller-scoped',
    helper: { name: helperName, file, startLine: helper.startLine, endLine: helper.endLine, sha256: verified.actual } };
  let successComparison = null;
  if (verify[1] === 'VerifyAccessToken') {
    successComparison = new RegExp(`(?:==|!=)\\s*(?:Security::AccessToken::)?(?:TypePermissionState::)?` +
      `(?:PERMISSION_GRANTED|[A-Z][A-Z0-9_]*)`);
  } else {
    successComparison = new RegExp(`!=\\s*[A-Z][A-Z0-9_]*`);
  }
  const helperRootBypass = /\buid\s*==\s*ROOT_UID\b/.test(window.text);
  if (!successComparison.test(window.text) || !/return\s+false\s*;/.test(window.text)) {
    return { status: 'not-caller-permission', helperName, reason: 'permission-helper-not-caller-scoped',
      helper: { name: helperName, file, startLine: helper.startLine, endLine: helper.endLine, sha256: verified.actual } };
  }
  return {
    status: 'caller-permission', helperName, verifyCall: verify[1], helperRootBypass,
    helper: { name: helperName, file, startLine: helper.startLine, endLine: helper.endLine, sha256: verified.actual }
  };
}

function privacyManagerHelpers(facts, callee) {
  const file = callee.sourceRange?.file;
  if (!file || !facts.verifyFile?.(file).ok ||
      !/::PrivacyManagerService::RegisterPermActiveStatusCallback$/.test(callee.qualified || '')) return false;
  const functions = facts.index().functions;
  const body = (name) => {
    const hits = functions.filter((fn) => fn.role === 'production' && fn.sourceRange?.file === file &&
      fn.qualified === callee.qualified.replace(/RegisterPermActiveStatusCallback$/, name));
    if (hits.length !== 1) return null;
    const window = facts.sourceWindow(file, hits[0].startLine, hits[0].endLine);
    return window.truncated || window.sha256 !== facts.fileHash(file)?.sha256 ? null : window.text;
  };
  const system = body('IsSystemAppCalling');
  const permission = body('VerifyPermission');
  const permissionCode = permission?.split(/\r?\n/).map(stripCode).join('\n');
  return Boolean(system && permission &&
    (system.match(/\breturn\b/g) || []).length === 1 && !/\b(?:if|else|switch)\s*\(/.test(system) &&
    /uint64_t\s+fullTokenId\s*=\s*IPCSkeleton::GetCallingFullTokenID\(\s*\)\s*;/.test(system) &&
    /return\s+TokenIdKit::IsSystemAppByFullTokenID\(\s*fullTokenId\s*\)\s*;/.test(system) &&
    (permissionCode.match(/\bif\s*\(/g) || []).length === 1 &&
    (permissionCode.match(/\breturn\b/g) || []).length === 2 &&
    /uint32_t\s+callingTokenID\s*=\s*IPCSkeleton::GetCallingTokenID\(\s*\)\s*;/.test(permission) &&
    /if\s*\(\s*AccessTokenKit::VerifyAccessToken\(\s*callingTokenID\s*,\s*permission\s*\)\s*==\s*PERMISSION_DENIED\s*\)\s*\{[^{}]*return\s+false\s*;\s*\}\s*return\s+true\s*;/.test(permissionCode) &&
    !/\b(?:ResetCallingIdentity|SetCallingIdentity)\b/.test(system + permission));
}

/**
 * 枚举一个实现体源码窗口内的门禁。
 * @param {object} facts 快照适配器
 * @param {object} callee 实现体函数事实（startLine/endLine 用于行号换算）
 * @param {{text:string}} windowBody 函数体文本（sourceWindow 的 text）
 * @param {object} options { operationLine, resolvePermissionConstant(symbol)->literal|null,
 *                           resolvePermissionHelper(helperName, absLine)->object }
 */
function enumerate(facts, callee, windowBody, options = {}) {
  const lines = windowBody.text.split(/\r?\n/);
  const resolvePermission = options.resolvePermissionConstant || (() => null);
  const gateRe = addTokens(GATE_TOKEN_RE, options.gateTokens);
  const identityRe = addTokens(IDENTITY_CONDITION_RE, options.identityTokens);
  const gates = [];
  const modifiers = [];
  const unanalyzable = [];
  const absLine = (idx) => callee.startLine + idx;
  const gateVocab = (options && options.gateVocabulary) || {};
  const enableSystemAppShape = gateVocab.systemAppShape === true;
  const enableSystemAppOrNative = gateVocab.systemAppOrNativeShape === true;
  const privacyShape = gateVocab.privacyManagerShape === true;
  const privacyHelpersValid = privacyShape && privacyManagerHelpers(facts, callee);
  const systemAppVars = new Set();
  const nativeFlags = new Set();
  const permissionResults = new Map();
  const stringLiterals = new Map();

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] || '';
    if (privacyShape && /^\s*if\s*\(/.test(line) &&
        /\b(?:IsSystemAppCalling|VerifyPermission)\s*\(/.test(line)) {
      const callerBound = lines.slice(0, i).filter((row) =>
        /\bcallingTokenID\s*=/.test(row)).length === 1 &&
        lines.slice(0, i).some((row) =>
          /^\s*uint32_t\s+callingTokenID\s*=\s*IPCSkeleton::GetCallingTokenID\(\s*\)\s*;\s*$/.test(row));
      const systemIf = /^\s*if\s*\(\s*\(AccessTokenKit::GetTokenTypeFlag\(callingTokenID\)\s*==\s*TOKEN_HAP\)\s*&&\s*\(!IsSystemAppCalling\(\)\)\s*\)\s*\{\s*$/.test(line);
      const permissionIf = /^\s*if\s*\(\s*!VerifyPermission\(\s*([A-Z][A-Z0-9_]*)\s*\)\s*\)\s*\{\s*$/.exec(line);
      if (!privacyHelpersValid || !callerBound || (!systemIf && !permissionIf)) {
        unanalyzable.push({ line: absLine(i), reasonCode: !privacyHelpersValid
          ? 'privacy-helper-unresolved' : 'unrecognized-caller-guard', text: line.trim() });
        continue;
      }
      const reject = rejectBranchOf(lines, i, { privacyManagerReturn: true });
      const expectedCode = systemIf ? 'PrivacyError::ERR_NOT_SYSTEM_APP' : 'PrivacyError::ERR_PERMISSION_DENIED';
      const early = reject.type === 'early-return' && reject.code === expectedCode;
      const permission = permissionIf && resolvePermission(permissionIf[1]);
      gates.push({ kind: systemIf ? 'hap-system-app-check' : 'permission-check',
        line: absLine(i), subjectScope: 'caller', subjectVariable: 'callingTokenID',
        ...(permissionIf ? { constantSymbol: permissionIf[1],
          ...(permission ? { permission } : { unresolved: 'permission-constant-unresolved' }) } : {}),
        rejectBranch: early ? { type: 'early-return', code: reject.code } : { type: 'none-observed' },
        blockEndIndex: reject.closeIndex, callText: line.trim() });
      continue;
    }
    if (enableSystemAppOrNative) {
      const nativeAssign = /^\s*bool\s+([A-Za-z_]\w*)\s*=\s*(?:[A-Za-z_]\w*::)*VerifyNativeToken\s*\(\s*([A-Za-z_]\w*)\s*\)\s*;\s*$/.exec(line);
      if (nativeAssign) { nativeFlags.add(nativeAssign[1]); continue; }
      const permissionAssign = /^\s*bool\s+([A-Za-z_]\w*)\s*=\s*(?:[A-Za-z_]\w*::)*VerifyAccessToken\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*\)\s*;\s*$/.exec(line);
      if (permissionAssign) { permissionResults.set(permissionAssign[1], permissionAssign[3]); continue; }
      const literalAssign = /^\s*const\s+std::string\s+([A-Za-z_]\w*)\s*=\s*"([^"]+)"\s*;\s*$/.exec(line);
      if (literalAssign) { stringLiterals.set(literalAssign[1], literalAssign[2]); continue; }
      const sysOrNative = SYSTEM_APP_OR_NATIVE_IF_RE.exec(line);
      if (sysOrNative && nativeFlags.has(sysOrNative[1])) {
        const reject = rejectBranchOf(lines, i);
        gates.push({
          kind: 'system-app-or-native', line: absLine(i), subjectScope: 'caller',
          nativeFlag: sysOrNative[1],
          rejectBranch: reject.type === 'early-return'
            ? { type: 'early-return', code: reject.code } : { type: 'none-observed' },
          blockEndIndex: reject.closeIndex, callText: line.trim()
        });
        continue;
      }
      const bypass = PERMISSION_BYPASS_IF_RE.exec(line);
      if (bypass && permissionResults.has(bypass[1]) && nativeFlags.has(bypass[2])) {
        const permissionVar = permissionResults.get(bypass[1]);
        const permission = stringLiterals.get(permissionVar) || null;
        const reject = rejectBranchOf(lines, i);
        gates.push({
          kind: 'permission-check', via: 'inline-verify-access-token', line: absLine(i),
          subjectVariable: 'callingTokenId', subjectScope: 'caller',
          ...(permission ? { permission } : { unresolved: 'permission-constant-unresolved' }),
          bypassNative: true,
          rejectBranch: reject.type === 'early-return'
            ? { type: 'early-return', code: reject.code } : { type: 'none-observed' },
          blockEndIndex: reject.closeIndex, callText: line.trim()
        });
        continue;
      }
    }
    if (enableSystemAppShape) {
      const sysAssign = /^\s*(?:std::)?(?:ErrCode|int32_t|auto)\s+([A-Za-z_]\w*)\s*=\s*(?:AccountPermissionManager|AccessTokenHelper)::CheckSystemApp\s*\(\s*(true|false)?\s*\)\s*;/.exec(line);
      if (sysAssign) {
        const isCallStub = sysAssign[2] !== 'false';
        if (isCallStub) systemAppVars.add(sysAssign[1]);
        else modifiers.push({ line: absLine(i), kind: 'self-scan-modifier', text: line.trim() });
        continue;
      }
      // 变量被重新赋值给其他调用后，不再保留“CheckSystemApp 状态变量”的语义。
      const reassign = /^\s*([A-Za-z_]\w*)\s*=\s*([^;]+);/.exec(line);
      if (reassign && systemAppVars.has(reassign[1]) && !/CheckSystemApp\s*\(/.test(reassign[2])) {
        systemAppVars.delete(reassign[1]);
      }
      const sysVar = [...systemAppVars].find((name) =>
        new RegExp(`^\\s*if\\s*\\(\\s*${name}\\s*!=\\s*ERR_OK\\s*\\)\\s*\\{\\s*$`).test(line));
      if (sysVar) {
        const reject = rejectBranchOf(lines, i, { statusVars: systemAppVars });
        gates.push({
          kind: 'system-app-check',
          line: absLine(i),
          subjectScope: 'caller',
          statusVariable: sysVar,
          rejectBranch: reject.type === 'early-return'
            ? { type: 'early-return', code: reject.code } : { type: 'none-observed' },
          blockEndIndex: reject.closeIndex,
          callText: line.trim()
        });
        continue;
      }
    }
    if (!gateRe.test(line)) {
      // 未识别的调用方身份条件（如 VerifyAuthorized(callingTokenId)）：
      // 词表未命中不能证明无门禁，登记具名缺口。
      if (/^\s*(?:if|else\s+if)\s*\(/.test(line) && identityRe.test(line)) {
        unanalyzable.push({ line: absLine(i), reasonCode: 'unrecognized-caller-guard', text: line.trim() });
      }
      continue;
    }

    const permIf = PERMISSION_IF_RE.exec(line);
    if (permIf) {
      const subjectVariable = permIf[1];
      const constantSymbol = permIf[2];
      const permission = subjectVariable === 'callingTokenId' ? resolvePermission(constantSymbol) : null;
      const reject = rejectBranchOf(lines, i);
      gates.push({
        kind: 'permission-check',
        line: absLine(i),
        subjectVariable,
        subjectScope: subjectVariable === 'callingTokenId' ? 'caller' : 'non-caller',
        constantSymbol,
        ...(permission ? { permission } : {}),
        ...(subjectVariable === 'callingTokenId' && !permission
          ? { unresolved: 'permission-constant-unresolved' } : {}),
        rejectBranch: reject.type === 'early-return'
          ? { type: 'early-return', code: reject.code } : { type: 'none-observed' },
        blockEndIndex: reject.closeIndex,
        callText: line.trim()
      });
      continue;
    }
    const helperIf = HELPER_PERMISSION_IF_RE.exec(line);
    if (helperIf) {
      const helperName = helperIf[1];
      const constantSymbol = helperIf[2];
      const resolved = typeof options.resolvePermissionHelper === 'function'
        ? options.resolvePermissionHelper(helperName, absLine(i))
        : { status: 'unresolved', helperName, reason: 'permission-helper-unresolved' };
      if (resolved.status === 'caller-permission') {
        const permission = resolvePermission(constantSymbol);
        const reject = rejectBranchOf(lines, i);
        gates.push({
          kind: 'permission-check',
          via: 'local-helper',
          line: absLine(i),
          subjectVariable: 'callingTokenId',
          subjectScope: 'caller',
          constantSymbol,
          ...(permission ? { permission } : { unresolved: 'permission-constant-unresolved' }),
          helper: resolved.helper,
          verifyCall: resolved.verifyCall,
          helperRootBypass: Boolean(resolved.helperRootBypass),
          rejectBranch: reject.type === 'early-return'
            ? { type: 'early-return', code: reject.code } : { type: 'none-observed' },
          blockEndIndex: reject.closeIndex,
          callText: line.trim()
        });
      } else {
        unanalyzable.push({ line: absLine(i), reasonCode: resolved.reason || 'permission-helper-unresolved',
          text: line.trim(), helperName });
      }
      continue;
    }
    const nativeIf = NATIVE_IF_RE.exec(line);
    if (nativeIf) {
      const helperName = nativeIf[1];
      const subjectVariable = nativeIf[2];
      const resolved = subjectVariable === 'callingTokenId'
        ? resolveNativeHelper(facts, helperName)
        : { status: 'unresolved', reason: 'native-token-subject-mismatch' };
      const reject = rejectBranchOf(lines, i);
      gates.push({
        kind: 'native-token-match',
        line: absLine(i),
        subjectVariable,
        subjectScope: subjectVariable === 'callingTokenId' ? 'caller' : 'non-caller',
        helperName,
        ...(resolved.status === 'resolved' ? { nativeProcess: resolved.nativeProcess, helper: resolved.helper }
          : { unresolved: resolved.reason }),
        rejectBranch: reject.type === 'early-return'
          ? { type: 'early-return', code: reject.code } : { type: 'none-observed' },
        blockEndIndex: reject.closeIndex,
        callText: line.trim()
      });
      continue;
    }
    const uidIf = UID_REJECT_RE.exec(line);
    if (uidIf) {
      const uidSymbol = uidIf[1] || uidIf[2];
      const reject = rejectBranchOf(lines, i);
      gates.push({
        kind: 'uid-match',
        line: absLine(i),
        subjectVariable: 'callingUid',
        subjectScope: 'caller',
        uidSymbol,
        // FOUNDATION_UID 的数值在作用域外；符号语义（foundation 进程组）作为记录假设保留。
        assumption: `${uidSymbol} denotes the foundation process-group uid`,
        rejectBranch: reject.type === 'early-return'
          ? { type: 'early-return', code: reject.code } : { type: 'none-observed' },
        blockEndIndex: reject.closeIndex,
        callText: line.trim()
      });
      continue;
    }
    const uidAllow = UID_ALLOW_RE.exec(line) || NATIVE_ALLOW_RE.exec(line);
    if (uidAllow) {
      const outcome = allowShapeOutcome(lines, i);
      if (outcome.modifier) {
        modifiers.push({ line: absLine(i), kind: 'allow-shape-modifier', text: line.trim() });
        i = outcome.closeIndex;
        continue;
      }
      unanalyzable.push({ line: absLine(i), reasonCode: 'gate-shape-unsupported', text: line.trim() });
      continue;
    }
    // 存在门禁相关 token 但不符合任何受支持形状：组合条件（含跨行 &&/||）或未知形状。
    // 组件可显式要求“只在条件行登记缺口”（CES scope.gateVocabulary），避免把
    // GetCallingUid() 当实参传给操作、或 VerifyNativeToken 的赋值误报成门禁缺口；
    // 默认（pilot 等旧 scope）保持原行为，旧 run 复算不变。
    if (options.conditionLinesOnly && !/^\s*(?:if|else\s+if)\s*\(/.test(line)) continue;
    if (/&&|\|\|/.test(`${stripCode(line)} ${stripCode(lines[i - 1] || '')}`)) {
      unanalyzable.push({ line: absLine(i), reasonCode: 'combined-gate-unsupported', text: line.trim() });
    } else unanalyzable.push({ line: absLine(i), reasonCode: 'gate-shape-unsupported', text: line.trim() });
  }

  // 拒绝分支是否阻断操作：深度 1 + 早退 + 直线到达操作调用点。
  const operationLine = options.operationLine || null;
  for (const gate of gates) {
    let blocks = null;
    if (operationLine !== null && gate.line < operationLine && gate.rejectBranch.type === 'early-return') {
      const gateIndex = gate.line - callee.startLine;
      const opIndex = operationLine - callee.startLine;
      if (gateIndex >= 0 && opIndex < lines.length &&
          depthBefore(lines, gateIndex) === 1 && depthBefore(lines, opIndex) === 1 &&
          gate.blockEndIndex !== null &&
          straightLineBetween(lines, gate.blockEndIndex + 1, opIndex)) blocks = true;
    }
    gate.blocksOperation = blocks;
  }

  return { status: 'observed', gates, modifiers, unanalyzable };
}

/**
 * 评估具体主体是否被门禁集合拒绝（仅评估已识别、阻断操作的门禁）。
 * @param {{kind:string, holdsPermissions:string[], nativeToken:string|null, uid:string|null}} subject
 */
function evaluateSubject(gates, subject) {
  const effective = gates.filter((gate) => gate.blocksOperation === true);
  const rejecting = [];
  let unknown = null;
  let unconstrained = false;
  for (const gate of effective) {
    if (gate.unresolved) { unknown = unknown || gate.unresolved; continue; }
    if (gate.kind === 'permission-check') {
      if (gate.subjectScope !== 'caller') { unconstrained = true; continue; }
      // helper 的 root 旁路只对 root 主体成立；普通应用仍受权限门禁约束。
      if (gate.helperRootBypass && subject.uid === 'root') continue;
      // native-subsystem 旁路只对 native token 成立；普通应用仍走权限校验。
      if (gate.bypassNative && subject.nativeToken === 'native') continue;
      if (!subject.holdsPermissions.includes(gate.permission)) rejecting.push(gate);
      continue;
    }
    if (gate.kind === 'system-app-check') {
      if (gate.subjectScope !== 'caller') { unconstrained = true; continue; }
      if (subject.isSystemApp !== true) rejecting.push(gate);
      continue;
    }
    if (gate.kind === 'hap-system-app-check') {
      if (subject.tokenType === 'hap' && subject.isSystemApp === false) rejecting.push(gate);
      else if (subject.tokenType !== 'hap' && subject.tokenType !== 'native') {
        unknown = unknown || 'token-type-or-system-app-unknown';
      } else if (subject.tokenType === 'hap' && subject.isSystemApp !== true) {
        unknown = unknown || 'token-type-or-system-app-unknown';
      }
      continue;
    }
    if (gate.kind === 'system-app-or-native') {
      if (gate.subjectScope !== 'caller') { unconstrained = true; continue; }
      const native = subject.nativeToken === 'native';
      if (!native && subject.isSystemApp !== true) rejecting.push(gate);
      continue;
    }
    if (gate.kind === 'native-token-match') {
      if (gate.subjectScope !== 'caller') { unconstrained = true; continue; }
      if (subject.nativeToken !== gate.nativeProcess) rejecting.push(gate);
      continue;
    }
    if (gate.kind === 'uid-match') {
      if (subject.uid !== 'foundation') rejecting.push(gate);
    }
  }
  if (unknown) return { status: 'unknown', rejectingGates: rejecting, passingNote: null, reason: unknown };
  if (rejecting.length) return { status: 'rejected', rejectingGates: rejecting, passingNote: null, reason: null };
  return {
    status: 'passes', rejectingGates: [],
    passingNote: unconstrained
      ? 'at least one recognized gate checks a non-caller subject and does not constrain the caller'
      : null,
    reason: null
  };
}

module.exports = { enumerate, evaluateSubject, resolvePermissionHelper, GATE_TOKEN_RE, IDENTITY_CONDITION_RE };
