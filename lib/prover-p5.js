'use strict';

/**
 * prover-p5.js —— P5 权限提升/访问控制绕过的 L4a 判定（R1）。
 *
 * 两条路径：
 *   1) fixture：对 pre/post 或 original/mutant 源码做行级检查覆盖分析；
 *   2) 真实 unit：读取 pairing/paths/check-sites 的 O1–O10 证据。
 *
 * 纪律：
 *   - client/test check 不计入 O6/O7/O8；
 *   - 没有 O6/O7/O8 证明时不得 PROVEN-VULN；
 *   - 没有 O10 confirmed 时最高 PROVEN-WEAKNESS；
 *   - 模型只做语义残差，不直接给最终 verdict。
 */

const CHECK_RE = String.raw`(?:CheckPermission|CheckChannelPermission|VerifyPermission|VerifyCallingPermission|VerifyAccessToken|IsSystemApp)`;
const CHECK_KINDS = new Set(['check-permission', 'verify-calling-permission', 'verify-permission', 'verify-access-token', 'is-system-app']);

function findLine(lines, re, from = 0, to = null) {
  const end = to == null ? lines.length : Math.min(to, lines.length);
  for (let i = from; i < end; i += 1) if (re.test(lines[i])) return i;
  return -1;
}

function isComment(line) {
  return /^\s*(\/\/|\/\*|\*)/.test(String(line || ''));
}

function exitAfterCheck(lines, checkIdx) {
  let open = -1;
  if (String(lines[checkIdx] || '').includes('{')) open = checkIdx;
  else {
    for (let i = checkIdx + 1; i < Math.min(lines.length, checkIdx + 4); i += 1) {
      if (String(lines[i] || '').includes('{')) { open = i; break; }
    }
  }
  if (open >= 0) {
    let depth = 0;
    let close = -1;
    for (let i = open; i < lines.length; i += 1) {
      for (const ch of String(lines[i] || '')) {
        if (ch === '{') depth += 1;
        if (ch === '}') depth -= 1;
      }
      if (depth === 0) { close = i; break; }
    }
    if (close >= 0) {
      for (let i = open; i <= close; i += 1) {
        if (/\b(return|throw|goto|break|continue)\b/.test(lines[i])) return i;
      }
      return -1;
    }
  }
  for (let i = checkIdx + 1; i < Math.min(lines.length, checkIdx + 4); i += 1) {
    if (/\b(return|throw|goto|break|continue)\b/.test(lines[i])) return i;
  }
  return -1;
}

function argsOfCall(line, start = 0) {
  const s = String(line || '');
  const idx = s.indexOf('(', start);
  if (idx < 0) return '';
  let depth = 0;
  for (let i = idx; i < s.length; i += 1) {
    if (s[i] === '(') depth += 1;
    else if (s[i] === ')') {
      depth -= 1;
      if (depth === 0) return s.slice(idx + 1, i);
    }
  }
  return s.slice(idx + 1);
}

function analyzeP5Source(caseRow, sourceKey) {
  const source = sourceKey === 'mutant' ? caseRow.mutantSource : sourceKey === 'post' ? caseRow.postSource : sourceKey === 'pre' ? caseRow.preSource : caseRow.originalSource;
  if (!source) return { error: 'source-missing' };
  const lines = String(source).split(/\r?\n/);
  const sinkRe = new RegExp(caseRow.sinkPattern || 'SendMessage\\s*\\(');
  const checkRe = new RegExp(caseRow.checkPattern || CHECK_RE);
  const sinkIdx = findLine(lines, sinkRe);
  const checks = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (isComment(lines[i])) continue;
    if (!checkRe.test(lines[i])) continue;
    checks.push({ line: i + 1, index: i, text: lines[i].trim() });
  }
  const before = checks.filter((c) => sinkIdx >= 0 && c.index < sinkIdx);
  const after = checks.filter((c) => sinkIdx >= 0 && c.index > sinkIdx);
  const effective = [];
  for (const c of before) {
    const scopeLines = lines.slice(c.index, Math.min(lines.length, c.index + 10)).join('\n');
    const disabled = /if\s*\(\s*(false|0)\s*\)/.test(scopeLines);
    const exit = exitAfterCheck(lines, c.index);
    const permissionOk = !caseRow.requiredPermission || new RegExp(caseRow.requiredPermission.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).test(scopeLines);
    const args = argsOfCall(c.text, 0);
    const argsOk = !caseRow.requiredArgs || caseRow.requiredArgs.every((a) => scopeLines.includes(a));
    effective.push({ ...c, exitLine: exit >= 0 ? exit + 1 : null, disabled, permissionOk, argsOk, args, scopeLines });
  }
  const anyBefore = before.length > 0;
  const anyEffective = effective.some((c) => !c.disabled && c.exitLine && c.permissionOk && c.argsOk);
  const anyWithExit = effective.some((c) => !c.disabled && c.exitLine);
  const anyPermissionMismatch = effective.some((c) => !c.permissionOk);
  const anyArgsMismatch = effective.some((c) => !c.argsOk);
  const checkAfterSink = after.length > 0 && !anyBefore;
  let o6;
  let o7;
  let o8;
  if (!anyBefore) { o6 = 'disproven'; o7 = 'disproven'; o8 = 'disproven'; }
  else {
    o6 = 'proven';
    o7 = (anyPermissionMismatch || anyArgsMismatch) ? 'disproven' : (anyEffective ? 'proven' : (anyWithExit ? 'unproven' : 'disproven'));
    o8 = anyEffective ? 'proven' : (anyWithExit ? 'disproven' : 'disproven');
  }
  return {
    sinkLine: sinkIdx + 1,
    checks,
    beforeSink: before.map((c) => c.line),
    afterSink: after.map((c) => c.line),
    effective: effective.map((c) => ({ line: c.line, exitLine: c.exitLine, disabled: c.disabled, permissionOk: c.permissionOk, argsOk: c.argsOk })),
    checkAfterSink,
    O6: o6,
    O7: o7,
    O8: o8
  };
}

function obligationsForSource(caseRow, sourceKey) {
  const a = analyzeP5Source(caseRow, sourceKey);
  const mk = (id, kind, status, evidence = {}, reason = null) => ({ id, kind, status, evidence, ...(reason ? { reason } : {}) });
  return {
    analysis: a,
    obligations: [
      mk('O1', 'entry-resolved', 'proven', { entry: caseRow.function, repo: caseRow.repo }),
      mk('O2', 'caller-identity', 'proven', { fixture: true }),
      mk('O3', 'object-identity', 'proven', { fixture: true }),
      mk('O4', 'sink-resolved', a.sinkLine > 0 ? 'proven' : 'disproven', { sinkLine: a.sinkLine }),
      mk('O5', 'permission-requirement', 'proven', { requiredPermission: caseRow.requiredPermission || null }),
      mk('O6', 'check-presence', a.O6, { beforeSink: a.beforeSink, checks: a.checks }, a.O6 !== 'proven' ? 'no-server-check-before-sink' : null),
      mk('O7', 'check-operand-match', a.O7, { effective: a.effective, requiredPermission: caseRow.requiredPermission || null }, a.O7 !== 'proven' ? 'check-operand-mismatch' : null),
      mk('O8', 'path-coverage', a.O8, { sinkLine: a.sinkLine, effective: a.effective }, a.O8 !== 'proven' ? 'check-not-covering-sink-path' : null),
      mk('O9', 'entry-coverage', 'proven', { fixture: true }),
      mk('O10', 'fix-kind/oracle', 'proven', { oracle: caseRow.fixCommit ? `historical:${caseRow.fixCommit}` : 'synthetic-mutant' })
    ]
  };
}

function p5Verdict(obligations) {
  const o = (id) => obligations.find((x) => x.id === id) || { status: 'unproven', evidence: {} };
  if (o('O1').status === 'disproven') return { claimVerdict: 'NOT-APPLICABLE', reason: 'not-service-entry' };
  if (o('O5').status === 'disproven') return { claimVerdict: 'NOT-VULN', reason: 'no-privilege-boundary' };
  const gate = ['O6', 'O7', 'O8'].map((id) => o(id));
  if (gate.some((x) => x.status === 'disproven')) return { claimVerdict: 'VIOLATION', reason: 'access-control-obligation-disproven' };
  if (gate.some((x) => x.status === 'unproven')) return { claimVerdict: 'UNPROVEN', reason: 'access-control-obligation-unproven' };
  if (o('O9').status === 'disproven') return { claimVerdict: 'VIOLATION', reason: 'alternate-entry-bypass' };
  if (o('O9').status === 'proven') return { claimVerdict: 'SATISFIED', reason: 'server-check-covers-sink' };
  return { claimVerdict: 'UNPROVEN', reason: 'entry-coverage-unproven' };
}

function productForP5(claimVerdict, obligations, opts = {}) {
  const o = (id) => obligations.find((x) => x.id === id) || { status: 'unproven', evidence: {} };
  const impact = opts.impact || null;
  if (impact && impact.status === 'refuted') return { productVerdict: 'NOT-VULN', reason: `impact-refuted:${impact.reason || 'refuted'}` };
  if (claimVerdict === 'SATISFIED') return { productVerdict: 'NOT-VULN', reason: 'server-check-covers-sink' };
  if (claimVerdict === 'NOT-VULN') return { productVerdict: 'NOT-VULN', reason: 'no-privilege-boundary' };
  if (claimVerdict === 'NOT-APPLICABLE') return { productVerdict: 'NOT-APPLICABLE', reason: 'not-service-entry' };
  if (claimVerdict !== 'VIOLATION') return { productVerdict: 'CONDITIONS-NOT-MET', reason: 'unproven' };
  const required = ['O1', 'O2', 'O3', 'O4', 'O5', 'O9'];
  const allRequired = required.every((id) => o(id).status === 'proven');
  const o10 = o('O10').status === 'proven';
  const impactConfirmed = impact ? impact.status === 'confirmed' : opts.impactNotAssessed !== true;
  if (allRequired && o10 && impactConfirmed) return { productVerdict: 'PROVEN-VULN', reason: 'all-required-proven-and-oracle-confirmed' };
  if (allRequired && o10) return { productVerdict: 'PROVEN-WEAKNESS', reason: impact ? `impact-${impact.status || 'unknown'}` : 'impact-not-assessed' };
  return { productVerdict: 'PROVEN-WEAKNESS', reason: 'oracle-or-obligation-unproven' };
}

function proveP5SourceCase(caseRow, sourceKey) {
  const { obligations, analysis } = obligationsForSource(caseRow, sourceKey);
  const v = p5Verdict(obligations);
  const p = productForP5(v.claimVerdict, obligations, { impactNotAssessed: true });
  return { caseId: caseRow.id, sourceKey, obligations, analysis, claimVerdict: v.claimVerdict, reason: v.reason, productVerdict: p.productVerdict };
}

module.exports = {
  CHECK_RE,
  CHECK_KINDS,
  analyzeP5Source,
  obligationsForSource,
  p5Verdict,
  productForP5,
  proveP5SourceCase
};
