'use strict';

/**
 * prover-p3.js —— P3 空指针的 L4a 蕴含式判定（O1–O4）。
 *
 * 修正后的口径：
 *   O2 producer-may-null 是风险前提，不是安全义务；
 *   O2 unproven 时，即使 O3 没有 guard，也只能 UNPROVEN，不能 VIOLATION；
 *   O4-local 只证明同函数/同表达式的局部路径，`O4-full`（跨函数/别名/分支可行性）本轮不做；
 *   VIOLATION 只是 claim-candidate；impact/reportability 未实现时不允许升 PROVEN-VULN。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('./util.js');
const { findFunction } = require('./prover.js');

const OK = 'proven';
const NO = 'disproven';
const UNK = 'unproven';

const P3_CASES = path.join(OUT_ROOT, '..', 'eval', 'p3', 'cases.jsonl');
const OUT = path.join(OUT_ROOT, 'p3');

function exitInBlock(lines, start, end) {
  for (let i = start; i <= end && i < lines.length; i += 1) {
    const t = String(lines[i] || '');
    if (/\b(return|throw|continue|break)\b/.test(t)) return i + 1;
    if (/\b(CHECK|RETURN_IF|LOG_AND_RETURN|ABORT|EXIT)\w*\s*\(/.test(t)) return i + 1;
  }
  return null;
}

function isTestOnlyMacro(line) {
  return /\b(EXPECT|ASSERT)_[A-Z_]+\s*\(/.test(String(line || ''));
}

function normalizeExpr(expr) {
  return String(expr || '').replace(/\s+/g, '');
}

function targetMatches(condition, target) {
  const c = normalizeExpr(condition);
  const t = normalizeExpr(target);
  if (!t) return false;
  return c.includes(t) || c.includes(`!${t}`);
}

function nullCheckKind(condition, target) {
  const c = normalizeExpr(condition);
  const t = normalizeExpr(target);
  if (!t) return null;
  // 负向守卫：条件成立 => target 为空（then 分支应退出）
  const negative = [
    `!${t}`,
    `${t}==nullptr`,
    `nullptr==${t}`,
    `${t}==NULL`,
    `NULL==${t}`,
    `${t}==0`,
    `0==${t}`
  ];
  // 正向守卫：条件成立 => target 非空（then 分支可安全 deref）
  const positive = [
    `${t}!=nullptr`,
    `nullptr!=${t}`,
    `${t}!=NULL`,
    `NULL!=${t}`,
    `${t}!=0`,
    `0!=${t}`
  ];
  // 成员/函数返回值：x.y == nullptr / p->f == nullptr / p->Get() == nullptr
  const memberNeg = new RegExp(`${escapeRe(t)}(?:\\.|->)[\\w.>()]+==(?:nullptr|NULL)`);
  const memberPos = new RegExp(`${escapeRe(t)}(?:\\.|->)[\\w.>()]+!=(?:nullptr|NULL)`);
  if (negative.includes(c) || memberNeg.test(c)) return 'negative';
  if (positive.includes(c) || memberPos.test(c)) return 'positive';
  return null;
}

function splitTopLevelOr(condition) {
  const parts = [];
  let depth = 0;
  let last = 0;
  const s = String(condition);
  for (let i = 0; i < s.length - 1; i += 1) {
    if (s[i] === '(') depth += 1;
    else if (s[i] === ')') depth -= 1;
    else if (depth === 0 && s[i] === '|' && s[i + 1] === '|') {
      parts.push(s.slice(last, i));
      last = i + 2;
      i += 1;
    }
  }
  if (!parts.length) return [s];
  parts.push(s.slice(last));
  return parts;
}

function splitTopLevelAnd(condition) {
  const parts = [];
  let depth = 0;
  let last = 0;
  const s = String(condition);
  for (let i = 0; i < s.length - 1; i += 1) {
    if (s[i] === '(') depth += 1;
    else if (s[i] === ')') depth -= 1;
    else if (depth === 0 && s[i] === '&' && s[i + 1] === '&') {
      parts.push(s.slice(last, i));
      last = i + 2;
      i += 1;
    }
  }
  if (!parts.length) return [s];
  parts.push(s.slice(last));
  return parts;
}

function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractCondition(lines, startIdx) {
  const text = String(lines[startIdx] || '');
  const idx = text.indexOf('(');
  if (idx < 0) return null;
  let depth = 0;
  let cond = '';
  for (let i = startIdx; i < Math.min(lines.length, startIdx + 8); i += 1) {
    const t = i === startIdx ? text.slice(idx) : String(lines[i] || '');
    for (const ch of t) {
      if (ch === '(') {
        depth += 1;
        if (depth === 1) continue;
      }
      if (ch === ')') {
        depth -= 1;
        if (depth === 0) return cond.trim();
      }
      cond += ch;
    }
  }
  return null;
}

function findBlock(lines, startIdx, searchFrom = 0) {
  let open = -1;
  for (let i = startIdx + searchFrom; i < Math.min(lines.length, startIdx + 6); i += 1) {
    if (String(lines[i] || '').includes('{')) { open = i; break; }
  }
  if (open < 0) return null;
  let depth = 0;
  let close = -1;
  for (let i = open; i < lines.length; i += 1) {
    for (const ch of String(lines[i] || '')) {
      if (ch === '{') depth += 1;
      if (ch === '}') depth -= 1;
    }
    if (depth === 0) { close = i; break; }
  }
  return close < 0 ? null : { open, close };
}

/**
 * 在函数体内找 deref 前的 null guard。
 * 返回 proven/disproven/unproven，不做 CFG 支配性证明。
 */
function evalGuard(l1, repo, file, functionName, derefLine, target, fnRange = null) {
  const lines = l1.sourceLines(repo, file);
  if (!lines || !lines.length) return { status: UNK, reason: 'source-not-found', evidence: {} };
  let start = fnRange ? fnRange[0] : null;
  let end = fnRange ? fnRange[1] : null;
  if (!start || !end) {
    const fn = findFunction(lines.join('\n'), functionName);
    if (!fn) return { status: UNK, reason: 'function-not-found', evidence: {} };
    start = fn.startLine;
    end = fn.endLine;
  }
  const bodyEnd = Math.min(end, lines.length);
  const targetText = String(target || '');
  if (!targetText) return { status: UNK, reason: 'variable-missing', evidence: {} };

  let candidateGuard = null;
  for (let i = Math.max(0, start - 1); i < Math.min(derefLine - 1, bodyEnd); i += 1) {
    const line = String(lines[i] || '');
    if (isTestOnlyMacro(line)) continue;

    // 宏式 null 检查
    const macro = new RegExp(`\\b(CHECK_NULL|RETURN_IF_NULL|CHECK_AND_RETURN|RETURN_IF)\\s*\\([^)]*${escapeRe(targetText.split('::').pop())}`).exec(line);
    if (macro) {
      return { status: OK, evidence: { guardKind: 'macro', guardLine: i + 1, macro: macro[1] } };
    }

    const ifIdx = line.search(/\bif\s*\(/);
    if (ifIdx < 0) continue;
    const cond = extractCondition(lines, i);
    if (!cond) continue;
    const block = findBlock(lines, i, line.indexOf('{', ifIdx) >= 0 ? 0 : 1);
    if (!block) continue;
    const derefInside = derefLine - 1 >= block.open && derefLine - 1 <= block.close;
    const exitLine = exitInBlock(lines, block.open, block.close);

    const orParts = splitTopLevelOr(cond);
    const negHit = orParts.some((p) => nullCheckKind(p, targetText) === 'negative' && targetMatches(p, targetText));
    const andParts = splitTopLevelAnd(cond);
    const posHit = andParts.some((p) => nullCheckKind(p, targetText) === 'positive' && targetMatches(p, targetText));

    if (negHit) {
      if (exitLine) return { status: OK, evidence: { guardKind: 'negative-null-guard-exit', guardLine: i + 1, exitLine, condition: cond } };
      if (derefInside) return { status: NO, reason: 'deref-in-null-branch', evidence: { guardLine: i + 1, condition: cond } };
      candidateGuard = { guardLine: i + 1, condition: cond, reason: 'guard-no-exit' };
      continue;
    }
    if (posHit) {
      if (derefInside) return { status: OK, evidence: { guardKind: 'positive-null-guard-encloses-deref', guardLine: i + 1, condition: cond } };
      candidateGuard = { guardLine: i + 1, condition: cond, reason: 'positive-guard-does-not-enclose-deref' };
      continue;
    }
    // 成员/返回值空检查：guard 变量不是 target 本身时，仅当条件文本包含 target 且含 null 才认
    if (/nullptr|NULL/.test(cond) && targetMatches(cond, targetText)) {
      if (exitLine) return { status: OK, evidence: { guardKind: 'member-null-guard-exit', guardLine: i + 1, exitLine, condition: cond } };
      candidateGuard = { guardLine: i + 1, condition: cond, reason: 'member-guard-no-exit' };
    }
  }
  if (candidateGuard) return { status: UNK, reason: candidateGuard.reason, evidence: candidateGuard };
  return { status: NO, reason: 'no-null-guard-before-deref', evidence: { derefLine } };
}

/** 从文本片段（mutant）评估 guard */
function evalGuardFromText(text, functionName, variable) {
  const fn = findFunction(text, functionName);
  if (!fn) return { status: UNK, reason: 'function-not-found', evidence: {} };
  const lines = String(text).split(/\r?\n/);
  const fake = {
    sourceLines: () => lines
  };
  const target = String(variable || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const derefRe = new RegExp(`\\b${target}\\s*(?:->|\\.)`);
  let derefLine = fn.endLine;
  for (let i = fn.startLine - 1; i < Math.min(lines.length, fn.endLine); i += 1) {
    if (derefRe.test(lines[i])) { derefLine = i + 1; break; }
  }
  return evalGuard(fake, null, null, functionName, derefLine, variable, [fn.startLine, fn.endLine]);
}

/**
 * O4-local：只证明同函数内“producer 调用 -> deref”的局部路径。
 */
function evalO4Local(l1, claim) {
  const repo = claim.source.repo;
  const file = claim.source.file;
  const line = claim.source.line;
  const text = String(claim.source.text || '');
  const producerName = claim.producer && claim.producer.name;
  const fn = claim.entry.functionId ? l1.getFunctionById(claim.entry.functionId) : null;
  if (!producerName) return { status: UNK, reason: 'producer-missing', evidence: {} };

  // 同一表达式：GetInstance()->Method() / x.GetInstance().Method()
  if (new RegExp(`${escapeRe(producerName)}\\s*\\([^)]*\\)\\s*(?:\\.|->)`).test(text)) {
    return {
      status: OK,
      evidence: {
        path: 'same-expression',
        producerCall: `${producerName}()`,
        derefLine: line,
        note: 'producer call and deref are in the same expression; no assignment/branch between them'
      }
    };
  }

  // 相邻行赋值：p = GetInstance(); p->Method();
  const lines = l1.sourceLines(repo, file);
  const start = fn ? fn.startLine : Math.max(1, line - 30);
  for (let i = line - 2; i >= Math.max(0, start - 1); i -= 1) {
    const l = String(lines[i] || '');
    if (!new RegExp(`${escapeRe(producerName)}\\s*\\(`).test(l)) continue;
    const between = lines.slice(i + 1, line - 1).filter((x) => String(x).trim() && !/^\s*(\/\/|\/\*|\*)/.test(String(x)));
    if (line - 1 - i === 1 && between.length === 0) {
      return { status: OK, evidence: { path: 'adjacent-line', producerLine: i + 1, derefLine: line } };
    }
    if (between.some((x) => /\b(if|for|while|return|goto|switch)\b|[{}=]/.test(String(x)))) {
      return { status: UNK, reason: 'control-flow-or-assignment-between', evidence: { producerLine: i + 1, betweenLines: between.length } };
    }
    return { status: UNK, reason: 'non-adjacent-local-path', evidence: { producerLine: i + 1, derefLine: line } };
  }
  return { status: UNK, reason: 'producer-call-not-located', evidence: { producer: producerName, line } };
}

function verdictFor(o1, o2, o3, o4 = { status: UNK }) {
  if (o1.status === NO) return 'NOT-APPLICABLE';
  if (o2.status === NO) return 'NOT-VULN';
  if (o2.status === UNK) return 'UNPROVEN';
  if (o3.status === NO) return 'VIOLATION';
  if (o3.status === OK) return 'SATISFIED';
  return 'UNPROVEN';
}

function productFor(claimVerdict, o4, opts = {}) {
  if (claimVerdict === 'VIOLATION') {
    if (o4.status !== OK) return 'CONDITIONS-NOT-MET';
    return opts.impactNotAssessed ? 'PROVEN-WEAKNESS' : 'PROVEN-VULN';
  }
  if (claimVerdict === 'SATISFIED') return 'NOT-VULN';
  if (claimVerdict === 'NOT-APPLICABLE') return 'NOT-APPLICABLE';
  return 'CONDITIONS-NOT-MET';
}

function proveP3Claim(claim, l1, l2, opts = {}) {
  const fn = claim.entry.functionId ? l1.getFunctionById(claim.entry.functionId) : null;
  const o1 = {
    status: claim.entry.reachable ? OK : NO,
    evidence: { reachable: claim.entry.reachable, entryBinding: claim.entry.entryBinding, entryKey: claim.entry.entryKey, depth: claim.entry.depth }
  };
  const probe = l1.derefById(String(claim.claimId).replace(/^L3-P3-/, ''));
  const producerEval = l2.resolveProducer(claim.source.repo, probe || {
    producer: claim.producer.name,
    text: claim.source.text
  });
  const o2 = { status: producerEval.status, reason: producerEval.reason, evidence: producerEval.evidence };
  const o3 = evalGuard(l1, claim.source.repo, claim.source.file, claim.entry.function, claim.source.line, claim.producer.name, fn ? [fn.startLine, fn.endLine] : null);
  const o4 = evalO4Local(l1, claim);
  const claimVerdict = verdictFor(o1, o2, o3, o4);
  const productVerdict = productFor(claimVerdict, o4, opts);
  return {
    claimId: claim.claimId,
    class: 'P3',
    group: claim.group,
    origin: claim.origin || null,
    inTarget: claim.inTarget === true,
    codeState: claim.codeState || null,
    productionEligible: claim.productionEligible === true,
    novelty: claim.novelty || null,
    repo: claim.source.repo,
    file: claim.source.file,
    line: claim.source.line,
    function: claim.entry.function,
    variable: claim.producer.name,
    obligations: [
      { id: 'O1', kind: 'entry-reachable', ...o1 },
      { id: 'O2', kind: 'producer-may-null', ...o2 },
      { id: 'O3', kind: 'guard-before-deref', ...o3 },
      { id: 'O4', kind: 'deref-in-path-local', ...o4 }
    ],
    claimVerdict,
    claimability: claimVerdict === 'VIOLATION' ? (o4.status === OK ? 'claim-candidate' : 'needs-path') : 'none',
    productVerdict,
    productReason: opts.impactNotAssessed ? 'impact-not-assessed' : null
  };
}

function proveP3Claims(claims, l1, l2, opts = {}) {
  return claims.map((c) => proveP3Claim(c, l1, l2, opts));
}

function evaluateFixture(caseRow, text, functionName, variable) {
  const fn = text ? findFunction(text, functionName) : null;
  if (!fn) return { status: UNK, reason: 'function-not-found', evidence: {} };
  return evalGuardFromText(text, functionName, variable);
}

function proveFixtures(l1) {
  const cases = readJsonl(P3_CASES);
  const rows = [];
  for (const c of cases) {
    const lines = l1.sourceLines(c.repo, c.file);
    const mutPath = path.join(path.dirname(path.dirname(P3_CASES)), c.mutantFile);
    let mutText = '';
    try { mutText = fs.readFileSync(mutPath, 'utf8'); } catch (_) { mutText = ''; }
    const originalText = lines ? lines.join('\n') : '';
    const origGuard = originalText ? evalGuardFromText(originalText, c.function, c.variable) : { status: UNK, reason: 'source-not-found', evidence: {} };
    const mutGuard = mutText ? evalGuardFromText(mutText, c.function, c.variable) : { status: UNK, reason: 'mutant-not-found', evidence: {} };
    const mk = (variant, o3) => {
      const o1 = { status: OK, evidence: { fixture: true, functionRange: c.functionRange } };
      const o2 = { status: OK, evidence: { fixture: 'producer-assumed-nullable' } };
      const o4 = { status: OK, evidence: { fixture: 'local-path-declared-by-mutant' } };
      const claimVerdict = verdictFor(o1, o2, o3, o4);
      rows.push({
        claimId: c.id,
        class: 'P3',
        kind: 'fixture',
        variant,
        repo: c.repo,
        file: c.file,
        function: c.function,
        variable: c.variable,
        obligations: [
          { id: 'O1', kind: 'entry-reachable', ...o1 },
          { id: 'O2', kind: 'producer-may-null', ...o2 },
          { id: 'O3', kind: 'guard-before-deref', ...o3 },
          { id: 'O4', kind: 'deref-in-path-local', ...o4 }
        ],
        claimVerdict,
        claimability: claimVerdict === 'VIOLATION' ? 'fixture' : 'none',
        // 合成 mutant 只用于验证判别力，不是产品 claim；不写 PROVEN-VULN。
        productVerdict: claimVerdict === 'VIOLATION' ? 'PROVEN-WEAKNESS' : 'NOT-VULN',
        productReason: variant === 'mutant' ? 'synthetic-mutant' : 'synthetic-original'
      });
    };
    mk('original', origGuard);
    mk('mutant', mutGuard);
  }
  return rows;
}

function summaryOfVerdicts(rows) {
  const countBy = (list, field) => list.reduce((a, r) => { a[r[field]] = (a[r[field]] || 0) + 1; return a; }, {});
  const obligations = {};
  for (const r of rows) {
    for (const ob of r.obligations || []) {
      if (!obligations[ob.id]) obligations[ob.id] = {};
      obligations[ob.id][ob.status] = (obligations[ob.id][ob.status] || 0) + 1;
    }
  }
  return { claimVerdict: countBy(rows, 'claimVerdict'), productVerdict: countBy(rows, 'productVerdict'), obligations };
}

function main() {
  ensureDir(OUT);
  process.stdout.write('prover-p3: main 已迁移到 bin/run-p3p4p6.js；本入口只保留兼容导出。\n');
}

module.exports = {
  evalGuard,
  evalGuardFromText,
  evalO4Local,
  verdictFor,
  productFor,
  proveP3Claim,
  proveP3Claims,
  proveFixtures,
  summaryOfVerdicts,
  main
};
