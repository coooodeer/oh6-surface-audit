'use strict';

/**
 * p4-facts.js —— 为 P4 11 条候选补当前可补的本地事实：
 *   - 现有 candidate/origin/sizeExpr/widthMix/boundCheck
 *   - native-harness UBSan oracle 的 state/reason/trigger
 *   - 入口契约 required_checks/reachability
 *   - 源码窗口里的类型/参数声明（type hints）
 *
 * 输出 out/p4/{candidates,summary}.jsonl/json、out/report/p4-data.md
 */

const fs = require('fs');
const path = require('path');
const { TOOL_ROOT, SOURCE_ROOT, OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');

const CANDIDATES = path.join(TOOL_ROOT, '..', 'oh6-vuln-agent', 'result', 'latest', 'candidates.jsonl');
const ENTRIES = path.join(TOOL_ROOT, '..', 'oh6-vuln-agent', 'result', 'latest', 'contracts', 'entries.jsonl');
const ORACLE = path.join(TOOL_ROOT, '..', 'oh6-vuln-agent', 'result', 'optimization', 'native-harness-20261014', 'per-candidate.jsonl');
const OUT = path.join(OUT_ROOT, 'p4');

const TYPE_RE = /\b(uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t|size_t|ssize_t|unsigned\s+int|unsigned\s+long|unsigned\s+short|unsigned\s+char|int|long|short|char|bool)\b\s+\**\s*([A-Za-z_]\w*)/g;

function stripPrefix(f) { return String(f || '').replace(/^OpenHarmony\//, ''); }

function main() {
  ensureDir(OUT);
  const candidates = readJsonl(CANDIDATES).filter((r) => r.generator === 'G-P4');
  const entries = new Map(readJsonl(ENTRIES).map((e) => [e.id, e]));
  const oracle = new Map(readJsonl(ORACLE).map((r) => [r.candidateId, r]));
  const cache = new Map();
  const rows = [];
  for (const c of candidates) {
    const file = stripPrefix(c.origin && c.origin.file);
    const line = c.origin && c.origin.line;
    const repo = file.split('/').slice(0, 3).join('/');
    const rel = file.startsWith(`${repo}/`) ? file.slice(repo.length + 1) : file;
    let lines = cache.get(`${repo}\u0000${rel}`);
    if (!lines) {
      try { lines = fs.readFileSync(path.join(SOURCE_ROOT, repo, rel), 'utf8').split(/\r?\n/); } catch (_) { lines = null; }
      cache.set(`${repo}\u0000${rel}`, lines);
    }
    const hints = [];
    if (lines && line) {
      const a = Math.max(0, line - 12);
      const b = Math.min(lines.length, line + 8);
      for (let i = a; i < b; i += 1) {
        TYPE_RE.lastIndex = 0;
        let m;
        while ((m = TYPE_RE.exec(lines[i] || '')) !== null) {
          hints.push({ type: m[1].replace(/\s+/g, ' '), name: m[2], line: i + 1 });
        }
      }
    }
    const o = oracle.get(c.candidateId) || null;
    const e = entries.get(c.entryId) || null;
    rows.push({
      candidateId: c.candidateId,
      entryId: c.entryId,
      repo,
      file: rel,
      line,
      sizeExpr: c.origin && c.origin.sizeExpr,
      originText: c.origin && c.origin.text,
      binding: c.binding && c.binding.status,
      entryBinding: c.signal && c.signal.entryBinding,
      entry: e ? { id: e.id, kind: e.kind, reachability: e.reachability, attacker_position: e.attacker_position, required_checks: e.required_checks, originStatus: e.originStatus } : null,
      widthMix: (c.signal && c.signal.widthMix) || [],
      sizeExprArith: !!(c.signal && c.signal.sizeExprArith),
      explicitCast: !!(c.signal && c.signal.explicitCast),
      boundCheckInWindow: c.signal && c.signal.boundCheckInWindow,
      typeHints: hints,
      knownTypeNames: [...new Set(hints.map((h) => h.type))],
      oracle: o ? {
        state: o.state,
        reason: o.reason,
        template: o.template,
        oracleId: o.verification && o.verification.oracleId,
        triggered: o.verification && o.verification.runs && o.verification.runs.triggered,
        repeats: o.verification && o.verification.runs && o.verification.runs.repeats,
        triggerArg: o.verification && o.verification.runs && o.verification.runs.triggerArg,
        params: o.detail && o.detail.params,
        function: o.detail && o.detail.function
      } : null
    });
  }
  writeJsonl(path.join(OUT, 'candidates.jsonl'), rows);
  const byOracle = rows.reduce((a, r) => { const k = r.oracle ? r.oracle.state : 'missing'; a[k] = (a[k] || 0) + 1; return a; }, {});
  const withHints = rows.filter((r) => r.typeHints.length).length;
  const withEntry = rows.filter((r) => r.entry).length;
  const summary = {
    generatedAt: new Date().toISOString(),
    candidates: rows.length,
    oracle: byOracle,
    withTypeHints: withHints,
    withEntryContract: withEntry,
    confirmed: rows.filter((r) => r.oracle && r.oracle.state === 'confirmed').map((r) => r.candidateId),
    blockedReasons: rows.filter((r) => r.oracle && r.oracle.state !== 'confirmed').reduce((a, r) => { const k = r.oracle.reason || 'unknown'; a[k] = (a[k] || 0) + 1; return a; }, {}),
    remainingGaps: [
      'entry binding 仍为 suspect/module-inherited；需要 L2 function-entry pairing',
      'typeHints 只是源码窗口声明，不是完整表达式类型/宽度；需要 clang/类型推导',
      'boundCheckInWindow 只是语法窗口，不是 CFG 支配性',
      '7 条 no-driver-template、3 条 compile-failed 的 UBSan 缺口仍在'
    ]
  };
  writeJson(path.join(OUT, 'summary.json'), summary);
  const lines = [];
  lines.push('# P4 当前可补事实');
  lines.push('');
  lines.push(`生成时间：${summary.generatedAt}`);
  lines.push(`候选 ${summary.candidates}；oracle=${JSON.stringify(summary.oracle)}；有类型提示 ${summary.withTypeHints}/${summary.candidates}；有入口契约 ${summary.withEntryContract}/${summary.candidates}。`);
  lines.push('');
  lines.push('| candidate | oracle | sizeExpr | 类型提示 | entry | binding |');
  lines.push('| --- | --- | --- | --- | --- | --- |');
  for (const r of rows) {
    lines.push(`| ${r.candidateId} | ${r.oracle ? r.oracle.state : '-'} | ${r.sizeExpr || '-'} | ${r.knownTypeNames.join(',') || '-'} | ${r.entry ? r.entry.reachability : '-'} | ${r.binding || '-'} |`);
  }
  lines.push('');
  lines.push('## 仍未补');
  lines.push('');
  for (const g of summary.remainingGaps) lines.push(`- ${g}`);
  ensureDir(path.join(OUT_ROOT, 'report'));
  fs.writeFileSync(path.join(OUT_ROOT, 'report', 'p4-data.md'), lines.join('\n'), 'utf8');
  process.stdout.write(`p4 facts: candidates=${rows.length} oracle=${JSON.stringify(byOracle)} typeHints=${withHints} entry=${withEntry}\n`);
}

main();
