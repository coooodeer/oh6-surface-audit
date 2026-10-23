'use strict';

/**
 * spec-prover-batch.js —— 对 12 条 spec 的自动义务批量跑 prover。
 *
 * 输入：out/obligations/obligations.jsonl（valid obligations）+ OpenHarmony 源码
 * 输出：out/obligations/{verdicts,claims,summary}.jsonl/json、out/report/obligations.md
 *
 * 只把 VIOLATION 且 confidence 非 low 的条目写成 claim-candidates；
 * 因为还没有 entry-reachability / dataflow，**不送 judge**，gate 状态写 needs-path-and-dataflow。
 */

const fs = require('fs');
const path = require('path');
const { proveSpec } = require(path.join(__dirname, '..', 'lib', 'prover.js'));

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, '..', 'OpenHarmony');
const OUT = path.join(ROOT, 'out', 'obligations');
const REPORT = path.join(ROOT, 'out', 'report', 'obligations.md');

function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }
function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
}
function writeJsonl(file, rows) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''), 'utf8');
}
function writeJson(file, obj) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, JSON.stringify(obj, null, 2) + '\n', 'utf8');
}

function main() {
  ensureDir(OUT);
  const rows = readJsonl(path.join(OUT, 'obligations.jsonl'));
  const verdicts = [];
  const claims = [];
  for (const rec of rows) {
    if (!rec.ok) {
      verdicts.push({
        specId: rec.specId,
        seedId: rec.seedId,
        family: rec.family || '(unavailable)',
        repo: rec.repo || null,
        file: rec.file || null,
        functionName: rec.functionName || '(unavailable)',
        ok: false,
        error: rec.error,
        verdict: 'UNPROVEN',
        reason: 'obligations-unavailable',
        claimability: 'none',
        obligations: []
      });
      continue;
    }
    const valid = (rec.obligations || []).filter((o) => o.status === 'valid');
    const invalid = (rec.obligations || []).filter((o) => o.status !== 'valid');
    const abs = path.join(SRC, rec.repo, rec.file);
    if (!fs.existsSync(abs)) {
      verdicts.push({ specId: rec.specId, ok: false, error: 'file-not-found', verdict: 'UNPROVEN', reason: 'source-missing', obligations: [] });
      continue;
    }
    const text = fs.readFileSync(abs, 'utf8');
    const entry = {
      specId: rec.specId,
      seedId: rec.seedId,
      title: rec.title,
      repo: rec.repo,
      file: rec.file,
      functionName: rec.functionName,
      obligations: valid
    };
    const proved = proveSpec(entry, text);
    const confById = new Map(valid.map((o) => [o.id, o.confidence || 'medium']));
    const disprovenConfidence = (proved.disproven || []).map((d) => confById.get(d.id) || 'low');
    const claimable = disprovenConfidence.some((c) => c === 'high' || c === 'medium');
    const v = {
      specId: rec.specId,
      seedId: rec.seedId,
      family: rec.family,
      repo: rec.repo,
      file: rec.file,
      functionName: rec.functionName,
      functionRange: proved.functionRange || rec.functionRange,
      ok: true,
      verdict: proved.verdict,
      reason: proved.verdict === 'SATISFIED' ? 'all-valid-obligations-proven'
        : proved.verdict === 'VIOLATION' ? 'some-valid-obligation-disproven'
          : 'some-valid-obligation-unproven',
      obligations: proved.obligations || [],
      disproven: proved.disproven || [],
      unproven: proved.unproven || [],
      invalidObligations: invalid.map((o) => ({ id: o.id, reason: o.reason, kind: o.kind })),
      validObligations: valid.length,
      disprovenConfidence,
      claimability: proved.verdict === 'VIOLATION' ? (claimable ? 'ready' : 'low-confidence') : 'none',
      claimCandidate: proved.verdict === 'VIOLATION' && claimable,
      readyForJudge: false,
      requires: proved.verdict === 'VIOLATION' && claimable ? ['entry-reachability', 'dataflow'] : []
    };
    verdicts.push(v);
    if (v.claimCandidate) {
      claims.push({
        claimId: `CLAIM-${rec.specId}`,
        specId: rec.specId,
        seedId: rec.seedId,
        function: { repo: rec.repo, file: rec.file, name: rec.functionName, range: v.functionRange },
        verdict: 'VIOLATION',
        disproven: v.disproven,
        evidence: v.disproven.flatMap((d) => Object.entries(d.evidence || {}).map(([k, val]) => ({ kind: k, value: val }))),
        status: 'needs-path-and-dataflow',
        requires: ['entry-reachability', 'dataflow'],
        judgeReady: false,
        reason: 'prover found a disproven obligation; path/dataflow not yet established'
      });
    }
  }
  writeJsonl(path.join(OUT, 'verdicts.jsonl'), verdicts);
  writeJsonl(path.join(OUT, 'claims.jsonl'), claims);

  const counts = {};
  for (const v of verdicts) {
    const k = v.ok ? v.verdict : 'OBLIGATIONS-UNAVAILABLE';
    counts[k] = (counts[k] || 0) + 1;
  }
  const unprovenReasons = {};
  for (const v of verdicts) for (const u of (v.unproven || [])) unprovenReasons[u.reason] = (unprovenReasons[u.reason] || 0) + 1;
  const summary = {
    generatedAt: new Date().toISOString(),
    specs: verdicts.length,
    withValidObligations: verdicts.filter((v) => v.ok).length,
    totalValidObligations: verdicts.reduce((a, v) => a + (v.validObligations || 0), 0),
    counts,
    unprovenReasons,
    claimCandidates: claims.length,
    sentToJudge: 0,
    judgeGate: 'needs entry-reachability + dataflow; not implemented in this step'
  };
  writeJson(path.join(OUT, 'summary.json'), summary);

  const lines = [];
  lines.push('# 12 条 spec 的自动义务化与批量 prover');
  lines.push('');
  lines.push(`生成时间：${summary.generatedAt}`);
  lines.push('');
  lines.push(`${summary.specs} 条 spec；${summary.withValidObligations} 条有有效义务；有效义务 ${summary.totalValidObligations} 条。`);
  lines.push(`判定：${Object.entries(counts).map(([k, n]) => `${k}=${n}`).join('，') || '无'}。`);
  lines.push(`claim-candidates：${summary.claimCandidates}；送 judge：0（缺 entry-reachability + dataflow）。`);
  lines.push('');
  lines.push('| spec | family | 函数 | 义务 | proven | disproven | unproven | 判定 | claimability |');
  lines.push('| --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |');
  for (const v of verdicts) {
    const proven = (v.obligations || []).filter((o) => o.status === 'proven').length;
    lines.push(`| ${v.specId} | ${v.family} | ${v.functionName} | ${v.validObligations || 0} | ${proven} | ${(v.disproven || []).length} | ${(v.unproven || []).length} | ${v.verdict} | ${v.claimability || '-'} |`);
  }
  lines.push('');
  const violations = verdicts.filter((v) => v.verdict === 'VIOLATION');
  if (violations.length) {
    lines.push('## VIOLATION 明细');
    lines.push('');
    for (const v of violations) {
      lines.push(`### ${v.specId}`);
      lines.push('');
      lines.push(`- 函数：\`${v.functionName}\`（${v.repo}/${v.file}）`);
      for (const d of v.disproven || []) lines.push(`- ${d.id}：${d.reason}；evidence=${JSON.stringify(d.evidence)}`);
      lines.push(`- claimability：${v.claimability}；disproven confidence=${JSON.stringify(v.disprovenConfidence || [])}`);
      lines.push(`- status：${v.claimCandidate ? 'needs-path-and-dataflow（未送 judge）' : 'not-a-claim（low-confidence）'}`);
      lines.push('');
    }
  }
  const unavailable = verdicts.filter((v) => !v.ok);
  if (unavailable.length) {
    lines.push('## 无有效义务');
    lines.push('');
    for (const v of unavailable) lines.push(`- ${v.specId}：${v.error || v.reason}`);
    lines.push('');
  }
  lines.push('## 口径');
  lines.push('');
  lines.push('- 义务由模型生成，但只有“片段能在函数体里匹配”的义务才会被执行；模型写错片段记 invalid，不算 violation。');
  lines.push('- prover 是行级/块级检查，不是 CFG/别名/路径敏感分析；`SATISFIED` 不是漏洞否定，`VIOLATION` 也不是漏洞报告。');
  lines.push('- `VIOLATION` 只进 claim-candidate；没有 entry-reachability 和 dataflow，不送 judge。');
  lines.push('');
  ensureDir(path.dirname(REPORT));
  fs.writeFileSync(REPORT, lines.join('\n'), 'utf8');
  process.stdout.write(`batch: specs=${summary.specs} valid=${summary.withValidObligations} verdicts=${JSON.stringify(counts)} claims=${summary.claimCandidates}\n`);
}

main();
