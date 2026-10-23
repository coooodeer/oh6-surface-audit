'use strict';

/**
 * p3-history-obligations.js —— 32 条 null-check-added 历史补丁的 P3 义务反向分析。
 *
 * 只读 history-invariants + git diff；不调用模型。
 * 输出 out/p3/history-obligations.jsonl、summary.json、out/report/p3-history-obligations.md
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { TOOL_ROOT, SOURCE_ROOT, OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');

const INV = path.join(TOOL_ROOT, '..', 'oh6-vuln-agent', 'data', 'facts', 'history-invariants.jsonl');
const OUT = path.join(OUT_ROOT, 'p3');

function gitShow(repo, sha, file) {
  try {
    return execFileSync('git', ['-C', path.join(SOURCE_ROOT, repo), 'show', '--format=', '--unified=3', sha, '--', file], {
      encoding: 'utf8',
      maxBuffer: 8 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe']
    });
  } catch (e) {
    return null;
  }
}

function guardKind(line) {
  const t = String(line || '').trim();
  if (/\b(?:EXPECT|ASSERT)_[A-Z_]+\s*\(/.test(t)) return 'assertion';
  if (/\bCHECK_[A-Z_]+\s*\(/.test(t) || /\bRETURN_IF\b/.test(t)) return 'macro';
  if (/^if\s*\(\s*!\s*[A-Za-z_]\w*\s*\)/.test(t)) return 'negation';
  if (/^if\s*\(\s*[A-Za-z_]\w*\s*==\s*nullptr\s*\)/.test(t)) return 'eq-null';
  if (/^if\s*\(\s*[A-Za-z_]\w*\s*!=\s*nullptr\s*\)/.test(t)) return 'nonnull';
  if (/==\s*nullptr|!=\s*nullptr/.test(t)) return 'compound-null';
  if (/^if\s*\(\s*[A-Za-z_]\w*\s*\)/.test(t)) return 'truthy';
  return 'other';
}

function guardVar(line) {
  const t = String(line || '');
  let m = /!\s*([A-Za-z_]\w*)\s*\)/.exec(t);
  if (m) return m[1];
  m = /([A-Za-z_]\w*(?:\s*(?:\.|->)\s*[A-Za-z_]\w*)*)\s*==\s*nullptr/.exec(t);
  if (m) return m[1].replace(/\s+/g, '');
  return null;
}

function parseDiff(text) {
  const lines = text.split(/\r?\n/);
  const added = [];
  const removed = [];
  const context = [];
  let hunk = '';
  let functionName = null;
  for (const line of lines) {
    if (line.startsWith('@@')) {
      hunk = line;
      const m = /@@[^@]*@@\s*(.*)$/.exec(line);
      if (m && m[1].trim()) functionName = m[1].trim();
      continue;
    }
    if (line.startsWith('diff --git') || line.startsWith('index ') || line.startsWith('---') || line.startsWith('+++')) continue;
    if (line.startsWith('+')) added.push(line.slice(1));
    else if (line.startsWith('-')) removed.push(line.slice(1));
    else if (line.startsWith(' ')) context.push(line.slice(1));
  }
  return { added, removed, context, hunk, functionName };
}

function main() {
  ensureDir(OUT);
  const inv = readJsonl(INV).filter((r) => r.family === 'null-check-added');
  const rows = [];
  for (const r of inv) {
    const file = r.file;
    const text = gitShow(r.repo, r.sha, file);
    if (!text) {
      rows.push({ ...r, diffOk: false, reason: 'git-show-failed', coverage: { O1: 'not-covered', O2: 'not-covered', O3: 'not-covered', O4: 'not-covered' } });
      continue;
    }
    const d = parseDiff(text);
    const witnessNorm = String(r.witness || '').replace(/\s+/g, ' ').trim();
    let witnessLine = d.added.find((x) => x.replace(/\s+/g, ' ').trim() === witnessNorm)
      || d.added.find((x) => x.includes(witnessNorm))
      || d.added.find((x) => /^\s*if\s*\(/.test(x))
      || null;
    const kind = witnessLine ? guardKind(witnessLine) : 'missing';
    const variable = witnessLine ? guardVar(witnessLine) : null;
    const witnessIndex = witnessLine ? d.added.indexOf(witnessLine) : -1;
    const after = witnessIndex >= 0 ? d.added.slice(witnessIndex + 1, witnessIndex + 12) : [];
    const exitLine = after.find((x) => /\b(return|throw|continue|break|goto)\b/.test(x)) || null;
    const allAfter = witnessIndex >= 0 ? [...after, ...d.context].join('\n') : d.context.join('\n');
    const derefAfter = variable ? new RegExp(`\\b${variable}\\s*->|\\*\\s*${variable}\\b`).test(allAfter) : false;
    const isTest = /(?:^|\/)(test|tests|unittest|fuzz|fuzzer|mock)(?:\/|$)/i.test(file);
    const producerHint = d.added.some((x) => /new\s*\(\s*std::nothrow\s*\)|return\s+(nullptr|NULL)\b/.test(x));
    const macro = kind === 'macro';
    const guardExit = !!exitLine || macro;
    const coverage = {
      O1: 'not-covered',
      O2: producerHint ? 'partial' : 'not-covered',
      O3: (kind !== 'missing' && guardExit) ? 'covered' : (kind !== 'missing' ? 'partial' : 'not-covered'),
      O4: derefAfter ? 'covered-local' : 'not-covered'
    };
    const patterns = [];
    if (kind !== 'missing') patterns.push(`guard-${kind}`);
    if (macro) patterns.push('macro-guard');
    if (exitLine) patterns.push('guard-exit');
    if (!exitLine && kind !== 'missing' && !macro) patterns.push('guard-no-exit');
    if (isTest) patterns.push('test-only');
    if (derefAfter) patterns.push('deref-after-guard');
    rows.push({
      id: r.id,
      repo: r.repo,
      sha: r.sha,
      date: r.date,
      subject: r.commitSubject,
      file,
      function: d.functionName,
      witness: r.witness,
      witnessLine: witnessLine ? witnessLine.trim() : null,
      guardKind: kind,
      variable,
      guardExit,
      exitLine: exitLine ? exitLine.trim() : null,
      macro,
      isTest,
      derefAfter,
      producerHint,
      addedLines: d.added.length,
      removedLines: d.removed.length,
      patterns,
      obligationHints: [
        ...(kind !== 'missing' ? ['guard-before-deref'] : []),
        ...(guardExit ? ['guard-branch-exits'] : []),
        ...(macro ? ['macro-guard-exits'] : []),
        ...(producerHint ? ['producer-may-null'] : []),
        ...(derefAfter ? ['deref-in-path-local'] : [])
      ],
      coverage,
      diffOk: true
    });
  }
  writeJsonl(path.join(OUT, 'history-obligations.jsonl'), rows);
  const count = (fn) => rows.filter(fn).length;
  const production = rows.filter((r) => r.diffOk && !r.isTest);
  const o3ByKind = {};
  for (const r of production) {
    const k = `${r.guardKind}|${r.coverage.O3}`;
    o3ByKind[k] = (o3ByKind[k] || 0) + 1;
  }
  const o3PotentialMiss = production.filter((r) => ['compound-null', 'nonnull', 'macro'].includes(r.guardKind)).length;
  const summary = {
    generatedAt: new Date().toISOString(),
    total: rows.length,
    diffOk: count((r) => r.diffOk),
    testOnly: count((r) => r.isTest),
    production: production.length,
    guardKinds: rows.reduce((a, r) => { a[r.guardKind] = (a[r.guardKind] || 0) + 1; return a; }, {}),
    guardExit: count((r) => r.guardExit),
    macro: count((r) => r.macro),
    derefAfter: count((r) => r.derefAfter),
    o3ByKind,
    o3PotentialMiss,
    coverage: {
      O1: rows.reduce((a, r) => { a[r.coverage.O1] = (a[r.coverage.O1] || 0) + 1; return a; }, {}),
      O2: rows.reduce((a, r) => { a[r.coverage.O2] = (a[r.coverage.O2] || 0) + 1; return a; }, {}),
      O3: rows.reduce((a, r) => { a[r.coverage.O3] = (a[r.coverage.O3] || 0) + 1; return a; }, {}),
      O4: rows.reduce((a, r) => { a[r.coverage.O4] = (a[r.coverage.O4] || 0) + 1; return a; }, {})
    },
    gaps: [
      'O1 entry-reachable：32 条补丁都不携带入口信息，历史补丁本身不能证明入口可达',
      'O2 producer-may-null：补丁只给 guard witness，不说明 producer 是否可能为空；需要 producer 类型/返回值摘要',
      'O3 guard-before-deref：行级 guard 可覆盖，但 CHECK_/RETURN_IF 宏、throw、多个 guard 需要扩展',
      'O4 deref-in-path-local：多数 diff 不包含 guard 后的 deref，不能从补丁本身证明局部路径',
      'test-only 补丁不能作为生产入口证据，需单独分桶'
    ]
  };
  writeJson(path.join(OUT, 'history-summary.json'), summary);
  const lines = [];
  lines.push('# P3 历史 null-check 补丁对现有义务的覆盖');
  lines.push('');
  lines.push(`生成时间：${summary.generatedAt}`);
  lines.push(`32 条 null-check-added；diffOk=${summary.diffOk}；production=${summary.production}；test-only=${summary.testOnly}。`);
  lines.push('');
  lines.push('## 现有义务覆盖');
  lines.push('');
  lines.push('| 义务 | 覆盖分布 |');
  lines.push('| --- | --- |');
  for (const k of ['O1', 'O2', 'O3', 'O4']) lines.push(`| ${k} | ${JSON.stringify(summary.coverage[k])} |`);
  lines.push('');
  lines.push('## guard 形态');
  lines.push('');
  lines.push(`kind=${JSON.stringify(summary.guardKinds)}；guardExit=${summary.guardExit}；macro=${summary.macro}；derefAfter=${summary.derefAfter}。`);
  lines.push('');
  lines.push(`生产补丁 O3 形态：${JSON.stringify(summary.o3ByKind)}；当前简单正则可能漏 ${summary.o3PotentialMiss} 条（compound/non-null/macro）。`);
  lines.push('');
  lines.push('## 缺什么');
  lines.push('');
  for (const g of summary.gaps) lines.push(`- ${g}`);
  lines.push('');
  lines.push('## 结论');
  lines.push('');
  lines.push('历史补丁能补 O3 的 guard 形态和 O4 的一部分局部路径，但不能单独补 O1/O2；O2 仍必须回到 producer 类型/返回值摘要。');
  ensureDir(path.join(OUT_ROOT, 'report'));
  fs.writeFileSync(path.join(OUT_ROOT, 'report', 'p3-history-obligations.md'), lines.join('\n'), 'utf8');
  process.stdout.write(`P3 history: total=${summary.total} production=${summary.production} testOnly=${summary.testOnly} O3=${JSON.stringify(summary.coverage.O3)} O4=${JSON.stringify(summary.coverage.O4)}\n`);
}

main();
