'use strict';

/**
 * gt-build.js —— Ground truth v0：
 *   P3：10 个“删 null guard”的函数级 mutant + 5 条历史 null-check seed
 *   P6：10 个正向 action + 10 个加 subscriber permission 的负向对照 + 5 个 restricted 负例
 *
 * 只写 eval/ 目录，不改 OpenHarmony。
 */

const fs = require('fs');
const path = require('path');
const { TOOL_ROOT, SOURCE_ROOT, OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');
const { findFunction, matchBrace } = require('../lib/prover.js');

const EVAL = path.join(OUT_ROOT, '..', 'eval');
const P3DIR = path.join(EVAL, 'p3');
const P6DIR = path.join(EVAL, 'p6');

function readSource(repo, file, cache) {
  const k = `${repo}\u0000${file}`;
  if (cache.has(k)) return cache.get(k);
  let t = null;
  try { t = fs.readFileSync(path.join(SOURCE_ROOT, repo, file), 'utf8'); } catch (_) {}
  cache.set(k, t);
  return t;
}

function buildP3(limit = 10) {
  const fns = readJsonl(path.join(OUT_ROOT, 'l1', 'functions.jsonl'));
  const cache = new Map();
  const cases = [];
  for (const f of fns) {
    if (cases.length >= limit) break;
    const text = readSource(f.repo, f.file, cache);
    if (!text) continue;
    const fn = findFunction(text, f.name);
    if (!fn) continue;
    const body = text.slice(fn.openIdx, fn.closeIdx + 1);
    const lines = body.split('\n');
    let guardLine = -1;
    let varName = null;
    for (let i = 0; i < lines.length; i += 1) {
      const t = lines[i].trim();
      let m = /^if\s*\(\s*!\s*([A-Za-z_]\w*)\s*\)/.exec(t);
      if (!m) m = /^if\s*\(\s*([A-Za-z_]\w*)\s*==\s*nullptr\s*\)/.exec(t);
      if (!m) continue;
      const v = m[1];
      const later = lines.slice(i + 1).some((l) => new RegExp(`\\b${v}\\s*->`).test(l));
      if (!later) continue;
      guardLine = i;
      varName = v;
      break;
    }
    if (guardLine < 0) continue;
    // 找 guard 的块并删除
    let open = -1;
    for (let i = guardLine; i < Math.min(lines.length, guardLine + 3); i += 1) {
      const p = lines[i].indexOf('{');
      if (p >= 0) { open = i; break; }
    }
    if (open < 0) continue;
    const blockText = lines.slice(open).join('\n');
    const blockClose = matchBrace(blockText, blockText.indexOf('{'));
    if (blockClose < 0) continue;
    const blockEnd = open + blockText.slice(0, blockClose + 1).split('\n').length - 1;
    const mutatedLines = lines.slice(0, guardLine).concat(lines.slice(blockEnd + 1));
    const mutatedBody = mutatedLines.join('\n');
    const mutatedText = text.slice(0, fn.openIdx) + mutatedBody + text.slice(fn.closeIdx + 1);
    const id = `P3-GT-${String(cases.length + 1).padStart(2, '0')}`;
    const safe = `${id}_${f.name.replace(/[^\w]/g, '_')}.cpp`;
    const mutantPath = path.join(P3DIR, 'mutants', safe);
    ensureDir(path.dirname(mutantPath));
    fs.writeFileSync(mutantPath, mutatedText, 'utf8');
    cases.push({
      id,
      repo: f.repo,
      file: f.file,
      function: f.name,
      functionRange: [f.startLine, f.endLine],
      guardLineInBody: guardLine + 1,
      variable: varName,
      mutantFile: path.relative(EVAL, mutantPath).split(path.sep).join('/'),
      expected: { original: 'SATISFIED', mutant: 'VIOLATION', violatedObligation: 'guard-before-deref' }
    });
  }
  writeJsonl(path.join(P3DIR, 'cases.jsonl'), cases);
  return cases;
}

function buildP6(limit = 10) {
  const actions = readJsonl(path.join(OUT_ROOT, 'l2', 'actions.jsonl'));
  const eligible = actions.filter((a) => (a.params || []).length
    && a.thirdPartyReachability === 'reachable'
    && !(a.subscriberPermissions || []).length
    && !(a.directedSubscriberUids || []).length);
  const restricted = actions.filter((a) => a.thirdPartyReachability === 'restricted');
  const cases = [];
  for (const a of eligible.slice(0, limit)) {
    cases.push({
      id: `P6-GT-${String(cases.length + 1).padStart(2, '0')}`,
      recordId: a.recordId,
      action: a.action,
      sink: a.sink,
      params: a.params,
      subscriberPermissions: a.subscriberPermissions,
      directedSubscriberUids: a.directedSubscriberUids,
      thirdPartyReachability: a.thirdPartyReachability,
      variant: 'original',
      expected: { receiverThirdParty: true, payloadPresent: true, status: 'candidate' }
    });
    cases.push({
      id: `P6-GT-${String(cases.length + 1).padStart(2, '0')}`,
      recordId: a.recordId,
      action: a.action,
      sink: a.sink,
      params: a.params,
      subscriberPermissions: ['ohos.permission.TEST_ONLY'],
      directedSubscriberUids: [],
      thirdPartyReachability: 'restricted',
      variant: 'control-subscriber-permission',
      expected: { receiverThirdParty: false, payloadPresent: true, status: 'rejected' }
    });
    if (cases.length >= limit * 2) break;
  }
  for (const a of restricted.slice(0, 5)) {
    cases.push({
      id: `P6-GT-${String(cases.length + 1).padStart(2, '0')}`,
      recordId: a.recordId,
      action: a.action,
      sink: a.sink,
      params: a.params,
      subscriberPermissions: a.subscriberPermissions,
      directedSubscriberUids: a.directedSubscriberUids,
      thirdPartyReachability: a.thirdPartyReachability,
      variant: 'negative-restricted',
      expected: { receiverThirdParty: false, payloadPresent: (a.params || []).length > 0, status: 'rejected' }
    });
  }
  writeJsonl(path.join(P6DIR, 'cases.jsonl'), cases);
  return cases;
}

function buildHistorical() {
  const hist = readJsonl(path.join(TOOL_ROOT, 'data', 'facts', 'history-invariants.jsonl'));
  const nulls = hist.filter((r) => r.family === 'null-check-added').slice(0, 5);
  writeJsonl(path.join(P3DIR, 'historical.jsonl'), nulls.map((r) => ({
    id: r.id,
    repo: r.repo,
    file: r.file,
    sha: r.sha,
    date: r.date,
    subject: r.commitSubject,
    family: r.family,
    witness: r.witness,
    evidence: r.evidence
  })));
  return nulls.length;
}

function main() {
  ensureDir(P3DIR); ensureDir(P6DIR);
  const p3 = buildP3(10);
  const p6 = buildP6(10);
  const hist = buildHistorical();
  const summary = {
    generatedAt: new Date().toISOString(),
    p3: { cases: p3.length, historical: hist },
    p6: { cases: p6.length, originals: p6.filter((c) => c.variant === 'original').length, controls: p6.filter((c) => c.variant === 'control-subscriber-permission').length, restricted: p6.filter((c) => c.variant === 'negative-restricted').length }
  };
  writeJson(path.join(EVAL, 'summary.json'), summary);
  process.stdout.write(`gt: P3 ${p3.length} mutants + ${hist} historical; P6 ${p6.length} cases ${JSON.stringify(summary.p6)}\n`);
}

main();
