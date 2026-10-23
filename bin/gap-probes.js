'use strict';

/**
 * gap-probes.js —— 在 L1/L2 已补齐的数据上，测 P3/P6 的真实缺口。
 *
 * 输出：
 *   out/gaps/p3-probe.jsonl
 *   out/gaps/p6-probe.jsonl
 *   out/gaps/summary.json
 *   out/report/gaps.md
 *
 * 只做确定性探针，不调用模型。
 */

const fs = require('fs');
const path = require('path');
const { TOOL_ROOT, SOURCE_ROOT, OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');

const L1 = path.join(OUT_ROOT, 'l1', 'functions.jsonl');
const L2E = path.join(OUT_ROOT, 'l2', 'entries.jsonl');
const L2A = path.join(OUT_ROOT, 'l2', 'actions.jsonl');
const OUT = path.join(OUT_ROOT, 'gaps');
const REPORT = path.join(OUT_ROOT, 'report', 'gaps.md');

const REPOS = new Set(['foundation/communication/dsoftbus', 'base/account/os_account']);

function tokenize(s) {
  return String(s || '').toLowerCase().replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^a-z0-9_]+/).flatMap((t) => t.split('_')).filter((t) => t.length >= 3);
}
function lineOfIndex(lines, idx) { let n = 1; for (let i = 0; i < idx; i += 1) if (lines[i] === '\n') n += 1; return n; }

function main() {
  ensureDir(OUT);
  const fns = readJsonl(L1);
  const byFile = new Map();
  for (const f of fns) {
    const k = `${f.repo}\u0000${f.file}`;
    if (!byFile.has(k)) byFile.set(k, []);
    byFile.get(k).push(f);
  }
  for (const list of byFile.values()) list.sort((a, b) => a.startLine - b.startLine);
  const fileRoot = new Map();
  for (const f of fns) if (!fileRoot.has(f.file)) fileRoot.set(f.file, f.repo);

  const entries = readJsonl(L2E);
  const fileEntry = new Map();
  for (const e of entries) {
    const f = e.site && e.site.file;
    if (!f) continue;
    const k = `${e.repo}\u0000${f}`;
    fileEntry.set(k, (fileEntry.get(k) || 0) + 1);
  }

  const bodyCache = new Map();
  function bodyOf(repo, file) {
    const k = `${repo}\u0000${file}`;
    if (bodyCache.has(k)) return bodyCache.get(k);
    let lines = null;
    try { lines = fs.readFileSync(path.join(SOURCE_ROOT, repo, file), 'utf8').split(/\r?\n/); } catch (_) {}
    bodyCache.set(k, lines);
    return lines;
  }
  function enclosing(repo, file, line) {
    const list = byFile.get(`${repo}\u0000${file}`) || [];
    let best = null;
    for (const f of list) {
      if (f.startLine > line) break;
      if (line <= f.endLine && (!best || f.endLine - f.startLine < best.endLine - best.startLine)) best = f;
    }
    return best;
  }
  function producerName(p) {
    const s = String(p || '');
    const m = /([A-Za-z_]\w*)\s*(?:\(|->|\.)/.exec(s);
    return m ? m[1] : null;
  }
  function findProducer(repo, name, file) {
    const list = fns.filter((f) => f.repo === repo && f.name === name);
    if (!list.length) return null;
    return list.find((f) => f.file === file) || list[0];
  }

  // ---------------------------------------------------------------- P3

  const derefs = readJsonl(path.join(TOOL_ROOT, 'index', 'derefs.jsonl'));
  const p3 = [];
  for (const d of derefs) {
    const repo = fileRoot.get(d.file);
    if (!repo || !REPOS.has(repo)) continue;
    const fn = enclosing(repo, d.file, d.line);
    if (!fn) continue;
    const entryCount = fileEntry.get(`${repo}\u0000${d.file}`) || 0;
    const pname = producerName(d.producer);
    const producer = pname ? findProducer(repo, pname, d.file) : null;
    const lines = bodyOf(repo, d.file);
    let guard = false;
    if (lines && pname) {
      const re = new RegExp(`(?:\\b${pname}\\b\\s*(?:==|!=)\\s*(?:nullptr|NULL)|!\\s*${pname}\\b|if\\s*\\(\\s*${pname}\\s*\\))`);
      for (let i = fn.startLine - 1; i < Math.min(d.line - 1, lines.length); i += 1) {
        if (re.test(lines[i] || '')) { guard = true; break; }
      }
    }
    let producerMayNull = null;
    if (producer) {
      const plines = bodyOf(repo, producer.file);
      if (plines) producerMayNull = /return\s+(nullptr|NULL)\b|new\s*\(\s*std::nothrow|malloc\s*\(|calloc\s*\(|\.find\s*\(/.test(plines.slice(producer.startLine - 1, producer.endLine).join('\n'));
    }
    const status = !entryCount ? 'unbound'
      : !producer ? 'producer-unresolved'
        : guard ? 'guarded'
          : producerMayNull ? 'potential-violation'
            : 'producer-not-null';
    p3.push({
      id: `P3-${repo.split('/').pop()}-${d.file}:${d.line}`,
      repo,
      file: d.file,
      line: d.line,
      kind: d.kind,
      text: d.text,
      function: fn.name,
      functionRange: [fn.startLine, fn.endLine],
      entryCount,
      producer: pname,
      producerFunction: producer ? { name: producer.name, file: producer.file, startLine: producer.startLine } : null,
      producerMayNull,
      guardBefore: guard,
      signature: fn.signature,
      typeKnown: !!(fn.signature && /[*]|shared_ptr|weak_ptr|unique_ptr/.test(fn.signature)),
      status
    });
  }
  writeJsonl(path.join(OUT, 'p3-probe.jsonl'), p3);

  // ---------------------------------------------------------------- P6

  const restricted = readJsonl(path.join(TOOL_ROOT, 'data', 'facts', 'restricted-apis.jsonl'));
  const publics = readJsonl(path.join(TOOL_ROOT, 'data', 'facts', 'public-apis.jsonl'));
  const design = readJsonl(path.join(TOOL_ROOT, 'data', 'facts', 'design-specs.jsonl'));
  const restrictedNames = new Set();
  for (const r of restricted) for (const t of tokenize(`${r.name} ${r.qualifiedName}`)) restrictedNames.add(t);
  const publicNames = new Set();
  for (const r of publics) for (const t of tokenize(`${r.apiName} ${r.module}`)) publicNames.add(t);
  const designNames = new Set();
  for (const r of design) for (const t of tokenize(`${(r.entity && r.entity.name) || ''} ${r.statement || ''}`)) designNames.add(t);

  const actions = readJsonl(L2A);
  const p6 = [];
  for (const a of actions) {
    const params = a.params || [];
    const payloadNames = params.map((p) => (typeof p === 'string' ? p : p && p.name)).filter(Boolean);
    const tokens = new Set(payloadNames.flatMap(tokenize));
    const restrictedHit = [...tokens].filter((t) => restrictedNames.has(t));
    const publicHit = [...tokens].filter((t) => publicNames.has(t));
    const designHit = [...tokens].filter((t) => designNames.has(t));
    const receiverThirdParty = a.thirdPartyReachability === 'reachable'
      && !(a.subscriberPermissions || []).length
      && !(a.directedSubscriberUids || []).length;
    const sensitive = restrictedHit.length || designHit.length ? 'sensitive'
      : payloadNames.length ? 'unknown' : 'no-payload';
    const publicEquivalent = publicHit.length ? 'possible' : 'unknown';
    p6.push({
      id: `P6-${a.recordId}`,
      recordId: a.recordId,
      action: a.action,
      eventClass: a.eventClass,
      language: a.language,
      sink: a.sink,
      payloadNames,
      params,
      subscriberPermissions: a.subscriberPermissions,
      directedSubscriberUids: a.directedSubscriberUids,
      thirdPartyReachability: a.thirdPartyReachability,
      analysisStatus: a.analysisStatus,
      receiverThirdParty,
      sensitive,
      restrictedHit,
      designHit,
      publicEquivalent,
      publicHit,
      status: !payloadNames.length ? 'no-payload'
        : !receiverThirdParty ? 'receiver-restricted'
          : sensitive === 'unknown' ? 'needs-l4b-sensitivity'
            : publicEquivalent === 'unknown' ? 'needs-l4b-public-equivalence'
              : 'claim-candidate'
    });
  }
  writeJsonl(path.join(OUT, 'p6-probe.jsonl'), p6);

  const count = (rows, field) => rows.reduce((a, r) => { a[r[field]] = (a[r[field]] || 0) + 1; return a; }, {});
  const summary = {
    generatedAt: new Date().toISOString(),
    scope: [...REPOS],
    l1: { functions: fns.length, files: byFile.size },
    l2: { entries: entries.length, filesWithEntries: fileEntry.size, actions: actions.length },
    p3: {
      total: p3.length,
      status: count(p3, 'status'),
      entryBound: p3.filter((r) => r.entryCount > 0).length,
      producerResolved: p3.filter((r) => r.producerFunction).length,
      guarded: p3.filter((r) => r.guardBefore).length,
      potentialViolations: p3.filter((r) => r.status === 'potential-violation').length,
      typeKnown: p3.filter((r) => r.typeKnown).length
    },
    p6: {
      total: p6.length,
      status: count(p6, 'status'),
      withPayload: p6.filter((r) => r.payloadNames.length).length,
      receiverThirdParty: p6.filter((r) => r.receiverThirdParty).length,
      sensitive: p6.filter((r) => r.sensitive === 'sensitive').length,
      sensitivityUnknown: p6.filter((r) => r.sensitive === 'unknown').length,
      publicPossible: p6.filter((r) => r.publicEquivalent === 'possible').length,
      publicUnknown: p6.filter((r) => r.publicEquivalent === 'unknown').length,
      languages: count(p6, 'language')
    }
  };
  writeJson(path.join(OUT, 'summary.json'), summary);

  const lines = [];
  lines.push('# L1–L4 / P3+P6 缺口探针');
  lines.push('');
  lines.push(`生成时间：${summary.generatedAt}`);
  lines.push(`范围：${summary.scope.join(' + ')}`);
  lines.push('');
  lines.push('## L1/L2 基线');
  lines.push('');
  lines.push(`L1：${summary.l1.functions} 函数 / ${summary.l1.files} 文件；L2：${summary.l2.entries} 入口 / ${summary.l2.filesWithEntries} 文件 / ${summary.l2.actions} 个 P6 action。`);
  lines.push('');
  lines.push('## P3');
  lines.push('');
  lines.push(`deref ${summary.p3.total}；entry-bound ${summary.p3.entryBound}；producer 解析 ${summary.p3.producerResolved}；已有 guard ${summary.p3.guarded}；potential violation ${summary.p3.potentialViolations}；签名含指针/智能指针 ${summary.p3.typeKnown}。`);
  lines.push('');
  lines.push('| status | count |');
  lines.push('| --- | ---: |');
  for (const [k, v] of Object.entries(summary.p3.status).sort()) lines.push(`| ${k} | ${v} |`);
  lines.push('');
  lines.push('## P6');
  lines.push('');
  lines.push(`action ${summary.p6.total}；有 payload ${summary.p6.withPayload}；第三方可接收 ${summary.p6.receiverThirdParty}；sensitive ${summary.p6.sensitive}；sensitivity unknown ${summary.p6.sensitivityUnknown}；public possible ${summary.p6.publicPossible}；public unknown ${summary.p6.publicUnknown}。`);
  lines.push('');
  lines.push('| status | count |');
  lines.push('| --- | ---: |');
  for (const [k, v] of Object.entries(summary.p6.status).sort()) lines.push(`| ${k} | ${v} |`);
  lines.push('');
  lines.push('## 判定');
  lines.push('');
  lines.push('- P3 的 `potential-violation` 只是“producer 可能为空且当前函数没有可见 guard”，还不是 claim；缺路径/entry 闭合和 producer 可空性的更强证据。');
  lines.push('- P6 的 `needs-l4b-*` 是必须交给 L4b 的语义义务；`public possible` 只是词法命中，不能直接判“存在公开 API 等价”。');
  lines.push('- 这些数字决定 L3/L4 的义务模板和 L4b 调用量；不是漏洞结论。');
  lines.push('');
  ensureDir(path.dirname(REPORT));
  fs.writeFileSync(REPORT, lines.join('\n'), 'utf8');
  process.stdout.write(`gaps: P3=${p3.length} (potential ${summary.p3.potentialViolations}) P6=${p6.length} (thirdParty ${summary.p6.receiverThirdParty}, l4b unknown ${summary.p6.sensitivityUnknown + summary.p6.publicUnknown})\n`);
}

main();
