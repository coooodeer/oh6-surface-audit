'use strict';

/**
 * l1-callgraph.js —— P3 函数级调用图 + entry 可达性。
 *
 * 输入：out/l1/functions.jsonl、out/l2/entries.jsonl、out/gaps/p3-probe.jsonl
 * 输出：out/l1/call-edges.jsonl、out/gaps/p3-reachability.json(l)、out/report/callgraph.md
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');

const L1 = path.join(OUT_ROOT, 'l1', 'functions.jsonl');
const L2E = path.join(OUT_ROOT, 'l2', 'entries.jsonl');
const P3 = path.join(OUT_ROOT, 'gaps', 'p3-probe.jsonl');
const OUT = path.join(OUT_ROOT, 'l1');
const GAPS = path.join(OUT_ROOT, 'gaps');
const REPORT = path.join(OUT_ROOT, 'report', 'callgraph.md');

function idOf(f) { return `${f.repo}|${f.file}:${f.startLine}`; }

function main() {
  ensureDir(OUT); ensureDir(GAPS);
  const fns = readJsonl(L1);
  const byName = new Map();
  const byFile = new Map();
  for (const f of fns) {
    const nk = `${f.repo}\u0000${f.name}`;
    if (!byName.has(nk)) byName.set(nk, []);
    byName.get(nk).push(f);
    const fk = `${f.repo}\u0000${f.file}`;
    if (!byFile.has(fk)) byFile.set(fk, []);
    byFile.get(fk).push(f);
  }
  for (const list of byFile.values()) list.sort((a, b) => a.startLine - b.startLine);

  const edges = [];
  const adj = new Map();
  for (const f of fns) {
    const from = idOf(f);
    const set = new Map();
    for (const c of f.calls || []) {
      const list = byName.get(`${f.repo}\u0000${c.name}`) || [];
      if (!list.length) continue;
      const sameFile = list.filter((x) => x.file === f.file);
      const candidates = sameFile.length ? sameFile : list;
      const resolution = sameFile.length === 1 ? 'same-file' : (list.length === 1 ? 'repo-unique' : 'name-only');
      for (const callee of candidates.slice(0, 8)) {
        const to = idOf(callee);
        if (!set.has(to)) set.set(to, { from, to, name: c.name, line: c.line, resolution, candidateCount: candidates.length });
      }
    }
    adj.set(from, [...set.keys()]);
    edges.push(...set.values());
  }
  writeJsonl(path.join(OUT, 'call-edges.jsonl'), edges);

  const entries = readJsonl(L2E);
  const seeds = new Map(); // id -> {reason,entryKey}
  const unresolvedEntries = [];
  for (const e of entries) {
    const f = e.site && e.site.file;
    if (!f) continue;
    const sym = e.site && e.site.symbol;
    const list = byFile.get(`${e.repo}\u0000${f}`) || [];
    const exact = sym ? list.find((x) => x.name === sym) : null;
    if (exact) seeds.set(idOf(exact), { reason: 'entry-symbol', entryKey: e.entryKey });
    else if (list.length) for (const fn of list) seeds.set(idOf(fn), { reason: 'entry-file-fallback', entryKey: e.entryKey });
    else unresolvedEntries.push(e.entryKey);
  }
  // IDL method name 作为弱种子：没有 stub/proxy 时，用同名实现函数补入口
  for (const e of entries) {
    if (e.channel !== 'idl') continue;
    const method = e.identity && e.identity.method;
    if (!method) continue;
    const list = byName.get(`${e.repo}\u0000${method}`) || [];
    for (const fn of list) {
      if (!seeds.has(idOf(fn))) seeds.set(idOf(fn), { reason: 'idl-method-name', entryKey: e.entryKey });
    }
  }

  const depth = new Map([...seeds.keys()].map((id) => [id, 0]));
  const q = [...seeds.keys()];
  for (let i = 0; i < q.length; i += 1) {
    const cur = q[i];
    const d = depth.get(cur) || 0;
    if (d >= 8) continue;
    for (const nxt of adj.get(cur) || []) {
      if (depth.has(nxt)) continue;
      depth.set(nxt, d + 1);
      q.push(nxt);
    }
  }

  const p3 = readJsonl(P3);
  const rows = [];
  for (const r of p3) {
    const fn = (byFile.get(`${r.repo}\u0000${r.file}`) || []).find((x) => x.name === r.function);
    const id = fn ? idOf(fn) : null;
    rows.push({
      id: r.id,
      repo: r.repo,
      file: r.file,
      line: r.line,
      function: r.function,
      functionId: id,
      status: r.status,
      reachable: id ? depth.has(id) : false,
      depth: id && depth.has(id) ? depth.get(id) : null,
      seed: id ? seeds.get(id) || null : null
    });
  }
  writeJsonl(path.join(GAPS, 'p3-reachability.jsonl'), rows);
  const summary = {
    generatedAt: new Date().toISOString(),
    functions: fns.length,
    callEdges: edges.length,
    entrySeeds: seeds.size,
    entryFiles: new Set(entries.map((e) => `${e.repo}\u0000${e.site && e.site.file}`)).size,
    reachableFunctions: depth.size,
    derefs: rows.length,
    reachableDerefs: rows.filter((r) => r.reachable).length,
    reachablePotentialViolations: rows.filter((r) => r.reachable && r.status === 'potential-violation').length,
    byDepth: rows.filter((r) => r.reachable).reduce((a, r) => { a[r.depth] = (a[r.depth] || 0) + 1; return a; }, {}),
    unresolvedEntries: unresolvedEntries.length
  };
  writeJson(path.join(GAPS, 'p3-reachability.json'), summary);

  const lines = [];
  lines.push('# P3 函数级调用图 / 入口可达性');
  lines.push('');
  lines.push(`生成时间：${summary.generatedAt}`);
  lines.push(`函数 ${summary.functions}；调用边 ${summary.callEdges}；entry 种子 ${summary.entrySeeds}；可达函数 ${summary.reachableFunctions}。`);
  lines.push(`P3 deref ${summary.derefs}；可达 ${summary.reachableDerefs}；其中 potential violation 可达 ${summary.reachablePotentialViolations}。`);
  lines.push('');
  lines.push('| depth | derefs |');
  lines.push('| ---: | ---: |');
  for (const [k, v] of Object.entries(summary.byDepth).sort((a, b) => Number(a[0]) - Number(b[0]))) lines.push(`| ${k} | ${v} |`);
  lines.push('');
  lines.push('## 口径');
  lines.push('');
  lines.push('- 调用边只按函数名解析：同文件唯一 → same-file；全仓唯一 → repo-unique；同名多义 → name-only（最多 8 个候选）。');
  lines.push('- entry 种子优先用 `site.symbol`；没有 symbol 时退回“入口文件内全部函数”，会高估可达性。');
  lines.push('- 没有类型/虚调用/函数指针解析；可达不等于数据流可达。');
  lines.push('');
  ensureDir(path.dirname(REPORT));
  fs.writeFileSync(REPORT, lines.join('\n'), 'utf8');
  process.stdout.write(`callgraph: edges=${summary.callEdges} seeds=${summary.entrySeeds} reachableDerefs=${summary.reachableDerefs}/${summary.derefs} potential=${summary.reachablePotentialViolations}\n`);
}

main();
