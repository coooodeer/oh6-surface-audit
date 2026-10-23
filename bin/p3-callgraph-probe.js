'use strict';

/**
 * p3-callgraph-probe.js —— 测 P3 的入口可达性缺口：
 * 文件级 entry 绑定只有 9/182，看看“直接调用图 + entry 文件里的函数作种子”能覆盖多少。
 *
 * 输出：out/gaps/p3-callgraph.json、out/gaps/p3-callgraph.jsonl
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, readJsonl, writeJson, writeJsonl, ensureDir } = require('../lib/util.js');

const L1 = path.join(OUT_ROOT, 'l1', 'functions.jsonl');
const L2E = path.join(OUT_ROOT, 'l2', 'entries.jsonl');
const P3 = path.join(OUT_ROOT, 'gaps', 'p3-probe.jsonl');
const OUT = path.join(OUT_ROOT, 'gaps');

function idOf(f) { return `${f.repo}|${f.file}:${f.startLine}`; }

function main() {
  ensureDir(OUT);
  const fns = readJsonl(L1);
  const p3 = readJsonl(P3);
  const byId = new Map(fns.map((f) => [idOf(f), f]));
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
  // 直接调用边：同仓、同名；同文件优先
  const adj = new Map();
  for (const f of fns) {
    const from = idOf(f);
    const set = new Set();
    for (const c of f.calls || []) {
      const list = byName.get(`${f.repo}\u0000${c.name}`) || [];
      if (!list.length) continue;
      const sameFile = list.find((x) => x.file === f.file) || list[0];
      set.add(idOf(sameFile));
      if (set.size >= 80) break;
    }
    adj.set(from, [...set]);
  }
  const entries = readJsonl(L2E);
  const entryFiles = new Set(entries.map((e) => `${e.repo}\u0000${e.site && e.site.file}`).filter((x) => !x.endsWith('\u0000undefined')));
  const seeds = [];
  for (const e of entries) {
    const f = e.site && e.site.file;
    if (!f) continue;
    for (const fn of byFile.get(`${e.repo}\u0000${f}`) || []) seeds.push(idOf(fn));
  }
  const seedSet = new Set(seeds);
  const depth = new Map([...seedSet].map((id) => [id, 0]));
  const q = [...seedSet];
  for (let i = 0; i < q.length; i += 1) {
    const cur = q[i];
    const d = depth.get(cur) || 0;
    if (d >= 6) continue;
    for (const nxt of adj.get(cur) || []) {
      if (depth.has(nxt)) continue;
      depth.set(nxt, d + 1);
      q.push(nxt);
    }
  }
  const rows = [];
  for (const r of p3) {
    const fn = byId.get(`${r.repo}|${r.file}:${r.functionRange ? r.functionRange[0] : 0}`)
      || (byFile.get(`${r.repo}\u0000${r.file}`) || []).find((f) => f.name === r.function);
    const id = fn ? idOf(fn) : null;
    rows.push({
      id: r.id,
      repo: r.repo,
      file: r.file,
      line: r.line,
      function: r.function,
      functionId: id,
      entryFile: entryFiles.has(`${r.repo}\u0000${r.file}`),
      reachable: id ? depth.has(id) : false,
      depth: id && depth.has(id) ? depth.get(id) : null,
      status: r.status
    });
  }
  writeJsonl(path.join(OUT, 'p3-callgraph.jsonl'), rows);
  const summary = {
    generatedAt: new Date().toISOString(),
    functions: fns.length,
    entryFiles: entryFiles.size,
    seedFunctions: seedSet.size,
    reachableFunctions: depth.size,
    derefs: rows.length,
    entryFileDerefs: rows.filter((r) => r.entryFile).length,
    reachableDerefs: rows.filter((r) => r.reachable).length,
    reachablePotentialViolations: rows.filter((r) => r.reachable && r.status === 'potential-violation').length,
    byDepth: rows.filter((r) => r.reachable).reduce((a, r) => { a[r.depth] = (a[r.depth] || 0) + 1; return a; }, {}),
    samples: rows.filter((r) => r.reachable).slice(0, 10)
  };
  writeJson(path.join(OUT, 'p3-callgraph.json'), summary);
  process.stdout.write(`p3 callgraph: derefs=${summary.derefs} entryFile=${summary.entryFileDerefs} reachable=${summary.reachableDerefs} reachablePotential=${summary.reachablePotentialViolations}\n`);
}

main();
