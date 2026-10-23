'use strict';

/**
 * l4b-evidence.js —— 预生成 L4b 语义判定证据包（不调用模型）。
 *
 * P6：对第三方可达且有 payload 的 action，打包 payload/source/matches，问 sensitive/publicEquivalent。
 * P3：对 reachable potential，打包函数/生产者/guard，问 producerMayNull/guardBeforeDeref。
 *
 * 输出：out/l4b/{p6,p3}-evidence.jsonl、out/l4b/summary.json
 */

const fs = require('fs');
const path = require('path');
const { SOURCE_ROOT, OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');

const OUT = path.join(OUT_ROOT, 'l4b');

function stripPrefix(f) { return String(f || '').replace(/^OpenHarmony\//, ''); }

function main() {
  ensureDir(OUT);
  const actions = readJsonl(path.join(OUT_ROOT, 'l2', 'actions.jsonl'));
  const payloads = new Map(readJsonl(path.join(OUT_ROOT, 'l2', 'p6-payload.jsonl')).map((x) => [String(x.recordId), x]));
  const index = readJsonl(path.join(OUT_ROOT, 'l2', 'p6-index.jsonl'));
  const idxByRecord = new Map();
  for (const r of index) {
    if (!idxByRecord.has(String(r.recordId))) idxByRecord.set(String(r.recordId), []);
    idxByRecord.get(String(r.recordId)).push(r);
  }
  const fns = readJsonl(path.join(OUT_ROOT, 'l1', 'functions.jsonl'));
  const fnByFile = new Map();
  for (const f of fns) {
    const k = `${f.repo}\u0000${f.file}`;
    if (!fnByFile.has(k)) fnByFile.set(k, []);
    fnByFile.get(k).push(f);
  }
  const cache = new Map();
  function sourceOf(repo, file) {
    const k = `${repo}\u0000${file}`;
    if (cache.has(k)) return cache.get(k);
    let lines = null;
    try { lines = fs.readFileSync(path.join(SOURCE_ROOT, repo, file), 'utf8').split(/\r?\n/); } catch (_) {}
    cache.set(k, lines);
    return lines;
  }

  const p6 = [];
  for (const a of actions) {
    if (a.thirdPartyReachability !== 'reachable') continue;
    if ((a.subscriberPermissions || []).length || (a.directedSubscriberUids || []).length) continue;
    const p = payloads.get(String(a.recordId));
    if (!p || !(p.payloadCandidates || []).length) continue;
    const items = idxByRecord.get(String(a.recordId)) || [];
    const sensitivityUnknown = items.filter((x) => x.sensitivity === 'unknown').length;
    const publicUnknown = items.filter((x) => !x.publicZeroPermissionMatch).length;
    if (!sensitivityUnknown && !publicUnknown) continue;
    const file = stripPrefix(a.sink.file);
    const repo = file.split('/').slice(0, 3).join('/');
    const rel = file.slice(repo.length + 1);
    const lines = sourceOf(repo, rel);
    let snippet = '';
    let fnName = a.sink.function || null;
    if (lines) {
      const list = fnByFile.get(`${repo}\u0000${rel}`) || [];
      const fn = list.find((f) => f.startLine <= a.sink.line && f.endLine >= a.sink.line);
      if (fn) {
        fnName = fn.name;
        snippet = lines.slice(Math.max(0, fn.startLine - 1), Math.min(lines.length, fn.endLine)).join('\n').slice(0, 12000);
      } else {
        snippet = lines.slice(Math.max(0, a.sink.line - 40), Math.min(lines.length, a.sink.line + 40)).join('\n').slice(0, 12000);
      }
    }
    p6.push({
      id: `L4B-P6-${a.recordId}`,
      kind: 'P6',
      action: a.action,
      recordId: a.recordId,
      sink: a.sink,
      function: fnName,
      subscriberPermissions: a.subscriberPermissions,
      directedSubscriberUids: a.directedSubscriberUids,
      thirdPartyReachability: a.thirdPartyReachability,
      payloads: p.payloadCandidates,
      payloadNames: p.payloadNames,
      matches: items.map((x) => ({ payload: x.payload, sensitivity: x.sensitivity, restricted: x.sensitivityMatches.slice(0, 3), design: x.designMatches.slice(0, 3), publicZero: x.publicZeroPermissionMatch })),
      source: { file: rel, line: a.sink.line, snippet },
      ask: { sensitive: 'yes|no|unknown', publicEquivalent: 'yes|no|unknown' }
    });
  }
  writeJsonl(path.join(OUT, 'p6-evidence.jsonl'), p6);

  const p3Rows = readJsonl(path.join(OUT_ROOT, 'gaps', 'p3-reachability.jsonl'));
  const p3Probe = readJsonl(path.join(OUT_ROOT, 'gaps', 'p3-probe.jsonl'));
  const byId = new Map(p3Probe.map((r) => [r.id, r]));
  const producersPath = path.join(OUT_ROOT, 'l1', 'producers-ast.jsonl');
  const producers = readJsonl(fs.existsSync(producersPath) ? producersPath : path.join(OUT_ROOT, 'l1', 'producers.jsonl'));
  const prodByKey = new Map(producers.map((r) => [`${r.repo}\u0000${r.file}\u0000${r.name}`, r]));
  const p3 = [];
  for (const r of p3Rows) {
    if (!r.reachable || r.status !== 'potential-violation') continue;
    const p = byId.get(r.id);
    if (!p) continue;
    const lines = sourceOf(p.repo, p.file);
    let fnSnippet = '';
    if (lines && p.functionRange) {
      fnSnippet = lines.slice(Math.max(0, p.functionRange[0] - 1), Math.min(lines.length, p.functionRange[1])).join('\n').slice(0, 12000);
    }
    let producer = null;
    if (p.producerFunction) {
      const plines = sourceOf(p.repo, p.producerFunction.file);
      const prod = prodByKey.get(`${p.repo}\u0000${p.producerFunction.file}\u0000${p.producerFunction.name}`) || null;
      producer = {
        name: p.producerFunction.name,
        file: p.producerFunction.file,
        startLine: p.producerFunction.startLine,
        returnType: prod ? prod.returnType : null,
        pointerLike: prod ? prod.pointerLike : null,
        snippet: plines ? plines.slice(Math.max(0, p.producerFunction.startLine - 5), Math.min(plines.length, p.producerFunction.startLine + 50)).join('\n').slice(0, 6000) : ''
      };
    }
    p3.push({
      id: `L4B-P3-${r.id}`,
      kind: 'P3',
      repo: p.repo,
      file: p.file,
      line: p.line,
      function: p.function,
      text: p.text,
      producerFunction: p.producerFunction,
      producer,
      guardBefore: p.guardBefore,
      producerMayNull: p.producerMayNull,
      typeKnown: p.typeKnown,
      source: { file: p.file, functionRange: p.functionRange, snippet: fnSnippet },
      ask: { producerMayNull: 'yes|no|unknown', guardBeforeDeref: 'yes|no|unknown' }
    });
  }
  writeJsonl(path.join(OUT, 'p3-evidence.jsonl'), p3);

  const summary = {
    generatedAt: new Date().toISOString(),
    p6: { packs: p6.length, sensitivityUnknown: p6.filter((x) => x.matches.some((m) => m.sensitivity === 'unknown')).length, publicUnknown: p6.filter((x) => x.matches.some((m) => !m.publicZero)).length },
    p3: { packs: p3.length, withProducer: p3.filter((x) => x.producer).length, typeKnown: p3.filter((x) => x.producer && x.producer.returnType).length }
  };
  writeJson(path.join(OUT, 'summary.json'), summary);
  process.stdout.write(`l4b evidence: P6 packs=${summary.p6.packs}; P3 packs=${summary.p3.packs} (typeKnown ${summary.p3.typeKnown})\n`);
}

main();
