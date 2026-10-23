'use strict';

/**
 * l2-ledger.js —— L2 的 P3/P6 最小入口台账。
 *
 * 输入：
 *   - out/surface/dsoftbus.jsonl（已有 dsoftbus 台账）
 *   - 对 CES 重新跑 surface.enumerateRepo
 *   - broadcast_point_evidence.jsonl + broadcast-actions.jsonl
 * 输出：
 *   out/l2/entries.jsonl
 *   out/l2/actions.jsonl
 *   out/l2/summary.json
 */

const fs = require('fs');
const path = require('path');
const { TOOL_ROOT, OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');
const { loadFunctions } = require('../lib/index.js');
const { enumerateRepo, summarize } = require('../lib/surface.js');

const REPOS = [
  'foundation/communication/dsoftbus',
  'base/account/os_account'
];
const OUT = path.join(OUT_ROOT, 'l2');
const MINER = path.resolve(OUT_ROOT, '..', '..', 'oh6-framework-want-leak-miner');

function main() {
  ensureDir(OUT);
  const fns = loadFunctions(new Set(REPOS));
  const all = [];
  const stats = {};
  for (const repo of REPOS) {
    let rows;
    const cached = path.join(OUT_ROOT, 'surface', `${repo.split('/').pop()}.jsonl`);
    if (fs.existsSync(cached)) rows = readJsonl(cached);
    else rows = enumerateRepo(repo, fns);
    for (const r of rows) all.push({ ...r, repo });
    stats[repo] = summarize(rows, repo).totals;
  }
  // 去重（同一 entryKey 合并 provenance）
  const byKey = new Map();
  for (const r of all) {
    const k = r.entryKey || `${r.repo}|${r.channel}|${r.site && r.site.file}|${r.site && r.site.line}|${r.identity && (r.identity.code || r.identity.method || r.identity.saId || r.identity.module || r.identity.function)}`;
    if (!byKey.has(k)) byKey.set(k, { ...r, entryKey: k, provenance: r.provenance || [] });
    else {
      const e = byKey.get(k);
      e.provenance = [...new Set([...(e.provenance || []), ...(r.provenance || [])])];
      if (!e.implLink || e.implLink.status === 'unresolved') e.implLink = r.implLink || e.implLink;
    }
  }
  const entries = [...byKey.values()];
  writeJsonl(path.join(OUT, 'entries.jsonl'), entries);

  // P6 action ledger：evidence record_id ↔ action recordId
  const ev = readJsonl(path.join(MINER, 'result', 'providers', 'broadcast', 'broadcast_point_evidence.jsonl'));
  const actions = new Map(readJsonl(path.join(TOOL_ROOT, 'data', 'facts', 'broadcast-actions.jsonl')).map((a) => [a.recordId, a]));
  const actionRows = [];
  for (const e of ev) {
    const sinkFile = (e.sink && e.sink.file) || '';
    if (!sinkFile.includes('base/account/os_account')) continue;
    const a = actions.get(e.record_id);
    if (!a) continue;
    actionRows.push({
      recordId: e.record_id,
      action: a.action,
      actionExpr: a.actionExpr,
      eventClass: a.eventClass,
      language: a.language,
      sink: e.sink || null,
      sourceLocations: e.source_locations || [],
      guards: e.guards || [],
      params: a.params || [],
      subscriberPermissions: a.subscriberPermissions || [],
      directedSubscriberUids: a.directedSubscriberUids || [],
      thirdPartyReachability: a.thirdPartyReachability || null,
      analysisStatus: e.analysis_status || null,
      confidence: e.confidence || null
    });
  }
  writeJsonl(path.join(OUT, 'actions.jsonl'), actionRows);

  // file → entries
  const fileEntries = new Map();
  for (const e of entries) {
    const f = e.site && e.site.file;
    if (!f) continue;
    const k = `${e.repo}\u0000${f}`;
    if (!fileEntries.has(k)) fileEntries.set(k, []);
    fileEntries.get(k).push(e.entryKey);
  }
  const summary = {
    generatedAt: new Date().toISOString(),
    repos: stats,
    entries: entries.length,
    filesWithEntries: fileEntries.size,
    channels: entries.reduce((a, e) => { a[e.channel] = (a[e.channel] || 0) + 1; return a; }, {}),
    actions: actionRows.length,
    actionLanguages: actionRows.reduce((a, r) => { a[r.language] = (a[r.language] || 0) + 1; return a; }, {}),
    actionsWithPayload: actionRows.filter((r) => (r.params || []).length > 0).length,
    actionsNoSubscriberPermission: actionRows.filter((r) => !(r.subscriberPermissions || []).length).length,
    actionsNoDirectedUid: actionRows.filter((r) => !(r.directedSubscriberUids || []).length).length,
    actionsThirdParty: actionRows.filter((r) => r.thirdPartyReachability === 'reachable').length
  };
  writeJson(path.join(OUT, 'summary.json'), summary);
  process.stdout.write(`l2: entries=${summary.entries}, filesWithEntries=${summary.filesWithEntries}, actions=${summary.actions}, payload=${summary.actionsWithPayload}\n`);
}

main();
