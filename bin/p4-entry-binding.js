'use strict';

/**
 * p4-entry-binding.js —— 对 P4 R1 候选做一次静态 O1 入口绑定核查。
 *
 * 只回答一个问题：候选点所在函数，是否存在从 IPC server handler / stub 出发的
 * 反向调用链。存在 ⇒ 可补 O1；不存在 ⇒ 保持 entry-binding-suspect，不把 driver
 * 修复当成 T1 依据。
 *
 * 产物：out/p4/entry-binding.json + out/report/p4-entry-binding.md
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, SOURCE_ROOT, TOOL_ROOT, ensureDir, readJsonl, writeJson } = require('../lib/util.js');
const { loadL1 } = require('../lib/l1.js');
const { R1_REPOS, isR1 } = require('../lib/in-scope.js');

const CANDIDATES = path.join(OUT_ROOT, 'p4', 'candidates.jsonl');
const ENTRIES = path.join(TOOL_ROOT, '..', 'oh6-vuln-agent', 'result', 'latest', 'contracts', 'entries.jsonl');

function stripPrefix(f) { return String(f || '').replace(/^OpenHarmony\//, ''); }
function repoOf(file) { return String(file || '').split('/').slice(0, 3).join('/'); }
function relOf(repo, file) { return file.startsWith(`${repo}/`) ? file.slice(repo.length + 1) : file; }
function isServerish(file) { return /(stub|server|service|ipc|sa_profile|dispatcher)/i.test(String(file || '')); }

function isIpcHandler(fn) {
  const file = String(fn.file || '');
  const name = String(fn.name || '');
  if (/softbus_server_stub\.(cpp|c)$/.test(file) && (/Inner$/.test(name) || name === 'OnRemoteRequest')) return true;
  if (/(account_mgr_service|os_account_manager_service|account_iam_service|domain_account_manager_service)\.cpp$/.test(file)) return true;
  if (/(_stub\.cpp|_stub\.c)$/.test(file) && /(OnRemoteRequest|Inner$)/.test(name)) return true;
  return false;
}

function entryMethod(entry) {
  const spec = String((entry && entry.specKey) || '');
  const m = /::([A-Za-z0-9_]+)$/.exec(spec);
  if (!m) return null;
  return m[1].replace(/^(CLIENT|SERVER)_/, '').replace(/^COMMAND_/, '').toLowerCase();
}

function entryMatchesHandler(entry, handler) {
  const method = entryMethod(entry);
  if (!method) return false;
  const name = String(handler.name || '').toLowerCase();
  return name.includes(method) || name.includes(method.replace(/_/g, ''));
}

function findIpcPath(reverse, startId, maxDepth = 5) {
  if (!startId) return null;
  const queue = [{ id: startId, depth: 0, path: [] }];
  const seen = new Set([startId]);
  while (queue.length) {
    const cur = queue.shift();
    if (cur.depth >= maxDepth) continue;
    for (const caller of reverse.get(cur.id) || []) {
      if (seen.has(caller.functionId)) continue;
      const nextPath = [...cur.path, `${caller.file}:${caller.startLine}:${caller.name}`];
      if (isIpcHandler(caller)) return { handler: caller, path: nextPath, depth: cur.depth + 1 };
      seen.add(caller.functionId);
      queue.push({ id: caller.functionId, depth: cur.depth + 1, path: nextPath });
    }
  }
  return null;
}

function buildReverse(l1, repos) {
  const byName = new Map();
  for (const repo of repos) {
    for (const fn of l1.functionsOfRepo(repo)) {
      if (!byName.has(fn.name)) byName.set(fn.name, []);
      byName.get(fn.name).push(fn);
    }
  }
  const reverse = new Map();
  for (const repo of repos) {
    for (const fn of l1.functionsOfRepo(repo)) {
      for (const call of fn.calls || []) {
        for (const target of byName.get(call.name) || []) {
          if (target.repo !== fn.repo) continue;
          if (!reverse.has(target.functionId)) reverse.set(target.functionId, []);
          reverse.get(target.functionId).push(fn);
        }
      }
    }
  }
  return reverse;
}

function callersOf(reverse, fnId, depth = 4) {
  const out = [];
  const seen = new Set([fnId]);
  let frontier = [fnId];
  for (let d = 0; d < depth && frontier.length; d += 1) {
    const next = [];
    for (const id of frontier) {
      for (const caller of reverse.get(id) || []) {
        if (seen.has(caller.functionId)) continue;
        seen.add(caller.functionId);
        out.push({ ...caller, depth: d + 1 });
        next.push(caller.functionId);
      }
    }
    frontier = next;
  }
  return out;
}

function main() {
  ensureDir(path.join(OUT_ROOT, 'p4'));
  const l1 = loadL1();
  const candidates = readJsonl(CANDIDATES).filter((c) => isR1(c.repo));
  const entryById = new Map(readJsonl(ENTRIES).map((e) => [e.id, e]));
  const reverse = buildReverse(l1, R1_REPOS);
  const rows = [];
  for (const c of candidates) {
    const file = stripPrefix(c.file);
    const repo = c.repo || repoOf(file);
    const rel = relOf(repo, file);
    const fullEntry = entryById.get(c.entry && c.entry.id) || c.entry || {};
    const fn = (l1.functionsOfFile(repo, rel) || []).find((f) => f.startLine <= c.line && f.endLine >= c.line) || null;
    const callers = fn ? callersOf(reverse, fn.functionId, 5) : [];
    const serverCallers = callers.filter((x) => isIpcHandler(x));
    const ipcPath = fn ? findIpcPath(reverse, fn.functionId, 5) : null;
    const matched = ipcPath && entryMatchesHandler(fullEntry, ipcPath.handler);
    let status = 'unproven';
    let reason = 'no-ipc-call-path';
    if (!fn) reason = 'candidate-function-not-found';
    else if (matched) { status = 'proven'; reason = 'entry-matched-ipc-call-path'; }
    else if (ipcPath) { status = 'suspect'; reason = 'ipc-path-but-entry-not-matched'; }
    else if (isServerish(rel)) { status = 'suspect'; reason = 'candidate-file-serverish-but-no-call-path'; }
    rows.push({
      candidateId: c.candidateId,
      repo,
      file: rel,
      line: c.line,
      function: fn ? fn.name : null,
      functionId: fn ? fn.functionId : null,
      entryId: fullEntry.id || (c.entry && c.entry.id),
      entryKind: fullEntry.kind || (c.entry && c.entry.kind),
      entrySpecKey: fullEntry.specKey || null,
      entryBinding: c.entryBinding || null,
      status,
      reason,
      ipcPath: ipcPath ? ipcPath.path : [],
      ipcHandler: ipcPath ? `${ipcPath.handler.file}:${ipcPath.handler.startLine}:${ipcPath.handler.name}` : null,
      entryMatched: !!matched,
      directCallers: callers.filter((x) => x.depth === 1).map((x) => `${x.file}:${x.startLine}:${x.name}`),
      serverCallers: serverCallers.map((x) => `${x.file}:${x.startLine}:${x.name}`),
      reverseDepth: callers.length ? Math.max(...callers.map((x) => x.depth)) : 0,
      candidateOracle: c.oracle || null
    });
  }
  const summary = {
    scope: 'R1',
    repos: R1_REPOS,
    candidates: rows.length,
    byStatus: rows.reduce((a, r) => { a[r.status] = (a[r.status] || 0) + 1; return a; }, {}),
    byReason: rows.reduce((a, r) => { a[r.reason] = (a[r.reason] || 0) + 1; return a; }, {}),
    confirmedOracleUnprovenBinding: rows.filter((r) => r.candidateOracle && r.candidateOracle.state === 'confirmed' && r.status !== 'proven').map((r) => r.candidateId),
    rows
  };
  const out = path.join(OUT_ROOT, 'p4', 'entry-binding.json');
  writeJson(out, summary);
  const md = [
    '# P4 R1 入口绑定静态核查',
    '',
    `- 候选：${summary.candidates}`,
    `- 状态：${JSON.stringify(summary.byStatus)}`,
    `- 原因：${JSON.stringify(summary.byReason)}`,
    '',
    '| candidate | function | status | reason | direct callers | server callers |',
    '| --- | --- | --- | --- | --- | --- |'
  ];
  for (const r of rows) md.push(`| ${r.candidateId} | ${r.function || '-'} | ${r.status} | ${r.reason} | ${r.directCallers.length} | ${r.serverCallers.length} |`);
  md.push('', '口径：只有 server/stub 反向调用链才算 O1 可补；`no-ipc-call-path` 保持 entry-binding-suspect，不因 driver/oracle 修复自动升 T1。', '');
  ensureDir(path.join(OUT_ROOT, 'report'));
  fs.writeFileSync(path.join(OUT_ROOT, 'report', 'p4-entry-binding.md'), md.join('\n'), 'utf8');
  process.stdout.write(`P4 entry-binding: candidates=${rows.length} status=${JSON.stringify(summary.byStatus)} reason=${JSON.stringify(summary.byReason)}\n`);
  return summary;
}

if (require.main === module) {
  try { main(); } catch (e) { process.stderr.write(`${e && e.stack ? e.stack : e}\n`); process.exit(1); }
}

module.exports = { main };
