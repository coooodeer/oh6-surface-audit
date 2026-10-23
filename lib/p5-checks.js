'use strict';

/**
 * p5-checks.js —— P5 权限/身份检查站点索引（R1）。
 *
 * 数据源：
 *   - oh6-vuln-agent/index/perm.jsonl（2,727 条权限/身份调用点）
 *   - oh6-vuln-agent/index/perm-refs.jsonl（权限引用/宏）
 *
 * 纪律：
 *   - server/client/test/unknown 必须分开；client/test 不能计入 O6/O7/O8；
 *   - get-calling-uid/pid 是 identity source，不是 check；不能当 O6 proven；
 *   - 每条 check 必须有稳定 file:line+functionId。
 */

const fs = require('fs');
const path = require('path');
const { WORKSPACE, OUT_ROOT, ensureDir, readJsonl, writeJsonl, writeJson } = require('./util.js');
const { isR1 } = require('./in-scope.js');

const AGENT = path.join(WORKSPACE, 'oh6-vuln-agent');

const CHECK_KINDS = new Set(['check-permission', 'verify-calling-permission', 'verify-permission', 'verify-access-token', 'is-system-app']);
const IDENTITY_KINDS = new Set(['get-calling-uid', 'get-calling-pid', 'get-calling-token-id', 'get-self-token-id', 'get-self-uid']);
const CALL_CHECK_RE = /^(?:Check|Verify).*Permission$|^HasAccountRequestPermission$|^CheckSystemApp$|^IsSystemApp$|^CheckChannelPermission$|^CheckOpenSessionPermission$|^CheckCallingPermission$|^TransGetAndComparePid$|^ComparePid$|^CompareUid$|^CompareToken$/;

function permissionOf(text, refs) {
  const names = new Set();
  const s = String(text || '');
  for (const re of [/ohos\.permission\.[A-Za-z0-9_]+/g, /\bOHOS_PERMISSION_[A-Z0-9_]+/g, /\bPERMISSION_[A-Z0-9_]+/g]) {
    let m;
    while ((m = re.exec(s))) names.add(m[0]);
  }
  for (const r of refs || []) {
    if (r && r.raw) names.add(String(r.raw));
    if (r && r.ref && r.ref !== 'DENIED') names.add(String(r.ref));
  }
  return [...names];
}

function sideOf(repo, file) {
  const f = String(file || '').split(path.sep).join('/');
  if (/(^|\/)(test|tests|unittest|moduletest|fuzztest)(\/|$)/.test(f)) return 'test';
  if (repo === 'base/account/os_account') {
    if (f.startsWith('services/')) return 'server';
    if (f.startsWith('frameworks/') || f.startsWith('interfaces/')) return 'client';
    return 'unknown';
  }
  if (repo === 'foundation/communication/dsoftbus') {
    if (/client|proxy|sdk\//.test(f) && !/server|stub/.test(f)) return 'client';
    if (/server|stub|core\/frame/.test(f)) return 'server';
    return 'unknown';
  }
  return 'unknown';
}

function repoOfPath(l1, file, line) {
  for (const repo of ['base/account/os_account', 'foundation/communication/dsoftbus']) {
    const fn = l1.getFunction(repo, file, line);
    if (fn) return { repo, fn };
  }
  return null;
}

function buildP5Checks(l1, opts = {}) {
  const perm = readJsonl(path.join(AGENT, 'index', 'perm.jsonl'));
  const refs = readJsonl(path.join(AGENT, 'index', 'perm-refs.jsonl'));
  const refsByLine = new Map();
  for (const r of refs) {
    const k = `${r.file}|${r.line}`;
    if (!refsByLine.has(k)) refsByLine.set(k, []);
    refsByLine.get(k).push(r);
  }
  const rows = [];
  const seen = new Set();
  for (const r of perm) {
    const loc = repoOfPath(l1, r.file, r.line);
    if (!loc || !isR1(loc.repo)) continue;
    const key = `${loc.repo}|${r.file}|${r.line}|${r.kind}|${r.text}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const refList = refsByLine.get(`${r.file}|${r.line}`) || [];
    const permissions = permissionOf(r.text, refList);
    const isCheck = CHECK_KINDS.has(r.kind);
    const isIdentity = IDENTITY_KINDS.has(r.kind);
    rows.push({
      checkId: `P5CHK-${loc.repo.replace(/[^A-Za-z0-9]+/g, '_')}-${r.file.replace(/[^A-Za-z0-9]+/g, '_')}-${r.line}-${r.kind}`,
      scope: 'R1',
      repo: loc.repo,
      file: r.file,
      line: r.line,
      functionId: loc.fn.functionId,
      functionName: loc.fn.name,
      functionStartLine: loc.fn.startLine,
      kind: r.kind,
      isCheck,
      isIdentitySource: isIdentity,
      side: sideOf(loc.repo, r.file),
      text: r.text,
      permissions,
      refs: refList.map((x) => ({ ref: x.ref, raw: x.raw, form: x.form })).slice(0, 5),
      owner: loc.fn.owner || null
    });
  }
  const existingCheckLines = new Set(rows.filter((r) => r.isCheck).map((r) => `${r.repo}|${r.file}|${r.line}`));
  // Call-site checks：perm.jsonl 只覆盖部分调用点；从 L1 calls 补 CheckChannelPermission /
  // CheckOpenSessionPermission 等“函数名即检查”的调用点。
  for (const repo of ['base/account/os_account', 'foundation/communication/dsoftbus']) {
    for (const fn of l1.functionsOfRepo(repo)) {
      if (!fn.calls || !fn.calls.length) continue;
      for (const call of fn.calls) {
        if (!CALL_CHECK_RE.test(call.name)) continue;
        const absLine = fn.startLine + Number(call.line || 0) - 1;
        if (!absLine || absLine < fn.startLine) continue;
        if (existingCheckLines.has(`${repo}|${fn.file}|${absLine}`)) continue;
        const text = l1.lineAt(repo, fn.file, absLine) || `${call.name}(...)`;
        const permissions = permissionOf(text, []);
        const kind = /SystemApp/.test(call.name) ? 'is-system-app' : (/Permission/.test(call.name) ? 'check-permission' : 'check-call');
        const id = `P5CHK-CALL-${repo.replace(/[^A-Za-z0-9]+/g, '_')}-${fn.file.replace(/[^A-Za-z0-9]+/g, '_')}-${absLine}-${call.name}`;
        rows.push({
          checkId: id,
          scope: 'R1',
          repo,
          file: fn.file,
          line: absLine,
          functionId: fn.functionId,
          functionName: fn.name,
          functionStartLine: fn.startLine,
          kind,
          isCheck: true,
          isIdentitySource: false,
          side: sideOf(repo, fn.file),
          text,
          permissions,
          refs: [],
          owner: fn.owner || null
        });
        existingCheckLines.add(`${repo}|${fn.file}|${absLine}`);
      }
    }
  }
  const summary = {
    total: rows.length,
    checks: rows.filter((r) => r.isCheck).length,
    identitySources: rows.filter((r) => r.isIdentitySource).length,
    byRepo: rows.reduce((a, r) => { a[r.repo] = (a[r.repo] || 0) + 1; return a; }, {}),
    bySide: rows.reduce((a, r) => { a[r.side] = (a[r.side] || 0) + 1; return a; }, {}),
    checksBySide: rows.filter((r) => r.isCheck).reduce((a, r) => { a[r.side] = (a[r.side] || 0) + 1; return a; }, {}),
    byKind: rows.reduce((a, r) => { a[r.kind] = (a[r.kind] || 0) + 1; return a; }, {}),
    permissions: [...new Set(rows.flatMap((r) => r.permissions))].slice(0, 200)
  };
  return { rows, summary };
}

function writeChecks(result) {
  const dir = path.join(OUT_ROOT, 'p5');
  ensureDir(dir);
  writeJsonl(path.join(dir, 'check-sites.jsonl'), result.rows);
  writeJson(path.join(dir, 'check-summary.json'), result.summary);
  return { dir, file: path.join(dir, 'check-sites.jsonl'), summaryFile: path.join(dir, 'check-summary.json') };
}

module.exports = { CHECK_KINDS, IDENTITY_KINDS, permissionOf, sideOf, buildP5Checks, writeChecks };
