'use strict';

/**
 * p5-paths.js —— 从 service impl 出发的 bounded call path + 权限检查覆盖。
 *
 * 只做函数级 BFS（depth <= 6），不声称完整 CFG/支配性；
 * 目的是回答“sink 所在函数/其可调用路径上是否有 server-side check”，
 * 并把 client/test check 单独排除。
 */

const path = require('path');
const { OUT_ROOT, ensureDir, writeJsonl, writeJson } = require('./util.js');

function buildP5Paths(units, pairingRows, checkRows, l1, opts = {}) {
  const maxDepth = Number(opts.maxDepth || 6);
  const maxNodes = Number(opts.maxNodes || 300);
  const pairingByUnit = new Map(pairingRows.map((r) => [r.unitId, r]));
  const checksByFunction = new Map();
  for (const c of checkRows) {
    if (!c.functionId) continue;
    if (!checksByFunction.has(c.functionId)) checksByFunction.set(c.functionId, []);
    checksByFunction.get(c.functionId).push(c);
  }
  const rows = [];
  for (const unit of units) {
    const pair = pairingByUnit.get(unit.unitId);
    const base = {
      unitId: unit.unitId,
      entryId: unit.entryId,
      interface: unit.interface,
      method: unit.method,
      direction: unit.direction,
      pairingStatus: pair ? pair.pairingStatus : null,
      implFunction: pair ? pair.implFunction || null : null
    };
    if (!pair || !pair.resolved) {
      rows.push({ ...base, pathScoped: false, noCheckOnPath: null, reason: pair ? pair.reason || 'pairing-gap' : 'pairing-missing', checks: [], serverChecks: 0, clientChecks: 0, identitySources: 0, maxDepth: 0 });
      continue;
    }
    const start = pair.implFunction;
    const visited = new Set([start]);
    const parent = new Map();
    const depth = new Map([[start, 0]]);
    const queue = [start];
    let qi = 0;
    while (qi < queue.length && visited.size < maxNodes) {
      const cur = queue[qi++];
      const d = depth.get(cur) || 0;
      if (d >= maxDepth) continue;
      for (const edge of l1.callees(cur, 100)) {
        if (!edge.functionId || visited.has(edge.functionId)) continue;
        visited.add(edge.functionId);
        parent.set(edge.functionId, cur);
        depth.set(edge.functionId, d + 1);
        queue.push(edge.functionId);
      }
    }
    const pathTo = (fid) => {
      const chain = [];
      let cur = fid;
      while (cur) {
        chain.push(cur);
        cur = parent.get(cur);
      }
      return chain.reverse();
    };
    const checks = [];
    for (const fid of visited) {
      for (const c of checksByFunction.get(fid) || []) {
        checks.push({
          checkId: c.checkId,
          kind: c.kind,
          file: c.file,
          line: c.line,
          functionId: c.functionId,
          side: c.side,
          permissions: c.permissions,
          text: c.text,
          depth: depth.get(fid) || 0,
          path: pathTo(fid)
        });
      }
    }
    const serverChecks = checks.filter((c) => c.side === 'server' && ['check-permission', 'verify-calling-permission', 'verify-permission', 'verify-access-token', 'is-system-app', 'check-call'].includes(c.kind));
    const clientChecks = checks.filter((c) => c.side === 'client' && ['check-permission', 'verify-calling-permission', 'verify-permission', 'verify-access-token', 'is-system-app', 'check-call'].includes(c.kind));
    const identitySources = checks.filter((c) => ['get-calling-uid', 'get-calling-pid', 'get-calling-token-id', 'get-self-token-id'].includes(c.kind));
    rows.push({
      ...base,
      pathScoped: serverChecks.length > 0,
      noCheckOnPath: visited.size < maxNodes && serverChecks.length === 0,
      reason: serverChecks.length ? null : (visited.size >= maxNodes ? 'path-bfs-truncated' : 'no-server-check-on-path'),
      checks,
      serverChecks: serverChecks.length,
      clientChecks: clientChecks.length,
      identitySources: identitySources.length,
      maxDepth: Math.max(0, ...depth.values()),
      visitedFunctions: visited.size
    });
  }
  const service = rows.filter((r) => r.direction === 'service');
  const summary = {
    total: rows.length,
    service: service.length,
    pathScoped: service.filter((r) => r.pathScoped).length,
    pathScopedRate: service.length ? Number((service.filter((r) => r.pathScoped).length / service.length).toFixed(3)) : 0,
    noCheckOnPath: service.filter((r) => r.noCheckOnPath).length,
    truncated: service.filter((r) => r.reason === 'path-bfs-truncated').length,
    withServerCheck: service.filter((r) => r.serverChecks > 0).length,
    withClientOnlyCheck: service.filter((r) => r.clientChecks > 0 && r.serverChecks === 0).length,
    withIdentitySource: service.filter((r) => r.identitySources > 0).length,
    maxDepth: maxDepth
  };
  return { rows, summary };
}

function writePaths(result) {
  const dir = path.join(OUT_ROOT, 'p5');
  ensureDir(dir);
  writeJsonl(path.join(dir, 'paths.jsonl'), result.rows);
  writeJson(path.join(dir, 'path-summary.json'), result.summary);
  return { dir, file: path.join(dir, 'paths.jsonl'), summaryFile: path.join(dir, 'path-summary.json') };
}

module.exports = { buildP5Paths, writePaths };
