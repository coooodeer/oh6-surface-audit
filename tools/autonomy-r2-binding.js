'use strict';

/**
 * tools/autonomy-r2-binding.js —— R2-D1：access_token 同 argc 重载的类型族消歧实验。
 *
 * before：R1 口径（owner 映射 + 无 argc/类型 tie-breaker）→ 79 resolved / 2 suspect / 4 unbound。
 * after：scope.binding.matchParamTypes=true（IDL 参数类型族 vs C++ 签名类型族，
 * 仅 vector/map/string 可判位强制一致、别名不参与判定、role=test 不作候选）。
 * 输出 85 个入口的前后分布与每条变动证据；仍 suspect/unbound 的每条给定位原因。
 *
 * 只读：不改快照、不建 run。输出 --out（默认 out/autonomy/inventory/r2-binding-overloads.json）。
 *
 * 用法：node tools/autonomy-r2-binding.js [--scope=access-token-r2] [--out=<file>]
 */

const fs = require('node:fs');
const path = require('node:path');

const factsLib = require('../lib/autonomy/facts');
const indexLib = require('../lib/autonomy/index');
const discovery = require('../lib/autonomy/discovery');

const TOOL_DIR = path.resolve(__dirname, '..');

function parseArgs(argv) {
  const out = { scope: 'access-token-r2', out: null };
  for (const a of argv) {
    if (a.startsWith('--scope=')) out.scope = a.slice('--scope='.length);
    else if (a.startsWith('--out=')) out.out = a.slice('--out='.length);
    else throw new Error(`unknown-arg: ${a}`);
  }
  return out;
}

// R1 §11 实验使用的 IDL→实现 owner 映射（El5FilekeyManagerService /
// AccessTokenManagerService / PrivacyManagerService），原样注入，不新造映射。
const OWNER_MAP = {
  'OHOS.Security.AccessToken.El5FilekeyManagerInterface': 'El5FilekeyManagerService',
  'OHOS.Security.AccessToken.IAccessTokenManager': 'AccessTokenManagerService',
  'OHOS.Security.AccessToken.IPrivacyManager': 'PrivacyManagerService'
};

function bindingPass(facts, policy, matchParamTypes) {
  const scopeCfg = {
    ...policy,
    modelMetadata: {
      ...(policy.modelMetadata || {}),
      interfaces: Object.fromEntries(Object.entries(OWNER_MAP)
        .map(([iface, owner]) => [iface, { implOwnerSuffix: owner }]))
    },
    binding: {
      ...(policy.binding || {}),
      // R1 after 状态 = owner 映射 + matchArgc（同参数个数 tie-breaker，默认关）
      matchArgc: true,
      matchParamTypes
    }
  };
  const anchorsInfo = discovery.buildAnchors(facts, scopeCfg);
  const rows = [];
  for (const [ref, anchor] of anchorsInfo.anchors) {
    if (anchor.kind !== 'idl' && anchor.kind !== 'sa') continue; // 85 入口口径：元数据入口
    const b = discovery.resolveBinding(ref, { facts, scope: scopeCfg, anchors: anchorsInfo.anchors });
    rows.push({
      kind: anchor.kind,
      interface: anchor.interface || null,
      method: anchor.method || null,
      saId: anchor.saId || null,
      ipcCode: anchor.ipcCode === undefined ? null : anchor.ipcCode,
      entryRef: ref,
      binding: b.binding,
      candidates: (b.candidates || []).map((c) => ({ file: c.file, line: c.startLine, qualified: c.qualified })),
      note: b.note
    });
  }
  const dist = { resolved: 0, suspect: 0, unbound: 0 };
  for (const r of rows) dist[r.binding] = (dist[r.binding] || 0) + 1;
  return { rows, dist };
}

function entryKey(r) {
  return `${r.kind}|${r.interface || ''}|${r.method || ''}|${r.saId ?? ''}|${r.ipcCode ?? ''}`;
}

function main(argv = []) {
  const args = parseArgs(argv);
  const policy = JSON.parse(fs.readFileSync(path.join(TOOL_DIR, 'K', 'policies', `scope-${args.scope}.json`), 'utf8'));
  const facts = factsLib.AutonomyFacts.open({ snapshot: 'latest', scope: policy });

  const before = bindingPass(facts, policy, false);
  const after = bindingPass(facts, policy, true);

  const beforeByKey = new Map(before.rows.map((r) => [entryKey(r), r]));
  const changes = [];
  const unchangedSuspect = [];
  const unchangedUnbound = [];
  for (const r of after.rows) {
    const prev = beforeByKey.get(entryKey(r));
    if (!prev) continue;
    if (prev.binding !== r.binding) {
      changes.push({
        entry: { kind: r.kind, interface: r.interface, method: r.method, ipcCode: r.ipcCode, saId: r.saId },
        before: prev.binding,
        after: r.binding,
        evidence: { note: r.note, candidates: r.candidates }
      });
    } else if (r.binding === 'suspect') {
      unchangedSuspect.push({ entry: { kind: r.kind, interface: r.interface, method: r.method, ipcCode: r.ipcCode },
        reason: r.note, candidates: r.candidates });
    } else if (r.binding === 'unbound') {
      unchangedUnbound.push({ entry: { kind: r.kind, saId: r.saId, library: r.note }, reason: r.note });
    }
  }

  const result = {
    experimentVersion: 'r2-binding-overloads-v1',
    generatedAt: new Date().toISOString(),
    scope: args.scope,
    snapshotId: facts.snapshotId,
    method: 'scope.binding.matchParamTypes=true：IDL 参数类型族（List/Map/String 可判）'
      + ' vs C++ 签名类型族；别名不参与判定；role=test 不作候选；仅唯一幸存才 resolved。',
    before: { dist: before.dist, note: 'R1 口径（owner 映射，无 argc/类型 tie-breaker）' },
    after: { dist: after.dist },
    changes,
    unchangedSuspect,
    unchangedUnbound,
    totalEntries: after.rows.length
  };
  const outFile = args.out || path.join(TOOL_DIR, 'out', 'autonomy', 'inventory', 'r2-binding-overloads.json');
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({
    ok: true, totalEntries: result.totalEntries,
    before: before.dist, after: after.dist,
    changes: changes.map((c) => `${c.entry.method}(ipcCode=${c.entry.ipcCode}): ${c.before}->${c.after}`),
    out: path.relative(TOOL_DIR, outFile).split(path.sep).join('/')
  })}\n`);
  return 0;
}

module.exports = { main, bindingPass, entryKey };

if (require.main === module) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (e) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: e.message })}\n`);
    process.exitCode = 1;
  }
}
